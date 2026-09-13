#!/usr/bin/env python3
"""Sauvegardes protégées contre l'écrasement — y compris par root.

Un ransomware moderne ne chiffre pas seulement les fichiers de
production : il s'attaque aussi aux sauvegardes accessibles depuis le
même réseau (NAS, partage SMB, dossier cloud synchronisé), souvent avec
les mêmes droits que ceux qu'il vient de compromettre. Un simple
`chmod 444` sur l'archive ne résiste pas à ça : le compte compromis peut
se remettre lui-même en écriture avec `chmod` avant de réécrire le
fichier. La seule protection qui tient sous Linux est l'attribut
immuable du système de fichiers (`chattr +i`, extension ext2/ext3/ext4),
qui refuse toute modification — y compris à root — tant qu'il n'a pas
été explicitement retiré. C'est ce que ce module applique réellement
(avec repli sur `chmod 444` seul si `chattr` est indisponible : conteneur
sans `CAP_LINUX_IMMUTABLE`, système de fichiers qui ne supporte pas
l'attribut comme tmpfs/overlayfs, ou exécution hors Linux). Le manifest
SHA-256 signé permet en plus de détecter toute altération qui aurait
malgré tout réussi. En production cloud, l'équivalent est un objet en
« retention mode » (S3 Object Lock, Azure Immutable Blob Storage), qui
offre la même garantie sans dépendre d'un attribut de système de
fichiers local.
"""

import os
import sys
import json
import time
import stat
import gzip
import hashlib
import shutil
import subprocess
import sqlite3
import tarfile
import threading
import random
import string
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional


# ════════════════════════════════════════════════════════════════
# CONFIGURATION
# ════════════════════════════════════════════════════════════════

class BackupConfig:
    # Répertoire de stockage des backups
    BACKUP_ROOT     = Path("/tmp/immutable_backups")

    # Rétention minimale en jours (aucune suppression avant)
    RETENTION_DAYS  = 30

    # Compression : gz, bz2, xz (xz = meilleur ratio, plus lent)
    COMPRESSION     = "gz"

    # Niveau de compression 1-9
    COMPRESS_LEVEL  = 6

    # Nombre max de backups à conserver (après la rétention)
    MAX_BACKUPS     = 12   # 12 backups mensuels = 1 an

    # Vérification d'intégrité automatique (en heures)
    INTEGRITY_CHECK_INTERVAL = 24

    # Manifest signé
    MANIFEST_FILE   = BACKUP_ROOT / "manifest.json"
    DB_PATH         = BACKUP_ROOT / "backup_registry.db"


# ════════════════════════════════════════════════════════════════
# CALCUL D'EMPREINTES (INTÉGRITÉ)
# ════════════════════════════════════════════════════════════════

def sha256_file(path: Path) -> str:
    """SHA-256 d'un fichier par blocs de 64 Ko (gère les gros fichiers)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_tree(folder: Path) -> dict:
    """
    Empreinte de tout un arbre de fichiers.
    Retourne {chemin_relatif: sha256}.
    Utilisé pour vérifier qu'aucun fichier n'a été altéré.
    """
    checksums = {}
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(folder))
            checksums[rel] = sha256_file(path)
    return checksums


def sign_manifest(manifest: dict) -> str:
    """
    'Signature' du manifest — hash du contenu JSON canonique.
    En production : remplacer par une vraie signature RSA/ECDSA.
    Ce hash permet de détecter toute altération du manifest lui-même.
    """
    canonical = json.dumps(manifest, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ════════════════════════════════════════════════════════════════
# BASE DE DONNÉES DES BACKUPS
# ════════════════════════════════════════════════════════════════

def init_registry(db_path: Path):
    """Registre SQLite de tous les backups créés."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS backups (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_id       TEXT UNIQUE NOT NULL,
            created_at      REAL NOT NULL,
            expires_at      REAL NOT NULL,
            source_path     TEXT NOT NULL,
            archive_path    TEXT NOT NULL,
            size_bytes      INTEGER,
            original_size   INTEGER,
            file_count      INTEGER,
            checksum        TEXT NOT NULL,
            manifest_sig    TEXT,
            status          TEXT DEFAULT 'ACTIVE',
            verified_at     REAL,
            integrity_ok    INTEGER DEFAULT 1,
            tags            TEXT
        );

        CREATE TABLE IF NOT EXISTS integrity_checks (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_id       TEXT NOT NULL,
            checked_at      REAL NOT NULL,
            result          TEXT NOT NULL,
            details         TEXT
        );

        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   REAL NOT NULL,
            event_type  TEXT NOT NULL,
            backup_id   TEXT,
            message     TEXT
        );
    """)
    conn.commit()
    conn.close()


def log_event(db_path: Path, event_type: str,
              message: str, backup_id: str = None):
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "INSERT INTO events (timestamp, event_type, backup_id, message) VALUES (?,?,?,?)",
            (time.time(), event_type, backup_id, message)
        )
        conn.commit()


# ════════════════════════════════════════════════════════════════
# MOTEUR DE BACKUP IMMUABLE
# ════════════════════════════════════════════════════════════════

class ImmutableBackup:
    """
    Gestionnaire de backups immuables.

    Garanties d'immuabilité locales :
    - Archive verrouillée avec chattr +i (repli sur chmod 444 seul si le
      système de fichiers ou le conteneur ne supporte pas l'attribut)
    - Répertoire parent en lecture/exécution seule (chmod 555)
    - Manifest SHA-256 vérifiant chaque fichier
    - Registre SQLite horodaté et signé

    Le champ "immutable_chattr" retourné par create() dit honnêtement
    laquelle des deux protections est réellement active — chmod seul
    reste contournable par le propriétaire du fichier, chattr +i résiste
    même à root. Pour une garantie opposable légalement (au-delà d'un
    attribut de système de fichiers local) : S3 Object Lock, Azure
    Immutable Blob Storage, ou un stockage hors-ligne (cold storage).
    """

    def __init__(self, config: BackupConfig = None):
        self.cfg = config or BackupConfig()
        self.cfg.BACKUP_ROOT.mkdir(parents=True, exist_ok=True)
        init_registry(self.cfg.DB_PATH)

    def create(self, source: Path, tags: dict = None) -> dict:
        """
        Crée un backup immuable d'un dossier source.

        Étapes :
        1. Calculer les empreintes de tous les fichiers sources
        2. Créer l'archive tar.gz
        3. Calculer l'empreinte de l'archive
        4. Verrouiller l'archive (chattr +i, repli chmod 444)
        5. Signer le manifest
        6. Enregistrer dans le registre
        """
        source = Path(source)
        if not source.exists():
            raise FileNotFoundError(f"Source introuvable : {source}")

        # Identifiant unique du backup
        ts = datetime.now()
        backup_id = f"backup_{ts.strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"

        # Dossier de destination
        dest_dir = self.cfg.BACKUP_ROOT / backup_id
        dest_dir.mkdir(parents=True)

        archive_path = dest_dir / f"{backup_id}.tar.{self.cfg.COMPRESSION}"

        # ── Étape 1 : Empreintes sources ──
        print(f"    Calcul des empreintes sources...")
        source_checksums = sha256_tree(source)
        file_count = len(source_checksums)
        original_size = sum(
            (source / k).stat().st_size for k in source_checksums
            if (source / k).is_file()
        )

        # ── Étape 2 : Compression ──
        print(f"    Compression ({self.cfg.COMPRESSION})...")
        with tarfile.open(
            str(archive_path), f"w:{self.cfg.COMPRESSION}",
            compresslevel=self.cfg.COMPRESS_LEVEL
        ) as tar:
            tar.add(str(source), arcname=source.name)

        archive_size = archive_path.stat().st_size
        ratio = (1 - archive_size / max(original_size, 1)) * 100

        # ── Étape 3 : Empreinte de l'archive ──
        archive_checksum = sha256_file(archive_path)

        # ── Étape 4 : IMMUTABILITÉ ──
        print("    Verrouillage de l'archive (chattr +i, repli chmod 444)...")
        chattr_ok = self._make_immutable(archive_path)
        if chattr_ok:
            print("    chattr +i posé — résiste même à root.")
        else:
            print("    chattr indisponible ici — chmod 444 seul (contournable par le propriétaire du fichier).")

        # ── Étape 5 : Manifest signé ──
        manifest = {
            "backup_id":        backup_id,
            "created_at":       ts.isoformat(),
            "expires_at":       (ts + timedelta(days=self.cfg.RETENTION_DAYS)).isoformat(),
            "source":           str(source),
            "archive":          str(archive_path),
            "file_count":       file_count,
            "original_size_b":  original_size,
            "archive_size_b":   archive_size,
            "compression":      self.cfg.COMPRESSION,
            "archive_sha256":   archive_checksum,
            "source_checksums": source_checksums,
            "immutability":     "chattr+i" if chattr_ok else "chmod_444_only",
        }
        manifest["signature"] = sign_manifest(manifest)

        manifest_path = dest_dir / "manifest.json"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        self._make_immutable(manifest_path)

        # Rendre le dossier en lecture seule aussi
        os.chmod(dest_dir, stat.S_IRUSR | stat.S_IXUSR |
                           stat.S_IRGRP | stat.S_IXGRP |
                           stat.S_IROTH | stat.S_IXOTH)  # 555

        # ── Étape 6 : Registre ──
        expires = time.time() + (self.cfg.RETENTION_DAYS * 86400)
        with sqlite3.connect(str(self.cfg.DB_PATH)) as conn:
            conn.execute(
                """INSERT INTO backups
                   (backup_id, created_at, expires_at, source_path,
                    archive_path, size_bytes, original_size, file_count,
                    checksum, manifest_sig, tags)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (backup_id, time.time(), expires, str(source),
                 str(archive_path), archive_size, original_size,
                 file_count, archive_checksum,
                 manifest["signature"], json.dumps(tags or {}))
            )
            conn.commit()

        log_event(self.cfg.DB_PATH, "BACKUP_CREATED",
                  f"{file_count} fichiers, {archive_size:,} octets", backup_id)

        return {
            "backup_id":      backup_id,
            "archive":        str(archive_path),
            "file_count":     file_count,
            "original_size":  original_size,
            "archive_size":   archive_size,
            "compression_pct": f"{ratio:.1f}%",
            "sha256":         archive_checksum,
            "expires":        (ts + timedelta(days=self.cfg.RETENTION_DAYS)).strftime("%Y-%m-%d"),
            "immutable":      True,
            "immutable_chattr": chattr_ok,
        }

    def _make_immutable(self, path: Path) -> bool:
        """Verrouille un fichier. Retourne True si l'attribut immuable
        (chattr +i) a réellement été posé, False si on est retombé sur
        le seul chmod 444 (protection plus faible, contournable par le
        propriétaire du fichier)."""
        os.chmod(path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        try:
            result = subprocess.run(
                ["chattr", "+i", str(path)],
                capture_output=True, text=True, timeout=5,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            return False

    def _remove_immutable(self, path: Path) -> None:
        """Retire l'attribut immuable pour permettre une suppression
        légitime (retention expirée ou --force admin)."""
        try:
            subprocess.run(
                ["chattr", "-i", str(path)],
                capture_output=True, text=True, timeout=5,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            pass

    def verify(self, backup_id: str) -> dict:
        """
        Vérifie l'intégrité d'un backup.

        Contrôles :
        1. Existence physique de l'archive
        2. SHA-256 de l'archive = valeur enregistrée
        3. Signature du manifest = valeur calculée
        4. Permissions = read-only (444)
        """
        result = {
            "backup_id":     backup_id,
            "verified_at":   datetime.now().isoformat(),
            "checks":        {},
            "integrity":     True,
            "verdict":       "INTÈGRE",
        }

        # Récupérer depuis le registre
        with sqlite3.connect(str(self.cfg.DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM backups WHERE backup_id = ?", (backup_id,)
            ).fetchone()

        if not row:
            return {"error": f"Backup '{backup_id}' introuvable"}

        archive_path  = Path(row["archive_path"])
        stored_sha256 = row["checksum"]

        # ── Check 1 : Existence ──
        exists = archive_path.exists()
        result["checks"]["file_exists"] = exists
        if not exists:
            result["integrity"] = False
            result["verdict"]   = "ARCHIVE MANQUANTE"
            return result

        # ── Check 2 : SHA-256 ──
        current_sha256 = sha256_file(archive_path)
        sha_ok = current_sha256 == stored_sha256
        result["checks"]["sha256_match"] = sha_ok
        if not sha_ok:
            result["integrity"] = False
            result["verdict"]   = "ARCHIVE ALTÉRÉE (SHA-256 mismatch)"
            result["expected"]  = stored_sha256[:20] + "..."
            result["actual"]    = current_sha256[:20] + "..."

        # ── Check 3 : Manifest ──
        manifest_path = archive_path.parent / "manifest.json"
        if manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            stored_sig   = manifest.pop("signature", "")
            computed_sig = sign_manifest(manifest)
            manifest["signature"] = stored_sig  # Restaurer
            sig_ok = computed_sig == stored_sig
            result["checks"]["manifest_signature"] = sig_ok
            if not sig_ok:
                result["integrity"] = False
                result["verdict"]   = "MANIFEST FALSIFIÉ"

        # ── Check 4 : Permissions ──
        file_stat = os.stat(archive_path)
        perms     = oct(file_stat.st_mode & 0o777)
        is_readonly = not bool(file_stat.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
        result["checks"]["read_only"] = is_readonly
        result["checks"]["permissions"] = perms

        # ── Check 5 : Rétention ──
        expires = row["expires_at"]
        days_left = (expires - time.time()) / 86400
        deletable = days_left <= 0
        result["checks"]["retention_days_left"] = round(max(days_left, 0), 1)
        result["checks"]["can_delete"] = deletable

        # ── Enregistrer le résultat ──
        with sqlite3.connect(str(self.cfg.DB_PATH)) as conn:
            conn.execute(
                """UPDATE backups SET verified_at=?, integrity_ok=?
                   WHERE backup_id=?""",
                (time.time(), int(result["integrity"]), backup_id)
            )
            conn.execute(
                """INSERT INTO integrity_checks
                   (backup_id, checked_at, result, details)
                   VALUES (?,?,?,?)""",
                (backup_id, time.time(),
                 "PASS" if result["integrity"] else "FAIL",
                 json.dumps(result["checks"]))
            )
            conn.commit()

        log_event(self.cfg.DB_PATH,
                  "INTEGRITY_PASS" if result["integrity"] else "INTEGRITY_FAIL",
                  result["verdict"], backup_id)

        return result

    def restore(self, backup_id: str, dest: Path) -> dict:
        """
        Restaure un backup après vérification d'intégrité.
        JAMAIS de restauration sans vérification préalable.
        """
        # Vérifier l'intégrité AVANT de restaurer
        integrity = self.verify(backup_id)
        if not integrity.get("integrity"):
            raise ValueError(
                f"⛔ Restauration refusée : {integrity.get('verdict')}\n"
                f"   Le backup est corrompu ou altéré."
            )

        with sqlite3.connect(str(self.cfg.DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM backups WHERE backup_id = ?", (backup_id,)
            ).fetchone()

        archive_path = Path(row["archive_path"])
        dest = Path(dest)
        dest.mkdir(parents=True, exist_ok=True)

        print(f"    📂  Extraction vers {dest}...")
        with tarfile.open(str(archive_path), f"r:{self.cfg.COMPRESSION}") as tar:
            tar.extractall(str(dest))

        log_event(self.cfg.DB_PATH, "RESTORE",
                  f"Restauré vers {dest}", backup_id)

        return {
            "status":    "restored",
            "backup_id": backup_id,
            "dest":      str(dest),
            "files":     row["file_count"],
        }

    def can_delete(self, backup_id: str) -> tuple[bool, str]:
        """Vérifie si un backup peut être supprimé (rétention expirée)."""
        with sqlite3.connect(str(self.cfg.DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT expires_at FROM backups WHERE backup_id = ?",
                (backup_id,)
            ).fetchone()

        if not row:
            return False, "Backup introuvable"

        days_left = (row["expires_at"] - time.time()) / 86400
        if days_left > 0:
            return False, f"Rétention active — encore {days_left:.1f} jours"
        return True, "Rétention expirée — suppression autorisée"

    def delete(self, backup_id: str, force: bool = False) -> dict:
        """
        Supprime un backup UNIQUEMENT si la rétention est expirée.
        force=True contourne la politique — à réserver aux admin avec MFA.
        """
        can, reason = self.can_delete(backup_id)
        if not can and not force:
            return {"error": reason, "deleted": False}

        with sqlite3.connect(str(self.cfg.DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM backups WHERE backup_id = ?", (backup_id,)
            ).fetchone()

        if not row:
            return {"error": "Backup introuvable", "deleted": False}

        dest_dir = Path(row["archive_path"]).parent

        # Retirer les protections avant suppression (admin seulement) :
        # chattr -i d'abord, chmod ensuite, sinon chmod échoue sur un
        # fichier encore marqué immuable par le système de fichiers.
        for path in dest_dir.rglob("*"):
            if path.is_file():
                self._remove_immutable(path)
                os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        os.chmod(dest_dir, stat.S_IRWXU)

        shutil.rmtree(dest_dir)

        with sqlite3.connect(str(self.cfg.DB_PATH)) as conn:
            conn.execute(
                "UPDATE backups SET status='DELETED' WHERE backup_id=?",
                (backup_id,)
            )
            conn.commit()

        log_event(self.cfg.DB_PATH, "DELETED",
                  f"Force={force}", backup_id)
        return {"deleted": True, "backup_id": backup_id}

    def list_backups(self) -> list:
        """Liste tous les backups actifs."""
        with sqlite3.connect(str(self.cfg.DB_PATH)) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                """SELECT * FROM backups WHERE status='ACTIVE'
                   ORDER BY created_at DESC"""
            ).fetchall()
        return [dict(r) for r in rows]


# ════════════════════════════════════════════════════════════════
# SIMULATION RANSOMWARE
# ════════════════════════════════════════════════════════════════

def simulate_ransomware_attack(target: Path) -> dict:
    """
    Simule un ransomware qui chiffre (ici : corrompt) des fichiers.
    Éducatif uniquement — les fichiers sont juste écrasés de bytes aléatoires.
    """
    corrupted = []
    for path in target.rglob("*"):
        if path.is_file():
            original_size = path.stat().st_size
            # Simuler le chiffrement : écraser avec du bruit
            path.write_bytes(
                b"ENCRYPTED_BY_RANSOMWARE_" +
                os.urandom(max(original_size, 32)) +
                b".LOCKED\n"
            )
            corrupted.append(str(path.name))
    return {"corrupted_files": corrupted, "count": len(corrupted)}


# ════════════════════════════════════════════════════════════════
# CONFIGURATION CLOUD (documentation)
# ════════════════════════════════════════════════════════════════

CLOUD_CONFIG_DOCS = """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Déploiement cloud — immuabilité garantie légalement
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. AWS S3 Object Lock (WORM — Write Once Read Many)
─────────────────────────────────────────────────────
  import boto3
  s3 = boto3.client('s3')

  # Créer un bucket avec Object Lock activé
  s3.create_bucket(
      Bucket='mon-backup-immuable',
      ObjectLockEnabledForBucket=True,
  )

  # Uploader avec rétention 30 jours COMPLIANCE mode
  # (même un admin AWS ne peut pas supprimer avant l'expiration)
  s3.put_object(
      Bucket='mon-backup-immuable',
      Key=f'backups/{backup_id}.tar.gz',
      Body=archive_bytes,
      ObjectLockMode='COMPLIANCE',           # ou GOVERNANCE
      ObjectLockRetainUntilDate=datetime.now() + timedelta(days=30)
  )

  # COMPLIANCE = personne ne peut supprimer (même root AWS)
  # GOVERNANCE = les admins avec permission spéciale peuvent

2. Azure Immutable Blob Storage
─────────────────────────────────────────────────────
  from azure.storage.blob import BlobServiceClient
  # Activer la politique WORM sur le container :
  # Portal Azure → Storage Account → Containers
  # → Access policy → Add policy → Time-based retention → 30 days
  # → Lock policy (irréversible !)

3. Stockage local immuable Linux (chattr) — c'est ce que fait ce script
─────────────────────────────────────────────────────
  BackupManager._make_immutable() pose déjà chattr +i sur chaque backup
  (repli automatique sur chmod 444 si le système de fichiers ou le
  conteneur ne le permet pas — ext4 seul, généralement pas sur
  tmpfs/overlayfs). Pour vérifier l'attribut sur un backup existant :

  lsattr chemin/vers/backup.tar.gz    # 'i' dans la sortie = verrouillé

4. Règle 3-2-1 renforcée (recommandation ANSSI)
─────────────────────────────────────────────────────
  3 copies de données
  2 supports différents (ex: disque local + cloud)
  1 copie hors-site ET hors-ligne (déconnectée du réseau)
     ↳ S3 Object Lock = hors-ligne logique (aucun accès écriture)
"""


# ════════════════════════════════════════════════════════════════
# DÉMO COMPLÈTE
# ════════════════════════════════════════════════════════════════

def run_demo():
    import tempfile

    SEP = "═" * 62

    print(f"\n{SEP}")
    print("  Démo — backup immuable + simulation ransomware")
    print(f"{SEP}\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp       = Path(tmpdir)
        source    = tmp / "donnees_entreprise"
        restore   = tmp / "restauration"

        # ── Créer des données de production ──
        source.mkdir()
        (source / "clients").mkdir()
        (source / "comptabilite").mkdir()
        (source / "rh").mkdir()

        data_files = {
            "clients/base_clients.csv":
                "id,nom,email,ca\n1,ACME Corp,acme@example.com,45000\n2,Dupont SA,dupont@example.com,22000\n",
            "comptabilite/bilan_2024.json":
                json.dumps({"chiffre_affaires": 890000, "charges": 650000,
                            "resultat_net": 240000, "tresorerie": 125000}),
            "comptabilite/factures_q4.txt":
                "FAC-2024-0891: ACME Corp — 12 450€\nFAC-2024-0892: Dupont SA — 8 900€\n",
            "rh/salaries.csv":
                "id,nom,salaire_brut,poste\n1,Alice Martin,42000,DRH\n2,Bob Dupont,38000,Dev\n",
            "rh/contrats/cdi_alice.txt":
                "CONTRAT CDI — Alice Martin — Date: 01/03/2019 — Poste: DRH\n",
            "config.env":
                "DB_HOST=prod-db.internal\nDB_PASS=SuperSecure2024\nAPI_KEY=abc123\n",
        }

        for rel_path, content in data_files.items():
            full = source / rel_path
            full.parent.mkdir(parents=True, exist_ok=True)
            full.write_text(content, encoding="utf-8")

        total_size = sum(f.stat().st_size for f in source.rglob("*") if f.is_file())

        print(f"  Données de production créées :")
        print(f"      {len(data_files)} fichiers · {total_size:,} octets")
        for f in sorted(source.rglob("*")):
            if f.is_file():
                print(f"      - {f.relative_to(source)}")

        # ── Étape 1 : Création du backup ──
        print(f"\n  {'─'*60}")
        print(f"  Étape 1 : création du backup immuable")
        print(f"  {'─'*60}\n")

        cfg = BackupConfig()
        cfg.BACKUP_ROOT = tmp / "backups"
        bm = ImmutableBackup(cfg)

        print(f"  Démarrage du backup...")
        r = bm.create(source, tags={"type": "quotidien", "env": "production"})

        print(f"\n  Backup créé avec succès :")
        print(f"      ID       : {r['backup_id']}")
        print(f"      Fichiers : {r['file_count']}")
        print(f"      Taille   : {r['original_size']:,} B → {r['archive_size']:,} B "
              f"(−{r['compression_pct']})")
        print(f"      SHA-256  : {r['sha256'][:32]}...")
        print(f"      Expire   : {r['expires']} (rétention {cfg.RETENTION_DAYS}j)")
        print(f"      Immuable : {'chattr +i (résiste à root)' if r['immutable_chattr'] else 'chmod 444 seul (chattr indisponible ici)'}")

        backup_id = r["backup_id"]

        # Vérifier les permissions
        archive_path = Path(r["archive"])
        perms = oct(os.stat(archive_path).st_mode & 0o777)
        print(f"      Permissions : {perms} (lecture seule)")

        # ── Étape 2 : Vérification d'intégrité initiale ──
        print(f"\n  {'─'*60}")
        print("  Étape 2 : vérification d'intégrité")
        print(f"  {'─'*60}\n")

        v = bm.verify(backup_id)
        print(f"  Résultat : {v['verdict']}")
        for check, val in v["checks"].items():
            if check == "retention_days_left":
                print(f"    {check:<30} : {val} jours")
            elif check == "can_delete":
                print(f"    {check:<30} : {'NON (protégé)' if not val else 'OUI'}")
            else:
                print(f"    {check:<30} : {val}")

        # ── Étape 3 : RANSOMWARE ──
        print(f"\n  {'─'*60}")
        print("  Étape 3 : attaque ransomware simulée")
        print(f"  {'─'*60}\n")

        print("  Simulation : chiffrement de tous les fichiers de production...")
        time.sleep(0.3)

        attack = simulate_ransomware_attack(source)

        print(f"  {attack['count']} fichiers chiffrés / corrompus :")
        for f in attack["corrupted_files"]:
            print(f"      - {f}")

        print(f"\n  Contenu après attaque :")
        corrupted_content = list(source.rglob("*.csv"))[0].read_bytes()[:60]
        print(f"      {corrupted_content}")

        # Tentative de suppression du backup (rétention active)
        print(f"\n  Le ransomware tente de supprimer les backups...")
        result_del = bm.delete(backup_id, force=False)
        if result_del.get("error"):
            print(f"  Suppression bloquée : {result_del['error']}")
        else:
            print("  Backup supprimé (inattendu !)")

        # Tentative d'écriture directe sur l'archive
        print("\n  Le ransomware tente d'écrire sur l'archive...")
        try:
            with open(archive_path, "ab") as f2:
                f2.write(b"RANSOMWARE_PAYLOAD")
            if r["immutable_chattr"]:
                print("  Écriture passée MALGRÉ chattr +i — vérifier les capacités du conteneur (CAP_LINUX_IMMUTABLE).")
            else:
                print("  Écriture passée : seul chmod 444 protégeait ce fichier (chattr indisponible), et il tourne ici comme propriétaire du fichier.")
        except (PermissionError, OSError) as exc:
            layer = "chattr +i" if r["immutable_chattr"] else "chmod 444"
            print(f"  Écriture refusée par {layer} ({exc.__class__.__name__}).")

        # ── Étape 4 : Détection d'altération ──
        print(f"\n  {chr(8212)*60}")
        print("  Étape 4 : détection d'altération (SHA-256)")
        print(f"  {chr(8212)*60}\n")

        v2 = bm.verify(backup_id)
        sha_ok = v2["checks"].get("sha256_match", True)
        if not sha_ok:
            print(f"  Archive altérée détectée -> restauration bloquée")
            print(f"  → En prod : restaurer depuis S3 Object Lock / bande hors-ligne")
            # Recréer source propre pour simuler backup S3 intact
            clean_source2 = tmp / "clean_src2"
            clean_source2.mkdir()
            for rel_path2, content2 in data_files.items():
                full2 = clean_source2 / rel_path2
                full2.parent.mkdir(parents=True, exist_ok=True)
                full2.write_text(content2, encoding="utf-8")
            r2 = bm.create(clean_source2, tags={"site": "s3-backup"})
            backup_id = r2["backup_id"]
            print(f"  Backup secondaire (S3 simulé) : {backup_id[:40]}")
        else:
            verdict = v2["verdict"]
            print(f"  {verdict}")

        # ── Étape 5 : Restauration ──
        print(f"\n  {'─'*60}")
        print(f"  🔄  ÉTAPE 5 : RESTAURATION DEPUIS LE BACKUP")
        print(f"  {'─'*60}\n")

        res = bm.restore(backup_id, restore)
        print(f"  Restauration : {res['status']}")
        print(f"  Dossier  : {res['dest']}")
        print(f"  Fichiers : {res['files']}")

        # Vérifier que les données sont intactes
        print(f"\n  Vérification des données restaurées :")
        restored_csv = (restore / source.name / "clients" / "base_clients.csv")
        if restored_csv.exists():
            content = restored_csv.read_text(encoding="utf-8")
            print(f"    clients/base_clients.csv :")
            for line in content.strip().splitlines():
                print(f"      {line}")

        restored_json = (restore / source.name / "comptabilite" / "bilan_2024.json")
        if restored_json.exists():
            bilan = json.loads(restored_json.read_text())
            print(f"\n    comptabilite/bilan_2024.json :")
            print(f"      CA : {bilan["chiffre_affaires"]:,}€ | Net : {bilan["resultat_net"]:,}€")

        # ── Bilan ──
        print(f"\n{SEP}")
        print("  Bilan — protection anti-ransomware")
        print(f"{SEP}")
        print(f"""
  Avant le backup immuable :
  - attaque ransomware -> 100% des fichiers corrompus
  - option : payer la rançon (65 000€ en moyenne, PME)
  - option : reconstruction manuelle (semaines de travail)

  Après le backup immuable :
  - archive protégée (chattr +i si disponible, sinon chmod 444)
  - rétention bloquée (pas de suppression avant J+30)
  - SHA-256 vérifié (intégrité certifiée avant restauration)
  - RPO (Recovery Point Objective) : durée depuis dernier backup
  - RTO (Recovery Time Objective) : quelques minutes

  Coût de cette protection :
    • Script local   : 0€ (ce script)
    • S3 Object Lock : ~15€/mois pour 100 Go
    • vs rançon moy. : 65 000€ + downtime + réputation

  Conformité :
    Art. 32 RGPD  : Capacité de rétablissement des données
    ANSSI Guideline: Règle 3-2-1 + backup hors-ligne logique
    ISO 27001 A.12.3: Sauvegarde des données vérifiée
""")

        print(CLOUD_CONFIG_DOCS)


# ─── CLI ─────────────────────────────────────────────────────────

USAGE = """
Usage :
  python3 immutable_backup.py demo                   Démo complète
  python3 immutable_backup.py backup  <dossier>      Créer un backup
  python3 immutable_backup.py verify  <backup_id>    Vérifier intégrité
  python3 immutable_backup.py restore <backup_id> <dest>  Restaurer
  python3 immutable_backup.py list                   Lister les backups
  python3 immutable_backup.py delete  <backup_id>    Supprimer (si expiré)
"""

def main():
    print(__doc__)
    args = sys.argv[1:]

    if not args or args[0] == "demo":
        run_demo()
        return

    cfg = BackupConfig()
    bm  = ImmutableBackup(cfg)
    cmd = args[0].lower()

    if cmd == "backup":
        if len(args) < 2:
            print(USAGE); sys.exit(1)
        source = Path(args[1])
        tags   = {"cli": True}
        print(f"\n  ⏳  Backup de {source}...")
        r = bm.create(source, tags)
        print(f"\n  {r['backup_id']}")
        print(f"  SHA-256 : {r['sha256']}")
        print(f"  Expire  : {r['expires']}")
        print(f"  Taille  : {r['archive_size']:,} B (−{r['compression_pct']})")

    elif cmd == "verify":
        if len(args) < 2:
            print(USAGE); sys.exit(1)
        v = bm.verify(args[1])
        print(f"\n  {v['verdict']}")
        for k, val in v.get("checks", {}).items():
            print(f"    {k}: {val}")

    elif cmd == "restore":
        if len(args) < 3:
            print(USAGE); sys.exit(1)
        dest = Path(args[2])
        r    = bm.restore(args[1], dest)
        print(f"\n  Restauré dans {r['dest']}")

    elif cmd == "list":
        backups = bm.list_backups()
        if not backups:
            print("  Aucun backup.")
            return
        print(f"\n  {'ID':<35} {'Date':<20} {'Fichiers':>8} {'Taille':>10}")
        print("  " + "─"*75)
        for b in backups:
            date = datetime.fromtimestamp(b["created_at"]).strftime("%Y-%m-%d %H:%M")
            size = f"{b['size_bytes']:,}" if b["size_bytes"] else "?"
            print(f"  {b['backup_id']:<35} {date:<20} {b['file_count']:>8} {size:>10} B")

    elif cmd == "delete":
        if len(args) < 2:
            print(USAGE); sys.exit(1)
        r = bm.delete(args[1])
        if r.get("error"):
            print(f"\n  {r['error']}")
        else:
            print(f"\n  🗑️   Backup supprimé : {args[1]}")

    else:
        print(USAGE)


if __name__ == "__main__":
    main()
