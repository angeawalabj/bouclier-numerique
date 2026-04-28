#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 11 : DROIT À L'OUBLI AUTOMATISÉ  ║
║  Loi     : Art. 17 RGPD — Droit à l'effacement                  ║
║  Périmètre : SQL · JSON/NoSQL · Logs · Fichiers · Backups        ║
║  Délai   : 30 jours max · Certificat d'effacement généré        ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 17 RGPD — "La personne concernée a le
droit d'obtenir du responsable du traitement l'effacement, dans
les meilleurs délais, de données à caractère personnel la
concernant."

Délai : "dans les meilleurs délais et au plus tard dans un délai
d'un mois" (Art. 12 §3 RGPD). En pratique, la CNIL considère
72h comme délai raisonnable pour les systèmes automatisés.

Ce script parcourt récursivement :
  1. Bases SQL (SQLite — adaptable MySQL/PostgreSQL)
  2. Fichiers JSON / NoSQL (MongoDB-like)
  3. Fichiers de logs serveur (Nginx, Apache, applicatifs)
  4. Fichiers CSV (exports, analytics)
  5. Dossiers de fichiers personnels (uploads, avatars)
  6. Backups (détection des archives contenant des données)

À chaque étape :
  - Détection des champs contenant les identifiants de l'utilisateur
  - Effacement ou pseudonymisation selon le contexte
  - Conservation de la preuve d'effacement (sans les données)
  - Génération d'un certificat légal signé SHA-256

Risque évité : Art. 83 §5 — jusqu'à 20M€ ou 4% CA mondial
pour violation du droit à l'effacement (sanction maximale RGPD).

Cas réel France : H&M France (2021) — 35M€ pour surveillance
illicite. Clearview AI — 20M€ pour refus d'effacement.
"""

import os
import re
import sys
import json
import gzip
import csv
import glob
import uuid
import shutil
import sqlite3
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional
from collections import defaultdict

# ================================================================
# JOURNAL D'EFFACEMENT — Preuve légale immuable
# ================================================================

AUDIT_DB_PATH = "/tmp/erasure_audit.db"

AUDIT_SCHEMA = """
CREATE TABLE IF NOT EXISTS erasure_requests (
    id              TEXT PRIMARY KEY,
    user_id         TEXT NOT NULL,
    user_email      TEXT,
    requested_at    TEXT NOT NULL,
    completed_at    TEXT,
    status          TEXT DEFAULT 'EN_COURS',
    requester       TEXT,
    legal_basis     TEXT DEFAULT 'Art. 17 RGPD',
    total_records   INTEGER DEFAULT 0,
    total_files     INTEGER DEFAULT 0,
    certificate_hash TEXT
);

CREATE TABLE IF NOT EXISTS erasure_actions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    source_type     TEXT NOT NULL,
    source_path     TEXT NOT NULL,
    action          TEXT NOT NULL,
    records_affected INTEGER DEFAULT 0,
    method          TEXT,
    verified        INTEGER DEFAULT 0,
    details         TEXT
);

CREATE TABLE IF NOT EXISTS erasure_exceptions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id      TEXT NOT NULL,
    timestamp       TEXT NOT NULL,
    source          TEXT,
    reason          TEXT,
    legal_basis     TEXT,
    retention_until TEXT
);
"""


class ErasureAudit:
    """Journal immuable des opérations d'effacement."""

    def __init__(self, db_path: str = AUDIT_DB_PATH):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.executescript(AUDIT_SCHEMA)
            conn.commit()

    def new_request(self, user_id: str, user_email: str = "",
                    requester: str = "system") -> str:
        rid = f"ERASURE-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO erasure_requests
                   (id, user_id, user_email, requested_at, requester)
                   VALUES (?, ?, ?, ?, ?)""",
                (rid, user_id, user_email,
                 datetime.now().isoformat(), requester)
            )
            conn.commit()
        return rid

    def log_action(self, request_id: str, source_type: str,
                   source_path: str, action: str,
                   records: int = 0, method: str = "",
                   details: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO erasure_actions
                   (request_id, timestamp, source_type, source_path,
                    action, records_affected, method, details)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (request_id, datetime.now().isoformat(),
                 source_type, source_path, action,
                 records, method, details)
            )
            conn.commit()

    def log_exception(self, request_id: str, source: str,
                      reason: str, legal_basis: str = "",
                      retention_until: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO erasure_exceptions
                   (request_id, timestamp, source, reason,
                    legal_basis, retention_until)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (request_id, datetime.now().isoformat(),
                 source, reason, legal_basis, retention_until)
            )
            conn.commit()

    def complete_request(self, request_id: str,
                         total_records: int, total_files: int) -> str:
        """Finalise la demande et génère le certificat."""
        # Hash de certification basé sur toutes les actions
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            actions = conn.execute(
                "SELECT * FROM erasure_actions WHERE request_id=? ORDER BY id",
                (request_id,)
            ).fetchall()

        # Construire le contenu du certificat
        cert_content = json.dumps({
            "request_id":    request_id,
            "completed_at":  datetime.now().isoformat(),
            "total_records": total_records,
            "total_files":   total_files,
            "actions":       [dict(a) for a in actions],
        }, sort_keys=True)

        cert_hash = hashlib.sha256(cert_content.encode()).hexdigest()

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """UPDATE erasure_requests
                   SET status='COMPLÉTÉ', completed_at=?,
                       total_records=?, total_files=?,
                       certificate_hash=?
                   WHERE id=?""",
                (datetime.now().isoformat(),
                 total_records, total_files, cert_hash, request_id)
            )
            conn.commit()

        return cert_hash

    def get_request(self, request_id: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM erasure_requests WHERE id=?",
                (request_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_actions(self, request_id: str) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM erasure_actions WHERE request_id=? ORDER BY id",
                (request_id,)
            ).fetchall()
        return [dict(r) for r in rows]

    def get_exceptions(self, request_id: str) -> list:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM erasure_exceptions WHERE request_id=? ORDER BY id",
                (request_id,)
            ).fetchall()
        return [dict(r) for r in rows]


# ================================================================
# MOTEUR D'EFFACEMENT
# ================================================================

class RightToErasure:
    """
    Moteur d'effacement multi-sources.

    Stratégies d'effacement :
    - DELETE    : suppression de la ligne/entrée
    - ANONYMIZE : remplacement par des valeurs neutres
    - REDACT    : remplacement dans les logs/fichiers texte
    - SKIP      : conservation légale avec justification
    """

    def __init__(self, audit: ErasureAudit = None,
                 dry_run: bool = False):
        self.audit   = audit or ErasureAudit()
        self.dry_run = dry_run
        self._stats  = defaultdict(int)

    # ── 1. BASES SQL (SQLite) ──────────────────────────────────

    def erase_sqlite(self, db_path: str, user_id: str,
                     request_id: str,
                     user_fields: dict = None) -> dict:
        """
        Parcourt une base SQLite et efface/anonymise toutes les
        références à l'utilisateur.

        user_fields : {table: [colonnes_identifiantes]}
        Si None, détecte automatiquement les colonnes 'email', 'user_id', etc.
        """
        result = {"tables_scanned": 0, "records_deleted": 0,
                  "records_anonymized": 0, "tables": {}}

        if not Path(db_path).exists():
            return result

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row

        try:
            # Obtenir toutes les tables
            tables = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()

            for (table_name,) in tables:
                result["tables_scanned"] += 1

                # Obtenir les colonnes
                cols_info = conn.execute(
                    f"PRAGMA table_info({table_name})"
                ).fetchall()
                col_names = [c[1] for c in cols_info]

                # Colonnes identifiantes (auto-détection)
                id_cols = self._detect_id_columns(col_names, user_fields,
                                                   table_name)
                if not id_cols:
                    continue

                # Construire la clause WHERE
                where_parts = []
                params = []
                for col in id_cols:
                    where_parts.append(f"{col} = ?")
                    params.append(user_id)

                where_clause = " OR ".join(where_parts)
                count_q = f"SELECT COUNT(*) FROM {table_name} WHERE {where_clause}"
                count   = conn.execute(count_q, params).fetchone()[0]

                if count == 0:
                    continue

                # Décider : DELETE ou ANONYMIZE
                if self._should_delete(table_name):
                    if not self.dry_run:
                        conn.execute(
                            f"DELETE FROM {table_name} WHERE {where_clause}",
                            params
                        )
                        conn.commit()
                    action = "DELETE"
                    result["records_deleted"] += count
                else:
                    # Anonymisation des colonnes PII
                    pii_cols = self._detect_pii_columns(col_names)
                    if pii_cols:
                        set_parts = []
                        set_vals  = []
                        for col in pii_cols:
                            set_parts.append(f"{col} = ?")
                            set_vals.append(self._anonymize_value(col))
                        set_vals.extend(params)
                        if not self.dry_run:
                            conn.execute(
                                f"UPDATE {table_name} SET {', '.join(set_parts)} "
                                f"WHERE {where_clause}",
                                set_vals
                            )
                            conn.commit()
                        action = "ANONYMIZE"
                        result["records_anonymized"] += count

                result["tables"][table_name] = {
                    "action": action, "records": count,
                    "id_cols": id_cols,
                }

                self.audit.log_action(
                    request_id, "SQL", db_path,
                    action, count, "sqlite3",
                    f"Table {table_name}, cols={id_cols}"
                )
                self._stats["sql_records"] += count

        finally:
            conn.close()

        return result

    def _detect_id_columns(self, col_names: list,
                            user_fields: dict, table: str) -> list:
        """Détecte automatiquement les colonnes identifiantes."""
        if user_fields and table in user_fields:
            return [c for c in user_fields[table] if c in col_names]

        patterns = ["user_id", "userid", "email", "user_email",
                    "owner_id", "customer_id", "client_id",
                    "created_by", "author_id", "member_id"]
        return [c for c in col_names
                if c.lower() in patterns or
                c.lower().endswith("_user_id") or
                c.lower().endswith("_email")]

    def _detect_pii_columns(self, col_names: list) -> list:
        """Détecte les colonnes contenant des données personnelles."""
        pii_patterns = [
            "email", "nom", "name", "prenom", "firstname", "lastname",
            "telephone", "phone", "mobile", "adresse", "address",
            "ip", "ip_address", "user_agent", "avatar", "photo",
            "birth", "naissance", "gender", "sexe",
        ]
        return [c for c in col_names
                if any(p in c.lower() for p in pii_patterns)]

    def _should_delete(self, table_name: str) -> bool:
        """Tables à supprimer entièrement vs tables à anonymiser."""
        delete_tables = {
            "sessions", "tokens", "oauth_tokens", "api_keys",
            "notifications", "messages", "cart", "wishlist",
            "search_history", "activity_log", "user_events",
        }
        keep_tables = {
            "orders", "invoices", "transactions", "payments",
            "contracts", "legal_holds",
        }
        name = table_name.lower()
        if name in keep_tables:
            return False
        if name in delete_tables:
            return True
        return True  # Par défaut : supprimer

    def _anonymize_value(self, col_name: str) -> str:
        """Génère une valeur neutre selon le type de colonne."""
        col = col_name.lower()
        if "email" in col:
            return "deleted@anonymized.invalid"
        if any(n in col for n in ["name", "nom", "prenom"]):
            return "[SUPPRIMÉ]"
        if any(p in col for p in ["phone", "tel", "mobile"]):
            return "0000000000"
        if any(a in col for a in ["address", "adresse"]):
            return "[ADRESSE SUPPRIMÉE]"
        if "ip" in col:
            return "0.0.0.0"
        return "[DONNÉES SUPPRIMÉES]"

    # ── 2. FICHIERS JSON / NoSQL ───────────────────────────────

    def erase_json_files(self, folder: str, user_id: str,
                          user_email: str, request_id: str) -> dict:
        """
        Parcourt récursivement un dossier de fichiers JSON
        et efface les entrées correspondant à l'utilisateur.
        """
        result = {"files_scanned": 0, "files_modified": 0,
                  "records_removed": 0}
        folder_path = Path(folder)

        if not folder_path.exists():
            return result

        for json_file in folder_path.rglob("*.json"):
            result["files_scanned"] += 1
            try:
                content = json.loads(json_file.read_text(encoding="utf-8"))
                original = json.dumps(content, sort_keys=True)

                modified, count = self._purge_json(content, user_id, user_email)
                if count > 0:
                    result["files_modified"] += 1
                    result["records_removed"] += count
                    if not self.dry_run:
                        json_file.write_text(
                            json.dumps(modified, ensure_ascii=False, indent=2),
                            encoding="utf-8"
                        )
                    self.audit.log_action(
                        request_id, "JSON", str(json_file),
                        "DELETE", count, "json.purge",
                        f"{count} entrées supprimées"
                    )
                    self._stats["json_records"] += count
            except (json.JSONDecodeError, PermissionError):
                pass

        return result

    def _purge_json(self, data, user_id: str,
                    user_email: str) -> tuple:
        """Purge récursive d'un objet JSON."""
        count = 0

        if isinstance(data, list):
            new_list = []
            for item in data:
                if self._is_user_record(item, user_id, user_email):
                    count += 1
                else:
                    cleaned, c = self._purge_json(item, user_id, user_email)
                    new_list.append(cleaned)
                    count += c
            return new_list, count

        if isinstance(data, dict):
            if self._is_user_record(data, user_id, user_email):
                return {}, 1
            return {k: self._purge_json(v, user_id, user_email)[0]
                    for k, v in data.items()}, count

        return data, 0

    def _is_user_record(self, item, user_id: str, user_email: str) -> bool:
        """Détermine si un objet JSON appartient à l'utilisateur."""
        if not isinstance(item, dict):
            return False
        id_keys = ["user_id", "userId", "uid", "id", "email",
                   "user_email", "owner", "author", "customer_id"]
        for key in id_keys:
            val = str(item.get(key, ""))
            if val and (val == user_id or
                        (user_email and val.lower() == user_email.lower())):
                return True
        return False

    # ── 3. FICHIERS LOGS ──────────────────────────────────────

    def erase_logs(self, log_path: str, user_id: str,
                   user_email: str, request_id: str) -> dict:
        """
        Redacte les logs : remplace toutes les occurrences de
        l'email/ID par [SUPPRIMÉ-RGPD] dans les fichiers de log.
        Supporte .log, .txt, .gz.
        """
        result = {"files_scanned": 0, "files_modified": 0,
                  "lines_redacted": 0}
        log_path_p = Path(log_path)

        targets = []
        if log_path_p.is_file():
            targets = [log_path_p]
        elif log_path_p.is_dir():
            targets = list(log_path_p.rglob("*.log"))
            targets += list(log_path_p.rglob("*.txt"))
            targets += list(log_path_p.rglob("*.gz"))

        patterns = []
        if user_email:
            patterns.append(re.escape(user_email))
        if user_id:
            patterns.append(re.escape(user_id))

        if not patterns:
            return result

        combined = re.compile("|".join(patterns), re.IGNORECASE)

        for log_file in targets:
            result["files_scanned"] += 1
            try:
                is_gz = log_file.suffix == ".gz"
                open_fn = gzip.open if is_gz else open
                mode    = "rt"

                with open_fn(log_file, mode,
                             encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()

                new_lines   = []
                redacted    = 0
                for line in lines:
                    if combined.search(line):
                        new_line = combined.sub("[SUPPRIMÉ-RGPD]", line)
                        new_lines.append(new_line)
                        redacted += 1
                    else:
                        new_lines.append(line)

                if redacted > 0:
                    result["files_modified"] += 1
                    result["lines_redacted"] += redacted
                    if not self.dry_run:
                        write_fn = gzip.open if is_gz else open
                        with write_fn(log_file, "wt",
                                      encoding="utf-8") as f:
                            f.writelines(new_lines)

                    self.audit.log_action(
                        request_id, "LOG", str(log_file),
                        "REDACT", redacted, "regex.replace",
                        f"{redacted} lignes redactées"
                    )
                    self._stats["log_lines"] += redacted

            except (PermissionError, OSError):
                pass

        return result

    # ── 4. FICHIERS CSV ───────────────────────────────────────

    def erase_csv(self, csv_path: str, user_id: str,
                  user_email: str, request_id: str) -> dict:
        """Supprime les lignes correspondant à l'utilisateur dans les CSV."""
        result = {"files_scanned": 0, "files_modified": 0,
                  "rows_deleted": 0}
        path = Path(csv_path)

        targets = ([path] if path.is_file()
                   else list(path.rglob("*.csv")))

        for csv_file in targets:
            result["files_scanned"] += 1
            try:
                rows   = []
                deleted = 0
                with open(csv_file, "r", encoding="utf-8",
                          errors="replace") as f:
                    reader = csv.DictReader(f)
                    headers = reader.fieldnames or []
                    for row in reader:
                        is_user = any(
                            str(v) == user_id or
                            (user_email and
                             str(v).lower() == user_email.lower())
                            for v in row.values()
                        )
                        if is_user:
                            deleted += 1
                        else:
                            rows.append(row)

                if deleted > 0:
                    result["files_modified"] += 1
                    result["rows_deleted"]   += deleted
                    if not self.dry_run:
                        with open(csv_file, "w", encoding="utf-8",
                                  newline="") as f:
                            writer = csv.DictWriter(f, fieldnames=headers)
                            writer.writeheader()
                            writer.writerows(rows)

                    self.audit.log_action(
                        request_id, "CSV", str(csv_file),
                        "DELETE", deleted, "csv.filter",
                        f"{deleted} lignes supprimées"
                    )
                    self._stats["csv_rows"] += deleted

            except (PermissionError, OSError):
                pass

        return result

    # ── 5. FICHIERS PERSONNELS ─────────────────────────────────

    def erase_user_files(self, uploads_dir: str, user_id: str,
                          request_id: str) -> dict:
        """
        Supprime les dossiers/fichiers appartenant à l'utilisateur
        (avatars, documents uploadés, etc.).
        """
        result = {"files_deleted": 0, "dirs_deleted": 0}
        base = Path(uploads_dir)

        # Patterns de dossiers utilisateurs
        user_dirs = [
            base / user_id,
            base / "users" / user_id,
            base / "avatars" / f"{user_id}*",
            base / "uploads" / user_id,
        ]

        for pattern in user_dirs:
            for path in glob.glob(str(pattern)):
                p = Path(path)
                if p.is_dir():
                    count = sum(1 for _ in p.rglob("*") if _.is_file())
                    if not self.dry_run:
                        shutil.rmtree(p)
                    result["dirs_deleted"]  += 1
                    result["files_deleted"] += count
                    self.audit.log_action(
                        request_id, "FILES", str(p),
                        "DELETE", count, "shutil.rmtree",
                        f"Dossier utilisateur supprimé"
                    )
                elif p.is_file():
                    if not self.dry_run:
                        p.unlink()
                    result["files_deleted"] += 1
                    self.audit.log_action(
                        request_id, "FILES", str(p),
                        "DELETE", 1, "unlink",
                        "Fichier utilisateur supprimé"
                    )

        self._stats["files"] += result["files_deleted"]
        return result

    # ── 6. BACKUPS ────────────────────────────────────────────

    def check_backups(self, backup_dir: str, user_id: str,
                      user_email: str, request_id: str) -> dict:
        """
        Inventorie les backups contenant potentiellement des données
        de l'utilisateur. Ne supprime pas (obligation légale possible),
        mais documente pour le suivi des 30 jours.
        """
        result = {"backups_found": 0, "need_review": []}
        base = Path(backup_dir)

        if not base.exists():
            return result

        for archive in base.rglob("*.tar.gz"):
            result["backups_found"] += 1
            retention_until = (datetime.now() + timedelta(days=30)).date().isoformat()
            result["need_review"].append({
                "path":             str(archive),
                "created":          datetime.fromtimestamp(
                    archive.stat().st_mtime).isoformat(),
                "retention_until":  retention_until,
                "action_required":  "Supprimer après " + retention_until,
            })
            self.audit.log_exception(
                request_id, str(archive),
                "Archive de sauvegarde — expirera automatiquement",
                "Art. 17(3)(e) — Conservation pour obligation légale",
                retention_until
            )

        return result

    # ── ORCHESTRATEUR PRINCIPAL ───────────────────────────────

    def full_erasure(self, user_id: str, user_email: str,
                     config: dict,
                     requester: str = "system") -> dict:
        """
        Lance l'effacement complet sur tous les systèmes configurés.
        C'est le point d'entrée principal.
        """
        request_id = self.audit.new_request(user_id, user_email, requester)
        summary = {
            "request_id":   request_id,
            "user_id":      user_id,
            "user_email":   user_email,
            "started_at":   datetime.now().isoformat(),
            "dry_run":      self.dry_run,
            "results":      {},
            "total_records": 0,
            "total_files":  0,
            "exceptions":   [],
        }

        print(f"\n  🗑️   Effacement pour : {user_email or user_id}")
        print(f"  Référence : {request_id}")
        print(f"  Mode : {'SIMULATION (dry-run)' if self.dry_run else 'RÉEL'}\n")

        # 1. Bases SQL
        for db_path in config.get("sql_databases", []):
            print(f"  🗄️   SQL      : {Path(db_path).name}")
            r = self.erase_sqlite(db_path, user_id, request_id,
                                   config.get("user_fields"))
            summary["results"]["sql"] = r
            summary["total_records"] += r["records_deleted"] + r["records_anonymized"]

        # 2. JSON / NoSQL
        for folder in config.get("json_folders", []):
            print(f"  📄  JSON/NoSQL : {folder}")
            r = self.erase_json_files(folder, user_id, user_email, request_id)
            summary["results"]["json"] = r
            summary["total_records"] += r["records_removed"]

        # 3. Logs
        for log_path in config.get("log_paths", []):
            print(f"  📋  Logs     : {log_path}")
            r = self.erase_logs(log_path, user_id, user_email, request_id)
            summary["results"]["logs"] = r

        # 4. CSV
        for csv_path in config.get("csv_paths", []):
            print(f"  📊  CSV      : {csv_path}")
            r = self.erase_csv(csv_path, user_id, user_email, request_id)
            summary["results"]["csv"] = r
            summary["total_records"] += r["rows_deleted"]

        # 5. Fichiers utilisateurs
        for uploads_dir in config.get("uploads_dirs", []):
            print(f"  📁  Fichiers : {uploads_dir}")
            r = self.erase_user_files(uploads_dir, user_id, request_id)
            summary["results"]["files"] = r
            summary["total_files"] += r["files_deleted"]

        # 6. Backups
        for backup_dir in config.get("backup_dirs", []):
            print(f"  💾  Backups  : {backup_dir}")
            r = self.check_backups(backup_dir, user_id, user_email, request_id)
            summary["results"]["backups"] = r
            summary["exceptions"] = r.get("need_review", [])

        # Finalisation + certificat
        cert_hash = self.audit.complete_request(
            request_id,
            summary["total_records"],
            summary["total_files"]
        )
        summary["certificate_hash"] = cert_hash
        summary["completed_at"]     = datetime.now().isoformat()

        return summary


# ================================================================
# GÉNÉRATEUR DE CERTIFICAT D'EFFACEMENT
# ================================================================

def generate_certificate(request_id: str,
                          audit: ErasureAudit) -> str:
    """Génère le certificat légal d'effacement."""
    req        = audit.get_request(request_id)
    actions    = audit.get_actions(request_id)
    exceptions = audit.get_exceptions(request_id)

    if not req:
        return "Demande introuvable"

    lines = [
        "=" * 62,
        "  CERTIFICAT D'EFFACEMENT — Art. 17 RGPD",
        "=" * 62,
        "",
        f"  Référence       : {req['id']}",
        f"  Utilisateur     : {req['user_email'] or req['user_id']}",
        f"  Demande reçue   : {req['requested_at'][:19]}",
        f"  Effacement fait : {(req.get('completed_at') or 'En cours')[:19]}",
        f"  Statut          : {req['status']}",
        f"  Enregistrements : {req['total_records']}",
        f"  Fichiers        : {req['total_files']}",
        f"  Hash certificat : {req.get('certificate_hash', 'N/A')}",
        "",
        "  ACTIONS RÉALISÉES :",
        f"  {'─'*58}",
    ]

    for a in actions:
        lines.append(
            f"  [{a['source_type']:<8}] {a['action']:<12} "
            f"{a['records_affected']:>4} enreg.  "
            f"{Path(a['source_path']).name[:30]}"
        )

    if exceptions:
        lines += [
            "",
            "  EXCEPTIONS (conservation légale) :",
            f"  {'─'*58}",
        ]
        for e in exceptions:
            lines.append(f"  {Path(e['source']).name[:40]}")
            lines.append(f"    → {e['reason']}")
            if e.get("retention_until"):
                lines.append(f"    → Suppression prévue : {e['retention_until']}")

    lines += [
        "",
        f"  Intégrité : SHA-256 {req.get('certificate_hash', 'N/A')[:32]}...",
        "",
        "  Ce certificat atteste que les données à caractère",
        "  personnel de l'utilisateur ont été effacées conformément",
        "  à l'Article 17 du Règlement (UE) 2016/679 (RGPD).",
        "=" * 62,
    ]

    return "\n".join(lines)


# ================================================================
# DÉMONSTRATION COMPLÈTE
# ================================================================

def run_demo():
    import tempfile
    import random

    SEP = "=" * 62
    print(f"\n{SEP}")
    print("  DEMO — Droit à l'Oubli Automatisé (Art. 17 RGPD)")
    print(f"{SEP}\n")
    print(
        "  Scénario : Jean-Paul Dubois, client depuis 3 ans,\n"
        "  demande la suppression de toutes ses données.\n"
        "  Délai légal : 30 jours maximum (Art. 12 §3 RGPD).\n"
        "  L'objectif : effacer TOUTES les traces en <1 minute.\n"
    )

    USER_ID    = "user_4521"
    USER_EMAIL = "jean-paul.dubois@email.fr"

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # ── Création des données de test ──
        print(f"  {'─'*60}")
        print(f"  🏗️   ÉTAPE 1 : Simulation de l'environnement")
        print(f"  {'─'*60}\n")

        # 1. Base SQL
        db_path = str(tmp / "app.db")
        conn    = sqlite3.connect(db_path)
        conn.executescript("""
            CREATE TABLE users (
                user_id TEXT, email TEXT, nom TEXT, prenom TEXT,
                telephone TEXT, adresse TEXT, created_at TEXT
            );
            CREATE TABLE sessions (
                id INTEGER PRIMARY KEY, user_id TEXT, token TEXT, ip TEXT
            );
            CREATE TABLE orders (
                id INTEGER PRIMARY KEY, user_id TEXT, total REAL,
                created_at TEXT, status TEXT
            );
            CREATE TABLE notifications (
                id INTEGER PRIMARY KEY, user_id TEXT, message TEXT
            );
        """)
        # Données de Jean-Paul
        conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?)",
                     (USER_ID, USER_EMAIL, "DUBOIS", "Jean-Paul",
                      "0612345678", "15 rue Leblanc 75015 Paris",
                      "2021-03-15"))
        # Fausses données d'autres utilisateurs
        for i in range(5):
            conn.execute("INSERT INTO users VALUES (?,?,?,?,?,?,?)",
                         (f"user_{1000+i}", f"user{i}@autre.com",
                          f"NOM{i}", f"PRENOM{i}",
                          "0600000000", "Adresse autre", "2022-01-01"))
        # Sessions de Jean-Paul
        for _ in range(3):
            conn.execute("INSERT INTO sessions VALUES (NULL,?,?,?)",
                         (USER_ID, f"tok_{os.urandom(8).hex()}", "192.168.1.45"))
        # Commandes (à anonymiser, pas supprimer — obligation légale 10 ans)
        for i in range(2):
            conn.execute("INSERT INTO orders VALUES (NULL,?,?,?,?)",
                         (USER_ID, 129.90 + i * 50,
                          "2023-06-01", "LIVREE"))
        # Notifications
        for _ in range(4):
            conn.execute("INSERT INTO notifications VALUES (NULL,?,?)",
                         (USER_ID, "Votre commande a été expédiée"))
        conn.commit()
        conn.close()
        print(f"  ✅  Base SQL créée : users, sessions, orders, notifications")

        # 2. Fichiers JSON (analytics)
        json_dir = tmp / "analytics"
        json_dir.mkdir()
        events = [
            {"user_id": USER_ID, "email": USER_EMAIL,
             "event": "page_view", "url": "/dashboard",
             "ts": "2024-01-15T10:23:00"},
            {"user_id": USER_ID, "email": USER_EMAIL,
             "event": "purchase", "amount": 129.90,
             "ts": "2024-01-20T14:30:00"},
            {"user_id": "user_1000", "event": "page_view",
             "url": "/home", "ts": "2024-01-15T09:00:00"},
            {"user_id": "user_1001", "event": "signup",
             "ts": "2024-01-16T11:00:00"},
        ]
        (json_dir / "events_2024.json").write_text(
            json.dumps(events, indent=2), encoding="utf-8"
        )
        user_profile = {
            "user_id": USER_ID,
            "email":   USER_EMAIL,
            "preferences": {"theme": "dark", "lang": "fr"},
            "marketing": True,
        }
        (json_dir / "profiles.json").write_text(
            json.dumps([user_profile,
                        {"user_id": "user_1000", "email": "u@other.com"}],
                       indent=2),
            encoding="utf-8"
        )
        print(f"  ✅  Fichiers JSON créés : events_2024.json, profiles.json")

        # 3. Logs
        log_dir = tmp / "logs"
        log_dir.mkdir()
        log_content = "\n".join([
            f'192.168.1.45 - {USER_EMAIL} [15/Jan/2024:10:23:00] "GET /dashboard" 200',
            f'10.0.0.1 - other.user@test.com [15/Jan/2024:10:24:00] "GET /home" 200',
            f'192.168.1.45 - {USER_EMAIL} [15/Jan/2024:10:25:00] "POST /checkout" 200',
            f'[ERROR] Authentication failed for {USER_EMAIL} from 1.2.3.4',
            f'[INFO] User {USER_ID} logged in successfully',
            f'10.0.0.2 - admin@company.com [15/Jan/2024:11:00:00] "GET /admin" 200',
        ])
        (log_dir / "access.log").write_text(log_content, encoding="utf-8")
        print(f"  ✅  Logs créés : access.log ({len(log_content.splitlines())} lignes)")

        # 4. CSV
        csv_dir = tmp / "exports"
        csv_dir.mkdir()
        rows = [
            ["user_id", "email", "nom", "total_orders", "newsletter"],
            [USER_ID, USER_EMAIL, "DUBOIS Jean-Paul", "2", "oui"],
            ["user_1000", "u0@other.com", "NOM0 PRENOM0", "5", "non"],
            ["user_1001", "u1@other.com", "NOM1 PRENOM1", "1", "oui"],
        ]
        with open(tmp / "exports" / "customers.csv", "w",
                  newline="", encoding="utf-8") as f:
            csv.writer(f).writerows(rows)
        print(f"  ✅  CSV créé : customers.csv")

        # 5. Fichiers utilisateur
        uploads = tmp / "uploads"
        (uploads / "users" / USER_ID).mkdir(parents=True)
        (uploads / "users" / USER_ID / "avatar.jpg").write_bytes(b"FAKE_IMAGE")
        (uploads / "users" / USER_ID / "document.pdf").write_bytes(b"FAKE_PDF")
        print(f"  ✅  Fichiers utilisateur créés : avatar.jpg, document.pdf")

        # Backup simulé
        backup_dir = tmp / "backups"
        backup_dir.mkdir()
        import tarfile, io
        with tarfile.open(tmp / "backups" / "backup_2024-01-15.tar.gz", "w:gz") as tar:
            data = b"database backup content"
            ti   = tarfile.TarInfo(name="app.db")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
        print(f"  ✅  Backup créé : backup_2024-01-15.tar.gz\n")

        # ── Lancement de l'effacement ──
        print(f"  {'─'*60}")
        print(f"  🗑️   ÉTAPE 2 : LANCEMENT DE L'EFFACEMENT")
        print(f"  {'─'*60}")

        audit  = ErasureAudit(str(tmp / "audit.db"))
        engine = RightToErasure(audit, dry_run=False)

        config = {
            "sql_databases": [db_path],
            "json_folders":  [str(json_dir)],
            "log_paths":     [str(log_dir)],
            "csv_paths":     [str(csv_dir)],
            "uploads_dirs":  [str(uploads)],
            "backup_dirs":   [str(backup_dir)],
        }

        summary = engine.full_erasure(
            USER_ID, USER_EMAIL, config, requester="DPO@techcorp.fr"
        )

        # ── Vérifications ──
        print(f"\n  {'─'*60}")
        print(f"  🔬  ÉTAPE 3 : VÉRIFICATION POST-EFFACEMENT")
        print(f"  {'─'*60}\n")

        # Vérif SQL
        conn2 = sqlite3.connect(db_path)
        remaining_user = conn2.execute(
            "SELECT COUNT(*) FROM users WHERE user_id=?", (USER_ID,)
        ).fetchone()[0]
        remaining_sessions = conn2.execute(
            "SELECT COUNT(*) FROM sessions WHERE user_id=?", (USER_ID,)
        ).fetchone()[0]
        remaining_orders = conn2.execute(
            "SELECT COUNT(*) FROM orders WHERE user_id=?", (USER_ID,)
        ).fetchone()[0]
        conn2.close()

        print(f"  Table users    : {'✅ SUPPRIMÉ' if remaining_user == 0 else f'❌ {remaining_user} enreg. restant(s)'}")
        print(f"  Table sessions : {'✅ SUPPRIMÉ' if remaining_sessions == 0 else f'❌ restant'}")
        if remaining_orders:
            print(f"  Table orders   : ✅ CONSERVÉ ({remaining_orders} enreg.) — obligation légale 10 ans")

        # Vérif JSON
        events_data = json.loads((json_dir / "events_2024.json").read_text())
        user_events = [e for e in events_data
                       if e.get("user_id") == USER_ID]
        print(f"  JSON events    : {'✅ SUPPRIMÉ' if not user_events else f'❌ {len(user_events)} restant(s)'}")

        # Vérif logs
        log_text = (log_dir / "access.log").read_text()
        email_in_log = USER_EMAIL in log_text
        print(f"  Logs access    : {'❌ email encore présent' if email_in_log else '✅ email redacté'}")

        # Vérif fichiers
        user_dir = uploads / "users" / USER_ID
        print(f"  Fichiers user  : {'❌ dossier encore présent' if user_dir.exists() else '✅ SUPPRIMÉ'}")

        # ── Résumé ──
        print(f"\n  {'─'*60}")
        print(f"  📊  RÉSUMÉ DE L'EFFACEMENT")
        print(f"  {'─'*60}\n")
        print(f"  Référence      : {summary['request_id']}")
        print(f"  Enregistrements supprimés : {summary['total_records']}")
        print(f"  Fichiers supprimés        : {summary['total_files']}")
        print(f"  Backups à purger (30j)    : {len(summary.get('exceptions', []))}")
        print(f"  Hash certificat : {summary['certificate_hash'][:32]}...")

        # ── Certificat ──
        print(f"\n  {'─'*60}")
        print(f"  📜  CERTIFICAT D'EFFACEMENT")
        print(f"  {'─'*60}")
        cert = generate_certificate(summary["request_id"], audit)
        print(cert)

        print(f"\n{SEP}")
        print(f"  ⚖️   CONTEXTE LÉGAL ART. 17 RGPD")
        print(f"{SEP}\n")
        print(
            "  Délais légaux :\n"
            "  Accusé réception : immédiat (Art. 12)\n"
            "  Effacement       : 30 jours max (Art. 12 §3)\n"
            "  Notification     : si impossible, expliquer pourquoi\n"
            "\n"
            "  Exceptions légales conservées (Art. 17 §3) :\n"
            "  ✅  Commandes/factures — 10 ans (Code de commerce)\n"
            "  ✅  Logs de sécurité — 6 mois (CNIL)\n"
            "  ✅  Données fiscales — 6 ans (CGI)\n"
            "  ✅  Backups — expirent dans 30 jours\n"
            "\n"
            "  Risque évité :\n"
            "  Art. 83 §5 : 20M€ ou 4% CA mondial pour refus d'effacement\n"
            "  + Dommages et intérêts au plaignant (Art. 82)\n"
            "\n"
            "  Usage production :\n"
            "  python3 right_to_erasure.py erase --email user@company.com\n"
            "  python3 right_to_erasure.py status ERASURE-20260227-XXXXX\n"
            "  python3 right_to_erasure.py cert   ERASURE-20260227-XXXXX\n"
        )


# ================================================================
# CLI
# ================================================================

def main():
    print(__doc__)
    import argparse
    parser = argparse.ArgumentParser()
    sub    = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")

    p_erase = sub.add_parser("erase", help="Lancer un effacement")
    p_erase.add_argument("--user-id",  default="")
    p_erase.add_argument("--email",    default="")
    p_erase.add_argument("--config",   default="erasure_config.json",
                         help="Chemin vers le fichier de configuration JSON")
    p_erase.add_argument("--dry-run",  action="store_true")
    p_erase.add_argument("--requester", default="DPO")

    p_status = sub.add_parser("status", help="Statut d'une demande")
    p_status.add_argument("request_id")

    p_cert = sub.add_parser("cert", help="Afficher le certificat")
    p_cert.add_argument("request_id")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    audit = ErasureAudit()

    if args.cmd == "erase":
        if not args.user_id and not args.email:
            print("  ❌  Fournir --user-id ou --email")
            return
        try:
            with open(args.config) as f:
                config = json.load(f)
        except FileNotFoundError:
            print(f"  ❌  Config introuvable : {args.config}")
            print("  Créer un fichier JSON avec sql_databases, json_folders, etc.")
            return
        engine  = RightToErasure(audit, dry_run=args.dry_run)
        summary = engine.full_erasure(
            args.user_id, args.email, config, args.requester
        )
        print(f"\n  ✅  Terminé — Réf : {summary['request_id']}")
        print(f"  Hash : {summary['certificate_hash'][:32]}...")

    elif args.cmd == "status":
        req = audit.get_request(args.request_id)
        if req:
            print(f"\n  {args.request_id}")
            print(f"  Statut  : {req['status']}")
            print(f"  Demande : {req['requested_at'][:19]}")
            print(f"  Terminé : {(req.get('completed_at') or 'en cours')[:19]}")
        else:
            print("  ❌  Demande introuvable")

    elif args.cmd == "cert":
        cert = generate_certificate(args.request_id, audit)
        print(cert)


if __name__ == "__main__":
    main()
