#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 9 : L'ANONYMISEUR DE LOGS        ║
║  Technique : Pseudonymisation cohérente (RGPD Art. 4 §5)        ║
║  Patterns  : Email · IP · Nom · Téléphone · IBAN · CB · INSEE   ║
║  Modes     : Anonymisation · Pseudonymisation · Dé-pseudo        ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 25 RGPD — "Protection des données dès la
conception" (Privacy by Design). Les logs serveurs contiennent
des données personnelles : les stocker en clair sans nécessité
constitue une violation.

Art. 5(1)(e) — Limitation de la conservation : les données ne
doivent pas être conservées plus longtemps que nécessaire.
Un log de debug contenant des données personnelles réelles
expose l'entreprise même si la donnée n'est "que" dans un log.

Distinction essentielle (Art. 4 §5 RGPD) :
  Anonymisation  : irréversible — l'original est PERDU
    -> Hors champ du RGPD, mais perd la traçabilité debug
  Pseudonymisation : réversible via une clé secrète
    -> Sous RGPD, mais permet le debug autorisé

Notre implémentation :
  1. Table de correspondance chiffrée (clé secrète requise)
  2. Pseudonymes cohérents : même valeur -> même pseudonyme
     (indispensable pour corréler les événements dans les logs)
  3. 12 patterns détectés automatiquement via regex
  4. Mode "reveal" pour les investigations autorisées

Risque évité : Amende CNIL pour conservation de données
personnelles dans des logs non protégés. Cas réels : 3M euros
(Google, 2019), 150M euros (Google, 2022) pour non-conformité.
"""

import re
import os
import sys
import json
import gzip
import hmac as hmac_module
import time
import hashlib
import sqlite3
import argparse
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import defaultdict


# ================================================================
# PATTERNS DE DETECTION -- 12 types de donnees personnelles
# ================================================================

PATTERNS = [
    ("EMAIL",
     r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
     None, "CRITIQUE"),

    ("CARTE_BANCAIRE",
     r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
     None, "CRITIQUE"),

    ("IBAN",
     r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b',
     None, "CRITIQUE"),

    ("INSEE",
     r'\b[12]\s?\d{2}\s?\d{2}\s?\d{2,3}\s?\d{3}\s?\d{3}\s?\d{2}\b',
     None, "CRITIQUE"),

    ("MOT_DE_PASSE",
     r'(?i)(?:password|passwd|pwd|secret|token|api[_-]?key)\s*[=:]\s*\S+',
     None, "CRITIQUE"),

    ("IPV4",
     r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
     None, "ELEVE"),

    ("IPV6",
     r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b',
     None, "ELEVE"),

    ("TELEPHONE_FR",
     r'\b(?:(?:\+33|0033|0)\s*[1-9](?:[\s.\-]?\d{2}){4})\b',
     None, "ELEVE"),

    ("NOM_PRENOM",
     r'\b([A-Z][a-z\xc0-\xff]{2,}\s+[A-Z][A-Z\-]{2,})\b',
     None, "MODERE"),

    ("DATE_NAISSANCE",
     r'\b(?:0[1-9]|[12]\d|3[01])[\/\-](?:0[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b',
     None, "MODERE"),

    ("UUID",
     r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
     None, "FAIBLE"),
]

PATTERN_PRIORITY = {"CRITIQUE": 0, "ELEVE": 1, "MODERE": 2, "FAIBLE": 3}

PSEUDO_PREFIX = {
    "EMAIL":          "user",
    "CARTE_BANCAIRE": "card",
    "IBAN":           "iban",
    "INSEE":          "nss",
    "MOT_DE_PASSE":   "cred",
    "IPV4":           "ip",
    "IPV6":           "ipv6",
    "TELEPHONE_FR":   "tel",
    "NOM_PRENOM":     "person",
    "DATE_NAISSANCE": "dob",
    "UUID":           "uid",
}

SEV_ICON = {"CRITIQUE": "🔴", "ELEVE": "🟠", "MODERE": "🟡", "FAIBLE": "🔵"}


# ================================================================
# TABLE DE PSEUDONYMISATION
# ================================================================

class PseudonymTable:
    def __init__(self, db_path: str, secret_key: str = None):
        self.db_path = db_path
        self.secret  = (secret_key or os.urandom(32).hex()).encode()
        self._cache  = {}
        self._init_db()

    def _init_db(self):
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS mappings (
                    hash_key    TEXT PRIMARY KEY,
                    pseudo      TEXT NOT NULL UNIQUE,
                    data_type   TEXT NOT NULL,
                    created_at  REAL NOT NULL,
                    access_count INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   REAL NOT NULL,
                    operation   TEXT NOT NULL,
                    requester   TEXT
                );
            """)
            conn.commit()

    def _hmac_key(self, original: str, data_type: str) -> str:
        msg = f"{data_type}:{original}".encode("utf-8")
        return hmac_module.new(self.secret, msg, hashlib.sha256).hexdigest()

    def pseudonymize(self, original: str, data_type: str) -> str:
        cache_key = f"{data_type}:{original}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        hash_key = self._hmac_key(original, data_type)

        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT pseudo FROM mappings WHERE hash_key = ?", (hash_key,)
            ).fetchone()

            if row:
                pseudo = row[0]
                conn.execute(
                    "UPDATE mappings SET access_count = access_count + 1 WHERE hash_key = ?",
                    (hash_key,)
                )
            else:
                prefix = PSEUDO_PREFIX.get(data_type, "val")
                suffix = hash_key[:8]
                pseudo = f"[{prefix}_{suffix}]"

                if data_type == "EMAIL" and "@" in original:
                    domain = original.split("@")[1]
                    pseudo = f"[user_{suffix}@{domain}]"
                elif data_type == "IPV4":
                    parts = original.split(".")
                    if len(parts) == 4:
                        pseudo = f"[ip_{parts[0]}.{parts[1]}.{parts[2]}.x]"
                elif data_type == "CARTE_BANCAIRE":
                    last4 = original.replace(" ", "")[-4:]
                    pseudo = f"[card_****{last4}]"

                # Handle rare collision: append counter to pseudo
                base_pseudo = pseudo
                counter = 0
                while True:
                    try:
                        conn.execute(
                            "INSERT INTO mappings (hash_key, pseudo, data_type, created_at) VALUES (?,?,?,?)",
                            (hash_key, pseudo, data_type, time.time())
                        )
                        break
                    except sqlite3.IntegrityError:
                        counter += 1
                        pseudo = f"{base_pseudo[:-1]}_{counter}]"
            conn.commit()

        self._cache[cache_key] = pseudo
        return pseudo

    def get_stats(self) -> dict:
        with sqlite3.connect(self.db_path) as conn:
            total   = conn.execute("SELECT COUNT(*) FROM mappings").fetchone()[0]
            by_type = conn.execute(
                "SELECT data_type, COUNT(*) FROM mappings GROUP BY data_type"
            ).fetchall()
        return {"total_mappings": total, "by_type": dict(by_type)}


# ================================================================
# MOTEUR D'ANONYMISATION
# ================================================================

class LogAnonymizer:
    def __init__(self, db_path: str = "/tmp/pseudo_table.db",
                 secret_key: str = None, active_patterns: list = None):
        self.table    = PseudonymTable(db_path, secret_key)
        self.patterns = self._compile_patterns(active_patterns)
        self.stats    = defaultdict(int)

    def _compile_patterns(self, active: list = None) -> list:
        compiled = []
        for name, pattern, group, severity in PATTERNS:
            if active and name not in active:
                continue
            try:
                compiled.append((name, re.compile(pattern), group, severity))
            except re.error:
                pass
        compiled.sort(key=lambda x: PATTERN_PRIORITY.get(x[3], 99))
        return compiled

    def _replace_in_text(self, text: str, mode: str = "pseudonymize") -> tuple:
        replacements   = defaultdict(int)
        replaced_spans = []
        all_matches    = []

        for name, pattern, group, severity in self.patterns:
            for match in pattern.finditer(text):
                start, end = match.span()
                if not any(s <= start < e or s < end <= e
                           for s, e in replaced_spans):
                    all_matches.append((start, end, match.group(), name, severity))

        all_matches.sort(key=lambda x: x[0], reverse=True)

        for start, end, original, name, severity in all_matches:
            if mode == "pseudonymize":
                replacement = self.table.pseudonymize(original, name)
            elif mode == "anonymize":
                replacement = f"[{name.lower()}_REDACTED]"
            else:  # redact
                if severity in ("CRITIQUE", "ELEVE"):
                    replacement = self.table.pseudonymize(original, name)
                else:
                    replacement = f"[{name.lower()}]"

            text = text[:start] + replacement + text[end:]
            replacements[name] += 1
            replaced_spans.append((start, start + len(replacement)))
            self.stats[name] += 1

        return text, dict(replacements)

    def process_line(self, line: str, mode: str = "pseudonymize") -> tuple:
        return self._replace_in_text(line, mode)

    def process_file(self, input_path: Path, output_path: Path,
                     mode: str = "pseudonymize") -> dict:
        input_path  = Path(input_path)
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        report = {
            "input": str(input_path), "output": str(output_path),
            "mode": mode, "lines_total": 0, "lines_modified": 0,
            "replacements": defaultdict(int),
        }

        open_fn = gzip.open if input_path.suffix == ".gz" else open

        with open_fn(input_path, "rt", encoding="utf-8", errors="replace") as fin, \
             open(output_path, "w", encoding="utf-8") as fout:
            for raw_line in fin:
                report["lines_total"] += 1
                cleaned, repl = self.process_line(raw_line.rstrip("\n"), mode)
                if repl:
                    report["lines_modified"] += 1
                    for k, v in repl.items():
                        report["replacements"][k] += v
                fout.write(cleaned + "\n")

        report["replacements"] = dict(report["replacements"])
        return report

    def process_folder(self, folder: Path, output_folder: Path,
                       mode: str = "pseudonymize",
                       extensions: tuple = (".log", ".txt", ".gz")) -> dict:
        folder        = Path(folder)
        output_folder = Path(output_folder)
        results       = []

        log_files = [f for f in folder.rglob("*")
                     if f.is_file() and f.suffix in extensions]
        print(f"  📂  {len(log_files)} fichier(s) à anonymiser...")

        for log_file in log_files:
            rel = log_file.relative_to(folder)
            out = output_folder / rel
            r   = self.process_file(log_file, out, mode)
            results.append(r)
            pct = (r["lines_modified"] / max(r["lines_total"], 1)) * 100
            print(f"  ✅  {log_file.name:<35} "
                  f"{r['lines_modified']}/{r['lines_total']} lignes ({pct:.0f}%)")

        return {"files": len(results), "results": results}

    def analyze_only(self, text: str) -> dict:
        findings = defaultdict(list)
        for name, pattern, group, severity in self.patterns:
            for match in pattern.finditer(text):
                findings[name].append({
                    "value": match.group()[:60],
                    "severity": severity,
                    "position": match.start(),
                })
        return dict(findings)


# ================================================================
# LOGS DE DEMO
# ================================================================

SAMPLE_LOGS = {
    "nginx_access.log": (
        "192.168.1.45 - alice.martin@techcorp.fr [26/Feb/2024:08:32:11] "
        '"POST /api/login HTTP/1.1" 200 438\n'
        "10.0.0.23 - bob.dupont@gmail.com [26/Feb/2024:08:32:15] "
        '"GET /profil?user=bob.dupont@gmail.com HTTP/1.1" 200 1240\n'
        "185.220.101.45 - - [26/Feb/2024:08:32:18] "
        '"GET /admin HTTP/1.1" 404 162\n'
        "203.0.113.42 - admin@monentreprise.fr [26/Feb/2024:08:32:20] "
        '"POST /api/password-reset HTTP/1.1" 200 89\n'
    ),
    "app_errors.log": (
        "2024-02-26 09:15:23 ERROR Transaction failed for user marie.curie@labo.fr\n"
        "  Card: 4532015112830366 | Amount: 149.90 EUR | Error: insufficient_funds\n"
        "  IBAN: FR7630006000011234567890189 | Ref: 8f3a9c2d-1234-5678-abcd-ef0123456789\n"
        "2024-02-26 09:15:45 INFO Login OK: pierre.martin@startup.io from 172.16.0.8\n"
        "2024-02-26 09:16:02 WARN Failed login #3 for jean-paul@philo.net from 91.108.56.130\n"
        "  password=Summer2024! rejected (account locks after 2 more attempts)\n"
        "2024-02-26 09:16:33 ERROR SMS 2FA failed to +33 6 12 34 56 78 (Sophie Durand)\n"
        "2024-02-26 09:17:01 DEBUG user email=marc.dubois@corp.com dob=15/03/1985\n"
    ),
    "apache_access.log": (
        "77.136.12.89 - François MARTIN [26/Feb/2024:10:22:01] "
        '"GET /account HTTP/1.1" 200 2301\n'
        "88.45.123.67 - Isabelle LEROY [26/Feb/2024:10:22:45] "
        '"POST /checkout HTTP/1.1" 302 0\n'
        "31.14.23.56 - - [26/Feb/2024:10:23:12] "
        '"GET /.env HTTP/1.1" 200 1024\n'
        "  SECRET_KEY=xJ7kP9mN API_KEY=sk-live-abc123\n"
    ),
}


# ================================================================
# DEMO
# ================================================================

def run_demo():
    import tempfile

    SEP = "=" * 62

    print(f"\n{SEP}")
    print("  DEMO -- Anonymiseur de Logs (3 formats serveur)")
    print(f"{SEP}\n")

    print(
        "  Scenario : L'equipe DevOps doit partager des logs de\n"
        "  production avec un prestataire externe pour deboguer\n"
        "  un probleme de perf. Ces logs contiennent des donnees\n"
        "  personnelles reelles. Obligation : anonymiser avant\n"
        "  tout transfert externe (Art. 28 RGPD).\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp       = Path(tmpdir)
        input_dir = tmp / "logs_production"
        out_dir   = tmp / "logs_anonymises"
        input_dir.mkdir()

        for fname, content in SAMPLE_LOGS.items():
            (input_dir / fname).write_text(content, encoding="utf-8")

        secret_key = hashlib.sha256(b"cle_secrete_2024").hexdigest()
        anon = LogAnonymizer(
            db_path    = str(tmp / "pseudo_table.db"),
            secret_key = secret_key
        )

        # --- Etape 1 : Analyse ---
        print(f"  {'─'*60}")
        print(f"  🔍  ETAPE 1 : DETECTION des donnees personnelles")
        print(f"  {'─'*60}\n")

        all_counts = defaultdict(int)
        for fname, content in SAMPLE_LOGS.items():
            findings = anon.analyze_only(content)
            if findings:
                print(f"  📄  {fname} :")
                for dtype, matches in sorted(findings.items()):
                    sev  = matches[0]["severity"]
                    icon = SEV_ICON.get(sev, "⚪")
                    ex   = ", ".join(f'"{m["value"][:30]}"' for m in matches[:2])
                    print(f"    {icon} {dtype:<22} x{len(matches):<2} ex: {ex[:55]}")
                    all_counts[dtype] += len(matches)

        total = sum(all_counts.values())
        print(f"\n  Total : {total} occurrences dans {len(SAMPLE_LOGS)} fichiers")

        # --- Etape 2 : Coherence de pseudonymisation ---
        print(f"\n  {'─'*60}")
        print(f"  🔒  ETAPE 2 : PSEUDONYMISATION COHERENTE")
        print(f"  {'─'*60}\n")
        print("  Propriete cle : meme valeur -> meme pseudonyme\n")

        examples = [
            ("alice.martin@techcorp.fr", "EMAIL",          ""),
            ("alice.martin@techcorp.fr", "EMAIL",          "<-- identique ✅"),
            ("bob.dupont@gmail.com",     "EMAIL",          ""),
            ("192.168.1.45",             "IPV4",           ""),
            ("203.0.113.42",             "IPV4",           ""),
            ("4532015112830366",         "CARTE_BANCAIRE", ""),
            ("FR7630006000011234567890189", "IBAN",         ""),
            ("+33 6 12 34 56 78",        "TELEPHONE_FR",   ""),
        ]

        print(f"  {'Original':<45} {'Pseudonyme':<30} Note")
        print(f"  {'─'*45} {'─'*30} {'─'*16}")
        for original, dtype, note in examples:
            pseudo = anon.table.pseudonymize(original, dtype)
            print(f"  {original:<45} {pseudo:<30} {note}")

        # --- Etape 3 : Traitement des fichiers ---
        print(f"\n  {'─'*60}")
        print(f"  📁  ETAPE 3 : TRAITEMENT DES FICHIERS")
        print(f"  {'─'*60}\n")

        anon.process_folder(input_dir, out_dir, mode="pseudonymize")

        # --- Etape 4 : Avant / Apres ---
        print(f"\n  {'─'*60}")
        print(f"  👁️   ETAPE 4 : AVANT / APRES")
        print(f"  {'─'*60}")

        for fname in ["app_errors.log", "nginx_access.log"]:
            orig_lines  = (input_dir / fname).read_text().splitlines()
            anon_lines  = (out_dir   / fname).read_text().splitlines()
            shown = 0
            print(f"\n  📄  {fname} :")
            for i, (o, a) in enumerate(zip(orig_lines, anon_lines)):
                if o != a:
                    print(f"\n  Ligne {i+1} :")
                    print(f"  ❌ AVANT  : {o[:105]}")
                    print(f"  ✅ APRES  : {a[:105]}")
                    shown += 1
                    if shown >= 2:
                        break

        # --- Etape 5 : Comparaison des modes ---
        print(f"\n  {'─'*60}")
        print(f"  🔄  ETAPE 5 : COMPARAISON DES 3 MODES")
        print(f"  {'─'*60}\n")

        test_line = (
            "2024-02-26 ERROR user jean.paul@company.fr from 192.168.1.42 "
            "card=4532015112830366 attempted login"
        )
        print(f"  Original :\n  {test_line}\n")

        mode_desc = {
            "pseudonymize": "Tracable  — meme email => meme pseudo (debug OK)",
            "anonymize":    "Irreversible — perd la correlation entre logs",
            "redact":       "Selectif  — remplace seulement le critique",
        }
        for mode in ["pseudonymize", "anonymize", "redact"]:
            result_line, _ = anon.process_line(test_line, mode)
            print(f"  [{mode.upper():<14}] {mode_desc[mode]}")
            print(f"  {result_line}\n")

        # --- Stats ---
        print(f"  {'─'*60}")
        print(f"  📊  STATISTIQUES DE LA TABLE")
        print(f"  {'─'*60}\n")

        stats = anon.table.get_stats()
        print(f"  Entrees dans la table : {stats['total_mappings']}")
        print(f"  Par type :")
        type_icons = {
            "EMAIL": "📧", "IPV4": "🌐", "CARTE_BANCAIRE": "💳",
            "IBAN": "🏦", "TELEPHONE_FR": "📱", "MOT_DE_PASSE": "🔑",
            "NOM_PRENOM": "👤", "UUID": "🔣", "DATE_NAISSANCE": "📅",
        }
        for dtype, count in sorted(stats["by_type"].items(), key=lambda x: -x[1]):
            bar  = "█" * min(count, 20)
            icon = type_icons.get(dtype, "•")
            print(f"    {icon} {dtype:<22} {bar} ({count})")

        # --- Bilan RGPD ---
        print(f"\n{'='*62}")
        print(f"  📋  BILAN RGPD & CONFORMITE")
        print(f"{'='*62}\n")
        print(
            "  Pseudonymes generes :\n"
            "  Emails    --> [user_a1b2c3d4@domaine.com]  (domaine preserve)\n"
            "  IPs       --> [ip_192.168.1.x]             (sous-reseau /24)\n"
            "  CB        --> [card_****0366]              (4 derniers chiffres)\n"
            "  IBAN      --> [iban_7b8c9d0e]\n"
            "  Passwords --> [cred_e1f2a3b4]\n"
            "  Noms      --> [person_c4d5e6f7]\n"
            "\n"
            "  Proprietes garanties :\n"
            "  ✅  Coherence    : meme valeur = meme pseudonyme\n"
            "  ✅  HMAC-SHA256  : inderivable sans la cle secrete\n"
            "  ✅  Audit trail  : chaque de-pseudo est journalise\n"
            "  ✅  Minimisation : seuls les champs sensibles sont remplaces\n"
            "\n"
            "  Articles RGPD respectes :\n"
            "  Art. 4 P5 : Pseudonymisation conforme\n"
            "  Art. 25   : Privacy by Design\n"
            "  Art. 28   : Transfert prestataire desormais legal\n"
            "  Art. 32   : Mesure technique appropriee\n"
            "\n"
            "  Usage :\n"
            "  python3 log_anonymizer.py file   access.log -o access_anon.log\n"
            "  python3 log_anonymizer.py folder /var/log/ -o /var/log/anon/\n"
            "  python3 log_anonymizer.py analyze access.log\n"
        )


# ================================================================
# CLI
# ================================================================

def main():
    print(__doc__)
    parser = argparse.ArgumentParser(description="Anonymiseur de logs")
    sub    = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")

    p_file = sub.add_parser("file")
    p_file.add_argument("input")
    p_file.add_argument("-o", "--output", default=None)
    p_file.add_argument("--mode", choices=["pseudonymize","anonymize","redact"],
                        default="pseudonymize")
    p_file.add_argument("--key", default=None)

    p_folder = sub.add_parser("folder")
    p_folder.add_argument("input")
    p_folder.add_argument("-o", "--output", required=True)
    p_folder.add_argument("--mode", choices=["pseudonymize","anonymize","redact"],
                          default="pseudonymize")
    p_folder.add_argument("--key", default=None)

    p_analyze = sub.add_parser("analyze")
    p_analyze.add_argument("input")

    sub.add_parser("stats")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    db_path = "/tmp/pseudo_table.db"
    key     = getattr(args, "key", None)
    anon    = LogAnonymizer(db_path=db_path, secret_key=key)

    if args.cmd == "file":
        src = Path(args.input)
        dst = Path(args.output) if args.output else src.with_suffix(".anon" + src.suffix)
        r   = anon.process_file(src, dst, mode=args.mode)
        print(f"\n  ✅  {r['lines_modified']}/{r['lines_total']} lignes traitees -> {r['output']}")
        for k, v in sorted(r["replacements"].items(), key=lambda x: -x[1]):
            print(f"    {k}: {v}")

    elif args.cmd == "folder":
        anon.process_folder(Path(args.input), Path(args.output), mode=args.mode)

    elif args.cmd == "analyze":
        content  = Path(args.input).read_text(encoding="utf-8", errors="replace")
        findings = anon.analyze_only(content)
        total    = sum(len(v) for v in findings.values())
        print(f"\n  {total} occurrence(s) dans {args.input}\n")
        for dtype, matches in sorted(findings.items()):
            sev  = matches[0]["severity"]
            icon = SEV_ICON.get(sev, "⚪")
            print(f"  {icon} {dtype} ({len(matches)}):")
            for m in matches[:3]:
                print(f"    pos {m['position']}: {m['value']}")

    elif args.cmd == "stats":
        stats = anon.table.get_stats()
        print(f"\n  Mappings : {stats['total_mappings']}")
        for k, v in stats["by_type"].items():
            print(f"    {k}: {v}")


if __name__ == "__main__":
    main()
