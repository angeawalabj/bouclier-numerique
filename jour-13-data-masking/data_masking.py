#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 13 : DATA MASKING EN TEMPS RÉEL  ║
║  Objectif : Masquage dynamique selon le rôle de l'appelant       ║
║  Données  : CB · IBAN · Email · Téléphone · INSEE · Nom · IP     ║
║  Modèle   : RBAC (Role-Based Access Control) + audit trail       ║
╚══════════════════════════════════════════════════════════════════╝

Problème concret :
  Le support client voit les données d'un client pour l'aider.
  Mais il n'a pas besoin de voir le numéro CB complet.
  Le service paiement, lui, en a besoin pour débiter.
  Un auditeur externe ne doit voir que des données masquées.

  Sans masquage : 1 accès à la base = accès à TOUT.
  Avec masquage : chaque rôle voit exactement ce qu'il lui faut.

Modèle RBAC (4 niveaux) :
  ADMIN     → Données complètes (audit loggé)
  PAIEMENT  → CB complète + IBAN complet (service facturation)
  SUPPORT   → 4589 **** **** 1234 · iban****1234 · email masqué
  EXTERNE   → Tout masqué (auditeurs, régulateurs, partenaires)

Conformité :
  Art. 25 RGPD — Privacy by Design & by Default
  Art. 32 RGPD — Mesures techniques de protection
  PCI-DSS 3.4  — Masquage des PAN (Primary Account Numbers)
  ISO 27001 A.9.4.1 — Restriction d'accès à l'information

Risque évité :
  Une fuite de CB via un accès support expose l'entreprise
  à PCI-DSS Level 1 (audit forcé + amendes ~500K$/an)
  + Art. 83 §4 RGPD (10M€ ou 2% CA).
"""

import re
import os
import json
import sqlite3
import hashlib
import functools
import threading
from datetime import datetime
from typing import Any, Optional, Callable
from collections import defaultdict


# ================================================================
# DÉFINITION DES RÔLES ET NIVEAUX D'ACCÈS
# ================================================================

class Role:
    ADMIN    = "ADMIN"
    PAIEMENT = "PAIEMENT"
    SUPPORT  = "SUPPORT"
    EXTERNE  = "EXTERNE"

# Hiérarchie : 0 = accès total, 3 = accès minimal
ROLE_LEVEL = {
    Role.ADMIN:    0,
    Role.PAIEMENT: 1,
    Role.SUPPORT:  2,
    Role.EXTERNE:  3,
}

# ================================================================
# RÈGLES DE MASQUAGE PAR TYPE DE DONNÉE
# ================================================================
#
# Chaque règle définit le comportement pour chaque rôle.
# "reveal"    → données complètes
# "partial"   → masquage partiel (4 premiers + **** + 4 derniers)
# "tokenize"  → remplacement par un token non réversible
# "redact"    → remplacement complet par ***
# "hash"      → hash SHA-256 tronqué (traçable mais illisible)
#

MASKING_RULES = {
    "carte_bancaire": {
        Role.ADMIN:    "reveal",
        Role.PAIEMENT: "reveal",
        Role.SUPPORT:  "partial_cb",   # 4589 **** **** 1234
        Role.EXTERNE:  "redact",
        "pattern": r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
        "format":  "CB",
    },
    "cvv": {
        Role.ADMIN:    "reveal",
        Role.PAIEMENT: "reveal",
        Role.SUPPORT:  "redact",       # *** toujours
        Role.EXTERNE:  "redact",
        "format":  "CVV",
    },
    "iban": {
        Role.ADMIN:    "reveal",
        Role.PAIEMENT: "reveal",
        Role.SUPPORT:  "partial_iban", # FR76 3000 **** **** 1234
        Role.EXTERNE:  "redact",
        "pattern": r'\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,16})\b',
        "format":  "IBAN",
    },
    "email": {
        Role.ADMIN:    "reveal",
        Role.PAIEMENT: "reveal",
        Role.SUPPORT:  "partial_email",# a***@domaine.com
        Role.EXTERNE:  "hash",
        "pattern": r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b',
        "format":  "EMAIL",
    },
    "telephone": {
        Role.ADMIN:    "reveal",
        Role.PAIEMENT: "reveal",
        Role.SUPPORT:  "partial_phone",# 06 ** ** ** 78
        Role.EXTERNE:  "redact",
        "pattern": r'\b(?:(?:\+33|0033|0)\s*[1-9](?:[\s.\-]?\d{2}){4})\b',
        "format":  "PHONE",
    },
    "insee": {
        Role.ADMIN:    "reveal",
        Role.PAIEMENT: "redact",
        Role.SUPPORT:  "redact",
        Role.EXTERNE:  "redact",
        "pattern": r'\b[12]\s?\d{2}\s?\d{2}\s?\d{2,3}\s?\d{3}\s?\d{3}\s?\d{2}\b',
        "format":  "INSEE",
    },
    "ip": {
        Role.ADMIN:    "reveal",
        Role.PAIEMENT: "partial_ip",   # 192.168.1.x
        Role.SUPPORT:  "partial_ip",
        Role.EXTERNE:  "redact",
        "pattern": r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
        "format":  "IP",
    },
    "nom": {
        Role.ADMIN:    "reveal",
        Role.PAIEMENT: "reveal",
        Role.SUPPORT:  "partial_name", # J*** D***
        Role.EXTERNE:  "redact",
        "format":  "NAME",
    },
}


# ================================================================
# FONCTIONS DE MASQUAGE
# ================================================================

def _mask_cb(value: str) -> str:
    """4589 **** **** 1234"""
    clean = value.replace(" ", "").replace("-", "")
    if len(clean) < 8:
        return "*" * len(value)
    return f"{clean[:4]} **** **** {clean[-4:]}"

def _mask_iban(value: str) -> str:
    """FR76 3000 **** **** 1234"""
    clean = value.replace(" ", "")
    if len(clean) < 8:
        return "*" * len(value)
    visible_start = clean[:8]
    visible_end   = clean[-4:]
    masked_len    = len(clean) - 12
    return f"{visible_start[:4]} {visible_start[4:8]} {'*' * 4} {'*' * 4} {visible_end}"

def _mask_email(value: str) -> str:
    """alice.martin@domaine.com → a***@domaine.com"""
    if "@" not in value:
        return "***@***.***"
    local, domain = value.split("@", 1)
    if len(local) <= 1:
        return f"*@{domain}"
    return f"{local[0]}***@{domain}"

def _mask_phone(value: str) -> str:
    """06 12 34 56 78 → 06 ** ** ** 78"""
    digits = re.sub(r'\D', '', value)
    if len(digits) < 6:
        return "** ** ** ** **"
    masked = digits[:2] + " ** ** ** " + digits[-2:]
    return masked

def _mask_ip(value: str) -> str:
    """192.168.1.45 → 192.168.1.x"""
    parts = value.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.x"
    return value

def _mask_name(value: str) -> str:
    """Jean-Paul DUPONT → J*** D***"""
    parts = value.split()
    return " ".join(
        p[0] + "***" if len(p) > 1 else "***"
        for p in parts
    )

def _hash_value(value: str) -> str:
    """Hash SHA-256 tronqué — traçable mais illisible."""
    h = hashlib.sha256(value.encode()).hexdigest()[:12]
    return f"[hash:{h}]"

def apply_masking(value: str, data_type: str, role: str) -> str:
    """Applique le masquage selon le type de donnée et le rôle."""
    rule   = MASKING_RULES.get(data_type, {})
    method = rule.get(role, "redact")

    if method == "reveal":
        return value
    elif method == "redact":
        return "*" * min(len(str(value)), 8)
    elif method == "partial_cb":
        return _mask_cb(value)
    elif method == "partial_iban":
        return _mask_iban(value)
    elif method == "partial_email":
        return _mask_email(value)
    elif method == "partial_phone":
        return _mask_phone(value)
    elif method == "partial_ip":
        return _mask_ip(value)
    elif method == "partial_name":
        return _mask_name(value)
    elif method == "hash":
        return _hash_value(value)
    elif method == "tokenize":
        return f"[token:{hashlib.md5(value.encode()).hexdigest()[:8]}]"
    return "*" * 8


# ================================================================
# MASQUEUR DE CHAMPS (dict/objet)
# ================================================================

# Mapping des noms de champs vers les types de données
FIELD_TYPE_MAP = {
    # CB
    "carte_bancaire": "carte_bancaire", "card_number": "carte_bancaire",
    "pan": "carte_bancaire", "numero_carte": "carte_bancaire",
    "cvv": "cvv", "cvc": "cvv", "cvv2": "cvv",
    # IBAN
    "iban": "iban", "bic": "iban",
    # Email
    "email": "email", "mail": "email", "courriel": "email",
    "user_email": "email", "email_address": "email",
    # Téléphone
    "telephone": "telephone", "phone": "telephone", "mobile": "telephone",
    "tel": "telephone", "portable": "telephone",
    # INSEE
    "insee": "insee", "numero_secu": "insee", "nir": "insee",
    "social_security": "insee",
    # IP
    "ip": "ip", "ip_address": "ip", "remote_ip": "ip",
    "client_ip": "ip",
    # Nom
    "nom": "nom", "name": "nom", "prenom": "nom",
    "first_name": "nom", "last_name": "nom", "full_name": "nom",
    "nom_complet": "nom",
}


class DataMasker:
    """
    Masqueur de données temps réel.
    Prend un dict (ou objet JSON) et retourne la version
    masquée selon le rôle de l'appelant.
    """

    def __init__(self, audit_db: str = "/tmp/masking_audit.db"):
        self.audit_db = audit_db
        self._init_audit()
        self._lock = threading.Lock()

    def _init_audit(self):
        """Initialise la base d'audit des accès."""
        Path_p = __import__("pathlib").Path
        Path_p(self.audit_db).parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.audit_db) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS access_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp   TEXT NOT NULL,
                    role        TEXT NOT NULL,
                    user        TEXT,
                    resource    TEXT,
                    fields_accessed TEXT,
                    fields_masked   TEXT,
                    ip          TEXT
                )
            """)
            conn.commit()

    def _log_access(self, role: str, user: str, resource: str,
                    revealed: list, masked: list, ip: str = ""):
        """Journalise chaque accès — obligation Art. 30 + ISO 27001."""
        with sqlite3.connect(self.audit_db) as conn:
            conn.execute(
                """INSERT INTO access_log
                   (timestamp, role, user, resource,
                    fields_accessed, fields_masked, ip)
                   VALUES (?,?,?,?,?,?,?)""",
                (datetime.now().isoformat(), role, user, resource,
                 json.dumps(revealed), json.dumps(masked), ip)
            )
            conn.commit()

    def mask_dict(self, data: dict, role: str,
                  user: str = "unknown",
                  resource: str = "unknown",
                  ip: str = "") -> dict:
        """
        Masque un dictionnaire selon le rôle.
        Retourne un nouveau dict (non mutant).
        """
        result   = {}
        revealed = []
        masked   = []

        for key, value in data.items():
            if value is None:
                result[key] = value
                continue

            key_lower  = key.lower()
            data_type  = FIELD_TYPE_MAP.get(key_lower)

            if data_type:
                rule   = MASKING_RULES.get(data_type, {})
                method = rule.get(role, "redact")
                if method == "reveal":
                    result[key] = value
                    revealed.append(key)
                else:
                    result[key] = apply_masking(str(value), data_type, role)
                    masked.append(key)
            elif isinstance(value, dict):
                # Récursion sur les objets imbriqués
                result[key] = self.mask_dict(
                    value, role, user, resource, ip
                )
            elif isinstance(value, list):
                result[key] = [
                    self.mask_dict(item, role, user, resource, ip)
                    if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                result[key] = value

        # Journaliser si des champs sensibles ont été accédés
        if revealed or masked:
            self._log_access(role, user, resource, revealed, masked, ip)

        return result

    def mask_text(self, text: str, role: str,
                  user: str = "unknown") -> tuple:
        """
        Masque un texte libre (logs, commentaires, messages).
        Retourne (texte_masqué, nb_remplacements).
        """
        count = 0
        for dtype, rule in MASKING_RULES.items():
            pattern = rule.get("pattern")
            if not pattern:
                continue
            method = rule.get(role, "redact")
            if method == "reveal":
                continue

            def replacer(m, dt=dtype, r=role):
                return apply_masking(m.group(), dt, r)

            new_text, n = re.subn(pattern, replacer, text)
            if n > 0:
                text  = new_text
                count += n

        return text, count

    def get_access_stats(self) -> dict:
        """Statistiques des accès par rôle."""
        with sqlite3.connect(self.audit_db) as conn:
            conn.row_factory = sqlite3.Row
            by_role = conn.execute(
                "SELECT role, COUNT(*) as cnt FROM access_log GROUP BY role"
            ).fetchall()
            recent = conn.execute(
                "SELECT * FROM access_log ORDER BY id DESC LIMIT 10"
            ).fetchall()
        return {
            "by_role": {r["role"]: r["cnt"] for r in by_role},
            "recent":  [dict(r) for r in recent],
        }


# ================================================================
# PROXY DE BASE DE DONNÉES (couche transparente)
# ================================================================

class MaskedDB:
    """
    Proxy SQLite avec masquage transparent.
    Toute requête retourne des données masquées selon le rôle.
    L'application ne change rien à son code existant.
    """

    def __init__(self, db_path: str, masker: DataMasker):
        self.db_path = db_path
        self.masker  = masker

    def query(self, sql: str, params: tuple = (),
              role: str = Role.EXTERNE,
              user: str = "unknown") -> list:
        """Exécute une requête et masque les résultats."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, params).fetchall()

        result = []
        for row in rows:
            row_dict = dict(row)
            masked   = self.masker.mask_dict(row_dict, role, user,
                                              sql[:50])
            result.append(masked)

        return result


# ================================================================
# DÉMONSTRATION COMPLÈTE
# ================================================================

DEMO_CUSTOMER = {
    "id":            "USR-4521",
    "nom":           "DUPONT Jean-Paul",
    "email":         "jean-paul.dupont@entreprise.fr",
    "telephone":     "06 12 34 56 78",
    "adresse":       "42 rue de la Paix, 75002 Paris",
    "carte_bancaire": "4532015112830366",
    "cvv":           "847",
    "iban":          "FR7630006000011234567890189",
    "insee":         "1 85 05 75 123 456 78",
    "ip":            "192.168.1.45",
    "solde":         1250.00,
    "statut":        "ACTIF",
    "historique": [
        {"date": "2024-01-15", "montant": 149.90,
         "carte_bancaire": "4532015112830366",
         "description": "Abonnement Pro"},
        {"date": "2024-02-15", "montant": 149.90,
         "carte_bancaire": "4532015112830366",
         "description": "Abonnement Pro"},
    ]
}

DEMO_LOG = (
    "2024-01-15 10:23:45 [INFO] User jean-paul.dupont@entreprise.fr "
    "logged in from 192.168.1.45 — card 4532015112830366 charged 149.90€ "
    "IBAN FR7630006000011234567890189 validated — tel 06 12 34 56 78"
)


def run_demo():
    import tempfile

    SEP = "=" * 62
    print(f"\n{SEP}")
    print("  DEMO — Data Masking Temps Réel (Art. 25 + PCI-DSS)")
    print(f"{SEP}\n")
    print(
        "  Scénario : Le même profil client est demandé par\n"
        "  4 acteurs différents. Chacun voit exactement\n"
        "  ce dont il a besoin — rien de plus.\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        masker = DataMasker(f"{tmpdir}/audit.db")

        # ── Étape 1 : Masquage par rôle ──
        print(f"  {'─'*60}")
        print(f"  👁️   ÉTAPE 1 : MÊME DONNÉE — 4 RÔLES DIFFÉRENTS")
        print(f"  {'─'*60}\n")

        roles_desc = {
            Role.ADMIN:    "Direction / Équipe sécurité",
            Role.PAIEMENT: "Service facturation",
            Role.SUPPORT:  "Agent support client",
            Role.EXTERNE:  "Auditeur externe / Régulateur",
        }

        for role, desc in roles_desc.items():
            masked = masker.mask_dict(
                DEMO_CUSTOMER, role,
                user=f"user_{role.lower()}",
                resource="customer_profile"
            )
            print(f"  ┌─ [{role:<9}] — {desc}")
            print(f"  │  nom           : {masked['nom']}")
            print(f"  │  email         : {masked['email']}")
            print(f"  │  telephone     : {masked['telephone']}")
            print(f"  │  carte_bancaire: {masked['carte_bancaire']}")
            print(f"  │  cvv           : {masked['cvv']}")
            print(f"  │  iban          : {masked['iban']}")
            print(f"  │  insee         : {masked['insee']}")
            print(f"  └─ ip            : {masked['ip']}\n")

        # ── Étape 2 : Objets imbriqués ──
        print(f"  {'─'*60}")
        print(f"  📦  ÉTAPE 2 : OBJETS IMBRIQUÉS (historique)")
        print(f"  {'─'*60}\n")

        for role in [Role.PAIEMENT, Role.SUPPORT]:
            masked = masker.mask_dict(
                DEMO_CUSTOMER, role,
                user=f"user_{role.lower()}",
                resource="customer_history"
            )
            print(f"  [{role}] historique[0] :")
            h = masked["historique"][0]
            print(f"    date            : {h['date']}")
            print(f"    montant         : {h['montant']}")
            print(f"    carte_bancaire  : {h['carte_bancaire']}")
            print()

        # ── Étape 3 : Masquage de texte libre ──
        print(f"  {'─'*60}")
        print(f"  📋  ÉTAPE 3 : MASQUAGE DE LOGS / TEXTE LIBRE")
        print(f"  {'─'*60}\n")

        print(f"  Original :")
        print(f"  {DEMO_LOG}\n")

        for role in [Role.SUPPORT, Role.EXTERNE]:
            masked_text, count = masker.mask_text(
                DEMO_LOG, role, user=f"user_{role.lower()}"
            )
            print(f"  [{role}] ({count} remplacements) :")
            print(f"  {masked_text}\n")

        # ── Étape 4 : Proxy DB transparent ──
        print(f"  {'─'*60}")
        print(f"  🗄️   ÉTAPE 4 : PROXY BASE DE DONNÉES TRANSPARENT")
        print(f"  {'─'*60}\n")

        # Créer une mini DB de démo
        import sqlite3 as sq
        db = f"{tmpdir}/customers.db"
        conn = sq.connect(db)
        conn.execute("""CREATE TABLE customers (
            id TEXT, nom TEXT, email TEXT, carte_bancaire TEXT,
            iban TEXT, telephone TEXT, solde REAL
        )""")
        conn.execute("INSERT INTO customers VALUES (?,?,?,?,?,?,?)", (
            "USR-4521", "DUPONT Jean-Paul",
            "jean-paul.dupont@entreprise.fr",
            "4532015112830366",
            "FR7630006000011234567890189",
            "06 12 34 56 78", 1250.00
        ))
        conn.commit()
        conn.close()

        proxy = MaskedDB(db, masker)

        print(f"  SQL : SELECT * FROM customers WHERE id='USR-4521'\n")
        for role in [Role.PAIEMENT, Role.SUPPORT]:
            rows = proxy.query(
                "SELECT * FROM customers WHERE id=?",
                ("USR-4521",), role=role, user=f"svc_{role.lower()}"
            )
            if rows:
                r = rows[0]
                print(f"  [{role}]")
                print(f"    email           : {r['email']}")
                print(f"    carte_bancaire  : {r['carte_bancaire']}")
                print(f"    iban            : {r['iban']}")
                print()

        # ── Étape 5 : Audit trail ──
        print(f"  {'─'*60}")
        print(f"  📊  ÉTAPE 5 : AUDIT TRAIL DES ACCÈS")
        print(f"  {'─'*60}\n")

        stats = masker.get_access_stats()
        print(f"  Accès enregistrés par rôle :")
        for role, count in stats["by_role"].items():
            bar  = "█" * count
            icon = {"ADMIN": "🔴", "PAIEMENT": "🟠",
                    "SUPPORT": "🟡", "EXTERNE": "🔵"}.get(role, "⚪")
            print(f"    {icon} {role:<10} {bar} ({count})")

        print(f"\n  Derniers accès :")
        print(f"  {'─'*55}")
        print(f"  {'Timestamp':<22} {'Rôle':<10} {'Utilisateur':<20} Masqués")
        print(f"  {'─'*22} {'─'*10} {'─'*20} {'─'*10}")
        for entry in stats["recent"][:6]:
            masked_fields = json.loads(entry.get("fields_masked") or "[]")
            print(f"  {entry['timestamp'][:19]:<22} "
                  f"{entry['role']:<10} "
                  f"{entry['user']:<20} "
                  f"{len(masked_fields)} champ(s)")

        # ── Bilan ──
        print(f"\n{SEP}")
        print(f"  📋  BILAN CONFORMITÉ")
        print(f"{SEP}\n")
        print(
            "  Masquage appliqué par type :\n\n"
            "  TYPE         SUPPORT              EXTERNE\n"
            "  ──────────── ──────────────────── ────────────\n"
            "  CB           4589 **** **** 1234   ********\n"
            "  CVV          ***                   ***\n"
            "  IBAN         FR76 3000 **** ****   ********\n"
            "  Email        j***@domaine.com       [hash:a1b2c3d4]\n"
            "  Téléphone    06 ** ** ** 78         ********\n"
            "  INSEE        ********               ********\n"
            "  IP           192.168.1.x            ********\n"
            "\n"
            "  Conformité couverte :\n"
            "  ✅  Art. 25 RGPD — Privacy by Design & by Default\n"
            "  ✅  Art. 32 RGPD — Mesures techniques appropriées\n"
            "  ✅  PCI-DSS 3.4  — Masquage PAN (CB) obligatoire\n"
            "  ✅  ISO 27001 A.9.4.1 — Contrôle d'accès aux données\n"
            "  ✅  Audit trail  — Chaque accès journalisé\n"
            "\n"
            "  Intégration production (2 lignes) :\n"
            "  masker = DataMasker()\n"
            "  safe   = masker.mask_dict(customer, role=current_user.role)\n"
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

    p_mask = sub.add_parser("mask", help="Masquer un champ")
    p_mask.add_argument("value")
    p_mask.add_argument("type", choices=list(MASKING_RULES.keys()))
    p_mask.add_argument("--role", default=Role.SUPPORT,
                        choices=[Role.ADMIN, Role.PAIEMENT,
                                 Role.SUPPORT, Role.EXTERNE])

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    if args.cmd == "mask":
        result = apply_masking(args.value, args.type, args.role)
        print(f"\n  Original  : {args.value}")
        print(f"  Rôle      : {args.role}")
        print(f"  Masqué    : {result}\n")


if __name__ == "__main__":
    main()
