#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 3 : LE DÉTECTEUR DE FUITES       ║
║  API  : Have I Been Pwned (haveibeenpwned.com)                   ║
║  Tech : k-Anonymat SHA-1 — votre mot de passe ne quitte JAMAIS  ║
║         votre machine.                                           ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 33 & 34 RGPD — Obligation de notification
en cas de violation de données personnelles (72h pour notifier
l'autorité, sans délai si risque élevé pour les personnes).

Problème : Des milliards de credentials circulent dans des bases
de données piratées. Un utilisateur qui réutilise un mot de passe
compromis expose toute son identité numérique. Comment vérifier
sans envoyer son mot de passe à un tiers ?

Solution technique — k-Anonymat :
  1. SHA-1(mot_de_passe)                 → hash complet 40 chars
  2. Envoyer UNIQUEMENT les 5 premiers   → 5 chars (préfixe)
  3. L'API retourne ~500 hashes ayant ce préfixe (jamais le vôtre)
  4. Chercher en LOCAL si votre hash est dans la liste
  → Le serveur ne voit jamais votre hash complet. Jamais.

Risque évité : Compromission silencieuse d'un compte.
Amende évitée : Jusqu'à 10M€ ou 2% CA mondial (Art. 83 §4 RGPD)
pour défaut de notification de violation de données.
"""

import hashlib
import urllib.request
import urllib.error
import json
import time
import sys
import getpass
import csv
import re
from pathlib import Path
from datetime import datetime

# ─── Configuration ────────────────────────────────────────────────
HIBP_PASSWORD_API  = "https://api.pwnedpasswords.com/range/"
HIBP_BREACH_API    = "https://haveibeenpwned.com/api/v3/breachedaccount/"
HIBP_PASTES_API    = "https://haveibeenpwned.com/api/v3/pasteaccount/"

# Délai entre requêtes API (bonne pratique, évite le rate limiting)
REQUEST_DELAY_SEC  = 1.5

# User-Agent requis par l'API HIBP v3
USER_AGENT = "BouclierNumerique-Jour3/1.0 (RGPD Compliance Tool)"


# ════════════════════════════════════════════════════════════════════
# BLOC 1 : VÉRIFICATION DE MOT DE PASSE — K-ANONYMAT
# ════════════════════════════════════════════════════════════════════

def sha1_hash(text: str) -> str:
    """Calcule le SHA-1 d'un texte, retourne en majuscules."""
    return hashlib.sha1(text.encode("utf-8")).hexdigest().upper()


def check_password_pwned(password: str) -> dict:
    """
    Vérifie si un mot de passe est dans une base piratée.

    ┌─────────────────────────────────────────────────────────────┐
    │  PRINCIPE K-ANONYMAT (RFC 5 — Troy Hunt, HIBP)             │
    │                                                             │
    │  hash = SHA1("monMotDePasse") = "5BAA61E4C9B93F3F..."      │
    │  préfixe = hash[:5]           = "5BAA6"  ← envoyé à l'API │
    │  suffixe = hash[5:]           = "1E4C9..." ← JAMAIS envoyé │
    │                                                             │
    │  L'API retourne ~500 lignes du type:                        │
    │    1E4C9B93F3F0682250B6CF8331B7EE68FD8:3303003            │
    │    ...                                                      │
    │  On cherche notre suffixe en LOCAL. Aucun risque.           │
    └─────────────────────────────────────────────────────────────┘

    Returns:
        dict avec 'pwned' (bool), 'count' (int), 'hash_prefix', etc.
    """
    result = {
        "password_checked": True,
        "pwned": False,
        "count": 0,
        "risk_level": None,
        "hash_prefix": None,
        "error": None,
    }

    full_hash = sha1_hash(password)
    prefix    = full_hash[:5]   # Seul ce préfixe est envoyé
    suffix    = full_hash[5:]   # Ce suffixe reste local

    result["hash_prefix"] = prefix

    try:
        url = HIBP_PASSWORD_API + prefix
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=10) as response:
            body = response.read().decode("utf-8")

        # Recherche locale du suffixe dans la réponse
        for line in body.splitlines():
            parts = line.split(":")
            if len(parts) == 2:
                returned_suffix, count = parts[0].strip(), int(parts[1].strip())
                if returned_suffix == suffix:
                    result["pwned"] = True
                    result["count"] = count
                    break

        # Évaluation du risque
        if result["pwned"]:
            if result["count"] >= 100_000:
                result["risk_level"] = "🔴 CRITIQUE"
                result["advice"] = "Mot de passe ultra-commun. Changer IMMÉDIATEMENT."
            elif result["count"] >= 1_000:
                result["risk_level"] = "🟠 ÉLEVÉ"
                result["advice"] = "Très répandu. Changer immédiatement."
            else:
                result["risk_level"] = "🟡 MODÉRÉ"
                result["advice"] = "Présent dans des fuites. Changer ce mot de passe."
        else:
            result["risk_level"] = "✅ SÛRE"
            result["advice"] = "Non trouvé dans les bases connues. Continuez à le garder secret."

    except urllib.error.URLError as e:
        result["error"] = f"Réseau indisponible : {e.reason}"
        result["offline_demo"] = True
    except Exception as e:
        result["error"] = str(e)

    return result


# ════════════════════════════════════════════════════════════════════
# BLOC 2 : VÉRIFICATION D'EMAIL (BREACHES + PASTES)
# ════════════════════════════════════════════════════════════════════

def check_email_breaches(email: str, api_key: str) -> dict:
    """
    Vérifie si un email apparaît dans des bases piratées connues.
    Nécessite une clé API HIBP (abonnement ~3.50$/mois).

    Returns:
        dict avec liste des breaches et pastes associés
    """
    result = {
        "email": _mask_email(email),
        "breaches": [],
        "pastes": [],
        "total_breaches": 0,
        "error": None,
    }

    headers = {
        "User-Agent": USER_AGENT,
        "hibp-api-key": api_key,
    }

    # Vérification des breaches
    try:
        url = HIBP_BREACH_API + urllib.parse.quote(email) + "?truncateResponse=false"
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as response:
            breaches = json.loads(response.read().decode("utf-8"))
            result["breaches"] = [
                {
                    "name": b.get("Name"),
                    "domain": b.get("Domain"),
                    "date": b.get("BreachDate"),
                    "pwn_count": b.get("PwnCount"),
                    "data_classes": b.get("DataClasses", []),
                    "description": b.get("Description", "")[:200],
                }
                for b in breaches
            ]
            result["total_breaches"] = len(result["breaches"])

    except urllib.error.HTTPError as e:
        if e.code == 404:
            result["breaches"] = []  # Aucun breach
        elif e.code == 401:
            result["error"] = "Clé API invalide ou manquante."
        else:
            result["error"] = f"HTTP {e.code}"
    except urllib.error.URLError as e:
        result["error"] = f"Réseau indisponible : {e.reason}"

    return result


def _mask_email(email: str) -> str:
    """Masque partiellement un email pour l'affichage (privacy)."""
    parts = email.split("@")
    if len(parts) != 2:
        return email[:3] + "***"
    local, domain = parts
    if len(local) <= 2:
        return local + "***@" + domain
    return local[:2] + "*" * (len(local) - 2) + "@" + domain


# ════════════════════════════════════════════════════════════════════
# BLOC 3 : AUDIT EN MASSE (fichier CSV d'emails)
# ════════════════════════════════════════════════════════════════════

def audit_email_list(csv_path: Path, api_key: str, output_path: Path = None):
    """
    Audite une liste d'emails depuis un fichier CSV.
    Format CSV : une colonne 'email' (ou première colonne).
    Génère un rapport JSON.

    Cas d'usage RGPD : Le DPO audite les comptes de l'entreprise
    pour détecter des credentials compromis avant une violation.
    """
    emails = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames and "email" in [h.lower() for h in reader.fieldnames]:
            email_col = next(h for h in reader.fieldnames if h.lower() == "email")
            emails = [row[email_col].strip() for row in reader if row[email_col].strip()]
        else:
            f.seek(0)
            emails = [line.strip() for line in f if "@" in line]

    print(f"📋  {len(emails)} email(s) à auditer...")

    results = []
    for i, email in enumerate(emails):
        print(f"   [{i+1}/{len(emails)}] {_mask_email(email)}...")
        r = check_email_breaches(email, api_key)
        results.append(r)
        time.sleep(REQUEST_DELAY_SEC)  # Rate limiting respectueux

    report = {
        "audit_date": datetime.now().isoformat(),
        "total_checked": len(results),
        "compromised": sum(1 for r in results if r["total_breaches"] > 0),
        "clean": sum(1 for r in results if r["total_breaches"] == 0),
        "results": results,
    }

    if output_path:
        with open(output_path, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n📄  Rapport sauvegardé : {output_path}")

    return report


# ════════════════════════════════════════════════════════════════════
# BLOC 4 : DÉMO LOCALE (sans réseau) — Simulation k-anonymat
# ════════════════════════════════════════════════════════════════════

# Base de données fictive simulant une réponse HIBP (suffixe:count)
# SHA1 de "password"  = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
# SHA1 de "123456"    = 7C4A8D09CA3762AF61E59520943DC26494F8941B
# SHA1 de "azerty"    = 13B24F9...

MOCK_HIBP_DB = {
    # prefix -> [(suffix, count), ...]
    "5BAA6": [
        ("1E4C9B93F3F0682250B6CF8331B7EE68FD8", 3303003),  # "password" → 3.3M fuites !
        ("3E4C9B93F3F0682250B6CF8331B7EE68FD9", 15),
        ("9F4C9B93F3F0682250B6CF8331B7EE68FDA", 2),
    ],
    "7C4A8": [
        ("D09CA3762AF61E59520943DC26494F8941B", 2543285),  # "123456" → 2.5M fuites !
        ("A19CA3762AF61E59520943DC26494F894CC", 890),
    ],
    "B1B3B": [
        ("D2354F14DC97B5AE2E7E5FDD8A2E1D89C", 2),          # "MonMotDePasse2024!" → rare
    ],
}

def check_password_offline_demo(password: str) -> dict:
    """
    Démo k-anonymat sans réseau — même logique qu'en production,
    mais avec une base de données locale simulée.
    """
    result = {
        "pwned": False,
        "count": 0,
        "risk_level": None,
        "demo_mode": True,
    }

    full_hash = sha1_hash(password)
    prefix    = full_hash[:5]
    suffix    = full_hash[5:]

    print(f"\n   🔐  Analyse k-anonymat :")
    print(f"   SHA-1 complet : {full_hash}")
    print(f"   Préfixe envoyé à l'API : \033[1;32m{prefix}\033[0m (5 chars seulement)")
    print(f"   Suffixe gardé LOCAL    : \033[1;31m{suffix}\033[0m (jamais transmis)")

    # Simuler la réponse API
    mock_responses = MOCK_HIBP_DB.get(prefix, [])

    if not mock_responses:
        # Générer des faux suffixes pour simuler une vraie réponse HIBP
        import random
        mock_responses = [
            (hashlib.sha1(f"fake{i}".encode()).hexdigest().upper()[5:], random.randint(1, 100))
            for i in range(20)
        ]

    print(f"   API retourne : {len(mock_responses)} hash(es) avec ce préfixe")
    print(f"   Recherche locale du suffixe...")

    for ret_suffix, count in mock_responses:
        if ret_suffix == suffix:
            result["pwned"] = True
            result["count"] = count
            break

    if result["pwned"]:
        c = result["count"]
        if c >= 100_000:
            result["risk_level"] = "🔴 CRITIQUE"
            result["advice"] = f"Trouvé {c:,} fois ! Changer IMMÉDIATEMENT sur tous vos comptes."
        elif c >= 1_000:
            result["risk_level"] = "🟠 ÉLEVÉ"
            result["advice"] = f"Trouvé {c:,} fois dans des fuites. Changer immédiatement."
        else:
            result["risk_level"] = "🟡 MODÉRÉ"
            result["advice"] = f"Trouvé {c:,} fois. Présent dans des fuites, à changer."
    else:
        result["risk_level"] = "✅ SÛR"
        result["advice"] = "Non trouvé dans la base simulée."

    return result


# ════════════════════════════════════════════════════════════════════
# BLOC 5 : INTERFACE CLI
# ════════════════════════════════════════════════════════════════════

SEPARATOR = "═" * 62

def print_password_result(r: dict, password_label: str = ""):
    print(f"\n{SEPARATOR}")
    print(f"  🔑  Résultat : {password_label or '(mot de passe saisi)'}")
    print(f"{SEPARATOR}")
    if r.get("error"):
        print(f"  ❌  Erreur  : {r['error']}")
        if not r.get("offline_demo"):
            return
    print(f"  Préfixe hash envoyé : {r.get('hash_prefix', 'N/A')}")
    print(f"  Statut  : {r.get('risk_level', '?')}")
    if r.get("pwned"):
        print(f"  Fuites  : \033[1;31m{r['count']:,} fois trouvé dans des bases piratées\033[0m")
    else:
        print(f"  Fuites  : Aucune trouvée ✅")
    print(f"  Conseil : {r.get('advice', '')}")


def cmd_demo():
    """Démo complète illustrant le principe k-anonymat."""
    print(f"\n{'═'*62}")
    print("  🎬  DÉMO — Principe k-Anonymat HIBP")
    print(f"{'═'*62}")
    print("""
  ┌──────────────────────────────────────────────────────────┐
  │  POURQUOI C'EST BRILLANT :                               │
  │                                                          │
  │  Naïf  : envoyer "password" à l'API → ❌ DANGEREUX      │
  │  HIBP  : envoyer "5BAA6" → recevoir 500 hashes → ✅     │
  │                                                          │
  │  Probabilité de collision sur 5 chars hex :              │
  │  1 préfixe = ~16^5 = 1 048 576 combinaisons             │
  │  La réponse contient ~500 entrées sur 1M → anonymat réel│
  └──────────────────────────────────────────────────────────┘
""")

    tests = [
        ("password",           "Mot de passe ultra-courant"),
        ("123456",             "Suite numérique triviale"),
        ("MonMotDePasse2024!", "Mot de passe plus fort"),
        ("azerty",             "Clavier français courant"),
        ("correct horse battery staple", "Passphrase (style XKCD)"),
    ]

    for pwd, label in tests:
        print(f"\n  Testing : \"{label}\" ({len(pwd)} chars)")
        r = check_password_offline_demo(pwd)

        if r.get("pwned"):
            print(f"  \033[1;31m⛔  {r['risk_level']} — {r['count']:,} fuites détectées\033[0m")
            print(f"  💡  {r['advice']}")
        else:
            print(f"  \033[1;32m✅  {r['risk_level']} — Non trouvé dans la base de démo\033[0m")
            print(f"  💡  {r['advice']}")
        time.sleep(0.1)

    print(f"\n{SEPARATOR}")
    print("  📊  BILAN RGPD")
    print(f"{SEPARATOR}")
    print("""
  Art. 33 RGPD : Si un mot de passe compromis de votre base
  est utilisé par un attaquant pour accéder à vos systèmes,
  vous avez 72h pour notifier la CNIL d'une violation de données.

  Ce script, intégré dans votre pipeline d'inscription,
  bloque l'utilisation de tout mot de passe compromis AVANT
  qu'il soit jamais stocké dans votre base.

  → Conformité proactive plutôt que notification reactive.

  💻  En production (avec réseau) :
  python3 leak_detector.py password
  python3 leak_detector.py email user@example.com --key VOTRE_CLE
  python3 leak_detector.py audit emails.csv --key VOTRE_CLE
""")


def cmd_check_password(interactive: bool = False):
    """Vérification interactive d'un mot de passe."""
    if interactive:
        pwd = getpass.getpass("  Entrez le mot de passe à vérifier : ")
    else:
        pwd = sys.argv[2] if len(sys.argv) > 2 else getpass.getpass("  Mot de passe : ")

    print(f"\n  ⏳  Vérification en cours (k-anonymat)...")
    r = check_password_pwned(pwd)

    if r.get("error"):
        print(f"\n  ⚠️  Mode hors-ligne détecté → Démo locale")
        r = check_password_offline_demo(pwd)

    print_password_result(r)


MENU = f"""
{SEPARATOR}
  🛡️  DÉTECTEUR DE FUITES — MENU
{SEPARATOR}
  1. Vérifier un mot de passe (k-anonymat)
  2. Démo k-anonymat complète (offline)
  3. Quitter
{SEPARATOR}"""


def main():
    print(__doc__)

    args = sys.argv[1:]

    if not args:
        # Mode interactif
        while True:
            print(MENU)
            choice = input("  Choix : ").strip()
            if choice == "1":
                cmd_check_password(interactive=True)
            elif choice == "2":
                cmd_demo()
            elif choice == "3":
                print("  👋  Au revoir.")
                break
            else:
                print("  Choix invalide.")
        return

    cmd = args[0].lower()

    if cmd == "demo":
        cmd_demo()

    elif cmd == "password" or cmd == "pwd":
        if len(args) > 1:
            password = args[1]
        else:
            password = getpass.getpass("  Mot de passe : ")
        r = check_password_pwned(password)
        if r.get("error"):
            print(f"\n  ⚠️  Réseau indisponible — Mode démo local")
            r = check_password_offline_demo(password)
        print_password_result(r)

    elif cmd == "email":
        if len(args) < 2:
            print("  Usage: python3 leak_detector.py email user@example.com --key VOTRE_CLE")
            sys.exit(1)
        email = args[1]
        api_key = ""
        if "--key" in args:
            api_key = args[args.index("--key") + 1]
        r = check_email_breaches(email, api_key)
        print(f"\n  Email : {_mask_email(email)}")
        if r.get("error"):
            print(f"  ❌  {r['error']}")
            print("  💡  Obtenez une clé API sur : https://haveibeenpwned.com/API/Key")
        else:
            print(f"  Breaches : {r['total_breaches']}")
            for b in r["breaches"][:5]:
                print(f"    • {b['name']} ({b['date']}) — {b.get('pwn_count', '?'):,} comptes")
                if b.get("data_classes"):
                    print(f"      Données exposées : {', '.join(b['data_classes'][:4])}")

    elif cmd == "audit":
        if len(args) < 2:
            print("  Usage: python3 leak_detector.py audit emails.csv --key VOTRE_CLE")
            sys.exit(1)
        csv_file = Path(args[1])
        api_key = args[args.index("--key") + 1] if "--key" in args else ""
        output = Path("audit_report.json")
        report = audit_email_list(csv_file, api_key, output)
        print(f"\n  📊  {report['total_checked']} emails audités")
        print(f"  🔴  {report['compromised']} compromis")
        print(f"  ✅  {report['clean']} propres")

    else:
        print(f"  Commande inconnue : {cmd}")
        print("  Usage: demo | password [pwd] | email <addr> [--key KEY] | audit <csv> [--key KEY]")


if __name__ == "__main__":
    main()
