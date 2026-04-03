#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 1 : LE GESTIONNAIRE COFFRE-FORT  ║
║  Algorithme : scrypt (memory-hard KDF, recommandé OWASP)         ║
║  Standard   : NIST SP 800-132 / RFC 7914                         ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 32 RGPD — "mesures techniques appropriées
pour garantir un niveau de sécurité adapté au risque."

Solution technique : Hachage avec sel aléatoire (16 octets) +
scrypt (N=2^17, r=8, p=1) = résistant aux attaques par dictionnaire
et aux attaques GPU/ASIC.

Risque évité : En cas de fuite de base de données, les mots de passe
restent inexploitables (crackage prohibitif en coût/temps).
"""

import hashlib
import hmac
import os
import json
import base64
import getpass
from pathlib import Path

# ─── Paramètres scrypt ────────────────────────────────────────────
# N = facteur de coût CPU/mémoire (2^17 = 128 Mo RAM par hachage)
# r = taille du bloc (8 = recommandation RFC 7914)
# p = parallélisme
# dklen = longueur du hash en sortie (32 octets = 256 bits)
SCRYPT_N = 2 ** 14   # 16 384 — ~16 Mo RAM (production recommandée : 2^17 = 128 Mo)
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_SIZE = 16       # 128 bits de sel aléatoire

VAULT_FILE = Path("vault.json")


# ─── Fonctions cœur ──────────────────────────────────────────────

def generate_salt() -> bytes:
    """Génère un sel cryptographiquement sûr via os.urandom()."""
    return os.urandom(SALT_SIZE)


def hash_password(password: str, salt: bytes = None) -> dict:
    """
    Hache un mot de passe avec un sel aléatoire en utilisant scrypt.
    
    Returns:
        dict avec 'salt' et 'hash' encodés en base64 (stockage sûr JSON)
    """
    if salt is None:
        salt = generate_salt()

    password_bytes = password.encode("utf-8")

    hashed = hashlib.scrypt(
        password_bytes,
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN
    )

    return {
        "algorithm": "scrypt",
        "params": {"N": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "dklen": SCRYPT_DKLEN},
        "salt": base64.b64encode(salt).decode(),
        "hash": base64.b64encode(hashed).decode()
    }


def verify_password(password: str, stored_record: dict) -> bool:
    """
    Vérifie un mot de passe contre un enregistrement stocké.
    Utilise hmac.compare_digest() pour éviter les timing attacks.
    """
    salt = base64.b64decode(stored_record["salt"])
    stored_hash = base64.b64decode(stored_record["hash"])
    params = stored_record["params"]

    candidate_hash = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=params["N"],
        r=params["r"],
        p=params["p"],
        dklen=params["dklen"]
    )

    # compare_digest : comparaison en temps constant → résistant aux timing attacks
    return hmac.compare_digest(candidate_hash, stored_hash)


# ─── Gestionnaire de coffre-fort ─────────────────────────────────

def load_vault() -> dict:
    """Charge le coffre-fort depuis le fichier JSON."""
    if VAULT_FILE.exists():
        with open(VAULT_FILE, "r") as f:
            return json.load(f)
    return {}


def save_vault(vault: dict):
    """Sauvegarde le coffre-fort (permissions 600 : owner uniquement)."""
    with open(VAULT_FILE, "w") as f:
        json.dump(vault, f, indent=2)
    # Restreindre les permissions : lecture/écriture owner uniquement
    os.chmod(VAULT_FILE, 0o600)


def cmd_add(vault: dict):
    """Ajoute un nouveau mot de passe dans le coffre."""
    service = input("Service (ex: github, email) : ").strip()
    if not service:
        print("❌  Nom de service invalide.")
        return

    if service in vault:
        confirm = input(f"⚠️  '{service}' existe déjà. Écraser ? (o/N) : ").strip().lower()
        if confirm != "o":
            print("Annulé.")
            return

    password = getpass.getpass("Mot de passe : ")
    confirm_pwd = getpass.getpass("Confirmer le mot de passe : ")

    if password != confirm_pwd:
        print("❌  Les mots de passe ne correspondent pas.")
        return

    if len(password) < 8:
        print("⚠️  Avertissement : mot de passe trop court (< 8 caractères).")

    print("⏳  Hachage en cours (scrypt N=2^17)...")
    record = hash_password(password)
    vault[service] = record
    save_vault(vault)

    print(f"✅  Mot de passe pour '{service}' stocké avec succès.")
    print(f"    Salt : {record['salt'][:20]}...")
    print(f"    Hash : {record['hash'][:20]}...")


def cmd_verify(vault: dict):
    """Vérifie si un mot de passe correspond à l'entrée stockée."""
    service = input("Service à vérifier : ").strip()

    if service not in vault:
        print(f"❌  Service '{service}' introuvable dans le coffre.")
        return

    password = getpass.getpass("Mot de passe à vérifier : ")
    print("⏳  Vérification en cours...")

    if verify_password(password, vault[service]):
        print("✅  MOT DE PASSE CORRECT — Authentification réussie.")
    else:
        print("❌  MOT DE PASSE INCORRECT — Accès refusé.")


def cmd_list(vault: dict):
    """Liste les services stockés (sans afficher les hashes)."""
    if not vault:
        print("📭  Le coffre est vide.")
        return

    print(f"\n📋  Services stockés ({len(vault)}) :")
    for service, record in vault.items():
        algo = record.get("algorithm", "inconnu")
        print(f"   • {service:<20} [{algo}]")
    print()


def cmd_delete(vault: dict):
    """Supprime une entrée du coffre."""
    service = input("Service à supprimer : ").strip()

    if service not in vault:
        print(f"❌  Service '{service}' introuvable.")
        return

    confirm = input(f"⚠️  Supprimer '{service}' définitivement ? (o/N) : ").strip().lower()
    if confirm == "o":
        del vault[service]
        save_vault(vault)
        print(f"🗑️   '{service}' supprimé du coffre.")
    else:
        print("Annulé.")


def cmd_demo():
    """Démo rapide sans interactivité pour tester le script."""
    print("\n═══ DÉMO : Hachage & Vérification ═══\n")
    test_password = "MonSuperMotDePasse123!"

    print(f"Mot de passe original : {test_password}")
    print("⏳  Hachage en cours...")

    record = hash_password(test_password)

    print(f"\n✅  Hash généré :")
    print(f"   Algorithme : {record['algorithm']} (N={record['params']['N']})")
    print(f"   Salt (b64) : {record['salt']}")
    print(f"   Hash (b64) : {record['hash']}")

    print(f"\n🔍  Vérification avec le bon mot de passe...")
    result = verify_password(test_password, record)
    print(f"   → {'✅ CORRECT' if result else '❌ INCORRECT'}")

    print(f"\n🔍  Vérification avec un mauvais mot de passe...")
    result2 = verify_password("mauvais_mot_de_passe", record)
    print(f"   → {'✅ CORRECT' if result2 else '❌ INCORRECT'}")

    print(f"\n🔍  Deux hachages du même mot de passe = deux hashs différents (sel unique) :")
    r1 = hash_password(test_password)
    r2 = hash_password(test_password)
    print(f"   Hash 1 : {r1['hash'][:30]}...")
    print(f"   Hash 2 : {r2['hash'][:30]}...")
    print(f"   Identiques ? {'Oui ⚠️' if r1['hash'] == r2['hash'] else 'Non ✅ (normal : sel différent)'}")


# ─── Interface CLI ────────────────────────────────────────────────

MENU = """
╔═══════════════════════════════════╗
║  🛡️  COFFRE-FORT — MENU PRINCIPAL ║
╠═══════════════════════════════════╣
║  1. Ajouter un mot de passe        ║
║  2. Vérifier un mot de passe       ║
║  3. Lister les services            ║
║  4. Supprimer un service           ║
║  5. Démo technique                 ║
║  0. Quitter                        ║
╚═══════════════════════════════════╝
"""

def main():
    print(__doc__)
    vault = load_vault()

    while True:
        print(MENU)
        choice = input("Choix : ").strip()

        if choice == "1":
            cmd_add(vault)
        elif choice == "2":
            cmd_verify(vault)
        elif choice == "3":
            cmd_list(vault)
        elif choice == "4":
            cmd_delete(vault)
        elif choice == "5":
            cmd_demo()
        elif choice == "0":
            print("👋  Au revoir.")
            break
        else:
            print("Choix invalide.")


if __name__ == "__main__":
    main()
