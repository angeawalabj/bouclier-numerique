#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 4 : LE CHIFFREUR DE FICHIERS     ║
║  Algo   : AES-256-GCM (Authenticated Encryption)                 ║
║  KDF    : PBKDF2-HMAC-SHA256 — 600 000 itérations (NIST 2023)   ║
║  Format : .vault (header + nonce + tag + ciphertext)             ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 32 RGPD — "le chiffrement des données
à caractère personnel" est cité explicitement comme mesure
technique appropriée. Art. 34 : en cas de fuite, si les données
sont chiffrées, la notification aux personnes N'EST PAS requise.

Problème : Des documents sensibles (fiches de paie, contrats,
scans de pièces d'identité, données médicales) stockés en clair
sur un disque sont accessibles à quiconque y a accès physique ou
logiciel — vol, ransomware, technicien de maintenance, etc.

Solution technique :
  • AES-256-GCM : chiffrement + authentification en un seul algo
    → Garantit que le fichier n'a pas été falsifié (intégrité)
  • Clé dérivée depuis un mot de passe via PBKDF2 (600k tours)
    → Résistant aux attaques par dictionnaire/GPU
  • Nonce (IV) unique par chiffrement (12 octets, aléatoire)
    → Deux chiffrements du même fichier donnent deux résultats
    différents — aucune fuite d'information sur le contenu

Risque évité : En cas de vol d'ordinateur portable ou de fuite
de backup, les fichiers restent illisibles sans le mot de passe.
Art. 34 §3(a) : exemption de notification si chiffrement fort.
"""

import os
import sys
import struct
import hashlib
import hmac
import getpass
import json
import shutil
from pathlib import Path
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ─── Constantes cryptographiques ──────────────────────────────────

AES_KEY_SIZE    = 32       # 256 bits
NONCE_SIZE      = 12       # 96 bits (recommandation NIST pour GCM)
SALT_SIZE       = 32       # 256 bits
PBKDF2_ITERS    = 600_000  # NIST SP 800-132 recommandation 2023
TAG_SIZE        = 16       # 128 bits (GCM authentication tag)

# Magic bytes pour identifier nos fichiers .vault
MAGIC           = b"VAULT01"   # 7 octets
VAULT_EXT       = ".vault"

# ─── Format du fichier .vault ─────────────────────────────────────
#
#  OFFSET   SIZE   DESCRIPTION
#  ──────────────────────────────────────────────────────────────
#  0        7      Magic : b"VAULT01"
#  7        4      Longueur du header JSON (little-endian uint32)
#  11       N      Header JSON (metadata chiffrée en clair)
#  11+N     32     Salt PBKDF2
#  43+N     12     Nonce AES-GCM
#  55+N     R      Ciphertext + GCM Tag (tag = 16 derniers octets)
#
#  Header JSON contient : nom original, date, taille originale,
#  algo, kdf_iterations (permet de re-dériver la clé même si on
#  change les paramètres par défaut dans le futur)
#


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Dérive une clé AES-256 depuis un mot de passe via PBKDF2-HMAC-SHA256.

    Pourquoi PBKDF2 et pas SHA-256 direct ?
    SHA-256("password") prend 1 microseconde → GPU peut tester
    10 milliards de mots de passe par seconde.
    PBKDF2 à 600 000 tours prend ~300ms → GPU réduit à ~3 000/sec.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(input_path: Path, output_path: Path, password: str) -> dict:
    """
    Chiffre un fichier avec AES-256-GCM.

    AES-GCM = "Authenticated Encryption with Associated Data" (AEAD)
    → Le tag GCM garantit à la fois la confidentialité ET l'intégrité.
    → Toute modification du fichier chiffré rend le déchiffrement impossible.

    Returns:
        dict rapport du chiffrement
    """
    input_path = Path(input_path)
    if not input_path.exists():
        raise FileNotFoundError(f"Fichier introuvable : {input_path}")

    # Lire les données en clair
    plaintext = input_path.read_bytes()
    original_size = len(plaintext)

    # Générer sel et nonce aléatoires
    salt  = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # Dériver la clé AES-256
    print("  ⏳  Dérivation de la clé (PBKDF2, 600 000 tours)...")
    key = derive_key(password, salt)

    # Chiffrer avec AES-256-GCM
    aesgcm = AESGCM(key)

    # "Associated data" : lie le header au ciphertext (intégrité)
    # → Modifier le header sans la clé invalide le tag GCM
    header = {
        "original_name": input_path.name,
        "original_size": original_size,
        "encrypted_at":  datetime.now().isoformat(),
        "algorithm":     "AES-256-GCM",
        "kdf":           "PBKDF2-HMAC-SHA256",
        "kdf_iterations": PBKDF2_ITERS,
        "nonce_size":    NONCE_SIZE,
        "salt_size":     SALT_SIZE,
    }
    header_json = json.dumps(header, ensure_ascii=False).encode("utf-8")

    # Le ciphertext inclut le GCM tag (16 derniers octets)
    ciphertext = aesgcm.encrypt(nonce, plaintext, header_json)

    # ─ Écriture du fichier .vault ─
    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(struct.pack("<I", len(header_json)))   # header length
        f.write(header_json)
        f.write(salt)
        f.write(nonce)
        f.write(ciphertext)

    # Effacement sécurisé du mot de passe de la mémoire (best effort)
    key = b"\x00" * AES_KEY_SIZE

    encrypted_size = output_path.stat().st_size
    overhead = encrypted_size - original_size

    return {
        "status":          "encrypted",
        "input":           str(input_path),
        "output":          str(output_path),
        "original_size_b": original_size,
        "encrypted_size_b": encrypted_size,
        "overhead_b":      overhead,
        "algorithm":       "AES-256-GCM",
        "kdf_iterations":  PBKDF2_ITERS,
    }


def decrypt_file(vault_path: Path, output_path: Path, password: str) -> dict:
    """
    Déchiffre un fichier .vault et vérifie son intégrité.

    Si le fichier a été altéré (même 1 bit), AES-GCM lève une
    InvalidTag exception → Détection de falsification garantie.
    """
    from cryptography.exceptions import InvalidTag

    vault_path = Path(vault_path)
    if not vault_path.exists():
        raise FileNotFoundError(f"Vault introuvable : {vault_path}")

    with open(vault_path, "rb") as f:
        # Vérifier magic
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Format invalide — ce n'est pas un fichier .vault")

        # Lire header
        header_len = struct.unpack("<I", f.read(4))[0]
        header_json = f.read(header_len)
        header = json.loads(header_json.decode("utf-8"))

        # Lire salt, nonce, ciphertext
        salt       = f.read(SALT_SIZE)
        nonce      = f.read(NONCE_SIZE)
        ciphertext = f.read()

    # Dériver la clé avec les paramètres du header
    iters = header.get("kdf_iterations", PBKDF2_ITERS)
    print(f"  ⏳  Dérivation de la clé (PBKDF2, {iters:,} tours)...")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=iters,
    )
    key = kdf.derive(password.encode("utf-8"))

    # Déchiffrer et vérifier le tag GCM
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, header_json)
    except InvalidTag:
        raise ValueError(
            "❌ ÉCHEC D'AUTHENTIFICATION — Mot de passe incorrect "
            "ou fichier falsifié/corrompu."
        )

    # Écrire le fichier déchiffré
    output_path.write_bytes(plaintext)

    return {
        "status":          "decrypted",
        "input":           str(vault_path),
        "output":          str(output_path),
        "original_name":   header.get("original_name"),
        "original_size_b": header.get("original_size"),
        "encrypted_at":    header.get("encrypted_at"),
        "integrity":       "✅ Vérifié (GCM tag valide)",
    }


def inspect_vault(vault_path: Path) -> dict:
    """Lit uniquement le header d'un vault sans déchiffrer."""
    vault_path = Path(vault_path)

    with open(vault_path, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("Format invalide")
        header_len = struct.unpack("<I", f.read(4))[0]
        header_json = f.read(header_len)
        header = json.loads(header_json.decode("utf-8"))

    encrypted_size = vault_path.stat().st_size
    header["vault_file"] = str(vault_path)
    header["vault_size_b"] = encrypted_size
    return header


def secure_wipe(path: Path, passes: int = 3):
    """
    Écrasement sécurisé d'un fichier avant suppression.

    Note : Sur SSD/NVMe avec wear-leveling, l'écrasement n'est
    pas garanti au niveau physique. La vraie sécurité sur SSD
    nécessite le chiffrement du disque entier (FileVault, BitLocker).
    """
    path = Path(path)
    size = path.stat().st_size
    with open(path, "r+b") as f:
        for i in range(passes):
            f.seek(0)
            if i % 2 == 0:
                f.write(os.urandom(size))
            else:
                f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())
    path.unlink()


def encrypt_folder(folder: Path, password: str, wipe_originals: bool = False) -> list:
    """Chiffre récursivement tous les fichiers d'un dossier."""
    folder = Path(folder)
    results = []

    files = [f for f in folder.rglob("*")
             if f.is_file() and f.suffix != VAULT_EXT]

    print(f"  📂  {len(files)} fichier(s) à chiffrer dans {folder}")

    for fpath in files:
        out = fpath.with_suffix(fpath.suffix + VAULT_EXT)
        try:
            r = encrypt_file(fpath, out, password)
            status = "✅"
            if wipe_originals:
                secure_wipe(fpath)
                status = "✅🗑️"
            results.append({"file": fpath.name, "status": status, **r})
        except Exception as e:
            results.append({"file": fpath.name, "status": "❌", "error": str(e)})

    return results


# ─── Démo complète ────────────────────────────────────────────────

def run_demo():
    """Démo : chiffrer/déchiffrer/vérifier falsification."""
    import tempfile

    print(f"\n{'═'*62}")
    print("  🎬  DÉMO AES-256-GCM — Chiffrement de fichiers")
    print(f"{'═'*62}\n")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)

        # ── Créer des fichiers de test ──
        sensitive_files = {
            "fiche_paie_2024.txt": (
                "FICHE DE PAIE — CONFIDENTIEL\n"
                "Nom : Jean Dupont\n"
                "Salaire brut : 3 850,00 €\n"
                "Numéro sécu : 1 84 05 75 123 456 78\n"
                "IBAN : FR76 3000 6000 0112 3456 7890 189\n"
            ),
            "contrat_client.txt": (
                "CONTRAT DE PRESTATION — CONFIDENTIEL\n"
                "Client : ACME Corp\n"
                "Montant : 45 000 € HT\n"
                "Données personnelles client : ...\n"
            ),
            "scan_passeport.txt": (
                "DOCUMENT D'IDENTITÉ — ULTRA CONFIDENTIEL\n"
                "Nom : DUPONT Jean Michel\n"
                "N° passeport : 12AB34567\n"
                "Date naissance : 15/03/1985\n"
            ),
        }

        password = "MotDePasseVault2024!"

        for fname, content in sensitive_files.items():
            (tmp / fname).write_text(content, encoding="utf-8")

        print(f"  📄  Fichiers sensibles créés :")
        for fname in sensitive_files:
            size = (tmp / fname).stat().st_size
            print(f"     • {fname} ({size} octets — EN CLAIR ⚠️)")

        # ── Étape 1 : Chiffrement ──
        print(f"\n{'─'*62}")
        print(f"  🔒  ÉTAPE 1 : CHIFFREMENT")
        print(f"{'─'*62}")
        print(f"  Mot de passe : {password}")
        print(f"  Algorithme   : AES-256-GCM")
        print(f"  KDF          : PBKDF2-HMAC-SHA256, 600 000 tours\n")

        vault_files = []
        for fname in sensitive_files:
            src = tmp / fname
            dst = tmp / (fname + VAULT_EXT)
            r = encrypt_file(src, dst, password)
            vault_files.append(dst)
            ratio = r['encrypted_size_b'] / r['original_size_b']
            print(f"  ✅  {fname}")
            print(f"     → {fname}{VAULT_EXT}")
            print(f"     Taille : {r['original_size_b']} B → {r['encrypted_size_b']} B "
                  f"(×{ratio:.1f}, overhead = header+salt+nonce+tag)")

        # ── Étape 2 : Inspection sans clé ──
        print(f"\n{'─'*62}")
        print(f"  🔍  ÉTAPE 2 : INSPECTION VAULT (sans mot de passe)")
        print(f"{'─'*62}")
        info = inspect_vault(vault_files[0])
        print(f"  Ce qu'un attaquant peut voir sans la clé :")
        print(f"    Fichier       : {info['vault_file']}")
        print(f"    Taille vault  : {info['vault_size_b']} octets")
        print(f"    Nom original  : {info['original_name']}  ← visible (metadata)")
        print(f"    Date création : {info['encrypted_at']}")
        print(f"    Algorithme    : {info['algorithm']}")
        print(f"    Contenu       : [ILLISIBLE — clé requise]")
        print(f"\n  ℹ️  Note : Pour cacher aussi le nom du fichier, chiffrer")
        print(f"  dans un container (ex: VeraCrypt) ou nommer le vault")
        print(f"  avec un identifiant opaque (UUID).")

        # ── Étape 3 : Déchiffrement ──
        print(f"\n{'─'*62}")
        print(f"  🔓  ÉTAPE 3 : DÉCHIFFREMENT")
        print(f"{'─'*62}")
        vault = vault_files[0]
        out = tmp / "DECRYPTED_fiche_paie.txt"
        r = decrypt_file(vault, out, password)
        content = out.read_text(encoding="utf-8")
        print(f"  {r['integrity']}")
        print(f"  Fichier restauré : {r['output']}")
        print(f"  Contenu :\n")
        for line in content.strip().splitlines():
            print(f"    {line}")

        # ── Étape 4 : Mauvais mot de passe ──
        print(f"\n{'─'*62}")
        print(f"  🔐  ÉTAPE 4 : TENTATIVE AVEC MAUVAIS MOT DE PASSE")
        print(f"{'─'*62}")
        try:
            decrypt_file(vault, tmp / "fail.txt", "mauvais_mdp")
            print("  ⚠️  Déchiffrement inattendu !")
        except ValueError as e:
            print(f"  {e}")
            print(f"  → AES-GCM a détecté que la clé est incorrecte.")
            print(f"  → Aucune donnée partiellement déchiffrée n'est exposée.")

        # ── Étape 5 : Détection de falsification ──
        print(f"\n{'─'*62}")
        print(f"  ⚠️  ÉTAPE 5 : DÉTECTION DE FALSIFICATION (Tamper Detection)")
        print(f"{'─'*62}")
        tampered = tmp / "tampered.vault"
        shutil.copy(vault, tampered)

        # Modifier 1 octet au milieu du ciphertext
        with open(tampered, "r+b") as f:
            f.seek(-50, 2)   # 50 octets avant la fin
            original_byte = f.read(1)
            f.seek(-50, 2)
            f.write(bytes([original_byte[0] ^ 0xFF]))  # XOR : flip tous les bits

        print(f"  Simulation : 1 octet modifié dans le ciphertext...")
        try:
            decrypt_file(tampered, tmp / "tampered_out.txt", password)
            print("  ⚠️  Falsification non détectée !")
        except ValueError as e:
            print(f"  {e}")
            print(f"  → GCM Tag mismatch : toute modification est détectée,")
            print(f"    même 1 bit changé sur un fichier de plusieurs Go.")

        # ── Bilan ──
        print(f"\n{'═'*62}")
        print(f"  📊  BILAN DE SÉCURITÉ")
        print(f"{'═'*62}")
        print(f"""
  Fichiers chiffrés  : {len(vault_files)}
  Algorithme         : AES-256-GCM (FIPS 140-2 approved)
  Confidentialité    : ✅ Clé 256 bits, infaisable à brute-forcer
  Intégrité          : ✅ GCM Tag — toute altération détectée
  Authentification   : ✅ Lié au mot de passe via PBKDF2
  Résistance GPU     : ✅ PBKDF2 600k tours ≈ 300ms par tentative

  🔑  CONSEIL RGPD (Art. 32 + 34) :
  Chiffrer les documents sensibles avec ce script vous donne
  droit à l'exemption de notification en cas de fuite :
  Art. 34 §3(a) — si données chiffrées avec mesures appropriées,
  la notification aux personnes concernées N'EST PAS obligatoire.
  Économie potentielle : réputation + amendes + frais légaux.
""")


# ─── CLI ──────────────────────────────────────────────────────────

USAGE = """
Usage :
  python3 file_vault.py demo                          Démo complète
  python3 file_vault.py encrypt <fichier>             Chiffrer un fichier
  python3 file_vault.py decrypt <fichier.vault>       Déchiffrer
  python3 file_vault.py inspect <fichier.vault>       Voir les métadonnées
  python3 file_vault.py wipe    <fichier>             Effacement sécurisé
  python3 file_vault.py batch   <dossier>             Chiffrer un dossier
"""

def main():
    print(__doc__)
    args = sys.argv[1:]

    if not args or args[0] == "demo":
        run_demo()
        return

    cmd = args[0].lower()

    if cmd == "encrypt":
        if len(args) < 2:
            print(USAGE); sys.exit(1)
        src = Path(args[1])
        dst = Path(args[2]) if len(args) > 2 else src.with_suffix(src.suffix + VAULT_EXT)
        pwd = getpass.getpass("  Mot de passe : ")
        pwd2 = getpass.getpass("  Confirmer   : ")
        if pwd != pwd2:
            print("  ❌  Mots de passe différents."); sys.exit(1)
        r = encrypt_file(src, dst, pwd)
        print(f"\n  ✅  Chiffré : {r['output']}")
        print(f"  Taille : {r['original_size_b']} → {r['encrypted_size_b']} octets")

    elif cmd == "decrypt":
        if len(args) < 2:
            print(USAGE); sys.exit(1)
        vault = Path(args[1])
        default_out = vault.stem  # retire .vault
        dst = Path(args[2]) if len(args) > 2 else Path(default_out)
        pwd = getpass.getpass("  Mot de passe : ")
        try:
            r = decrypt_file(vault, dst, pwd)
            print(f"\n  ✅  Déchiffré : {r['output']}")
            print(f"  Intégrité   : {r['integrity']}")
        except ValueError as e:
            print(f"\n  {e}"); sys.exit(1)

    elif cmd == "inspect":
        if len(args) < 2:
            print(USAGE); sys.exit(1)
        info = inspect_vault(Path(args[1]))
        print(f"\n  📋  Métadonnées vault :")
        for k, v in info.items():
            print(f"  {k:<20} : {v}")

    elif cmd == "wipe":
        if len(args) < 2:
            print(USAGE); sys.exit(1)
        target = Path(args[1])
        confirm = input(f"  ⚠️  Effacer définitivement '{target}' ? (oui/N) : ")
        if confirm.lower() == "oui":
            secure_wipe(target)
            print(f"  🗑️  Effacé (3 passes).")
        else:
            print("  Annulé.")

    elif cmd == "batch":
        if len(args) < 2:
            print(USAGE); sys.exit(1)
        pwd = getpass.getpass("  Mot de passe : ")
        pwd2 = getpass.getpass("  Confirmer   : ")
        if pwd != pwd2:
            print("  ❌  Mots de passe différents."); sys.exit(1)
        wipe = "--wipe" in args
        results = encrypt_folder(Path(args[1]), pwd, wipe)
        ok = sum(1 for r in results if r["status"].startswith("✅"))
        print(f"\n  ✅  {ok}/{len(results)} fichiers chiffrés")

    else:
        print(USAGE)


if __name__ == "__main__":
    main()
