#!/usr/bin/env python3
"""Gestionnaire de mots de passe en ligne de commande.

Un coffre-fort doit pouvoir *rendre* un secret, pas seulement confirmer
qu'on l'a deviné. La première version de cet outil ne stockait que des
hachages scrypt à sens unique : elle vérifiait un mot de passe candidat,
mais ne pouvait jamais restituer le mot de passe original — inutilisable
comme gestionnaire au sens propre, malgré son nom. Cette version dérive
une clé du mot de passe maître (scrypt), puis chiffre chaque secret avec
AES-256-GCM : le déchiffrement, donc la récupération réelle, devient
possible. Le mot de passe maître lui-même n'est jamais stocké — seul un
sel et une empreinte de vérification (HMAC) le sont, pour détecter une
saisie incorrecte sans exposer la clé.
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import os
import secrets
import string
import sys
import tempfile
from pathlib import Path

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Dépendance manquante : pip install cryptography", file=sys.stderr)
    sys.exit(1)

DEFAULT_VAULT = Path("vault.json")

# N=2**15 (~32 Mo de RAM par dérivation) : robuste contre une attaque hors
# ligne par dictionnaire tout en restant utilisable en CLI interactive
# (2**17, plus lent, a du sens pour un service qui dérive une seule fois
# au démarrage — moins pour une commande qu'on tape plusieurs fois par jour).
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
KEY_LEN = 32
SALT_LEN = 16
NONCE_LEN = 12
CHECK_MESSAGE = b"bouclier-numerique-vault-check-v1"


class VaultError(Exception):
    """Erreur utilisateur (mauvais mot de passe, service inconnu...)."""


def derive_key(master_password: str, salt: bytes) -> bytes:
    # hashlib.scrypt refuse silencieusement de dépasser 32 Mo par défaut ;
    # la charge réelle (128*N*r) doit tenir dans maxmem, avec de la marge.
    return hashlib.scrypt(
        master_password.encode("utf-8"),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=KEY_LEN,
        maxmem=128 * SCRYPT_N * SCRYPT_R * 2,
    )


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data)


def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_=+"
    return "".join(secrets.choice(alphabet) for _ in range(length))


class Vault:
    """Coffre chiffré : un fichier JSON, une clé dérivée en mémoire."""

    def __init__(self, path: Path):
        self.path = path
        self._key: bytes | None = None
        self._data: dict | None = None

    @property
    def exists(self) -> bool:
        return self.path.exists()

    def create(self, master_password: str) -> None:
        if self.exists:
            raise VaultError(f"{self.path} existe déjà.")
        salt = os.urandom(SALT_LEN)
        key = derive_key(master_password, salt)
        check = hmac.new(key, CHECK_MESSAGE, hashlib.sha256).hexdigest()
        self._data = {"salt": b64e(salt), "check": check, "entries": {}}
        self._key = key
        self._save()

    def unlock(self, master_password: str) -> None:
        if not self.exists:
            raise VaultError(f"{self.path} introuvable — lancez `init` d'abord.")
        self._data = json.loads(self.path.read_text(encoding="utf-8"))
        salt = b64d(self._data["salt"])
        key = derive_key(master_password, salt)
        actual = hmac.new(key, CHECK_MESSAGE, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(self._data["check"], actual):
            raise VaultError("Mot de passe maître incorrect.")
        self._key = key

    def _save(self) -> None:
        self.path.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        os.chmod(self.path, 0o600)

    def add(self, service: str, secret: str, overwrite: bool = False) -> None:
        if service in self._data["entries"] and not overwrite:
            raise VaultError(f"'{service}' existe déjà (utilisez --force pour écraser).")
        nonce = os.urandom(NONCE_LEN)
        ciphertext = AESGCM(self._key).encrypt(
            nonce, secret.encode("utf-8"), service.encode("utf-8")
        )
        self._data["entries"][service] = {
            "nonce": b64e(nonce),
            "ciphertext": b64e(ciphertext),
        }
        self._save()

    def get(self, service: str) -> str:
        entry = self._data["entries"].get(service)
        if entry is None:
            raise VaultError(f"'{service}' introuvable dans le coffre.")
        nonce = b64d(entry["nonce"])
        ciphertext = b64d(entry["ciphertext"])
        # L'associated data (nom du service) empêche de recoller le
        # ciphertext d'une entrée sur le nom d'une autre.
        plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, service.encode("utf-8"))
        return plaintext.decode("utf-8")

    def remove(self, service: str) -> None:
        if service not in self._data["entries"]:
            raise VaultError(f"'{service}' introuvable.")
        del self._data["entries"][service]
        self._save()

    def list_services(self) -> list[str]:
        return sorted(self._data["entries"])


def prompt_master(confirm: bool = False) -> str:
    pwd = getpass.getpass("Mot de passe maître : ")
    if confirm:
        again = getpass.getpass("Confirmer : ")
        if pwd != again:
            raise VaultError("Les mots de passe maîtres ne correspondent pas.")
    return pwd


def cmd_init(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    master = prompt_master(confirm=True)
    vault.create(master)
    print(f"Coffre créé : {vault.path}")


def cmd_add(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    vault.unlock(prompt_master())
    if args.generate is not None:
        secret = generate_password(args.generate)
        print(f"Mot de passe généré : {secret}")
    else:
        secret = getpass.getpass(f"Secret pour '{args.service}' : ")
    vault.add(args.service, secret, overwrite=args.force)
    print(f"'{args.service}' stocké.")


def cmd_get(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    vault.unlock(prompt_master())
    print(vault.get(args.service))


def cmd_list(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    vault.unlock(prompt_master())
    services = vault.list_services()
    if not services:
        print("Le coffre est vide.")
        return
    for service in services:
        print(service)


def cmd_rm(args: argparse.Namespace) -> None:
    vault = Vault(Path(args.vault))
    vault.unlock(prompt_master())
    vault.remove(args.service)
    print(f"'{args.service}' supprimé.")


def run_demo() -> None:
    """Démo non-interactive : coffre temporaire, nettoyé à la fin."""
    with tempfile.TemporaryDirectory() as tmp:
        vault = Vault(Path(tmp) / "demo_vault.json")
        master = "Demo-Master-Passphrase-42!"

        vault.create(master)
        print(f"Coffre de démo créé ({vault.path}, supprimé en fin de script).")

        vault.add("github", "correct-horse-battery-staple")
        print("Secret stocké pour 'github'.")

        # Ré-ouverture du coffre pour prouver que la clé se re-dérive à
        # l'identique et que le secret est bien récupérable, pas juste
        # vérifiable comme dans l'ancienne version.
        fresh = Vault(vault.path)
        fresh.unlock(master)
        recovered = fresh.get("github")
        print(f"Secret récupéré pour 'github' : {recovered}")
        assert recovered == "correct-horse-battery-staple"
        print("-> récupération correcte : ce n'est pas qu'un vérificateur.")

        try:
            fresh.unlock("mauvais-mot-de-passe")
        except VaultError as exc:
            print(f"Mauvais mot de passe maître rejeté : {exc}")

        print(f"Services dans le coffre : {fresh.list_services()}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Gestionnaire de mots de passe chiffré (AES-256-GCM, scrypt)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    for name in ("init", "add", "get", "list", "rm"):
        p = sub.add_parser(name)
        p.add_argument("--vault", default=str(DEFAULT_VAULT), help="Chemin du coffre (JSON).")
        if name == "add":
            p.add_argument("service")
            p.add_argument("--generate", type=int, nargs="?", const=20, metavar="LONGUEUR")
            p.add_argument("--force", action="store_true")
        elif name in ("get", "rm"):
            p.add_argument("service")

    sub.add_parser("demo", help="Démonstration autonome, sans toucher à un vrai coffre.")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "demo":
        run_demo()
        return

    handlers = {
        "init": cmd_init,
        "add": cmd_add,
        "get": cmd_get,
        "list": cmd_list,
        "rm": cmd_rm,
    }
    try:
        handlers[args.command](args)
    except VaultError as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
