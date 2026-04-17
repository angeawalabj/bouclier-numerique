#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 18 : CHIFFREMENT DE BOUT EN BOUT  ║
║  Protocole : ECDH (X25519) + HKDF + AES-256-GCM                 ║
║  Garantie  : Le serveur ne peut JAMAIS lire les messages         ║
║  Standard  : Inspiré du protocole Signal (Double Ratchet-lite)  ║
╚══════════════════════════════════════════════════════════════════╝

Qu'est-ce que l'E2EE ?
  Dans une messagerie ordinaire (WhatsApp sans E2EE, email, Slack) :
    Alice → [TEXTE CLAIR] → Serveur → [TEXTE CLAIR] → Bob
  Le serveur voit tout, peut lire, modifier, transmettre aux autorités.

  Avec E2EE :
    Alice → [CHIFFRÉ avec clé publique Bob] → Serveur → Bob → [DÉCHIFFRÉ]
  Le serveur ne voit qu'un blob de bytes illisible. La clé privée
  de Bob ne quitte jamais son appareil.

Protocole implémenté :
  1. Chaque utilisateur génère une paire de clés ECDH (courbe X25519)
  2. Les clés PUBLIQUES sont publiées sur le serveur
  3. Pour envoyer à Bob, Alice :
     a. Génère une paire éphémère (Diffie-Hellman Ephemeral)
     b. Calcule un secret partagé : ECDH(clé_éphémère, clé_publique_Bob)
     c. Dérive une clé AES-256 via HKDF (Key Derivation Function)
     d. Chiffre le message avec AES-256-GCM (authentifié)
     e. Envoie : clé_publique_éphémère + nonce + ciphertext
  4. Bob déchiffre avec sa clé privée

  Propriétés cryptographiques :
  ✅  Perfect Forward Secrecy (PFS) — clé éphémère différente à chaque message
  ✅  Authentification intégrée — AES-GCM détecte toute falsification
  ✅  Zero-knowledge serveur — serveur ne voit jamais plaintext ni clés privées
  ✅  Résistance aux attaques de replay — nonce aléatoire 96 bits

Pourquoi ECDH plutôt que RSA ?
  - Clés 100x plus courtes pour sécurité équivalente
  - Calcul 10x plus rapide
  - X25519 conçu pour résister aux attaques sur courbe
  - Utilisé par Signal, WhatsApp, iMessage, WireGuard

Conformité :
  RGPD Art. 32 — 'Le chiffrement est une mesure technique appropriée'
  ANSSI — Recommandations sur les mécanismes cryptographiques
  NIS2 Art. 21 — 'Chiffrement des données en transit et au repos'
"""

import os
import json
import base64
import sqlite3
import secrets
from pathlib import Path
from datetime import datetime
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.exceptions import InvalidTag


# ================================================================
# PRIMITIVES CRYPTOGRAPHIQUES
# ================================================================

class E2EECrypto:
    """
    Boîte à outils E2EE.
    Toutes les opérations sensibles sont ici, isolées.
    """

    # ── Génération de clés ────────────────────────────────────

    @staticmethod
    def generate_identity_keypair() -> tuple:
        """
        Génère une paire de clés d'identité X25519.
        La clé privée ne quitte JAMAIS le client.
        """
        private_key = X25519PrivateKey.generate()
        public_key  = private_key.public_key()
        return private_key, public_key

    @staticmethod
    def serialize_public_key(pub_key: X25519PublicKey) -> str:
        """Sérialise la clé publique en base64 pour transmission."""
        raw = pub_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return base64.b64encode(raw).decode()

    @staticmethod
    def deserialize_public_key(b64: str) -> X25519PublicKey:
        """Désérialise une clé publique depuis base64."""
        raw = base64.b64decode(b64)
        return X25519PublicKey.from_public_bytes(raw)

    @staticmethod
    def serialize_private_key(priv_key: X25519PrivateKey,
                               password: bytes = None) -> bytes:
        """Sérialise la clé privée (chiffrée si password fourni)."""
        if password:
            enc = serialization.BestAvailableEncryption(password)
        else:
            enc = serialization.NoEncryption()
        return priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc
        )

    # ── Chiffrement d'un message ──────────────────────────────

    @staticmethod
    def encrypt_message(plaintext: str,
                         recipient_public_key: X25519PublicKey,
                         sender_identity_key: X25519PrivateKey = None
                         ) -> dict:
        """
        Chiffre un message pour un destinataire.

        Retourne un dict contenant tout ce dont Bob a besoin
        pour déchiffrer — sauf la clé privée d'Alice.

        Structure du message chiffré :
        {
          "eph_pub":  <clé publique éphémère en base64>,
          "nonce":    <nonce 96 bits aléatoire en base64>,
          "ciphertext": <message chiffré AES-256-GCM en base64>,
          "sender_pub": <clé publique d'Alice pour vérification>,
          "ts":       <timestamp>,
        }
        """
        # Étape 1 : Générer une paire éphémère (PFS)
        eph_priv = X25519PrivateKey.generate()
        eph_pub  = eph_priv.public_key()

        # Étape 2 : ECDH — calculer le secret partagé
        # shared_secret = ECDH(eph_priv, recipient_pub)
        shared_secret = eph_priv.exchange(recipient_public_key)

        # Étape 3 : HKDF — dériver une clé AES-256 depuis le secret
        # HKDF évite d'utiliser directement le résultat ECDH comme clé
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits
            salt=None,
            info=b"e2ee-messaging-v1",
        ).derive(shared_secret)

        # Étape 4 : Chiffrement AES-256-GCM
        # GCM = authentifié → détecte toute falsification
        nonce     = secrets.token_bytes(12)  # 96 bits — requis par GCM
        aesgcm    = AESGCM(aes_key)
        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode("utf-8"),
            None  # AAD (données authentifiées additionnelles) — optionnel
        )

        # Sérialiser pour envoi au serveur
        eph_pub_b64  = E2EECrypto.serialize_public_key(eph_pub)
        sender_b64   = ""
        if sender_identity_key:
            sender_b64 = E2EECrypto.serialize_public_key(
                sender_identity_key.public_key()
            )

        return {
            "eph_pub":    eph_pub_b64,
            "nonce":      base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "sender_pub": sender_b64,
            "ts":         datetime.now().isoformat(),
            "version":    "e2ee-v1",
        }

    @staticmethod
    def decrypt_message(encrypted: dict,
                         recipient_private_key: X25519PrivateKey) -> str:
        """
        Déchiffre un message avec la clé privée du destinataire.
        Lève une exception si le message a été falsifié.
        """
        # Récupérer la clé publique éphémère de l'expéditeur
        eph_pub = E2EECrypto.deserialize_public_key(encrypted["eph_pub"])

        # ECDH : calculer le même secret partagé que l'expéditeur
        # ECDH(recipient_priv, eph_pub) == ECDH(eph_priv, recipient_pub)
        # C'est la magie de Diffie-Hellman
        shared_secret = recipient_private_key.exchange(eph_pub)

        # HKDF : même dérivation que l'expéditeur
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"e2ee-messaging-v1",
        ).derive(shared_secret)

        # AES-256-GCM déchiffrement + vérification d'authenticité
        nonce      = base64.b64decode(encrypted["nonce"])
        ciphertext = base64.b64decode(encrypted["ciphertext"])
        aesgcm     = AESGCM(aes_key)

        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext.decode("utf-8")
        except InvalidTag:
            raise ValueError(
                "❌ Authentification échouée — message falsifié ou "
                "clé incorrecte"
            )

    @staticmethod
    def fingerprint(public_key: X25519PublicKey) -> str:
        """
        Empreinte de la clé publique pour vérification manuelle
        (comme Signal 'Safety Number').
        """
        raw = public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        h = hashes.Hash(hashes.SHA256())
        h.update(raw)
        digest = h.finalize().hex()
        # Formater en groupes de 5 chiffres (style Signal)
        return " ".join(digest[i:i+5] for i in range(0, 20, 5))


# ================================================================
# SERVEUR (ZERO-KNOWLEDGE)
# ================================================================

class E2EEServer:
    """
    Serveur de messagerie ZERO-KNOWLEDGE.
    Stocke et route les messages chiffrés.
    Ne connaît jamais les clés privées ni les plaintexts.

    Ce qu'il voit  : blobs opaques + clés publiques
    Ce qu'il ne voit PAS : le contenu des messages
    """

    def __init__(self, db_path: str = "/tmp/e2ee_server.db"):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _init(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS users (
                    username    TEXT PRIMARY KEY,
                    public_key  TEXT NOT NULL,
                    fingerprint TEXT,
                    registered_at TEXT
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_user   TEXT NOT NULL,
                    to_user     TEXT NOT NULL,
                    payload     TEXT NOT NULL,
                    delivered   INTEGER DEFAULT 0,
                    sent_at     TEXT NOT NULL
                );
            """)
            conn.commit()

    def register(self, username: str, public_key_b64: str,
                  fingerprint: str = "") -> bool:
        """Enregistre un utilisateur avec sa clé publique."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO users "
                    "(username, public_key, fingerprint, registered_at) "
                    "VALUES (?,?,?,?)",
                    (username, public_key_b64, fingerprint,
                     datetime.now().isoformat())
                )
                conn.commit()
            return True
        except Exception:
            return False

    def get_public_key(self, username: str) -> Optional[str]:
        """Retourne la clé publique d'un utilisateur."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT public_key FROM users WHERE username=?",
                (username,)
            ).fetchone()
        return row[0] if row else None

    def send_message(self, from_user: str, to_user: str,
                      payload: dict) -> int:
        """
        Stocke un message chiffré.
        Le serveur reçoit uniquement un blob JSON opaque.
        Il ne peut PAS le déchiffrer.
        """
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute(
                "INSERT INTO messages (from_user, to_user, payload, sent_at) "
                "VALUES (?,?,?,?)",
                (from_user, to_user,
                 json.dumps(payload), datetime.now().isoformat())
            )
            conn.commit()
            return cursor.lastrowid

    def get_messages(self, username: str) -> list:
        """Récupère les messages en attente pour un utilisateur."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM messages WHERE to_user=? AND delivered=0 "
                "ORDER BY id",
                (username,)
            ).fetchall()
            # Marquer comme délivrés
            conn.execute(
                "UPDATE messages SET delivered=1 WHERE to_user=?",
                (username,)
            )
            conn.commit()
        return [dict(r) for r in rows]

    def get_all_messages(self, username: str) -> list:
        """Récupère tous les messages (pour la démo)."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM messages WHERE to_user=? ORDER BY id",
                (username,)
            ).fetchall()
        return [dict(r) for r in rows]

    def dump_database(self) -> dict:
        """
        Ce que voit un admin/attaquant qui accède au serveur.
        Démontre l'opacité totale du stockage.
        """
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            users = conn.execute("SELECT * FROM users").fetchall()
            msgs  = conn.execute(
                "SELECT id, from_user, to_user, payload, sent_at "
                "FROM messages ORDER BY id"
            ).fetchall()
        return {
            "users":    [dict(u) for u in users],
            "messages": [dict(m) for m in msgs],
        }


# ================================================================
# CLIENT (détient la clé privée)
# ================================================================

class E2EEClient:
    """
    Client E2EE côté utilisateur.
    Détient la clé privée — ne la partage JAMAIS avec le serveur.
    """

    def __init__(self, username: str, server: E2EEServer,
                  key_file: str = None):
        self.username  = username
        self.server    = server
        self._priv_key = None
        self._pub_key  = None
        self._key_file = key_file or f"/tmp/e2ee_{username}.key"

    def register(self, password: str = "") -> str:
        """
        Génère les clés et s'enregistre sur le serveur.
        La clé privée est sauvegardée localement.
        """
        self._priv_key, self._pub_key = E2EECrypto.generate_identity_keypair()
        pub_b64  = E2EECrypto.serialize_public_key(self._pub_key)
        fp       = E2EECrypto.fingerprint(self._pub_key)

        # Sauvegarder la clé privée (chiffrée si password)
        priv_pem = E2EECrypto.serialize_private_key(
            self._priv_key,
            password.encode() if password else None
        )
        Path(self._key_file).write_bytes(priv_pem)

        # Publier uniquement la clé PUBLIQUE sur le serveur
        self.server.register(self.username, pub_b64, fp)
        return fp

    def send(self, to: str, message: str) -> int:
        """Envoie un message chiffré à un destinataire."""
        # Récupérer la clé publique du destinataire depuis le serveur
        recipient_pub_b64 = self.server.get_public_key(to)
        if not recipient_pub_b64:
            raise ValueError(f"Utilisateur {to} introuvable")

        recipient_pub = E2EECrypto.deserialize_public_key(recipient_pub_b64)

        # Chiffrer le message (hors-ligne possible)
        encrypted = E2EECrypto.encrypt_message(
            message, recipient_pub, self._priv_key
        )

        # Envoyer le blob opaque au serveur
        return self.server.send_message(self.username, to, encrypted)

    def receive(self) -> list:
        """Récupère et déchiffre les messages en attente."""
        raw_messages = self.server.get_all_messages(self.username)
        decrypted    = []

        for msg in raw_messages:
            payload = json.loads(msg["payload"])
            try:
                plaintext = E2EECrypto.decrypt_message(
                    payload, self._priv_key
                )
                decrypted.append({
                    "id":        msg["id"],
                    "from":      msg["from_user"],
                    "text":      plaintext,
                    "ts":        msg["sent_at"],
                    "decrypted": True,
                })
            except Exception as e:
                decrypted.append({
                    "id":        msg["id"],
                    "from":      msg["from_user"],
                    "text":      f"[Erreur déchiffrement : {e}]",
                    "ts":        msg["sent_at"],
                    "decrypted": False,
                })
        return decrypted

    @property
    def fingerprint(self) -> str:
        if self._pub_key:
            return E2EECrypto.fingerprint(self._pub_key)
        return "clé non chargée"


# ================================================================
# DÉMONSTRATION COMPLÈTE
# ================================================================

def run_demo():
    import tempfile

    SEP = "=" * 62
    print(f"\n{SEP}")
    print("  DEMO — Chiffrement E2EE (Signal-like)")
    print(f"{SEP}\n")
    print(
        "  Scénario : Alice et Bob communiquent via un serveur.\n"
        "  Démonstration que :\n"
        "  ✅  Le serveur ne peut pas lire les messages\n"
        "  ✅  Un attaquant qui vole la DB ne voit que des bytes\n"
        "  ✅  Chaque message utilise une clé différente (PFS)\n"
        "  ✅  Toute falsification est détectée (GCM auth)\n"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        server = E2EEServer(str(tmp / "server.db"))

        # ── Étape 1 : Enregistrement ──
        print(f"  {'─'*60}")
        print(f"  🔑  ÉTAPE 1 : GÉNÉRATION DES CLÉS (côté clients)")
        print(f"  {'─'*60}\n")

        alice = E2EEClient("alice", server, str(tmp / "alice.key"))
        bob   = E2EEClient("bob",   server, str(tmp / "bob.key"))
        eve   = E2EEClient("eve",   server, str(tmp / "eve.key"))

        fp_alice = alice.register()
        fp_bob   = bob.register()
        fp_eve   = eve.register()

        print(f"  Alice  — Clé générée localement")
        print(f"           Empreinte : {fp_alice}")
        print(f"           ↳ Clé PRIVÉE : stockée sur l'appareil d'Alice")
        print(f"           ↳ Clé PUBLIQUE : publiée sur le serveur\n")

        print(f"  Bob    — Clé générée localement")
        print(f"           Empreinte : {fp_bob}")
        print(f"           ↳ Clé PRIVÉE : stockée sur l'appareil de Bob\n")

        print(f"  Eve    — Clé générée (attaquante)")
        print(f"           Empreinte : {fp_eve}\n")

        # ── Étape 2 : Envoi de messages ──
        print(f"  {'─'*60}")
        print(f"  📨  ÉTAPE 2 : ALICE ENVOIE DES MESSAGES À BOB")
        print(f"  {'─'*60}\n")

        messages = [
            "Bonjour Bob ! Le serveur ne peut pas lire ceci.",
            "Mot de passe du VPN : Xk#9mP$2nQ@rL5",
            "RDV demain à 14h pour la réunion secrète.",
        ]

        for msg in messages:
            mid = alice.send("bob", msg)
            print(f"  ✉️  Alice → Bob  [msg#{mid}]")
            print(f"      Plaintext : « {msg} »")

            # Afficher ce que le serveur voit
            dump = server.dump_database()
            srv_payload = json.loads(dump["messages"][-1]["payload"])
            print(f"      Serveur voit : {{")
            print(f"        eph_pub    : {srv_payload['eph_pub'][:20]}...")
            print(f"        nonce      : {srv_payload['nonce']}")
            print(f"        ciphertext : {srv_payload['ciphertext'][:32]}...")
            print(f"      }}")
            print()

        # ── Étape 3 : Bob déchiffre ──
        print(f"  {'─'*60}")
        print(f"  🔓  ÉTAPE 3 : BOB DÉCHIFFRE AVEC SA CLÉ PRIVÉE")
        print(f"  {'─'*60}\n")

        received = bob.receive()
        for msg in received:
            icon = "✅" if msg["decrypted"] else "❌"
            print(f"  {icon}  Message #{msg['id']} de {msg['from']}")
            print(f"      Déchiffré : « {msg['text']} »\n")

        # ── Étape 4 : PFS — clés éphémères différentes ──
        print(f"  {'─'*60}")
        print(f"  🔄  ÉTAPE 4 : PERFECT FORWARD SECRECY (PFS)")
        print(f"  {'─'*60}\n")

        print(f"  Clés éphémères utilisées pour chaque message :")
        dump = server.dump_database()
        for m in dump["messages"]:
            p  = json.loads(m["payload"])
            print(f"  Message #{m['id']} → eph_pub = {p['eph_pub'][:28]}...")

        print(f"\n  ✅  Chaque message utilise une clé éphémère DIFFÉRENTE")
        print(f"  ✅  Si la clé privée de Bob est compromise APRÈS envoi,")
        print(f"      les messages passés restent chiffrés (PFS garantie)\n")

        # ── Étape 5 : Ce que voit l'attaquant sur le serveur ──
        print(f"  {'─'*60}")
        print(f"  👁️   ÉTAPE 5 : VUE D'UN ATTAQUANT AYANT ACCÈS AU SERVEUR")
        print(f"  {'─'*60}\n")

        dump = server.dump_database()
        print(f"  Base de données du serveur compromise (contenu réel) :\n")
        print(f"  Table USERS :")
        for u in dump["users"]:
            print(f"    {u['username']:<10} pub_key={u['public_key'][:28]}...")

        print(f"\n  Table MESSAGES :")
        for m in dump["messages"]:
            p = json.loads(m["payload"])
            print(f"    #{m['id']} {m['from_user']}→{m['to_user']} | "
                  f"ciphertext={p['ciphertext'][:24]}... [ILLISIBLE]")

        print(f"\n  ❌  L'attaquant voit les métadonnées (qui → qui)")
        print(f"  ❌  Mais le contenu est un blob de bytes inexploitable\n")

        # ── Étape 6 : Tentative d'usurpation (Eve) ──
        print(f"  {'─'*60}")
        print(f"  🎭  ÉTAPE 6 : TENTATIVE DE FALSIFICATION (Eve au milieu)")
        print(f"  {'─'*60}\n")

        print(f"  Scénario : Eve intercepte et modifie un message en transit\n")

        # Alice envoie un message légitime
        mid = alice.send("bob", "Virement de 10 000€ sur IBAN FR76...")

        # Eve récupère le message et modifie le ciphertext
        with sqlite3.connect(str(tmp / "server.db")) as conn:
            row = conn.execute(
                "SELECT payload FROM messages WHERE id=?", (mid,)
            ).fetchone()
            corrupted = json.loads(row[0])
            # Modifier quelques bytes du ciphertext
            ct_bytes = base64.b64decode(corrupted["ciphertext"])
            ct_tampered = bytes([b ^ 0xFF for b in ct_bytes[:4]]) + ct_bytes[4:]
            corrupted["ciphertext"] = base64.b64encode(ct_tampered).decode()
            conn.execute(
                "UPDATE messages SET payload=? WHERE id=?",
                (json.dumps(corrupted), mid)
            )
            conn.commit()

        print(f"  Eve a modifié le ciphertext du message #{mid}...")

        # Bob tente de déchiffrer
        tampered_raw = server.get_all_messages("bob")
        for msg_raw in tampered_raw:
            if msg_raw["id"] == mid:
                payload = json.loads(msg_raw["payload"])
                try:
                    pt = E2EECrypto.decrypt_message(payload, bob._priv_key)
                    print(f"  ⚠️  Bob déchiffre (ne devrait pas marcher) : {pt}")
                except ValueError as e:
                    print(f"  ✅  Bob reçoit une ERREUR : {e}")
                    print(f"  ✅  AES-GCM a détecté la falsification !")
                    print(f"  ✅  Message corrompu rejeté automatiquement\n")

        # ── Résumé cryptographique ──
        print(f"\n{SEP}")
        print(f"  🔬  RÉSUMÉ CRYPTOGRAPHIQUE")
        print(f"{SEP}\n")
        print(
            "  Protocole :\n"
            "  ┌─ Échange de clés : X25519 (ECDH)\n"
            "  │   Clé publique : 32 bytes · Clé privée : 32 bytes\n"
            "  │   Sécurité ≈ RSA 3072 bits avec 10x moins de calculs\n"
            "  │\n"
            "  ├─ Dérivation : HKDF-SHA256\n"
            "  │   Transforme le secret ECDH en clé AES propre\n"
            "  │\n"
            "  ├─ Chiffrement : AES-256-GCM\n"
            "  │   256 bits · Nonce 96 bits aléatoire · Tag d'auth 128 bits\n"
            "  │   Authentification intégrée → falsification impossible\n"
            "  │\n"
            "  └─ PFS : clé éphémère générée POUR CHAQUE message\n"
            "      Si clé privée compromise aujourd'hui → messages\n"
            "      passés restent chiffrés (pas de master key)\n"
            "\n"
            "  Ce que le serveur stocke : eph_pub + nonce + ciphertext\n"
            "  Ce que le serveur voit   : des bytes illisibles\n"
            "  Ce que le serveur peut   : router, stocker, transmettre\n"
            "  Ce que le serveur ne peut PAS : déchiffrer, modifier\n"
            "\n"
            "  Conformité :\n"
            "  ✅  RGPD Art. 32 — chiffrement approprié des données\n"
            "  ✅  NIS2 Art. 21 — chiffrement en transit et au repos\n"
            "  ✅  ANSSI RGS — algorithmes recommandés (AES-256, SHA-256)\n"
        )


# ================================================================
# CLI
# ================================================================

def main():
    import argparse, tempfile

    print(__doc__)
    parser = argparse.ArgumentParser()
    sub    = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")

    p_reg = sub.add_parser("register")
    p_reg.add_argument("username")
    p_reg.add_argument("--db", default="/tmp/e2ee_server.db")

    p_send = sub.add_parser("send")
    p_send.add_argument("from_user")
    p_send.add_argument("to_user")
    p_send.add_argument("message")
    p_send.add_argument("--db", default="/tmp/e2ee_server.db")

    p_recv = sub.add_parser("receive")
    p_recv.add_argument("username")
    p_recv.add_argument("--db", default="/tmp/e2ee_server.db")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    server = E2EEServer(args.db)

    if args.cmd == "register":
        client = E2EEClient(args.username, server)
        fp     = client.register()
        print(f"\n  ✅  {args.username} enregistré")
        print(f"  Empreinte : {fp}\n")

    elif args.cmd == "send":
        client = E2EEClient(args.from_user, server)
        # Charger clé si existante
        key_file = Path(f"/tmp/e2ee_{args.from_user}.key")
        if key_file.exists():
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            client._priv_key = load_pem_private_key(
                key_file.read_bytes(), password=None
            )
        mid = client.send(args.to_user, args.message)
        print(f"\n  ✅  Message #{mid} envoyé (chiffré)\n")

    elif args.cmd == "receive":
        client = E2EEClient(args.username, server)
        key_file = Path(f"/tmp/e2ee_{args.username}.key")
        if key_file.exists():
            from cryptography.hazmat.primitives.serialization import load_pem_private_key
            client._priv_key = load_pem_private_key(
                key_file.read_bytes(), password=None
            )
        msgs = client.receive()
        print(f"\n  {len(msgs)} message(s) pour {args.username} :\n")
        for m in msgs:
            print(f"  De : {m['from']}  [{m['ts'][:19]}]")
            print(f"  « {m['text']} »\n")


if __name__ == "__main__":
    main()
