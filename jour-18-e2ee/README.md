# Jour 18 — Messagerie Chiffrée de Bout en Bout (E2EE)

Python 3.10+. X25519 + HKDF + AES-256-GCM, inspiré du protocole Signal.
Le serveur stocke les messages mais ne peut jamais les lire.

---

## Problème résolu

Dans la plupart des messageries d'entreprise (Slack, Teams sans E2EE, email), **le serveur voit tout** : il peut lire, modifier, transmettre aux autorités ou être compromis. L'E2EE garantit que le chiffrement se fait *avant* l'envoi, avec des clés que le serveur ne possède jamais.

```
Messagerie classique :
  Alice → [TEXTE CLAIR] → Serveur (voit tout) → [TEXTE CLAIR] → Bob

Messagerie E2EE :
  Alice → [AES-256-GCM chiffré] → Serveur (blob illisible) → Bob → [Déchiffré]
```

**Cas d'usage :**
- Communication interne sur des sujets sensibles (M&A, RH, incidents sécu)
- Transmission de credentials ou secrets entre équipes
- Conformité RGPD Art. 32 sur les données personnelles en transit

---

## Protocole cryptographique

### Étapes d'un envoi (Alice → Bob)

```
1. Alice récupère la clé publique de Bob sur le serveur
2. Alice génère une paire éphémère (Diffie-Hellman Ephemeral)
3. ECDH : secret = X25519(alice_eph_priv, bob_pub)
4. HKDF-SHA256 : aes_key = derive(secret, "e2ee-messaging-v1")
5. AES-256-GCM : ciphertext = encrypt(message, aes_key, nonce_96bits)
6. Envoi : {eph_pub, nonce, ciphertext} → Serveur → Bob
7. Bob : secret = X25519(bob_priv, eph_pub) → même clé AES → déchiffre
```

### Pourquoi X25519 plutôt que RSA ?

| Critère | RSA-2048 | X25519 |
|---------|---------|--------|
| Taille de clé | 256 bytes | **32 bytes** |
| Vitesse | Référence | **~10× plus rapide** |
| Sécurité équivalente | RSA-3072 | ✅ |
| Résistance aux side-channel | Partielle | **Forte (temps constant)** |
| Utilisé par | PGP legacy | Signal, WhatsApp, WireGuard |

---

## Démarrage rapide

```bash
pip install cryptography

# Démo complète (6 scénarios), tout en local
python e2ee_messaging.py demo
```

### Sur deux machines différentes

Le relais HTTP ne voit que des clés publiques et des blobs chiffrés —
jamais une clé privée ni un texte en clair (`send_message`/`get_public_key`
sont ses seules opérations, comparer `e2ee_messaging.py` pour le détail).

```bash
# Sur le serveur (ou une machine accessible des deux correspondants)
python e2ee_messaging.py server --port 8766

# Sur le poste d'Alice
python e2ee_messaging.py register alice --server-url http://IP_SERVEUR:8766
python e2ee_messaging.py send alice bob "Message confidentiel" \
  --server-url http://IP_SERVEUR:8766

# Sur le poste de Bob
python e2ee_messaging.py register bob --server-url http://IP_SERVEUR:8766
python e2ee_messaging.py receive bob --server-url http://IP_SERVEUR:8766
```

Sans `--server-url`, `register`/`send`/`receive` utilisent une base
SQLite locale (`--db`, par défaut `/tmp/e2ee_server.db`) — pratique pour
tester le protocole sur une seule machine, mais ne remplace pas un
vrai relais entre deux correspondants distants.

---

## Ce que prouve la démo

### 1. Chiffrement effectif — le serveur ne voit que des bytes

```python
# Alice envoie : "Mot de passe du VPN : Xk#9mP$2nQ@rL5"

# Le serveur stocke :
{
  "eph_pub":    "k/fkVzrp6rFxFPBaWtXhwlxnow2Z...",
  "nonce":      "WCtFynzWl+nn6oTx",
  "ciphertext": "G7smLRa44oq1eY3M44eWt8oJ..."   # illisible
}
```

### 2. Perfect Forward Secrecy — clé différente pour chaque message

```
Message 1 → eph_pub = A5ZCEKcksn+fpQb+Xg2h...
Message 2 → eph_pub = k/fkVzrp6rFxFPBaWtXh...   ← différent
Message 3 → eph_pub = HX8LDRfIgyg4p477m598...   ← différent
```

Si la clé privée de Bob est compromise dans 6 mois, les messages passés **restent chiffrés**.

### 3. Détection de falsification (AES-GCM)

```python
# Eve modifie 4 bytes du ciphertext
# Bob tente de déchiffrer :
# → ❌ InvalidTag : Authentification échouée — message falsifié
```

---

## Structure des messages

```json
{
  "version":    "e2ee-v1",
  "eph_pub":    "<base64 clé publique éphémère 32 bytes>",
  "nonce":      "<base64 nonce 12 bytes aléatoire>",
  "ciphertext": "<base64 message chiffré + tag GCM 16 bytes>",
  "sender_pub": "<base64 clé publique de l'expéditeur>",
  "ts":         "2026-03-12T09:00:00"
}
```

**Ce que le serveur sait :** qui écrit à qui, quand, quelle taille.  
**Ce que le serveur ne sait pas :** le contenu des messages.

---

## Gestion des clés

```
Clé d'identité (long terme)
├── Privée : stockée localement (~/e2ee_alice.key)
│            Jamais transmise. Jamais.
└── Publique : publiée sur le serveur
               Accessible à tous (permet de chiffrer pour Alice)

Clé éphémère (par message)
├── Générée juste avant l'envoi
├── Utilisée une seule fois
└── Détruite après → PFS garantie
```

---

## Conformité

| Référentiel | Exigence couverte |
|------------|-----------------|
| **RGPD Art. 32** | Chiffrement approprié des données personnelles |
| **NIS2 Art. 21** | Chiffrement en transit et au repos |
| **ANSSI RGS** | AES-256, SHA-256 — algorithmes recommandés |
| **ISO 27001 A.10** | Cryptographie et gestion des clés |

---

## Ressources

- [Signal Protocol Specification](https://signal.org/docs/)
- [RFC 7748 — X25519](https://datatracker.ietf.org/doc/html/rfc7748)
- [RFC 5869 — HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [NIST SP 800-38D — AES-GCM](https://csrc.nist.gov/publications/detail/sp/800-38d/final)

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 18/30_
