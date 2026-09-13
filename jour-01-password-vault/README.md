# 🔑 Jour 01 — Coffre-fort de Mots de Passe

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Crypto](https://img.shields.io/badge/Crypto-AES--256--GCM%20·%20scrypt-00e5a0?style=flat-square)
![RGPD](https://img.shields.io/badge/RGPD-Art.%2032-blue?style=flat-square)
![ANSSI](https://img.shields.io/badge/ANSSI-RGS%20B+-green?style=flat-square)

**Gestionnaire de mots de passe local, chiffré de bout en bout.**  
Zéro dépendance cloud · Maître chiffré scrypt · Coffre AES-256-GCM

</div>

---

## 🎯 Problème résolu

Les gestionnaires de mots de passe cloud (LastPass, 1Password) ont été victimes de violations de données. Ce coffre-fort fonctionne entièrement **en local** : vos mots de passe ne quittent jamais votre machine, et le fichier chiffré est illisible sans le mot de passe maître.

**Cas d'usage concret :**
- Équipe IT qui stocke des credentials serveurs de production
- DPO qui archive les mots de passe d'accès aux traitements RGPD
- Développeur qui sécurise ses clés API et tokens

---

## 🔬 Architecture cryptographique

```
Mot de passe maître
        │
        ▼
   scrypt (N=2^17, r=8, p=1)       ← Résistant aux attaques GPU
        │
        ▼
   Clé AES-256 (32 bytes)
        │
        ▼
   AES-256-GCM (nonce 96 bits)     ← Authentifié : détecte toute falsification
        │
        ▼
   Fichier .vault chiffré
```

### Pourquoi scrypt et pas bcrypt ?

| Algorithme | Mémoire | GPU résistant | Usage recommandé |
|-----------|---------|--------------|-----------------|
| MD5/SHA | ~0 | ❌ Non | Jamais pour les mots de passe |
| bcrypt | Fixe (~4 KB) | Partiel | Acceptable |
| scrypt | Configurable (128 MB+) | ✅ Oui | Recommandé |
| Argon2id | Configurable | ✅ Oui | Optimal (OWASP 2023) |

scrypt avec `N=2^17` nécessite 128 MB de RAM par dérivation — un GPU avec 10 000 cœurs ne peut en faire que quelques dizaines simultanément.

---

## ⚡ Installation & Usage

### Dépendances

```bash
pip install cryptography
```

### Commandes

```bash
# Créer un nouveau coffre
python password_vault.py init --vault mon_coffre.vault

# Ajouter une entrée
python password_vault.py add --name "GitHub" --login "alice" --url "github.com"

# Lister les entrées
python password_vault.py list

# Récupérer un mot de passe
python password_vault.py get --name "GitHub"

# Générer un mot de passe fort
python password_vault.py generate --length 32 --symbols

# Démo complète
python password_vault.py demo
```

### Exemple de sortie

```
🔑  Coffre-fort · TechCorp RSSI
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Entrées : 5  ·  Dernière ouverture : 2026-03-12 09:14

  ┌─────────────────┬──────────────┬───────────┐
  │ Nom             │ Login        │ Force     │
  ├─────────────────┼──────────────┼───────────┤
  │ GitHub Prod     │ alice@...    │ ██████ 94 │
  │ AWS Console     │ admin        │ ████   71 │
  │ VPN TechCorp    │ jmartin      │ ██████ 88 │
  └─────────────────┴──────────────┴───────────┘
```

---

## 🛡️ Fonctionnalités de sécurité

| Fonctionnalité | Détail |
|---------------|--------|
| **Chiffrement** | AES-256-GCM — chiffrement + authentification |
| **Dérivation** | scrypt(N=2¹⁷, r=8, p=1) — résistant GPU |
| **Sel** | 32 bytes aléatoires uniques par coffre |
| **Nonce** | 12 bytes aléatoires uniques par opération |
| **Verrouillage** | Auto-lock après 5 min d'inactivité |
| **Audit** | Journal chiffré des accès |
| **Export** | CSV chiffré pour migration |
| **Générateur** | Mots de passe forts avec évaluation ZXCVBN |

---

## ⚖️ Conformité

| Référentiel | Exigence | Couverture |
|------------|----------|------------|
| **RGPD Art. 32** | Chiffrement des données personnelles | ✅ AES-256-GCM |
| **ANSSI RGS B+** | Algorithmes crypto approuvés | ✅ AES-256, scrypt |
| **ISO 27001 A.9.4** | Contrôle d'accès aux systèmes | ✅ Master password |
| **PCI-DSS 3.4** | Chiffrement des données sensibles | ✅ |

---

## 🔗 Ressources

- [ANSSI — Recommandations sur les mots de passe](https://www.ssi.gouv.fr/guide/recommandations-relatives-a-lauthentification-multifacteur-et-aux-mots-de-passe/)
- [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [RFC 7914 — scrypt specification](https://datatracker.ietf.org/doc/html/rfc7914)

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 1/30_
