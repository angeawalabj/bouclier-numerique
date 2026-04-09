# 🗄️ Jour 04 — Chiffrement de Fichiers AES-256-GCM

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Algo](https://img.shields.io/badge/Algo-AES--256--GCM+·+PBKDF2-00e5a0?style=flat-square)
![RGPD](https://img.shields.io/badge/RGPD-Art.+32-blue?style=flat-square)

</div>

---

## 🎯 Problème résolu

Un laptop volé, un bucket S3 mal configuré, une clé USB oubliée dans le train — vos fichiers confidentiels sont exposés. Ce vault chiffre n'importe quel fichier avec AES-256-GCM : même l'administrateur du serveur ne peut pas le lire sans le mot de passe.

**Différence avec un simple zip chiffré** : AES-256-GCM est authentifié (détecte toute falsification), utilise PBKDF2 pour résister aux attaques par force brute, et génère un nonce aléatoire unique pour chaque chiffrement.

---

## ⚡ Usage

```bash
pip install cryptography

# Chiffrer
python file_vault.py encrypt document_confidentiel.pdf

# Déchiffrer
python file_vault.py decrypt document_confidentiel.pdf.enc

# Chiffrer un dossier
python file_vault.py encrypt-dir ./rapports-financiers/

# Démo
python file_vault.py demo
```

---

## ✨ Fonctionnalités

- AES-256-GCM — chiffrement + authentification intégrée
- PBKDF2-SHA256 — dérivation résistante aux attaques GPU
- Sel unique 32 bytes par fichier
- Nonce aléatoire 96 bits par opération
- Chiffrement de dossiers entiers (récursif)
- Vérification d'intégrité avant déchiffrement

---

## ⚖️ Conformité

RGPD Art. 32 — chiffrement comme mesure technique appropriée

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 04/30_
