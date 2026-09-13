# Jour 04 — Chiffrement de fichiers (AES-256-GCM)

## Problème résolu

Un laptop volé, un bucket mal configuré, une clé USB oubliée dans le train — vos fichiers confidentiels sont exposés. Ce vault chiffre n'importe quel fichier avec AES-256-GCM : même l'administrateur du serveur ne peut pas le lire sans le mot de passe.

Différence avec un simple zip chiffré : AES-256-GCM est authentifié (détecte toute falsification), la clé est dérivée via PBKDF2 pour résister aux attaques par force brute, et chaque chiffrement utilise un nonce aléatoire unique.

## Usage

```bash
pip install cryptography

# Chiffrer un fichier (écrit <fichier>.vault)
python3 file_vault.py encrypt document_confidentiel.pdf

# Déchiffrer
python3 file_vault.py decrypt document_confidentiel.pdf.vault

# Voir les métadonnées d'un vault sans le mot de passe
python3 file_vault.py inspect document_confidentiel.pdf.vault

# Effacement sécurisé d'un fichier (3 passes)
python3 file_vault.py wipe fichier_sensible.txt

# Chiffrer tout un dossier (ajoute --wipe pour effacer les originaux)
python3 file_vault.py batch ./rapports-financiers/

# Démo (chiffrement, inspection, déchiffrement, mauvais mot de passe, falsification)
python3 file_vault.py demo
```

## Fonctionnalités

- AES-256-GCM — chiffrement et authentification en une seule opération
- PBKDF2-HMAC-SHA256, 600 000 itérations — dérivation résistante aux attaques GPU
- Sel 32 octets et nonce 12 octets aléatoires par fichier
- Format `.vault` auto-descriptif (header JSON avec nom d'origine, date, algorithme)
- Chiffrement de dossiers entiers, avec option d'effacement sécurisé des originaux
- Détection de falsification : toute modification du fichier chiffré fait échouer le déchiffrement

## Conformité

RGPD Art. 32 — le chiffrement comme mesure technique appropriée ; Art. 34(3)(a) — exemption de notification de violation si les données exposées étaient chiffrées.

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 04/30_
