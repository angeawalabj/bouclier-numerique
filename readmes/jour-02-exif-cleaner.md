# 🖼️ Jour 02 — Nettoyeur de Métadonnées EXIF

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Lib](https://img.shields.io/badge/Lib-Pillow+·+piexif-00e5a0?style=flat-square)
![RGPD](https://img.shields.io/badge/RGPD-Art.+5(1)(c)-blue?style=flat-square)

</div>

---

## 🎯 Problème résolu

Partagez une photo prise à votre domicile et tout le monde connaît votre adresse GPS exacte. Les fichiers JPEG/PNG contiennent des métadonnées invisibles : coordonnées GPS, modèle d'appareil, date et heure, parfois numéro de série.

**En 2022, un journaliste a été localisé uniquement via les métadonnées EXIF d'une photo publiée sur les réseaux sociaux.**

Cas d'usage : nettoyer les photos avant publication sur un site web ou les réseaux sociaux, traitement des photos soumises par des utilisateurs (RGPD Art. 5.1.c — minimisation des données).

---

## ⚡ Usage

```bash
pip install Pillow piexif

# Nettoyer une photo
python exif_cleaner.py clean photo.jpg

# Nettoyer un dossier entier (récursif)
python exif_cleaner.py clean-dir ./photos/ --recursive

# Rapport des métadonnées avant nettoyage
python exif_cleaner.py inspect photo.jpg

# Démo
python exif_cleaner.py demo
```

---

## ✨ Fonctionnalités

- Supprime GPS, appareil, horodatage, auteur, commentaires
- Préserve la qualité image (pas de recompression JPEG)
- Traitement par lot avec rapport de nettoyage
- Mode audit : inventaire des données présentes sans modifier
- Support JPEG, PNG, TIFF, HEIC

---

## ⚖️ Conformité

RGPD Art. 5(1)(c) — principe de minimisation des données

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 02/30_
