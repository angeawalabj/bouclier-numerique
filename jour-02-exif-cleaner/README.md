# Jour 02 — Nettoyeur de métadonnées EXIF

## Problème résolu

Partagez une photo prise à votre domicile et tout le monde peut en extraire les coordonnées GPS exactes. Les fichiers JPEG/PNG contiennent des métadonnées invisibles : coordonnées GPS, modèle d'appareil, date et heure, parfois numéro de série. Des journalistes et activistes ont déjà été localisés via les EXIF de photos publiées en ligne.

Cas d'usage : nettoyer les photos avant publication sur un site web ou les réseaux sociaux, traitement des photos soumises par des utilisateurs (RGPD Art. 5.1.c — minimisation des données).

## Usage

```bash
pip install Pillow

# Analyser les métadonnées d'une image sans la modifier
python3 exif_cleaner.py analyze photo.jpg

# Nettoyer une photo (écrit photo_clean.jpg par défaut)
python3 exif_cleaner.py clean photo.jpg
python3 exif_cleaner.py clean photo.jpg -o photo_sans_meta.jpg

# Nettoyer tout un dossier d'images (écrit dans <dossier>/cleaned/)
python3 exif_cleaner.py batch ./photos/

# Démo autonome (crée une image de test, l'analyse, la nettoie, vérifie)
python3 exif_cleaner.py demo
```

## Fonctionnalités

- Détecte et signale les tags GPS, identité, appareil et horodatage
- Nettoie en reconstruisant l'image depuis les pixels décodés (pas une suppression tag par tag), pour ne pas laisser de métadonnées cachées dans des blocs de fabricant non documentés
- Mode audit (`analyze`) : inventaire des métadonnées présentes sans rien modifier
- Traitement par lot avec rapport de nettoyage
- Vérification post-nettoyage (`verify_clean`) pour confirmer l'absence de tags sensibles

## Conformité

RGPD Art. 5(1)(c) — principe de minimisation des données.

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 02/30_
