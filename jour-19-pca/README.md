# 📖 Jour 19 — Plan de Continuité d'Activité (PCA/BCP)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Output](https://img.shields.io/badge/Output-DOCX+·+Checklist-00e5a0?style=flat-square)
![ISO](https://img.shields.io/badge/ISO-22301+·+27001+A.17-blue?style=flat-square)

</div>

---

## 🎯 Problème résolu

À 02h47, le ransomware se déclenche. Votre serveur est chiffré. Vous avez une heure avant que ça se propage. Sans PCA écrit, chaque minute perdue à chercher "qui appelle qui" et "qu'est-ce qu'on fait d'abord" coûte des milliers d'euros et augmente la durée d'impact. Ce générateur produit un PCA complet et actionnable.

**Principe clé** : R1 = déconnecter physiquement le câble réseau. PAS éteindre la machine (la RAM peut contenir des clés de déchiffrement).

---

## ⚡ Usage

```bash
# Démo complète (4 scénarios, matrice RTO/RPO)
python pca_generator.py demo

# Générer un PCA personnalisé (DOCX)
python pca_generator.py generate --company "Mon Entreprise"
```

---

## ✨ Fonctionnalités

- 4 scénarios : ransomware, data breach, panne serveur, DDoS
- Procédures chronologiques : 0-15min · 15min-2h · 2h-48h
- Matrice RTO/RPO avec calcul d'impact financier
- Livrable DOCX professionnel prêt à imprimer
- Cellule de crise avec annuaire d'urgence
- Notification CNIL 72h intégrée au workflow

---

## ⚖️ Conformité

ISO 22301 — BCP · ISO 27001 A.17 · DORA (secteur financier)

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 19/30_
