# 💾 Jour 08 — Backup Chiffré Immuable (Anti-Ransomware)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Pattern](https://img.shields.io/badge/Pattern-WORM+·+3--2--1+Backup-00e5a0?style=flat-square)
![Protection](https://img.shields.io/badge/Protection-Anti--Ransomware-ff3b3b?style=flat-square)

</div>

---

## 🎯 Problème résolu

Les ransomwares modernes ciblent **en priorité les backups connectés au réseau**. Si le backup est chiffré avec les données, la restauration est impossible. Ce système implémente des backups immuables (WORM — Write Once Read Many) : une fois écrit, aucun processus ne peut modifier ou supprimer les archives.

**Log4Shell (2021)** : les attaquants ont attendu 3 semaines avant d'activer le ransomware — s'assurant que les backups récents contenaient aussi le malware. Un backup offline/immuable aurait permis la restauration.

---

## ⚡ Usage

```bash
# Créer un backup immuable chiffré
python immutable_backup.py backup /data/production --encrypt

# Vérifier l'intégrité de tous les backups
python immutable_backup.py verify

# Restaurer un backup
python immutable_backup.py restore backup_2026-03-12.enc --target /restore/

# Démo
python immutable_backup.py demo
```

---

## ✨ Fonctionnalités

- Chiffrement AES-256-GCM de chaque archive
- Hash SHA-256 de chaque backup (détection de corruption)
- Politique de rétention configurable (30/90/365 jours)
- Immutabilité par permission (chmod 444 + chattr +i sur Linux)
- Rapport d'intégrité quotidien
- Simulation de restauration avant incident réel

---

## ⚖️ Conformité

ISO 22301 — Continuité d'activité · PCI-DSS 12.10 — Plan de reprise

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 08/30_
