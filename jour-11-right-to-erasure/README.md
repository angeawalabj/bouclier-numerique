# 🗑️ Jour 11 — Droit à l'Effacement RGPD (Art. 17)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![RGPD](https://img.shields.io/badge/RGPD-Art.+17+·+Art.+12-ff3b3b?style=flat-square)
![Délai](https://img.shields.io/badge/Délai-30+jours+légaux-blue?style=flat-square)

</div>

---

## 🎯 Problème résolu

Lorsqu'un utilisateur demande la suppression de ses données (RGPD Art. 17), votre organisation a **30 jours** pour les effacer de TOUTES les sources : base de données principale, backups, logs, emails, CRM, analytics... L'oubli d'une source constitue une violation. Ce module automatise et certifie le processus.

---

## ⚡ Usage

```bash
# Traiter une demande d'effacement
python right_to_erasure.py erase --email user@exemple.fr

# Vérifier le statut d'une demande
python right_to_erasure.py status REQ-2026-0142

# Générer le certificat d'effacement (preuve RGPD)
python right_to_erasure.py certificate REQ-2026-0142

# Lister les demandes en attente
python right_to_erasure.py pending

# Démo
python right_to_erasure.py demo
```

---

## ✨ Fonctionnalités

- Suppression multi-sources : DB, logs, backups, cache, emails
- Délai légal : alerte à J+25 si demande non traitée
- Certificat d'effacement horodaté (preuve en cas de contrôle)
- Exceptions légales documentées (Art. 17.3 : obligations légales)
- Audit trail complet et immuable
- Rapport mensuel des demandes pour le DPO

---

## ⚖️ Conformité

RGPD Art. 17 — droit à l'effacement · Art. 12 — délais de réponse

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 11/30_
