# 🔭 Jour 10 — Scanner de Ports Réseau

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Tech](https://img.shields.io/badge/Tech-asyncio+·+socket-00e5a0?style=flat-square)
![Usage](https://img.shields.io/badge/Usage-Audit+interne+uniquement-f5a623?style=flat-square)

</div>

---

## 🎯 Problème résolu

Avant de corriger une vulnérabilité, il faut la trouver. Ce scanner audite les ports ouverts sur votre réseau interne, identifie les services exposés, et croise avec une base de ports dangereux connus (MySQL sans auth, Redis sans mot de passe, Elasticsearch exposé).

**Usage légal uniquement sur votre propre réseau.** Scanner le réseau d'un tiers sans autorisation est illégal (Art. 323-1 Code pénal).

---

## ⚡ Usage

```bash
# Scanner un hôte
python port_scanner.py scan 192.168.1.1

# Scanner un sous-réseau (CIDR)
python port_scanner.py scan 192.168.1.0/24 --ports 22,80,443,3306,6379

# Scanner rapide (top 100 ports)
python port_scanner.py scan 192.168.1.1 --top100

# Rapport HTML
python port_scanner.py scan 192.168.1.0/24 --output rapport.html

# Démo
python port_scanner.py demo
```

---

## ✨ Fonctionnalités

- Scan asynchrone rapide (asyncio — jusqu'à 1000 ports/s)
- Détection de service par banner grabbing
- Base de ports dangereux : MySQL sans auth, Redis, Elasticsearch...
- Rapport des vulnérabilités par sévérité
- Comparaison avec scan précédent (nouveaux ports ouverts)
- Export JSON/HTML/CSV

---

## ⚖️ Conformité

ISO 27001 A.12.6 — Gestion des vulnérabilités techniques

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 10/30_
