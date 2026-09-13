# Jour 10 — Scanner de Ports Réseau

Audit interne uniquement. Python 3.10+, TCP connect via un pool de
threads (pas de raw sockets, pas de droits root nécessaires).

---

## Problème résolu

Avant de corriger une vulnérabilité, il faut la trouver. Ce scanner audite les ports ouverts sur votre réseau interne, identifie les services exposés, et croise avec une base de ports dangereux connus (MySQL sans auth, Redis sans mot de passe, Elasticsearch exposé).

**Usage légal uniquement sur votre propre réseau.** Scanner le réseau d'un tiers sans autorisation est illégal (Art. 323-1 Code pénal).

---

## Usage

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

## Fonctionnalités

- Scan TCP connect concurrent (pool de threads)
- Détection de service par banner grabbing
- Base de ports dangereux : MySQL sans auth, Redis, Elasticsearch...
- Rapport des vulnérabilités par sévérité
- Comparaison avec scan précédent (nouveaux ports ouverts)
- Export JSON/HTML/CSV

---

## Conformité

ISO 27001 A.12.6 — Gestion des vulnérabilités techniques

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 10/30_
