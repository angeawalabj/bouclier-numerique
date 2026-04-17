# 🔍 Jour 05 — Audit de Permissions

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![RGPD](https://img.shields.io/badge/RGPD-Art.%205(1)(b)-ff3b3b?style=flat-square)
![ISO](https://img.shields.io/badge/ISO%2027001-A.9.4.1-0078d4?style=flat-square)
![OS](https://img.shields.io/badge/Linux%20·%20macOS%20·%20Windows-compatible-00e5a0?style=flat-square)

**Le principe du moindre privilège est la règle de sécurité la plus enfreinte en entreprise.**  
Détection des permissions excessives · Fichiers world-writable · SUID dangereux · Export rapport

</div>

---

## 🎯 Problème résolu

**60% des incidents de sécurité internes** exploitent des permissions excessives — un utilisateur normal qui peut lire la base de données, un fichier de configuration world-readable contenant un mot de passe, un script SUID modifiable...

Le problème : personne ne sait exactement qui peut accéder à quoi sur un système en production.

```
Scénario réel : Un développeur quitte l'entreprise.
Son compte est désactivé mais son répertoire /home/ancien_dev
contient des clés SSH encore valides, world-readable.
→ Audit manuel : 3 jours · Ce script : 8 secondes
```

**RGPD Art. 5(1)(b)** : limitation des finalités → les données ne doivent être accessibles qu'aux personnes qui en ont besoin.

---

## ⚡ Démarrage rapide

```bash
# Audit du répertoire courant
python3 permission_audit.py scan .

# Audit complet d'un projet web
python3 permission_audit.py scan /var/www/monapp --output rapport.html

# Chercher tous les fichiers world-writable sur le système
python3 permission_audit.py scan / --world-writable-only

# Trouver les binaires SUID (élévation de privilèges potentielle)
python3 permission_audit.py suid /usr/bin

# Démo avec résultats simulés
python3 permission_audit.py demo
```

---

## 🔬 Ce que l'audit détecte

| Anomalie | Risque | Exemple |
|----------|--------|---------|
| **World-writable** | Modification par n'importe qui | `/tmp/config.json` en `777` |
| **World-readable sensible** | Fuite de secrets | `.env` en `644` avec `DB_PASSWORD=...` |
| **SUID sur script** | Élévation de privilèges | `script.py` en `4755` root |
| **Répertoires world-exec** | Navigation non autorisée | `/var/log/app/` en `755` |
| **Clés privées lisibles** | Compromission SSH/TLS | `id_rsa` en `644` |
| **Fichiers récents modifiés** | Indicateur de compromission | Fichier système modifié à 3h du matin |

---

## 📊 Scoring des anomalies

Le rapport attribue une sévérité basée sur la combinaison permission + contenu :

- 🔴 **CRITIQUE** : clé privée ou `.env` world-readable ; fichier SUID appartenant à root
- 🟠 **ÉLEVÉE** : répertoire de données world-writable ; logs accessibles à tous
- 🟡 **MODÉRÉE** : permissions trop larges sur fichiers non sensibles
- 🟢 **FAIBLE** : permissions sous-optimales mais sans impact direct

---

## ✨ Fonctionnalités

- Scan récursif avec filtres d'extension (`.key`, `.pem`, `.env`, `.conf`...)
- Détection des fichiers appartenant à des utilisateurs supprimés (UID orphelins)
- Comparaison avec une baseline sauvegardée (détection de changements)
- Rapport HTML ou JSON pour intégration SIEM
- Mode silencieux pour CI/CD (exit code 1 si anomalie critique)

---

## ⚖️ Conformité

| Référentiel | Contrôle |
|------------|---------|
| **RGPD Art. 5(1)(b)** | Limitation des finalités — accès minimal |
| **RGPD Art. 32** | Mesures techniques de contrôle d'accès |
| **ISO 27001 A.9.4.1** | Restriction d'accès à l'information |
| **ANSSI** | Guide hygiène informatique — mesure 15 (gestion des droits) |
| **PCI-DSS 7.1** | Limiter l'accès aux composants système aux seules personnes qui en ont besoin |

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 05/30_
