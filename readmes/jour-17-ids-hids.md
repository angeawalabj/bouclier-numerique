# 👁️ Jour 17 — Détecteur d'Infiltration HIDS (File Integrity Monitor)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Type](https://img.shields.io/badge/Type-HIDS%20·%20FIM-ff3b3b?style=flat-square)
![PCI](https://img.shields.io/badge/PCI--DSS-10.5.5%20obligatoire-f5a623?style=flat-square)
![ISO](https://img.shields.io/badge/ISO%2027001-A.12.4.1-blue?style=flat-square)

**Détecte toute modification non autorisée des fichiers système en < 30 secondes.**  
SHA-256 baseline · Alertes temps réel · Surveillance des permissions

</div>

---

## 🎯 Problème résolu

Un attaquant compromet votre serveur à 02h47. En 55 secondes, il :
1. Modifie `/etc/passwd` — ajoute un compte backdoor root
2. Crée `/etc/cron.d/persist` — installe un reverse shell persistant
3. Upload `wp-config.php` — webshell PHP
4. Remplace `/usr/bin/sudo` — capture des mots de passe
5. `chmod 777 config.php` — accès élargi

**Sans HIDS** : découverte possible des semaines plus tard (ou jamais).  
**Avec ce HIDS** : les 5 actions sont détectées en < 30 secondes.

---

## 🔬 Principe du FIM (File Integrity Monitoring)

```
Phase 1 — Baseline (système sain)
  /etc/passwd    → SHA-256: c8db5c431a02b617...  permissions: 0o644
  /etc/sudoers   → SHA-256: f1b0a36cec27b900...  permissions: 0o440
  /usr/bin/sudo  → SHA-256: a2e9b4c1d8f73e55...  permissions: 0o755
  (stocké en SQLite)

Phase 2 — Scan continu (toutes les 30s)
  /etc/passwd    → SHA-256: 5d22d219561b2b41...  ← DIFFÉRENT → 🔴 ALERTE
  /etc/sudoers   → SHA-256: f1b0a36cec27b900...  ← identique  → ✅ OK
  /usr/bin/sudo  → SHA-256: 7b88324d89063b67...  ← DIFFÉRENT → 🔴 ALERTE
```

---

## ⚡ Démarrage rapide

```bash
pip install psutil  # optionnel — pour l'analyse processus

# Construire la baseline sur un système sain
python ids_monitor.py baseline /etc /usr/bin /var/www

# Surveiller en continu (scan toutes les 30s)
python ids_monitor.py watch /etc /usr/bin --interval 30

# Scan unique (utile pour CI/CD)
python ids_monitor.py scan /etc

# Rapport des 24 dernières heures
python ids_monitor.py report --hours 24

# Démo complète avec attaque simulée
python ids_monitor.py demo
```

---

## 🚨 Types d'alertes

| Événement | Sévérité | Exemple |
|-----------|---------|---------|
| Contenu modifié (hash ≠) | 🔴 CRITIQUE si `/etc/` ou `/usr/bin/` | `/etc/passwd` modifié |
| Nouveau fichier zone critique | 🔴 CRITIQUE | Nouveau fichier dans `/etc/cron.d/` |
| Bit SUID ajouté | 🔴 CRITIQUE | `chmod u+s /bin/bash` |
| Permissions `777` | 🟠 ÉLEVÉ | `chmod 777 config.php` |
| Fichier supprimé | 🟠 ÉLEVÉ | Suppression de `/etc/sudoers.d/` |
| Exécutable caché (`.xxx`) | 🟠 ÉLEVÉ | `.backdoor` dans `/tmp/` |
| Fichier config modifié | 🟡 MODÉRÉ | `.env` ou `config.yaml` |

---

## 📊 Démo — Résultats de l'attaque simulée

```
[02:47:38] 🔴 CRITIQUE  CONTENT_MODIFIED  /etc/passwd
           Avant : c8db5c431a02b617...
           Après : 5d22d219561b2b41...

[02:47:38] 🟠 ÉLEVÉ     PERM_CHANGED      /var/www/html/config.php
           Avant : 0o644 → Après : 0o777

[02:47:38] 🟡 MODÉRÉ    CONTENT_MODIFIED  /usr/bin/sudo

[02:47:38] 🔵 INFO      NEW_FILE          /etc/cron.d/persist
           Nouveau fichier — 56 octets

[02:47:38] 🔵 INFO      NEW_FILE          /var/www/html/wp-config.php
           Nouveau fichier — 30 octets

5/5 actions de l'attaquant détectées ✅
```

---

## 🗂️ Fichiers surveillés par défaut

```
/etc/passwd, /etc/shadow, /etc/group       ← Comptes système
/etc/sudoers, /etc/sudoers.d/              ← Privilèges
/etc/ssh/sshd_config, /etc/ssh/            ← Accès distant
/etc/crontab, /etc/cron.d/, /var/spool/cron ← Persistance
/usr/bin/sudo, /usr/bin/su                 ← Escalade
/bin/bash, /bin/sh                         ← Shells
/var/www/                                  ← Applications web
```

---

## 🔌 Intégration SIEM

```python
# Callback personnalisé — intégration Splunk/Elastic/Grafana
def send_to_siem(alert):
    requests.post("https://siem.interne/api/events", json={
        "severity": alert["severity"],
        "message":  alert["details"],
        "source":   alert["path"],
        "timestamp": alert["timestamp"]
    })

detector.on_alert(send_to_siem)
```

---

## ⚖️ Conformité — PCI-DSS 10.5.5 obligatoire

> *"Déployer un mécanisme de surveillance de l'intégrité des fichiers pour être alerté des modifications non autorisées de fichiers système ou de contenu critiques."*

Sans FIM, une organisation traitant des données de cartes bancaires **échoue automatiquement** l'audit PCI-DSS, quel que soit le reste du dispositif.

| Référentiel | Exigence |
|------------|---------|
| **PCI-DSS 10.5.5** | FIM obligatoire |
| **ISO 27001 A.12.4.1** | Journalisation des événements système |
| **ANSSI R32** | Détection des incidents de sécurité |

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 17/30_
