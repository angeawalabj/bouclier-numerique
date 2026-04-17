# 📝 Jour 09 — Anonymiseur de Logs RGPD

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Technique](https://img.shields.io/badge/Technique-Pseudonymisation+·+HMAC-00e5a0?style=flat-square)
![RGPD](https://img.shields.io/badge/RGPD-Art.+4(5)+·+Art.+25-blue?style=flat-square)

</div>

---

## 🎯 Problème résolu

Vos logs Nginx/Apache/applicatifs contiennent des adresses IP (donnée personnelle selon la CNIL), emails, noms d'utilisateurs. Les conserver tels quels sans durée de rétention définie vous expose à une amende RGPD. Ce module pseudonymise les données personnelles de façon cohérente : la même IP produit toujours le même pseudonyme, permettant les analyses sans exposer les données réelles.

---

## ⚡ Usage

```bash
# Anonymiser un fichier de log Nginx
python log_anonymizer.py anonymize access.log --output access_anon.log

# Anonymiser en temps réel (pipe)
tail -f /var/log/nginx/access.log | python log_anonymizer.py stream

# Purger les logs anciens (RGPD rétention 12 mois)
python log_anonymizer.py purge --older-than 365

# Démo
python log_anonymizer.py demo
```

---

## ✨ Fonctionnalités

- Pseudonymisation HMAC-SHA256 : cohérente et irréversible sans la clé
- Détection automatique : IPv4, IPv6, emails, noms, numéros de téléphone
- Formats supportés : Nginx, Apache, JSON, syslog, format personnalisé
- Clé de pseudonymisation rotatable (révocation possible)
- Politique de rétention avec purge automatique
- Rapport de conformité RGPD

---

## ⚖️ Conformité

RGPD Art. 4(5) — pseudonymisation · Art. 25 — privacy by design

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 09/30_
