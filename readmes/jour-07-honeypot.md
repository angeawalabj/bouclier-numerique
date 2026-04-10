# 🍯 Jour 07 — Honeypot Multi-Protocoles

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Async](https://img.shields.io/badge/asyncio-multiport-00e5a0?style=flat-square)
![Protocols](https://img.shields.io/badge/Protocols-SSH%20·%20HTTP%20·%20FTP%20·%20MySQL-f5a623?style=flat-square)
![ANSSI](https://img.shields.io/badge/ANSSI-Mesure%2042-green?style=flat-square)

**Piège réseau qui simule des services vulnérables pour détecter les attaquants.**  
Détection précoce · Fingerprinting automatique · Alertes temps réel

</div>

---

## 🎯 Problème résolu

Un attaquant qui entre sur votre réseau commence toujours par une phase de reconnaissance : scan des ports, tentative de connexion sur SSH, MySQL, FTP. Le honeypot est un **piège invisible** : il simule ces services, journalise chaque interaction, et alerte votre équipe avant que l'attaquant atteigne les vrais systèmes.

**Analogie** : poser une fausse clé sous le paillasson avec une caméra cachée.

**Cas d'usage :**
- Détecter des scans automatisés (bots, worms) sur votre réseau interne
- Identifier des attaquants internes (insider threat)
- Collecter les tactiques/outils d'attaquants réels pour améliorer les défenses

---

## 🕸️ Services simulés

| Port | Service | Ce qui est émulé |
|------|---------|-----------------|
| 22 | SSH | Banner OpenSSH · Collecte credentials |
| 21 | FTP | Login · List · Retr — tout journalisé |
| 3306 | MySQL | Handshake · Tentatives SQL |
| 6379 | Redis | Commandes INFO/GET — sans données réelles |
| 80 | HTTP | Faux admin panel · `/wp-admin` · `/phpmyadmin` |
| 443 | HTTPS | Certificat auto-signé · même faux panel |
| 5900 | VNC | Banner VNC — détecte les scanners |

---

## ⚡ Démarrage rapide

```bash
# Lancer le honeypot en mode démo
python honeypot.py demo

# Surveiller les ports SSH et MySQL
python honeypot.py --ports 22,3306 --alert-email soc@techcorp.fr

# Mode silencieux (log uniquement)
python honeypot.py --ports 22,21,80 --quiet
```

### Exemple d'alerte déclenchée

```
🚨 [02:47:33] ALERTE HONEYPOT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Service   : SSH (port 22)
Source IP : 185.234.xx.xx  [RU / AS49505]
Action    : Tentative de connexion
Login     : root / Password: admin123
User-Agent: Masscan/1.3 libpcap/1.10
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
→ IP ajoutée à la blocklist automatiquement
→ Email envoyé à soc@techcorp.fr
```

---

## 🔬 Architecture

```
Attaquant
    │
    ▼
[asyncio server] ← écoute N ports simultanément
    │
    ├── SSH Handler  → capture banner exchange + credentials
    ├── FTP Handler  → simule PASV/LIST/RETR
    ├── HTTP Handler → faux panel admin avec tokens CSRF factices
    └── MySQL Handler → handshake réaliste
    │
    ▼
[Logger] → SQLite (IP, timestamp, payload, fingerprint)
    │
    ▼
[Alerter] → Email · Webhook · Syslog
    │
    ▼
[Blocker] → Mise à jour iptables / blocklist
```

### Détection de scanners automatiques

Le honeypot identifie automatiquement les outils :

| Signature | Outil détecté |
|-----------|--------------|
| Connexion sans banner exchange | Masscan |
| SSH version `libssh` | Script automatisé |
| FTP `USER anonymous` en < 100ms | Scanner de masse |
| HTTP `HEAD /` avec User-Agent vide | Crawler malveillant |

---

## 📊 Métriques collectées

Pour chaque connexion :
- Adresse IP source + ASN + pays (via lookup)
- Timestamp précis (ms)
- Protocole et port cible
- Payload complet (credentials, commandes)
- Fingerprint TCP/IP (OS detection passif)
- Durée de la session

---

## ⚖️ Aspects légaux

> ⚠️ Un honeypot **sur votre propre réseau** est légal et recommandé.  
> Toute utilisation offensive ou sur un réseau tiers est illégale.

| Contexte | Légalité |
|---------|---------|
| Réseau interne entreprise | ✅ Légal — recommandé ANSSI |
| VPS personnel | ✅ Légal |
| Réseau d'un tiers sans autorisation | ❌ Illégal (Art. 323-1 Code pénal) |

**ANSSI — Guide d'hygiène informatique, Mesure 23 :** "Déployer des systèmes de détection des attaques réseau."

---

## 🔗 Ressources

- [ANSSI — Mesures de détection](https://www.ssi.gouv.fr/guide/guide-dhygiene-informatique/)
- [T-Pot — Honeypot Platform](https://github.com/telekom-security/tpotce)
- [Awesome Honeypots](https://github.com/paralax/awesome-honeypots)

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 7/30_
