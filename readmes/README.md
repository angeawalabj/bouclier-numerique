# 🛡️ Le Bouclier Numérique — 30 jours, 30 outils de cybersécurité

[![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Jours](https://img.shields.io/badge/Challenge-30%2F30%20✅-27ae60?style=flat-square)]()
[![NIST CSF](https://img.shields.io/badge/NIST%20CSF%202.0-100%25-64ffda?style=flat-square)]()

> **Un outil de cybersécurité par jour. 30 jours. Du coffre-fort de mots de passe au SOAR automatisé.**

---

## 📋 Table des matières

| Semaine | Thème | Outils |
|---------|-------|--------|
| [S1 — Jours 1–5](#s1) | Sécurité individuelle | Password vault, EXIF, HIBP, AES-256, Audit perms |
| [S2 — Jours 6–10](#s2) | Sécurité PME | Rate limiter, Honeypot, Backup, Log anon, Port scan |
| [S3 — Jours 11–15](#s3) | Gouvernance & RGPD | Art.17, Art.30, RBAC, Cookies, Audit CVE |
| [S4 — Jours 16–20](#s4) | Détection & Résilience | Phishing, HIDS, E2EE, PCA, Dashboard RSSI |
| [S5 — Jours 21–25](#s5) | Red Team | Fuzzer API, Injections, Hash cracker, OSINT, Pentest |
| [S6 — Jours 26–30](#s6) | Architecture finale | Zero Trust, PKI, SOAR, Threat Intel, Suite intégrée |

---

## 🗓️ Les 30 outils

<a name="s1"></a>
### Semaine 1 — Sécurité individuelle

| Jour | Outil | Fichier | Conformité |
|------|-------|---------|-----------|
| J01 | Coffre-fort mots de passe (scrypt) | `password_vault.py` | NIST SP 800-63B |
| J02 | Nettoyeur EXIF/GPS | `exif_cleaner.py` | RGPD Art.5(1)(c) |
| J03 | Détecteur fuites HIBP (k-anonymat) | `leak_detector.py` | RGPD Art.33 |
| J04 | Chiffrement fichiers AES-256-GCM | `file_vault.py` | RGPD Art.34 · ISO 27001 A.10.1 |
| J05 | Audit de permissions | `permission_audit.py` | PCI-DSS 7.1 |

<a name="s2"></a>
### Semaine 2 — Sécurité PME

| Jour | Outil | Fichier | Conformité |
|------|-------|---------|-----------|
| J06 | Rate Limiter (sliding window + token bucket) | `rate_limiter.py` | OWASP API4 |
| J07 | Honeypot multi-protocoles | `honeypot.py` | ISO 27001 A.12.4 |
| J08 | Backup immuable anti-ransomware | `immutable_backup.py` | ISO 22301 |
| J09 | Anonymiseur logs RGPD | `log_anonymizer.py` | RGPD Art.25 |
| J10 | Scanner de ports réseau | `port_scanner.py` | NIST CSF ID.AM |

<a name="s3"></a>
### Semaine 3 — Gouvernance & RGPD

| Jour | Outil | Fichier | Conformité |
|------|-------|---------|-----------|
| J11 | Droit à l'effacement Art.17 | `right_to_erasure.py` | RGPD Art.17 · CCPA §1798.105 |
| J12 | Registre des traitements Art.30 | `registre_traitements.py` | RGPD Art.30 · CNIL |
| J13 | Data Masking RBAC | `data_masking.py` | RGPD Art.32 · PCI-DSS 3.4 |
| J14 | Cookie Consent CNIL (IAB TCF 2.2) | `cookie_consent.py` | RGPD Art.6 · CNIL |
| J15 | Audit CVE dépendances (OSV + NVD) | `dependency_audit.py` | ISO 27001 A.12.6.1 |
| ➕ | Générateur DPA Art.28 | `dpa_generator.py` | RGPD Art.28 |

<a name="s4"></a>
### Semaine 4 — Détection & Résilience

| Jour | Outil | Fichier | Conformité |
|------|-------|---------|-----------|
| J16 | Simulation phishing + éducation | `phishing_sim.py` | ANSSI mesure 42 |
| J17 | HIDS / FIM (SHA-256 baseline) | `ids_monitor.py` | PCI-DSS 10.5.5 |
| J18 | Messagerie E2EE (X25519 + AES-GCM) | `e2ee_messaging.py` | RGPD Art.32 |
| J19 | Plan de Continuité ISO 22301 | `pca_generator.py` | ISO 22301 · NIS2 Art.21 |
| J20 | Dashboard RSSI HTML | `rssi_dashboard.html` | ISO 27001 · NIST CSF |

<a name="s5"></a>
### Semaine 5 — Red Team

| Jour | Outil | Fichier | Conformité |
|------|-------|---------|-----------|
| J21 | Fuzzer API (OWASP API Top 10) | `api_fuzzer.py` | OWASP API Security 2023 |
| J22 | Scanner injections (SQLi/XSS/SSTI/CMDi) | `injection_scanner.py` | OWASP A03:2021 |
| J23 | Craqueur hachages éthique | `hash_cracker.py` | OWASP ASVS 2.4 · NIST SP 800-63B |
| J24 | Crawler OSINT défensif | `osint_crawler.py` | ISO 27001 A.12.6.1 |
| J25 | Générateur rapport pentest | `pentest_report.py` | ISO 27001 A.18.2.3 |

<a name="s6"></a>
### Semaine 6 — Architecture finale

| Jour | Outil | Fichier | Conformité |
|------|-------|---------|-----------|
| J26 | Zero Trust Controller | `zero_trust.py` | NIST SP 800-207 |
| J27 | PKI & Certificats (CA chain) | `pki_manager.py` | RFC 5280 · ANSSI RGS |
| J28 | SOAR — Réponse automatisée | `soar.py` | ISO 27001 A.16 · RGPD Art.33 |
| J29 | Threat Intelligence Feed (STIX 2.1) | `threat_intel.py` | MITRE ATT&CK |
| J30 | Suite intégrée — Bilan NIST CSF | `suite_integree.py` | NIST CSF 2.0 |

---

## 🚀 Démarrage rapide

```bash
git clone https://github.com/votre-org/bouclier-numerique
cd bouclier-numerique
pip install -r requirements.txt

# Exemple : lancer n'importe quel outil en mode démo
python3 password_vault.py demo
python3 soar.py demo
python3 threat_intel.py demo
python3 suite_integree.py          # Bilan NIST CSF complet
```

---

## ⚖️ Couverture réglementaire

| Référentiel | Articles / Contrôles couverts |
|------------|-------------------------------|
| **RGPD** | Art.5, 6, 17, 25, 28, 30, 32, 33, 34 |
| **ISO 27001** | A.5.9, A.7.2.2, A.8.8, A.9.4, A.10.1, A.12.4, A.12.6, A.13.1, A.14.2.8, A.16.1, A.18.2.3 |
| **NIST CSF 2.0** | IDENTIFY · PROTECT · DETECT · RESPOND · RECOVER |
| **OWASP** | Web Top 10 2021 · API Security 2023 · ASVS 2.4 |
| **ANSSI** | Guide hygiène 42 mesures · Guide anti-ransomware |
| **PCI-DSS** | Req.3.4, 7.1, 10.5.5, 11.3 |
| **NIS2** | Art.21 (mesures techniques), Art.23 (notifications) |
| **ISO 22301** | PCA · BIA · RTO/RPO |
| **MITRE ATT&CK** | Threat Intelligence · TTPs |

---

## 🏗️ Stack technique

```
Cryptographie  : AES-256-GCM · scrypt(N=2¹⁷) · X25519 · HKDF-SHA256 · RSA-4096 · bcrypt
Protocoles     : TLS 1.3 · mTLS · DNS-over-HTTPS · STIX 2.1 · JWT · IAB TCF 2.2
Standards      : RFC 5280 · NIST SP 800-207 · OWASP API Top 10 · Signal Protocol
Formats export : HTML · JSON · CSV · DOCX · STIX 2.1 bundle · SBOM
```

---

## ⚠️ Avertissement légal

Ces outils sont destinés exclusivement à un usage **défensif et éducatif** :
- Audit de **vos propres** systèmes
- Formations et sensibilisation interne
- Démonstrations dans un environnement contrôlé

Toute utilisation sur des systèmes sans autorisation explicite est **illégale** (Art. 323-1 du Code Pénal).

---

## 📄 Licence

MIT — voir [LICENSE](LICENSE)

---

*Le Bouclier Numérique — 30 jours · 30 outils · ~8 000 lignes · 9 référentiels · 100% open source*
