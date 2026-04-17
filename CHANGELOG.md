# 📅 Changelog — Le Bouclier Numérique

Toutes les modifications notables de ce projet sont documentées dans ce fichier.  
Format : [Keep a Changelog](https://keepachangelog.com/fr/1.0.0/) · Versioning : [Semantic Versioning](https://semver.org/lang/fr/)

---

## [Unreleased]

### Ajouté
- Jour 21 : Fuzzer d'API automatique (en cours)

---

## [v1.0.0] — 2026-03-12

### Semaine 1 — Sécurité Individuelle (Jours 1–5)
- **J01** `password_vault.py` — Coffre-fort mots de passe · scrypt(N=2¹⁷) · RGPD Art. 32
- **J02** `exif_cleaner.py` — Effaceur EXIF/GPS · reconstruction pixel · RGPD Art. 5(1)(c)
- **J03** `leak_detector.py` — Détecteur fuites HIBP · k-anonymat · RGPD Art. 33-34
- **J04** `file_vault.py` — Chiffrement AES-256-GCM · PBKDF2 600k tours · RGPD Art. 34
- **J05** `permission_audit.py` — Audit permissions Android/Linux · RGPD Art. 5(1)(b)

### Semaine 2 — Sécurité PME (Jours 6–10)
- **J06** `rate_limiter.py` — Rate limiter sliding window · ISO 27001 A.9.4.2
- **J07** `honeypot.py` — Honeypot multi-protocoles · tar pit · Art. 323-1 CP
- **J08** `immutable_backup.py` — Backup immuable anti-ransomware · ANSSI 3-2-1
- **J09** `log_anonymizer.py` — Anonymiseur logs RGPD · pseudonymisation · Art. 25
- **J10** `port_scanner.py` — Scanner de ports réseau · ISO 27001 A.13.1.1

### Semaine 3 — Gouvernance & Conformité (Jours 11–15)
- **J11** `right_to_erasure.py` — Droit à l'effacement SQL/NoSQL/Logs · Art. 17
- **J12** `registre_traitements.py` + `registre_rgpd.html` — Registre Art. 30 · score conformité
- **J13** `data_masking.py` — Data masking RBAC · formats PAN/IBAN/SSN · Art. 32
- **J14** `cookie_consent.py` + `cookie_consent_demo.html` — Consent manager · CNIL 2020-091
- **J15** `dependency_audit.py` — Audit CVE dépendances · SBOM · Log4Shell case study
- **Bonus** `dpa_generator.py` + `DPA_TechCorp_CloudHost.docx` — Générateur DPA Art. 28

### Semaine 4 — Détection & Résilience (Jours 16–20)
- **J16** `phishing_sim.py` + `phishing_education.html` — Sim. phishing · ANSSI mesure 42
- **J17** `ids_monitor.py` — HIDS/FIM SHA-256 · PCI-DSS 10.5.5 obligatoire
- **J18** `e2ee_messaging.py` — Messagerie E2EE · X25519+HKDF+AES-GCM · PFS prouvé
- **J19** `pca_generator.py` + `pca_techcorp.docx` — Plan de Continuité · ISO 22301
- **J20** `rssi_dashboard.html` — Dashboard RSSI · score 83/100 · 6 domaines

### Documentation
- 20 READMEs individuels par outil (badges, architecture, conformité)
- README master avec tableau 30 jours, conformité, crypto stack
- LICENSE MIT + avertissement usage offensif
- CONTRIBUTING.md avec standards code, tests, Conventional Commits
- CODE_OF_CONDUCT.md (Contributor Covenant v2.1)
- SECURITY.md politique de divulgation responsable

---

## Types de changements

- `Ajouté` — nouvelles fonctionnalités
- `Modifié` — changements dans les fonctionnalités existantes
- `Déprécié` — fonctionnalités qui seront supprimées prochainement
- `Supprimé` — fonctionnalités supprimées
- `Corrigé` — corrections de bugs
- `Sécurité` — corrections de vulnérabilités

[Unreleased]: https://github.com/votre-username/bouclier-numerique/compare/v1.0.0...HEAD
[v1.0.0]: https://github.com/votre-username/bouclier-numerique/releases/tag/v1.0.0
