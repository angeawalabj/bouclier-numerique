# 🔏 Jour 27 — PKI & Gestion de Certificats

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![OpenSSL](https://img.shields.io/badge/OpenSSL-3.0+-e74c3c?style=flat-square)
![RFC](https://img.shields.io/badge/RFC%205280-X.509-0078d4?style=flat-square)

**CA Root → CA Intermédiaire → Certificats TLS/mTLS : PKI complète en 4 étapes.**

```bash
python3 pki_manager.py demo
python3 pki_manager.py create --dir /opt/ma_pki
python3 pki_manager.py info /opt/ma_pki/server.crt
```

Génère une PKI interne à 3 niveaux (Root → Intermédiaire → Leaf) avec SAN, contraintes de base et CRL. Support mTLS pour authentification mutuelle client/serveur. Conformité RFC 5280 · ANSSI RGS · eIDAS.

---
_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 27/30_
