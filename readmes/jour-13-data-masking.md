# 🎭 Jour 13 — Data Masking RBAC — Contrôle d'Accès par Rôle

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![Pattern](https://img.shields.io/badge/Pattern-RBAC+·+Proxy+Transparent-00e5a0?style=flat-square)
![PCI-DSS](https://img.shields.io/badge/PCI-DSS-3.4+·+Tokenisation-f5a623?style=flat-square)

</div>

---

## 🎯 Problème résolu

Un développeur n'a pas besoin de voir les numéros de carte bancaire réels pour déboguer un problème de paiement. Un agent support n'a pas besoin du IBAN complet pour vérifier un virement. Ce module masque automatiquement les données sensibles selon le rôle de l'utilisateur — sans modifier les applications existantes (proxy transparent).

---

## ⚡ Usage

```bash
# Démo des 4 rôles sur 7 types de données
python data_masking.py demo

# API proxy (intégration transparente)
python data_masking.py server --port 8080

# Tester le masquage pour un rôle
python data_masking.py test --role DEVELOPER --data "4532 1234 5678 9010"
```

---

## ✨ Fonctionnalités

- 4 rôles : ADMIN, MANAGER, DEVELOPER, SUPPORT
- 7 types de données : PAN, IBAN, NIR, email, téléphone, nom, adresse
- Proxy transparent : les applications existantes ne changent pas
- Tokenisation réversible (ADMIN uniquement)
- Audit log de chaque accès aux données sensibles
- AUCUNE donnée sensible dans les logs applicatifs

---

## ⚖️ Conformité

PCI-DSS 3.4 — masquage PAN · RGPD Art. 25 — privacy by design

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 13/30_
