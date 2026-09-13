# Jour 13 — Data Masking RBAC — Contrôle d'Accès par Rôle

Python 3.10+ · RBAC + proxy transparent · PCI-DSS 3.4 tokenisation

---

## Problème résolu

Un agent support n'a pas besoin de voir le numéro de carte bancaire complet pour vérifier un paiement. Le service facturation, lui, en a besoin pour émettre un remboursement. Un auditeur externe ne devrait voir ni l'un ni l'autre. Ce module masque automatiquement les champs sensibles d'un enregistrement selon le rôle de l'appelant — sans modifier les applications existantes (proxy transparent devant SQLite, ou fonction directe sur un dict).

---

## Usage

```bash
# Démo : le même profil client vu par 4 rôles différents
python data_masking.py demo

# Masquer une valeur ponctuelle pour un rôle donné
python data_masking.py mask "4532015112830366" carte_bancaire --role SUPPORT
```

Types de données reconnus par `mask` : `carte_bancaire`, `cvv`, `iban`, `email`, `telephone`, `insee`, `ip`, `nom`.
Rôles disponibles : `ADMIN`, `PAIEMENT`, `SUPPORT`, `EXTERNE`.

---

## Fonctionnalités

- 4 rôles : ADMIN, PAIEMENT, SUPPORT, EXTERNE
- 7 types de données sensibles : carte bancaire, CVV, IBAN, email, téléphone, INSEE, IP, nom
- `DataMasker.mask_dict()` pour un dict (récursif sur les objets imbriqués), `mask_text()` pour du texte libre (logs)
- `MaskedDB` : proxy SQLite qui masque les résultats de requête sans changer le code appelant
- Audit trail SQLite de chaque accès à un champ sensible

---

## Conformité

PCI-DSS 3.4 — masquage PAN · RGPD Art. 25 — privacy by design · RGPD Art. 32 · ISO 27001 A.9.4.1

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 13/30_
