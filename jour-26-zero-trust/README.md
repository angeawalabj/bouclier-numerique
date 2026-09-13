# Jour 26 — Zero Trust Access Controller

Trust score par requête · RBAC hiérarchique · journal d'audit chaîné HMAC

---

## Problème résolu

Le modèle périmétrique classique fait confiance à tout ce qui est déjà dans le réseau interne — une hypothèse qui ne tient plus dès qu'un poste est compromis ou qu'un accès se fait en télétravail. Le Zero Trust (NIST SP 800-207) réévalue chaque requête indépendamment de son origine : identité, appareil, réseau et sensibilité de la ressource sont recombinés en un score de confiance à chaque appel, plutôt que de valider une session une fois pour toutes.

```bash
python3 zero_trust.py demo
python3 zero_trust.py check --user alice --resource /admin/dashboard --action read
```

## Fonctionnement

Le score de confiance (0-100) combine authentification (MFA, certificat mTLS), contexte de l'appareil (géré/conforme), réseau et horaire, puis sensibilité de la ressource et de l'action demandée. Trois décisions possibles :

| Score | Décision | Effet |
|-------|----------|-------|
| ≥ 70 | **ALLOW** | Accès autorisé si le RBAC le permet |
| 50-69 | **STEP_UP** | Authentification renforcée requise (MFA) |
| < 50 | **DENY** | Refus immédiat |

Le RBAC applique le moindre privilège avec héritage de rôles (`viewer` → `editor` → `manager` → `admin`). Chaque décision est journalisée dans un log chaîné par HMAC : chaque entrée inclut le hash de la précédente, donc toute modification rétroactive casse la chaîne et devient détectable.

## Conformité

| Référentiel | Lien |
|------------|------|
| **NIST SP 800-207** | Zero Trust Architecture |
| **ISO 27001 A.9** | Contrôle d'accès |
| **ANSSI PA-022** | Recommandations Zero Trust |

---
_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 26/30_
