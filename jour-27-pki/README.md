# Jour 27 — PKI & Gestion de Certificats

CA Root → CA Intermédiaire → Certificats TLS/mTLS via openssl

---

## Problème résolu

Ce script pilote la CLI `openssl` pour construire une PKI interne à trois niveaux. L'intérêt d'une CA intermédiaire plutôt que de signer directement avec la CA root est autant opérationnel que sécuritaire : la clé root peut rester hors ligne (elle ne sert qu'une fois, pour signer l'intermédiaire), alors que l'intermédiaire, utilisée en continu, peut être révoquée et renouvelée sans invalider toute la chaîne de confiance.

```bash
python3 pki_manager.py demo
python3 pki_manager.py create --dir /opt/ma_pki
python3 pki_manager.py info /opt/ma_pki/certs/server.crt
```

## Ce que génère la démo

Une CA root (RSA 4096), une CA intermédiaire (RSA 2048) signée par la root, un certificat serveur TLS avec SAN (`localhost`, `app.local`, `127.0.0.1`), et un certificat client mTLS (`alice@techcorp.fr`). Chaque chaîne de confiance est vérifiée avec `openssl verify` et le résultat est écrit dans `pki_report.json`.

## Points clés

- CN seul est déprécié depuis la RFC 6125 : chaque certificat porte un SAN explicite.
- mTLS : client et serveur s'authentifient mutuellement (pas seulement le serveur comme en TLS classique).
- Les commandes openssl sont invoquées comme des listes d'arguments, sans `shell=True`.

## Conformité

| Référentiel | Lien |
|------------|------|
| **RFC 5280** | Profil X.509 |
| **ANSSI RGS** | Référentiel général de sécurité |
| **eIDAS** | Règlement européen sur l'identification électronique |

---
_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 27/30_
