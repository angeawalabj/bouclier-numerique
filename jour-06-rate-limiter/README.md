# Jour 06 — Rate Limiter & Pare-feu Applicatif

Fenêtre glissante + blocage progressif contre le brute force et le
credential stuffing. Python 3.10+, middleware Flask.

---

## Problème résolu

Une API sans rate limiting est une cible parfaite pour le brute force (mots de passe), le credential stuffing (listes de comptes volés), et les attaques DDoS de couche 7. Ce rate limiter bloque automatiquement les sources abusives.

**Cas réel** : en 2022, une API de vérification d'emails sans rate limiting a permis à un attaquant d'énumérer 2 millions de comptes en 48 heures.

---

## Usage

```bash
# Démo avec simulation d'attaque
python rate_limiter.py demo

# Lancer le middleware (intégration Flask)
python rate_limiter.py server --port 8080

# Vérifier le statut d'une IP
python rate_limiter.py status 192.168.1.100
```

Intégration dans une route Flask existante :

```python
from rate_limiter import rate_limit

@app.route("/login", methods=["POST"])
@rate_limit("login")
def login():
    ...
```

---

## Fonctionnalités

- Fenêtre glissante sur les échecs récents par IP + endpoint (SQLite)
- Trois paliers : délai progressif, blocage temporaire, bannissement
- Blocklist automatique avec durée configurable
- Whitelist pour IPs internes
- Décorateur `@rate_limit("nom_endpoint")` pour protéger une route Flask

---

## Conformité

OWASP API Security Top 10 — API4:2023 Unrestricted Resource Consumption

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 06/30_
