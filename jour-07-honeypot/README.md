# Jour 07 — Honeypot (fausse interface admin)

Petit serveur Flask qui expose de fausses versions des chemins que les scanners
automatisés ciblent en premier (`/admin`, `/wp-admin`, `/phpmyadmin`, `/.env`,
`/config.php`, `/backup.sql`, `/.git/config`...), journalise chaque interaction
et envoie une alerte dès le premier contact.

## Problème résolu

La grande majorité des tentatives d'intrusion ne visent pas votre application :
elles testent une liste fixe d'URLs standard en espérant tomber sur une
installation par défaut oubliée ou des identifiants qui traînent. Un honeypot
place ces URLs "appétissantes" en évidence, sans qu'aucun chemin légitime n'y
mène : toute requête reçue dessus est donc, par construction, suspecte.

## Comment ça marche

- Chaque route piège renvoie une page ou un fichier crédible (faux formulaire
  de connexion WordPress, faux phpMyAdmin, faux `.env` avec des identifiants
  qui ne servent à rien) et journalise IP, user-agent, en-têtes, méthode et
  données postées.
- Le user-agent est comparé à une liste de signatures connues (sqlmap, nikto,
  gobuster, masscan...) pour distinguer un scan automatisé d'un humain qui
  teste manuellement.
- Un délai aléatoire de 2 à 8 secondes est ajouté avant la réponse (tar pit) :
  la plupart des scanners abandonnent après un court timeout, donc ce délai
  leur coûte plus qu'il ne coûte au serveur.
- Chaque intrusion est enregistrée dans SQLite (`/tmp/honeypot.db` par
  défaut) ; une alerte email est envoyée en tâche de fond dès le premier hit.

## Utilisation

```bash
# Simulation de plusieurs attaquants, sans lancer de serveur HTTP
python3 honeypot.py demo

# Lancer le honeypot (écoute sur 0.0.0.0:8080)
python3 honeypot.py server

# Statistiques depuis la base SQLite existante
python3 honeypot.py stats
```

La configuration (port, chemin de la base, identifiants SMTP, seuil
d'alerte, nom affiché dans la fausse interface) se fait directement dans la
classe `HoneypotConfig` en tête de `honeypot.py`. Tant que `SMTP_USER` garde
sa valeur par défaut, l'envoi d'email est simulé (affiché dans la console)
plutôt qu'effectué réellement.

En production, le honeypot doit tourner sur le même serveur (ou un
sous-domaine dédié) que l'application réelle, avec ses routes montées avant
les vraies routes de l'app :

```python
from honeypot import create_honeypot
app = create_honeypot()
```

Un tableau de bord temps réel est disponible sur `/honeypot/dashboard`
(à protéger par authentification ou VPN avant tout déploiement public), et
un export JSON sur `/honeypot/api/stats`.

## Aspects légaux

Un honeypot posé sur sa propre infrastructure, dans un but strictement
défensif, est légal en France :

- Il ne doit pas activement inciter à commettre une infraction — il se
  contente de détecter et d'enregistrer.
- Les données collectées servent la défense (blocage, analyse), pas une
  contre-attaque ("hack back" interdit).
- L'article 32 du RGPD demande de tester régulièrement l'efficacité des
  mesures de sécurité techniques ; un honeypot en fait partie.
- Les logs collectés ont une valeur de preuve en cas de plainte au titre de
  l'article 323-1 du Code pénal (accès frauduleux à un système
  d'information).

## Limites

Ce script simule un seul service web (HTTP/Flask) avec une poignée de routes
pièges ; il ne simule pas d'autres protocoles (SSH, FTP, MySQL...). Pour une
maquette multi-protocoles plus proche d'un honeypot réseau complet, voir des
projets dédiés comme [T-Pot](https://github.com/telekom-security/tpotce).

---

_Partie du challenge [Bouclier Numérique](../README.md) — Jour 7/30_
