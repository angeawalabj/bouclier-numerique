# Jour 09 — Anonymiseur de logs

Détecte les données personnelles dans des fichiers de logs (emails, IPs,
IBAN, numéros de carte, mots de passe en clair, noms, dates de naissance...)
et les remplace par des pseudonymes cohérents avant que ces logs ne quittent
le périmètre de l'entreprise.

## Problème résolu

Les logs Nginx/Apache/applicatifs contiennent des adresses IP (donnée
personnelle selon la CNIL), des emails, parfois des identifiants ou des
numéros de carte capturés par erreur dans un message d'erreur. Les partager
tels quels avec un prestataire externe pour du support ou du débogage
expose l'entreprise. Ce module remplace ces valeurs par des pseudonymes :
la même valeur produit toujours le même pseudonyme, ce qui permet de
corréler les événements dans les logs sans jamais exposer la donnée réelle.

## Usage

```bash
# Démo : détection + pseudonymisation sur 3 formats de logs d'exemple
python3 log_anonymizer.py demo

# Anonymiser un fichier
python3 log_anonymizer.py file access.log -o access_anon.log --mode pseudonymize

# Anonymiser un dossier entier (récursif, .log/.txt/.gz)
python3 log_anonymizer.py folder /var/log/ -o /var/log/anon/

# Lister les données détectées sans les remplacer
python3 log_anonymizer.py analyze access.log

# Statistiques de la table de correspondance
python3 log_anonymizer.py stats
```

`--mode` accepte `pseudonymize` (par défaut, réversible via la clé),
`anonymize` (irréversible, remplace par une étiquette générique) ou
`redact` (ne pseudonymise que les catégories les plus sensibles). `--key`
permet de fournir sa propre clé secrète ; sans elle, une clé aléatoire est
générée à la création de la table de correspondance.

## Fonctionnement

- 11 catégories détectées par regex : email, IPv4, IPv6, téléphone français,
  IBAN, numéro de carte bancaire, numéro de sécurité sociale, mot de passe /
  token en clair, nom + prénom, date de naissance, UUID.
- Les pseudonymes sont générés par HMAC-SHA256 (clé secrète), pas par un
  simple hash : un hash direct d'un email ou d'une IP serait cassable par
  force brute (l'espace des emails ou des plages IP courantes est petit et
  énumérable), alors que HMAC avec une clé non publiée rend cette attaque
  inutile.
- La correspondance original → pseudonyme est stockée dans une base SQLite
  (`/tmp/pseudo_table.db` par défaut) pour garantir la cohérence entre
  plusieurs exécutions.

## Conformité RGPD

- Art. 4(5) — définition de la pseudonymisation : réversible via une
  information supplémentaire (ici, la clé secrète), à distinguer de
  l'anonymisation qui est irréversible et sort du champ du RGPD.
- Art. 25 — protection des données dès la conception (privacy by design).
- Art. 28 — un log pseudonymisé peut être transmis à un sous-traitant sans
  exposer les données personnelles réelles.
- Art. 32 — mesure technique appropriée pour réduire le risque en cas de
  fuite des logs.

---

_Partie du challenge [Bouclier Numérique](../README.md) — Jour 09/30_
