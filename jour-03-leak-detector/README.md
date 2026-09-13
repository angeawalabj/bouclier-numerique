# Jour 03 — Détecteur de fuites (Have I Been Pwned)

## Problème résolu

Des milliards de couples identifiant/mot de passe circulent dans des bases de données piratées. Ce détecteur interroge l'API Have I Been Pwned sans jamais envoyer votre mot de passe en clair, grâce au principe de k-anonymat : seuls les 5 premiers caractères du hash SHA-1 sont transmis, l'API renvoie environ 500 hashes partageant ce préfixe, et la comparaison finale se fait localement. HIBP ne sait jamais quel mot de passe a été vérifié.

## Usage

```bash
# Menu interactif (aucun argument)
python3 leak_detector.py

# Démo k-anonymat complète, hors ligne
python3 leak_detector.py demo

# Vérifier un mot de passe (en ligne si le réseau est disponible,
# bascule automatiquement sur la démo locale sinon)
python3 leak_detector.py password
python3 leak_detector.py password "MonMotDePasse2024!"

# Vérifier un email (nécessite une clé API HIBP)
python3 leak_detector.py email user@example.com --key VOTRE_CLE

# Auditer une liste d'emails depuis un CSV (colonne "email")
python3 leak_detector.py audit emails.csv --key VOTRE_CLE
```

## Fonctionnalités

- Vérification de mot de passe par k-anonymat (le mot de passe n'est jamais transmis)
- Vérification d'email via l'API breachedaccount (nécessite une clé HIBP payante)
- Audit en masse d'une liste d'emails avec rapport JSON
- Mode démo hors ligne avec base de correspondances simulée, pour illustrer le mécanisme sans dépendre du réseau ni d'une clé API

## Conformité

RGPD Art. 33/34 — obligation de notification en cas de violation de données ; bloquer un mot de passe déjà compromis avant son stockage réduit le risque qui déclencherait cette obligation.

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 03/30_
