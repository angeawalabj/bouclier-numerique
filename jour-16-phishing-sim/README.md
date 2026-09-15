# Jour 16 — Simulation de Phishing & Formation

Python 3.10+. Usage exclusivement interne avec accord DRH écrit — un
usage malveillant est un délit (Art. 323-1 Code pénal).

---

## Problème résolu

**91% des cyberattaques commencent par un email de phishing**. La meilleure défense : entraîner régulièrement vos utilisateurs à reconnaître les signaux d'alerte. Ce simulateur crée de vraies campagnes internes, envoie réellement les emails (SMTP), trackle les clics, et redirige immédiatement vers une page éducative qui explique les erreurs commises.

---

## Usage

```bash
# Démo complète (12 utilisateurs simulés, envoi en simulation console)
python phishing_sim.py demo

# 1. Créer une campagne
python phishing_sim.py create --template reset_password --company "Mon Entreprise"

# 2. Lancer le serveur de tracking (dans un terminal séparé)
python phishing_sim.py server --port 8765

# 3. Ajouter les cibles et envoyer — fichier CSV "email,departement" par ligne
#    Sans PHISHING_SMTP_HOST/PORT/USER/PASS configurées, --send simule en console.
export PHISHING_SMTP_HOST=smtp.exemple.fr PHISHING_SMTP_PORT=587
export PHISHING_SMTP_USER=campagnes@exemple.fr PHISHING_SMTP_PASS=...
python phishing_sim.py launch --campaign CAMP-20260312-A1B2C3 \
  --file targets.csv --send

# 4. Rapport de la campagne
python phishing_sim.py report --campaign CAMP-20260312-A1B2C3
```

---

## Fonctionnalités

- 5 templates : reset_password, it_security, hr_document, invoice, shared_file
- Envoi SMTP réel (ou simulation console si non configuré)
- Token unique par destinataire (tracking individuel) — seul le hachage
  de l'email est conservé en base, jamais l'adresse en clair
- Page d'éducation interactive avec quiz (3 questions, score immédiat)
- Email annoté montrant les 5 signaux d'alerte
- Rapport par département : taux de clic, niveau de risque
- Recommandations de formation ciblées

---

## Conformité

ANSSI mesure 42 — sensibilisation par tests réguliers

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 16/30_
