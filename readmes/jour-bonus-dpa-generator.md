# 📄 Bonus — Générateur DPA (Accord de Sous-traitance Art. 28)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![RGPD](https://img.shields.io/badge/RGPD-Art.%2028%20obligatoire-ff3b3b?style=flat-square)
![Output](https://img.shields.io/badge/Output-DOCX%20professionnel-0078d4?style=flat-square)
![CNIL](https://img.shields.io/badge/Amende-10M€%20ou%202%25%20CA-f5a623?style=flat-square)

**Sans DPA, tout contrat avec un sous-traitant traitant des données personnelles est illégal.**  
Génération automatique · Clauses Art. 28 complètes · Format Word signable

</div>

---

## 🎯 Problème résolu

**Art. 28 RGPD** : tout responsable de traitement doit conclure un contrat écrit (DPA — Data Processing Agreement) avec chaque sous-traitant qui traite des données personnelles pour son compte.

En pratique, 70% des PME n'ont pas de DPA en ordre avec leurs prestataires SaaS, hébergeurs, intégrateurs...

```
Exemples typiques nécessitant un DPA :
  → Votre hébergeur cloud (AWS, OVH, Azure)
  → Votre outil d'emailing (Mailchimp, Brevo)
  → Votre CRM (Salesforce, HubSpot)
  → Votre sous-traitant de paie
  → Votre prestataire de support IT
```

**En cas de contrôle CNIL :** l'absence de DPA est une violation directe et immédiate, sanctionnable jusqu'à **10M€ ou 2% du CA mondial**.

---

## ⚡ Démarrage rapide

```bash
# Générer un DPA complet (mode interactif)
python3 dpa_generator.py generate

# Génération avec paramètres en ligne de commande
python3 dpa_generator.py generate \
  --responsable "TechCorp SARL" \
  --sous-traitant "CloudHost SAS" \
  --service "Hébergement infrastructure" \
  --donnees "Données clients, logs applicatifs" \
  --output DPA_CloudHost.docx

# Vérifier un DPA existant (checklist Art. 28)
python3 dpa_generator.py check --input contrat_existant.docx

# Démo — génère DPA_TechCorp_CloudHost.docx
python3 dpa_generator.py demo
```

---

## 📋 Clauses générées (Art. 28 §3 a-h)

Le DPA généré couvre les 8 obligations réglementaires :

| Clause | Art. 28 §3 | Contenu |
|--------|-----------|---------|
| **Objet & durée** | Intro | Périmètre exact des traitements |
| **Instructions documentées** | (a) | Le ST ne traite que sur instruction écrite |
| **Confidentialité** | (b) | Engagement du personnel autorisé |
| **Sécurité (Art. 32)** | (c) | Mesures techniques et organisationnelles |
| **Sous-traitance ultérieure** | (d) | Autorisation préalable écrite obligatoire |
| **Droits des personnes** | (e) | Assistance dans les 72h |
| **Fin du contrat** | (f) | Retour ou destruction des données |
| **Audits & coopération** | (g-h) | Droit d'audit, documentation, AIPD |

---

## 📄 Exemple de document produit

Le fichier `.docx` généré est un contrat professionnel incluant :
- En-tête avec parties, date, et numéro de contrat
- Définitions RGPD intégrées (Art. 4)
- Tableaux récapitulatifs des traitements
- Annexes : liste des sous-traitants ultérieurs autorisés, mesures de sécurité
- Espace pour signatures et dates

---

## ⚖️ Conformité

| Référentiel | Exigence |
|------------|---------|
| **RGPD Art. 28** | Contrat de sous-traitance obligatoire |
| **RGPD Art. 83 §4** | Amende jusqu'à 10M€ pour absence de DPA |
| **CNIL** | Modèle de clauses contractuelles sous-traitants |
| **EDPB Guidelines 07/2020** | Lignes directrices sur les notions de RT et ST |

> **Note :** Ce générateur produit un modèle de contrat à adapter avec votre conseil juridique. Il ne remplace pas un avis d'avocat spécialisé en protection des données.

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Outil Bonus_
