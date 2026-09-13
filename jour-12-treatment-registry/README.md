# 📋 Jour 12 — Registre des Traitements RGPD (Art. 30)

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10+-3776AB?style=flat-square&logo=python)
![RGPD](https://img.shields.io/badge/RGPD-Art.%2030%20obligatoire-ff3b3b?style=flat-square)
![Output](https://img.shields.io/badge/Output-HTML%20·%20DOCX%20·%20JSON-00e5a0?style=flat-square)
![CNIL](https://img.shields.io/badge/Amende-10M€%20ou%202%25%20CA-f5a623?style=flat-square)

**Le registre des traitements est obligatoire depuis le 25 mai 2018. Sans lui, c'est la mise en demeure CNIL.**  
Détection automatique des anomalies · Export rapport HTML · Score de conformité

</div>

---

## 🎯 Problème résolu

**Art. 30 RGPD** : toute organisation traitant des données personnelles doit tenir un registre écrit couvrant exactement 7 mentions obligatoires (a) à (g). La CNIL peut le demander à tout moment lors d'une inspection. L'absence est l'une des infractions les plus fréquemment sanctionnées car la plus simple à vérifier.

```
Inspectrice CNIL : "Montrez-moi votre registre des traitements."
Sans ce script : Recherche dans des tableurs disséminés · Données manquantes · 3 jours de stress
Avec ce script : python registre_traitements.py export --html rapport.html · 3 secondes
```

**Art. 83 §4** — Jusqu'à **10M€ ou 2% du CA mondial** pour absence de registre.

---

## ⚡ Démarrage rapide

```bash
# Démo complète avec 6 traitements réalistes et détection d'anomalies
python registre_traitements.py demo

# Ajouter un traitement
python registre_traitements.py add --name "CRM Salesforce" --base-legale "6.1.b"

# Vérifier la conformité
python registre_traitements.py check

# Export rapport HTML (contrôle CNIL)
python registre_traitements.py export --html rapport_cnil.html

# Export JSON (intégration SIRH)
python registre_traitements.py export --json registre.json
```

---

## 🔬 Les 7 mentions obligatoires (Art. 30)

| Mention | Description | Champ dans l'outil |
|---------|-------------|-------------------|
| **(a)** | Nom et coordonnées du responsable | `responsable` |
| **(b)** | Finalités du traitement | `finalite` |
| **(c)** | Catégories de personnes et données | `categories_personnes`, `categories_donnees` |
| **(d)** | Destinataires | `destinataires` |
| **(e)** | Transferts vers pays tiers | `transferts_hors_ue` |
| **(f)** | Délais de suppression | `duree_conservation` |
| **(g)** | Mesures de sécurité | `mesures_securite` |

---

## 🚨 Détection automatique d'anomalies

Le vérificateur analyse 7 points de conformité sur chaque traitement :

```
[2 anomalies détectées sur TechCorp SARL]

🔴 CRITIQUE — Traitement "Transferts financiers"
   Transfert hors UE vers Maroc sans CCT documentées
   → Art. 44-49 RGPD : violation directe du chapitre V
   Action : Signer les Clauses Contractuelles Types Commission EU 2021/914

🟠 MAJEUR — Traitement "Recrutement LinkedIn"
   Aucune mesure de sécurité documentée
   → Art. 32 RGPD
   Action : Documenter chiffrement, contrôle d'accès, politique de rétention

Score de conformité : 86/100
```

---

## ✨ Fonctionnalités

- 6 traitements réalistes pré-chargés en démo (CRM, RH, analytics, vidéosurveillance...)
- Score de conformité sur 100 avec détail par traitement
- Détection des transferts hors UE sans garanties appropriées
- Alerte sur les données sensibles (santé, biométrie) sans AIPD documentée
- Rapport HTML professionnel (prêt pour inspection CNIL)
- Export JSON pour intégration dans vos outils existants
- Interface web minimale pour les DPO non-techniques

---

## 📊 Score de conformité — méthode de calcul

Le score n'est pas arbitraire. 100 points sont répartis :

- Complétude des 7 mentions (40 pts)
- Mesures de sécurité documentées (20 pts)
- AIPD pour données sensibles (15 pts)
- Conformité transferts hors UE (15 pts)
- Gestion des violations (10 pts)

Chaque anomalie déduit des points et pointe vers l'article précis et une action corrective avec délai recommandé.

---

## ⚖️ Conformité

| Référentiel | Exigence |
|------------|---------|
| **RGPD Art. 30** | Registre des activités de traitement — obligatoire |
| **RGPD Art. 83 §4** | Amende jusqu'à 10M€ ou 2% du CA pour non-conformité |
| **CNIL** | Guide pratique des sous-traitants — registre modèle |

> **Note :** Ce script est également fourni avec un générateur de DPA (Contrat de Sous-traitance Art. 28) dans le fichier bonus `dpa_generator.py`.

---

_Partie du challenge [🛡️ Le Bouclier Numérique](../README.md) — Jour 12/30_
