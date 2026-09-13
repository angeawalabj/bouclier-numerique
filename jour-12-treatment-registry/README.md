# Jour 12 — Registre des Traitements RGPD (Art. 30)

Détection automatique d'anomalies, export HTML, score de conformité
calculé (pas déclaratif). Python 3.10+, SQLite.

---

## Problème résolu

**Art. 30 RGPD** : toute organisation traitant des données personnelles doit tenir un registre écrit couvrant exactement 7 mentions obligatoires (a) à (g). La CNIL peut le demander à tout moment lors d'une inspection. L'absence est l'une des infractions les plus fréquemment sanctionnées car la plus simple à vérifier.

```
Inspectrice CNIL : "Montrez-moi votre registre des traitements."
Sans ce script : Recherche dans des tableurs disséminés · Données manquantes · 3 jours de stress
Avec ce script : python registre_traitements.py export --html rapport.html · 3 secondes
```

**Art. 83 §4** — Jusqu'à **10M€ ou 2% du CA mondial** pour absence de registre.

---

## Démarrage rapide

```bash
# Démo complète avec 6 traitements réalistes et détection d'anomalies
python registre_traitements.py demo

# Ajouter un traitement
python registre_traitements.py add \
  --nom "CRM Salesforce" \
  --finalite "Gestion de la relation client" \
  --base-legale "6.1.b"

# Lister les traitements enregistrés
python registre_traitements.py list

# Vérifier la conformité (score calculé, pas déclaratif)
python registre_traitements.py check

# Export rapport HTML (contrôle CNIL)
python registre_traitements.py export --html rapport_cnil.html
```

---

## Les 7 mentions obligatoires (Art. 30)

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

## Détection automatique d'anomalies

Le vérificateur analyse 7 points de conformité sur chaque traitement :

```
[2 anomalies détectées sur TechCorp SARL]

CRITIQUE — Traitement "Transferts financiers"
   Transfert hors UE vers Maroc sans CCT documentées
   → Art. 44-49 RGPD : violation directe du chapitre V
   Action : Signer les Clauses Contractuelles Types Commission EU 2021/914

MAJEUR — Traitement "Recrutement LinkedIn"
   Aucune mesure de sécurité documentée
   → Art. 32 RGPD
   Action : Documenter chiffrement, contrôle d'accès, politique de rétention

Score de conformité : 86/100
```

---

## Fonctionnalités

- 6 traitements réalistes pré-chargés en démo (CRM, RH, analytics, vidéosurveillance...)
- Ajout de traitements réels via `add` (pas seulement en démo)
- Score de conformité sur 100 avec détail par traitement
- Détection des transferts hors UE sans garanties appropriées
- Alerte sur les données sensibles (santé, biométrie) sans AIPD documentée
- Rapport HTML professionnel (prêt pour inspection CNIL)

---

## Score de conformité — méthode de calcul

Le score n'est pas arbitraire. 100 points sont répartis :

- Complétude des 7 mentions (40 pts)
- Mesures de sécurité documentées (20 pts)
- AIPD pour données sensibles (15 pts)
- Conformité transferts hors UE (15 pts)
- Gestion des violations (10 pts)

Chaque anomalie déduit des points et pointe vers l'article précis et une action corrective avec délai recommandé.

---

## Conformité

| Référentiel | Exigence |
|------------|---------|
| **RGPD Art. 30** | Registre des activités de traitement — obligatoire |
| **RGPD Art. 83 §4** | Amende jusqu'à 10M€ ou 2% du CA pour non-conformité |
| **CNIL** | Guide pratique des sous-traitants — registre modèle |

> **Note :** Ce script est complété par un générateur de DPA (Contrat de Sous-traitance Art. 28) dans le fichier bonus `dpa_generator.py`.

---

_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 12/30_
