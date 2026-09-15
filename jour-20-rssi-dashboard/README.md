# Jour 20 — Tableau de Bord RSSI

Python 3.10+ pour la génération, HTML/JS vanilla pour le rendu (aucune
dépendance côté navigateur).

## Problème résolu

Un RSSI qui pilote plusieurs outils de sécurité a besoin d'une vue
d'ensemble, pas de 19 fenêtres séparées. Ce tableau de bord agrège des
mesures réelles de quatre outils du challenge (réseau, conformité RGPD,
intégrité fichiers, dépendances) en un seul écran, plutôt que d'exiger
qu'on lise chaque rapport individuellement.

## Usage

```bash
python3 rssi_dashboard.py demo
# ou, pour choisir le fichier de sortie :
python3 rssi_dashboard.py generate --output rapport.html
```

Le script exécute quatre contrôles en direct sur ce poste
(`port_scanner`, `registre_traitements`, `ids_monitor`,
`dependency_audit`) et injecte leurs résultats réels dans le gabarit
`rssi_dashboard.html`, sans le modifier — le résultat est écrit dans
`./output/`.

**`rssi_dashboard.html` seul, ouvert directement dans un navigateur,
affiche un tableau de bord vide** : c'est un gabarit, pas une démo
autonome. Il n'y a pas de nombres à y trouver tant que le script Python
n'a pas tourné.

## Fonctionnalités

- Score global animé (jauge SVG), calculé sur les domaines réellement mesurés
- Alertes générées à partir de ce que les contrôles ont effectivement trouvé
  (port à risque, anomalie RGPD, fichier modifié, CVE) — pas une liste pré-écrite
- Barres de conformité par référentiel (ISO 27001, RGPD, PCI-DSS, NIS2, ANSSI),
  dérivées des mesures réelles selon les domaines de contrôle que chacun couvre —
  ce ne sont pas des scores d'audit officiels
- Fonctionne offline une fois généré ; aucune dépendance côté navigateur

## Limites connues

- Sur une première exécution (dépôt fraîchement cloné), plusieurs
  mesures partent d'un état neutre (aucun traitement RGPD enregistré,
  aucune baseline HIDS existante) : le score reflète cet état de départ,
  pas une compromission.
- Le contrôle dépendances nécessite un accès réseau à OSV.dev ; sans
  réseau, ce domaine est marqué "non mesuré" plutôt que de recevoir un
  score inventé.
- Seuls 4 domaines sur les 30 outils du challenge sont mesurés ici — les
  autres outils restent utilisables individuellement.

## Conformité

Tableau de bord de pilotage — s'inscrit dans la démarche de suivi
continu de l'ISO 27001 A.18.2, sans s'y substituer.

---
_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 20/30_
