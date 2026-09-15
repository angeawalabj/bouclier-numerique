# Jour 30 — Suite Intégrée

Python 3.10+. Orchestrateur qui appelle réellement six outils du
challenge, dans l'ordre, sur ce poste — pas un tableau de bord statique.

```bash
python3 suite_integree.py demo
python3 suite_integree.py report --output rapport.html
```

## Ce que ça fait vraiment

Six phases s'exécutent en séquence, chacune important et appelant le
module correspondant plutôt que d'afficher un résultat pré-écrit :

1. **permission_audit** (Jour 5) — audit local des accès caméra/micro et connexions suspectes
2. **port_scanner** (Jour 10) — scan TCP réel des ports en écoute sur ce poste
3. **ids_monitor** (Jour 17) — baseline puis détection réelle d'une modification de fichier
4. **registre_traitements** (Jour 12) — score de conformité Art. 30 calculé sur un vrai traitement
5. **threat_intel** (Jour 29) — peuple la base d'IoC réelle avec les indicateurs de démo
6. **soar** (Jour 28) — traite une alerte via le moteur de playbooks, enrichie par la base que l'étape précédente vient de peupler

La dépendance entre les étapes 5 et 6 est vérifiable dans la sortie :
le score de réputation IP que SOAR affiche est celui que threat_intel a
réellement inséré juste avant, pas une coïncidence.

Chaque phase est isolée par un `try/except` : si l'une échoue (`openssl`
absent, pas de réseau...), les autres continuent et le rapport final le
signale honnêtement au lieu de masquer l'échec.

## Limites connues

- Les six phases tournent en local, sur ce poste ou un répertoire
  temporaire — ça ne remplace pas un audit sur une vraie cible distante.
- Seuls 6 des outils du challenge sont orchestrés ici (ceux qui
  s'exécutent rapidement et sans dépendance externe lourde). Les autres
  restent utilisables individuellement, voir leurs README respectifs.

---
_Partie du challenge [Le Bouclier Numérique](../README.md) — Jour 30/30_
