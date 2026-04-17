# 🔐 Politique de Sécurité — Le Bouclier Numérique

## Versions supportées

| Version | Support sécurité |
|---------|-----------------|
| `main` (branche principale) | ✅ Supporté |
| Tags `v1.x` | ✅ Supporté |
| Branches de feature | ❌ Non supporté |
| Forks non maintenus | ❌ Non supporté |

---

## Signaler une vulnérabilité

> ⚠️ **Ne pas ouvrir une Issue GitHub publique pour les vulnérabilités de sécurité.**  
> Une divulgation publique avant un correctif met en danger les utilisateurs du projet.

### Procédure de divulgation responsable

**1. Nous contacter en privé**

Envoyez un rapport par l'un de ces canaux (par ordre de préférence) :

- **GitHub Security Advisory** : [Onglet Security > Advisories > New draft advisory](../../security/advisories/new)
- **Email PGP** : `security@bouclier-numerique.dev` — clé publique disponible sur [keys.openpgp.org](https://keys.openpgp.org)

**2. Inclure dans votre rapport**

```
Titre          : Description courte de la vulnérabilité
Outil affecté  : ex. jour-07-honeypot/honeypot.py
Version        : ex. commit abc1234 / tag v1.2.0
Sévérité       : Critique / Élevée / Modérée / Faible (CVSS si possible)
Description    : Explication détaillée
Reproduction   : Étapes pour reproduire
Impact         : Qu'est-ce qu'un attaquant peut faire ?
Correctif      : Suggestion si vous en avez une (optionnel)
```

**3. Délais de réponse**

| Action | Délai |
|--------|-------|
| Accusé de réception | 48 heures ouvrées |
| Évaluation initiale | 5 jours ouvrés |
| Correctif (critique) | 7 jours |
| Correctif (élevée) | 14 jours |
| Correctif (modérée) | 30 jours |
| Publication CVE (si applicable) | Après le correctif |

---

## Programme de reconnaissance

Nous remercions publiquement les chercheurs qui nous signalent des vulnérabilités de manière responsable dans le fichier [HALL_OF_FAME.md](HALL_OF_FAME.md) (avec leur accord).

Ce projet n'offre pas de récompense financière (bug bounty), mais une reconnaissance explicite et une mention dans le changelog de la release.

---

## Périmètre de la politique

### Dans le périmètre ✅

- Vulnérabilités dans le code Python des outils du challenge
- Problèmes cryptographiques (algorithmes faibles, mauvaise utilisation)
- Injections possibles dans les outils d'audit
- Fuites de données sensibles dans les logs ou outputs
- Dépendances avec CVE critique non patchées

### Hors périmètre ❌

- Attaques sur l'infrastructure GitHub elle-même
- Social engineering des mainteneurs
- Vulnérabilités dans les outils tiers utilisés (signaler directement à leurs auteurs)
- "Vulnérabilités" dans les outils offensifs utilisés *contre des tiers* — c'est illégal et hors scope

---

## Contexte légal — outils offensifs

Plusieurs outils de ce dépôt sont intentionnellement capables d'actions offensives (scanner de ports, simulation de phishing, honeypot, fuzzer d'API). Cela fait partie de leur nature éducative.

**Ce n'est pas une vulnérabilité** que ces outils *puissent* être utilisés de façon malveillante — c'est intentionnel et documenté dans les avertissements légaux de chaque outil.

Ce qui **est** dans le périmètre : si un outil offensif peut être détourné pour attaquer la machine qui l'exécute (ex: path traversal dans le fuzzer qui lit des fichiers locaux arbitraires).

---

## Historique des avis de sécurité

| Date | Outil | Sévérité | Statut |
|------|-------|---------|--------|
| — | — | — | Aucun incident à ce jour |

---

## Maintainers

Pour les questions de sécurité urgentes :

- Ouvrir un [Security Advisory privé GitHub](../../security/advisories/new)
- Les Issues publiques sur des vulnérabilités seront fermées sans réponse détaillée et redirigées vers ce canal

---

*Cette politique est inspirée des meilleures pratiques de [GitHub Security](https://docs.github.com/en/code-security/security-advisories) et de la [ISO/IEC 29147 — Vulnerability Disclosure](https://www.iso.org/standard/72311.html).*
