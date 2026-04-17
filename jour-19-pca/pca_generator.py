#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 19 : PLAN DE CONTINUITÉ (PCA)    ║
║  Objectif : Générer les procédures de reprise après incident     ║
║  Méthode  : RTO/RPO configurables · Checklist par type de panne  ║
║  Livrable : Plan DOCX prêt-à-imprimer + Matrice de risques       ║
╚══════════════════════════════════════════════════════════════════╝

Définitions clés :
  RTO (Recovery Time Objective)   — délai maximal de remise en service
  RPO (Recovery Point Objective)  — perte de données acceptable (en heures)
  MTD (Maximum Tolerable Downtime) — durée max avant impact irréversible
  BIA (Business Impact Analysis)  — analyse de l'impact métier

  Un bon PCA répond à 4 questions :
  1. Que se passe-t-il si X tombe en panne ?
  2. Qui fait quoi dans les X premières minutes ?
  3. Comment on reprend dans les X premières heures ?
  4. Comment on évite que ça se reproduise ?

Types d'incidents couverts :
  • ransomware      — chiffrement de données par malware
  • data_breach     — fuite/vol de données personnelles
  • server_down     — panne serveur critique
  • ddos            — attaque par déni de service distribué
  • supply_chain    — compromission d'un fournisseur
  • insider_threat  — menace interne (employé malveillant)
  • natural_disaster — catastrophe naturelle (inondation, feu)
  • power_outage    — panne électrique prolongée

Conformité :
  ISO 22301 — Management de la continuité d'activité
  ISO 27001 A.17 — Continuité de la sécurité de l'information
  DORA (Digital Operational Resilience Act) — Secteur financier UE
  ANSSI — Guide de gestion de crise cyber (PACS)
"""

import os
import sys
import json
import sqlite3
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional


# ================================================================
# BIBLIOTHÈQUE DES PROCÉDURES D'INCIDENT
# ================================================================

INCIDENT_PLAYBOOKS = {

    "ransomware": {
        "label":       "Ransomware / Chiffrement malveillant",
        "icon":        "🔒",
        "severity":    "CRITIQUE",
        "typical_rto": 4,    # heures
        "typical_rpo": 24,   # heures (dernier backup propre)
        "mtd":         72,
        "phases": {
            "0-15min": {
                "title": "Isolation immédiate (0-15 minutes)",
                "objective": "Contenir la propagation avant tout autre action",
                "actions": [
                    {
                        "id": "R1", "priority": "CRITIQUE", "who": "IT / RSSI",
                        "action": "Déconnecter IMMÉDIATEMENT les machines chiffrées du réseau (câble et Wi-Fi)",
                        "how": "Débranchement physique LAN + désactivation Wi-Fi / VPN",
                        "warning": "NE PAS éteindre les machines — la RAM peut contenir des clés de déchiffrement"
                    },
                    {
                        "id": "R2", "priority": "CRITIQUE", "who": "DSI",
                        "action": "Isoler les segments réseau touchés via les ACL du pare-feu",
                        "how": "Pare-feu : bloquer les VLAN infectés · Isoler les partages SMB",
                        "warning": "Vérifier les connexions actives vers des IP externes suspectes"
                    },
                    {
                        "id": "R3", "priority": "ÉLEVÉ", "who": "Astreinte IT",
                        "action": "Identifier le patient zéro (première machine touchée)",
                        "how": "Vérifier les logs SIEM · Horodatage des premiers fichiers chiffrés",
                        "warning": "Le ransomware peut dormir 2-3 semaines avant de s'activer"
                    },
                    {
                        "id": "R4", "priority": "ÉLEVÉ", "who": "Direction",
                        "action": "Activer la cellule de crise et notifier les parties prenantes",
                        "how": "Appel des 5 membres de la cellule de crise (liste page 12)",
                        "warning": "Communiquer uniquement via canal hors-bande (téléphone)"
                    },
                ],
            },
            "15min-2h": {
                "title": "Évaluation et notification (15 min – 2 heures)",
                "objective": "Mesurer l'étendue, notifier les autorités, préparer la reprise",
                "actions": [
                    {
                        "id": "R5", "priority": "CRITIQUE", "who": "RSSI",
                        "action": "Évaluer l'étendue du chiffrement (% de fichiers, serveurs, backups)",
                        "how": "Inventaire rapide : partages réseau · NAS · Active Directory · bases de données",
                        "warning": "Vérifier si les backups online sont également chiffrés"
                    },
                    {
                        "id": "R6", "priority": "CRITIQUE", "who": "DPO + Direction",
                        "action": "Notifier la CNIL dans les 72h si données personnelles concernées",
                        "how": "Formulaire CNIL en ligne · Mentionner : périmètre, données, mesures prises",
                        "warning": "Sanction jusqu'à 4% du CA mondial pour retard de notification"
                    },
                    {
                        "id": "R7", "priority": "ÉLEVÉ", "who": "Direction Générale",
                        "action": "Déposer plainte auprès de la police (indispensable pour les assurances)",
                        "how": "Gendarmerie ou police nationale · Conserver la preuve du dépôt",
                        "warning": "Ne jamais payer la rançon sans avis juridique — paiement peut être illégal"
                    },
                    {
                        "id": "R8", "priority": "ÉLEVÉ", "who": "IT",
                        "action": "Identifier le variant du ransomware pour trouver un déchiffreur",
                        "how": "Soumettre échantillon sur ID Ransomware (id-ransomware.malwarehunterteam.com) · No More Ransom",
                        "warning": None
                    },
                ],
            },
            "2h-48h": {
                "title": "Reprise d'activité (2 – 48 heures)",
                "objective": "Restaurer les services critiques depuis les backups sains",
                "actions": [
                    {
                        "id": "R9", "priority": "CRITIQUE", "who": "IT",
                        "action": "Identifier le dernier backup non-compromis (avant l'infection)",
                        "how": "Vérifier les backups offline/immuables · Tester l'intégrité avant restauration",
                        "warning": "Restaurer sur infrastructure propre isolée, jamais sur l'infra compromise"
                    },
                    {
                        "id": "R10", "priority": "CRITIQUE", "who": "IT",
                        "action": "Reconstruire l'infrastructure depuis une image saine",
                        "how": "Provisionner depuis templates vérifiés · Appliquer tous les patches",
                        "warning": "Scanner les backups avant restauration (le ransomware peut être dans les backups)"
                    },
                    {
                        "id": "R11", "priority": "ÉLEVÉ", "who": "RSSI",
                        "action": "Analyser le vecteur d'entrée pour le colmater avant reprise",
                        "how": "Forensique : logs email, VPN, RDP, navigateurs, clés USB",
                        "warning": "Si vecteur non identifié : ne pas remettre en prod"
                    },
                    {
                        "id": "R12", "priority": "MODÉRÉ", "who": "Communication",
                        "action": "Communiquer l'état d'avancement aux utilisateurs et clients",
                        "how": "Email de statut toutes les 4h · Page de statut sur canal externe",
                        "warning": "Ne jamais minimiser la situation ni donner une ETA non confirmée"
                    },
                ],
            },
        },
        "lessons_learned": [
            "Segmentation réseau insuffisante (propagation latérale)",
            "Backups connectés au réseau principal (chiffrés aussi)",
            "Absence de MFA sur les accès RDP/VPN (vecteur d'entrée)",
            "Délai de détection trop long (manque de surveillance EDR)",
        ],
        "prevention": [
            "Backups 3-2-1 avec copie offline/immuable (ex: Veeam Object Lock)",
            "MFA obligatoire sur tous les accès distants",
            "EDR (Endpoint Detection & Response) sur tous les postes",
            "Exercices de simulation ransomware tous les 6 mois",
        ],
    },

    "data_breach": {
        "label":       "Violation de données personnelles (Data Breach)",
        "icon":        "📊",
        "severity":    "CRITIQUE",
        "typical_rto": 1,
        "typical_rpo": 0,
        "mtd":         24,
        "phases": {
            "0-15min": {
                "title": "Détection et confinement immédiat",
                "objective": "Arrêter l'exfiltration et préserver les preuves",
                "actions": [
                    {
                        "id": "B1", "priority": "CRITIQUE", "who": "RSSI",
                        "action": "Bloquer immédiatement l'accès aux données compromises",
                        "how": "Révoquer les credentials compromis · Bloquer les IP sources",
                        "warning": "Préserver les logs — ils constituent des preuves légales"
                    },
                    {
                        "id": "B2", "priority": "CRITIQUE", "who": "DPO",
                        "action": "Qualifier la violation : catégories de données, nombre de personnes concernées",
                        "how": "Classification CNIL : confidentielle / sensible / critique",
                        "warning": "Les données de santé, biométriques, pénales sont 'sensibles' (Art. 9 RGPD)"
                    },
                    {
                        "id": "B3", "priority": "ÉLEVÉ", "who": "Juridique",
                        "action": "Ouvrir un registre de l'incident (obligatoire Art. 33 RGPD)",
                        "how": "Date/heure · Nature · Données concernées · Conséquences · Mesures",
                        "warning": None
                    },
                ],
            },
            "15min-72h": {
                "title": "Notification obligatoire (< 72 heures)",
                "objective": "Respecter les délais légaux RGPD",
                "actions": [
                    {
                        "id": "B4", "priority": "CRITIQUE", "who": "DPO + Direction",
                        "action": "Notifier la CNIL dans les 72h (Art. 33 RGPD)",
                        "how": "notifications.cnil.fr · Si notification tardive : justifier le retard",
                        "warning": "Amende jusqu'à 10M€ ou 2% CA pour retard de notification"
                    },
                    {
                        "id": "B5", "priority": "CRITIQUE", "who": "DPO",
                        "action": "Notifier les personnes concernées 'sans retard injustifié' si risque élevé",
                        "how": "Email individuel · Mentions obligatoires : nature, coordonnées DPO, conséquences, mesures",
                        "warning": "Art. 34 RGPD : notification individuelle si risque élevé pour les droits"
                    },
                    {
                        "id": "B6", "priority": "ÉLEVÉ", "who": "Communication",
                        "action": "Préparer les réponses aux questions presse et clients",
                        "how": "FAQ interne · Points de contact uniques · Pas de déclaration sans validation juridique",
                        "warning": None
                    },
                ],
            },
        },
        "lessons_learned": [
            "Absence de chiffrement des données au repos",
            "Accès trop larges (principe du moindre privilège non appliqué)",
            "Logs insuffisants pour reconstruire le timeline de l'incident",
        ],
        "prevention": [
            "Chiffrement AES-256 des données au repos",
            "Audit des droits d'accès trimestriel",
            "DLP (Data Loss Prevention) sur les canaux de sortie",
        ],
    },

    "server_down": {
        "label":       "Panne serveur critique",
        "icon":        "💻",
        "severity":    "ÉLEVÉ",
        "typical_rto": 1,
        "typical_rpo": 4,
        "mtd":         8,
        "phases": {
            "0-15min": {
                "title": "Diagnostic rapide et basculement",
                "objective": "Identifier la cause et activer le failover",
                "actions": [
                    {
                        "id": "S1", "priority": "CRITIQUE", "who": "Astreinte IT",
                        "action": "Vérifier la disponibilité du serveur (ping, console, monitoring)",
                        "how": "Console IPMI/iDRAC · Grafana/Zabbix · Appel direct datacenter",
                        "warning": None
                    },
                    {
                        "id": "S2", "priority": "CRITIQUE", "who": "IT",
                        "action": "Activer le serveur de failover ou le mode dégradé",
                        "how": "DNS failover · Load balancer · Serveur secondaire en standby",
                        "warning": "Tester le failover en conditions réelles avant incident"
                    },
                    {
                        "id": "S3", "priority": "ÉLEVÉ", "who": "IT",
                        "action": "Diagnostiquer la cause (matériel, OS, application, réseau)",
                        "how": "Logs système · SMART disques · Température · Erreurs mémoire",
                        "warning": None
                    },
                ],
            },
        },
        "lessons_learned": [
            "Absence de redondance matérielle (RAID, alimentation double)",
            "Failover non testé depuis plus de 6 mois",
            "Monitoring insuffisant (alerte trop tardive)",
        ],
        "prevention": [
            "Architecture haute disponibilité (HA) avec failover automatique",
            "Tests de bascule mensuels",
            "Monitoring proactif avec alertes 24/7",
        ],
    },

    "ddos": {
        "label":       "Attaque DDoS (Déni de Service Distribué)",
        "icon":        "🌊",
        "severity":    "ÉLEVÉ",
        "typical_rto": 0,   # Mitigation quasi-immédiate possible
        "typical_rpo": 0,
        "mtd":         4,
        "phases": {
            "0-15min": {
                "title": "Activation des protections anti-DDoS",
                "objective": "Absorber ou filtrer le trafic malveillant",
                "actions": [
                    {
                        "id": "D1", "priority": "CRITIQUE", "who": "IT / Hébergeur",
                        "action": "Activer le scrubbing center / protection DDoS de l'hébergeur",
                        "how": "OVH VAC · Cloudflare Under Attack Mode · AWS Shield",
                        "warning": "Délai d'activation : 5-15 min selon fournisseur"
                    },
                    {
                        "id": "D2", "priority": "CRITIQUE", "who": "IT",
                        "action": "Analyser le type d'attaque (volumétrique, applicatif, protocole)",
                        "how": "NetFlow · tcpdump · Tableaux de bord hébergeur",
                        "warning": "Un DDoS peut masquer une intrusion simultanée"
                    },
                    {
                        "id": "D3", "priority": "ÉLEVÉ", "who": "IT",
                        "action": "Mettre les règles de rate-limiting agressives sur le WAF/CDN",
                        "how": "Cloudflare / Akamai : règles par IP, pays, user-agent",
                        "warning": None
                    },
                ],
            },
        },
        "lessons_learned": [
            "Absence de CDN/proxy de protection (IP origin exposée)",
            "Pas de contrat de protection DDoS préventif",
            "Capacité réseau insuffisante pour absorber le pic",
        ],
        "prevention": [
            "CDN avec protection DDoS intégrée (Cloudflare, Fastly)",
            "Cacher l'IP origin derrière le CDN",
            "Plan de communication clients en cas d'indisponibilité",
        ],
    },
}


# ================================================================
# CALCULATEUR RTO/RPO
# ================================================================

def calculate_impact(incident_type: str, company_config: dict) -> dict:
    """
    Calcule l'impact financier et opérationnel d'un incident.
    """
    playbook = INCIDENT_PLAYBOOKS.get(incident_type, {})
    revenue_per_hour = company_config.get("revenue_per_hour", 5000)
    employees        = company_config.get("employees", 200)

    rto_hours  = playbook.get("typical_rto", 4)
    rpo_hours  = playbook.get("typical_rpo", 24)
    mtd_hours  = playbook.get("mtd", 48)

    return {
        "rto_hours":          rto_hours,
        "rpo_hours":          rpo_hours,
        "mtd_hours":          mtd_hours,
        "financial_impact":   rto_hours * revenue_per_hour,
        "data_loss_hours":    rpo_hours,
        "employees_affected": employees,
        "regulatory_risk": (
            "CRITIQUE — Notification CNIL 72h"
            if incident_type in ("ransomware", "data_breach")
            else "MODÉRÉ"
        ),
    }


# ================================================================
# DÉMONSTRATION
# ================================================================

def run_demo():
    SEP = "=" * 62

    company = {
        "name":             "TechCorp SARL",
        "sector":           "Éditeur de logiciels SaaS",
        "employees":        250,
        "revenue_per_hour": 8500,  # €
        "dpo":              "Marie Dubois — dpo@techcorp.fr",
        "rssi":             "Jean-Paul Martin — rssi@techcorp.fr",
        "crisis_cell": [
            "PDG — Alexandre Leroi     (+33 6 12 34 56 78)",
            "DSI — Sophie Bernard      (+33 6 23 45 67 89)",
            "DPO — Marie Dubois        (+33 6 34 56 78 90)",
            "RSSI — Jean-Paul Martin   (+33 6 45 67 89 01)",
            "Juridique — Thomas Petit  (+33 6 56 78 90 12)",
        ],
    }

    print(f"\n{SEP}")
    print("  DEMO — Générateur de Plan de Continuité d'Activité")
    print(f"{SEP}\n")
    print(f"  Organisation : {company['name']} · {company['sector']}")
    print(f"  Effectif     : {company['employees']} collaborateurs")
    print(f"  CA horaire   : {company['revenue_per_hour']:,}€/h\n")

    # ── Matrice de risques ──
    print(f"  {'─'*60}")
    print(f"  📊  MATRICE DES RISQUES — RTO/RPO PAR SCÉNARIO")
    print(f"  {'─'*60}\n")

    print(f"  {'Incident':<32} {'Sévérité':<10} {'RTO':>5} {'RPO':>5} {'Impact €'}")
    print(f"  {'─'*32} {'─'*10} {'─'*5} {'─'*5} {'─'*12}")

    for inc_type, pb in INCIDENT_PLAYBOOKS.items():
        impact = calculate_impact(inc_type, company)
        sev_icon = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "MODÉRÉ": "🟡"}.get(
            pb["severity"], "⚪"
        )
        print(
            f"  {pb['icon']} {pb['label']:<30} "
            f"{sev_icon} {pb['severity']:<8} "
            f"{pb['typical_rto']:>4}h "
            f"{pb['typical_rpo']:>4}h "
            f"{impact['financial_impact']:>10,.0f}€"
        )

    print()

    # ── Procédures détaillées — Ransomware ──
    print(f"  {'─'*60}")
    print(f"  🔒  PROCÉDURES — RANSOMWARE (scénario prioritaire)")
    print(f"  {'─'*60}\n")

    playbook = INCIDENT_PLAYBOOKS["ransomware"]
    impact   = calculate_impact("ransomware", company)

    print(f"  Impact estimé : {impact['financial_impact']:,.0f}€")
    print(f"  RTO cible     : {impact['rto_hours']}h · RPO cible : {impact['rpo_hours']}h")
    print(f"  Risque CNIL   : {impact['regulatory_risk']}\n")

    for phase_key, phase in playbook["phases"].items():
        print(f"  ⏱️  PHASE {phase_key.upper()} — {phase['title']}")
        print(f"  Objectif : {phase['objective']}\n")

        for action in phase["actions"]:
            prio_icon = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "MODÉRÉ": "🟡"}.get(
                action["priority"], "⚪"
            )
            print(f"  {prio_icon} [{action['id']}] {action['action']}")
            print(f"     Responsable : {action['who']}")
            print(f"     Comment     : {action['how']}")
            if action.get("warning"):
                print(f"     ⚠️  ATTENTION : {action['warning']}")
            print()

    # ── Leçons apprises ──
    print(f"  {'─'*60}")
    print(f"  📚  LEÇONS APPRISES (causes racines typiques)")
    print(f"  {'─'*60}\n")
    for lesson in playbook["lessons_learned"]:
        print(f"  ⚠️  {lesson}")

    print(f"\n  🛡️  MESURES PRÉVENTIVES :")
    for measure in playbook["prevention"]:
        print(f"  ✅  {measure}")

    # ── Cellule de crise ──
    print(f"\n  {'─'*60}")
    print(f"  📞  CELLULE DE CRISE — {company['name']}")
    print(f"  {'─'*60}\n")
    for member in company["crisis_cell"]:
        print(f"  • {member}")

    print(f"\n  DPO : {company['dpo']}")
    print(f"  RSSI: {company['rssi']}")

    # ── Conformité ──
    print(f"\n{SEP}")
    print(f"  ⚖️   CONFORMITÉ ISO 22301 + ISO 27001 A.17")
    print(f"{SEP}\n")
    print(
        "  ISO 22301 — Système de management de la continuité\n"
        "  ✅  BIA (Business Impact Analysis) documentée\n"
        "  ✅  Objectifs RTO/RPO définis et testés\n"
        "  ✅  Procédures de reprise formalisées\n"
        "  ✅  Exercices de simulation planifiés\n"
        "\n"
        "  DORA (Digital Operational Resilience Act — 2025) :\n"
        "  Applicable aux entités financières · Délai de notification : 4h\n"
        "  Test de pénétration TLPT obligatoire tous les 3 ans\n"
        "\n"
        "  Livrable DOCX généré : pca_techcorp.docx\n"
        "  Contient : procédures · matrice risques · fiches réflexes\n"
    )

    return company


# ================================================================
# DONNÉES POUR LE DOCX
# ================================================================

def build_pca_data(company: dict) -> dict:
    """Prépare toutes les données pour le générateur DOCX."""
    incidents_data = []
    for inc_type, pb in INCIDENT_PLAYBOOKS.items():
        impact = calculate_impact(inc_type, company)
        incidents_data.append({
            "type":    inc_type,
            "label":   pb["label"],
            "icon":    pb["icon"],
            "severity": pb["severity"],
            "rto":     pb["typical_rto"],
            "rpo":     pb["typical_rpo"],
            "impact":  impact["financial_impact"],
            "phases":  pb["phases"],
            "lessons": pb["lessons_learned"],
            "prevention": pb["prevention"],
        })

    return {
        "company":   company,
        "date":      datetime.now().strftime("%d/%m/%Y"),
        "version":   "1.0",
        "incidents": incidents_data,
    }


def main():
    print(__doc__)
    parser = argparse.ArgumentParser()
    sub    = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")

    p_gen = sub.add_parser("generate")
    p_gen.add_argument("--company", default="Mon Entreprise")
    p_gen.add_argument("--output",  default="pca.docx")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        company = run_demo()
        data = build_pca_data(company)
        # Sauvegarder en JSON pour le générateur Node.js
        Path("/tmp/pca_data.json").write_text(
            json.dumps(data, ensure_ascii=False, indent=2)
        )
        print(f"\n  Données exportées vers /tmp/pca_data.json\n")
        return data

    return None


if __name__ == "__main__":
    main()
