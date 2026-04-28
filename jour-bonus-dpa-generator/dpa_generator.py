#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 11 : GÉNÉRATEUR DE DPA           ║
║  Obligation : Art. 28 RGPD — Contrat sous-traitant obligatoire  ║
║  Format     : .docx signable · Modèle CNIL 2024                 ║
║  Clauses    : 12 clauses obligatoires + clauses recommandées     ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 28 §3 RGPD — Tout traitement effectué
par un sous-traitant doit être régi par un contrat liant le
sous-traitant au responsable de traitement, stipulant notamment
que le sous-traitant :

  a) Ne traite les données que sur instruction documentée
  b) Garantit la confidentialité des personnes autorisées
  c) Prend toutes les mesures de sécurité (Art. 32)
  d) Respecte les conditions de recours aux sous-traitants
  e) Aide le RT à garantir les droits des personnes
  f) Aide le RT à respecter Art. 32-36 (sécurité, AIPD)
  g) Supprime/restitue toutes les données en fin de contrat
  h) Met à disposition toutes les informations nécessaires
     pour démontrer le respect des obligations

Sanctions : Art. 83 §4 — jusqu'à 10M€ ou 2% CA mondial
pour absence de contrat sous-traitant conforme.

Cas réel : La CNIL a sanctionné plusieurs entreprises pour
avoir utilisé des sous-traitants sans DPA en bonne et due
forme, notamment dans le cloud et le marketing.
"""

import os
import sys
import json
import subprocess
import tempfile
import hashlib
from pathlib import Path
from datetime import datetime, date
from typing import Optional

# ================================================================
# MODÈLES DE CLAUSES (conforme CNIL + EDPB Guidelines 07/2020)
# ================================================================

CLAUSES_OBLIGATOIRES = {
    "objet_duree": {
        "titre": "Objet et durée du traitement",
        "article": "Art. 28(3) RGPD",
        "contenu": (
            "Le Sous-traitant est autorisé à traiter les Données Personnelles "
            "décrites à l'Annexe 1 pour le compte du Responsable du traitement, "
            "aux seules fins définies à l'Annexe 1, pour la durée du Contrat "
            "principal ou jusqu'à résiliation expresse."
        ),
    },
    "instructions": {
        "titre": "Instructions documentées",
        "article": "Art. 28(3)(a)",
        "contenu": (
            "Le Sous-traitant traite les Données Personnelles uniquement sur "
            "instruction documentée du Responsable du traitement, y compris en "
            "ce qui concerne les transferts de données vers un pays tiers. "
            "Si le Sous-traitant est tenu de procéder à un transfert vers un "
            "pays tiers en vertu du droit de l'Union ou du droit d'un État "
            "membre auquel il est soumis, il en informe le Responsable du "
            "traitement préalablement au traitement, sauf si ce droit interdit "
            "une telle information."
        ),
    },
    "confidentialite": {
        "titre": "Obligation de confidentialité",
        "article": "Art. 28(3)(b)",
        "contenu": (
            "Le Sous-traitant veille à ce que les personnes autorisées à "
            "traiter les Données Personnelles s'engagent à respecter la "
            "confidentialité ou soient soumises à une obligation légale "
            "appropriée de confidentialité. La liste des personnes autorisées "
            "est tenue à jour et mise à disposition du Responsable du traitement "
            "sur demande."
        ),
    },
    "securite": {
        "titre": "Mesures de sécurité (Art. 32)",
        "article": "Art. 28(3)(c) + Art. 32",
        "contenu": (
            "Le Sous-traitant met en oeuvre les mesures techniques et "
            "organisationnelles appropriées visées à l'Article 32 du RGPD, "
            "notamment celles décrites à l'Annexe 2. Ces mesures comprennent "
            "au minimum : (i) le chiffrement des données en transit et au "
            "repos ; (ii) des contrôles d'accès basés sur les rôles (RBAC) ; "
            "(iii) une authentification multi-facteurs pour les accès aux "
            "systèmes traitant les Données ; (iv) un plan de réponse aux "
            "incidents avec délai de notification de 24h au Responsable."
        ),
    },
    "sous_sous_traitance": {
        "titre": "Recours à un autre sous-traitant",
        "article": "Art. 28(2) + Art. 28(4)",
        "contenu": (
            "Le Sous-traitant ne recourt à un autre sous-traitant (ci-après "
            "'Sous-traitant Ultérieur') qu'avec l'autorisation écrite préalable "
            "spécifique ou générale du Responsable du traitement. "
            "Dans le cas d'une autorisation générale, le Sous-traitant informe "
            "le Responsable de tout changement prévu concernant l'ajout ou le "
            "remplacement d'autres sous-traitants, donnant ainsi au Responsable "
            "la possibilité d'émettre des objections à l'encontre de ces "
            "changements. Le Sous-traitant impose au Sous-traitant Ultérieur "
            "les mêmes obligations que celles prévues au présent Contrat."
        ),
    },
    "droits_personnes": {
        "titre": "Assistance pour les droits des personnes",
        "article": "Art. 28(3)(e) + Art. 12-22",
        "contenu": (
            "Compte tenu de la nature du traitement, le Sous-traitant aide le "
            "Responsable du traitement, par des mesures techniques et "
            "organisationnelles appropriées, à s'acquitter de son obligation "
            "de donner suite aux demandes dont les personnes concernées le "
            "saisissent en vue d'exercer leurs droits : droit d'accès (Art. 15), "
            "de rectification (Art. 16), d'effacement (Art. 17), à la "
            "portabilité (Art. 20), d'opposition (Art. 21). "
            "Le délai de réponse du Sous-traitant ne dépasse pas 72h ouvrées."
        ),
    },
    "violations": {
        "titre": "Notification des violations de données",
        "article": "Art. 28(3)(f) + Art. 33-34",
        "contenu": (
            "Le Sous-traitant notifie au Responsable du traitement toute "
            "violation de données à caractère personnel dans les meilleurs "
            "délais après en avoir pris connaissance, et au plus tard dans un "
            "délai de 24 heures. Cette notification contient au minimum : "
            "(i) la nature de la violation ; (ii) les catégories et nombre "
            "approximatif de personnes concernées ; (iii) les catégories et "
            "nombre approximatif d'enregistrements concernés ; (iv) les "
            "conséquences probables ; (v) les mesures prises ou envisagées."
        ),
    },
    "aipd": {
        "titre": "Analyse d'impact (AIPD) et consultation préalable",
        "article": "Art. 28(3)(f) + Art. 35-36",
        "contenu": (
            "Le Sous-traitant aide le Responsable du traitement à garantir le "
            "respect des obligations découlant des Articles 32 à 36, compte "
            "tenu de la nature du traitement et des informations dont dispose "
            "le Sous-traitant. En cas de traitement susceptible d'engendrer un "
            "risque élevé, le Sous-traitant apporte son concours à la "
            "réalisation d'une Analyse d'Impact relative à la Protection des "
            "Données (AIPD) dans un délai de 20 jours ouvrés."
        ),
    },
    "restitution_suppression": {
        "titre": "Sort des données en fin de contrat",
        "article": "Art. 28(3)(g)",
        "contenu": (
            "Au terme du Contrat principal ou sur demande du Responsable du "
            "traitement, le Sous-traitant : (i) restitue au Responsable "
            "l'intégralité des Données dans un format ouvert et portable "
            "(CSV, JSON ou XML selon les données) dans un délai de 30 jours "
            "calendaires ; puis (ii) détruit toutes les copies existantes, "
            "sauf obligation légale de conservation. La suppression est "
            "attestée par un certificat de destruction délivré sous 5 jours "
            "ouvrés. Les données de sauvegarde sont détruites dans un délai "
            "n'excédant pas 60 jours."
        ),
    },
    "audit": {
        "titre": "Droit d'audit et d'inspection",
        "article": "Art. 28(3)(h)",
        "contenu": (
            "Le Sous-traitant met à la disposition du Responsable du traitement "
            "toutes les informations nécessaires pour apporter la preuve du "
            "respect des obligations prévues à l'Article 28 du RGPD et pour "
            "permettre la réalisation d'audits, y compris des inspections, par "
            "le Responsable du traitement ou un auditeur qu'il a mandaté, et "
            "contribue à ces audits. Les audits ont lieu sur préavis de 15 "
            "jours ouvrés, sauf urgence justifiée, et ne dépassent pas 2 jours "
            "par an sauf manquement avéré."
        ),
    },
    "transferts_tiers": {
        "titre": "Transferts vers pays tiers",
        "article": "Art. 44-49 RGPD",
        "contenu": (
            "Tout transfert de Données vers un pays tiers ou une organisation "
            "internationale est subordonné au respect du Chapitre V du RGPD. "
            "En l'absence de décision d'adéquation de la Commission européenne "
            "pour le pays destinataire, le Sous-traitant s'engage à mettre en "
            "oeuvre des garanties appropriées, notamment : des Clauses "
            "Contractuelles Types (CCT) adoptées par la Commission (décision "
            "2021/914), ou des Règles d'Entreprise Contraignantes (BCR), ou "
            "tout autre mécanisme prévu à l'Article 46 du RGPD."
        ),
    },
    "dpo_contact": {
        "titre": "Délégué à la Protection des Données",
        "article": "Art. 37-39 RGPD",
        "contenu": (
            "Si le Sous-traitant est tenu de désigner un Délégué à la "
            "Protection des Données (DPO) en vertu de l'Article 37 du RGPD, "
            "il communique ses coordonnées au Responsable du traitement lors "
            "de la signature du présent Contrat. Toute modification des "
            "coordonnées du DPO est notifiée dans un délai de 10 jours "
            "ouvrés. Les échanges avec le DPO du Responsable du traitement "
            "se font par voie électronique sécurisée."
        ),
    },
}

# Bases légales pour les transferts
MECANISMES_TRANSFERT = {
    "CCT": "Clauses Contractuelles Types (décision 2021/914)",
    "BCR": "Règles d'Entreprise Contraignantes",
    "adequation": "Décision d'adéquation de la Commission européenne",
    "consentement": "Consentement explicite des personnes concernées",
    "contrat": "Exécution d'un contrat avec la personne concernée",
    "interet_vital": "Protection des intérêts vitaux",
}

# ================================================================
# GÉNÉRATEUR DE CONTENU DPA
# ================================================================

def build_dpa_data(config: dict) -> dict:
    """
    Construit le contenu structuré du DPA à partir de la configuration.
    Retourne un dict complet prêt pour la génération DOCX.
    """
    today = date.today()
    ref   = f"DPA-{today.strftime('%Y%m%d')}-{os.urandom(3).hex().upper()}"

    # Numéro de version + signature hash pour traçabilité
    content_hash = hashlib.sha256(
        json.dumps(config, sort_keys=True).encode()
    ).hexdigest()[:12]

    # Vérification des clauses de transfert
    transfert_clause = ""
    if config.get("pays_traitement") and config["pays_traitement"] not in (
        "France", "Allemagne", "Espagne", "Italie", "Pays-Bas",
        "Belgique", "Luxembourg", "Suède", "Finlande", "Danemark",
    ):
        mecanisme = config.get("mecanisme_transfert", "CCT")
        transfert_clause = MECANISMES_TRANSFERT.get(mecanisme, mecanisme)

    return {
        "ref":             ref,
        "version":         "1.0",
        "content_hash":    content_hash,
        "date_creation":   today.isoformat(),
        "date_entree":     config.get("date_entree", today.isoformat()),

        # Parties
        "rt_nom":          config.get("rt_nom", "[RESPONSABLE DU TRAITEMENT]"),
        "rt_forme":        config.get("rt_forme", "SAS"),
        "rt_siren":        config.get("rt_siren", ""),
        "rt_adresse":      config.get("rt_adresse", ""),
        "rt_representant": config.get("rt_representant", ""),
        "rt_dpo_email":    config.get("rt_dpo_email", ""),

        "st_nom":          config.get("st_nom", "[SOUS-TRAITANT]"),
        "st_forme":        config.get("st_forme", ""),
        "st_siren":        config.get("st_siren", ""),
        "st_adresse":      config.get("st_adresse", ""),
        "st_representant": config.get("st_representant", ""),
        "st_dpo_email":    config.get("st_dpo_email", ""),
        "st_pays":         config.get("pays_traitement", "France"),

        # Traitement
        "objet_contrat":   config.get("objet_contrat", ""),
        "finalites":       config.get("finalites", []),
        "categories_personnes": config.get("categories_personnes", []),
        "categories_donnees":   config.get("categories_donnees", []),
        "donnees_sensibles":    config.get("donnees_sensibles", False),
        "duree":           config.get("duree", "Durée du contrat principal"),
        "volume_estime":   config.get("volume_estime", ""),

        # Sécurité
        "mesures_securite": config.get("mesures_securite", []),
        "hebergement":      config.get("hebergement", ""),
        "certifications":   config.get("certifications", []),

        # Transferts
        "transfert_hors_ue": bool(config.get("pays_traitement") and
                                   config.get("pays_traitement") not in ("France",)),
        "mecanisme_transfert": transfert_clause,
        "pays_traitement":     config.get("pays_traitement", "France"),

        # Options
        "autorisation_sst":      config.get("autorisation_sst", "specifique"),
        "liste_sst":             config.get("liste_sst", []),
        "delai_notification_vio": config.get("delai_notification_vio", "24"),
        "delai_reponse_droits":  config.get("delai_reponse_droits", "72"),
        "delai_restitution":     config.get("delai_restitution", "30"),

        # Clauses
        "clauses": CLAUSES_OBLIGATOIRES,
    }


def verifier_conformite_dpa(data: dict) -> dict:
    """Vérifie que le DPA contient tous les éléments Art. 28."""
    checks  = {}
    manques = []

    checks["parties_identifiees"] = bool(
        data.get("rt_nom") and data.get("st_nom") and
        "[" not in data.get("rt_nom", "") and
        "[" not in data.get("st_nom", "")
    )
    if not checks["parties_identifiees"]:
        manques.append("Coordonnées des parties incomplètes")

    checks["finalites_definies"] = bool(data.get("finalites") and
                                         len(data["finalites"]) > 0)
    checks["categories_personnes"] = bool(data.get("categories_personnes"))
    checks["categories_donnees"]   = bool(data.get("categories_donnees"))
    checks["duree_definie"]        = bool(data.get("duree"))
    checks["mesures_securite"]     = bool(data.get("mesures_securite") and
                                           len(data["mesures_securite"]) >= 3)
    checks["transfert_encadre"]    = (
        not data.get("transfert_hors_ue") or
        bool(data.get("mecanisme_transfert"))
    )
    checks["dpo_rt"]   = bool(data.get("rt_dpo_email"))
    checks["toutes_clauses"] = len(data.get("clauses", {})) >= 10

    score = sum(1 for v in checks.values() if v)
    total = len(checks)

    return {
        "checks":     checks,
        "score":      score,
        "total":      total,
        "pct":        int(score / total * 100),
        "manquants":  manques,
        "conforme":   score == total,
    }


# ================================================================
# GÉNÉRATION DU DOCUMENT WORD
# ================================================================

def generate_docx(data: dict, output_path: Path) -> str:
    """Génère le DPA en format .docx via docx-js."""

    js_data = json.dumps(data, ensure_ascii=False, indent=2)

    # Construire les listes d'annexe
    finalites_items = ",\n".join(
        f'new Paragraph({{numbering:{{reference:"numbers",level:0}}, children:[new TextRun("{f}")]}})'
        for f in (data["finalites"] or ["À définir"])
    )
    cats_personnes_items = ",\n".join(
        f'new Paragraph({{numbering:{{reference:"bullets",level:0}}, children:[new TextRun("{c}")]}})'
        for c in (data["categories_personnes"] or ["À définir"])
    )
    cats_donnees_items = ",\n".join(
        f'new Paragraph({{numbering:{{reference:"bullets",level:0}}, children:[new TextRun("{c}")]}})'
        for c in (data["categories_donnees"] or ["À définir"])
    )
    mesures_items = ",\n".join(
        f'new Paragraph({{numbering:{{reference:"bullets",level:0}}, children:[new TextRun("{m}")]}})'
        for m in (data["mesures_securite"] or ["Mesures standard de sécurité"])
    )
    sst_items = ",\n".join(
        f'new Paragraph({{numbering:{{reference:"bullets",level:0}}, children:[new TextRun("{s}")]}})'
        for s in (data.get("liste_sst") or ["Aucun sous-traitant ultérieur prévu"])
    )

    # Construire les paragraphes des clauses
    clauses_js = ""
    for key, clause in data["clauses"].items():
        escaped_titre   = clause["titre"].replace('"', '\\"')
        escaped_article = clause["article"].replace('"', '\\"')
        escaped_contenu = (
            clause["contenu"]
            .replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", " ")
        )
        clauses_js += f"""
        // Clause: {escaped_titre}
        new Paragraph({{
            heading: HeadingLevel.HEADING_2,
            children: [new TextRun("{escaped_article} — {escaped_titre}")]
        }}),
        new Paragraph({{
            spacing: {{before: 80, after: 160}},
            children: [new TextRun("{escaped_contenu}")]
        }}),
        """

    date_fr = datetime.fromisoformat(data["date_creation"]).strftime("%d/%m/%Y")

    js_script = f"""
const fs = require('fs');
const {{
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  HeadingLevel, AlignmentType, BorderStyle, WidthType, ShadingType,
  LevelFormat, PageNumber, Footer, Header, TabStopType, TabStopPosition
}} = require('docx');

const BLUE      = "1F3864";
const LIGHTBLUE = "D6E4F0";
const GRAY      = "F5F5F5";
const border    = {{ style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" }};
const borders   = {{ top: border, bottom: border, left: border, right: border }};
const noBorder  = {{ style: BorderStyle.NONE, size: 0, color: "FFFFFF" }};
const noBorders = {{ top: noBorder, bottom: noBorder, left: noBorder, right: noBorder }};

function cell(text, opts={{}}) {{
  return new TableCell({{
    borders,
    width: {{ size: opts.width || 4683, type: WidthType.DXA }},
    shading: {{ fill: opts.fill || "FFFFFF", type: ShadingType.CLEAR }},
    margins: {{ top: 100, bottom: 100, left: 140, right: 140 }},
    children: [new Paragraph({{
      children: [new TextRun({{ text, bold: opts.bold||false, size: 22 }})]
    }})]
  }});
}}

function section(title) {{
  return new Paragraph({{
    heading: HeadingLevel.HEADING_1,
    children: [new TextRun(title)]
  }});
}}

const doc = new Document({{
  numbering: {{
    config: [
      {{ reference: "bullets",
         levels: [{{ level: 0, format: LevelFormat.BULLET, text: "\\u2022",
           alignment: AlignmentType.LEFT,
           style: {{ paragraph: {{ indent: {{ left: 720, hanging: 360 }} }} }} }}] }},
      {{ reference: "numbers",
         levels: [{{ level: 0, format: LevelFormat.DECIMAL, text: "%1.",
           alignment: AlignmentType.LEFT,
           style: {{ paragraph: {{ indent: {{ left: 720, hanging: 360 }} }} }} }}] }},
    ]
  }},
  styles: {{
    default: {{
      document: {{ run: {{ font: "Arial", size: 22 }} }}
    }},
    paragraphStyles: [
      {{ id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal",
         quickFormat: true,
         run: {{ size: 28, bold: true, font: "Arial", color: BLUE }},
         paragraph: {{
           spacing: {{ before: 360, after: 120 }},
           border: {{ bottom: {{ style: BorderStyle.SINGLE, size: 4, color: BLUE, space: 4 }} }},
           outlineLevel: 0
         }} }},
      {{ id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal",
         quickFormat: true,
         run: {{ size: 24, bold: true, font: "Arial", color: "2E4057" }},
         paragraph: {{ spacing: {{ before: 240, after: 80 }}, outlineLevel: 1 }} }},
      {{ id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal",
         quickFormat: true,
         run: {{ size: 22, bold: true, font: "Arial", color: "444444" }},
         paragraph: {{ spacing: {{ before: 160, after: 60 }}, outlineLevel: 2 }} }},
    ]
  }},
  sections: [{{
    properties: {{
      page: {{
        size: {{ width: 11906, height: 16838 }},
        margin: {{ top: 1134, bottom: 1134, left: 1418, right: 1134 }}
      }}
    }},
    headers: {{
      default: new Header({{
        children: [new Paragraph({{
          border: {{ bottom: {{ style: BorderStyle.SINGLE, size: 4, color: BLUE, space: 6 }} }},
          children: [
            new TextRun({{ text: "ACCORD DE TRAITEMENT DES DONNÉES (DPA)", bold: true,
                           size: 20, color: BLUE }}),
            new TextRun({{ text: "   \\u2022   Réf. {data['ref']}", size: 18, color: "888888" }})
          ]
        }})]
      }})
    }},
    footers: {{
      default: new Footer({{
        children: [new Paragraph({{
          border: {{ top: {{ style: BorderStyle.SINGLE, size: 2, color: "CCCCCC", space: 4 }} }},
          tabStops: [{{ type: TabStopType.RIGHT, position: 9026 }}],
          children: [
            new TextRun({{ text: "Confidentiel — {data['rt_nom']} / {data['st_nom']}", size: 18, color: "888888" }}),

          ]
        }})]
      }})
    }},
    children: [

      // ═══ PAGE DE GARDE ═══
      new Paragraph({{ spacing: {{ before: 720, after: 0 }} , children: [] }}),

      // Bandeau titre
      new Paragraph({{
        alignment: AlignmentType.CENTER,
        spacing: {{ before: 0, after: 240 }},
        border: {{
          top:    {{ style: BorderStyle.SINGLE, size: 24, color: BLUE }},
          left:   {{ style: BorderStyle.SINGLE, size: 8,  color: BLUE }},
          bottom: {{ style: BorderStyle.SINGLE, size: 8,  color: BLUE }},
          right:  {{ style: BorderStyle.SINGLE, size: 8,  color: BLUE }},
        }},
        shading: {{ fill: BLUE, type: ShadingType.CLEAR }},
        children: [
          new TextRun({{ text: "", size: 14, break: 1 }} ),
          new TextRun({{ text: "ACCORD DE TRAITEMENT DES DONNÉES", bold: true, size: 40, color: "FFFFFF" }}),
          new TextRun({{ text: "Data Processing Agreement (DPA)", size: 24, color: "D0E4F7", break: 1 }}),
          new TextRun({{ text: "Conformément à l'Article 28 du Règlement (UE) 2016/679 (RGPD)", size: 20, color: "AACCE0", break: 1 }}),
          new TextRun({{ text: "", size: 14, break: 1 }}),
        ]
      }}),

      new Paragraph({{ spacing: {{ before: 360, after: 120 }}, children: [] }}),

      // Table des parties
      new Table({{
        width: {{ size: 9026, type: WidthType.DXA }},
        columnWidths: [4513, 4513],
        rows: [
          new TableRow({{
            children: [
              new TableCell({{
                borders,
                width: {{ size: 4513, type: WidthType.DXA }},
                shading: {{ fill: BLUE, type: ShadingType.CLEAR }},
                margins: {{ top: 120, bottom: 120, left: 180, right: 180 }},
                children: [
                  new Paragraph({{ children: [new TextRun({{ text: "RESPONSABLE DU TRAITEMENT", bold: true, color: "FFFFFF", size: 22 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "{data['rt_nom']}", bold: true, color: "FFFFFF", size: 26 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "{data['rt_forme']}", color: "AACCE0", size: 20 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "{data['rt_adresse']}", color: "D0E4F7", size: 18 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "DPO : {data['rt_dpo_email']}", color: "AACCE0", size: 18 }})] }}),
                ]
              }}),
              new TableCell({{
                borders,
                width: {{ size: 4513, type: WidthType.DXA }},
                shading: {{ fill: LIGHTBLUE, type: ShadingType.CLEAR }},
                margins: {{ top: 120, bottom: 120, left: 180, right: 180 }},
                children: [
                  new Paragraph({{ children: [new TextRun({{ text: "SOUS-TRAITANT", bold: true, color: BLUE, size: 22 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "{data['st_nom']}", bold: true, color: "1a1a1a", size: 26 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "{data['st_forme']}", color: "555555", size: 20 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "{data['st_adresse']}", color: "555555", size: 18 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "DPO : {data['st_dpo_email'] or 'N/A'}", color: "555555", size: 18 }})] }}),
                ]
              }}),
            ]
          }})
        ]
      }}),

      new Paragraph({{ spacing: {{ before: 240, after: 120 }}, children: [] }}),

      // Métadonnées du contrat
      new Table({{
        width: {{ size: 9026, type: WidthType.DXA }},
        columnWidths: [2400, 4200, 2426],
        rows: [
          new TableRow({{
            children: [
              new TableCell({{ borders, width: {{ size: 2400, type: WidthType.DXA }},
                shading: {{ fill: GRAY, type: ShadingType.CLEAR }},
                margins: {{ top: 80, bottom: 80, left: 140, right: 140 }},
                children: [new Paragraph({{ children: [new TextRun({{ text: "Référence", bold: true, size: 20 }})] }})] }}),
              new TableCell({{ borders, width: {{ size: 4200, type: WidthType.DXA }},
                margins: {{ top: 80, bottom: 80, left: 140, right: 140 }},
                children: [new Paragraph({{ children: [new TextRun({{ text: "{data['ref']}", size: 20 }})] }})] }}),
              new TableCell({{ borders, width: {{ size: 2426, type: WidthType.DXA }},
                margins: {{ top: 80, bottom: 80, left: 140, right: 140 }},
                shading: {{ fill: GRAY, type: ShadingType.CLEAR }},
                children: [new Paragraph({{ children: [new TextRun({{ text: "Date : {date_fr}", size: 20 }})] }})] }}),
            ]
          }}),
          new TableRow({{
            children: [
              new TableCell({{ borders, width: {{ size: 2400, type: WidthType.DXA }},
                shading: {{ fill: GRAY, type: ShadingType.CLEAR }},
                margins: {{ top: 80, bottom: 80, left: 140, right: 140 }},
                children: [new Paragraph({{ children: [new TextRun({{ text: "Objet", bold: true, size: 20 }})] }})] }}),
              new TableCell({{ borders, columnSpan: 2, width: {{ size: 6626, type: WidthType.DXA }},
                margins: {{ top: 80, bottom: 80, left: 140, right: 140 }},
                children: [new Paragraph({{ children: [new TextRun({{ text: "{data['objet_contrat'] or 'Prestation de services définie au contrat principal'}", size: 20 }})] }})] }}),
            ]
          }}),
          new TableRow({{
            children: [
              new TableCell({{ borders, width: {{ size: 2400, type: WidthType.DXA }},
                shading: {{ fill: GRAY, type: ShadingType.CLEAR }},
                margins: {{ top: 80, bottom: 80, left: 140, right: 140 }},
                children: [new Paragraph({{ children: [new TextRun({{ text: "Version", bold: true, size: 20 }})] }})] }}),
              new TableCell({{ borders, width: {{ size: 4200, type: WidthType.DXA }},
                margins: {{ top: 80, bottom: 80, left: 140, right: 140 }},
                children: [new Paragraph({{ children: [new TextRun({{ text: "v{data['version']}  —  Hash : {data['content_hash']}", size: 18, color: "888888" }})] }})] }}),
              new TableCell({{ borders, width: {{ size: 2426, type: WidthType.DXA }},
                margins: {{ top: 80, bottom: 80, left: 140, right: 140 }},
                children: [new Paragraph({{ children: [new TextRun({{ text: "Pays ST : {data['pays_traitement']}", size: 20 }})] }})] }}),
            ]
          }}),
        ]
      }}),

      // ═══ CLAUSES ═══
      new Paragraph({{ children: [new TextRun({{ text: "", break: 1 }})] }}),
      section("I. CLAUSES OBLIGATOIRES (Art. 28 RGPD)"),

      {clauses_js}

      // ═══ ANNEXES ═══
      section("II. ANNEXE 1 — DESCRIPTION DU TRAITEMENT"),

      new Paragraph({{ heading: HeadingLevel.HEADING_2, children: [new TextRun("A. Finalités du traitement")] }}),
      {finalites_items},

      new Paragraph({{ heading: HeadingLevel.HEADING_2, children: [new TextRun("B. Catégories de personnes concernées")] }}),
      {cats_personnes_items},

      new Paragraph({{ heading: HeadingLevel.HEADING_2, children: [new TextRun("C. Catégories de données traitées")] }}),
      {cats_donnees_items},

      new Paragraph({{ heading: HeadingLevel.HEADING_2, children: [new TextRun("D. Volume estimé et durée")] }}),
      new Paragraph({{ children: [new TextRun("Volume estimé : {data['volume_estime'] or 'À préciser'}")] }}),
      new Paragraph({{ children: [new TextRun("Durée du traitement : {data['duree']}")] }}),

      {"new Paragraph({ children: [new TextRun({ text: '⚠️ ATTENTION : Ce traitement inclut des données sensibles (Art. 9 RGPD). Une AIPD est obligatoire.', bold: true, color: 'C00000', size: 22 })] })," if data.get("donnees_sensibles") else ""}

      section("III. ANNEXE 2 — MESURES DE SÉCURITÉ (Art. 32 RGPD)"),

      new Paragraph({{ spacing: {{before: 80, after: 120}}, children: [new TextRun("Le Sous-traitant met en oeuvre les mesures techniques et organisationnelles suivantes :")] }}),
      {mesures_items},

      {"new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun('Certifications et conformités')] }), new Paragraph({ children: [new TextRun('" + ', '.join(data.get('certifications') or []) + "')] })," if data.get("certifications") else ""}

      section("IV. ANNEXE 3 — SOUS-TRAITANTS ULTÉRIEURS"),

      new Paragraph({{ spacing: {{before: 80, after: 120}}, children: [
        new TextRun("Autorisation : {'Spécifique (au cas par cas)' if data.get('autorisation_sst') == 'specifique' else 'Générale (avec notification préalable)'}. ")
      ]}}),
      {sst_items},

      {"section('V. ANNEXE 4 — TRANSFERTS HORS UE')," if data.get("transfert_hors_ue") else ""}
      {"new Paragraph({ children: [new TextRun('Pays de traitement : " + data.get("pays_traitement","?") + "') ] })," if data.get("transfert_hors_ue") else ""}
      {"new Paragraph({ children: [new TextRun('Mécanisme de transfert : " + (data.get("mecanisme_transfert") or "À définir") + "') ] })," if data.get("transfert_hors_ue") else ""}

      // ═══ SIGNATURES ═══
      section("V. SIGNATURES"),

      new Paragraph({{ spacing: {{before: 120, after: 360}}, children: [
        new TextRun("Les parties soussignées déclarent avoir lu et approuvé l'intégralité du présent Accord de Traitement des Données. Cet accord entre en vigueur à la date de la dernière signature.")
      ]}}),

      new Table({{
        width: {{ size: 9026, type: WidthType.DXA }},
        columnWidths: [4513, 4513],
        rows: [
          new TableRow({{
            children: [
              new TableCell({{
                borders,
                width: {{ size: 4513, type: WidthType.DXA }},
                shading: {{ fill: LIGHTBLUE, type: ShadingType.CLEAR }},
                margins: {{ top: 100, bottom: 100, left: 180, right: 180 }},
                children: [
                  new Paragraph({{ children: [new TextRun({{ text: "Responsable du traitement", bold: true, size: 22 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "{data['rt_nom']}", size: 22 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "Représenté par : {data['rt_representant'] or '___________________'}", size: 20 }})] }}),
                  new Paragraph({{ spacing: {{before: 480, after: 0}}, children: [new TextRun("Date et signature :")] }}),
                  new Paragraph({{ spacing: {{before: 480, after: 0}}, children: [new TextRun("____________________________")] }}),
                ]
              }}),
              new TableCell({{
                borders,
                width: {{ size: 4513, type: WidthType.DXA }},
                shading: {{ fill: GRAY, type: ShadingType.CLEAR }},
                margins: {{ top: 100, bottom: 100, left: 180, right: 180 }},
                children: [
                  new Paragraph({{ children: [new TextRun({{ text: "Sous-traitant", bold: true, size: 22 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "{data['st_nom']}", size: 22 }})] }}),
                  new Paragraph({{ children: [new TextRun({{ text: "Représenté par : {data['st_representant'] or '___________________'}", size: 20 }})] }}),
                  new Paragraph({{ spacing: {{before: 480, after: 0}}, children: [new TextRun("Date et signature :")] }}),
                  new Paragraph({{ spacing: {{before: 480, after: 0}}, children: [new TextRun("____________________________")] }}),
                ]
              }}),
            ]
          }})
        ]
      }}),

    ]
  }}]
}});

Packer.toBuffer(doc).then(buffer => {{
  fs.writeFileSync('{output_path}', buffer);
  console.log('OK:' + buffer.length);
}}).catch(e => {{
  console.error('ERR:' + e.message);
  process.exit(1);
}});
"""

    with tempfile.NamedTemporaryFile(mode="w", suffix=".js",
                                      delete=False, encoding="utf-8") as f:
        f.write(js_script)
        js_path = f.name

    try:
        result = subprocess.run(
            ["node", js_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            raise RuntimeError(f"docx-js error: {result.stderr[:500]}")
        if "ERR:" in result.stdout:
            raise RuntimeError(result.stdout)
        return str(output_path)
    finally:
        os.unlink(js_path)


# ================================================================
# DEMO
# ================================================================

DEMO_CONFIG = {
    # Responsable du traitement
    "rt_nom":          "TechCorp SARL",
    "rt_forme":        "SARL au capital de 50 000€",
    "rt_siren":        "123 456 789",
    "rt_adresse":      "42 rue de la Paix, 75002 Paris",
    "rt_representant": "Pierre Dupont, Directeur Général",
    "rt_dpo_email":    "dpo@techcorp.fr",

    # Sous-traitant
    "st_nom":          "CloudHost Solutions SAS",
    "st_forme":        "SAS au capital de 100 000€",
    "st_siren":        "987 654 321",
    "st_adresse":      "18 avenue des Champs-Élysées, 75008 Paris",
    "st_representant": "Marie Laurent, Directrice Technique",
    "st_dpo_email":    "privacy@cloudhost.fr",

    # Traitement
    "objet_contrat":   "Hébergement et maintenance de la plateforme CRM",
    "finalites": [
        "Hébergement de la base de données clients",
        "Sauvegarde quotidienne des données",
        "Maintenance préventive et corrective",
        "Supervision des performances",
    ],
    "categories_personnes": [
        "Clients et prospects de TechCorp",
        "Contacts commerciaux (entreprises)",
        "Utilisateurs de la plateforme",
    ],
    "categories_donnees": [
        "Identité : nom, prénom, fonction",
        "Coordonnées : email, téléphone, adresse",
        "Données commerciales : historique achats, devis",
        "Données de connexion : logs, IP pseudonymisées",
    ],
    "donnees_sensibles": False,
    "duree":           "Durée du contrat de service (3 ans renouvelables)",
    "volume_estime":   "Environ 25 000 enregistrements clients",

    # Sécurité
    "mesures_securite": [
        "Chiffrement AES-256 des données au repos et TLS 1.3 en transit",
        "Authentification multi-facteurs (MFA) pour tous les accès admin",
        "Contrôle d'accès RBAC avec principe du moindre privilège",
        "Journalisation complète des accès (conservation 12 mois)",
        "Sauvegardes chiffrées quotidiennes avec rétention 30 jours",
        "Plan de réponse aux incidents (PRI) avec équipe 24/7",
        "Tests de pénétration annuels par prestataire certifié",
        "Certification ISO 27001 en cours (audit prévu Q2 2026)",
    ],
    "hebergement":    "Datacenters Tier III en France (Paris + Lyon)",
    "certifications": ["HDS (Hébergement Données de Santé) — non applicable",
                       "ISO 27001 (certification en cours)"],

    # Transferts
    "pays_traitement":     "France",
    "mecanisme_transfert": "",

    # Sous-traitants ultérieurs
    "autorisation_sst": "generale",
    "liste_sst": [
        "OVHcloud — Hébergement physique des serveurs (France)",
        "Datadog — Monitoring et alerting (États-Unis — DPF)",
        "PagerDuty — Gestion des astreintes (États-Unis — DPF)",
    ],

    # Délais
    "delai_notification_vio": "24",
    "delai_reponse_droits":   "48",
    "delai_restitution":      "30",
}


def run_demo():
    SEP = "=" * 62

    print(f"\n{SEP}")
    print("  DEMO — Générateur de DPA (Art. 28 RGPD)")
    print(f"{SEP}\n")
    print(
        "  Scénario : TechCorp SARL confie l'hébergement de son\n"
        "  CRM à CloudHost Solutions. Sans DPA signé, tout\n"
        "  incident de sécurité chez le sous-traitant engage\n"
        "  la responsabilité de TechCorp vis-à-vis de la CNIL.\n"
    )

    print(f"  {'─'*60}")
    print(f"  📋  ÉTAPE 1 : Construction du DPA")
    print(f"  {'─'*60}\n")

    data = build_dpa_data(DEMO_CONFIG)

    print(f"  Référence     : {data['ref']}")
    print(f"  RT            : {data['rt_nom']}")
    print(f"  Sous-traitant : {data['st_nom']}")
    print(f"  Pays ST       : {data['pays_traitement']}")
    print(f"  Clauses       : {len(data['clauses'])} obligatoires (Art. 28)")
    print(f"  Transfert UE  : {'Non — mécanisme : ' + data['mecanisme_transfert'] if data['transfert_hors_ue'] else 'Oui (hébergement France)'}")

    print(f"\n  {'─'*60}")
    print(f"  ✅  ÉTAPE 2 : Vérification de conformité")
    print(f"  {'─'*60}\n")

    conformite = verifier_conformite_dpa(data)
    bar = "█" * conformite["score"] * 2 + "░" * ((conformite["total"] - conformite["score"]) * 2)
    print(f"  Score Art. 28 : [{bar}] {conformite['pct']}%  "
          f"({conformite['score']}/{conformite['total']} checks)")
    for check, ok in conformite["checks"].items():
        icon = "✅" if ok else "❌"
        print(f"    {icon}  {check.replace('_', ' ')}")

    print(f"\n  {'─'*60}")
    print(f"  📄  ÉTAPE 3 : Génération du document Word")
    print(f"  {'─'*60}\n")

    output_path = Path("/mnt/user-data/outputs/DPA_TechCorp_CloudHost.docx")
    print(f"  Génération en cours...")

    try:
        generate_docx(data, output_path)
        size_kb = output_path.stat().st_size // 1024
        print(f"  ✅  Document généré : {output_path.name}")
        print(f"  Taille  : {size_kb} Ko")
        print(f"  Contenu : Page de garde · {len(data['clauses'])} clauses "
              f"· 4 annexes · Bloc signatures")
    except Exception as e:
        print(f"  ❌  Erreur génération DOCX : {e}")

    print(f"\n{SEP}")
    print(f"  📋  RÉSUMÉ DES 12 CLAUSES GÉNÉRÉES")
    print(f"{SEP}")
    for i, (key, clause) in enumerate(data["clauses"].items(), 1):
        print(f"  {i:>2}. [{clause['article']:<25}] {clause['titre']}")

    print(f"\n{SEP}")
    print(f"  ⚖️   CONTEXTE LÉGAL")
    print(f"{SEP}\n")
    print(
        "  Sans DPA conforme Art. 28 :\n"
        "  ❌  Responsabilité solidaire RT + ST en cas de fuite\n"
        "  ❌  Amende CNIL : jusqu'à 10M€ ou 2% CA (Art. 83 §4)\n"
        "  ❌  Absence de recours contractuel contre le ST\n"
        "  ❌  Impossibilité de notifier la CNIL dans les 72h\n"
        "\n"
        "  Avec ce DPA :\n"
        "  ✅  Obligations contractuellement opposables au ST\n"
        "  ✅  Droit d'audit formalisé\n"
        "  ✅  Procédure de notification violation définie\n"
        "  ✅  Sort des données en fin de contrat garanti\n"
        "  ✅  Preuve de conformité pour la CNIL\n"
    )
    print(f"  Usage :\n"
          f"  python3 dpa_generator.py generate --rt 'MaBoite' --st 'MonCloud'\n"
          f"  python3 dpa_generator.py demo\n")


# ================================================================
# CLI
# ================================================================

def main():
    print(__doc__)
    import argparse
    parser = argparse.ArgumentParser()
    sub    = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")

    p_gen = sub.add_parser("generate", help="Générer un DPA")
    p_gen.add_argument("--rt",     required=True, help="Nom du responsable du traitement")
    p_gen.add_argument("--st",     required=True, help="Nom du sous-traitant")
    p_gen.add_argument("--objet",  default="Prestation de services")
    p_gen.add_argument("--pays",   default="France")
    p_gen.add_argument("--output", default="dpa.docx")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    if args.cmd == "generate":
        config = {
            "rt_nom": args.rt,
            "st_nom": args.st,
            "objet_contrat": args.objet,
            "pays_traitement": args.pays,
        }
        data = build_dpa_data(config)
        out  = Path(args.output)
        generate_docx(data, out)
        print(f"\n  ✅  DPA généré : {out}")
        print(f"  Référence : {data['ref']}")


if __name__ == "__main__":
    main()
