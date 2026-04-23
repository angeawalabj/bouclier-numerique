#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 30 : SUITE INTÉGRÉE FINALE     ║
║  Challenge terminé — 30 outils de cybersécurité                ║
║  Orchestration complète : OSINT → Scan → ZT → SOAR → Rapport  ║
╚══════════════════════════════════════════════════════════════════╝

Le Jour 30 est l'aboutissement du challenge : tous les outils
des jours 1-29 sont orchestrés dans un pipeline de sécurité
complet qui simule une journée de travail d'un SOC :

  PHASE 1 — Cartographie de la surface d'attaque (J24 OSINT)
  PHASE 2 — Tests de sécurité actifs (J21 API + J22 Injections)
  PHASE 3 — Vérification des hachages (J23 Hash Audit)
  PHASE 4 — Évaluation Zero Trust (J26 ZT Controller)
  PHASE 5 — Détection d'incidents (J17 HIDS + J28 SOAR)
  PHASE 6 — Enrichissement Threat Intel (J29 TI Feed)
  PHASE 7 — Rapport final unifié (J25 Pentest Report)

Conformité totale couverte :
  RGPD  : Art.5/6/17/25/28/30/32/33/34
  ISO   : 27001 complet · 22301 (PCA)
  OWASP : Web Top 10 · API Top 10
  ANSSI : Guide Hygiène 42 mesures
  NIST  : SP 800-207 (ZT) · SP 800-61 (CSIRT)
  NIS2  : Notification incidents
  PCI-DSS : 10.5.5 · 7.1
"""

import json, time, sys, os, threading
from pathlib import Path
from datetime import datetime
from collections import defaultdict
import html as html_mod


# Couleurs terminal
R="\033[91m"; G="\033[92m"; Y="\033[93m"; B="\033[94m"; C="\033[96m"; W="\033[0m"; BOLD="\033[1m"

BANNER = f"""
{C}╔══════════════════════════════════════════════════════════════════╗
║  {BOLD}🛡️  LE BOUCLIER NUMÉRIQUE — JOUR 30 : SUITE FINALE{W}{C}          ║
║  30 jours · 30 outils · Protection complète à 360°            ║
╚══════════════════════════════════════════════════════════════════╝{W}
"""

def phase(n: int, title: str, icon: str = "🔧"):
    print(f"\n{B}{'═'*62}{W}")
    print(f"{B}  {icon}  PHASE {n} — {title.upper()}{W}")
    print(f"{B}{'═'*62}{W}\n")
    time.sleep(0.1)

def ok(msg: str):   print(f"  {G}✅  {msg}{W}")
def warn(msg: str): print(f"  {Y}⚠️   {msg}{W}")
def info(msg: str): print(f"  {C}ℹ️   {msg}{W}")
def fail(msg: str): print(f"  {R}❌  {msg}{W}")


class BouclierSuite:
    """Orchestrateur du Bouclier Numérique — 30 outils intégrés."""

    def __init__(self, target: str = "demo.techcorp.fr"):
        self.target    = target
        self.start_ts  = datetime.now()
        self.findings  = []
        self.events    = []
        self.metrics   = defaultdict(int)

    # ════════════════════════════════════════════════════════════
    # PIPELINE PRINCIPAL
    # ════════════════════════════════════════════════════════════

    def run(self):
        print(BANNER)
        print(f"  Cible     : {BOLD}{self.target}{W}")
        print(f"  Démarrage : {self.start_ts.strftime('%d/%m/%Y %H:%M:%S')}")
        print(f"  Mode      : Démonstration complète (simulation)")

        self._phase1_surface_mapping()
        self._phase2_active_security_tests()
        self._phase3_crypto_audit()
        self._phase4_zero_trust_check()
        self._phase5_incident_detection()
        self._phase6_threat_intel()
        self._phase7_final_report()

        elapsed = (datetime.now() - self.start_ts).total_seconds()
        self._print_final_summary(elapsed)

    # ── Phase 1 : Surface d'attaque ─────────────────────────────

    def _phase1_surface_mapping(self):
        phase(1, "Cartographie de la surface d'attaque", "🗺️")

        # Simulation des résultats OSINT (J24)
        osint_results = {
            "subdomains": ["api.techcorp.fr", "admin.techcorp.fr", "dev.techcorp.fr",
                           "staging.techcorp.fr", "old.techcorp.fr"],
            "spf_ok":     False,
            "dmarc_ok":   False,
            "tls_version":"TLSv1.2",
            "open_ports": [80, 443, 22, 8080, 3306],
            "exposures":  [
                {"type":"SPF manquant",   "severity":"ÉLEVÉE"},
                {"type":"DMARC manquant", "severity":"ÉLEVÉE"},
                {"type":"Port MySQL 3306 ouvert", "severity":"CRITIQUE"},
                {"type":"Sous-domaine dev exposé","severity":"MODÉRÉE"},
                {"type":"Sous-domaine staging exposé","severity":"MODÉRÉE"},
            ]
        }

        info(f"Sous-domaines découverts : {len(osint_results['subdomains'])}")
        for s in osint_results["subdomains"]:
            print(f"     🏷️  {s}")

        info(f"Ports ouverts : {osint_results['open_ports']}")

        for exp in osint_results["exposures"]:
            sev = exp["severity"]
            icon = "🔴" if sev == "CRITIQUE" else "🟠" if sev == "ÉLEVÉE" else "🟡"
            print(f"  {icon}  [{sev}] {exp['type']}")
            self.findings.append({
                "title":    exp["type"],
                "severity": sev,
                "category": "OSINT — Surface d'attaque",
                "source":   "J24 OSINT Crawler",
                "remediation": "Corriger la configuration exposée.",
            })
            self.metrics[f"sev_{sev.lower()}"] += 1

        self.metrics["subdomains"] = len(osint_results["subdomains"])
        ok(f"Phase 1 terminée — {len(osint_results['exposures'])} exposition(s) identifiée(s)")

    # ── Phase 2 : Tests actifs ───────────────────────────────────

    def _phase2_active_security_tests(self):
        phase(2, "Tests de sécurité actifs", "💉")

        # Simulation API Fuzzer (J21)
        info("API Fuzzer (J21) — OWASP API Top 10...")
        api_findings = [
            ("IDOR sur /api/v1/users/{id}",    "CRITIQUE", "API1"),
            ("Rate limiting absent sur /login", "ÉLEVÉE",   "API4"),
            ("Endpoint /api/v1/admin non protégé","CRITIQUE","API2"),
            ("Header Server révèle nginx/1.24", "FAIBLE",   "API8"),
        ]
        for title, sev, owasp in api_findings:
            icon = "🔴" if sev=="CRITIQUE" else "🟠" if sev=="ÉLEVÉE" else "🟢"
            print(f"  {icon}  [{sev}] {owasp} — {title}")
            self.findings.append({"title":title,"severity":sev,
                                  "category":f"API — {owasp}","source":"J21 API Fuzzer",
                                  "remediation":"Corriger selon guide OWASP API Security."})
            self.metrics[f"sev_{sev.lower()}"] += 1

        # Simulation Scanner d'injections (J22)
        info("Scanner d'injections (J22) — OWASP A03...")
        inj_findings = [
            ("SQLi error-based sur /search?q=",     "CRITIQUE", "SQLi"),
            ("XSS réfléchi sur /search?q=",         "ÉLEVÉE",   "XSS"),
            ("SSTI sur /greet?name=",               "CRITIQUE", "SSTI→RCE"),
            ("SQLi time-based sur POST /login",     "CRITIQUE", "SQLi"),
        ]
        for title, sev, vtype in inj_findings:
            icon = "🔴" if sev=="CRITIQUE" else "🟠"
            print(f"  {icon}  [{sev}] {vtype} — {title}")
            self.findings.append({"title":title,"severity":sev,
                                  "category":"Injection","source":"J22 Scanner",
                                  "remediation":"Requêtes paramétrées, encodage sorties."})
            self.metrics[f"sev_{sev.lower()}"] += 1

        ok(f"Phase 2 terminée — {len(api_findings)+len(inj_findings)} vulnérabilité(s)")

    # ── Phase 3 : Audit crypto ───────────────────────────────────

    def _phase3_crypto_audit(self):
        phase(3, "Audit cryptographique", "🔑")

        # Hash cracker (J23)
        info("Audit des hachages (J23) — base de données utilisateurs...")
        hash_results = [
            ("admin",   "MD5", "admin",     True, "💀 TRIVIAL"),
            ("alice",   "MD5", "sunshine",  True, "💀 FAIBLE"),
            ("bob",     "MD5", "bob2024",   True, "⚠️  MOYEN"),
            ("carol",   "MD5", "Tr0ub4dor&3",False,"✅ RÉSISTANT"),
            ("dave",    "MD5", "123456",    True, "💀 TRIVIAL"),
        ]
        cracked = sum(1 for _,_,_,c,_ in hash_results if c)
        for user, algo, pwd, cracked_bool, label in hash_results:
            print(f"  {label}  {user:<10} [{algo}] → {pwd if cracked_bool else '(non craqué)'}")

        if cracked > 0:
            self.findings.append({
                "title":    f"Hachage MD5 sans sel — {cracked}/5 mots de passe récupérables",
                "severity": "CRITIQUE",
                "category": "Cryptographie faible",
                "source":   "J23 Hash Cracker",
                "remediation": "Migrer vers bcrypt(12) ou Argon2id. OWASP ASVS 2.4.1",
            })
            self.metrics["sev_critique"] += 1

        warn(f"{cracked}/5 mots de passe craqués — migration vers bcrypt obligatoire")

        # PKI (J27)
        info("Vérification PKI (J27) — validité des certificats...")
        certs = [
            ("app.techcorp.fr",    "2026-03-10", "2027-03-10", "TLS 1.3", True),
            ("api.techcorp.fr",    "2025-01-01", "2026-01-01", "TLS 1.2", False),  # Expiré
            ("admin.techcorp.fr",  "2025-06-01", "2026-06-01", "TLS 1.2", True),
        ]
        for domain, issued, expires, tls, valid in certs:
            if not valid:
                print(f"  🔴  {domain} — EXPIRÉ ({expires}) !")
                self.findings.append({
                    "title":    f"Certificat expiré : {domain}",
                    "severity": "CRITIQUE",
                    "category": "PKI / TLS",
                    "source":   "J27 PKI Manager",
                    "remediation": "Renouveler le certificat immédiatement. Configurer le renouvellement automatique (certbot).",
                })
                self.metrics["sev_critique"] += 1
            else:
                ok(f"{domain} — {tls} · valide jusqu'au {expires}")

    # ── Phase 4 : Zero Trust ─────────────────────────────────────

    def _phase4_zero_trust_check(self):
        phase(4, "Évaluation Zero Trust", "🔐")

        info("Contrôleur ZT (J26) — évaluation des accès...")
        zt_scenarios = [
            ("alice",   ["admin"],   "/admin/", "read",   True,  True,  True,  True,  65, "STEP_UP"),
            ("bob",     ["editor"],  "/data/",  "write",  False, False, False, False,  5, "DENY"),
            ("charlie", ["viewer"],  "/data/",  "delete", True,  True,  True,  True,  50, "DENY"),
            ("diana",   ["auditor"], "/audit/", "read",   True,  True,  True,  True,  75, "ALLOW"),
            ("inconnu", [],          "/public/","read",   False, False, False, False,  0, "DENY"),
        ]

        allows = sum(1 for *_,d in zt_scenarios if d == "ALLOW")
        denies = sum(1 for *_,d in zt_scenarios if d == "DENY")
        stepup = sum(1 for *_,d in zt_scenarios if d == "STEP_UP")

        icons = {"ALLOW":"✅","DENY":"❌","STEP_UP":"🔐"}
        for user, roles, res, action, mfa, cert, managed, compliant, score, decision in zt_scenarios:
            print(f"  {icons[decision]}  {user:<10} → {res:<12} [{action}] "
                  f"score:{score}/100  {decision}")

        print(f"\n  Résumé : {allows} autorisés · {denies} refusés · {stepup} step-up")

        if stepup > 0:
            self.findings.append({
                "title":    f"{stepup} accès en attente de MFA renforcé",
                "severity": "MODÉRÉE",
                "category": "Zero Trust — Step-Up Auth",
                "source":   "J26 ZT Controller",
                "remediation": "Déployer MFA obligatoire pour tous les accès aux ressources sensibles.",
            })
            self.metrics["sev_modérée"] += 1

        ok("Phase 4 — Politique Zero Trust opérationnelle")

    # ── Phase 5 : Détection ──────────────────────────────────────

    def _phase5_incident_detection(self):
        phase(5, "Détection d'incidents & SOAR", "🚨")

        info("HIDS/FIM (J17) — intégrité des fichiers système...")
        hids_alerts = [
            ("/etc/passwd",         "MODIFIÉ", "hash SHA256 changé"),
            ("/usr/bin/sudo",       "MODIFIÉ", "SUID bit ajouté — possible élévation"),
            ("/var/www/html/index.php", "CRÉÉ","Nouveau fichier web shell suspect"),
        ]
        for path, event, detail in hids_alerts:
            icon = "🔴" if "shell" in detail.lower() or "élévation" in detail.lower() else "🟠"
            print(f"  {icon}  [{event}] {path} — {detail}")
            self.findings.append({
                "title":    f"HIDS : {event} {path}",
                "severity": "CRITIQUE" if "shell" in detail.lower() else "ÉLEVÉE",
                "category": "Intégrité système",
                "source":   "J17 HIDS/FIM",
                "remediation": "Vérifier l'origine de la modification. Restaurer depuis backup si non autorisé.",
            })
            sev = "CRITIQUE" if "shell" in detail.lower() else "ÉLEVÉE"
            self.metrics[f"sev_{sev.lower()}"] += 1

        # SOAR (J28)
        info("SOAR (J28) — réponse automatique aux incidents...")
        incidents = [
            ("brute_force", "185.220.101.42", "ssh:22",    "ÉLEVÉE", "PB-001 → IP bloquée 2h"),
            ("malware",     "inconnu",        "LAPTOP-A",  "CRITIQUE","PB-003 → Quarantaine + forensics"),
            ("phishing",    "external",       "employees", "ÉLEVÉE", "PB-005 → Lien désactivé + alerte"),
        ]
        gdpr_count = 0
        for itype, src, target, sev, action in incidents:
            icon = "🔴" if sev=="CRITIQUE" else "🟠"
            print(f"  {icon}  [{itype}] {src} → {target} : {action}")
            if "malware" in itype:
                gdpr_count += 1
                print(f"  ⏱️   Timer RGPD Art.33 déclenché — notification CNIL avant 72h")
                self.events.append({"type": itype, "gdpr_timer": True})

        self.metrics["incidents_detected"] = len(incidents)
        self.metrics["gdpr_timers"]        = gdpr_count
        ok(f"Phase 5 — {len(incidents)} incident(s) traités · {gdpr_count} timer(s) RGPD")

    # ── Phase 6 : Threat Intel ───────────────────────────────────

    def _phase6_threat_intel(self):
        phase(6, "Threat Intelligence", "🕵️")

        info("Feed TI (J29) — enrichissement des IOCs...")
        ioc_results = [
            ("185.220.101.42",              "ip",     "tor_exit_node",  95, True),
            ("91.234.55.12",                "ip",     "c2_server",      99, True),
            ("techcorp-secure-login.xyz",   "domain", "phishing",       98, True),
            ("8.8.8.8",                     "ip",     None,              0, False),
            ("update.microsoft.com",        "domain", None,              0, False),
        ]

        listed   = sum(1 for *_,found in ioc_results if found)
        unlisted = len(ioc_results) - listed

        for value, itype, threat, conf, found in ioc_results:
            if found:
                icon = "🔴" if conf >= 90 else "🟠"
                print(f"  {icon}  {value:<45} [{threat}] confiance:{conf}%")
            else:
                print(f"  {G}✅  {value:<45} [sain — non listé]{W}")

        self.metrics["iocs_listed"]   = listed
        self.metrics["iocs_unlisted"] = unlisted

        info(f"Blocklists générées : {listed} IOCs haute confiance")
        ok(f"Phase 6 — {listed}/{len(ioc_results)} IOCs corrélés avec la base TI")

    # ── Phase 7 : Rapport final ──────────────────────────────────

    def _phase7_final_report(self):
        phase(7, "Génération du rapport final", "📊")

        # Calculer stats globales
        counts = defaultdict(int)
        for f in self.findings:
            counts[f["severity"]] += 1

        score = max(0, 100 - (
            counts["CRITIQUE"] * 20 + counts["ÉLEVÉE"] * 10 +
            counts["MODÉRÉE"]  *  5 + counts["FAIBLE"]  *  2
        ))

        # Générer le rapport HTML final
        report_path = Path("/tmp/bouclier_rapport_final.html")
        self._write_final_html(report_path, counts, score)

        # Résumé RSSI
        summary = {
            "target":     self.target,
            "date":       self.start_ts.isoformat(),
            "score":      score,
            "findings":   dict(counts),
            "total":      len(self.findings),
            "events":     len(self.events),
            "tools_used": 10,
            "report":     str(report_path),
        }
        json_path = Path("/tmp/bouclier_summary.json")
        json_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False))

        ok(f"Rapport HTML → {report_path}")
        ok(f"Résumé JSON  → {json_path}")

    def _write_final_html(self, path: Path, counts: dict, score: int):
        """Génère le rapport HTML final de la suite complète."""
        score_color = "#e74c3c" if score < 50 else "#e67e22" if score < 75 else "#27ae60"

        tools_table = """
        <table>
          <tr><th>Jour</th><th>Outil</th><th>Catégorie</th><th>Conformité</th></tr>
        """ + "\n".join(f"<tr><td>J{j}</td><td>{t}</td><td>{c}</td><td>{conf}</td></tr>"
                        for j, t, c, conf in [
            ("01","Password Vault","Authentification","RGPD Art.32"),
            ("02","EXIF Cleaner","Vie privée","RGPD Art.5"),
            ("03","Leak Detector","Fuite de données","RGPD Art.33"),
            ("04","File Vault AES","Chiffrement","ISO 27001 A.10"),
            ("05","Permission Audit","Contrôle accès","ISO 27001 A.9"),
            ("06","Rate Limiter","Résilience","OWASP A.4"),
            ("07","Honeypot","Détection","ISO 27001 A.13"),
            ("08","Backup Immuable","Continuité","ANSSI / ISO 22301"),
            ("09","Log Anonymizer","RGPD","RGPD Art.25"),
            ("10","Port Scanner","Réseau","ISO 27001 A.13.1"),
            ("11","Right to Erasure","RGPD","RGPD Art.17"),
            ("12","Registre Art.30","Gouvernance","RGPD Art.30"),
            ("13","Data Masking","RBAC","RGPD Art.5"),
            ("14","Cookie Consent","CNIL","RGPD Art.7"),
            ("15","Dependency Audit","CVE","ISO 27001 A.12.6"),
            ("B","DPA Generator","Sous-traitance","RGPD Art.28"),
            ("16","Phishing Sim","Sensibilisation","ANSSI mesure 42"),
            ("17","HIDS/FIM","Intégrité","PCI-DSS 10.5.5"),
            ("18","E2EE Messaging","Chiffrement","ISO 27001 A.13"),
            ("19","PCA Generator","Continuité","ISO 22301"),
            ("20","RSSI Dashboard","Gouvernance","ISO 27001"),
            ("21","API Fuzzer","Red Team","OWASP API Top 10"),
            ("22","Injection Scanner","Red Team","OWASP A03:2021"),
            ("23","Hash Cracker","Audit crypto","NIST SP 800-63B"),
            ("24","OSINT Crawler","Reconnaissance","ISO 27001 A.12.6"),
            ("25","Pentest Report","Reporting","PTES · ISO 27001"),
            ("26","Zero Trust","Architecture","NIST SP 800-207"),
            ("27","PKI Manager","Certificats","RFC 5280 · ANSSI"),
            ("28","SOAR Engine","Réponse IR","ISO 27035 · NIS2"),
            ("29","Threat Intel","CTI","STIX 2.1 · MITRE"),
            ("30","Suite Intégrée","Orchestration","RGPD+ISO+ANSSI+NIST"),
        ]) + "</table>"

        findings_rows = ""
        for i, f in enumerate(sorted(self.findings,
                              key=lambda x: {"CRITIQUE":0,"ÉLEVÉE":1,"MODÉRÉE":2,"FAIBLE":3}.get(x["severity"],9)),1):
            c = {"CRITIQUE":"#e74c3c","ÉLEVÉE":"#e67e22","MODÉRÉE":"#f39c12","FAIBLE":"#27ae60"}.get(f["severity"],"#666")
            findings_rows += f"""<tr>
              <td style="font-weight:700;color:{c}">{f['severity']}</td>
              <td>{html_mod.escape(f['title'])}</td>
              <td>{html_mod.escape(f.get('source',''))}</td>
              <td style="font-size:.8rem">{html_mod.escape(f.get('remediation','')[:80])}</td>
            </tr>"""

        now = self.start_ts.strftime("%d/%m/%Y %H:%M")
        report = f"""<!DOCTYPE html>
<html lang="fr"><head><meta charset="UTF-8">
<title>🛡️ Bouclier Numérique — Rapport Final</title>
<style>
  :root{{--bg:#0f1117;--card:#1a1d27;--border:#2d3148;--text:#e2e8f0;--muted:#8892b0;--accent:#64ffda}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;padding:2rem;max-width:1200px;margin:auto}}
  h1{{color:var(--accent);font-size:2rem;margin-bottom:.3rem}}
  h2{{color:var(--accent);font-size:1.1rem;margin:2rem 0 1rem;padding-bottom:.4rem;border-bottom:1px solid var(--border)}}
  .meta{{color:var(--muted);font-size:.82rem;margin-bottom:2rem}}
  .score-hero{{text-align:center;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:2rem;margin-bottom:2rem}}
  .score-big{{font-size:5rem;font-weight:900;color:{score_color}}}
  .chips{{display:flex;justify-content:center;gap:.8rem;flex-wrap:wrap;margin-top:1rem}}
  .chip{{padding:.3rem .9rem;border-radius:20px;font-weight:700;font-size:.82rem}}
  table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;overflow:hidden;border:1px solid var(--border);margin-bottom:1.5rem}}
  th{{background:#0a0c14;color:var(--accent);padding:.65rem 1rem;text-align:left;font-size:.8rem}}
  td{{padding:.55rem 1rem;border-top:1px solid var(--border);font-size:.82rem;color:var(--muted)}}
  tr:hover td{{background:#1e2235}}
  .badge-complete{{background:linear-gradient(135deg,#64ffda,#7b68ee);color:#000;padding:.8rem 1.5rem;border-radius:8px;font-weight:900;font-size:1.1rem;display:inline-block;margin:1rem 0}}
</style></head><body>

<h1>🛡️ Bouclier Numérique — Rapport de Sécurité Final</h1>
<div class="meta">Cible : {html_mod.escape(self.target)} · {now} · 30 outils · Challenge terminé ✅</div>

<div class="score-hero">
  <div style="color:var(--muted);font-size:.85rem;margin-bottom:.5rem">Score de Sécurité Global</div>
  <div class="score-big">{score}</div>
  <div style="color:{score_color};font-size:1rem;font-weight:700;margin:.3rem 0">/100</div>
  <div class="chips">
    <span class="chip" style="background:#e74c3c22;color:#e74c3c">🔴 {counts.get('CRITIQUE',0)} Critique(s)</span>
    <span class="chip" style="background:#e67e2222;color:#e67e22">🟠 {counts.get('ÉLEVÉE',0)} Élevée(s)</span>
    <span class="chip" style="background:#f39c1222;color:#f39c12">🟡 {counts.get('MODÉRÉE',0)} Modérée(s)</span>
    <span class="chip" style="background:#27ae6022;color:#27ae60">🟢 {counts.get('FAIBLE',0)} Faible(s)</span>
  </div>
  <div class="badge-complete" style="margin-top:1.5rem">🏆 CHALLENGE 30 JOURS TERMINÉ</div>
</div>

<h2>📋 Vulnérabilités identifiées ({len(self.findings)})</h2>
<table>
  <thead><tr><th>Sévérité</th><th>Vulnérabilité</th><th>Source</th><th>Remédiation</th></tr></thead>
  <tbody>{findings_rows}</tbody>
</table>

<h2>🔧 Les 30 Outils du Challenge</h2>
{tools_table}

<h2>⚖️ Conformité Couverte</h2>
<table>
  <thead><tr><th>Référentiel</th><th>Articles/Contrôles couverts</th></tr></thead>
  <tbody>
    <tr><td>RGPD</td><td>Art.5 (principes) · 6 (légalité) · 17 (effacement) · 25 (privacy by design) · 28 (DPA) · 30 (registre) · 32 (sécurité) · 33-34 (notification)</td></tr>
    <tr><td>ISO 27001</td><td>A.9 (accès) · A.10 (crypto) · A.12 (opérations) · A.13 (réseau) · A.14 (dev) · A.16 (incidents) · A.18 (conformité)</td></tr>
    <tr><td>OWASP</td><td>Web Top 10 2021 complet · API Security Top 10 2023 complet · ASVS 2.4</td></tr>
    <tr><td>ANSSI</td><td>Guide Hygiène 42 mesures · RGS B3 · PA-022 Zero Trust</td></tr>
    <tr><td>NIST</td><td>SP 800-207 Zero Trust · SP 800-61 CSIRT · SP 800-63B Auth · SP 800-132 PBKDF</td></tr>
    <tr><td>NIS2</td><td>Art.21 (mesures) · Notification incidents 24h/72h</td></tr>
    <tr><td>PCI-DSS</td><td>7.1 (accès) · 10.5.5 (FIM) · 6.3 (vulnérabilités)</td></tr>
    <tr><td>ISO 22301</td><td>Plan de Continuité · RTO/RPO · Tests de reprise</td></tr>
  </tbody>
</table>

<div style="color:var(--muted);font-size:.76rem;text-align:center;margin-top:2rem;padding-top:1rem;border-top:1px solid var(--border)">
  <strong style="color:var(--accent)">🛡️ Le Bouclier Numérique</strong> — 30 jours · 30 outils · Protection complète à 360°<br>
  Généré le {now} · Usage légal uniquement
</div>
</body></html>"""
        path.write_text(report, encoding="utf-8")

    def _print_final_summary(self, elapsed: float):
        counts = defaultdict(int)
        for f in self.findings:
            counts[f["severity"]] += 1
        score = max(0, 100 - (
            counts["CRITIQUE"]*20 + counts["ÉLEVÉE"]*10 +
            counts["MODÉRÉE"]*5   + counts["FAIBLE"]*2
        ))

        print(f"""
{C}╔══════════════════════════════════════════════════════════════════╗
║  🏆  BOUCLIER NUMÉRIQUE — CHALLENGE TERMINÉ                    ║
╚══════════════════════════════════════════════════════════════════╝{W}

  {BOLD}Score de sécurité global : {score}/100{W}
  Durée du pipeline        : {elapsed:.1f}s

  {BOLD}Résumé des findings :{W}
  {R}🔴 Critique : {counts['CRITIQUE']}{W}
  {Y}🟠 Élevée   : {counts['ÉLEVÉE']}{W}
  {Y}🟡 Modérée  : {counts['MODÉRÉE']}{W}
  {G}🟢 Faible   : {counts['FAIBLE']}{W}

  {BOLD}Livrables :{W}
  📊 Rapport HTML final  → /tmp/bouclier_rapport_final.html
  📋 Résumé JSON         → /tmp/bouclier_summary.json

  {BOLD}30 outils créés en 30 jours :{W}
  J01-J05  Sécurité individuelle   (crypto, EXIF, fuites, permissions)
  J06-J10  Sécurité PME            (rate limit, honeypot, backup, HIDS)
  J11-J15  Gouvernance RGPD        (registres, masking, cookies, CVE)
  J16-J20  Détection & résilience  (phishing, FIM, E2EE, PCA, RSSI)
  J21-J25  Red Team                (fuzzer, injections, hashes, OSINT)
  J26-J30  Architecture            (Zero Trust, PKI, SOAR, CTI, Suite)

{G}  ✅  Challenge 30 jours terminé avec succès !{W}
  Conformité : RGPD · ISO 27001 · OWASP · ANSSI · NIST · NIS2
""")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Bouclier Numérique — Suite finale J30")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo", help="Démo complète du pipeline")
    ps = sub.add_parser("run");  ps.add_argument("target", default="demo.techcorp.fr", nargs="?")
    args = p.parse_args()

    target = getattr(args, "target", "demo.techcorp.fr") or "demo.techcorp.fr"
    suite  = BouclierSuite(target)
    suite.run()

if __name__ == "__main__":
    main()
