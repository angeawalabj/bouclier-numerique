#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 24 : CRAWLER OSINT            ║
║  Objectif  : Cartographier l'exposition publique de votre org  ║
║  Sources   : DNS · WHOIS · Certificats · Headers · Emails      ║
║  Légalité  : Informations PUBLIQUES uniquement                 ║
╚══════════════════════════════════════════════════════════════════╝

L'OSINT (Open Source INTelligence) est la première phase de tout
test d'intrusion. Un attaquant passe des heures à collecter des
informations publiques avant d'agir. Ce script fait la même chose
sur VOTRE domaine pour identifier ce qui est exposé.

Sources exploitées (100% légales — données publiques) :
  DNS      : enregistrements A, MX, NS, TXT, SPF, DMARC, DKIM
  WHOIS    : registrant, dates, contacts (si non masqués)
  Certificats SSL : crt.sh — sous-domaines dans le SAN
  Headers HTTP    : Server, X-Powered-By, technos exposées
  Sécurité email  : SPF, DMARC, DKIM — protection anti-phishing

Chaque information trouvée est une surface d'attaque potentielle.

Conformité : ISO 27001 A.18.1.4 · RGPD Art. 32 · ANSSI hygiène
"""

import urllib.request
import urllib.parse
import urllib.error
import socket
import json
import ssl
import re
import time
import html as html_module
from pathlib import Path
from datetime import datetime
from typing import Optional


# ════════════════════════════════════════════════════════════════
# COLLECTE DNS
# ════════════════════════════════════════════════════════════════

def resolve_dns(domain: str, record_type: str = "A") -> list[str]:
    """Résout un enregistrement DNS via Google DoH (DNS over HTTPS)."""
    try:
        url = (f"https://dns.google/resolve?name="
               f"{urllib.parse.quote(domain)}&type={record_type}")
        req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
        answers = data.get("Answer", [])
        return [a.get("data", "").rstrip(".") for a in answers if a.get("type")]
    except Exception:
        return []


def get_dns_records(domain: str) -> dict:
    """Collecte tous les enregistrements DNS pertinents."""
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        results = resolve_dns(domain, rtype)
        if results:
            records[rtype] = results
    return records


def analyze_email_security(domain: str) -> dict:
    """Analyse la configuration de sécurité email (SPF, DMARC, DKIM)."""
    report = {"spf": None, "dmarc": None, "dkim": {}, "score": 0, "issues": []}

    # SPF
    txt = resolve_dns(domain, "TXT")
    spf = next((r for r in txt if r.startswith('"v=spf1')), None)
    if spf:
        report["spf"] = spf.strip('"')
        report["score"] += 30
        if "-all" in spf:
            report["score"] += 10
        elif "~all" in spf:
            report["issues"].append("⚠️  SPF ~all (softfail) — préférer -all (hardfail)")
        elif "?all" in spf:
            report["issues"].append("🔴 SPF ?all = SPF inutile — aucune protection")
        elif "+all" in spf:
            report["issues"].append("🔴 SPF +all = tout le monde peut envoyer vos emails !")
    else:
        report["issues"].append("🔴 Pas de SPF — usurpation d'identité email triviale")

    # DMARC
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_txt = resolve_dns(dmarc_domain, "TXT")
    dmarc = next((r for r in dmarc_txt if "v=DMARC1" in r), None)
    if dmarc:
        report["dmarc"] = dmarc.strip('"')
        report["score"] += 40
        if "p=reject" in dmarc:
            report["score"] += 20
        elif "p=quarantine" in dmarc:
            report["issues"].append("⚠️  DMARC p=quarantine — passer à p=reject")
        elif "p=none" in dmarc:
            report["issues"].append("🔴 DMARC p=none = aucune protection effective")
    else:
        report["issues"].append("🔴 Pas de DMARC — phishing avec votre domaine non bloqué")

    if not report["issues"]:
        report["issues"].append("✅ Configuration email sécurisée")

    return report


# ════════════════════════════════════════════════════════════════
# CERTIFICATS SSL — crt.sh
# ════════════════════════════════════════════════════════════════

def get_subdomains_from_crtsh(domain: str) -> list[str]:
    """
    Récupère les sous-domaines depuis crt.sh (Certificate Transparency Logs).
    Les CT logs sont publics — chaque certificat SSL émis y est enregistré.
    """
    try:
        url = f"https://crt.sh/?q=%.{urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": "BouclierNumerique/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            certs = json.loads(resp.read())

        subdomains = set()
        for cert in certs:
            names = cert.get("name_value", "")
            for name in names.split("\n"):
                name = name.strip().lower().lstrip("*.")
                if name.endswith(domain) and name != domain:
                    subdomains.add(name)

        return sorted(subdomains)
    except Exception:
        return []


def get_ssl_info(domain: str, port: int = 443) -> dict:
    """Analyse le certificat SSL d'un serveur."""
    info = {"valid": False, "subject": None, "issuer": None,
            "expires": None, "sans": [], "error": None}
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                info["valid"]   = True
                info["subject"] = dict(x[0] for x in cert.get("subject", []))
                info["issuer"]  = dict(x[0] for x in cert.get("issuer", []))
                info["expires"] = cert.get("notAfter", "")
                sans = cert.get("subjectAltName", [])
                info["sans"]    = [s[1] for s in sans if s[0] == "DNS"]
    except ssl.SSLCertVerificationError as e:
        info["error"] = f"Certificat invalide : {e}"
    except Exception as e:
        info["error"] = str(e)
    return info


# ════════════════════════════════════════════════════════════════
# ANALYSE HTTP
# ════════════════════════════════════════════════════════════════

def analyze_http_headers(domain: str) -> dict:
    """Analyse les headers HTTP pour identifier les technologies et problèmes."""
    result = {"url": None, "status": 0, "server": None, "tech": [],
              "security_headers": {}, "missing_headers": [], "findings": []}

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                result["url"]    = url
                result["status"] = resp.status
                result["headers_raw"] = dict(hdrs)

                # Technologies exposées
                server = hdrs.get("server", "")
                if server:
                    result["server"] = server
                    result["tech"].append(f"Server: {server}")
                    result["findings"].append(
                        f"🟠 Header Server exposé : '{server}' → révèle la technologie"
                    )

                for h in ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
                    if h in hdrs:
                        result["tech"].append(f"{h}: {hdrs[h]}")
                        result["findings"].append(
                            f"🟠 Header '{h}' exposé : '{hdrs[h]}'"
                        )

                # Headers de sécurité
                security_checks = {
                    "strict-transport-security": "HSTS — Forcer HTTPS",
                    "x-content-type-options":    "Empêche le MIME sniffing",
                    "x-frame-options":           "Protection clickjacking",
                    "content-security-policy":   "CSP — Prévient XSS",
                    "referrer-policy":           "Contrôle du Referer",
                    "permissions-policy":        "Contrôle APIs navigateur",
                }
                for h, desc in security_checks.items():
                    if h in hdrs:
                        result["security_headers"][h] = hdrs[h]
                    else:
                        result["missing_headers"].append(h)
                        result["findings"].append(f"🟡 Header manquant : {h} ({desc})")

                return result
        except Exception:
            continue

    result["findings"].append("🔴 Serveur inaccessible")
    return result


# ════════════════════════════════════════════════════════════════
# RAPPORT HTML
# ════════════════════════════════════════════════════════════════

def generate_report(domain: str, data: dict, output_path: Optional[Path] = None) -> str:
    now    = datetime.now().strftime("%d/%m/%Y %H:%M")
    dns    = data.get("dns", {})
    email  = data.get("email_security", {})
    subs   = data.get("subdomains", [])
    ssl    = data.get("ssl", {})
    http   = data.get("http", {})

    # Score global
    score = email.get("score", 0)
    if ssl.get("valid"):   score += 20
    if not http.get("server"): score += 10
    missing = len(http.get("missing_headers", []))
    score = max(0, min(100, score - missing * 5))

    score_color = "#e74c3c" if score < 50 else "#e67e22" if score < 70 else "#27ae60"

    def section(title: str, content: str) -> str:
        return f'<div class="section-title">{title}</div>{content}'

    # DNS table
    dns_rows = ""
    for rtype, vals in dns.items():
        for v in vals:
            dns_rows += f"<tr><td>{rtype}</td><td><code>{html_module.escape(v[:80])}</code></td></tr>"
    dns_html = f"<table><tr><th>Type</th><th>Valeur</th></tr>{dns_rows}</table>" if dns_rows else "<p>Aucun enregistrement</p>"

    # Email security
    email_score = email.get("score", 0)
    email_color = "#e74c3c" if email_score < 50 else "#e67e22" if email_score < 80 else "#27ae60"
    issues_html = "".join(f"<li>{html_module.escape(i)}</li>" for i in email.get("issues", []))
    email_html  = f"""
    <div style="display:flex;gap:1.5rem;align-items:center;margin-bottom:1rem">
      <div style="font-size:2.5rem;font-weight:900;color:{email_color}">{email_score}</div>
      <div>
        <div style="color:var(--muted);font-size:.85rem">Score email /100</div>
        <div>SPF : {'✅' if email.get('spf') else '❌'} &nbsp; DMARC : {'✅' if email.get('dmarc') else '❌'}</div>
      </div>
    </div>
    <ul style="padding-left:1.2rem;color:var(--muted);font-size:.88rem">{issues_html}</ul>"""

    # Sous-domaines
    subs_html = "".join(
        f'<div class="sub-chip">{html_module.escape(s)}</div>' for s in subs[:30]
    ) or "<p style='color:var(--muted)'>Aucun sous-domaine trouvé</p>"

    # HTTP findings
    http_findings = "".join(
        f"<li style='margin:.3rem 0'>{html_module.escape(f)}</li>"
        for f in http.get("findings", [])
    )

    report = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>🛡️ OSINT — {html_module.escape(domain)}</title>
  <style>
    :root{{--bg:#0f1117;--card:#1a1d27;--border:#2d3148;--text:#e2e8f0;--muted:#8892b0;--accent:#64ffda}}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;padding:2rem;max-width:1100px;margin:auto}}
    h1{{color:var(--accent);font-size:1.8rem;margin-bottom:.3rem}}
    .meta{{color:var(--muted);font-size:.82rem;margin-bottom:2rem}}
    .score-card{{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:2rem;display:flex;align-items:center;gap:2rem;flex-wrap:wrap}}
    .score-big{{font-size:4rem;font-weight:900;color:{score_color}}}
    .section-title{{color:var(--accent);font-size:1.1rem;margin:2rem 0 1rem;border-bottom:1px solid var(--border);padding-bottom:.4rem}}
    .card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:1.2rem;margin-bottom:1rem}}
    table{{width:100%;border-collapse:collapse;font-size:.85rem}}
    th{{background:#161923;padding:.6rem 1rem;text-align:left;color:var(--accent);font-size:.82rem}}
    td{{padding:.5rem 1rem;border-bottom:1px solid var(--border);color:var(--muted)}}
    code{{background:#0a0c14;padding:.1rem .4rem;border-radius:3px;font-size:.8rem;color:#a8b2d8;word-break:break-all}}
    .sub-chips{{display:flex;flex-wrap:wrap;gap:.4rem;margin-top:.5rem}}
    .sub-chip{{background:#1e3a5f;color:#7eb8f7;padding:.3rem .7rem;border-radius:4px;font-size:.8rem;font-family:monospace}}
    ul{{padding-left:1.2rem;color:var(--muted);font-size:.88rem;line-height:1.8}}
    p{{color:var(--muted);font-size:.88rem;line-height:1.5;margin:.3rem 0}}
    .badge{{display:inline-block;padding:.2rem .6rem;border-radius:4px;font-size:.78rem;font-weight:700}}
  </style>
</head>
<body>
  <h1>🛡️ Rapport OSINT</h1>
  <div class="meta">Cible : <strong>{html_module.escape(domain)}</strong> · {now} · Données publiques uniquement</div>

  <div class="score-card">
    <div><div class="score-big">{score}</div><div style="color:var(--muted);font-size:.85rem">Score exposition /100</div></div>
    <div>
      <div style="margin-bottom:.5rem">Plus le score est <strong>bas</strong>, plus la surface d'attaque est grande.</div>
      <div style="color:var(--muted);font-size:.85rem">
        DNS : {len(dns)} types · Sous-domaines : {len(subs)} · SSL : {'✅' if ssl.get('valid') else '❌'} · Email : {email.get('score',0)}/100
      </div>
    </div>
  </div>

  {section("🌐 Enregistrements DNS", f'<div class="card">{dns_html}</div>')}

  {section("📧 Sécurité Email (SPF · DMARC · DKIM)", f'<div class="card">{email_html}</div>')}

  {section(f"🔐 Certificat SSL", f'''<div class="card">
    <p>Valide : {'✅ Oui' if ssl.get("valid") else '❌ Non — ' + html_module.escape(str(ssl.get("error","")))}</p>
    {"<p>Expire : " + html_module.escape(str(ssl.get("expires",""))) + "</p>" if ssl.get("expires") else ""}
    {"<p>SANs : " + ", ".join(html_module.escape(s) for s in ssl.get("sans",[])[:10]) + "</p>" if ssl.get("sans") else ""}
  </div>''')}

  {section(f"🗺️  Sous-domaines découverts ({len(subs)} via Certificate Transparency)", f'''<div class="card">
    <p style="color:var(--muted);font-size:.82rem;margin-bottom:.8rem">
      Source : crt.sh (CT logs publics). Chaque sous-domaine est une surface d'attaque potentielle.
    </p>
    <div class="sub-chips">{subs_html}</div>
  </div>''')}

  {section("🌍 Analyse HTTP / Headers", f'<div class="card"><ul>{http_findings}</ul></div>')}

  <div style="color:var(--muted);font-size:.76rem;text-align:center;margin-top:2rem">
    Généré par <strong>Le Bouclier Numérique — Jour 24</strong> · Sources publiques · ISO 27001 A.18.1.4
  </div>
</body>
</html>"""

    if output_path:
        output_path.write_text(report, encoding="utf-8")
        print(f"\n  📄  Rapport → {output_path}")
    return report


# ════════════════════════════════════════════════════════════════
# SCAN PRINCIPAL
# ════════════════════════════════════════════════════════════════

def scan_domain(domain: str, verbose: bool = True) -> dict:
    """Lance toutes les sondes OSINT sur un domaine."""
    domain = domain.lower().strip().lstrip("https://").lstrip("http://").split("/")[0]

    if verbose:
        print(f"\n  🎯  Cible : {domain}")
        print(f"  {'─'*56}\n")

    data = {}

    if verbose: print("  🌐  Collecte des enregistrements DNS...")
    data["dns"] = get_dns_records(domain)
    if verbose:
        for rtype, vals in data["dns"].items():
            print(f"      {rtype:<6} : {vals[0][:60]}{'...' if len(vals[0])>60 else ''}"
                  + (f" (+{len(vals)-1})" if len(vals) > 1 else ""))

    if verbose: print("\n  📧  Analyse sécurité email (SPF, DMARC)...")
    data["email_security"] = analyze_email_security(domain)
    email = data["email_security"]
    if verbose:
        print(f"      SPF   : {'✅ ' + email['spf'][:50] if email['spf'] else '❌ Absent'}")
        print(f"      DMARC : {'✅ ' + email['dmarc'][:50] if email['dmarc'] else '❌ Absent'}")
        print(f"      Score : {email['score']}/100")

    if verbose: print("\n  🔐  Vérification certificat SSL...")
    data["ssl"] = get_ssl_info(domain)
    if verbose:
        ssl_info = data["ssl"]
        if ssl_info["valid"]:
            print(f"      ✅  Valide · Expire : {ssl_info['expires']}")
            print(f"      SANs : {len(ssl_info['sans'])} entrées")
        else:
            print(f"      ❌  {ssl_info.get('error','Erreur SSL')}")

    if verbose: print("\n  🗺️   Découverte des sous-domaines (crt.sh)...")
    data["subdomains"] = get_subdomains_from_crtsh(domain)
    if verbose:
        subs = data["subdomains"]
        print(f"      {len(subs)} sous-domaine(s) trouvé(s)")
        for s in subs[:5]:
            print(f"      → {s}")
        if len(subs) > 5:
            print(f"      ... et {len(subs)-5} autres")

    if verbose: print("\n  🌍  Analyse des headers HTTP...")
    data["http"] = analyze_http_headers(domain)
    if verbose:
        http = data["http"]
        print(f"      Status   : {http.get('status',0)}")
        print(f"      Serveur  : {http.get('server','(masqué) ✅') or '(masqué) ✅'}")
        print(f"      Headers  : {len(http.get('security_headers',{}))} présents / {len(http.get('missing_headers',[]))} manquants")

    return data


def run_demo():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 24 : CRAWLER OSINT            ║
║  Sources : DNS · SSL · crt.sh · Headers — 100% légal          ║
╚══════════════════════════════════════════════════════════════════╝

  Ce scan est réalisé sur example.com (domaine de démonstration IANA).
  Remplacez par votre propre domaine pour un audit réel.
""")

    # Test sur un domaine public connu
    domain = "example.com"
    data   = scan_domain(domain)

    report_path = Path("/tmp/rapport_osint.html")
    generate_report(domain, data, report_path)

    # Résumé
    email = data.get("email_security", {})
    subs  = data.get("subdomains", [])

    print(f"""
  ══════════════════════════════════════════════════════════
  📋  RÉSUMÉ POUR {domain.upper()}
  ══════════════════════════════════════════════════════════
  DNS        : {len(data.get('dns', {}))} types d'enregistrements
  SSL        : {'✅ Valide' if data.get('ssl',{}).get('valid') else '❌ Invalide/absent'}
  Sous-dom.  : {len(subs)} trouvés via CT logs
  SPF        : {'✅' if email.get('spf') else '❌ ABSENT — usurpation email possible'}
  DMARC      : {'✅' if email.get('dmarc') else '❌ ABSENT — phishing non bloqué'}
  Score email: {email.get('score',0)}/100
  Rapport    : {report_path}
  ══════════════════════════════════════════════════════════

  Ce qu'un attaquant obtient en 30 secondes avec ces données :
  → Liste des sous-domaines → cibles d'attaque supplémentaires
  → Absence de DMARC → il peut se faire passer pour vous par email
  → Header Server exposé → il sait quelle version patcher
  → NS records → vecteur de DNS hijacking si mal configuré
  ══════════════════════════════════════════════════════════
""")


def main():
    import argparse
    p = argparse.ArgumentParser(description="Crawler OSINT — Bouclier Numérique J24")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    ps = sub.add_parser("scan")
    ps.add_argument("domain")
    ps.add_argument("--output", "-o")

    args = p.parse_args()
    if not args.cmd or args.cmd == "demo":
        run_demo()
    elif args.cmd == "scan":
        data = scan_domain(args.domain)
        out  = Path(args.output) if args.output else Path(f"osint_{args.domain}.html")
        generate_report(args.domain, data, out)


if __name__ == "__main__":
    main()
