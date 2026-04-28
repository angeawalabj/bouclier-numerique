#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 24 : CRAWLER OSINT            ║
║  Objectif  : Cartographier l'empreinte publique de votre org. ║
║  Sources   : WHOIS · DNS · Certificats · Headers · GitHub     ║
║  Usage     : Défensif — connaître ce qu'un attaquant voit     ║
╚══════════════════════════════════════════════════════════════════╝

L'OSINT (Open Source INTelligence) est la première phase de tout
pentest ou attaque ciblée. Un attaquant passe 60–80% de son temps
en reconnaissance avant d'envoyer la première requête offensive.

Ce que ce script cartographie (comme un attaquant le ferait) :
  🌐  Infrastructure  — sous-domaines, IPs, ASN, localisation
  📜  Certificats SSL — Certificate Transparency (crt.sh)
  🔍  DNS             — enregistrements A/MX/TXT/CNAME/NS/SOA
  📋  WHOIS           — registrant, dates, nameservers
  🔒  Sécurité TLS    — version, cipher, HSTS, headers
  📂  GitHub          — dépôts publics, langages, contributeurs
  🕵️  Emails          — formats probables, erreurs de config SPF/DMARC
  🌍  Géolocalisation — pays/ville de chaque IP

Défense : savoir ce qui est visible vous permet de :
  1. Retirer les informations sensibles exposées publiquement
  2. Sécuriser les sous-domaines oubliés (shadow IT)
  3. Corriger les emails sans SPF/DMARC (vecteur phishing)
  4. Identifier les services ouverts non intentionnels

Conformité : ISO 27001 A.12.6.1 · ANSSI hygiène mesure 2
"""

import json
import socket
import ssl
import time
import re
import urllib.request
import urllib.error
import urllib.parse
import threading
from pathlib import Path
from datetime import datetime
from typing import Optional
from collections import defaultdict
from html import escape


# ════════════════════════════════════════════════════════════════
# COLLECTEURS OSINT
# ════════════════════════════════════════════════════════════════

class OsintCollector:
    """Collecte d'informations OSINT sur un domaine cible."""

    def __init__(self, domain: str, timeout: float = 5.0, rate_limit: float = 0.3):
        self.domain     = domain.lower().strip().removeprefix("https://").removeprefix("http://").split("/")[0]
        self.timeout    = timeout
        self.rate_limit = rate_limit
        self.data       = {
            "domain":       self.domain,
            "ts":           datetime.now().isoformat(),
            "dns":          {},
            "whois":        {},
            "certificates": [],
            "subdomains":   [],
            "tls":          {},
            "headers":      {},
            "github":       {},
            "emails":       [],
            "exposures":    [],
        }
        self._lock = threading.Lock()

    def _http_get(self, url: str, headers: dict = None,
                  as_json: bool = False) -> Optional[dict | str]:
        """Requête HTTP GET simple."""
        req_headers = {
            "User-Agent": "Mozilla/5.0 (compatible; BouclierNumerique-OSINT/1.0)",
            "Accept": "application/json, text/html, */*",
        }
        if headers:
            req_headers.update(headers)
        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(1_000_000).decode("utf-8", errors="replace")
                if as_json:
                    return json.loads(body)
                return body
        except Exception:
            return None
        finally:
            time.sleep(self.rate_limit)

    # ── DNS ─────────────────────────────────────────────────────

    def collect_dns(self) -> dict:
        """Résolution DNS : A, MX, TXT (SPF/DMARC), NS, CNAME."""
        print("  [DNS]   Résolution DNS...", flush=True)
        results = defaultdict(list)

        record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]

        # Utiliser l'API DNS-over-HTTPS de Cloudflare (pas besoin de dnspython)
        doh_url = "https://cloudflare-dns.com/dns-query"

        for rtype in record_types:
            url = f"{doh_url}?name={self.domain}&type={rtype}"
            data = self._http_get(url,
                                  headers={"Accept": "application/dns-json"},
                                  as_json=True)
            if not data or data.get("Status") != 0:
                continue

            for answer in data.get("Answer", []):
                record_data = answer.get("data", "")
                results[rtype].append(record_data)

        # Analyser SPF et DMARC
        spf_found   = any("v=spf1" in t for t in results.get("TXT", []))
        dmarc_found = False
        dmarc_url   = f"{doh_url}?name=_dmarc.{self.domain}&type=TXT"
        dmarc_data  = self._http_get(dmarc_url,
                                     headers={"Accept": "application/dns-json"},
                                     as_json=True)
        if dmarc_data and dmarc_data.get("Status") == 0:
            for ans in dmarc_data.get("Answer", []):
                if "v=DMARC1" in ans.get("data", ""):
                    dmarc_found = True
                    results["DMARC"].append(ans["data"])

        results["_analysis"] = {
            "spf_configured":   spf_found,
            "dmarc_configured": dmarc_found,
        }

        if not spf_found:
            with self._lock:
                self.data["exposures"].append({
                    "type": "Email spoofing",
                    "severity": "ÉLEVÉE",
                    "detail": f"Pas d'enregistrement SPF sur {self.domain} — phishing facilité",
                    "remediation": "Ajouter : TXT @ \"v=spf1 include:_spf.google.com ~all\"",
                })
        if not dmarc_found:
            with self._lock:
                self.data["exposures"].append({
                    "type": "Email spoofing",
                    "severity": "ÉLEVÉE",
                    "detail": f"Pas d'enregistrement DMARC sur {self.domain}",
                    "remediation": "Ajouter : TXT _dmarc \"v=DMARC1; p=reject; rua=mailto:dmarc@votre-domaine.com\"",
                })

        with self._lock:
            self.data["dns"] = dict(results)
        return dict(results)

    # ── Certificats (Certificate Transparency) ──────────────────

    def collect_certificates(self) -> list:
        """
        Interroge crt.sh pour récupérer tous les certificats SSL émis.
        Certificate Transparency = registre public de TOUS les certificats.
        Révèle les sous-domaines même non répertoriés.
        """
        print("  [CERT]  Certificate Transparency (crt.sh)...", flush=True)
        url  = f"https://crt.sh/?q=%.{self.domain}&output=json"
        data = self._http_get(url, as_json=True)

        if not data or not isinstance(data, list):
            return []

        subdomains = set()
        certs      = []
        seen_ids   = set()

        for entry in data[:200]:  # Limiter à 200 certificats
            cert_id = entry.get("id")
            if cert_id in seen_ids:
                continue
            seen_ids.add(cert_id)

            name_value = entry.get("name_value", "")
            for name in name_value.splitlines():
                name = name.strip().lower()
                if name.endswith(f".{self.domain}") or name == self.domain:
                    if not name.startswith("*"):
                        subdomains.add(name)

            certs.append({
                "id":           cert_id,
                "issuer":       entry.get("issuer_name", "")[:80],
                "not_before":   entry.get("not_before", ""),
                "not_after":    entry.get("not_after", ""),
                "common_name":  entry.get("common_name", ""),
                "names":        name_value[:200],
            })

        with self._lock:
            self.data["certificates"] = certs[:50]
            self.data["subdomains"]   = sorted(subdomains)

        print(f"  [CERT]  {len(certs)} certificat(s) · {len(subdomains)} sous-domaine(s) découvert(s)")
        return certs

    # ── WHOIS ────────────────────────────────────────────────────

    def collect_whois(self) -> dict:
        """Récupère les informations WHOIS via l'API rdap.org."""
        print("  [WHOIS] Informations RDAP...", flush=True)
        url  = f"https://rdap.org/domain/{self.domain}"
        data = self._http_get(url, as_json=True)

        if not data:
            # Fallback : whois.iana.org
            return {"error": "RDAP non disponible"}

        result = {
            "status": data.get("status", []),
            "events": [],
            "nameservers": [],
            "registrar": "",
        }

        for event in data.get("events", []):
            result["events"].append({
                "action": event.get("eventAction", ""),
                "date":   event.get("eventDate", "")[:10],
            })

        for ns in data.get("nameservers", []):
            result["nameservers"].append(ns.get("ldhName", "").lower())

        # Registrar
        for entity in data.get("entities", []):
            roles = entity.get("roles", [])
            if "registrar" in roles:
                vcard = entity.get("vcardArray", [])
                if len(vcard) > 1:
                    for field in vcard[1]:
                        if field[0] == "fn":
                            result["registrar"] = field[3]
                            break

        with self._lock:
            self.data["whois"] = result
        return result

    # ── TLS / Headers de sécurité ────────────────────────────────

    def collect_tls_and_headers(self) -> dict:
        """Analyse TLS et les headers de sécurité HTTP."""
        print("  [TLS]   Analyse TLS et headers...", flush=True)
        result = {}

        # Connexion TLS directe
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert   = ssock.getpeercert()
                    cipher = ssock.cipher()
                    result["tls"] = {
                        "version":      ssock.version(),
                        "cipher_suite": cipher[0] if cipher else "?",
                        "cipher_bits":  cipher[2] if cipher else 0,
                        "subject":      dict(x[0] for x in cert.get("subject", [])),
                        "issuer":       dict(x[0] for x in cert.get("issuer", [])),
                        "not_after":    cert.get("notAfter", ""),
                        "sans":         [x[1] for x in cert.get("subjectAltName", [])],
                    }
                    # Alertes TLS
                    if ssock.version() in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self.data["exposures"].append({
                            "type": "TLS obsolète",
                            "severity": "ÉLEVÉE",
                            "detail": f"Version TLS obsolète : {ssock.version()} (vulnérable POODLE/BEAST)",
                            "remediation": "Désactiver TLS < 1.2. Forcer TLS 1.3.",
                        })
        except Exception as e:
            result["tls"] = {"error": str(e)}

        # Headers HTTP
        try:
            req = urllib.request.Request(
                f"https://{self.domain}",
                headers={"User-Agent": "BouclierNumerique-OSINT/1.0"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                result["headers"] = {k: v for k, v in headers.items()
                                     if k in (
                                         "server", "x-powered-by", "x-frame-options",
                                         "strict-transport-security", "content-security-policy",
                                         "x-content-type-options", "referrer-policy",
                                         "permissions-policy", "x-aspnet-version",
                                     )}
                # Expositions
                for dangerous in ("server", "x-powered-by", "x-aspnet-version"):
                    if dangerous in headers:
                        self.data["exposures"].append({
                            "type": "Information disclosure",
                            "severity": "FAIBLE",
                            "detail": f"Header '{dangerous}: {headers[dangerous]}' révèle la technologie",
                            "remediation": f"Supprimer ou masquer le header {dangerous}.",
                        })
                if "strict-transport-security" not in headers:
                    self.data["exposures"].append({
                        "type": "HTTPS non forcé",
                        "severity": "MODÉRÉE",
                        "detail": "Header Strict-Transport-Security (HSTS) absent",
                        "remediation": "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    })
        except Exception:
            result["headers"] = {}

        with self._lock:
            self.data["tls"]     = result.get("tls", {})
            self.data["headers"] = result.get("headers", {})
        return result

    # ── GitHub (repos publics) ───────────────────────────────────

    def collect_github(self) -> dict:
        """Cherche les dépôts GitHub publics liés à l'organisation."""
        print("  [GH]    Recherche GitHub publique...", flush=True)

        # Dériver le nom d'organisation probable depuis le domaine
        org_name = self.domain.split(".")[0]
        url      = f"https://api.github.com/orgs/{org_name}/repos?per_page=10&sort=updated"
        data     = self._http_get(url, as_json=True)

        result = {"org": org_name, "repos": [], "found": False}

        if data and isinstance(data, list):
            result["found"] = True
            for repo in data[:10]:
                result["repos"].append({
                    "name":        repo.get("name", ""),
                    "description": (repo.get("description") or "")[:100],
                    "language":    repo.get("language", ""),
                    "stars":       repo.get("stargazers_count", 0),
                    "updated":     repo.get("updated_at", "")[:10],
                    "private":     repo.get("private", False),
                    "url":         repo.get("html_url", ""),
                })
            # Chercher des secrets potentiels dans les descriptions
            secret_keywords = ["api", "key", "secret", "token", "password", "credential"]
            for repo in result["repos"]:
                desc_lower = (repo["description"] or "").lower()
                if any(kw in desc_lower for kw in secret_keywords):
                    self.data["exposures"].append({
                        "type": "Secret potentiel GitHub",
                        "severity": "MODÉRÉE",
                        "detail": f"Dépôt '{repo['name']}' : description suspecte",
                        "remediation": "Auditer le dépôt avec git-secrets ou truffleHog.",
                    })

        with self._lock:
            self.data["github"] = result
        return result

    # ── Résolution et géoloc des IPs ────────────────────────────

    def collect_ips(self) -> list:
        """Résout les IPs et collecte les informations de géolocalisation."""
        print("  [IP]    Géolocalisation des IPs...", flush=True)
        ips = []
        for record in self.data["dns"].get("A", []):
            ip = record.strip()
            if not ip or ip in [x["ip"] for x in ips]:
                continue
            # ipapi.co — gratuit, pas de clé requise
            geo = self._http_get(f"https://ipapi.co/{ip}/json/", as_json=True)
            info = {"ip": ip, "country": "?", "city": "?", "org": "?", "asn": "?"}
            if geo and isinstance(geo, dict) and not geo.get("error"):
                info.update({
                    "country": geo.get("country_name", "?"),
                    "city":    geo.get("city", "?"),
                    "org":     geo.get("org", "?"),
                    "asn":     geo.get("asn", "?"),
                })
            ips.append(info)

        with self._lock:
            self.data["ips"] = ips
        return ips

    # ── Collecte complète ────────────────────────────────────────

    def collect_all(self) -> dict:
        """Lance toutes les collectes en parallèle."""
        print(f"\n  🎯  Cible : {self.domain}\n")

        with threading.ThreadPoolExecutor(max_workers=4) as ex:
            futures = {
                ex.submit(self.collect_dns):              "DNS",
                ex.submit(self.collect_certificates):     "Certificats",
                ex.submit(self.collect_whois):            "WHOIS",
                ex.submit(self.collect_tls_and_headers):  "TLS/Headers",
            }
            for fut in futures:
                try:
                    fut.result(timeout=30)
                except Exception as e:
                    print(f"  ⚠️  Erreur {futures[fut]}: {e}")

        # GitHub et IPs après DNS
        self.collect_github()
        if self.data["dns"].get("A"):
            self.collect_ips()

        return self.data


# ════════════════════════════════════════════════════════════════
# RAPPORT HTML
# ════════════════════════════════════════════════════════════════

def generate_report(data: dict, output_path: Optional[Path] = None) -> str:
    domain   = data["domain"]
    subs     = data.get("subdomains", [])
    certs    = data.get("certificates", [])
    dns      = data.get("dns", {})
    whois    = data.get("whois", {})
    tls      = data.get("tls", {})
    hdrs     = data.get("headers", {})
    gh       = data.get("github", {})
    ips      = data.get("ips", [])
    exposures = data.get("exposures", [])

    sev_colors = {"CRITIQUE":"#e74c3c","ÉLEVÉE":"#e67e22","MODÉRÉE":"#f39c12","FAIBLE":"#27ae60"}
    sev_icons  = {"CRITIQUE":"🔴","ÉLEVÉE":"🟠","MODÉRÉE":"🟡","FAIBLE":"🟢"}

    # Score d'exposition
    score_penalty = sum({
        "CRITIQUE": 25, "ÉLEVÉE": 15, "MODÉRÉE": 8, "FAIBLE": 3
    }.get(e["severity"], 0) for e in exposures)
    score = max(0, 100 - score_penalty)
    score_color = "#e74c3c" if score < 50 else "#e67e22" if score < 75 else "#27ae60"

    # HTML des expositions
    exp_html = ""
    for ex in sorted(exposures, key=lambda x: {"CRITIQUE":0,"ÉLEVÉE":1,"MODÉRÉE":2,"FAIBLE":3}.get(x["severity"],9)):
        c = sev_colors.get(ex["severity"],"#666")
        i = sev_icons.get(ex["severity"],"⚪")
        exp_html += f"""<div class="exp" style="border-left:4px solid {c}">
          <div class="exp-head">
            <span class="badge" style="background:{c}">{i} {escape(ex['severity'])}</span>
            <strong>{escape(ex['type'])}</strong>
          </div>
          <p>{escape(ex['detail'])}</p>
          <div class="fix">✅ {escape(ex['remediation'])}</div>
        </div>"""

    # HTML des sous-domaines
    subs_html = "".join(
        f'<span class="tag">{escape(s)}</span>' for s in subs[:50]
    ) or "<em style='color:var(--muted)'>Aucun trouvé</em>"

    # HTML DNS
    dns_rows = ""
    for rtype, records in dns.items():
        if rtype.startswith("_") or not isinstance(records, list):
            continue
        for r in records[:5]:
            dns_rows += f"<tr><td>{escape(rtype)}</td><td><code>{escape(str(r)[:100])}</code></td></tr>"

    # HTML GitHub
    gh_html = ""
    if gh.get("found"):
        for repo in gh.get("repos", []):
            gh_html += f"""<div class="repo">
              <a href="{escape(repo['url'])}" target="_blank">{escape(repo['name'])}</a>
              <span class="lang">{escape(repo.get('language') or '?')}</span>
              <span style="color:var(--muted);font-size:.8rem">⭐ {repo['stars']} · {repo['updated']}</span>
              <div style="color:var(--muted);font-size:.82rem">{escape(repo.get('description') or '')}</div>
            </div>"""

    # HTML IPs
    ips_html = ""
    for ip_info in ips:
        ips_html += f"""<tr>
          <td><code>{escape(ip_info['ip'])}</code></td>
          <td>{escape(ip_info.get('country','?'))}</td>
          <td>{escape(ip_info.get('city','?'))}</td>
          <td>{escape(ip_info.get('org','?'))}</td>
          <td>{escape(ip_info.get('asn','?'))}</td>
        </tr>"""

    # TLS info
    tls_version = tls.get("version","?")
    tls_cipher  = tls.get("cipher_suite","?")
    tls_expiry  = tls.get("not_after","?")
    spf_ok  = "✅" if dns.get("_analysis",{}).get("spf_configured")  else "❌"
    dmarc_ok = "✅" if dns.get("_analysis",{}).get("dmarc_configured") else "❌"
    hsts_ok  = "✅" if "strict-transport-security" in hdrs else "❌"

    now = datetime.now().strftime("%d/%m/%Y %H:%M")
    report = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>🕵️ OSINT — {escape(domain)}</title>
  <style>
    :root{{--bg:#0f1117;--card:#1a1d27;--border:#2d3148;--text:#e2e8f0;--muted:#8892b0;--accent:#64ffda}}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;padding:2rem;max-width:1100px;margin:auto}}
    h1{{color:var(--accent);font-size:1.8rem;margin-bottom:.3rem}}
    .meta-info{{color:var(--muted);font-size:.82rem;margin-bottom:2rem}}
    .score-row{{display:flex;align-items:center;gap:2rem;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.5rem;margin-bottom:1.5rem;flex-wrap:wrap}}
    .score-num{{font-size:3.5rem;font-weight:900;color:{score_color}}}
    .section{{color:var(--accent);font-size:1.05rem;margin:2rem 0 .8rem;border-bottom:1px solid var(--border);padding-bottom:.4rem}}
    .grid-3{{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:.8rem;margin-bottom:1rem}}
    .info-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:.8rem}}
    .info-label{{color:var(--muted);font-size:.75rem;margin-bottom:.3rem}}
    .info-val{{font-size:.95rem;font-weight:600}}
    .tags{{display:flex;flex-wrap:wrap;gap:.4rem}}
    .tag{{background:#1e3a5f;color:#7eb8f7;padding:.2rem .6rem;border-radius:4px;font-size:.78rem;font-family:monospace}}
    .exp{{background:var(--card);border-radius:8px;padding:1rem;margin-bottom:.8rem;border:1px solid var(--border)}}
    .exp-head{{display:flex;align-items:center;gap:.6rem;margin-bottom:.5rem}}
    .badge{{color:#fff;padding:.2rem .5rem;border-radius:4px;font-size:.76rem;font-weight:700}}
    p{{color:var(--muted);font-size:.88rem;line-height:1.5}}
    .fix{{background:rgba(100,255,218,.06);border-radius:4px;padding:.5rem .7rem;margin-top:.5rem;font-size:.84rem}}
    table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;overflow:hidden;border:1px solid var(--border);margin-bottom:1rem}}
    th{{background:#0a0c14;color:var(--accent);padding:.6rem .9rem;text-align:left;font-size:.8rem}}
    td{{padding:.55rem .9rem;border-top:1px solid var(--border);font-size:.83rem;color:var(--muted)}}
    code{{background:#0a0c14;padding:.15rem .4rem;border-radius:3px;font-size:.8rem;word-break:break-all}}
    .repo{{background:var(--card);border:1px solid var(--border);border-radius:6px;padding:.7rem;margin-bottom:.5rem}}
    .repo a{{color:var(--accent);text-decoration:none;font-weight:600}}
    .lang{{background:#1a3a1a;color:#7ef77e;padding:.1rem .4rem;border-radius:3px;font-size:.74rem;margin-left:.5rem}}
    .check-row{{display:flex;gap:2rem;flex-wrap:wrap;margin:.5rem 0}}
    .check-item{{font-size:.88rem}}
  </style>
</head>
<body>
  <h1>🕵️ Rapport OSINT</h1>
  <div class="meta-info">Cible : <strong>{escape(domain)}</strong> · {now} · Usage défensif uniquement</div>

  <div class="score-row">
    <div><div class="score-num">{score}</div><div style="color:var(--muted);font-size:.85rem">Score d'exposition /100</div></div>
    <div>
      <div style="font-size:.9rem;color:var(--muted)">
        {len(exposures)} exposition(s) détectée(s) · {len(subs)} sous-domaine(s) · {len(certs)} certificat(s)
      </div>
      <div class="check-row" style="margin-top:.8rem">
        <span class="check-item">{spf_ok} SPF</span>
        <span class="check-item">{dmarc_ok} DMARC</span>
        <span class="check-item">{hsts_ok} HSTS</span>
        <span class="check-item">🔒 TLS {escape(str(tls_version))}</span>
      </div>
    </div>
  </div>

  <div class="section">🚨 Expositions détectées</div>
  {exp_html or '<p style="color:#27ae60;padding:.5rem">✅ Aucune exposition identifiée</p>'}

  <div class="section">🌐 Infrastructure</div>
  <table>
    <thead><tr><th>IP</th><th>Pays</th><th>Ville</th><th>Organisation</th><th>ASN</th></tr></thead>
    <tbody>{ips_html or '<tr><td colspan="5" style="color:var(--muted)">Aucune IP résolue</td></tr>'}</tbody>
  </table>

  <div class="section">🔍 Enregistrements DNS</div>
  <table>
    <thead><tr><th>Type</th><th>Valeur</th></tr></thead>
    <tbody>{dns_rows or '<tr><td colspan="2" style="color:var(--muted)">Non disponible</td></tr>'}</tbody>
  </table>

  <div class="section">🏷️ Sous-domaines découverts ({len(subs)})</div>
  <div class="tags" style="margin-bottom:1rem">{subs_html}</div>

  <div class="section">🔒 TLS & Headers</div>
  <div class="grid-3">
    <div class="info-card"><div class="info-label">Version TLS</div><div class="info-val">{escape(str(tls_version))}</div></div>
    <div class="info-card"><div class="info-label">Cipher Suite</div><div class="info-val" style="font-size:.8rem">{escape(str(tls_cipher)[:40])}</div></div>
    <div class="info-card"><div class="info-label">Expiration cert.</div><div class="info-val">{escape(str(tls_expiry)[:20])}</div></div>
    {''.join(f'<div class="info-card"><div class="info-label">{escape(k)}</div><div class="info-val" style="font-size:.78rem;word-break:break-all">{escape(str(v)[:60])}</div></div>' for k,v in hdrs.items())}
  </div>

  <div class="section">📂 GitHub public ({len(gh.get('repos',[]))} dépôt(s))</div>
  {gh_html or f'<p style="color:var(--muted)">Organisation GitHub "{escape(gh.get("org","?"))}" non trouvée ou privée</p>'}

  <div class="section">📜 Certificats SSL ({len(certs)})</div>
  <table>
    <thead><tr><th>CN</th><th>Émetteur</th><th>Validité</th></tr></thead>
    <tbody>{''.join(f'<tr><td><code>{escape(c.get("common_name","")[:50])}</code></td><td style="font-size:.78rem">{escape(c.get("issuer","")[:60])}</td><td style="font-size:.78rem">{escape(c.get("not_before","")[:10])} → {escape(c.get("not_after","")[:10])}</td></tr>' for c in certs[:10])}</tbody>
  </table>

  <div style="color:var(--muted);font-size:.76rem;text-align:center;margin-top:2rem">
    Généré par <strong>Le Bouclier Numérique — Jour 24</strong> · OSINT défensif · ISO 27001 A.12.6.1
  </div>
</body>
</html>"""

    if output_path:
        output_path.write_text(report, encoding="utf-8")
        print(f"\n  📄  Rapport → {output_path}")
    return report


# ════════════════════════════════════════════════════════════════
# DÉMONSTRATION
# ════════════════════════════════════════════════════════════════

def run_demo():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 24 : OSINT DÉFENSIF            ║
╚══════════════════════════════════════════════════════════════════╝

  Ce script effectue une reconnaissance OSINT passive sur un
  domaine public en utilisant uniquement des sources légalement
  accessibles (DNS, RDAP, crt.sh, GitHub API, ipapi.co).

  Nous allons scanner wikipedia.org comme cible de démonstration
  — un domaine public de la Wikimedia Foundation.
""")

    collector = OsintCollector("wikipedia.org", timeout=6.0, rate_limit=0.4)
    data      = collector.collect_all()

    # Afficher un résumé
    print(f"""
  ─────────────────────────────────────────────────────────
  📊  RÉSULTATS POUR {data['domain'].upper()}
  ─────────────────────────────────────────────────────────

  🌐  Sous-domaines découverts : {len(data.get('subdomains', []))}
  📜  Certificats SSL          : {len(data.get('certificates', []))}
  🚨  Expositions              : {len(data.get('exposures', []))}
  🔒  Version TLS              : {data.get('tls', {}).get('version', '?')}
  📋  SPF configuré            : {'✅' if data.get('dns', {}).get('_analysis', {}).get('spf_configured') else '❌'}
  📋  DMARC configuré          : {'✅' if data.get('dns', {}).get('_analysis', {}).get('dmarc_configured') else '❌'}
  🔒  HSTS                     : {'✅' if 'strict-transport-security' in data.get('headers', {}) else '❌'}
""")

    if data.get("subdomains"):
        print("  🏷️  Premiers sous-domaines :")
        for s in data["subdomains"][:10]:
            print(f"     • {s}")

    if data.get("exposures"):
        print("\n  🚨  Expositions détectées :")
        for e in data["exposures"]:
            icon = {"CRITIQUE":"🔴","ÉLEVÉE":"🟠","MODÉRÉE":"🟡","FAIBLE":"🟢"}.get(e["severity"],"⚪")
            print(f"     {icon} [{e['severity']}] {e['type']} — {e['detail'][:60]}...")

    report_path = Path("/tmp/rapport_osint.html")
    generate_report(data, report_path)

    print(f"""
  ─────────────────────────────────────────────────────────
  Rapport HTML complet → {report_path}

  Comment utiliser ce rapport défensivement :
  1. Identifier les sous-domaines oubliés (shadow IT)
  2. Corriger SPF/DMARC si absent → stoppe le phishing
  3. Mettre à jour TLS si version obsolète
  4. Supprimer les headers qui révèlent la technologie
  5. Auditer les dépôts GitHub publics pour des secrets
  ─────────────────────────────────────────────────────────
""")


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════

def main():
    import argparse
    p = argparse.ArgumentParser(
        description="Crawler OSINT défensif — Bouclier Numérique Jour 24"
    )
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo", help="Démonstration sur wikipedia.org")

    ps = sub.add_parser("scan", help="Scanner un domaine")
    ps.add_argument("domain",    help="Domaine cible (ex: monentreprise.fr)")
    ps.add_argument("--output",  help="Fichier HTML de rapport")
    ps.add_argument("--json",    help="Export JSON des données brutes")
    ps.add_argument("--timeout", type=float, default=5.0)

    args = p.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    collector = OsintCollector(args.domain, timeout=args.timeout)
    data      = collector.collect_all()

    if args.json:
        Path(args.json).write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        print(f"Données JSON → {args.json}")

    out = Path(args.output or f"osint_{args.domain.replace('.','_')}.html")
    generate_report(data, out)
    print(f"\n✅ Scan terminé · {len(data.get('exposures',[]))} exposition(s) · {len(data.get('subdomains',[]))} sous-domaine(s)")


if __name__ == "__main__":
    main()
