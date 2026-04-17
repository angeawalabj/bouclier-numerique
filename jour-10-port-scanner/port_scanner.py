#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 10 : SCANNER DE PORTS INTERNE    ║
║  Objectif  : Détecter les portes dangereuses ouvertes en réseau  ║
║  Scope     : Réseau local entreprise · Poste local · Services   ║
║  Alertes   : Ports critiques · Services non autorisés · Shadow IT║
╚══════════════════════════════════════════════════════════════════╝

Problème concret : Un employé installe un serveur FTP pour
"partager des fichiers facilement", ouvre le port 21 sur son
poste, et expose sans le savoir tous ses fichiers à quiconque
sur le réseau interne — ou pire, via le firewall d'entreprise.

Ce scanner détecte ces "Shadow IT" silencieux :
  • Ports de base de données exposés (3306 MySQL, 5432 PostgreSQL)
  • Serveurs FTP/Telnet en clair (21, 23) — protocoles non chiffrés
  • Interfaces d'administration exposées (8080, 8443, 9200 Elasticsearch)
  • Services de debug ouverts (4444 Metasploit, 5900 VNC)
  • Partages de fichiers non autorisés (445 SMB, 2049 NFS)

Conformité ISO 27001 — Contrôle A.13.1.1 :
  "Les réseaux doivent être gérés et contrôlés pour protéger
   les informations dans les systèmes et applications."

Conformité RGPD Art. 32 :
  "Des mesures pour garantir la confidentialité, l'intégrité et
   la disponibilité des systèmes de traitement."
"""

import os
import sys
import json
import socket
import threading
import ipaddress
import subprocess
import sqlite3
import time
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ================================================================
# RÉFÉRENTIEL DES PORTS DANGEREUX
# ================================================================

PORTS_CRITIQUES = {
    # Protocoles non chiffrés / obsolètes
    21:   {"service": "FTP",       "risque": "CRITIQUE", "desc": "Transfert fichiers EN CLAIR — sniffable"},
    23:   {"service": "Telnet",    "risque": "CRITIQUE", "desc": "Administration EN CLAIR — mot de passe visible"},
    69:   {"service": "TFTP",      "risque": "CRITIQUE", "desc": "Transfert sans authentification"},
    161:  {"service": "SNMP v1",   "risque": "CRITIQUE", "desc": "Community string 'public' souvent par défaut"},

    # Bases de données exposées
    1433: {"service": "MSSQL",      "risque": "CRITIQUE", "desc": "Base de données SQL Server directement exposée"},
    1521: {"service": "Oracle DB",  "risque": "CRITIQUE", "desc": "Base de données Oracle directement exposée"},
    3306: {"service": "MySQL",      "risque": "CRITIQUE", "desc": "Base de données MySQL directement exposée"},
    5432: {"service": "PostgreSQL", "risque": "CRITIQUE", "desc": "Base de données PostgreSQL directement exposée"},
    6379: {"service": "Redis",      "risque": "CRITIQUE", "desc": "Cache Redis sans auth — vol de données trivial"},
    27017:{"service": "MongoDB",    "risque": "CRITIQUE", "desc": "MongoDB souvent sans auth par défaut"},
    9200: {"service": "Elasticsearch","risque": "CRITIQUE","desc": "Index ES lisibles sans authentification"},
    9300: {"service": "Elasticsearch Cluster","risque": "CRITIQUE","desc": "Cluster ES exposé"},
    2181: {"service": "Zookeeper",  "risque": "ELEVÉ",   "desc": "Coordination distribuée — config exposée"},

    # Administration à distance
    3389: {"service": "RDP",        "risque": "CRITIQUE", "desc": "Bureau à distance Windows — cible brute force"},
    5900: {"service": "VNC",        "risque": "CRITIQUE", "desc": "Bureau distant souvent sans chiffrement"},
    5901: {"service": "VNC-1",      "risque": "CRITIQUE", "desc": "VNC session 1"},
    4444: {"service": "Metasploit", "risque": "CRITIQUE", "desc": "Port par défaut des payloads Metasploit"},
    4445: {"service": "Reverse shell","risque": "CRITIQUE","desc": "Port reverse shell classique"},
    1234: {"service": "Debug",      "risque": "ELEVÉ",   "desc": "Port de debug générique"},

    # Partages de fichiers
    139:  {"service": "NetBIOS",    "risque": "ELEVÉ",   "desc": "Partage Windows — lateral movement"},
    445:  {"service": "SMB",        "risque": "ÉLEVÉ",   "desc": "Partage SMB — EternalBlue, ransomwares"},
    2049: {"service": "NFS",        "risque": "ÉLEVÉ",   "desc": "Partage NFS — montage non autorisé"},
    548:  {"service": "AFP",        "risque": "MODÉRÉ",  "desc": "Partage Apple Filing Protocol"},

    # Interfaces web d'administration
    8080: {"service": "HTTP Alt",   "risque": "MODÉRÉ",  "desc": "Serveur web alternatif — souvent sans TLS"},
    8443: {"service": "HTTPS Alt",  "risque": "MODÉRÉ",  "desc": "Admin web alternatif"},
    8888: {"service": "Jupyter",    "risque": "CRITIQUE", "desc": "Jupyter Notebook — exécution de code arbitraire"},
    9090: {"service": "Cockpit/Prometheus","risque": "MODÉRÉ","desc": "Interface admin système"},
    9443: {"service": "Admin HTTPS","risque": "MODÉRÉ",  "desc": "Interface d'administration"},
    10000:{"service": "Webmin",     "risque": "ÉLEVÉ",   "desc": "Admin système web — historique de vulnérabilités"},

    # Messagerie & protocoles anciens
    25:   {"service": "SMTP",       "risque": "MODÉRÉ",  "desc": "Relay email — risque de spam"},
    110:  {"service": "POP3",       "risque": "MODÉRÉ",  "desc": "Email EN CLAIR"},
    143:  {"service": "IMAP",       "risque": "MODÉRÉ",  "desc": "Email EN CLAIR"},

    # Conteneurs & orchestration
    2375: {"service": "Docker",     "risque": "CRITIQUE", "desc": "API Docker non chiffrée — RCE trivial"},
    2376: {"service": "Docker TLS", "risque": "ÉLEVÉ",   "desc": "API Docker TLS — vérifier les certificats"},
    8500: {"service": "Consul",     "risque": "ÉLEVÉ",   "desc": "Service discovery — secrets exposés"},

    # Divers
    5000: {"service": "Flask/Dev",  "risque": "MODÉRÉ",  "desc": "Serveur de développement Flask/Python"},
    3000: {"service": "Node Dev",   "risque": "MODÉRÉ",  "desc": "Serveur de développement Node.js"},
    4200: {"service": "Angular Dev","risque": "FAIBLE",  "desc": "Dev server Angular"},
}

# Ports autorisés standard (à ne pas alerter)
PORTS_AUTORISES = {
    22,    # SSH chiffré
    80,    # HTTP standard
    443,   # HTTPS standard
    53,    # DNS
    123,   # NTP
    67, 68,# DHCP
}

RISQUE_PRIO = {"CRITIQUE": 0, "ÉLEVÉ": 1, "ELEVÉ": 1, "MODÉRÉ": 2, "FAIBLE": 3}


# ================================================================
# SCANNER DE PORTS
# ================================================================

class PortScanner:
    def __init__(self, timeout: float = 0.5, max_workers: int = 100):
        self.timeout    = timeout
        self.max_workers = max_workers
        self.results    = []

    def scan_port(self, host: str, port: int) -> Optional[dict]:
        """Tente une connexion TCP sur un port. Retourne les infos si ouvert."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as s:
                # Tenter de récupérer la bannière (fingerprinting)
                banner = ""
                try:
                    s.settimeout(0.3)
                    # Envoyer une requête générique
                    s.send(b"\r\n")
                    raw = s.recv(256)
                    banner = raw.decode("utf-8", errors="replace").strip()[:80]
                except Exception:
                    pass

                info = PORTS_CRITIQUES.get(port, {
                    "service": self._guess_service(port),
                    "risque":  "INCONNU",
                    "desc":    "Service non répertorié — vérification manuelle requise",
                })

                return {
                    "host":    host,
                    "port":    port,
                    "state":   "OUVERT",
                    "service": info["service"],
                    "risque":  info["risque"],
                    "desc":    info["desc"],
                    "banner":  banner,
                    "ts":      datetime.now().isoformat(),
                }
        except (ConnectionRefusedError, OSError, TimeoutError):
            return None

    def _guess_service(self, port: int) -> str:
        """Tente une identification basique par numéro de port."""
        try:
            return socket.getservbyport(port, "tcp")
        except Exception:
            return f"unknown-{port}"

    def scan_host(self, host: str, ports: list) -> list:
        """Scanne tous les ports d'un hôte en parallèle."""
        open_ports = []
        with ThreadPoolExecutor(max_workers=self.max_workers) as ex:
            futures = {ex.submit(self.scan_port, host, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
        return sorted(open_ports, key=lambda x: x["port"])

    def scan_network(self, network: str, ports: list,
                     progress_cb=None) -> dict:
        """
        Scanne tous les hôtes d'un réseau /24 (ou /28, etc.).
        Retourne un dict {host: [ports_ouverts]}.
        """
        try:
            net = ipaddress.ip_network(network, strict=False)
        except ValueError as e:
            raise ValueError(f"Réseau invalide : {network}") from e

        all_hosts = list(net.hosts())
        results   = {}
        total     = len(all_hosts)

        # Limiter à /24 max pour éviter les scans trop longs
        if total > 254:
            all_hosts = all_hosts[:254]

        print(f"  🌐  Scan du réseau {network} — {min(total, 254)} hôtes")

        for i, host in enumerate(all_hosts):
            host_str = str(host)
            # Test rapide de présence (ping-like via TCP)
            if self._is_alive(host_str):
                open_ports = self.scan_host(host_str, ports)
                if open_ports:
                    results[host_str] = open_ports
            if progress_cb and i % 10 == 0:
                progress_cb(i, total)

        return results

    def _is_alive(self, host: str) -> bool:
        """Test rapide de présence d'un hôte."""
        try:
            with socket.create_connection((host, 80), timeout=0.2):
                return True
        except Exception:
            pass
        try:
            with socket.create_connection((host, 443), timeout=0.2):
                return True
        except Exception:
            pass
        try:
            with socket.create_connection((host, 22), timeout=0.2):
                return True
        except Exception:
            pass
        return False

    def scan_localhost(self) -> list:
        """
        Audit du poste local : liste les services réellement en écoute
        via /proc/net/tcp (Linux) ou psutil.
        """
        results = []

        if HAS_PSUTIL:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status == "LISTEN":
                    port  = conn.laddr.port
                    laddr = conn.laddr.ip

                    # Récupérer le processus
                    proc_name = "?"
                    proc_pid  = conn.pid or 0
                    try:
                        if conn.pid:
                            p = psutil.Process(conn.pid)
                            proc_name = p.name()
                    except Exception:
                        pass

                    info = PORTS_CRITIQUES.get(port, {
                        "service": self._guess_service(port),
                        "risque":  "FAIBLE",
                        "desc":    "Service local",
                    })

                    results.append({
                        "port":      port,
                        "addr":      laddr,
                        "service":   info["service"],
                        "risque":    info["risque"],
                        "desc":      info["desc"],
                        "pid":       proc_pid,
                        "process":   proc_name,
                        "dangerous": port in PORTS_CRITIQUES,
                    })
        else:
            # Fallback : lecture /proc/net/tcp
            results = self._parse_proc_net()

        return sorted(results, key=lambda x: (
            RISQUE_PRIO.get(x.get("risque","FAIBLE"), 3), x["port"]
        ))

    def _parse_proc_net(self) -> list:
        """Fallback Linux : lit /proc/net/tcp pour les ports en écoute."""
        results = []
        for proto_file in ["/proc/net/tcp", "/proc/net/tcp6"]:
            try:
                with open(proto_file) as f:
                    for line in f.readlines()[1:]:
                        parts = line.split()
                        if len(parts) < 4:
                            continue
                        state = parts[3]
                        if state != "0A":  # 0A = LISTEN
                            continue
                        local = parts[1]
                        port  = int(local.split(":")[1], 16)
                        info  = PORTS_CRITIQUES.get(port, {
                            "service": f"port-{port}",
                            "risque": "FAIBLE", "desc": ""
                        })
                        results.append({
                            "port": port, "addr": "0.0.0.0",
                            "service": info["service"],
                            "risque": info["risque"],
                            "desc": info["desc"],
                            "pid": 0, "process": "?",
                            "dangerous": port in PORTS_CRITIQUES,
                        })
            except FileNotFoundError:
                pass
        return results


# ================================================================
# ANALYSEUR DE RISQUES + RAPPORT
# ================================================================

def analyser_resultats(scan_results: list) -> dict:
    """Génère un rapport de risque à partir des ports ouverts locaux."""
    critique = [r for r in scan_results if r.get("risque") == "CRITIQUE"]
    eleve    = [r for r in scan_results if r.get("risque") in ("ÉLEVÉ", "ELEVÉ")]
    modere   = [r for r in scan_results if r.get("risque") == "MODÉRÉ"]
    faible   = [r for r in scan_results if r.get("risque") == "FAIBLE"]

    score_risque = (
        len(critique) * 10 +
        len(eleve)    *  5 +
        len(modere)   *  2 +
        len(faible)   *  1
    )

    if score_risque == 0:
        niveau = "✅ SÛRE"
    elif score_risque <= 5:
        niveau = "🟡 ACCEPTABLE"
    elif score_risque <= 15:
        niveau = "🟠 RISQUÉ"
    else:
        niveau = "🔴 CRITIQUE"

    return {
        "score":       score_risque,
        "niveau":      niveau,
        "critique":    critique,
        "eleve":       eleve,
        "modere":      modere,
        "faible":      faible,
        "total_ports": len(scan_results),
        "dangereux":   len(critique) + len(eleve),
    }


def generer_recommandations(port_info: dict) -> list:
    """Recommandations d'action par port dangereux."""
    recs = []
    risque = port_info.get("risque", "FAIBLE")
    port   = port_info.get("port", 0)
    svc    = port_info.get("service", "")

    if port == 21:
        recs.append("Remplacer FTP par SFTP (port 22) ou FTPS — FTP transmet les mots de passe en clair")
    elif port == 23:
        recs.append("Désactiver Telnet immédiatement — utiliser SSH (port 22) avec authentification par clé")
    elif port in (3306, 5432, 1433, 27017, 6379):
        recs.append(f"Restreindre {svc} à localhost (127.0.0.1) uniquement — utiliser un tunnel SSH pour l'accès distant")
        recs.append("Activer l'authentification si ce n'est pas le cas")
    elif port in (5900, 5901):
        recs.append("Remplacer VNC par SSH avec tunnel X11 ou RDP avec NLA")
        recs.append("Si VNC nécessaire : activer le chiffrement et protéger par un mot de passe fort")
    elif port == 3389:
        recs.append("Désactiver RDP si non nécessaire — sinon : activer NLA, restreindre aux IPs autorisées")
        recs.append("Activer le Rate Limiting (voir Jour 6) pour bloquer le brute-force")
    elif port == 445:
        recs.append("Désactiver SMBv1 immédiatement (vulnérable à EternalBlue/WannaCry)")
        recs.append("Restreindre SMB aux seuls partages nécessaires avec authentification forte")
    elif port == 8888:
        recs.append("Jupyter Notebook ne doit JAMAIS être exposé — arrêter le service ou le restreindre à localhost")
    elif port in (2375,):
        recs.append("Fermer l'API Docker non chiffrée — utiliser le socket Unix (/var/run/docker.sock)")
    elif port in (8080, 5000, 3000):
        recs.append(f"Serveur de développement ({svc}) : ne pas exposer en production")
        recs.append("Utiliser un reverse proxy (Nginx) avec HTTPS pour les services web")
    else:
        if risque == "CRITIQUE":
            recs.append(f"Fermer le port {port} immédiatement ou restreindre à localhost")
        elif risque in ("ÉLEVÉ", "ELEVÉ"):
            recs.append(f"Restreindre le port {port} aux IPs autorisées via firewall (iptables/ufw)")

    return recs


# ================================================================
# SIMULATION DE DÉMONSTRATION
# ================================================================

def run_demo():
    SEP = "=" * 62

    print(f"\n{SEP}")
    print("  DEMO — Scanner de Ports Interne (réseau entreprise)")
    print(f"{SEP}\n")

    print(
        "  Scénario : Un audit de sécurité du réseau interne\n"
        "  d'une PME. 4 postes de travail + serveur. L'objectif\n"
        "  est de trouver les 'portes ouvertes' laissées par des\n"
        "  employés sans malveillance mais sans formation sécu.\n"
    )

    # ── Étape 1 : Scan du localhost ──
    print(f"  {'─'*60}")
    print(f"  🔍  ÉTAPE 1 : AUDIT DU POSTE LOCAL")
    print(f"  {'─'*60}\n")

    scanner   = PortScanner(timeout=0.3)
    local_res = scanner.scan_localhost()

    if local_res:
        print(f"  Ports en écoute sur ce poste ({len(local_res)} détectés) :\n")
        print(f"  {'Port':<8} {'Service':<22} {'Risque':<12} {'Processus':<20} Description")
        print(f"  {'─'*8} {'─'*22} {'─'*12} {'─'*20} {'─'*30}")
        for r in local_res:
            icon = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "ELEVÉ": "🟠",
                    "MODÉRÉ": "🟡", "FAIBLE": "🔵"}.get(r["risque"], "⚪")
            print(f"  {r['port']:<8} {r['service']:<22} "
                  f"{icon} {r['risque']:<10} "
                  f"{r['process']:<20} {r['desc'][:40]}")
    else:
        print("  Aucun port dangereux détecté sur ce poste. ✅")

    # ── Étape 2 : Scan de ports ciblé (simulation réaliste) ──
    print(f"\n  {'─'*60}")
    print(f"  🎭  ÉTAPE 2 : SIMULATION RÉSEAU ENTREPRISE")
    print(f"  {'─'*60}\n")

    # Simulation de 4 postes avec des ports "problématiques"
    simulated_network = {
        "10.0.1.12": [
            {"port": 3306, **PORTS_CRITIQUES[3306],
             "banner": "5.7.39-log MySQL Community Server",
             "host": "10.0.1.12", "state": "OUVERT", "ts": "2026-02-27T09:00:01"},
            {"port": 21,   **PORTS_CRITIQUES[21],
             "banner": "220 FileZilla Server 1.7.0",
             "host": "10.0.1.12", "state": "OUVERT", "ts": "2026-02-27T09:00:02"},
        ],
        "10.0.1.24": [
            {"port": 5900, **PORTS_CRITIQUES[5900],
             "banner": "RFB 003.008",
             "host": "10.0.1.24", "state": "OUVERT", "ts": "2026-02-27T09:00:05"},
            {"port": 8080, **PORTS_CRITIQUES[8080],
             "banner": "HTTP/1.1 200 OK Server: Jetty/9.4",
             "host": "10.0.1.24", "state": "OUVERT", "ts": "2026-02-27T09:00:06"},
        ],
        "10.0.1.31": [
            {"port": 445,  **PORTS_CRITIQUES[445],
             "banner": "",
             "host": "10.0.1.31", "state": "OUVERT", "ts": "2026-02-27T09:00:10"},
            {"port": 23,   **PORTS_CRITIQUES[23],
             "banner": "Linux telnetd",
             "host": "10.0.1.31", "state": "OUVERT", "ts": "2026-02-27T09:00:11"},
        ],
        "10.0.1.45": [
            {"port": 8888, **PORTS_CRITIQUES[8888],
             "banner": "HTTP/1.1 200 OK\nServer: tornado/6.3",
             "host": "10.0.1.45", "state": "OUVERT", "ts": "2026-02-27T09:00:15"},
            {"port": 6379, **PORTS_CRITIQUES[6379],
             "banner": "-NOAUTH Authentication required",
             "host": "10.0.1.45", "state": "OUVERT", "ts": "2026-02-27T09:00:16"},
        ],
    }

    descriptions = {
        "10.0.1.12": "Poste de Alice (comptabilité) — MySQL + FileZilla installés",
        "10.0.1.24": "Poste de Bob (dev) — VNC actif pour télétravail + Tomcat",
        "10.0.1.31": "NAS du bureau — SMB + Telnet pour la config",
        "10.0.1.45": "Poste de Charlie (data) — Jupyter Notebook + Redis local",
    }

    total_ports = sum(len(v) for v in simulated_network.values())
    print(f"  Réseau scanné : 10.0.1.0/24 | 4 hôtes actifs | {total_ports} ports dangereux trouvés\n")

    all_findings = []
    for host, ports in simulated_network.items():
        desc = descriptions.get(host, "Hôte inconnu")
        print(f"  📍  {host}  —  {desc}")

        for p in sorted(ports, key=lambda x: RISQUE_PRIO.get(x["risque"], 3)):
            icon = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "ELEVÉ": "🟠",
                    "MODÉRÉ": "🟡", "FAIBLE": "🔵"}.get(p["risque"], "⚪")
            banner_str = f"  [{p['banner'][:35]}]" if p.get("banner") else ""
            print(f"      {icon} Port {p['port']:<6} {p['service']:<22} {p['risque']}")
            print(f"         └─ {p['desc']}{banner_str}")
            all_findings.append(p)

        print()

    # ── Étape 3 : Analyse de risque ──
    print(f"  {'─'*60}")
    print(f"  📊  ÉTAPE 3 : ANALYSE DE RISQUE")
    print(f"  {'─'*60}\n")

    critique_found = [p for p in all_findings if p["risque"] == "CRITIQUE"]
    eleve_found    = [p for p in all_findings if p["risque"] in ("ÉLEVÉ", "ELEVÉ")]
    modere_found   = [p for p in all_findings if p["risque"] == "MODÉRÉ"]

    print(f"  🔴 CRITIQUE  : {len(critique_found)} ports  {[str(p['port']) for p in critique_found]}")
    print(f"  🟠 ÉLEVÉ     : {len(eleve_found)} ports  {[str(p['port']) for p in eleve_found]}")
    print(f"  🟡 MODÉRÉ    : {len(modere_found)} ports  {[str(p['port']) for p in modere_found]}")

    score = len(critique_found) * 10 + len(eleve_found) * 5 + len(modere_found) * 2
    bar   = "█" * min(score, 30) + "░" * max(0, 30 - score)
    print(f"\n  Score de risque : [{bar}] {score} — 🔴 CRITIQUE")

    # ── Étape 4 : Recommandations par port ──
    print(f"\n  {'─'*60}")
    print(f"  🎯  ÉTAPE 4 : PLAN DE REMÉDIATION PRIORISÉ")
    print(f"  {'─'*60}\n")

    prio = 1
    for port_info in sorted(all_findings,
                             key=lambda x: RISQUE_PRIO.get(x["risque"], 3)):
        if port_info["risque"] not in ("CRITIQUE", "ÉLEVÉ", "ELEVÉ"):
            continue
        recs = generer_recommandations(port_info)
        if not recs:
            continue
        icon = "🔴" if port_info["risque"] == "CRITIQUE" else "🟠"
        print(f"  {prio}. {icon} Port {port_info['port']} — {port_info['service']} "
              f"({port_info['host']})")
        for rec in recs:
            print(f"     → {rec}")
        print()
        prio += 1

    # ── Bilan ──
    print(f"\n{SEP}")
    print(f"  📋  BILAN SÉCURITÉ RÉSEAU INTERNE")
    print(f"{SEP}\n")
    print(
        "  Risques identifiés :\n"
        "  🔴  FTP port 21 (Alice) : mots de passe en clair sniffables\n"
        "      depuis n'importe quel poste du réseau local\n"
        "  🔴  MySQL port 3306 (Alice) : accès DB sans whitelist IP\n"
        "      → n'importe qui sur le réseau peut tenter une connexion\n"
        "  🔴  Jupyter port 8888 (Charlie) : exécution de code Python\n"
        "      arbitraire depuis le navigateur — sans authentification\n"
        "  🔴  Redis port 6379 (Charlie) : lecture/écriture de cache\n"
        "      sans auth — vol de sessions utilisateurs possible\n"
        "  🔴  Telnet port 23 (NAS) : admin du NAS en clair\n"
        "      → credentials admin lisibles par Wireshark\n"
        "\n"
        "  Ces failles existent sans malveillance : ce sont des\n"
        "  outils de dev/productivité mal configurés.\n"
        "\n"
        "  ISO 27001 A.13.1.1 — Gestion des réseaux :\n"
        "  ✅  Audit trimestriel des ports recommandé\n"
        "  ✅  Politique : tout port non déclaré = fermé\n"
        "  ✅  Segmentation réseau (VLAN dev / prod / admin)\n"
        "\n"
        "  Usage :\n"
        "  python3 port_scanner.py local             # Audit du poste local\n"
        "  python3 port_scanner.py scan 192.168.1.0/24  # Scan réseau\n"
        "  python3 port_scanner.py demo              # Simulation\n"
    )


# ================================================================
# CLI
# ================================================================

def main():
    print(__doc__)
    import argparse
    parser = argparse.ArgumentParser()
    sub    = parser.add_subparsers(dest="cmd")
    sub.add_parser("demo")

    p_local = sub.add_parser("local", help="Audit du poste local")

    p_scan = sub.add_parser("scan", help="Scanner un réseau")
    p_scan.add_argument("target", help="IP ou réseau CIDR (ex: 192.168.1.0/24)")
    p_scan.add_argument("--ports", default="critiques",
                        help="critiques|tous|custom:21,22,80")

    args = parser.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
        return

    scanner = PortScanner()

    if args.cmd == "local":
        print("\n  🔍  Audit du poste local...\n")
        results = scanner.scan_localhost()
        if not results:
            print("  ✅  Aucun port dangereux détecté.")
            return
        for r in results:
            icon = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "MODÉRÉ": "🟡",
                    "FAIBLE": "🔵"}.get(r["risque"], "⚪")
            print(f"  {icon} Port {r['port']:<6} {r['service']:<20} "
                  f"[{r['process']}] {r['desc'][:50]}")
            for rec in generer_recommandations(r):
                print(f"       → {rec}")

    elif args.cmd == "scan":
        if args.ports == "critiques":
            ports = list(PORTS_CRITIQUES.keys())
        elif args.ports == "tous":
            ports = list(range(1, 1025)) + list(PORTS_CRITIQUES.keys())
        else:
            ports = [int(p) for p in args.ports.replace("custom:", "").split(",")]

        try:
            results = scanner.scan_network(args.target, ports)
        except ValueError as e:
            # Essayer comme IP unique
            results = {args.target: scanner.scan_host(args.target, ports)}

        total = sum(len(v) for v in results.values())
        print(f"\n  Résultats : {len(results)} hôtes · {total} ports ouverts\n")
        for host, ports_list in results.items():
            print(f"  📍  {host}")
            for p in ports_list:
                icon = {"CRITIQUE": "🔴", "ÉLEVÉ": "🟠", "MODÉRÉ": "🟡"}.get(
                    p.get("risque", ""), "⚪")
                print(f"     {icon} {p['port']:<6} {p['service']}")


if __name__ == "__main__":
    main()
