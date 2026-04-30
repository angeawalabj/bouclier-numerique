#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 28 : SOAR ENGINE               ║
║  Objectif  : Automatiser la réponse aux incidents              ║
║  Modèle    : Playbook → Trigger → Actions → Rapport           ║
║  Intègre   : IDS (J17) · Honeypot (J07) · Rate Limiter (J06) ║
╚══════════════════════════════════════════════════════════════════╝

SOAR = Security Orchestration, Automation and Response
Permet de répondre aux incidents en secondes au lieu de minutes/heures.

Playbooks implémentés :
  PB-001 — Bruteforce SSH/Login    → blocage IP + alerte
  PB-002 — Scan de ports           → isolation + ticket
  PB-003 — Malware détecté (HIDS)  → quarantaine + forensics
  PB-004 — Exfiltration de données → coupure réseau + CNIL timer
  PB-005 — Phishing signalé        → désactivation lien + alerte users

Conformité : NIST SP 800-61 (CSIRT) · ISO 27035 · RGPD Art.33
"""

import json, time, uuid, hashlib, re
from pathlib import Path
from datetime import datetime, timedelta
from typing import Callable
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class SecurityEvent:
    event_id:   str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    type:       str = ""           # brute_force, port_scan, malware, exfil, phishing
    source_ip:  str = ""
    target:     str = ""
    severity:   str = "MODÉRÉE"   # CRITIQUE / ÉLEVÉE / MODÉRÉE / FAIBLE
    raw_data:   dict = field(default_factory=dict)
    ts:         str = field(default_factory=lambda: datetime.now().isoformat())


class SOARAction:
    """Registre des actions automatisées disponibles."""

    def __init__(self):
        self._log = []
        # Simule les systèmes externes (firewall, AD, ticketing...)
        self._blocked_ips:  set   = set()
        self._quarantined:  set   = set()
        self._tickets:      list  = []
        self._notifications: list = []
        self._gdpr_timers:  dict  = {}

    def block_ip(self, ip: str, duration_min: int = 60, reason: str = "") -> dict:
        self._blocked_ips.add(ip)
        result = {"action":"block_ip","ip":ip,"duration_min":duration_min,"reason":reason,"ok":True}
        self._log.append(result)
        print(f"    🚫  IP bloquée : {ip} ({duration_min}min) — {reason}")
        return result

    def quarantine_host(self, host: str, reason: str = "") -> dict:
        self._quarantined.add(host)
        result = {"action":"quarantine","host":host,"reason":reason,"ok":True}
        self._log.append(result)
        print(f"    🔒  Hôte isolé : {host} — {reason}")
        return result

    def create_ticket(self, title: str, severity: str, details: str) -> dict:
        ticket_id = f"INC-{len(self._tickets)+1:04d}"
        ticket = {"id":ticket_id,"title":title,"severity":severity,"details":details,"ts":datetime.now().isoformat()}
        self._tickets.append(ticket)
        result = {"action":"ticket","ticket_id":ticket_id,"ok":True}
        self._log.append(result)
        print(f"    🎫  Ticket créé : {ticket_id} [{severity}] {title}")
        return result

    def send_alert(self, channel: str, message: str, recipients: list = None) -> dict:
        notif = {"channel":channel,"message":message[:120],"recipients":recipients or ["rssi@corp.fr"]}
        self._notifications.append(notif)
        result = {"action":"alert","channel":channel,"ok":True}
        self._log.append(result)
        print(f"    📧  Alerte envoyée [{channel}] : {message[:60]}...")
        return result

    def start_gdpr_timer(self, incident_id: str, violation_type: str) -> dict:
        """Démarre le compteur RGPD Art. 33 — notification CNIL sous 72h."""
        deadline = datetime.now() + timedelta(hours=72)
        self._gdpr_timers[incident_id] = {
            "violation": violation_type,
            "start":     datetime.now().isoformat(),
            "deadline":  deadline.isoformat(),
            "remaining_h": 72,
        }
        result = {"action":"gdpr_timer","incident_id":incident_id,"deadline":deadline.isoformat(),"ok":True}
        self._log.append(result)
        print(f"    ⏱️   Timer RGPD Art.33 démarré : notification CNIL avant {deadline.strftime('%d/%m %H:%M')}")
        return result

    def collect_forensics(self, host: str, artifacts: list) -> dict:
        result = {"action":"forensics","host":host,"artifacts_requested":artifacts,"ok":True}
        self._log.append(result)
        print(f"    🔬  Forensics déclenchée sur {host} : {', '.join(artifacts[:3])}")
        return result

    def disable_account(self, user: str, reason: str = "") -> dict:
        result = {"action":"disable_account","user":user,"reason":reason,"ok":True}
        self._log.append(result)
        print(f"    🚷  Compte désactivé : {user} — {reason}")
        return result


class PlaybookEngine:
    """Exécute les playbooks de réponse aux incidents."""

    def __init__(self):
        self.actions = SOARAction()
        self._playbooks: dict[str, Callable] = {}
        self._register_builtin_playbooks()

    def _register_builtin_playbooks(self):
        self._playbooks["PB-001"] = self._pb_brute_force
        self._playbooks["PB-002"] = self._pb_port_scan
        self._playbooks["PB-003"] = self._pb_malware
        self._playbooks["PB-004"] = self._pb_exfiltration
        self._playbooks["PB-005"] = self._pb_phishing

    def _select_playbook(self, event: SecurityEvent) -> str:
        mapping = {
            "brute_force": "PB-001",
            "port_scan":   "PB-002",
            "malware":     "PB-003",
            "exfiltration":"PB-004",
            "phishing":    "PB-005",
            "data_breach": "PB-004",
        }
        return mapping.get(event.type, None)

    def respond(self, event: SecurityEvent) -> dict:
        pb_id = self._select_playbook(event)
        if not pb_id:
            print(f"  ⚠️  Pas de playbook pour '{event.type}' — escalade manuelle")
            return {"playbook": None, "actions": 0}

        print(f"\n  ▶️   Playbook {pb_id} déclenché pour événement [{event.severity}]")
        print(f"       Type: {event.type} · Source: {event.source_ip} · Cible: {event.target}")
        print(f"  {'─'*54}")

        t0      = time.monotonic()
        result  = self._playbooks[pb_id](event)
        elapsed = time.monotonic() - t0

        result["playbook"]  = pb_id
        result["event_id"]  = event.event_id
        result["elapsed_s"] = round(elapsed, 3)
        result["ts"]        = event.ts

        print(f"  {'─'*54}")
        print(f"  ✅  {pb_id} terminé en {elapsed*1000:.0f}ms · {result['actions_taken']} action(s)\n")
        return result

    # ── PB-001 : Bruteforce ──────────────────────────────────────
    def _pb_brute_force(self, event: SecurityEvent) -> dict:
        attempts = event.raw_data.get("attempts", 0)
        a = self.actions

        a.block_ip(event.source_ip, 120, f"Bruteforce {attempts} tentatives")
        a.create_ticket(f"Bruteforce depuis {event.source_ip}", event.severity,
                        f"{attempts} tentatives sur {event.target}")
        a.send_alert("slack-soc", f"Bruteforce bloqué : {event.source_ip} → {event.target} ({attempts} tentatives)")

        if attempts > 500:
            a.send_alert("email-rssi", f"ALERTE CRITIQUE : bruteforce massif depuis {event.source_ip}")

        return {"actions_taken": 3 if attempts <= 500 else 4, "ip_blocked": True}

    # ── PB-002 : Scan de ports ───────────────────────────────────
    def _pb_port_scan(self, event: SecurityEvent) -> dict:
        ports_scanned = event.raw_data.get("ports_scanned", 0)
        a = self.actions

        a.block_ip(event.source_ip, 30, "Scan de ports suspect")
        a.create_ticket(f"Scan de ports : {event.source_ip}", "MODÉRÉE",
                        f"{ports_scanned} ports scannés sur {event.target}")
        a.send_alert("teams-soc", f"Scan détecté : {event.source_ip} a scanné {ports_scanned} ports")

        return {"actions_taken": 3, "ip_blocked": True}

    # ── PB-003 : Malware (HIDS) ──────────────────────────────────
    def _pb_malware(self, event: SecurityEvent) -> dict:
        host     = event.target
        malware  = event.raw_data.get("malware_name", "Unknown")
        affected = event.raw_data.get("affected_files", [])
        a = self.actions

        a.quarantine_host(host, f"Malware détecté : {malware}")
        a.collect_forensics(host, ["memory_dump", "process_list", "network_connections", "file_hashes"])
        a.create_ticket(f"MALWARE : {malware} sur {host}", "CRITIQUE",
                        f"Fichiers affectés : {', '.join(affected[:5])}")
        a.send_alert("email-rssi", f"CRITIQUE : Malware {malware} sur {host} — hôte isolé")
        a.send_alert("pagerduty", f"Incident P1 : Malware actif sur {host}")

        # Vérifier si données personnelles exposées
        if any("user" in f or "customer" in f or "personal" in f for f in affected):
            a.start_gdpr_timer(event.event_id, f"Malware accès potentiel données personnelles sur {host}")

        return {"actions_taken": 5 if affected else 4, "host_quarantined": True}

    # ── PB-004 : Exfiltration ────────────────────────────────────
    def _pb_exfiltration(self, event: SecurityEvent) -> dict:
        volume_mb = event.raw_data.get("volume_mb", 0)
        dest_ip   = event.raw_data.get("destination_ip", "?")
        data_type = event.raw_data.get("data_type", "inconnu")
        a = self.actions

        a.block_ip(dest_ip, 10080, "Destination exfiltration de données")  # 1 semaine
        a.quarantine_host(event.source_ip, "Source d'exfiltration")
        a.create_ticket(f"EXFILTRATION {volume_mb}MB vers {dest_ip}", "CRITIQUE",
                        f"Type de données : {data_type}")
        a.send_alert("email-rssi", f"EXFILTRATION CRITIQUE : {volume_mb}MB de {data_type} vers {dest_ip}")
        a.start_gdpr_timer(event.event_id, f"Exfiltration potentielle de {data_type} ({volume_mb}MB)")
        a.collect_forensics(event.source_ip, ["network_logs", "file_access_logs", "user_sessions"])

        return {"actions_taken": 6, "gdpr_notified": True}

    # ── PB-005 : Phishing ────────────────────────────────────────
    def _pb_phishing(self, event: SecurityEvent) -> dict:
        url        = event.raw_data.get("phishing_url", "")
        user_hit   = event.raw_data.get("user_clicked", "")
        campaign   = event.raw_data.get("campaign_id", "?")
        a = self.actions

        a.create_ticket(f"Phishing signalé : {url[:50]}", "ÉLEVÉE",
                        f"Campagne {campaign} · utilisateur touché : {user_hit}")
        a.send_alert("email-all-users",
                     f"ALERTE : Ne pas cliquer sur les liens de la campagne '{campaign}'. "
                     f"Si vous avez cliqué, changez votre mot de passe immédiatement.")
        a.send_alert("slack-soc", f"Phishing actif : {url}")

        if user_hit:
            a.disable_account(user_hit, "Précaution post-phishing — réinitialisation requise")
            a.start_gdpr_timer(event.event_id, "Possible compromission de compte utilisateur")

        return {"actions_taken": 4 if user_hit else 3, "url": url}


def run_demo():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 28 : SOAR ENGINE               ║
╚══════════════════════════════════════════════════════════════════╝
""")
    engine = PlaybookEngine()

    events = [
        SecurityEvent(type="brute_force", source_ip="185.220.101.42",
                      target="ssh:22", severity="ÉLEVÉE",
                      raw_data={"attempts": 847, "service": "SSH"}),
        SecurityEvent(type="malware", source_ip="unknown",
                      target="LAPTOP-ALICE", severity="CRITIQUE",
                      raw_data={"malware_name":"Emotet.B",
                                "affected_files":["C:/Users/alice/customers.xlsx",
                                                  "C:/Users/alice/Documents/contracts/"]}),
        SecurityEvent(type="exfiltration", source_ip="10.0.1.45",
                      target="external", severity="CRITIQUE",
                      raw_data={"volume_mb":2400,"destination_ip":"91.234.55.12",
                                "data_type":"Données clients personnelles (RGPD Art.4)"}),
        SecurityEvent(type="phishing", source_ip="external",
                      target="employees", severity="ÉLEVÉE",
                      raw_data={"phishing_url":"http://techcorp-secure-login.xyz/auth",
                                "campaign_id":"CAMP-2026-03",
                                "user_clicked":"bob@techcorp.fr"}),
    ]

    results = []
    for event in events:
        r = engine.respond(event)
        results.append(r)

    # Résumé
    a = engine.actions
    print("  ══════════════════════════════════════════════════════")
    print("  📊  BILAN DE LA SESSION SOAR")
    print("  ══════════════════════════════════════════════════════")
    print(f"  Incidents traités  : {len(events)}")
    print(f"  IPs bloquées       : {len(a._blocked_ips)} — {', '.join(list(a._blocked_ips)[:4])}")
    print(f"  Hôtes isolés       : {len(a._quarantined)} — {', '.join(a._quarantined)}")
    print(f"  Tickets créés      : {len(a._tickets)} — {', '.join(t['id'] for t in a._tickets)}")
    print(f"  Alertes envoyées   : {len(a._notifications)}")
    print(f"  Timers RGPD Art.33 : {len(a._gdpr_timers)}")
    for inc_id, timer in a._gdpr_timers.items():
        print(f"    ⏱️  {inc_id[:8]} — deadline : {timer['deadline'][:16]}")
    total_actions = sum(r.get("actions_taken",0) for r in results)
    total_time    = sum(r.get("elapsed_s",0) for r in results)
    print(f"\n  Actions totales    : {total_actions}")
    print(f"  Temps de réponse   : {total_time*1000:.0f}ms total (vs. 30-60 min manuel)")
    print(f"""
  Conformité :
  ✅ NIST SP 800-61 — Plan de réponse aux incidents
  ✅ ISO 27035      — Gestion des incidents sécurité
  ✅ RGPD Art. 33   — Timer notification CNIL 72h auto
""")

def main():
    import argparse
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    args = p.parse_args()
    if not args.cmd or args.cmd == "demo": run_demo()

if __name__ == "__main__":
    main()
