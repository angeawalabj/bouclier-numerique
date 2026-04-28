#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 28 : SOAR                      ║
║  Objectif  : Automatiser la réponse aux incidents de sécurité  ║
║  Modèle    : Playbook engine · Actions · Enrichissement        ║
║  SOAR      : Security Orchestration, Automation & Response     ║
╚══════════════════════════════════════════════════════════════════╝

Problème : Un SOC reçoit en moyenne 11 000 alertes/jour.
Sans automatisation, les analystes passent 45% du temps
sur des faux positifs et des tâches répétitives.

Le SOAR automatise la réponse selon des playbooks :

  Alerte détectée → Playbook sélectionné → Actions exécutées
        ↓                                         ↓
  brute_force             bloquer_ip + notifier + créer_ticket
  phishing                quarantaine + reset_mdp + notifier
  malware                 isoler_machine + snapshot + escalader
  data_exfil              couper_connexion + notifier_dpo_rgpd
  credential_stuffing     bloquer_ip + invalider_sessions + mfa_force

Chaque playbook :
  - Enrichit l'alerte (géoloc IP, réputation, contexte)
  - Exécute des actions automatiques (DENY, block, quarantine)
  - Génère des preuves pour l'investigation
  - Notifie les bonnes personnes
  - Met à jour le ticket ITSM
  - Documente pour la conformité RGPD (Art. 33 : 72h)

Conformité : ISO 27001 A.16 · RGPD Art. 33/34 · NIS2 Art. 23
"""

import json
import time
import uuid
import re
import hashlib
import threading
import sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, Callable
from collections import defaultdict
from html import escape


# ════════════════════════════════════════════════════════════════
# MODÈLES DE DONNÉES
# ════════════════════════════════════════════════════════════════

SEVERITY_LEVELS = {"CRITIQUE": 4, "ÉLEVÉE": 3, "MODÉRÉE": 2, "FAIBLE": 1, "INFO": 0}

class Alert:
    """Représente une alerte de sécurité entrante."""

    def __init__(self, alert_type: str, severity: str, source_ip: str = "",
                 description: str = "", raw_data: dict = None):
        self.id          = str(uuid.uuid4())[:8].upper()
        self.type        = alert_type
        self.severity    = severity
        self.source_ip   = source_ip
        self.description = description
        self.raw_data    = raw_data or {}
        self.ts          = datetime.now()
        self.enrichment  = {}
        self.actions     = []
        self.status      = "NEW"          # NEW → IN_PROGRESS → RESOLVED / ESCALATED
        self.playbook    = None
        self.ticket_id   = None
        self.rgpd_notif  = False
        self.duration_s  = 0.0

    def to_dict(self) -> dict:
        return {
            "id": self.id, "type": self.type, "severity": self.severity,
            "source_ip": self.source_ip, "description": self.description,
            "ts": self.ts.isoformat(), "status": self.status,
            "playbook": self.playbook, "ticket_id": self.ticket_id,
            "enrichment": self.enrichment, "actions": self.actions,
            "rgpd_notif": self.rgpd_notif, "duration_s": round(self.duration_s, 3),
        }


class Action:
    """Une action exécutée dans le cadre d'un playbook."""

    def __init__(self, name: str, target: str, result: str,
                 success: bool = True, duration_ms: float = 0):
        self.name        = name
        self.target      = target
        self.result      = result
        self.success     = success
        self.duration_ms = duration_ms
        self.ts          = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "name": self.name, "target": self.target,
            "result": self.result, "success": self.success,
            "duration_ms": round(self.duration_ms, 1), "ts": self.ts,
        }


# ════════════════════════════════════════════════════════════════
# ACTIONS SOAR (simulées mais réalistes)
# ════════════════════════════════════════════════════════════════

class SoarActions:
    """
    Catalogue d'actions disponibles dans les playbooks.
    En production, chaque action ferait un appel API réel
    (firewall, AD, ITSM, SIEM...).
    """

    def __init__(self):
        self._blocked_ips   = set()
        self._quarantined   = set()
        self._locked_users  = set()
        self._tickets       = {}
        self._notifications = []
        self._lock          = threading.Lock()

    # ── Réseau ──────────────────────────────────────────────────

    def block_ip(self, ip: str, reason: str = "", duration_h: int = 24) -> Action:
        t0 = time.monotonic()
        with self._lock:
            self._blocked_ips.add(ip)
        elapsed = (time.monotonic() - t0) * 1000
        return Action(
            name="BLOCK_IP",
            target=ip,
            result=f"IP {ip} bloquée pendant {duration_h}h — Raison: {reason}",
            duration_ms=elapsed + 12,  # simule latence API firewall
        )

    def unblock_ip(self, ip: str) -> Action:
        with self._lock:
            self._blocked_ips.discard(ip)
        return Action("UNBLOCK_IP", ip, f"IP {ip} débloquée")

    def rate_limit_ip(self, ip: str, max_rps: int = 5) -> Action:
        return Action(
            "RATE_LIMIT", ip,
            f"Rate limit {max_rps} req/s appliqué sur {ip}",
            duration_ms=8,
        )

    # ── Identités ────────────────────────────────────────────────

    def lock_user(self, username: str, reason: str = "") -> Action:
        with self._lock:
            self._locked_users.add(username)
        return Action(
            "LOCK_USER", username,
            f"Compte {username} verrouillé — {reason}",
            duration_ms=15,
        )

    def reset_password(self, username: str) -> Action:
        temp_pwd = hashlib.sha256(
            f"{username}{datetime.now().timestamp()}".encode()
        ).hexdigest()[:12]
        return Action(
            "RESET_PASSWORD", username,
            f"Mot de passe réinitialisé pour {username} — lien envoyé par email",
            duration_ms=23,
        )

    def revoke_sessions(self, username: str) -> Action:
        return Action(
            "REVOKE_SESSIONS", username,
            f"Toutes les sessions actives de {username} révoquées (JWT blacklist)",
            duration_ms=18,
        )

    def force_mfa(self, username: str) -> Action:
        return Action(
            "FORCE_MFA", username,
            f"MFA forcé sur le prochain login de {username}",
            duration_ms=10,
        )

    # ── Endpoints ────────────────────────────────────────────────

    def quarantine_host(self, hostname: str) -> Action:
        with self._lock:
            self._quarantined.add(hostname)
        return Action(
            "QUARANTINE_HOST", hostname,
            f"Machine {hostname} isolée du réseau (VLAN quarantaine)",
            duration_ms=45,
        )

    def snapshot_host(self, hostname: str) -> Action:
        snap_id = f"SNAP-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
        return Action(
            "SNAPSHOT_HOST", hostname,
            f"Snapshot forensique créé : {snap_id} (disque + mémoire)",
            duration_ms=2800,
        )

    def kill_process(self, hostname: str, pid: int) -> Action:
        return Action(
            "KILL_PROCESS", f"{hostname}:PID={pid}",
            f"Processus {pid} terminé sur {hostname}",
            duration_ms=12,
        )

    # ── Communication & ITSM ─────────────────────────────────────

    def create_ticket(self, title: str, severity: str, body: str) -> Action:
        ticket_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{len(self._tickets)+1:04d}"
        with self._lock:
            self._tickets[ticket_id] = {
                "title": title, "severity": severity,
                "body": body, "ts": datetime.now().isoformat(),
                "status": "OPEN",
            }
        return Action(
            "CREATE_TICKET", ticket_id,
            f"Ticket créé : {ticket_id} [{severity}] {title}",
            duration_ms=35,
        )

    def notify_soc(self, message: str, severity: str = "ÉLEVÉE") -> Action:
        with self._lock:
            self._notifications.append({
                "channel": "SOC", "message": message,
                "severity": severity, "ts": datetime.now().isoformat(),
            })
        icon = {"CRITIQUE": "🚨", "ÉLEVÉE": "⚠️", "MODÉRÉE": "ℹ️"}.get(severity, "📢")
        return Action(
            "NOTIFY_SOC", "Slack #soc-alerts",
            f"{icon} [{severity}] {message}",
            duration_ms=5,
        )

    def notify_dpo(self, incident_id: str, data_categories: list, n_affected: int) -> Action:
        """Notification DPO — RGPD Art. 33 : obligation 72h après découverte."""
        deadline = (datetime.now() + timedelta(hours=72)).strftime("%d/%m/%Y %H:%M")
        with self._lock:
            self._notifications.append({
                "channel": "DPO", "incident_id": incident_id,
                "deadline_cnil": deadline, "ts": datetime.now().isoformat(),
            })
        return Action(
            "NOTIFY_DPO", "dpo@entreprise.fr",
            (f"DPO notifié — Incident {incident_id} · "
             f"Catégories : {', '.join(data_categories)} · "
             f"{n_affected} personnes concernées · "
             f"Deadline CNIL : {deadline}"),
            duration_ms=8,
        )

    def notify_cnil(self, incident_id: str) -> Action:
        """Notification CNIL — RGPD Art. 33 : 72h après découverte."""
        return Action(
            "NOTIFY_CNIL", "notifications.cnil.fr",
            f"Notification CNIL soumise pour incident {incident_id} (Art. 33 RGPD)",
            duration_ms=120,
        )

    # ── Enrichissement ───────────────────────────────────────────

    def enrich_ip(self, ip: str) -> dict:
        """
        Enrichissement IP : réputation, géoloc, ASN.
        En production : appel VirusTotal, AbuseIPDB, ipapi...
        Ici : simulation basée sur les plages d'IP.
        """
        time.sleep(0.05)  # simule latence API
        # Simulation de réputation basée sur l'IP
        parts = ip.split(".")
        if len(parts) != 4:
            return {}

        # IPs "suspectes" dans la démo
        suspicious_ranges = {"185", "45", "194", "91"}
        first_octet = parts[0]

        base = {
            "ip": ip, "country": "Unknown", "city": "Unknown",
            "asn": "AS12345", "org": "Unknown ISP",
            "reputation_score": 0,   # 0–100, 100 = malveillant
            "abuse_reports": 0,
            "is_tor": False, "is_vpn": False, "is_proxy": False,
        }

        if first_octet in suspicious_ranges:
            base.update({
                "country": "RU", "city": "Moscow",
                "asn": "AS60781", "org": "LeaseWeb Netherlands B.V.",
                "reputation_score": 85,
                "abuse_reports": 47,
                "is_vpn": True,
            })
        elif ip.startswith("192.168") or ip.startswith("10.") or ip.startswith("172."):
            base.update({
                "country": "Internal", "city": "LAN",
                "asn": "Internal", "org": "Réseau interne",
                "reputation_score": 0,
            })
        else:
            base.update({
                "country": "FR", "city": "Paris",
                "asn": "AS12322", "org": "Free SAS",
                "reputation_score": 10,
                "abuse_reports": 0,
            })

        return base


# ════════════════════════════════════════════════════════════════
# PLAYBOOKS
# ════════════════════════════════════════════════════════════════

class PlaybookEngine:
    """
    Moteur d'exécution des playbooks SOAR.
    Chaque playbook est une séquence d'étapes conditionnelles.
    """

    def __init__(self, actions: SoarActions):
        self.actions  = actions
        self.playbooks = self._register_playbooks()

    def _register_playbooks(self) -> dict:
        return {
            "brute_force":          self._pb_brute_force,
            "phishing":             self._pb_phishing,
            "malware":              self._pb_malware,
            "data_exfiltration":    self._pb_data_exfil,
            "credential_stuffing":  self._pb_credential_stuffing,
            "sql_injection":        self._pb_sqli,
            "dos_attack":           self._pb_dos,
        }

    def select_playbook(self, alert: Alert) -> Optional[str]:
        """Sélectionne automatiquement le bon playbook selon le type d'alerte."""
        mapping = {
            "brute_force":       "brute_force",
            "bruteforce":        "brute_force",
            "login_failure":     "brute_force",
            "phishing":          "phishing",
            "phishing_click":    "phishing",
            "malware":           "malware",
            "ransomware":        "malware",
            "data_exfiltration": "data_exfiltration",
            "data_leak":         "data_exfiltration",
            "credential_stuffing":"credential_stuffing",
            "account_takeover":  "credential_stuffing",
            "sql_injection":     "sql_injection",
            "sqli":              "sql_injection",
            "dos":               "dos_attack",
            "ddos":              "dos_attack",
        }
        return mapping.get(alert.type.lower())

    def execute(self, alert: Alert) -> Alert:
        """Exécute le playbook approprié sur l'alerte."""
        t0 = time.monotonic()
        alert.status   = "IN_PROGRESS"
        alert.playbook = self.select_playbook(alert)

        if not alert.playbook or alert.playbook not in self.playbooks:
            alert.status = "ESCALATED"
            a = self.actions.notify_soc(
                f"Alerte {alert.id} — type inconnu '{alert.type}' — escalade manuelle",
                severity="MODÉRÉE",
            )
            alert.actions.append(a.to_dict())
            alert.duration_s = time.monotonic() - t0
            return alert

        # Enrichissement IP systématique
        if alert.source_ip:
            alert.enrichment["ip_intel"] = self.actions.enrich_ip(alert.source_ip)

        # Exécution du playbook
        self.playbooks[alert.playbook](alert)

        alert.status     = "RESOLVED"
        alert.duration_s = time.monotonic() - t0
        return alert

    def _add(self, alert: Alert, action: Action):
        alert.actions.append(action.to_dict())

    # ── Playbook : Brute Force ───────────────────────────────────

    def _pb_brute_force(self, alert: Alert):
        alert.playbook = "brute_force"
        ip  = alert.source_ip
        usr = alert.raw_data.get("username", "unknown")
        rep = alert.enrichment.get("ip_intel", {}).get("reputation_score", 0)
        nb  = alert.raw_data.get("attempts", 10)

        # Toujours bloquer l'IP
        self._add(alert, self.actions.block_ip(ip, f"Brute force ({nb} tentatives)", 24))

        # Si l'utilisateur a été potentiellement compromis
        if nb > 50 or rep > 70:
            self._add(alert, self.actions.lock_user(usr, "Brute force haute intensité"))
            self._add(alert, self.actions.revoke_sessions(usr))
            self._add(alert, self.actions.force_mfa(usr))

        ticket = self.actions.create_ticket(
            f"Brute Force depuis {ip} sur compte {usr}",
            alert.severity,
            f"{nb} tentatives · Réputation IP : {rep}/100"
        )
        self._add(alert, ticket)
        alert.ticket_id = ticket.target

        if alert.severity in ("CRITIQUE", "ÉLEVÉE"):
            self._add(alert, self.actions.notify_soc(
                f"Brute force {ip} → {usr} ({nb} tentatives)", alert.severity
            ))

    # ── Playbook : Phishing ──────────────────────────────────────

    def _pb_phishing(self, alert: Alert):
        alert.playbook = "phishing"
        victim  = alert.raw_data.get("user", "unknown")
        url     = alert.raw_data.get("url", "unknown")
        clicked = alert.raw_data.get("clicked", False)

        # Bloquer le domaine malveillant
        self._add(alert, self.actions.block_ip(
            alert.source_ip or "unknown", f"Domaine phishing: {url}"
        ))

        if clicked:
            # L'utilisateur a cliqué → compromission possible
            self._add(alert, self.actions.reset_password(victim))
            self._add(alert, self.actions.revoke_sessions(victim))
            self._add(alert, self.actions.force_mfa(victim))

        ticket = self.actions.create_ticket(
            f"Phishing {'(clic)' if clicked else '(détecté)'} — {victim}",
            alert.severity,
            f"URL: {url} · Utilisateur: {victim} · Clic: {clicked}"
        )
        self._add(alert, ticket)
        alert.ticket_id = ticket.target
        self._add(alert, self.actions.notify_soc(
            f"Phishing {'CLIC ⚠️' if clicked else 'détecté'} — {victim} → {url[:50]}",
            "CRITIQUE" if clicked else "ÉLEVÉE"
        ))

    # ── Playbook : Malware ───────────────────────────────────────

    def _pb_malware(self, alert: Alert):
        alert.playbook = "malware"
        host   = alert.raw_data.get("hostname", "workstation-unknown")
        user   = alert.raw_data.get("user", "unknown")
        family = alert.raw_data.get("malware_family", "inconnu")

        # Isolation immédiate
        self._add(alert, self.actions.quarantine_host(host))
        self._add(alert, self.actions.snapshot_host(host))

        if alert.raw_data.get("pid"):
            self._add(alert, self.actions.kill_process(host, alert.raw_data["pid"]))

        # Compte de l'utilisateur
        self._add(alert, self.actions.lock_user(user, f"Machine infectée: {host}"))
        self._add(alert, self.actions.revoke_sessions(user))

        ticket = self.actions.create_ticket(
            f"Malware {family} sur {host}",
            "CRITIQUE",
            f"Machine isolée · Snapshot créé · Utilisateur: {user}"
        )
        self._add(alert, ticket)
        alert.ticket_id = ticket.target
        self._add(alert, self.actions.notify_soc(
            f"🚨 MALWARE {family} sur {host} — Machine isolée", "CRITIQUE"
        ))

    # ── Playbook : Data Exfiltration ─────────────────────────────

    def _pb_data_exfil(self, alert: Alert):
        alert.playbook = "data_exfiltration"
        host   = alert.raw_data.get("hostname", "unknown")
        user   = alert.raw_data.get("user", "unknown")
        volume = alert.raw_data.get("volume_mb", 0)
        dst_ip = alert.raw_data.get("destination_ip", alert.source_ip)

        # Couper la connexion sortante
        self._add(alert, self.actions.block_ip(dst_ip, f"Exfiltration vers {dst_ip}"))
        self._add(alert, self.actions.quarantine_host(host))
        self._add(alert, self.actions.snapshot_host(host))

        # RGPD : si données personnelles potentiellement exfiltrées
        self._add(alert, self.actions.notify_dpo(
            alert.id,
            data_categories=["données clients", "emails"],
            n_affected=alert.raw_data.get("estimated_records", 0),
        ))
        alert.rgpd_notif = True

        ticket = self.actions.create_ticket(
            f"Exfiltration de données depuis {host} vers {dst_ip}",
            "CRITIQUE",
            f"Volume : {volume}MB · Utilisateur : {user} · DPO notifié"
        )
        self._add(alert, ticket)
        alert.ticket_id = ticket.target
        self._add(alert, self.actions.notify_soc(
            f"🚨 EXFILTRATION {volume}MB {host}→{dst_ip} — DPO notifié", "CRITIQUE"
        ))

    # ── Playbook : Credential Stuffing ───────────────────────────

    def _pb_credential_stuffing(self, alert: Alert):
        alert.playbook = "credential_stuffing"
        ips       = alert.raw_data.get("source_ips", [alert.source_ip])
        accounts  = alert.raw_data.get("compromised_accounts", [])

        for ip in ips[:20]:
            self._add(alert, self.actions.block_ip(ip, "Credential stuffing", 48))

        for acc in accounts:
            self._add(alert, self.actions.reset_password(acc))
            self._add(alert, self.actions.force_mfa(acc))
            self._add(alert, self.actions.revoke_sessions(acc))

        ticket = self.actions.create_ticket(
            f"Credential Stuffing — {len(ips)} IPs · {len(accounts)} comptes",
            alert.severity,
            f"IPs bloquées : {len(ips)} · Comptes réinitialisés : {len(accounts)}"
        )
        self._add(alert, ticket)
        alert.ticket_id = ticket.target
        if accounts:
            self._add(alert, self.actions.notify_soc(
                f"Credential stuffing — {len(accounts)} comptes compromis", "CRITIQUE"
            ))

    # ── Playbook : SQL Injection ─────────────────────────────────

    def _pb_sqli(self, alert: Alert):
        alert.playbook = "sql_injection"
        ip       = alert.source_ip
        endpoint = alert.raw_data.get("endpoint", "/unknown")
        param    = alert.raw_data.get("param", "?")

        self._add(alert, self.actions.rate_limit_ip(ip, max_rps=2))
        if alert.severity in ("CRITIQUE", "ÉLEVÉE"):
            self._add(alert, self.actions.block_ip(ip, f"SQLi sur {endpoint}"))

        ticket = self.actions.create_ticket(
            f"SQLi détecté sur {endpoint} (param: {param})",
            alert.severity,
            f"IP: {ip} · Endpoint: {endpoint} · Param: {param}"
        )
        self._add(alert, ticket)
        alert.ticket_id = ticket.target
        self._add(alert, self.actions.notify_soc(
            f"SQLi {ip} → {endpoint}?{param}=...", alert.severity
        ))

    # ── Playbook : DoS ───────────────────────────────────────────

    def _pb_dos(self, alert: Alert):
        alert.playbook = "dos_attack"
        ips   = alert.raw_data.get("source_ips", [alert.source_ip])
        rps   = alert.raw_data.get("requests_per_sec", 0)

        for ip in ips[:50]:
            self._add(alert, self.actions.block_ip(ip, f"DoS ({rps} req/s)", 6))

        ticket = self.actions.create_ticket(
            f"DoS/DDoS — {len(ips)} sources · {rps} req/s",
            alert.severity,
            f"{len(ips)} IPs bloquées · Trafic : {rps} req/s"
        )
        self._add(alert, ticket)
        alert.ticket_id = ticket.target
        self._add(alert, self.actions.notify_soc(
            f"DoS {rps} req/s depuis {len(ips)} IPs — {len(ips)} bloquées",
            "CRITIQUE" if rps > 10000 else "ÉLEVÉE"
        ))


# ════════════════════════════════════════════════════════════════
# TABLEAU DE BORD SOAR (HTML)
# ════════════════════════════════════════════════════════════════

def generate_dashboard(alerts: list[Alert],
                        output_path: Optional[Path] = None) -> str:
    """Génère un tableau de bord HTML des incidents traités."""
    now = datetime.now().strftime("%d/%m/%Y %H:%M")

    counts = defaultdict(int)
    for a in alerts:
        counts[a.severity] += 1

    total_actions = sum(len(a.actions) for a in alerts)
    avg_time = sum(a.duration_s for a in alerts) / len(alerts) if alerts else 0
    auto_rate = sum(1 for a in alerts if a.status == "RESOLVED") / len(alerts) * 100 if alerts else 0
    rgpd_count = sum(1 for a in alerts if a.rgpd_notif)

    sev_colors = {"CRITIQUE":"#e74c3c","ÉLEVÉE":"#e67e22","MODÉRÉE":"#f39c12","FAIBLE":"#27ae60","INFO":"#3498db"}
    sev_icons  = {"CRITIQUE":"🔴","ÉLEVÉE":"🟠","MODÉRÉE":"🟡","FAIBLE":"🟢","INFO":"🔵"}

    rows_html = ""
    for a in alerts:
        c    = sev_colors.get(a.severity, "#666")
        icon = sev_icons.get(a.severity, "⚪")
        status_style = "color:#27ae60" if a.status=="RESOLVED" else "color:#e67e22"
        rows_html += f"""
        <tr>
          <td><code style="color:var(--accent)">{escape(a.id)}</code></td>
          <td>{escape(a.ts.strftime('%H:%M:%S'))}</td>
          <td><span class="badge" style="background:{c}">{icon} {escape(a.severity)}</span></td>
          <td>{escape(a.type)}</td>
          <td><code style="font-size:.78rem">{escape(a.source_ip or '—')}</code></td>
          <td>{escape(a.playbook or '—')}</td>
          <td>{len(a.actions)}</td>
          <td><span style="{status_style}">{escape(a.status)}</span></td>
          <td>{escape(a.ticket_id or '—')}</td>
          <td>{a.duration_s*1000:.0f}ms</td>
        </tr>"""

    report = f"""<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
  <title>🛡️ SOAR Dashboard</title>
  <style>
    :root{{--bg:#0f1117;--card:#1a1d27;--border:#2d3148;--text:#e2e8f0;--muted:#8892b0;--accent:#64ffda}}
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',sans-serif;padding:2rem;max-width:1300px;margin:auto}}
    h1{{color:var(--accent);font-size:1.8rem;margin-bottom:.3rem}}
    .meta{{color:var(--muted);font-size:.82rem;margin-bottom:2rem}}
    .kpi-row{{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:.8rem;margin-bottom:2rem}}
    .kpi{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:1rem;text-align:center}}
    .kpi-val{{font-size:2rem;font-weight:900;color:var(--accent)}}
    .kpi-label{{font-size:.75rem;color:var(--muted);margin-top:.3rem}}
    .section{{color:var(--accent);font-size:1.05rem;margin:2rem 0 .8rem;border-bottom:1px solid var(--border);padding-bottom:.4rem}}
    table{{width:100%;border-collapse:collapse;background:var(--card);border-radius:8px;overflow:hidden;border:1px solid var(--border)}}
    th{{background:#0a0c14;color:var(--accent);padding:.6rem .8rem;text-align:left;font-size:.78rem;white-space:nowrap}}
    td{{padding:.55rem .8rem;border-top:1px solid var(--border);font-size:.82rem;color:var(--muted)}}
    tr:hover td{{background:#1e2235}}
    .badge{{color:#fff;padding:.15rem .5rem;border-radius:3px;font-size:.75rem;font-weight:700;white-space:nowrap}}
    code{{background:#0a0c14;padding:.15rem .4rem;border-radius:3px;font-size:.78rem}}
  </style>
</head>
<body>
  <h1>🤖 SOAR — Tableau de Bord Incidents</h1>
  <div class="meta">Généré le {now} · {len(alerts)} incident(s) traité(s) · ISO 27001 A.16 · RGPD Art. 33</div>

  <div class="kpi-row">
    <div class="kpi"><div class="kpi-val">{len(alerts)}</div><div class="kpi-label">Incidents traités</div></div>
    <div class="kpi"><div class="kpi-val">{auto_rate:.0f}%</div><div class="kpi-label">Taux d'automatisation</div></div>
    <div class="kpi"><div class="kpi-val">{avg_time*1000:.0f}ms</div><div class="kpi-label">Temps moyen réponse</div></div>
    <div class="kpi"><div class="kpi-val">{total_actions}</div><div class="kpi-label">Actions exécutées</div></div>
    <div class="kpi"><div class="kpi-val" style="color:#e74c3c">{counts.get('CRITIQUE',0)}</div><div class="kpi-label">Critiques</div></div>
    <div class="kpi"><div class="kpi-val" style="color:#e67e22">{counts.get('ÉLEVÉE',0)}</div><div class="kpi-label">Élevées</div></div>
    <div class="kpi"><div class="kpi-val" style="color:#3498db">{rgpd_count}</div><div class="kpi-label">Notif. RGPD Art.33</div></div>
  </div>

  <div class="section">📋 Journal des incidents</div>
  <table>
    <thead>
      <tr><th>ID</th><th>Heure</th><th>Sévérité</th><th>Type</th><th>IP Source</th><th>Playbook</th><th>Actions</th><th>Statut</th><th>Ticket</th><th>Durée</th></tr>
    </thead>
    <tbody>{rows_html}</tbody>
  </table>

  <div style="color:var(--muted);font-size:.76rem;text-align:center;margin-top:2rem">
    Généré par <strong>Le Bouclier Numérique — Jour 28 SOAR</strong> · ISO 27001 A.16 · RGPD Art. 33/34 · NIS2 Art. 23
  </div>
</body>
</html>"""

    if output_path:
        output_path.write_text(report, encoding="utf-8")
    return report


# ════════════════════════════════════════════════════════════════
# DÉMONSTRATION
# ════════════════════════════════════════════════════════════════

def run_demo():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 28 : SOAR                      ║
║  Security Orchestration, Automation & Response                 ║
╚══════════════════════════════════════════════════════════════════╝
""")

    actions = SoarActions()
    engine  = PlaybookEngine(actions)
    treated = []

    # Scénarios réalistes
    scenarios = [
        Alert("brute_force", "ÉLEVÉE", "185.234.219.47", "500 tentatives SSH sur admin",
              {"username": "admin", "attempts": 500}),

        Alert("phishing", "CRITIQUE", "45.77.120.81", "Alice a cliqué sur un lien malveillant",
              {"user": "alice@corp.fr", "url": "http://corp-vip.ru/login", "clicked": True}),

        Alert("malware", "CRITIQUE", "10.0.1.45", "Ransomware détecté sur WS-042",
              {"hostname": "WS-042", "user": "bob", "malware_family": "LockBit 3.0", "pid": 4821}),

        Alert("data_exfiltration", "CRITIQUE", "10.0.1.55",
              "Exfiltration 2.4GB vers IP externe",
              {"hostname": "SRV-DB-01", "user": "carol", "volume_mb": 2400,
               "destination_ip": "194.26.212.35", "estimated_records": 15000}),

        Alert("sql_injection", "ÉLEVÉE", "91.108.56.12",
              "SQLi error-based sur /api/search",
              {"endpoint": "/api/v1/search", "param": "q"}),

        Alert("credential_stuffing", "CRITIQUE", "185.100.87.33",
              "Credential stuffing — 3 comptes compromis",
              {"source_ips": ["185.100.87.33", "185.100.87.34", "91.195.240.5"],
               "compromised_accounts": ["dave@corp.fr", "eve@corp.fr"]}),

        Alert("dos", "ÉLEVÉE", "45.89.125.0",
              "DDoS 85 000 req/s sur l'API publique",
              {"source_ips": [f"45.89.125.{i}" for i in range(20)],
               "requests_per_sec": 85000}),
    ]

    print(f"  {'─'*62}")
    print(f"  {'ID':<10} {'TYPE':<25} {'SEV':<10} {'PLAYBOOK':<25} {'ACTIONS':<8} {'ms'}")
    print(f"  {'─'*62}")

    for alert in scenarios:
        result = engine.execute(alert)
        treated.append(result)
        icon = {"CRITIQUE":"🔴","ÉLEVÉE":"🟠","MODÉRÉE":"🟡"}.get(result.severity,"⚪")
        rgpd = " 📋RGPD" if result.rgpd_notif else ""
        print(f"  {result.id:<10} {result.type:<25} {icon}{result.severity:<9} "
              f"{result.playbook:<25} {len(result.actions):<8} "
              f"{result.duration_s*1000:.0f}ms{rgpd}")

    print(f"  {'─'*62}")

    total_actions = sum(len(a.actions) for a in treated)
    avg_ms = sum(a.duration_s for a in treated) / len(treated) * 1000
    print(f"\n  ✅  {len(treated)} incidents traités automatiquement")
    print(f"  ⚡  Temps moyen de réponse : {avg_ms:.0f}ms")
    print(f"  🎬  Actions totales exécutées : {total_actions}")
    print(f"  📋  Notifications RGPD Art.33 : {sum(1 for a in treated if a.rgpd_notif)}")

    report_path = Path("/tmp/soar_dashboard.html")
    generate_dashboard(treated, report_path)
    print(f"\n  📄  Dashboard → {report_path}")

    print("""
  ─────────────────────────────────────────────────────────
  Sans SOAR : chaque incident = 15–45 min d'analyse manuelle
  Avec SOAR : réponse automatique en < 500ms
  → Blocage d'IP, isolation machine, notification DPO,
    ticket ITSM, révocation sessions — tout en une passe.

  Conformité automatisée :
  → RGPD Art.33 : DPO notifié dans les 72h ✅
  → ISO 27001 A.16.1.5 : réponse documentée ✅
  → NIS2 Art.23 : incident enregistré ✅
  ─────────────────────────────────────────────────────────
""")


def main():
    import argparse
    p = argparse.ArgumentParser(description="SOAR — Bouclier Numérique Jour 28")
    sub = p.add_subparsers(dest="cmd")
    sub.add_parser("demo")
    ps = sub.add_parser("simulate")
    ps.add_argument("--type",     default="brute_force")
    ps.add_argument("--severity", default="ÉLEVÉE")
    ps.add_argument("--ip",       default="1.2.3.4")
    args = p.parse_args()

    if not args.cmd or args.cmd == "demo":
        run_demo()
    elif args.cmd == "simulate":
        actions = SoarActions()
        engine  = PlaybookEngine(actions)
        alert   = Alert(args.type, args.severity, args.ip, "Simulation manuelle")
        result  = engine.execute(alert)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
