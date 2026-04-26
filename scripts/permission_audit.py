#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║  🛡️  BOUCLIER NUMÉRIQUE — JOUR 5 : AUDIT DES PERMISSIONS        ║
║  Cible  : Linux desktop · Android (ADB) · macOS                  ║
║  Détecte: Caméra · Micro · GPS · Contacts · SMS · Stockage      ║
╚══════════════════════════════════════════════════════════════════╝

Exigence légale : Art. 5(1)(b) RGPD — Principe de "limitation
des finalités" : une application n'est autorisée à collecter
que ce qui est strictement nécessaire à sa fonction déclarée.
Principe de "minimisation" : Art. 5(1)(c).

Problème : Sur smartphone, des dizaines d'applications ont
accumulé des permissions qu'elles n'utilisent pas ou plus —
souvent accordées par inadvertance lors d'une installation.
Une application de lampe de poche qui accède aux contacts ou
au micro est une violation caractérisée du RGPD et un vecteur
d'espionnage potentiel.

Solution technique : Scanner automatiquement toutes les
applications installées et leurs permissions déclarées, les
croiser avec leurs fonctions réelles, et générer un rapport
de risque avec recommandations de révocation.

Risque évité : Fuite de données personnelles silencieuse,
espionnage ambient, tracking de localisation non consenti.
Amende : Art. 83 §5 — jusqu'à 20M€ ou 4% CA mondial pour
traitement illicite de données (micro/caméra sans consentement).
"""

import os
import sys
import json
import subprocess
import platform
import glob
import re
import shutil
from pathlib import Path
from datetime import datetime
from typing import Optional

# ─── Niveaux de risque des permissions ───────────────────────────

PERMISSION_RISK = {
    # 🔴 CRITIQUE — accès direct au corps/vie privée
    "CAMERA":                   ("🔴 CRITIQUE",  "Accès caméra — peut capturer vidéo/photo"),
    "RECORD_AUDIO":             ("🔴 CRITIQUE",  "Accès micro — peut enregistrer en continu"),
    "ACCESS_FINE_LOCATION":     ("🔴 CRITIQUE",  "GPS précis (±3m) — tracking de localisation"),
    "PROCESS_OUTGOING_CALLS":   ("🔴 CRITIQUE",  "Interception des appels sortants"),
    "READ_PHONE_STATE":         ("🔴 CRITIQUE",  "IMEI, numéro téléphone, état appels"),
    "BODY_SENSORS":             ("🔴 CRITIQUE",  "Accès capteurs biométriques"),

    # 🟠 ÉLEVÉ — données personnelles sensibles
    "READ_CONTACTS":            ("🟠 ÉLEVÉ",     "Lecture de tous vos contacts"),
    "WRITE_CONTACTS":           ("🟠 ÉLEVÉ",     "Modification/suppression de contacts"),
    "READ_SMS":                 ("🟠 ÉLEVÉ",     "Lecture de tous vos SMS (codes 2FA !)"),
    "SEND_SMS":                 ("🟠 ÉLEVÉ",     "Envoi de SMS (surcoût possible)"),
    "READ_CALL_LOG":            ("🟠 ÉLEVÉ",     "Historique de tous vos appels"),
    "WRITE_CALL_LOG":           ("🟠 ÉLEVÉ",     "Modification de l'historique d'appels"),
    "READ_CALENDAR":            ("🟠 ÉLEVÉ",     "Accès à votre agenda complet"),
    "WRITE_CALENDAR":           ("🟠 ÉLEVÉ",     "Modification de votre agenda"),
    "GET_ACCOUNTS":             ("🟠 ÉLEVÉ",     "Liste de tous vos comptes (Google, etc.)"),
    "USE_BIOMETRIC":            ("🟠 ÉLEVÉ",     "Authentification biométrique"),
    "USE_FINGERPRINT":          ("🟠 ÉLEVÉ",     "Accès lecteur d'empreintes"),

    # 🟡 MODÉRÉ — données comportementales
    "ACCESS_COARSE_LOCATION":   ("🟡 MODÉRÉ",    "Localisation approximative (±100m)"),
    "READ_EXTERNAL_STORAGE":    ("🟡 MODÉRÉ",    "Lecture de tous vos fichiers/photos"),
    "WRITE_EXTERNAL_STORAGE":   ("🟡 MODÉRÉ",    "Écriture sur votre stockage"),
    "BLUETOOTH":                ("🟡 MODÉRÉ",    "Scan Bluetooth — tracking physique possible"),
    "BLUETOOTH_SCAN":           ("🟡 MODÉRÉ",    "Scan appareils Bluetooth proches"),
    "NFC":                      ("🟡 MODÉRÉ",    "Accès puce NFC"),
    "ACTIVITY_RECOGNITION":     ("🟡 MODÉRÉ",    "Détection marche/course/conduite"),

    # 🔵 FAIBLE — réseau et services
    "INTERNET":                 ("🔵 FAIBLE",    "Accès internet (quasi-universel)"),
    "ACCESS_NETWORK_STATE":     ("🔵 FAIBLE",    "État de la connexion réseau"),
    "ACCESS_WIFI_STATE":        ("🔵 FAIBLE",    "Infos réseau Wi-Fi connecté"),
    "CHANGE_WIFI_STATE":        ("🔵 FAIBLE",    "Modification paramètres Wi-Fi"),
    "VIBRATE":                  ("🔵 FAIBLE",    "Contrôle du vibreur"),
    "RECEIVE_BOOT_COMPLETED":   ("🔵 FAIBLE",    "Démarrage auto au boot"),
    "FOREGROUND_SERVICE":       ("🔵 FAIBLE",    "Service en arrière-plan"),
    "WAKE_LOCK":                ("🔵 FAIBLE",    "Empêche la mise en veille"),
    "SCHEDULE_EXACT_ALARM":     ("🔵 FAIBLE",    "Alarmes précises"),
    "POST_NOTIFICATIONS":       ("🔵 FAIBLE",    "Envoi de notifications"),
}

# Applications légitimes pour certaines permissions (heuristique)
EXPECTED_PERMISSIONS = {
    "Téléphone":     {"CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_CALL_LOG", "ACCESS_FINE_LOCATION"},
    "Maps":          {"ACCESS_FINE_LOCATION", "CAMERA", "RECORD_AUDIO"},
    "Instagram":     {"CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION"},
    "WhatsApp":      {"CAMERA", "RECORD_AUDIO", "READ_CONTACTS", "READ_SMS", "ACCESS_FINE_LOCATION"},
    "Torche":        {"CAMERA"},  # UNIQUEMENT CAMERA — tout le reste est suspect
    "Calculatrice":  set(),
    "Météo":         {"ACCESS_FINE_LOCATION"},
}

# Applications suspectes connues (liste illustrative)
SUSPICIOUS_APPS = {
    "com.adware.tracker",
    "com.stalkerware.mspy",
    "com.spyware.flexispy",
}


# ════════════════════════════════════════════════════════════════
# MODULE 1 : AUDIT LINUX (Desktop / Serveur)
# ════════════════════════════════════════════════════════════════

def audit_linux_devices() -> dict:
    """
    Scanne les processus Linux qui accèdent aux devices
    caméra/micro en temps réel via /proc/*/fd.
    """
    report = {
        "platform": "Linux",
        "scan_time": datetime.now().isoformat(),
        "camera_access": [],
        "audio_access":  [],
        "suspicious":    [],
    }

    # Devices à surveiller
    camera_patterns = ["/dev/video", "/dev/media"]
    audio_patterns  = ["/dev/snd/", "/dev/audio", "/dev/dsp"]

    for pid_fd_dir in glob.glob("/proc/[0-9]*/fd"):
        pid = pid_fd_dir.split("/")[2]
        try:
            # Nom du processus
            with open(f"/proc/{pid}/comm") as f:
                proc_name = f.read().strip()

            # Ligne de commande
            try:
                with open(f"/proc/{pid}/cmdline") as f:
                    cmdline = f.read().replace("\x00", " ").strip()[:120]
            except:
                cmdline = proc_name

            # Scanner les descripteurs de fichiers ouverts
            for fd in os.listdir(pid_fd_dir):
                try:
                    link = os.readlink(f"{pid_fd_dir}/{fd}")

                    if any(link.startswith(p) for p in camera_patterns):
                        report["camera_access"].append({
                            "pid": pid, "process": proc_name,
                            "device": link, "cmdline": cmdline,
                            "risk": "🔴 CRITIQUE"
                        })

                    elif any(link.startswith(p) for p in audio_patterns):
                        report["audio_access"].append({
                            "pid": pid, "process": proc_name,
                            "device": link, "cmdline": cmdline,
                            "risk": "🔴 CRITIQUE"
                        })

                except (PermissionError, FileNotFoundError):
                    pass

        except (PermissionError, FileNotFoundError, ProcessLookupError):
            pass

    # Détecter processus suspects (keyloggers connus, RATs, etc.)
    suspicious_names = {
        "keylogger", "rathole", "ngrok", "frp", "meterpreter",
        "netcat", "ncat", "socat", "tcpdump", "wireshark",
    }

    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name", "cmdline", "username"]):
            try:
                name = (proc.info.get("name") or "").lower()
                if any(s in name for s in suspicious_names):
                    report["suspicious"].append({
                        "pid":     proc.info["pid"],
                        "process": proc.info["name"],
                        "user":    proc.info.get("username", "?"),
                        "risk":    "🟠 ÉLEVÉ"
                    })
            except:
                pass
    except ImportError:
        pass

    return report


def audit_linux_network() -> dict:
    """
    Détecte les connexions réseau suspectes depuis des processus
    qui n'ont pas de raison légitime de communiquer.
    """
    try:
        import psutil
        connections = psutil.net_connections(kind="inet")
        suspicious = []

        for conn in connections:
            if conn.status == "ESTABLISHED" and conn.pid:
                try:
                    proc = psutil.Process(conn.pid)
                    name = proc.name()
                    # Processus système sans raison de se connecter
                    if name in ("bash", "sh", "python3", "perl", "ruby", "php"):
                        suspicious.append({
                            "pid": conn.pid,
                            "process": name,
                            "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?",
                            "risk": "🟠 ÉLEVÉ — Shell avec connexion active"
                        })
                except:
                    pass

        return {"suspicious_connections": suspicious}
    except:
        return {"suspicious_connections": []}


# ════════════════════════════════════════════════════════════════
# MODULE 2 : AUDIT ANDROID (via ADB)
# ════════════════════════════════════════════════════════════════

def check_adb_available() -> bool:
    return shutil.which("adb") is not None


def adb_run(cmd: list) -> Optional[str]:
    """Exécute une commande ADB et retourne la sortie."""
    try:
        result = subprocess.run(
            ["adb"] + cmd,
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def get_android_packages() -> list:
    """Liste toutes les apps installées (non-système)."""
    output = adb_run(["shell", "pm", "list", "packages", "-3"])
    if not output:
        return []
    return [line.replace("package:", "").strip() for line in output.splitlines()]


def get_app_permissions(package: str) -> dict:
    """
    Lit le AndroidManifest déclaré ET les permissions runtime accordées.
    Distingue ce qui est déclaré vs ce qui est activement accordé.
    """
    result = {
        "package": package,
        "declared": [],
        "granted":  [],
        "denied":   [],
    }

    # Permissions déclarées dans le manifest
    output = adb_run(["shell", "dumpsys", "package", package])
    if not output:
        return result

    # Parser les permissions (accordées vs refusées)
    for line in output.splitlines():
        line = line.strip()

        # Permissions accordées
        if "granted=true" in line:
            m = re.search(r"android\.permission\.(\w+)", line)
            if m:
                result["granted"].append(m.group(1))

        # Permissions refusées
        elif "granted=false" in line:
            m = re.search(r"android\.permission\.(\w+)", line)
            if m:
                result["denied"].append(m.group(1))

        # Permissions déclarées
        elif "uses-permission:" in line.lower():
            m = re.search(r"android\.permission\.(\w+)", line)
            if m:
                perm = m.group(1)
                if perm not in result["declared"]:
                    result["declared"].append(perm)

    return result


def get_app_label(package: str) -> str:
    """Récupère le nom lisible d'une application."""
    output = adb_run([
        "shell", "pm", "list", "packages", "-f", package
    ])
    if output:
        # Extraire le nom APK pour un label approximatif
        parts = output.split("=")
        if len(parts) > 1:
            apk = parts[0].split("/")[-1].replace(".apk", "")
            return apk
    return package.split(".")[-1]


def analyze_permission_anomalies(package: str, granted: list) -> list:
    """
    Détecte les permissions anormales selon le type d'application.
    Heuristique : nom de package vs permissions accordées.
    """
    anomalies = []
    pkg_lower = package.lower()

    # Règles heuristiques
    rules = [
        # (condition sur le nom, permission suspecte, explication)
        (lambda p: "torch" in p or "flashlight" in p or "flash" in p,
         ["RECORD_AUDIO", "READ_CONTACTS", "ACCESS_FINE_LOCATION", "READ_SMS"],
         "Torche avec accès données — suspecte"),

        (lambda p: "calculator" in p or "calc" in p,
         ["CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION", "READ_CONTACTS"],
         "Calculatrice avec capteurs — très suspecte"),

        (lambda p: "weather" in p or "meteo" in p,
         ["RECORD_AUDIO", "READ_CONTACTS", "READ_SMS", "CAMERA"],
         "Météo avec accès privé — suspecte"),

        (lambda p: "game" in p or "casino" in p or "puzzle" in p,
         ["RECORD_AUDIO", "READ_CONTACTS", "READ_SMS", "PROCESS_OUTGOING_CALLS"],
         "Jeu avec permissions sensibles — très suspecte"),

        (lambda p: "battery" in p or "cleaner" in p or "booster" in p or "optimizer" in p,
         ["RECORD_AUDIO", "CAMERA", "READ_SMS", "READ_CALL_LOG"],
         "Utilitaire système avec accès intime — classique adware"),
    ]

    for condition, suspicious_perms, explanation in rules:
        if condition(pkg_lower):
            found = [p for p in suspicious_perms if p in granted]
            for perm in found:
                anomalies.append({
                    "permission": perm,
                    "reason": explanation,
                    "risk": PERMISSION_RISK.get(perm, ("🟡 MODÉRÉ", "Permission suspecte"))[0]
                })

    # Toujours flaguer certaines permissions ultra-sensibles
    ultra_sensitive = ["PROCESS_OUTGOING_CALLS", "READ_SMS", "RECORD_AUDIO"]
    for perm in ultra_sensitive:
        if perm in granted and not any(a["permission"] == perm for a in anomalies):
            # Vérifier si c'est une app téléphonie légitime
            is_telecom = any(x in pkg_lower for x in ["phone", "dialer", "call", "sms", "messaging"])
            if not is_telecom:
                risk, desc = PERMISSION_RISK.get(perm, ("🟠 ÉLEVÉ", "Permission sensible"))
                anomalies.append({
                    "permission": perm,
                    "reason": f"Permission ultra-sensible sur app non-téléphonie : {desc}",
                    "risk": risk
                })

    return anomalies


def run_android_audit() -> dict:
    """Audit complet d'un appareil Android connecté via ADB."""
    report = {
        "platform":     "Android",
        "scan_time":    datetime.now().isoformat(),
        "device_info":  {},
        "apps_scanned": 0,
        "high_risk":    [],
        "critical_perms": {"camera": [], "microphone": [], "location": [], "sms": []},
        "anomalies":    [],
        "summary":      {}
    }

    # Infos appareil
    model = adb_run(["shell", "getprop", "ro.product.model"])
    android_ver = adb_run(["shell", "getprop", "ro.build.version.release"])
    report["device_info"] = {
        "model": model or "?",
        "android_version": android_ver or "?"
    }

    # Lister les apps tierces
    packages = get_android_packages()
    report["apps_scanned"] = len(packages)

    print(f"  📱  {len(packages)} application(s) tierces détectées")
    print(f"  ⏳  Scan des permissions en cours...\n")

    for pkg in packages:
        perms = get_app_permissions(pkg)
        granted = perms["granted"]

        if not granted:
            continue

        # Trier par permissions critiques
        for perm in ["CAMERA", "RECORD_AUDIO"]:
            if perm in granted:
                report["critical_perms"]["camera" if perm == "CAMERA" else "microphone"].append(pkg)

        if any(p in granted for p in ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"]):
            report["critical_perms"]["location"].append(pkg)

        if "READ_SMS" in granted or "SEND_SMS" in granted:
            report["critical_perms"]["sms"].append(pkg)

        # Analyser les anomalies
        anomalies = analyze_permission_anomalies(pkg, granted)
        if anomalies:
            app_entry = {
                "package":    pkg,
                "label":      get_app_label(pkg),
                "granted":    [p for p in granted if p in PERMISSION_RISK],
                "anomalies":  anomalies,
                "risk_score": sum(3 if "CRITIQUE" in a["risk"] else 2 if "ÉLEVÉ" in a["risk"] else 1
                                  for a in anomalies)
            }
            report["anomalies"].append(app_entry)

        # Apps à haut risque global
        critical_count = sum(1 for p in granted
                            if PERMISSION_RISK.get(p, ("", ""))[0] == "🔴 CRITIQUE")
        if critical_count >= 3 and pkg not in EXPECTED_PERMISSIONS:
            report["high_risk"].append({
                "package": pkg,
                "critical_permissions": critical_count,
                "granted": granted
            })

    # Trier par score de risque
    report["anomalies"].sort(key=lambda x: x["risk_score"], reverse=True)

    report["summary"] = {
        "apps_with_camera":  len(report["critical_perms"]["camera"]),
        "apps_with_micro":   len(report["critical_perms"]["microphone"]),
        "apps_with_location":len(report["critical_perms"]["location"]),
        "apps_with_sms":     len(report["critical_perms"]["sms"]),
        "anomalies_found":   len(report["anomalies"]),
    }

    return report


# ════════════════════════════════════════════════════════════════
# MODULE 3 : COMMANDES DE RÉVOCATION
# ════════════════════════════════════════════════════════════════

def generate_revocation_commands(anomalies: list) -> list:
    """
    Génère les commandes ADB pour révoquer les permissions suspectes.
    Ces commandes peuvent être exécutées directement ou intégrées
    dans un script MDM (Mobile Device Management) d'entreprise.
    """
    commands = []
    for app in anomalies[:10]:  # Top 10 plus risquées
        pkg = app["package"]
        for anomaly in app["anomalies"]:
            perm = anomaly["permission"]
            commands.append({
                "app":     pkg,
                "perm":    perm,
                "command": f"adb shell pm revoke {pkg} android.permission.{perm}",
                "risk":    anomaly["risk"],
                "reason":  anomaly["reason"]
            })
    return commands


# ════════════════════════════════════════════════════════════════
# MODULE 4 : DÉMO SIMULÉE (sans ADB)
# ════════════════════════════════════════════════════════════════

DEMO_APPS = [
    {
        "package": "com.flashlight.super",
        "label": "Super Torche Pro",
        "granted": ["CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
                    "READ_CONTACTS", "READ_SMS", "INTERNET", "VIBRATE"],
    },
    {
        "package": "com.battery.optimizer.cleaner",
        "label": "Battery Booster & Cleaner",
        "granted": ["CAMERA", "RECORD_AUDIO", "READ_CONTACTS",
                    "READ_CALL_LOG", "ACCESS_FINE_LOCATION",
                    "READ_EXTERNAL_STORAGE", "INTERNET"],
    },
    {
        "package": "com.puzzle.games.free",
        "label": "Puzzle Games Free",
        "granted": ["RECORD_AUDIO", "ACCESS_FINE_LOCATION",
                    "READ_CONTACTS", "INTERNET", "VIBRATE"],
    },
    {
        "package": "com.whatsapp",
        "label": "WhatsApp",
        "granted": ["CAMERA", "RECORD_AUDIO", "READ_CONTACTS",
                    "ACCESS_FINE_LOCATION", "READ_EXTERNAL_STORAGE",
                    "INTERNET", "VIBRATE"],
    },
    {
        "package": "com.calculator.basic",
        "label": "Calculatrice Simple",
        "granted": ["INTERNET", "VIBRATE"],
    },
    {
        "package": "com.weather.forecast",
        "label": "Météo & Prévisions",
        "granted": ["ACCESS_FINE_LOCATION", "CAMERA", "RECORD_AUDIO", "INTERNET"],
    },
    {
        "package": "com.spotify.music",
        "label": "Spotify",
        "granted": ["RECORD_AUDIO", "BLUETOOTH", "INTERNET",
                    "ACCESS_COARSE_LOCATION", "WAKE_LOCK"],
    },
    {
        "package": "com.android.chrome",
        "label": "Chrome",
        "granted": ["CAMERA", "RECORD_AUDIO", "ACCESS_FINE_LOCATION",
                    "READ_EXTERNAL_STORAGE", "INTERNET"],
    },
    {
        "package": "com.fake.vpn.free",
        "label": "Free VPN Proxy",
        "granted": ["RECORD_AUDIO", "READ_CONTACTS", "READ_SMS",
                    "PROCESS_OUTGOING_CALLS", "ACCESS_FINE_LOCATION", "INTERNET"],
    },
    {
        "package": "com.beautycam.selfie",
        "label": "Beauty Cam Selfie",
        "granted": ["CAMERA", "RECORD_AUDIO", "READ_CONTACTS",
                    "ACCESS_FINE_LOCATION", "READ_EXTERNAL_STORAGE",
                    "GET_ACCOUNTS", "INTERNET"],
    },
]


def run_demo():
    SEP = "═" * 62

    print(f"\n{SEP}")
    print("  🎬  DÉMO — Audit de permissions (10 apps simulées)")
    print(f"{SEP}\n")

    print("  📱  Appareil : Pixel 7 Pro — Android 14")
    print(f"  📦  {len(DEMO_APPS)} applications tierces analysées\n")

    # ── Phase 1 : Scan complet ──
    all_anomalies = []
    critical_map = {"camera": [], "microphone": [], "location": [], "sms": []}

    for app in DEMO_APPS:
        pkg     = app["package"]
        label   = app["label"]
        granted = app["granted"]

        # Comptage permissions critiques
        if "CAMERA" in granted:
            critical_map["camera"].append(label)
        if "RECORD_AUDIO" in granted:
            critical_map["microphone"].append(label)
        if any(p in granted for p in ["ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION"]):
            critical_map["location"].append(label)
        if "READ_SMS" in granted:
            critical_map["sms"].append(label)

        anomalies = analyze_permission_anomalies(pkg, granted)
        if anomalies:
            score = sum(3 if "CRITIQUE" in a["risk"] else 2 if "ÉLEVÉ" in a["risk"] else 1
                        for a in anomalies)
            all_anomalies.append({**app, "anomalies": anomalies, "risk_score": score})

    all_anomalies.sort(key=lambda x: x["risk_score"], reverse=True)

    # ── Phase 2 : Vue d'ensemble ──
    print(f"  {'─'*60}")
    print(f"  📊  VUE D'ENSEMBLE — Accès aux capteurs sensibles")
    print(f"  {'─'*60}")
    print(f"\n  🎥  Caméra ({len(critical_map['camera'])} apps) :")
    for app in critical_map["camera"]:
        marker = "⚠️ " if app in ["Super Torche Pro", "Battery Booster & Cleaner",
                                    "Météo & Prévisions", "Free VPN Proxy"] else "  "
        print(f"     {marker} {app}")

    print(f"\n  🎙️  Microphone ({len(critical_map['microphone'])} apps) :")
    for app in critical_map["microphone"]:
        marker = "⚠️ " if app in ["Super Torche Pro", "Battery Booster & Cleaner",
                                    "Puzzle Games Free", "Free VPN Proxy"] else "  "
        print(f"     {marker} {app}")

    print(f"\n  📍  Localisation ({len(critical_map['location'])} apps) :")
    for app in critical_map["location"]:
        print(f"       {app}")

    print(f"\n  💬  SMS ({len(critical_map['sms'])} apps) :")
    for app in critical_map["sms"]:
        print(f"     ⚠️  {app}")

    # ── Phase 3 : Top 5 apps suspectes ──
    print(f"\n  {'─'*60}")
    print(f"  🚨  TOP {min(5, len(all_anomalies))} APPLICATIONS SUSPECTES")
    print(f"  {'─'*60}")

    for i, app in enumerate(all_anomalies[:5], 1):
        print(f"\n  [{i}] {app['label']}")
        print(f"       Package    : {app['package']}")
        print(f"       Score      : {'🔴' * min(app['risk_score'], 5)} ({app['risk_score']} pts)")
        print(f"       Permissions accordées ({len(app['granted'])}) : "
              f"{', '.join(app['granted'][:5])}{'...' if len(app['granted']) > 5 else ''}")
        print(f"       Anomalies :")
        for a in app["anomalies"]:
            print(f"         {a['risk']} {a['permission']} — {a['reason']}")

    # ── Phase 4 : Commandes de révocation ──
    print(f"\n  {'─'*60}")
    print(f"  🔧  COMMANDES DE RÉVOCATION (ADB)")
    print(f"  {'─'*60}")
    print("  Copiez-collez ces commandes pour révoquer les accès suspects :\n")

    revoke_cmds = generate_revocation_commands(all_anomalies)
    for cmd in revoke_cmds[:8]:
        print(f"  {cmd['risk'][:2]}  {cmd['command']}")
        print(f"      → {cmd['reason']}\n")

    # ── Phase 5 : Bilan RGPD ──
    print(f"\n  {SEP}")
    print(f"  📋  BILAN RGPD — Responsabilités légales")
    print(f"  {SEP}")
    print(f"""
  ┌──────────────────────────────────────────────────────────┐
  │  RGPD — Art. 5(1)(b) : LIMITATION DES FINALITÉS         │
  │                                                          │
  │  "Super Torche Pro" déclare éclairer avec la LED.        │
  │  Elle accède en réalité au micro, GPS et contacts.       │
  │  → Traitement sans base légale = infraction Art. 6 RGPD  │
  │  → Amende possible : jusqu'à 20M€ (Art. 83 §5)          │
  │                                                          │
  │  POUR UNE ENTREPRISE (MDM) :                             │
  │  • Politique BYOD : interdire apps non-validées          │
  │  • Audit trimestriel avec ce script                      │
  │  • Révocation automatique sur appareils professionnels   │
  └──────────────────────────────────────────────────────────┘

  Risques supplémentaires identifiés :
  • {len(critical_map['microphone'])} apps avec accès micro → Réunions d'entreprise exposées
  • {len(critical_map['sms'])} app(s) avec accès SMS → Codes 2FA interceptables
  • "Free VPN Proxy" : accès appels + SMS + contacts = spyware probable
""")

    # ── Rapport JSON ──
    report_path = "/tmp/permission_audit_demo.json"
    report_data = {
        "scan_date":    datetime.now().isoformat(),
        "platform":     "Android (simulation)",
        "apps_scanned": len(DEMO_APPS),
        "critical_map": critical_map,
        "anomalies":    [
            {
                "app":        a["label"],
                "package":    a["package"],
                "risk_score": a["risk_score"],
                "anomalies":  a["anomalies"]
            }
            for a in all_anomalies
        ],
        "revoke_commands": revoke_cmds
    }
    with open(report_path, "w") as f:
        json.dump(report_data, f, indent=2, ensure_ascii=False)

    print(f"  💾  Rapport JSON sauvegardé : {report_path}")
    print(f"\n  📌  Usage sur un vrai appareil Android :")
    print(f"     1. Activez 'Débogage USB' dans Paramètres → Options dev")
    print(f"     2. Branchez et autorisez la connexion ADB")
    print(f"     3. python3 permission_audit.py android")


# ════════════════════════════════════════════════════════════════
# CLI
# ════════════════════════════════════════════════════════════════

USAGE = """
Usage :
  python3 permission_audit.py demo              Démo complète (simulée)
  python3 permission_audit.py linux             Audit système Linux live
  python3 permission_audit.py android           Audit Android via ADB
  python3 permission_audit.py android --revoke  Audit + révocation auto
"""

def main():
    print(__doc__)
    args = sys.argv[1:]

    if not args or args[0] == "demo":
        run_demo()

    elif args[0] == "linux":
        print(f"\n  🐧  Audit Linux en cours...\n")
        report = audit_linux_devices()
        net    = audit_linux_network()

        cam = report["camera_access"]
        mic = report["audio_access"]
        sus = report["suspicious"] + net.get("suspicious_connections", [])

        print(f"  🎥  Accès caméra live : {len(cam)} processus")
        for p in cam:
            print(f"     {p['risk']} PID {p['pid']} — {p['process']} → {p['device']}")

        print(f"\n  🎙️  Accès audio live : {len(mic)} processus")
        for p in mic:
            print(f"     {p['risk']} PID {p['pid']} — {p['process']} → {p['device']}")

        print(f"\n  ⚠️  Processus suspects : {len(sus)}")
        for p in sus:
            print(f"     {p.get('risk', '?')} {p.get('process', p.get('name', '?'))}")

        if not cam and not mic and not sus:
            print(f"\n  ✅  Aucun accès suspect détecté actuellement.")

    elif args[0] == "android":
        if not check_adb_available():
            print("  ❌  ADB non trouvé. Installez Android Platform Tools.")
            print("       https://developer.android.com/tools/releases/platform-tools")
            sys.exit(1)

        device = adb_run(["devices"])
        if not device or "device" not in device:
            print("  ❌  Aucun appareil Android connecté.")
            sys.exit(1)

        report = run_android_audit()

        print(f"\n  📊  RÉSUMÉ :")
        s = report["summary"]
        print(f"  Apps scannées  : {report['apps_scanned']}")
        print(f"  Avec caméra    : {s['apps_with_camera']}")
        print(f"  Avec micro     : {s['apps_with_micro']}")
        print(f"  Avec GPS       : {s['apps_with_location']}")
        print(f"  Avec SMS       : {s['apps_with_sms']}")
        print(f"  Anomalies      : {s['anomalies_found']}")

        if "--revoke" in args:
            cmds = generate_revocation_commands(report["anomalies"])
            print(f"\n  🔧  Révocation de {len(cmds)} permissions...")
            for cmd in cmds:
                os.system(cmd["command"])
                print(f"  ✅  Révoqué : {cmd['perm']} → {cmd['app']}")

        out = Path("android_permission_audit.json")
        with open(out, "w") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        print(f"\n  💾  Rapport : {out}")

    else:
        print(USAGE)


if __name__ == "__main__":
    main()
