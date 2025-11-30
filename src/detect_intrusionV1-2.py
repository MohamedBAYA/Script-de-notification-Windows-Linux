"""
Script de détection des tentatives d'intrusion (SSH sur Linux, EventLog sur Windows).

Sur Linux :
    - Analyse les journaux SSH via journalctl
    - Détecte "Failed password" (SSH bruteforce)
    - Envoie une notification + enregistre dans un fichier log

Sur Windows :
    - Analyse les événements de sécurité (EventID 4625)
    - Détecte les échecs de connexion
    - Envoie une notification + enregistre dans un fichier log

Auteur : Mohamed BAYA
Version : 1.0
"""

import platform
import os
import sys
import time
import re
import subprocess
import json
from datetime import datetime
from typing import Callable

# =======================
# Constantes Globales
# =======================
CONFIG = {}

# ========================
#   Sécurité & Utilitaires
# ========================


def load_config() -> None:
    """Charge la configuration depuis config/config.json si présent."""
    global CONFIG
    default_config = {
        "enable_linux_detection": True,
        "enable_windows_detection": True,
        "notifications": {"title": "Alerte Intrusion", "enable_notifications": True},
        "logging": {
            "enabled": True,
            "file_name": "intrusion_detection.log",
            "json_format": False,
        },
    }
    CONFIG = default_config.copy()
    try:
        config_path = os.path.join("config", "config.json")
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                user_conf = json.load(f)
                # Merge simple (par-dessus les valeurs par défaut)
                for k, v in user_conf.items():
                    CONFIG[k] = v
    except Exception as e:
        print(f"[AVERTISSEMENT] Impossible de charger la config : {e}")


def sanitize(text: str) -> str:
    """Supprime les caractères pouvant casser la commande systeme."""
    blacklist = ['"', "'", ";", "`", "$", "|", "&"]
    for c in blacklist:
        text = text.replace(c, "")
    return text


def write_log(message: str) -> None:
    """Écrit un message dans un fichier log local."""
    try:
        if CONFIG.get("logging", {}).get("enabled", True) is False:
            return
        os.makedirs("logs", exist_ok=True)
        file_name = CONFIG.get("logging", {}).get(
            "file_name", "intrusion_detection.log"
        )
        log_path = os.path.join("logs", file_name)
        with open(log_path, "a", encoding="utf-8") as f:
            t = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{t}] {message}\n")
    except Exception as e:
        print(f"[ERREUR] Impossible d'écrire dans le log : {e}")


def check_permissions() -> None:
    """Vérifie que l'utilisateur possède les droits nécessaires."""
    os_name = platform.system()

    if os_name == "Linux":
        # Vérifie que journalctl est disponible
        result = subprocess.run(["which", "journalctl"], capture_output=True)

        if result.returncode != 0:
            print("[ERREUR] journalctl n'est pas installé.")
            write_log("journalctl introuvable")
            sys.exit(1)

        # Teste si on peut accéder aux logs SSH
        result = subprocess.run(
            ["journalctl", "-u", "ssh", "-n", "1"],
            capture_output=True,
            text=True,
        )

        if "Permission denied" in (result.stderr or ""):
            print("[ERREUR] Accès aux logs SSH refusé.")
            print("[INFO] Ajoute-toi au groupe 'adm' : sudo usermod -aG adm $USER")
            write_log("Permissions insuffisantes pour journalctl")
            sys.exit(1)

    elif os_name == "Windows":
        try:
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[ERREUR] Lancer PowerShell en tant qu'administrateur.")
                write_log("Droits insuffisants pour lire EventLog")
                sys.exit(1)
        except:
            print("[AVERTISSEMENT] Impossible de vérifier les droits admin.")
            write_log("Impossible de vérifier les droits admin")


def setup_encoding_windows() -> None:
    """Force l'UTF-8 sur Windows pour éviter les problèmes d'accents."""
    if platform.system() == "Windows":
        try:
            # Pour la console
            os.system("chcp 65001 >NUL")
            # Pour Python lui-même (stdout/stderr)
            if hasattr(sys.stdout, "reconfigure"):
                sys.stdout.reconfigure(encoding="utf-8")
            if hasattr(sys.stderr, "reconfigure"):
                sys.stderr.reconfigure(encoding="utf-8")
        except Exception as e:
            print(f"[AVERTISSEMENT] Impossible de configurer l'encodage UTF-8 : {e}")


# ========================
#     Notifications
# ========================


def notify_linux(msg: str) -> None:
    if not CONFIG.get("notifications", {}).get("enable_notifications", True):
        return
    safe = sanitize(msg)
    title = CONFIG.get("notifications", {}).get("title", "Alerte Intrusion")
    os.system(f'notify-send "{title}" "{safe}"')


def notify_windows(msg: str) -> None:
    if not CONFIG.get("notifications", {}).get("enable_notifications", True):
        return
    try:
        from win10toast import ToastNotifier

        toaster = ToastNotifier()
        title = CONFIG.get("notifications", {}).get("title", "Alerte Intrusion")
        toaster.show_toast(title, sanitize(msg), duration=5)
    except Exception as e:
        print(f"[ERREUR] Impossible d'afficher une notification Windows : {e}")


def get_notifier() -> Callable[[str], None]:
    os_name = platform.system()
    if os_name == "Linux":
        return notify_linux
    elif os_name == "Windows":
        return notify_windows
    else:
        return lambda m: print(f"[NOTIFICATION] {m}")


# ========================
#   Détection Linux (SSH)
# ========================


def detect_linux_journalctl(notify: Callable[[str], None]) -> None:
    """
    Détection des tentatives SSH échouées via journalctl.
    Plus moderne et sécurisé que auth.log directement.
    """
    print("[+] Surveillance Linux : SSH (journalctl)")
    write_log("Détection Linux démarrée (journalctl)")

    # Variables pour tracker les logs déjà vus
    cursor = None
    pattern = re.compile(r"Failed password for (invalid user )?(\S+) from ([\d\.]+)")

    try:
        # Première exécution : on récupère le cursor actuel (point de départ)
        result = subprocess.run(
            ["journalctl", "-u", "ssh", "--no-pager", "-q", "-n", "1", "-o", "json"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        if result.stdout.strip():
            try:
                last_entry = json.loads(result.stdout.strip())
                cursor = last_entry.get("__CURSOR")
            except json.JSONDecodeError:
                cursor = None

        print("[*] En attente d'événements SSH...")

        while True:
            # Construit la commande journalctl
            cmd = ["journalctl", "-u", "ssh", "--no-pager", "-o", "json", "-f"]

            if cursor:
                cmd.extend(["--after-cursor", cursor])

            try:
                # Lance journalctl en mode "follow" (like tail -f)
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                )

                for line in process.stdout:
                    if not line.strip():
                        continue

                    try:
                        entry = json.loads(line)
                        message = entry.get("MESSAGE", "")
                        cursor = entry.get("__CURSOR")

                        # Cherche le pattern "Failed password"
                        match = pattern.search(message)
                        if match:
                            _, user, ip = match.groups()
                            msg = f"Tentative SSH échouée – user={user}, ip={ip}"

                            print("[ALERTE]", msg)
                            notify(msg)
                            write_log(msg)

                    except json.JSONDecodeError:
                        continue

            except subprocess.TimeoutExpired:
                process.kill()
                continue

    except Exception as e:
        write_log(f"Erreur Linux : {e}")
        print("[ERREUR] Détection Linux stoppée :", e)
        sys.exit(1)


# ========================
#  Détection Windows (4625)
# ========================


def detect_windows(notify: Callable[[str], None]) -> None:
    """Détection des échecs de connexion Windows via pywin32."""
    print("[+] Surveillance Windows : EventID 4625")
    write_log("Détection Windows démarrée")

    try:
        import win32evtlog

        server = "localhost"
        logtype = "Security"
        flags = (
            win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        )
        handle = win32evtlog.OpenEventLog(server, logtype)

        last_record = 0

        while True:
            events = win32evtlog.ReadEventLog(handle, flags, 0)

            for event in events:
                if event.RecordNumber <= last_record:
                    continue

                last_record = event.RecordNumber

                if event.EventID == 4625:
                    # Récupère le message brut pour plus de fiabilité
                    message = event.StringInserts

                    # Extrait user et IP de manière plus robuste
                    user = "Inconnu"
                    ip = "Inconnu"

                    if message and len(message) >= 6:
                        user = message[5]  # Target User Name
                    if message and len(message) >= 20:
                        ip = message[19]  # Source Network Address

                    msg = f"Échec connexion Windows – user={user}, ip={ip}"
                    print("[ALERTE]", msg)
                    notify(msg)
                    write_log(msg)

            time.sleep(1)

    except Exception as e:
        write_log(f"Erreur Windows : {e}")
        print("[ERREUR] Détection Windows stoppée :", e)
        sys.exit(1)


# ========================
#          Main
# ========================


def main():
    load_config()
    setup_encoding_windows()
    print("[*] Démarrage du système de détection d'intrusion...")
    write_log("Script démarré")
    check_permissions()
    notify = get_notifier()

    os_name = platform.system()

    try:
        if os_name == "Linux":
            if CONFIG.get("enable_linux_detection", True):
                detect_linux_journalctl(notify)
            else:
                print("[INFO] Détection Linux désactivée dans la configuration.")
        elif os_name == "Windows":
            if CONFIG.get("enable_windows_detection", True):
                detect_windows(notify)
            else:
                print("[INFO] Détection Windows désactivée dans la configuration.")
        else:
            print(f"[ERREUR] OS non supporté : {os_name}")
            sys.exit(1)

    except KeyboardInterrupt:
        print("\n[*] Arrêt demandé par l'utilisateur.")
        write_log("Arrêt du script")
        sys.exit(0)


if __name__ == "__main__":
    main()
