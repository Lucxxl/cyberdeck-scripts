#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERDECK - Orchestrateur offensif (Red Team Edition)
Pilote la chaîne d'attaque : énumération -> interception -> Wi-Fi -> BLE,
tout en conservant le contexte de session et la génération du manifeste
de preuves (chaîne de custody) propre au cyberdeck.
"""
import os
import sys
import tty
import glob
import json
import uuid
import hashlib
import termios
import subprocess
from datetime import datetime, timezone


def getch():
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    return ch


def generate_manifest(session_id):
    """Génère le manifeste SHA-256 des preuves de la session."""
    print("\n[*] Génération du manifeste des preuves...")
    manifest = {
        "session_id": session_id,
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "operator": os.environ.get("CYBERDECK_OPERATOR", "N/A"),
        "scenario": os.environ.get("CYBERDECK_SCENARIO", "N/A"),
        "files": {},
    }
    patterns = (f"*{session_id}*.pdf", f"*{session_id}*.pcapng",
                f"*{session_id}*.cap", f"*{session_id}*.json")
    files = []
    for p in patterns:
        files += glob.glob(p)
    for f in sorted(set(files)):
        h = hashlib.sha256()
        try:
            with open(f, "rb") as fo:
                for block in iter(lambda: fo.read(4096), b""):
                    h.update(block)
            manifest["files"][f] = h.hexdigest()
        except Exception as e:
            manifest["files"][f] = f"Erreur de lecture: {e}"
    out = f"manifest_{session_id}.json"
    with open(out, "w") as m:
        json.dump(manifest, m, indent=4)
    print(f"[+] Manifeste généré : {out} ({len(manifest['files'])} preuve(s))")


def init_session():
    os.system("clear")
    print("==========================================")
    print("     CYBERDECK INIT - Red Team Edition     ")
    print("==========================================\n")
    operator = input("ID Opérateur [Défaut: LUKA] : ").strip() or "LUKA"
    scenario = input("ID Scénario (ex: R01, R10) : ").strip() or "R00"
    target = input("Cible (IP, CIDR, MAC ou 'LAN') : ").strip() or "LAN"
    gateway = input("Passerelle (IP, pour le MITM) : ").strip() or ""
    interface = input("Interface (ex: eth0, wlan0, wlan0mon) : ").strip() or "eth0"

    session_id = uuid.uuid4().hex[:8].upper()
    ts_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    ts_file = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    os.environ.update({
        "CYBERDECK_SESSION_ID": session_id,
        "CYBERDECK_OPERATOR": operator,
        "CYBERDECK_SCENARIO": scenario,
        "CYBERDECK_TARGET": target,
        "CYBERDECK_GATEWAY": gateway,
        "CYBERDECK_INTERFACE": interface,
        "CYBERDECK_UTC_TIME": ts_utc,
        "CYBERDECK_FILE_TIME": ts_file,
    })
    print(f"\n[+] Session validée : {session_id}")
    print(f"[+] Horodatage UTC  : {ts_utc}")
    print("\nAppuyez sur une touche pour accéder au menu...")
    getch()


def run(cmd):
    """Lance un sous-module et gère son absence proprement."""
    try:
        subprocess.run(cmd)
    except FileNotFoundError as e:
        print(f"\n[!] Module introuvable : {e.filename}")


def main():
    init_session()
    sid = os.environ.get("CYBERDECK_SESSION_ID")
    iface = lambda: os.environ.get("CYBERDECK_INTERFACE", "eth0")
    target = lambda: os.environ.get("CYBERDECK_TARGET", "LAN")
    gw = lambda: os.environ.get("CYBERDECK_GATEWAY", "")

    while True:
        os.system("clear")
        print("=== MENU CYBERDECK (Red Team) ===")
        print(f"Session: {sid} | Op: {os.environ.get('CYBERDECK_OPERATOR')} "
              f"| Scén: {os.environ.get('CYBERDECK_SCENARIO')} | Cible: {target()}")
        print("=" * 50)
        print("  RECONNAISSANCE")
        print("  [e] - Énumération active (nmap : ports, services, OS)")
        print("  INTERCEPTION")
        print("  [m] - MITM actif (ARP spoof + extraction d'identifiants)")
        print("  WIFI")
        print("  [w] - Deauth + capture de handshake WPA")
        print("  [k] - Crack WPA par dictionnaire (handshake existant)")
        print("  BLUETOOTH")
        print("  [b] - Énumération GATT + test d'écriture (BLE)")
        print("  [q] - Quitter et générer le manifeste")
        print("=" * 50)
        print("Option : ", end="", flush=True)

        choice = getch().lower()
        print(choice)
        print("-" * 50)

        if choice == "e":
            run(["python3", "scan_enum.py", "-t", target(), "-p", "rapide"])
        elif choice == "m":
            cmd = ["sudo", "-E", "python3", "mitm_intercept.py",
                   "-t", target(), "-i", iface()]
            if gw():
                cmd += ["-g", gw()]
            run(cmd)
        elif choice == "w":
            run(["sudo", "-E", "python3", "wifi_attack.py", "-i", iface()])
        elif choice == "k":
            cap = input("Fichier de capture (.cap/.pcapng) : ").strip()
            bssid = input("BSSID cible : ").strip()
            wl = input("Dictionnaire : ").strip()
            if cap and bssid and wl:
                run(["python3", "wpa_handshake_audit.py",
                     "-c", cap, "-b", bssid, "-w", wl])
            else:
                print("[-] Paramètres incomplets.")
        elif choice == "b":
            run(["python3", "ble_attack.py", "-t", target()])
        elif choice == "q":
            print("\n[*] Fin de session. Fermeture du Cyberdeck.")
            generate_manifest(sid)
            break
        else:
            print("\n[-] Option invalide.")

        if choice != "q":
            print("\nAppuyez sur une touche pour revenir au menu...")
            getch()


if __name__ == "__main__":
    main()
