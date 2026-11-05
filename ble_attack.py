#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERDECK - Module BLE offensif (énumération GATT complète + test d'écriture)
Scan BLE enrichi (RSSI, constructeur, trackers), puis sur une cible désignée :
énumération de tous les services et caractéristiques GATT, test de lecture ET
d'écriture sur les caractéristiques accessibles sans authentification.

Refonte offensive de scan_bluetooth.py / scan_bluev.py : on ne lit plus une
seule caractéristique, on cartographie toute la surface GATT et on démontre
l'écart entre « lisible » et « modifiable » sur un objet mal protégé.

À réserver à un objet BLE de test que vous possédez.
"""
from __future__ import annotations

import os
import re
import sys
import json
import time
import platform
import argparse
import subprocess
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

MODULE_VERSION = "3.0 (BLE-GATT-Offensive)"
OBSERVATION_ORIGIN = "Bluetoothctl / gatttool (BlueZ)"

COMPANY_IDS = {
    0x0006: "Microsoft", 0x004C: "Apple", 0x0075: "Samsung",
    0x00E0: "Google", 0x0157: "Xiaomi", 0x0087: "Garmin",
    0x0059: "Nordic", 0x000F: "Broadcom", 0x0089: "Fitbit",
    0x00D2: "Bose", 0x012D: "Sony", 0x0171: "Amazon",
    0x02E5: "Espressif", 0x0001: "Nokia", 0x0002: "Intel",
}
TRACKER_SIGNATURES = {
    0x004C: "Apple (AirTag / FindMy)",
    0x0075: "Samsung (SmartTag)",
    0x0157: "Xiaomi (Mi Tracker)",
}
TRACKER_KEYWORDS = ["airtag", "tile", "smarttag", "tracker", "chipolo", "findmy"]

# Caractéristique générique "Device Name" utilisée comme témoin d'écriture.
GENERIC_NAME_UUID = "00002a00-0000-1000-8000-00805f9b34fb"


def classify_signal(rssi):
    if rssi is None or rssi == 0:
        return "Inconnu"
    if rssi >= -50:
        return "Tres proche"
    if rssi >= -65:
        return "Proche"
    if rssi >= -80:
        return "Moyen"
    return "Loin"


def detect_tracker(company_id, name):
    name_l = (name or "").lower()
    if company_id in TRACKER_SIGNATURES and name_l in ("", "unknown", "inconnu"):
        return TRACKER_SIGNATURES[company_id]
    for kw in TRACKER_KEYWORDS:
        if kw in name_l:
            return f"Tracker détecté par nom ({kw})"
    return None


def scan_ble(duree: int = 10) -> list:
    """Scan BLE avec infos enrichies (MAC, nom, RSSI, constructeur, tracker)."""
    devices = []
    try:
        subprocess.run(["bluetoothctl", "scan", "on"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(duree)
        subprocess.run(["bluetoothctl", "scan", "off"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result = subprocess.check_output(["bluetoothctl", "devices"], text=True)

        for line in result.strip().split("\n"):
            if not line.startswith("Device"):
                continue
            parts = line.split(" ", 2)
            if len(parts) < 3:
                continue
            mac, name = parts[1], parts[2]
            rssi = company_id = company_name = None
            try:
                info = subprocess.check_output(["bluetoothctl", "info", mac],
                                               text=True, timeout=5)
                m = re.search(r"RSSI:\s*(-?\d+)", info)
                if m:
                    rssi = int(m.group(1))
                m = re.search(r"ManufacturerData Key:\s*(0x[0-9a-fA-F]+)", info)
                if m:
                    company_id = int(m.group(1), 16)
                    company_name = COMPANY_IDS.get(company_id, f"0x{company_id:04X}")
            except Exception:
                pass
            devices.append({
                "mac": mac, "name": name, "rssi": rssi,
                "company_name": company_name,
                "tracker": detect_tracker(company_id, name),
                "signal": classify_signal(rssi),
            })
    except Exception as e:
        print(f"[!] Erreur scan BLE : {e}")
    return devices


def enumerate_gatt(mac: str) -> list:
    """Énumère tous les services et caractéristiques GATT de la cible.

    Retourne une liste de dicts : handle, uuid, propriétés (read/write/notify).
    Utilise gatttool (BlueZ) en mode primary + characteristics.
    """
    chars = []
    try:
        out = subprocess.check_output(
            ["gatttool", "-b", mac, "--characteristics"],
            text=True, timeout=20, stderr=subprocess.STDOUT)
    except Exception as e:
        print(f"[!] Énumération GATT impossible : {e}")
        return chars

    # Lignes type : handle = 0x0002, char properties = 0x02, char value handle
    # = 0x0003, uuid = 00002a00-0000-1000-8000-00805f9b34fb
    for line in out.splitlines():
        m = re.search(
            r"char value handle = (0x[0-9a-fA-F]+), uuid = ([0-9a-fA-F\-]+)", line)
        props = re.search(r"char properties = (0x[0-9a-fA-F]+)", line)
        if m:
            prop_val = int(props.group(1), 16) if props else 0
            chars.append({
                "handle": m.group(1),
                "uuid": m.group(2),
                "readable": bool(prop_val & 0x02),
                "writable": bool(prop_val & 0x08 or prop_val & 0x04),
                "notify": bool(prop_val & 0x10),
            })
    return chars


def test_read(mac: str, handle: str) -> str | None:
    try:
        out = subprocess.check_output(
            ["gatttool", "-b", mac, "--char-read", "-a", handle],
            text=True, timeout=10, stderr=subprocess.STDOUT)
        m = re.search(r"Characteristic value/descriptor:\s*(.+)", out)
        return m.group(1).strip() if m else None
    except Exception:
        return None


def test_write_safe(mac: str, handle: str, original_hex: str) -> str:
    """Teste si une caractéristique accepte une écriture non authentifiée,
    en réécrivant SA PROPRE valeur d'origine (aucune modification réelle)."""
    if not original_hex:
        return "Non testé (valeur initiale illisible)"
    value = original_hex.replace(" ", "")
    try:
        res = subprocess.run(
            ["gatttool", "-b", mac, "--char-write-req", "-a", handle, "-n", value],
            capture_output=True, text=True, timeout=10)
        combined = (res.stdout + res.stderr).lower()
        if "successfully" in combined or "written" in combined:
            return "ÉCRITURE ACCEPTÉE sans authentification"
        if "not permitted" in combined or "authentication" in combined:
            return "Refusée (authentification/permission requise)"
        return "Indéterminé"
    except Exception as e:
        return f"Erreur outil : {e}"


def confirm_authorization(mac: str) -> None:
    print("=" * 60)
    print(" CONFIRMATION D'AUTORISATION REQUISE")
    print("=" * 60)
    print(f"Objet BLE cible : {mac}")
    print(
        "\nL'énumération et surtout le test d'écriture GATT interagissent "
        "activement avec l'objet. À réserver à un objet de test vous appartenant."
    )
    confirmation = input("\nResaisissez la MAC cible pour confirmer : ").strip()
    if confirmation.lower() != mac.lower():
        print("[!] Confirmation invalide. Arrêt.", file=sys.stderr)
        sys.exit(1)


def generate_pdf_report(devices, target_mac, gatt_chars) -> str:
    session = os.getenv("CYBERDECK_SESSION_ID", "N/A")
    operator = os.getenv("CYBERDECK_OPERATOR", "Inconnu")
    scenario = os.getenv("CYBERDECK_SCENARIO", "N/A")
    timestamp_utc = os.getenv("CYBERDECK_UTC_TIME", "Inconnu")
    file_time = os.getenv("CYBERDECK_FILE_TIME",
                          datetime.now().strftime("%Y%m%d_%H%M%S"))
    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    output_path = f"ble_attack_{session}_{file_time}.pdf"
    json_path = f"ble_attack_{session}_{file_time}.json"
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("BLE offensif - Énumération & Test GATT", styles["Title"]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f"<b>Session / Scénario :</b> {session} / {scenario}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Opérateur :</b> {operator}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage session (UTC) :</b> {timestamp_utc}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage du test (UTC) :</b> {run_ts}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Origine :</b> {OBSERVATION_ORIGIN} | <b>Version :</b> {MODULE_VERSION}", styles["Normal"]))
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Appareils BLE détectés :", styles["Heading2"]))
    if not devices:
        elements.append(Paragraph("Aucun appareil BLE détecté.", styles["Normal"]))
    else:
        rows = [["MAC", "Nom", "RSSI", "Signal", "Constructeur", "Tracker"]]
        for d in devices:
            rows.append([
                d["mac"], (d["name"] or "?")[:18],
                str(d["rssi"]) if d["rssi"] else "-", d["signal"],
                (d["company_name"] or "?")[:14],
                d["tracker"] or "-",
            ])
        t = Table(rows, colWidths=[90, 85, 35, 70, 80, 105])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))
        elements.append(t)

    trackers = [d for d in devices if d.get("tracker")]
    if trackers:
        elements.append(Spacer(1, 12))
        elements.append(Paragraph("Trackers détectés :", styles["Heading2"]))
        for tr in trackers:
            elements.append(Paragraph(
                f"- {tr['mac']} : {tr['tracker']} (RSSI {tr['rssi']})", styles["Normal"]))

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Surface GATT de la cible :", styles["Heading2"]))
    elements.append(Paragraph(f"<b>Cible :</b> {target_mac}", styles["Normal"]))
    if not gatt_chars:
        elements.append(Paragraph(
            "Aucune caractéristique énumérée (connexion refusée, hors portée, "
            "ou cible non désignée).", styles["Normal"]))
    else:
        rows = [["Handle", "UUID", "Read", "Write", "Test lecture", "Test écriture"]]
        for c in gatt_chars:
            rows.append([
                c["handle"], c["uuid"][:8] + "...",
                "oui" if c["readable"] else "-",
                "oui" if c["writable"] else "-",
                (c.get("read_value") or "-")[:16],
                c.get("write_test") or "-",
            ])
        t = Table(rows, colWidths=[50, 70, 35, 35, 95, 170])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("FONTSIZE", (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Limites (Méthodologie) :", styles["Heading2"]))
    elements.append(Paragraph(
        "Le test d'écriture réécrit la valeur d'origine de chaque caractéristique : "
        "il prouve l'absence de contrôle d'accès sans modifier l'état de l'objet. "
        "Une caractéristique lisible/inscriptible sans authentification est une "
        "faiblesse de conception : un objet correctement protégé exige un appairage "
        "chiffré (Just Works n'offre aucune protection réelle).", styles["Normal"]))

    doc.build(elements)
    print(f"[+] Rapport PDF généré : {output_path}")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "meta": {"version": MODULE_VERSION, "origin": OBSERVATION_ORIGIN,
                     "timestamp_utc": run_ts, "host_os": platform.system()},
            "target_mac": target_mac,
            "devices": devices,
            "gatt": gatt_chars,
        }, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON exporté : {json_path}")
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(description="BLE offensif : énumération et test GATT.")
    parser.add_argument("-t", "--target", default=os.getenv("CYBERDECK_TARGET", ""),
                        help="MAC de la cible GATT. Défaut : CYBERDECK_TARGET.")
    parser.add_argument("--scan-time", type=int, default=10, help="Durée du scan BLE (s).")
    parser.add_argument("--no-write", action="store_true",
                        help="Énumérer et lire sans tester l'écriture.")
    parser.add_argument("--skip-confirmation", action="store_true")
    args = parser.parse_args()

    print("[*] Scan des appareils BLE...")
    devices = scan_ble(args.scan_time)
    print(f"\n[+] {len(devices)} appareil(s) détecté(s) :")
    for d in devices:
        flag = f"  [{d['tracker']}]" if d["tracker"] else ""
        rssi = f"{d['rssi']:>4} dBm" if d["rssi"] else "   -   "
        print(f"  {d['name'][:24]:<24} {d['mac']:<18} {rssi}  {d['signal']:<12}"
              f"{(d['company_name'] or '?'):<14}{flag}")

    target = args.target.strip()
    gatt_chars = []
    if target and target not in ("N/A", "LAN") and len(target.split(":")) == 6:
        if not args.skip_confirmation:
            confirm_authorization(target)
        print(f"\n[*] Énumération GATT de {target}...")
        gatt_chars = enumerate_gatt(target)
        print(f"[+] {len(gatt_chars)} caractéristique(s) énumérée(s).")
        for c in gatt_chars:
            if c["readable"]:
                c["read_value"] = test_read(target, c["handle"])
            if c["writable"] and not args.no_write:
                c["write_test"] = test_write_safe(
                    target, c["handle"], c.get("read_value", ""))
                if "ACCEPTÉE" in (c["write_test"] or ""):
                    print(f"  [!] {c['handle']} {c['uuid'][:8]} : écriture non protégée")
    else:
        print("\n[*] Pas de cible GATT valide : scan seul.")

    generate_pdf_report(devices, target or "N/A", gatt_chars)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
