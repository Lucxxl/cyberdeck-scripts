import os
import subprocess
import time
import re
import json
import platform
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

MODULE_VERSION = "2.1 (M13-GATT-Compliance)"
OBSERVATION_ORIGIN = "Bluetoothctl (BlueZ)"

# Company IDs Bluetooth SIG
COMPANY_IDS = {
    0x0006: "Microsoft",  0x004C: "Apple",    0x0075: "Samsung",
    0x00E0: "Google",     0x0157: "Xiaomi",   0x0087: "Garmin",
    0x0059: "Nordic",     0x000F: "Broadcom", 0x0089: "Fitbit",
    0x00D2: "Bose",       0x012D: "Sony",     0x0171: "Amazon",
    0x02E5: "Espressif",  0x0001: "Nokia",    0x0002: "Intel",
}

# Signatures de trackers connus
TRACKER_SIGNATURES = {
    0x004C: "🍎 Apple (AirTag / FindMy)",
    0x0075: "📱 Samsung (SmartTag)",
    0x0157: "📱 Xiaomi (Mi Tracker)",
}

TRACKER_KEYWORDS = ["airtag", "tile", "smarttag", "tracker", "chipolo", "findmy"]


def test_gatt_read(mac_address):
    """Tente une connexion et la lecture d'une caractéristique générique pour tester l'autorisation."""
    print(f"[*] Tentative de lecture GATT sur {mac_address}...")
    try:
        cmd = f"""
        connect {mac_address}
        sleep 3
        menu gatt
        select-attribute 00002a00-0000-1000-8000-00805f9b34fb
        read
        disconnect
        quit
        """
        process = subprocess.Popen(
            ['bluetoothctl'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True
        )
        out, err = process.communicate(cmd)

        if "Authentication Failed" in out or "not authorized" in out.lower():
            return "Refusé (Authentification/Autorisation requise)"
        elif "Value:" in out:
            return "Lecture Autorisée (Donnée accessible en clair)"
        else:
            return "Échec de connexion ou caractéristique introuvable"
    except Exception as e:
        return f"Erreur outil: {str(e)}"


def rssi_to_distance(rssi, tx_power=-59):
    """Estimation de distance à partir du RSSI (formule log-distance path loss)."""
    if rssi == 0:
        return None
    try:
        ratio = (tx_power - rssi) / 20.0
        distance = round(10 ** ratio, 2)
        return distance
    except Exception:
        return None


def classify_signal(rssi):
    """Classe le signal en catégorie visuelle."""
    if rssi is None or rssi == 0:
        return "❓ Inconnu"
    if rssi >= -50:
        return "🟢 Très proche"
    elif rssi >= -65:
        return "🟡 Proche"
    elif rssi >= -80:
        return "🟠 Moyen"
    else:
        return "🔴 Loin"


def detect_tracker(company_id, name):
    """Détecte si l'appareil est un tracker connu."""
    if company_id in TRACKER_SIGNATURES and (not name or name.lower() in ["unknown", "inconnu"]):
        return TRACKER_SIGNATURES[company_id]
    for kw in TRACKER_KEYWORDS:
        if kw in name.lower():
            return f"🔍 Tracker détecté par nom ({kw})"
    return None


def scan_ble():
    """
    Scan BLE avec récupération des infos enrichies :
    MAC, nom, RSSI, constructeur, tracker.
    """
    devices = []
    try:
        subprocess.run(["bluetoothctl", "scan", "on"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(10)
        subprocess.run(["bluetoothctl", "scan", "off"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Liste des appareils connus
        result = subprocess.check_output(["bluetoothctl", "devices"], text=True)

        # Récupère aussi les infos live (RSSI) via "info"
        for line in result.strip().split('\n'):
            if not line.startswith("Device"):
                continue
            parts = line.split(' ', 2)
            if len(parts) < 3:
                continue

            mac = parts[1]
            name = parts[2]
            rssi = None
            company_id = None
            company_name = None

            # Tentative de récupération du RSSI et manufacturer via "info"
            try:
                info_out = subprocess.check_output(
                    ["bluetoothctl", "info", mac],
                    text=True, timeout=5
                )
                # RSSI
                m = re.search(r"RSSI:\s*(-?\d+)", info_out)
                if m:
                    rssi = int(m.group(1))

                # ManufacturerData (parfois présent)
                m = re.search(r"ManufacturerData Key:\s*(0x[0-9a-fA-F]+)", info_out)
                if m:
                    company_id = int(m.group(1), 16)
                    company_name = COMPANY_IDS.get(company_id, f"0x{company_id:04X}")
            except Exception:
                pass

            tracker = detect_tracker(company_id, name) if company_id or name else None

            devices.append({
                "mac": mac,
                "name": name,
                "rssi": rssi,
                "company_id": company_id,
                "company_name": company_name,
                "tracker": tracker,
                "signal": classify_signal(rssi),
                "distance_m": rssi_to_distance(rssi) if rssi else None,
            })

    except Exception as e:
        print(f"[!] Erreur scan BLE : {e}")
    return devices


def export_json(devices, target_mac, gatt_result, path):
    """Export des résultats en JSON pour analyse ultérieure."""
    data = {
        "meta": {
            "version": MODULE_VERSION,
            "origin": OBSERVATION_ORIGIN,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "host_os": platform.system(),
        },
        "target_mac": target_mac,
        "gatt_result": gatt_result,
        "devices": devices,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] JSON exporté : {path}")


def generate_pdf_report(devices, target_mac, gatt_result):
    session = os.getenv('CYBERDECK_SESSION_ID', 'N/A')
    operator = os.getenv('CYBERDECK_OPERATOR', 'Inconnu')
    scenario = os.getenv('CYBERDECK_SCENARIO', 'N/A')
    timestamp_utc = os.getenv('CYBERDECK_UTC_TIME',
                              datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"))
    file_time = os.getenv('CYBERDECK_FILE_TIME',
                          datetime.now().strftime("%Y%m%d_%H%M%S"))

    output_path = f"audit_bluetooth_{session}_{file_time}.pdf"
    json_path = f"audit_bluetooth_{session}_{file_time}.json"

    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Test de Permissions GATT (BLE)", styles['Title']))

    elements.append(Paragraph(f"<b>Session / Scénario :</b> {session} / {scenario}", styles['Normal']))
    elements.append(Paragraph(f"<b>Opérateur :</b> {operator}", styles['Normal']))
    elements.append(Paragraph(f"<b>Horodatage (UTC) :</b> {timestamp_utc}", styles['Normal']))
    elements.append(Paragraph(
        f"<b>Origine :</b> {OBSERVATION_ORIGIN} | <b>Version :</b> {MODULE_VERSION}",
        styles['Normal']
    ))
    elements.append(Spacer(1, 15))

    # === Appareils détectés ===
    elements.append(Paragraph("Appareils détectés :", styles['Heading2']))

    if not devices:
        elements.append(Paragraph("Aucun appareil BLE détecté.", styles['Normal']))
    else:
        rows = [["MAC", "Nom", "RSSI", "Signal", "Constructeur", "Tracker"]]
        for d in devices:
            rows.append([
                d["mac"],
                (d["name"] or "?")[:18],
                str(d["rssi"]) if d["rssi"] else "-",
                d["signal"],
                (d["company_name"] or "?")[:15],
                d["tracker"] if d["tracker"] else "-",
            ])

        t = Table(rows, colWidths=[90, 90, 40, 80, 85, 110])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        elements.append(t)

    # === Alertes trackers ===
    trackers = [d for d in devices if d.get("tracker")]
    if trackers:
        elements.append(Spacer(1, 15))
        elements.append(Paragraph("🚨 Trackers détectés :", styles['Heading2']))
        for t in trackers:
            elements.append(Paragraph(
                f"• <b>{t['mac']}</b> — {t['tracker']} (RSSI {t['rssi']})",
                styles['Normal']
            ))
        elements.append(Paragraph(
            "<i>Si tu ne reconnais pas un tracker, il peut te suivre.</i>",
            styles['Normal']
        ))

    # === Test GATT ===
    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Test d'autorisation sur la cible :", styles['Heading2']))
    elements.append(Paragraph(f"<b>Cible désignée :</b> {target_mac}", styles['Normal']))
    elements.append(Paragraph(f"<b>Résultat d'accès GATT :</b> {gatt_result}", styles['Normal']))
    elements.append(Paragraph(
        "<i>Note: La présence d'un service ne prouve pas l'absence de chiffrement/autorisation.</i>",
        styles['Normal']
    ))

    doc.build(elements)
    print(f"\n[+] Rapport BLE généré : {output_path}")

    # Export de mon  JSON 
    export_json(devices, target_mac, gatt_result, json_path)


def main():
    target = os.getenv('CYBERDECK_TARGET', 'N/A')
    print("[*] Scan des appareils BLE...")
    devices = scan_ble()

    # Affichage console 
    print(f"\n{'='*90}")
    print(f"📊 {len(devices)} appareil(s) détecté(s)")
    print(f"{'='*90}")
    for d in devices:
        flag = f"  {d['tracker']}" if d['tracker'] else ""
        rssi_str = f"{d['rssi']:>4} dBm" if d['rssi'] else "   -   "
        print(f"  📡 {d['name'][:25]:<25} {d['mac']:<18} {rssi_str:<12} "
              f"{d['signal']:<15}{(d['company_name'] or '?'):<18}{flag}")

    trackers = [d for d in devices if d.get("tracker")]
    if trackers:
        print(f"\n🚨 {len(trackers)} TRACKER(S) détecté(s) :")
        for t in trackers:
            print(f"   → {t['mac']} — {t['tracker']} (RSSI {t['rssi']})")

    # Test GATT
    gatt_result = "Non testé (cible non spécifiée avec une adresse MAC valide)"
    if target != 'N/A' and target != 'LAN' and len(target.split(':')) == 6:
        gatt_result = test_gatt_read(target)

    generate_pdf_report(devices, target, gatt_result)


if __name__ == "__main__":
    main()
