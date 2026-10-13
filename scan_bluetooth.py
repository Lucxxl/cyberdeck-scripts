import os
import subprocess
import time
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

MODULE_VERSION = "2.0 (M13-GATT-Compliance)"
OBSERVATION_ORIGIN = "Bluetoothctl (BlueZ)"

def test_gatt_read(mac_address):
    """Tente une connexion et la lecture d'une caractéristique générique pour tester l'autorisation[cite: 3]."""
    print(f"[*] Tentative de lecture GATT sur {mac_address}...")
    try:
        # Script bluetoothctl automatisé pour se connecter et lire le Device Name (0x2a00)
        cmd = f"""
        connect {mac_address}
        sleep 3
        menu gatt
        select-attribute 00002a00-0000-1000-8000-00805f9b34fb
        read
        disconnect
        quit
        """
        process = subprocess.Popen(['bluetoothctl'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = process.communicate(cmd)
        
        if "Authentication Failed" in out or "not authorized" in out.lower():
            return "Refusé (Authentification/Autorisation requise)"
        elif "Value:" in out:
            return "Lecture Autorisée (Donnée accessible en clair)"
        else:
            return "Échec de connexion ou caractéristique introuvable"
    except Exception as e:
        return f"Erreur outil: {str(e)}"

def scan_ble():
    devices = []
    try:
        subprocess.run(["bluetoothctl", "scan", "on"], stdout=subprocess.DEVNULL)
        time.sleep(10)
        subprocess.run(["bluetoothctl", "scan", "off"], stdout=subprocess.DEVNULL)
        
        result = subprocess.check_output(["bluetoothctl", "devices"], text=True)
        for line in result.strip().split('\n'):
            if line.startswith("Device"):
                parts = line.split(' ', 2)
                if len(parts) >= 3:
                    devices.append([parts[1], parts[2]])
    except Exception as e:
        print(f"[!] Erreur scan BLE : {e}")
    return devices

def generate_pdf_report(devices, target_mac, gatt_result):
    session = os.getenv('CYBERDECK_SESSION_ID', 'N/A')
    operator = os.getenv('CYBERDECK_OPERATOR', 'Inconnu')
    scenario = os.getenv('CYBERDECK_SCENARIO', 'N/A')
    timestamp_utc = os.getenv('CYBERDECK_UTC_TIME', 'Inconnu')
    file_time = os.getenv('CYBERDECK_FILE_TIME', '000000_000000')

    output_path = f"audit_bluetooth_{session}_{file_time}.pdf"
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(Paragraph("Test de Permissions GATT (BLE)", styles['Title']))
    
    # Données communes
    elements.append(Paragraph(f"<b>Session / Scénario :</b> {session} / {scenario}", styles['Normal']))
    elements.append(Paragraph(f"<b>Opérateur :</b> {operator}", styles['Normal']))
    elements.append(Paragraph(f"<b>Horodatage (UTC) :</b> {timestamp_utc}", styles['Normal']))
    elements.append(Paragraph(f"<b>Origine :</b> {OBSERVATION_ORIGIN} | <b>Version :</b> {MODULE_VERSION}", styles['Normal']))
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Appareils détectés :", styles['Heading2']))
    if not devices:
        elements.append(Paragraph("Aucun appareil BLE détecté.", styles['Normal']))
    else:
        t = Table([['MAC', 'Nom']] + devices)
        t.setStyle(TableStyle([('BACKGROUND', (0,0), (-1,0), colors.darkblue), ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke), ('GRID', (0,0), (-1,-1), 1, colors.black)]))
        elements.append(t)

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Test d'autorisation sur la cible :", styles['Heading2']))
    elements.append(Paragraph(f"<b>Cible désignée :</b> {target_mac}", styles['Normal']))
    elements.append(Paragraph(f"<b>Résultat d'accès GATT :</b> {gatt_result}", styles['Normal']))
    elements.append(Paragraph("<i>Note: La présence d'un service ne prouve pas l'absence de chiffrement/autorisation[cite: 3].</i>", styles['Normal']))

    doc.build(elements)
    print(f"\n[+] Rapport BLE généré : {output_path}")

def main():
    target = os.getenv('CYBERDECK_TARGET', 'N/A')
    print("[*] Scan des appareils BLE...")
    devices = scan_ble()
    
    gatt_result = "Non testé (cible non spécifiée avec une adresse MAC valide)"
    if target != 'N/A' and target != 'LAN' and len(target.split(':')) == 6:
        gatt_result = test_gatt_read(target)
        
    generate_pdf_report(devices, target, gatt_result)

if __name__ == "__main__":
    main()
