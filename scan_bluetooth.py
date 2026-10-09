import subprocess
import time
import datetime
import os
import re
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

CHEMIN_RAPPORT = "rapport_bluetooth_ble.pdf"
TEMPS_SCAN = 15

def scan_bluetooth():
    print(f"[*] Écoute passive du spectre Bluetooth Low Energy ({TEMPS_SCAN}s)...")
    
    # Lancement du scan avec l'outil natif linux bluetoothctl
    scan_cmd = ["bluetoothctl", "--timeout", str(TEMPS_SCAN), "scan", "le"]
    try:
        result = subprocess.run(scan_cmd, capture_output=True, text=True)
    except Exception as e:
        print(f"[-] Erreur : Outil bluetoothctl introuvable. {e}")
        return []

    devices = {}
    
    # Analyse de la sortie brute (ex: "[NEW] Device AA:BB:CC:DD:EE:FF Nom")
    for line in result.stdout.split('\n'):
        match = re.search(r'Device ([0-9A-F:]{17}) (.*)', line)
        if match:
            mac = match.group(1)
            reste = match.group(2).strip()
            
            if mac not in devices:
                devices[mac] = {"name": "<Masqué/Inconnu>", "rssi": "N/A"}
            
            if reste.startswith("RSSI:"):
                devices[mac]["rssi"] = reste.split(" ")[1] + " dBm"
            elif reste.startswith("TxPower:") or reste.startswith("ManufacturerData:"):
                continue # On ignore ces données techniques pour ce rapport
            else:
                # Si le texte restant n'est pas juste l'adresse MAC répétée, c'est le nom
                if reste != mac and reste != mac.replace(":", "-"):
                    devices[mac]["name"] = reste

    # Formatage pour le PDF
    device_list = []
    for mac, data in devices.items():
        device_list.append([mac, data["name"], data["rssi"]])
        
    # Tri par nom (afficher les périphériques identifiés en premier)
    device_list.sort(key=lambda x: (x[1] == "<Masqué/Inconnu>", x[0]))
    return device_list

def generate_pdf(devices, output_path):
    print("[*] Génération du rapport d'exfiltration PDF...")
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CenterTitle', parent=styles['Title'], alignment=TA_CENTER))
    
    elements = []
    date_scan = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    elements.append(Paragraph("Reconnaissance Bluetooth (BLE)", styles['CenterTitle']))
    elements.append(Paragraph(f"Date : {date_scan}", styles['Normal']))
    elements.append(Spacer(1, 15))
    
    if not devices:
        elements.append(Paragraph("Aucun périphérique BLE détecté. Assurez-vous que le service Bluetooth est actif.", styles['Normal']))
    else:
        data = [["Adresse MAC (Cible)", "Nom du périphérique", "Signal (RSSI)"]]
        data.extend(devices)
        
        table = Table(data, colWidths=[130, 200, 100])
        ts = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#23395d")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 9),
            ('PADDING', (0,0), (-1,-1), 5),
        ])
        table.setStyle(ts)
        elements.append(table)
        
    doc.build(elements)
    print(f"[+] Rapport enregistré : {os.path.abspath(output_path)}")

if __name__ == "__main__":
    found_devices = scan_bluetooth()
    generate_pdf(found_devices, CHEMIN_RAPPORT)
