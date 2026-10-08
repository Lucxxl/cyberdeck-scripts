import subprocess
import datetime
import os
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

CHEMIN_RAPPORT = "audit_wifi.pdf"

def scan_wifi():
    print("[*] Scan des réseaux Wi-Fi environnants en cours (Mode Passif)...")
    try:
        # nmcli liste les réseaux sans couper la connexion actuelle
        result = subprocess.run(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY", "dev", "wifi", "list"],
            capture_output=True, text=True, check=True
        )
    except Exception as e:
        print("[-] Erreur : Impossible d'utiliser la carte Wi-Fi. (Normal sur une VM sans adaptateur USB).")
        return []

    networks = []
    for line in result.stdout.strip().split('\n'):
        if not line: continue
        
        # nmcli échappe les deux points des adresses MAC (\:). On les remplace temporairement.
        line_clean = line.replace('\\:', '-')
        parts = line_clean.split(':')
        
        if len(parts) >= 4:
            ssid = parts[0] if parts[0] else "<Réseau Masqué>"
            bssid = parts[1].replace('-', ':')
            signal = parts[2]
            security = parts[3]
            
            # Évaluation basique des vulnérabilités
            vuln_level = "Sécurisé"
            if not security or "OPEN" in security.upper() or security.strip() == "":
                vuln_level = "CRITIQUE (Ouvert)"
            elif "WEP" in security.upper():
                vuln_level = "ÉLEVÉ (WEP obsolète)"
                
            networks.append([ssid, bssid, f"{signal}%", security, vuln_level])
            
    # Tri des réseaux par puissance de signal (du plus proche au plus éloigné)
    networks.sort(key=lambda x: int(x[2].strip('%')) if x[2].strip('%').isdigit() else 0, reverse=True)
    return networks

def generate_pdf(networks, output_path):
    print("[*] Génération du rapport PDF...")
    doc = SimpleDocTemplate(output_path, pagesize=A4)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='CenterTitle', parent=styles['Title'], alignment=TA_CENTER))
    
    elements = []
    date_scan = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    elements.append(Paragraph("Rapport d'Audit Wi-Fi", styles['CenterTitle']))
    elements.append(Paragraph(f"Date : {date_scan}", styles['Normal']))
    elements.append(Spacer(1, 15))
    
    if not networks:
        elements.append(Paragraph("Aucun réseau détecté. Vérifiez que la carte Wi-Fi est active.", styles['Normal']))
    else:
        # En-têtes du tableau
        data = [["SSID (Nom du réseau)", "BSSID (Adresse MAC)", "Signal", "Chiffrement", "Vulnérabilité"]]
        data.extend(networks)
        
        table = Table(data, colWidths=[120, 100, 40, 100, 100])
        
        ts = TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#23395d")),
            ('TEXTCOLOR', (0,0), (-1,0), colors.white),
            ('ALIGN', (0,0), (-1,-1), 'CENTER'),
            ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('PADDING', (0,0), (-1,-1), 5),
        ])
        
        # Coloration conditionnelle pour mettre en évidence les réseaux vulnérables
        for i, row in enumerate(networks, start=1):
            if "CRITIQUE" in row[4]:
                ts.add('BACKGROUND', (4, i), (4, i), colors.red)
                ts.add('TEXTCOLOR', (4, i), (4, i), colors.white)
            elif "ÉLEVÉ" in row[4]:
                ts.add('BACKGROUND', (4, i), (4, i), colors.orange)
                
        table.setStyle(ts)
        elements.append(table)
        
    doc.build(elements)
    print(f"[+] Rapport enregistré : {os.path.abspath(output_path)}")

if __name__ == "__main__":
    net_list = scan_wifi()
    generate_pdf(net_list, CHEMIN_RAPPORT)
