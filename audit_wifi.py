import os
import time
from scapy.all import sniff, Dot11Beacon, Dot11Elt
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet

MODULE_VERSION = "2.0 (M10-Passive-Compliance)"
OBSERVATION_ORIGIN = "Écoute RF Monitor (Scapy 802.11)"

def generate_pdf_report(networks):
    session = os.getenv('CYBERDECK_SESSION_ID', 'N/A')
    operator = os.getenv('CYBERDECK_OPERATOR', 'Inconnu')
    scenario = os.getenv('CYBERDECK_SCENARIO', 'N/A')
    target = os.getenv('CYBERDECK_TARGET', 'N/A')
    interface = os.getenv('CYBERDECK_INTERFACE', 'N/A')
    timestamp_utc = os.getenv('CYBERDECK_UTC_TIME', 'Inconnu')
    file_time = os.getenv('CYBERDECK_FILE_TIME', '000000_000000')

    output_path = f"audit_wifi_{session}_{file_time}.pdf"
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(Paragraph("Footprinting Wi-Fi (Écoute Passive Stricte)", styles['Title']))
    
    # Données communes
    elements.append(Paragraph(f"<b>Session / Scénario :</b> {session} / {scenario}", styles['Normal']))
    elements.append(Paragraph(f"<b>Opérateur / Cible :</b> {operator} / {target}", styles['Normal']))
    elements.append(Paragraph(f"<b>Interface / Version :</b> {interface} / {MODULE_VERSION}", styles['Normal']))
    elements.append(Paragraph(f"<b>Horodatage (UTC) :</b> {timestamp_utc}", styles['Normal']))
    elements.append(Paragraph(f"<b>Origine :</b> {OBSERVATION_ORIGIN}", styles['Normal']))
    elements.append(Spacer(1, 15))

    if not networks:
        elements.append(Paragraph("Aucune trame Beacon détectée. L'interface est-elle en mode Monitor ?", styles['Normal']))
    else:
        table_data = [['SSID', 'BSSID']]
        for bssid, ssid in networks.items():
            table_data.append([ssid, bssid])
            
        t = Table(table_data)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(t)

    doc.build(elements)
    print(f"\n[+] Rapport Wi-Fi généré : {output_path}")

def main():
    interface = os.getenv('CYBERDECK_INTERFACE', 'wlan0mon')
    print(f"[*] Écoute passive stricte 802.11 sur {interface} (30s)...")
    print("[!] Assurez-vous que l'interface est préalablement configurée en mode Monitor[cite: 3].")
    
    networks = {}

    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            bssid = pkt.addr2
            try:
                ssid = pkt[Dot11Elt].info.decode()
                if not ssid: ssid = "<Caché>"
            except:
                ssid = "<Erreur décodage>"
            if bssid not in networks:
                networks[bssid] = ssid
                print(f"[+] AP Détecté : {ssid} ({bssid})")

    try:
        sniff(iface=interface, prn=packet_handler, timeout=30)
        generate_pdf_report(networks)
    except Exception as e:
        print(f"[!] Erreur de capture : {e}. L'interface est-elle en mode Monitor ?")

if __name__ == "__main__":
    main()
