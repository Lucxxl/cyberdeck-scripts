import os
from collections import Counter
from scapy.all import sniff, ARP, DHCP, ICMPv6ND_NS, ICMPv6ND_NA, IPv6
from fpdf import FPDF

# Définition de la version du module pour la traçabilité
MODULE_VERSION = "2.0 (M01-Compliance)"
OBSERVATION_ORIGIN = "Écoute passive LAN (Scapy)"

def generate_pdf_report(protocols_count, output_path="scan_net_report.pdf"):
    session = os.getenv('CYBERDECK_SESSION_ID', 'N/A')
    operator = os.getenv('CYBERDECK_OPERATOR', 'Inconnu')
    scenario = os.getenv('CYBERDECK_SCENARIO', 'N/A')
    target = os.getenv('CYBERDECK_TARGET', 'N/A')
    interface = os.getenv('CYBERDECK_INTERFACE', 'N/A')
    timestamp_utc = os.getenv('CYBERDECK_UTC_TIME', 'Inconnu')
    file_time = os.getenv('CYBERDECK_FILE_TIME', '000000_000000')

    actual_output_path = f"scan_net_{session}_{file_time}.pdf"
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', 15)
    pdf.cell(0, 10, txt="Cartographie et Compréhension de la Visibilité", ln=True, align='C')
    
    # Données communes exigées[cite: 3]
    pdf.set_font("Arial", size=10)
    pdf.cell(0, 5, txt=f"ID Session / Scénario : {session} / {scenario}", ln=True)
    pdf.cell(0, 5, txt=f"Opérateur : {operator} | Cible : {target} | Interface : {interface}", ln=True)
    pdf.cell(0, 5, txt=f"Horodatage (UTC) : {timestamp_utc}", ln=True)
    pdf.cell(0, 5, txt=f"Module Version : {MODULE_VERSION} | Origine : {OBSERVATION_ORIGIN}", ln=True)
    pdf.ln(10)

    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, txt="Événements observés par protocole (ARP, DHCP, IPv6 ND, LLDP) :", ln=True)
    pdf.set_font("Arial", size=10)
    
    if not protocols_count:
        pdf.cell(0, 10, txt="Aucun trafic pertinent détecté. (Le port est-il en miroir ?)", ln=True)
    else:
        for proto, count in protocols_count.items():
            pdf.cell(0, 8, txt=f"- {proto} : {count} paquets", ln=True)

    pdf.ln(10)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, txt="Limites de couverture (Méthodologie) :", ln=True)
    pdf.set_font("Arial", size=10)
    pdf.multi_cell(0, 5, txt="Une observation passive révèle uniquement les équipements qui communiquent "
                             "en diffusion (Broadcast/Multicast) sur le segment visible. Les flux unicast "
                             "entre deux hôtes silencieux ne sont pas capturés sans port miroir ou TAP.")

    pdf.output(actual_output_path)
    print(f"\n[+] Rapport PDF généré : {actual_output_path}")

def main():
    interface = os.getenv('CYBERDECK_INTERFACE', 'eth0')
    print(f"[*] Démarrage de l'écoute passive sur {interface} (30 secondes)...")
    
    protocols_count = Counter()

    def analyze_pcap(packet):
        if packet.haslayer(ARP):
            protocols_count["ARP"] += 1
        elif packet.haslayer(DHCP):
            protocols_count["DHCP"] += 1
        elif packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv
