import os
import sys
import argparse
import subprocess
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

MODULE_VERSION = "1.1 (M03-Compliance)"
OBSERVATION_ORIGIN = "Capture brute (dumpcap/tshark)"

def check_privileges():
    if os.geteuid() == 0:
        print("[!] ERREUR : Ce script ne DOIT PAS être lancé en root[cite: 3].")
        sys.exit(1)

def generate_pdf(pcap_file, dns_stats, http_stats):
    session = os.getenv('CYBERDECK_SESSION_ID', 'N/A')
    operator = os.getenv('CYBERDECK_OPERATOR', 'Inconnu')
    scenario = os.getenv('CYBERDECK_SCENARIO', 'N/A')
    target = os.getenv('CYBERDECK_TARGET', 'N/A')
    interface = os.getenv('CYBERDECK_INTERFACE', 'N/A')
    timestamp_utc = os.getenv('CYBERDECK_UTC_TIME', 'Inconnu')
    file_time = os.getenv('CYBERDECK_FILE_TIME', '000000_000000')

    actual_output_path = f"analyse_trames_{session}_{file_time}.pdf"
    
    doc = SimpleDocTemplate(actual_output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    elements.append(Paragraph("Rapport d'Analyse de Trames", styles['Title']))
    
    # Données communes obligatoires[cite: 3]
    elements.append(Paragraph(f"<b>Session / Scénario :</b> {session} / {scenario}", styles['Normal']))
    elements.append(Paragraph(f"<b>Opérateur / Cible :</b> {operator} / {target}", styles['Normal']))
    elements.append(Paragraph(f"<b>Interface / Version :</b> {interface} / {MODULE_VERSION}", styles['Normal']))
    elements.append(Paragraph(f"<b>Horodatage (UTC) :</b> {timestamp_utc}", styles['Normal']))
    elements.append(Paragraph(f"<b>Origine :</b> {OBSERVATION_ORIGIN} (Fichier: {pcap_file})", styles['Normal']))
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Requêtes DNS Observées (Limites: DoH/DoT non visibles) :", styles['Heading2']))
    if not dns_stats:
        elements.append(Paragraph("Aucune requête DNS en clair détectée.", styles['Normal']))
    else:
        for line in dns_stats.splitlines():
            elements.append(Paragraph(line, styles['Normal']))
            
    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Trafic HTTP en clair :", styles['Heading2']))
    if not http_stats:
        elements.append(Paragraph("Aucun trafic HTTP en clair détecté.", styles['Normal']))
    else:
        for line in http_stats.splitlines():
            elements.append(Paragraph(line, styles['Normal']))

    doc.build(elements)
    print(f"[+] Rapport PDF généré : {actual_output_path}")

def main():
    check_privileges()
    
    parser = argparse.ArgumentParser(description="Capture et analyse de trames")
    parser.add_argument("-i", "--interface", required=True, help="Interface réseau")
    parser.add_argument("-d", "--duree", type=int, required=True, help="Durée de capture (sec)")
    args = parser.parse_args()

    session_id = os.getenv('CYBERDECK_SESSION_ID', 'local')
    pcap_filename = f"capture_{session_id}.pcapng"

    print(f"[*] Capture via dumpcap sur {args.interface} ({args.duree}s)...")
    try:
        subprocess.run(["dumpcap", "-i", args.interface, "-a", f"duration:{args.duree}", "-w", pcap_filename], check=True)
        
        dns_output = subprocess.check_output(
            ["tshark", "-r", pcap_filename, "-Y", "dns.flags.response == 0", "-T", "fields", "-e", "dns.qry.name"], text=True
        )
        http_output = subprocess.check_output(
            ["tshark", "-r", pcap_filename, "-Y", "http.request", "-T", "fields", "-e", "http.host", "-e", "http.request.uri"], text=True
        )

        generate_pdf(pcap_filename, dns_output, http_output)
        subprocess.Popen(["wireshark", "-r", pcap_filename], stderr=subprocess.DEVNULL)
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Erreur de processus réseau : {e}")
    except FileNotFoundError:
        print("[!] Erreur : dumpcap ou tshark non installé.")

if __name__ == "__main__":
    main()
