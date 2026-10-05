import time
import keyboard
import datetime
from scapy.all import sniff, ARP
from fpdf import FPDF

# Définir l'interface réseau de ta VM (souvent eth0, vérifie avec la commande 'ip a')
INTERFACE = "eth0"
CHEMIN_RAPPORT = "/home/kali/audit_lan_anomalies.pdf"
TEMPS_ECOUTE = 30 

def analyze_lan_traffic():
    print(f"[*] Écoute passive du réseau local sur {INTERFACE} ({TEMPS_ECOUTE}s)...")
    
    # On capture uniquement les paquets ARP
    packets = sniff(iface=INTERFACE, filter="arp", timeout=TEMPS_ECOUTE)
    
    results = []
    # Dictionnaire pour compter le nombre de requêtes par IP
    arp_requests = {}
    
    for pkt in packets:
        if ARP in pkt:
            src_ip = pkt[ARP].psrc
            src_mac = pkt[ARP].hwsrc
            
            # Opération 1 : "Who has ?" (Requête)
            if pkt[ARP].op == 1:
                target_ip = pkt[ARP].pdst
                msg = f"Requête ARP : {src_ip} ({src_mac}) demande l'adresse de {target_ip}"
                if msg not in results:
                    results.append(msg)
                
                # Comptage pour détection d'anomalie (scan réseau agressif)
                arp_requests[src_ip] = arp_requests.get(src_ip, 0) + 1
                
            # Opération 2 : "Is at" (Réponse)
            elif pkt[ARP].op == 2:
                msg = f"Réponse ARP : {src_ip} est à l'adresse MAC {src_mac}"
                if msg not in results:
                    results.append(msg)

    # Analyse comportementale basique
    anomalies = []
    for ip, count in arp_requests.items():
        if count > 15:
            anomalies.append(f"/!\\ ALERTE : {ip} a envoyé un nombre suspect de requêtes ARP ({count}). Scan réseau ou empoisonnement potentiel.")

    return results, anomalies

def generate_pdf_report(results, anomalies, output_path):
    print("[*] Génération du rapport de sécurité...")
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Helvetica", size=10)
    
    date_scan = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(0, 10, txt="Rapport de Sécurité : Analyse des Trames LAN", ln=True, align='C')
    pdf.set_font("Helvetica", size=10)
    pdf.cell(0, 10, txt=f"Date : {date_scan} | Interface : {INTERFACE}", ln=True, align='C')
    pdf.ln(5)
    
    # Section Anomalies
    pdf.set_font("Helvetica", style="B", size=12)
    pdf.set_text_color(200, 0, 0) # Rouge
    pdf.cell(0, 10, txt="Anomalies détectées :", ln=True)
    pdf.set_font("Helvetica", size=10)
    
    if not anomalies:
        pdf.set_text_color(0, 128, 0) # Vert
        pdf.cell(0, 6, txt="Aucun comportement suspect détecté.", ln=True)
    else:
        for alerte in anomalies:
            pdf.cell(0, 6, txt=alerte, ln=True)
            
    pdf.ln(5)
    
    # Section Trafic Normal
    pdf.set_text_color(0, 0, 0) # Noir
    pdf.set_font("Helvetica", style="B", size=12)
    pdf.cell(0, 10, txt="Trafic ARP intercepté :", ln=True)
    pdf.set_font("Helvetica", size=9)
    
    if not results:
        pdf.cell(0, 6, txt="Aucun trafic ARP détecté. Le réseau est silencieux.", ln=True)
    else:
        for line in results:
            pdf.cell(0, 6, txt=line, ln=True)

    pdf.output(output_path)
    print(f"[+] Rapport généré avec succès : {output_path}")

def trigger_action():
    print("\n[!] Touche '1' pressée. Début de l'analyse réseau...")
    trafic, alertes = analyze_lan_traffic()
    generate_pdf_report(trafic, alertes, CHEMIN_RAPPORT)
    print("[*] Routine terminée. En attente d'une nouvelle frappe...")

if __name__ == "__main__":
    print("[*] Service Blue Team démarré. En attente de la touche '1'...")
    keyboard.add_hotkey('1', trigger_action)
    keyboard.wait()
