import os
import sys
import tty
import termios
import subprocess
import uuid
import hashlib
import json
import glob
from datetime import datetime, timezone

def getch():
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def generate_manifest(session_id):
    """Génère le manifeste SHA-256 des preuves de la session."""
    print("\n[*] Génération du manifeste des preuves...")
    manifest_data = {
        "session_id": session_id,
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": {}
    }
    
    # Cherche les PDF et PCAPNG liés à cette session
    files = glob.glob(f"*{session_id}*.pdf") + glob.glob(f"*{session_id}*.pcapng")
    
    for f in files:
        sha256_hash = hashlib.sha256()
        try:
            with open(f, "rb") as file_obj:
                for byte_block in iter(lambda: file_obj.read(4096), b""):
                    sha256_hash.update(byte_block)
            manifest_data["files"][f] = sha256_hash.hexdigest()
        except Exception as e:
            manifest_data["files"][f] = f"Erreur de lecture: {str(e)}"
            
    manifest_file = f"manifest_{session_id}.json"
    with open(manifest_file, "w") as m:
        json.dump(manifest_data, m, indent=4)
    print(f"[+] Manifeste généré : {manifest_file}")

def init_session():
    os.system('clear')
    print("==========================================")
    print("   CYBERDECK INIT - Purple Team Edition   ")
    print("==========================================\n")
    
    operator = input("Entrez l'ID Opérateur [Défaut: LUKA] : ").strip() or "LUKA"
    scenario = input("Entrez l'ID Scénario (ex: M01, M10) : ").strip() or "M00"
    target = input("Entrez la cible (IP, MAC ou 'LAN') : ").strip() or "LAN"
    interface = input("Entrez l'interface réseau (ex: eth0, wlan0mon) : ").strip() or "eth0"
        
    session_id = uuid.uuid4().hex[:8].upper()
    timestamp_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    timestamp_file = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    
    os.environ['CYBERDECK_SESSION_ID'] = session_id
    os.environ['CYBERDECK_OPERATOR'] = operator
    os.environ['CYBERDECK_SCENARIO'] = scenario
    os.environ['CYBERDECK_TARGET'] = target
    os.environ['CYBERDECK_INTERFACE'] = interface
    os.environ['CYBERDECK_UTC_TIME'] = timestamp_utc
    os.environ['CYBERDECK_FILE_TIME'] = timestamp_file
    
    print(f"\n[+] Session validée  : {session_id}")
    print(f"[+] Horodatage UTC   : {timestamp_utc}")
    print("\nAppuyez sur une touche pour accéder au menu...")
    getch()

def main():
    init_session()
    session_id = os.environ.get('CYBERDECK_SESSION_ID')
    
    while True:
        os.system('clear')
        print("=== MENU CYBERDECK (Purple Team) ===")
        print(f"Session: {session_id} | Op: {os.environ.get('CYBERDECK_OPERATOR')} | Scénario: {os.environ.get('CYBERDECK_SCENARIO')}")
        print("====================================")
        print("[a] - Cartographie Passive (ARP, IPv6 ND, DHCP, LLDP)")
        print("[c] - Capture et Analyse de trames (Wireshark/PDF)")
        print("[w] - Footprinting Wi-Fi (Mode Passif Monitor)")
        print("[b] - Scan et Tests Bluetooth (BLE)")
        print("[q] - Quitter et générer le manifeste")
        print("====================================")
        print("Choisissez une option : ", end="", flush=True)
        
        choice = getch().lower()
        print(choice)
        print("-" * 36)
        
        try:
            if choice == 'a':
                subprocess.run(["python3", "scan_net.py"])
            elif choice == 'c':
                subprocess.run(["python3", "capture_analyse_trames.py", "-i", os.environ.get('CYBERDECK_INTERFACE'), "-d", "30"])
            elif choice == 'w':
                subprocess.run(["python3", "audit_wifi.py"])
            elif choice == 'b':
                subprocess.run(["python3", "scan_bluetooth.py"])
            elif choice == 'q':
                print("\n[*] Fin de session. Fermeture du Cyberdeck.")
                generate_manifest(session_id)
                break
            else:
                print("\n[-] Option invalide.")
        except FileNotFoundError as e:
            print(f"\n[!] Erreur: Module introuvable ({e.filename}).")
            
        if choice != 'q':
            print("\nAppuyez sur une touche pour revenir au menu...")
            getch()

if __name__ == "__main__":
    main()
