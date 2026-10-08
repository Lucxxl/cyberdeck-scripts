import sys
import tty
import termios
import subprocess
import os

def get_char():
    """Lit un seul caractère au clavier sans attendre la touche Entrée."""
    fd = sys.stdin.fileno()
    old_settings = termios.tcgetattr(fd)
    try:
        # Passe le terminal en mode "raw" pour capturer la touche immédiatement
        tty.setraw(sys.stdin.fileno())
        ch = sys.stdin.read(1)
    finally:
        # Restaure le terminal dans son état normal
        termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
    return ch

def main():
    while True:
        os.system('clear') # Efface l'écran pour faire propre
        print("==================================================")
        print("            CYBERDECK - INTERFACE V1.0            ")
        print("==================================================")
        print("  [a] - Analyse passive du LAN (Détection ARP)")
        print("  [c] - Capture et Analyse de trames (Wireshark/PDF)")
        print("  [w] - Audit Wi-Fi (Analyse des vulnérabilités)")
        print("  [b] - Scan Bluetooth (Détection BLE)")
        print("  [q] - Quitter")
        print("==================================================")
        print("Appuyez sur une touche pour lancer un module...")
        
        # Le script se met en pause ici et attend UNE SEULE touche
        choix = get_char().lower()
        
        if choix == 'a':
            print("\n[+] Démarrage du module d'Analyse LAN...\n")
            # Récupère le chemin du dossier actuel pour lancer le bon script
            dossier_actuel = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(dossier_actuel, "scan_net.py")
            # Lance le script !
            subprocess.run(["sudo", "python3", script_path])
            input("\n[>] Appuyez sur Entrée pour revenir au menu...")
            

        elif choix == 'c':
            print("\n[+] Démarrage du module de Capture de Trames...\n")
            
            dossier_actuel = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(dossier_actuel, "capture_analyse_trames.py")

            # PAS de "sudo" ici ! On passe l'interface (i eth0) et la durée (-d 30)
            subprocess.run(["python3", script_path, "-i", "wlan0", "-d", "30"])

            input("\n[>] Appuyez sur Entrée pour revenir au menu...")


        elif choix == 'w':
            print("\n[+] Démarrage du module d'Audit Wi-Fi...\n")
            
            dossier_actuel = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(dossier_actuel, "audit_wifi.py")
            
            # Lancement classique sans sudo
            subprocess.run(["python3", script_path])
            
            input("\n[>] Appuyez sur Entrée pour revenir au menu...")
            
        elif choix == 'b':
            print("\n[+] Module Bluetooth en cours de développement...")
            input("\n[>] Appuyez sur Entrée pour revenir au menu...")
            
        elif choix == 'q' or choix == '\x03': # \x03 correspond à Ctrl+C
            os.system('clear')
            print("[!] Arrêt du Cyberdeck.")
            break

if __name__ == "__main__":
    main()
