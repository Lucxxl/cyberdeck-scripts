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
        print("  [w] - Audit Wi-Fi (Analyse des vulnérabilités)")
        print("  [b] - Scan Bluetooth (Détection BLE)")
        print("  [q] - Quitter")
        print("==================================================")
        print("Appuyez sur une touche pour lancer un module...")
        
        # Le script se met en pause ici et attend UNE SEULE touche
        choix = get_char().lower()
        
        if choix == 'a':
            print("\n[+] Démarrage du module d'Analyse LAN...\n")
            # Lance ton script Scapy comme si tu le tapais dans le terminal
            subprocess.run(["sudo", "python3", "/opt/cyberdeck/scan_net.py"])
            input("\n[>] Appuyez sur Entrée pour revenir au menu...")
            
        elif choix == 'w':
            print("\n[+] Module Wi-Fi en cours de développement...")
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
