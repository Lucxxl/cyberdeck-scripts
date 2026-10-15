# Cyberdeck - Menu de session Purple Team

Script Python en mode texte qui ouvre une session identifiée, propose un menu pour lancer les outils d'audit réseau, puis génère à la fermeture un manifeste SHA-256 des fichiers de preuves.

## Fonctionnement

```
Initialisation de session -> Menu -> Lancement d'un outil -> Retour au menu -> Quitter -> Manifeste SHA-256
```

1. Saisie des informations de session (opérateur, scénario, cible, interface).
2. Génération d'un identifiant de session et d'horodatages UTC.
3. Affichage d'une boucle de menu pilotée par une seule touche.
4. Lancement du script correspondant à l'option choisie.
5. À la sortie, génération du fichier `manifest_<session_id>.json`.

## Prérequis

- Linux (utilise `termios`, `tty` et la commande `clear`)
- Python 3
- Les scripts appelés par le menu, présents dans le dossier de lancement :
  - `scan_net.py`
  - `capture_analyse_trames.py`
  - `audit_wifi.py`
  - `scan_bluetooth.py`

## Utilisation

```bash
python3 <nom_du_script>.py
```

Le script est interactif et ne prend aucun argument.

### Saisie initiale

| Champ | Valeur par défaut | Exemple |
|---|---|---|
| ID Opérateur | `LUKA` | `LUKA` |
| ID Scénario | `M00` | `M01`, `M10` |
| Cible | `LAN` | IP, MAC ou `LAN` |
| Interface réseau | `eth0` | `eth0`, `wlan0mon` |

Une valeur vide applique la valeur par défaut.

### Menu

| Touche | Action | Commande lancée |
|---|---|---|
| `a` | Cartographie passive (ARP, IPv6 ND, DHCP, LLDP) | `python3 scan_net.py` |
| `c` | Capture et analyse de trames (Wireshark/PDF) | `python3 capture_analyse_trames.py -i <interface> -d 30` |
| `w` | Footprinting Wi-Fi (mode passif monitor) | `python3 audit_wifi.py` |
| `b` | Scan et tests Bluetooth (BLE) | `python3 scan_bluetooth.py` |
| `q` | Quitter et générer le manifeste | |

Toute autre touche affiche « Option invalide ». Après chaque action autre que `q`, le script attend une touche avant de réafficher le menu.

## Détail des fonctions

### `getch()`

Lit un seul caractère au clavier sans attendre la touche Entrée. Le terminal est passé en mode raw (`tty.setraw`) puis les paramètres d'origine sont restaurés (`termios.tcsetattr`) dans un bloc `finally`.

### `init_session()`

- Efface l'écran et demande les quatre informations de session.
- Génère l'identifiant de session : `uuid.uuid4().hex[:8].upper()` (8 caractères hexadécimaux en majuscules).
- Calcule deux horodatages UTC : un format lisible (`2026-01-01T12:00:00Z`) et un format de nom de fichier (`20260101_120000`).
- Enregistre les valeurs dans des variables d'environnement :

| Variable | Contenu |
|---|---|
| `CYBERDECK_SESSION_ID` | Identifiant de session |
| `CYBERDECK_OPERATOR` | ID opérateur |
| `CYBERDECK_SCENARIO` | ID scénario |
| `CYBERDECK_TARGET` | Cible |
| `CYBERDECK_INTERFACE` | Interface réseau |
| `CYBERDECK_UTC_TIME` | Horodatage UTC lisible |
| `CYBERDECK_FILE_TIME` | Horodatage pour noms de fichiers |

Ces variables sont héritées par les scripts lancés depuis le menu.

### `main()`

Appelle `init_session()`, puis boucle sur le menu. Chaque outil est lancé avec `subprocess.run`, qui attend la fin du script avant de rendre la main au menu. L'en-tête du menu rappelle l'identifiant de session, l'opérateur et le scénario.

### `generate_manifest(session_id)`

- Recherche dans le dossier courant les fichiers dont le nom correspond à `*<session_id>*.pdf` et `*<session_id>*.pcapng`.
- Calcule le SHA-256 de chaque fichier par blocs de 4096 octets.
- Écrit `manifest_<session_id>.json`.

Un fichier illisible est enregistré avec le message `Erreur de lecture: ...` à la place du hash.

## Format du manifeste

```json
{
    "session_id": "A1B2C3D4",
    "timestamp_utc": "2026-01-01T12:30:00Z",
    "files": {
        "rapport_A1B2C3D4.pdf": "<sha256>",
        "capture_A1B2C3D4.pcapng": "<sha256>"
    }
}
```

## Notes techniques

- La recherche des fichiers du manifeste se fait dans le dossier courant et repose sur la présence de l'identifiant de session dans le nom du fichier. `capture_analyse_trames.py` nomme ses fichiers `capture_<AAAAMMJJ_HHMMSS>.pcapng` et `rapport_<AAAAMMJJ_HHMMSS>.pdf` : ils ne contiennent pas l'identifiant de session et ne sont donc pas inclus dans le manifeste tel quel.
- L'exception `FileNotFoundError` n'est levée que si `python3` est introuvable. Si un script du menu est absent, c'est Python qui affiche l'erreur et le menu reprend normalement.
- Les variables d'environnement ne concernent que le processus du menu et ses processus enfants ; elles ne persistent pas après la fermeture.
- Les horodatages sont en UTC.
- L'interface saisie à l'initialisation est transmise à la capture (option `c`) avec une durée fixe de 30 secondes.
