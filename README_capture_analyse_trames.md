# capture_analyse_trames.py

Script Python qui capture le trafic réseau d'une interface, l'analyse, génère un rapport PDF puis ouvre la capture dans Wireshark.

## Fonctionnement

```
Vérifications -> Capture (dumpcap) -> Analyse (tshark) -> Rapport PDF (reportlab) -> Wireshark
```

1. Vérification de la présence de `dumpcap`, `tshark`, `wireshark` et du module `reportlab`, du compte utilisateur (non root) et de la durée.
2. Capture du trafic avec `dumpcap` pendant la durée demandée, dans un fichier `.pcapng`.
3. Lecture du fichier avec `tshark` pour en extraire des statistiques.
4. Génération d'un rapport PDF A4 avec `reportlab`.
5. Ouverture de la capture dans Wireshark.

## Prérequis

- Linux Debian/Ubuntu ou équivalent
- Python 3.8 ou supérieur
- Wireshark, tshark et reportlab :

```bash
sudo apt install wireshark tshark python3-reportlab
```

- Un accès `sudo` (utilisé pour la capture)

## Utilisation

```bash
python3 capture_analyse_trames.py -i <interface> [-d <secondes>] [-o <dossier>]
```

| Option | Obligatoire | Défaut | Description |
|---|---|---|---|
| `-i`, `--interface` | Oui | | Interface réseau (liste : `dumpcap -D`) |
| `-d`, `--duration` | Non | `60` | Durée de capture en secondes (minimum 1) |
| `-o`, `--output-dir` | Non | dossier courant | Dossier de sortie (créé si absent) |

Exemple :

```bash
python3 capture_analyse_trames.py -i eth0 -d 30 -o ./captures
```

Le script ne doit pas être lancé avec `sudo` : il appelle `sudo` lui-même pour la capture et refuse de s'exécuter en root.

## Fichiers produits

Dans le dossier de sortie, avec un horodatage `AAAAMMJJ_HHMMSS` :

- `capture_<horodatage>.pcapng` : capture brute
- `rapport_<horodatage>.pdf` : rapport d'analyse

## Détail des étapes

### Vérifications

- `require_programs()` contrôle la présence des trois programmes dans le `PATH` et refuse l'exécution en root.
- `require_reportlab()` contrôle la présence de `reportlab` avant la capture.

### Capture

- `sudo -v` demande le mot de passe avant le début de la capture.
- `sudo dumpcap -i <interface> -a duration:<N> -w <fichier>` capture le trafic et s'arrête après N secondes.
- `sudo chown` attribue le fichier à l'utilisateur courant afin que `tshark` et Wireshark puissent le lire.

### Analyse avec tshark

| Commande | Résultat |
|---|---|
| `-T fields -e frame.protocols` | Pile de protocoles de chaque trame (ex. `eth:ip:tcp:tls`) |
| `-q -z io,phs` | Hiérarchie des protocoles |
| `-q -z endpoints,ip` | Statistiques par adresse IP |
| `-q -z conv,ip` | Conversations entre paires d'adresses IP |
| `-Y dns.qry.name` | Noms DNS demandés |
| `-Y tls.handshake.extensions_server_name` | Noms de serveurs TLS (SNI) |

Chaque protocole est compté une seule fois par trame : `tcp: 120` signifie 120 trames contenant du TCP.

### Rapport PDF

- En-tête : date, interface, durée, fichier, nombre de trames
- Tableau des 25 protocoles les plus fréquents
- Hiérarchie des protocoles
- Points de terminaison IP
- Conversations IP
- Noms DNS demandés (30 maximum, dédupliqués, triés)
- Noms TLS/SNI (30 maximum, dédupliqués, triés)
- Mention des limites : le contenu chiffré n'est pas déchiffré

### Ouverture dans Wireshark

`subprocess.Popen(["wireshark", <capture>])` lance l'interface sans attendre sa fermeture.

## Gestion des erreurs

Les commandes externes passent par la fonction `run()`, qui convertit les erreurs (programme introuvable, code de retour non nul) en `RuntimeError`. `main()` affiche le message sur `stderr` et retourne le code 1. Le code 0 indique un succès.

## Notes techniques

- Les commandes sont passées sous forme de listes, sans `shell=True`.
- `tshark` relit le fichier à chaque statistique (6 passes) et les sorties sont conservées en mémoire.
- La capture n'a pas de limite de taille.
- Les listes DNS et TLS sont limitées à 30 entrées dans le PDF.
- `sudo -v` est interactif : le script nécessite un terminal.
- Wireshark antérieur à 3.0 : le champ `tls.handshake...` s'appelle `ssl.handshake...`.
