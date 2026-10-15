# scan_bluetooth.py - Scan BLE et test de permissions GATT

Script Python qui scanne les appareils Bluetooth à proximité, teste l'autorisation de lecture d'une caractéristique GATT sur une cible désignée, puis génère un rapport PDF.

## Fonctionnement

```
Scan BLE (bluetoothctl) -> Test de lecture GATT sur la cible -> Rapport PDF (reportlab)
```

1. Scan des appareils Bluetooth à portée pendant 10 secondes.
2. Si une cible au format adresse MAC est définie, tentative de connexion et de lecture de la caractéristique Device Name (UUID `00002a00-...`).
3. Génération d'un rapport PDF listant les appareils détectés et le résultat du test.

## Prérequis

- Linux avec BlueZ installé (fournit `bluetoothctl`)
- Un adaptateur Bluetooth actif
- Python 3
- Module `reportlab` :

```bash
sudo apt install python3-reportlab
```

## Utilisation

```bash
python3 scan_bluetooth.py
```

Le script ne prend aucun argument. Il lit ses paramètres dans des variables d'environnement, définies par exemple par le menu Cyberdeck :

| Variable | Rôle | Valeur par défaut si absente |
|---|---|---|
| `CYBERDECK_TARGET` | Cible du test GATT (adresse MAC) | `N/A` |
| `CYBERDECK_SESSION_ID` | Identifiant de session, utilisé dans le nom du rapport | `N/A` |
| `CYBERDECK_OPERATOR` | Opérateur, affiché dans le rapport | `Inconnu` |
| `CYBERDECK_SCENARIO` | Scénario, affiché dans le rapport | `N/A` |
| `CYBERDECK_UTC_TIME` | Horodatage affiché dans le rapport | `Inconnu` |
| `CYBERDECK_FILE_TIME` | Horodatage utilisé dans le nom du rapport | `000000_000000` |

Si ces variables ne sont pas définies, le script s'exécute avec les valeurs par défaut ci-dessus.

## Détail des fonctions

### `scan_ble()`

- Lance `bluetoothctl scan on`, attend 10 secondes, puis `bluetoothctl scan off`.
- Lit la liste des appareils connus avec `bluetoothctl devices`.
- Pour chaque ligne commençant par `Device`, extrait l'adresse MAC et le nom (`parts[1]`, `parts[2]`).
- Retourne une liste de paires `[MAC, Nom]`.
- Toute exception est interceptée et affichée ; la fonction retourne alors une liste vide.

### `test_gatt_read(mac_address)`

- N'est appelée que si `CYBERDECK_TARGET` est une adresse MAC valide (6 segments séparés par `:`) et différente de `LAN`.
- Construit une séquence de commandes `bluetoothctl` : connexion à l'appareil, pause de 3 secondes, passage au menu GATT, sélection de la caractéristique Device Name (`00002a00-0000-1000-8000-00805f9b34fb`), lecture, déconnexion.
- Envoie cette séquence à `bluetoothctl` via `subprocess.Popen` et `communicate()`.
- Analyse la sortie texte :

| Condition dans la sortie | Résultat retourné |
|---|---|
| `Authentication Failed` ou `not authorized` | Refusé (Authentification/Autorisation requise) |
| `Value:` | Lecture Autorisée (Donnée accessible en clair) |
| Autre cas | Échec de connexion ou caractéristique introuvable |
| Exception levée | Erreur outil: `<message>` |

### `generate_pdf_report(devices, target_mac, gatt_result)`

Construit un PDF au format lettre US (`letter`), nommé `audit_bluetooth_<session>_<file_time>.pdf`, contenant :

- Titre « Test de Permissions GATT (BLE) »
- Session, scénario, opérateur, horodatage UTC
- Origine de l'observation (`Bluetoothctl (BlueZ)`) et version du module
- Tableau des appareils détectés (adresse MAC, nom), ou la mention qu'aucun appareil n'a été détecté
- Cible désignée et résultat du test d'accès GATT
- Note indiquant que la présence d'un service ne prouve pas l'absence de chiffrement ou d'autorisation

### `main()`

Lit `CYBERDECK_TARGET`, lance `scan_ble()`, détermine si un test GATT doit être effectué selon la validité de la cible, puis appelle `generate_pdf_report()`.

## Format du nom de rapport

```
audit_bluetooth_<session_id>_<file_time>.pdf
```

## Notes techniques

- La détection d'une adresse MAC valide se limite à vérifier que la chaîne contient 6 segments séparés par `:` ; le format de chaque segment n'est pas contrôlé.
- Le scan BLE a une durée fixe de 10 secondes, non paramétrable en ligne de commande.
- La connexion GATT dépend de la pause fixe de 3 secondes après `connect` ; un appareil plus lent à répondre peut produire un résultat « Échec de connexion ».
- L'analyse du résultat GATT repose sur la recherche de sous-chaînes dans la sortie texte de `bluetoothctl`, dont le format peut varier selon la version de BlueZ.
- Le rapport est écrit dans le dossier courant.
