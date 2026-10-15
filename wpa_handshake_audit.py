#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

AIRCRACK_BIN = "aircrack-ng"


def require_aircrack() -> None:
    if not shutil.which(AIRCRACK_BIN):
        print(
            f"[!] {AIRCRACK_BIN} introuvable. Installez-le avec : "
            "sudo apt install aircrack-ng",
            file=sys.stderr,
        )
        sys.exit(1)


def count_wordlist_lines(path: Path) -> int:
    count = 0
    with open(path, "r", errors="ignore") as f:
        for _ in f:
            count += 1
    return count


def build_limited_wordlist(source: Path, limit: int, dest: Path) -> int:
    """Écrit les `limit` premières lignes de `source` dans `dest`. Retourne le nombre écrit."""
    written = 0
    with open(source, "r", errors="ignore") as src, open(dest, "w") as out:
        for line in src:
            if written >= limit:
                break
            out.write(line)
            written += 1
    return written


def confirm_authorization(bssid: str, capture_file: str) -> None:
    """Oblige l'opérateur à ressaisir la cible pour confirmer l'autorisation."""
    print("=" * 60)
    print(" CONFIRMATION D'AUTORISATION REQUISE")
    print("=" * 60)
    print(f"Fichier de capture : {capture_file}")
    print(f"BSSID cible        : {bssid}")
    print(
        "\nCe test ne doit être exécuté que sur un réseau pour lequel vous "
        "disposez d'une autorisation explicite (réseau personnel ou mandat "
        "de test écrit)."
    )
    confirmation = input(
        f"\nResaisissez le BSSID cible pour confirmer et continuer : "
    ).strip()
    if confirmation.lower() != bssid.lower():
        print("[!] Confirmation invalide. Arrêt.", file=sys.stderr)
        sys.exit(1)


def run_aircrack(capture_file: str, bssid: str, wordlist: str) -> dict:
    """Lance aircrack-ng en mode non interactif et parse la sortie."""
    cmd = [
        AIRCRACK_BIN,
        "-a", "2",          # WPA/WPA2
        "-b", bssid,
        "-w", wordlist,
        "-l", "found_key.txt",  # écrit la clé trouvée si succès
        capture_file,
    ]

    print(f"[*] Lancement : {' '.join(cmd)}")
    start = time.monotonic()

    process = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    output_lines: list[str] = []
    try:
        # aircrack-ng peut demander de choisir un réseau s'il y en a plusieurs
        # dans la capture ; on répond "1" par défaut.
        out, _ = process.communicate(input="1\n", timeout=1800)
        output_lines = out.splitlines()
    except subprocess.TimeoutExpired:
        process.kill()
        out, _ = process.communicate()
        output_lines = out.splitlines() + ["[!] Délai dépassé (30 min)."]

    elapsed = time.monotonic() - start

    full_output = "\n".join(output_lines)
    key_found = None
    match = re.search(r"KEY FOUND!\s*\[\s*(.+?)\s*\]", full_output)
    if match:
        key_found = match.group(1)

    # extraction du débit de tentatives/sec rapporté par aircrack-ng si présent
    speed_match = re.search(r"([\d.]+)\s*k?/s", full_output)
    reported_speed = speed_match.group(0) if speed_match else "Non rapporté"

    return {
        "success": key_found is not None,
        "key": key_found,
        "elapsed_seconds": elapsed,
        "reported_speed": reported_speed,
        "raw_output": full_output,
        "returncode": process.returncode,
    }


def generate_pdf_report(
    capture_file: str,
    bssid: str,
    wordlist: str,
    wordlist_count: int,
    result: dict,
) -> str:
    session = os.getenv("CYBERDECK_SESSION_ID", "N/A")
    operator = os.getenv("CYBERDECK_OPERATOR", "Inconnu")
    scenario = os.getenv("CYBERDECK_SCENARIO", "N/A")
    timestamp_utc = os.getenv("CYBERDECK_UTC_TIME", "Inconnu")
    file_time = os.getenv("CYBERDECK_FILE_TIME", "000000_000000")
    run_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    output_path = f"audit_wpa_{session}_{file_time}.pdf"
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Test de Robustesse WPA/WPA2 par Dictionnaire", styles["Title"]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph(f"<b>Session / Scénario :</b> {session} / {scenario}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Opérateur :</b> {operator}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage session (UTC) :</b> {timestamp_utc}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage du test (UTC) :</b> {run_timestamp}", styles["Normal"]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("Paramètres du test", styles["Heading2"]))
    rows = [
        ["Fichier de capture", capture_file],
        ["BSSID cible", bssid],
        ["Dictionnaire", wordlist],
        ["Entrées testées", str(wordlist_count)],
        ["Durée d'exécution", f"{result['elapsed_seconds']:.1f} s"],
        ["Débit rapporté", result["reported_speed"]],
        ["Code retour aircrack-ng", str(result["returncode"])],
    ]
    table = Table([["Paramètre", "Valeur"]] + rows, colWidths=[160, 300])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.darkblue),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ]
        )
    )
    elements.append(table)
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Résultat", styles["Heading2"]))
    if result["success"]:
        elements.append(
            Paragraph(
                f"<b>Clé trouvée :</b> le mot de passe figurait dans le dictionnaire fourni.",
                styles["Normal"],
            )
        )
        elements.append(
            Paragraph(
                "La valeur en clair n'est volontairement pas reproduite dans ce rapport ; "
                "elle est disponible dans le fichier found_key.txt produit par aircrack-ng.",
                styles["Normal"],
            )
        )
    else:
        elements.append(
            Paragraph(
                "Aucune correspondance trouvée dans le dictionnaire fourni pour le nombre "
                "d'entrées testées. Cela ne garantit pas la robustesse du mot de passe : "
                "seul l'espace couvert par ce dictionnaire a été exclu.",
                styles["Normal"],
            )
        )

    elements.append(Spacer(1, 15))
    elements.append(
        Paragraph(
            "<i>Note : ce test porte uniquement sur le dictionnaire fourni par l'opérateur. "
            "Un résultat négatif n'est pas une preuve de robustesse absolue.</i>",
            styles["Normal"],
        )
    )

    doc.build(elements)
    return output_path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Test par dictionnaire sur un handshake WPA/WPA2 déjà capturé."
    )
    parser.add_argument("-c", "--capture", required=True, help="Fichier de capture (.cap/.pcapng) contenant le handshake")
    parser.add_argument("-b", "--bssid", required=True, help="BSSID du réseau cible")
    parser.add_argument("-w", "--wordlist", required=True, help="Fichier dictionnaire (liste de mots de passe à tester)")
    parser.add_argument(
        "-n", "--limit", type=int, default=None,
        help="Ne tester que les N premières entrées du dictionnaire (ex. 5000 pour un sous-ensemble de rockyou.txt)",
    )
    parser.add_argument("--skip-confirmation", action="store_true", help="Ignorer la confirmation interactive (déconseillé, usage scripté encadré uniquement)")
    args = parser.parse_args()

    require_aircrack()

    if not Path(args.capture).is_file():
        print(f"[!] Fichier de capture introuvable : {args.capture}", file=sys.stderr)
        return 1
    if not Path(args.wordlist).is_file():
        print(f"[!] Dictionnaire introuvable : {args.wordlist}", file=sys.stderr)
        return 1

    if not args.skip_confirmation:
        confirm_authorization(args.bssid, args.capture)

    wordlist_path = args.wordlist
    if args.limit:
        subset_path = Path(f"wordlist_subset_{args.limit}.txt")
        wordlist_count = build_limited_wordlist(Path(args.wordlist), args.limit, subset_path)
        wordlist_path = str(subset_path)
        print(f"[*] Sous-ensemble généré : {wordlist_count} entrées (sur {args.limit} demandées) -> {subset_path}")
    else:
        wordlist_count = count_wordlist_lines(Path(args.wordlist))
        print(f"[*] Dictionnaire : {wordlist_count} entrées")

    result = run_aircrack(args.capture, args.bssid, wordlist_path)

    print("\n" + "=" * 60)
    if result["success"]:
        print(f"[+] Clé trouvée. Voir found_key.txt")
    else:
        print("[-] Aucune correspondance dans le dictionnaire fourni.")
    print(f"[*] Durée : {result['elapsed_seconds']:.1f} s")
    print(f"[*] Débit rapporté par aircrack-ng : {result['reported_speed']}")

    report_path = generate_pdf_report(
        args.capture, args.bssid, wordlist_path, wordlist_count, result
    )
    print(f"[+] Rapport PDF généré : {report_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
