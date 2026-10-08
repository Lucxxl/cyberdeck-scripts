#!/usr/bin/env python3
"""Capture network traffic, summarize it, create a PDF, then open it in Wireshark."""

from __future__ import annotations

import argparse
import collections
import datetime as dt
import html
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import textwrap


def run(command: list[str], *, capture_output: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            check=True,
            text=True,
            stdout=subprocess.PIPE if capture_output else None,
            stderr=subprocess.PIPE if capture_output else None,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(f"Commande introuvable : {command[0]}") from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        raise RuntimeError(
            f"La commande a échoué ({exc.returncode}) : {' '.join(command)}"
            + (f"\n{detail}" if detail else "")
        ) from exc


def require_programs() -> None:
    missing = [name for name in ("dumpcap", "tshark", "wireshark") if not shutil.which(name)]
    if missing:
        raise RuntimeError(
            "Programmes manquants : "
            + ", ".join(missing)
            + ". Installez Wireshark/tshark (par exemple : "
            "sudo apt install wireshark tshark python3-reportlab)."
        )
    if os.geteuid() == 0:
        raise RuntimeError(
            "Ne lancez pas ce script en root : il utilise sudo uniquement pour la capture "
            "et ouvrira ensuite Wireshark avec votre compte."
        )


def require_reportlab() -> None:
    if importlib.util.find_spec("reportlab") is None:
        raise RuntimeError(
            "Le module Python reportlab manque. Installez-le avec : "
            "sudo apt install python3-reportlab"
        )


def make_pdf(
    report_path: Path,
    capture_path: Path,
    interface: str,
    duration: int,
    packet_count: int,
    protocols: collections.Counter[str],
    hierarchy: str,
    endpoints: str,
    conversations: str,
    dns_names: list[str],
    tls_names: list[str],
) -> None:
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            Preformatted,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError(
            "Le module Python reportlab manque. Installez-le avec : "
            "sudo apt install python3-reportlab"
        ) from exc

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", parent=styles["Title"], alignment=TA_CENTER))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], spaceBefore=10))
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=8, leading=10))
    elements = [
        Paragraph("Rapport d'analyse de capture réseau", styles["ReportTitle"]),
        Spacer(1, 5 * mm),
        Paragraph(
            f"<b>Date :</b> {html.escape(dt.datetime.now().astimezone().strftime('%Y-%m-%d %H:%M:%S %Z'))}<br/>"
            f"<b>Interface :</b> {html.escape(interface)}<br/>"
            f"<b>Durée de capture :</b> {duration} secondes<br/>"
            f"<b>Fichier :</b> {html.escape(str(capture_path))}<br/>"
            f"<b>Trames capturées :</b> {packet_count}",
            styles["BodyText"],
        ),
        Paragraph("Protocoles observés", styles["Section"]),
    ]

    protocol_rows = [["Protocole", "Nombre de trames"]]
    protocol_rows.extend(
        [[name, str(count)] for name, count in protocols.most_common(25)]
    )
    if len(protocol_rows) == 1:
        protocol_rows.append(["Aucun protocole détecté", "0"])
    table = Table(protocol_rows, repeatRows=1, colWidths=[90 * mm, 55 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#23395d")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#eef2f7")]),
                ("PADDING", (0, 0), (-1, -1), 5),
            ]
        )
    )
    elements.extend([table, Paragraph("Hiérarchie des protocoles", styles["Section"])])

    def add_preformatted(title: str, content: str) -> None:
        elements.append(Paragraph(title, styles["Section"]))
        content = content.strip() or "Aucune donnée disponible."
        wrapped = "\n".join(
            textwrap.fill(line, width=100, subsequent_indent="  ") if line else ""
            for line in content.splitlines()
        )
        elements.append(Preformatted(html.escape(wrapped), styles["Code"]))

    add_preformatted("Résumé de la hiérarchie", hierarchy)
    add_preformatted("Points de terminaison IP", endpoints)
    add_preformatted("Conversations IP", conversations)
    add_preformatted("Noms DNS demandés (maximum 30)", "\n".join(dns_names[:30]))
    add_preformatted("Noms de serveurs TLS/SNI (maximum 30)", "\n".join(tls_names[:30]))
    elements.extend(
        [
            Spacer(1, 4 * mm),
            Paragraph(
                "Limites : ce rapport décrit uniquement les trames visibles dans cette capture. "
                "Le contenu chiffré (par exemple TLS) n'est pas déchiffré et les observations "
                "ne constituent pas, à elles seules, des constats de vulnérabilité.",
                styles["Small"],
            ),
        ]
    )
    document = SimpleDocTemplate(
        str(report_path),
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=18 * mm,
        title="Rapport d'analyse de capture réseau",
    )
    document.build(elements)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture le trafic d'une interface, produit un rapport PDF et ouvre la capture dans Wireshark."
    )
    parser.add_argument("-i", "--interface", required=True, help="Interface réseau (voir : dumpcap -D)")
    parser.add_argument(
        "-d", "--duration", type=int, default=60, help="Durée de capture en secondes (défaut : 60)"
    )
    parser.add_argument(
        "-o", "--output-dir", type=Path, default=Path.cwd(), help="Dossier de sortie (défaut : dossier courant)"
    )
    args = parser.parse_args()

    try:
        require_programs()
        require_reportlab()
        if args.duration < 1:
            raise RuntimeError("La durée doit être d'au moins une seconde.")
        args.output_dir.mkdir(parents=True, exist_ok=True)
        stamp = dt.datetime.now().astimezone().strftime("%Y%m%d_%H%M%S")
        capture_path = (args.output_dir / f"capture_{stamp}.pcapng").resolve()
        report_path = (args.output_dir / f"rapport_{stamp}.pdf").resolve()

        print(f"Capture de {args.duration} s sur {args.interface}. sudo peut demander votre mot de passe.")
        run(["sudo", "-v"])
        run(
            [
                "sudo",
                "dumpcap",
                "-i",
                args.interface,
                "-a",
                f"duration:{args.duration}",
                "-w",
                str(capture_path),
            ]
        )
        run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(capture_path)])

        def tshark(*options: str) -> str:
            return run(
                ["tshark", "-r", str(capture_path), *options],
                capture_output=True,
            ).stdout

        protocols: collections.Counter[str] = collections.Counter()
        packet_count = 0
        for protocol_stack in tshark("-T", "fields", "-e", "frame.protocols").splitlines():
            if not protocol_stack.strip():
                continue
            packet_count += 1
            for protocol in set(protocol_stack.split(":")):
                protocols[protocol] += 1

        hierarchy = tshark("-q", "-z", "io,phs")
        endpoints = tshark("-q", "-z", "endpoints,ip")
        conversations = tshark("-q", "-z", "conv,ip")
        dns_names = sorted(
            set(
                name.strip()
                for name in tshark(
                    "-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name"
                ).splitlines()
                if name.strip()
            )
        )
        tls_names = sorted(
            set(
                name.strip()
                for name in tshark(
                    "-Y",
                    "tls.handshake.extensions_server_name",
                    "-T",
                    "fields",
                    "-e",
                    "tls.handshake.extensions_server_name",
                ).splitlines()
                if name.strip()
            )
        )
        make_pdf(
            report_path,
            capture_path,
            args.interface,
            args.duration,
            packet_count,
            protocols,
            hierarchy,
            endpoints,
            conversations,
            dns_names,
            tls_names,
        )
        print(f"Rapport PDF créé : {report_path}")
        print(f"Capture enregistrée : {capture_path}")
        print("Ouverture de la capture dans Wireshark...")
        subprocess.Popen(["wireshark", str(capture_path)])
        return 0
    except (RuntimeError, OSError) as exc:
        print(f"Erreur : {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
