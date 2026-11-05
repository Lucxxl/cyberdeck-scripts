#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERDECK - Module d'énumération active (recon offensive)
Orchestration de nmap : découverte d'hôtes, scan de ports,
détection de services/versions, empreinte OS et scripts NSE.

Remplace scan_net.py (écoute passive) par une reconnaissance active,
première phase d'un test d'intrusion. À n'utiliser que sur un périmètre
pour lequel une autorisation explicite existe.
"""
from __future__ import annotations

import os
import sys
import shutil
import subprocess
import argparse
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

MODULE_VERSION = "1.0 (ENUM-Active)"
OBSERVATION_ORIGIN = "Scan actif (nmap)"
NMAP_BIN = "nmap"

# ---------------------------------------------------------------------------
# Profils de scan : du plus discret au plus complet.
# Chaque profil est une liste d'arguments nmap. -oX - envoie le XML sur stdout.
# ---------------------------------------------------------------------------
PROFILES = {
    "rapide": {
        "desc": "Top 100 ports, détection de version légère, rapide.",
        "args": ["-F", "-sV", "--version-light", "-T4"],
        "needs_root": False,
    },
    "complet": {
        "desc": "1000 ports TCP, versions, OS, scripts par défaut (bruyant).",
        "args": ["-sS", "-sV", "-O", "--script", "default", "-T4"],
        "needs_root": True,
    },
    "discret": {
        "desc": "Scan SYN lent, sans scripts, pour rester sous le radar.",
        "args": ["-sS", "-T2", "--max-retries", "1"],
        "needs_root": True,
    },
}


def require_nmap() -> None:
    if not shutil.which(NMAP_BIN):
        print(f"[!] {NMAP_BIN} introuvable. Installez-le : sudo apt install nmap",
              file=sys.stderr)
        sys.exit(1)


def confirm_authorization(target: str, profile: str) -> None:
    """Oblige l'opérateur à ressaisir la cible pour confirmer l'autorisation."""
    print("=" * 60)
    print(" CONFIRMATION D'AUTORISATION REQUISE")
    print("=" * 60)
    print(f"Cible          : {target}")
    print(f"Profil de scan : {profile} ({PROFILES[profile]['desc']})")
    print(
        "\nUn scan actif est intrusif et visible. Il ne doit viser qu'un "
        "périmètre pour lequel vous disposez d'une autorisation écrite "
        "(labo personnel ou mandat de test)."
    )
    confirmation = input("\nResaisissez la cible pour confirmer et continuer : ").strip()
    if confirmation != target:
        print("[!] Confirmation invalide. Arrêt.", file=sys.stderr)
        sys.exit(1)


def run_nmap(target: str, profile: str) -> str:
    """Lance nmap avec le profil choisi et retourne le chemin du XML produit."""
    prof = PROFILES[profile]
    is_root = (os.geteuid() == 0)

    args = list(prof["args"])
    # -O et -sS exigent les privilèges root ; sinon on retombe sur un scan
    # TCP connect (-sT) sans empreinte OS, pour rester fonctionnel en user.
    if prof["needs_root"] and not is_root:
        print("[!] Ce profil demande root (scan SYN / OS). "
              "Dégradation en scan TCP connect sans empreinte OS.")
        args = [a for a in args if a not in ("-sS", "-O")]
        args = [a for a in args if a != "default" and a != "--script"]
        if "-sT" not in args:
            args.insert(0, "-sT")

    xml_fd, xml_path = tempfile.mkstemp(suffix=".xml", prefix="nmap_")
    os.close(xml_fd)

    cmd = [NMAP_BIN] + args + ["-oX", xml_path, target]
    print(f"[*] Lancement : {' '.join(cmd)}")
    start = datetime.now(timezone.utc)
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        print(f"[!] nmap a renvoyé une erreur (code {exc.returncode}).",
              file=sys.stderr)
    elapsed = (datetime.now(timezone.utc) - start).total_seconds()
    print(f"[+] Scan terminé en {elapsed:.1f} s.")
    return xml_path


def parse_nmap_xml(xml_path: str) -> list:
    """Parse le XML nmap en une liste d'hôtes structurés."""
    hosts = []
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        print("[!] XML nmap illisible (scan interrompu ?).", file=sys.stderr)
        return hosts

    root = tree.getroot()
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") != "up":
            continue

        addr = "?"
        mac = None
        for a in host.findall("address"):
            if a.get("addrtype") == "ipv4":
                addr = a.get("addr")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr")

        hostname = None
        hn = host.find("hostnames/hostname")
        if hn is not None:
            hostname = hn.get("name")

        os_guess = None
        osmatch = host.find("os/osmatch")
        if osmatch is not None:
            os_guess = f"{osmatch.get('name')} ({osmatch.get('accuracy')}%)"

        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            service = svc.get("name") if svc is not None else "?"
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            banner = " ".join(x for x in (product, version) if x).strip() or "-"
            ports.append({
                "port": port.get("portid"),
                "proto": port.get("protocol"),
                "service": service,
                "banner": banner,
            })

        hosts.append({
            "addr": addr,
            "mac": mac,
            "hostname": hostname,
            "os": os_guess,
            "ports": ports,
        })
    return hosts


def generate_pdf_report(hosts: list, target: str, profile: str) -> str:
    session = os.getenv("CYBERDECK_SESSION_ID", "N/A")
    operator = os.getenv("CYBERDECK_OPERATOR", "Inconnu")
    scenario = os.getenv("CYBERDECK_SCENARIO", "N/A")
    interface = os.getenv("CYBERDECK_INTERFACE", "N/A")
    timestamp_utc = os.getenv("CYBERDECK_UTC_TIME", "Inconnu")
    file_time = os.getenv("CYBERDECK_FILE_TIME",
                          datetime.now().strftime("%Y%m%d_%H%M%S"))
    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    output_path = f"enum_active_{session}_{file_time}.pdf"
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("Reconnaissance Active - Énumération nmap", styles["Title"]))
    elements.append(Spacer(1, 8))

    elements.append(Paragraph(f"<b>Session / Scénario :</b> {session} / {scenario}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Opérateur :</b> {operator}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Cible / Interface :</b> {target} / {interface}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Profil :</b> {profile} - {PROFILES[profile]['desc']}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage session (UTC) :</b> {timestamp_utc}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage du scan (UTC) :</b> {run_ts}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Version module :</b> {MODULE_VERSION} | <b>Origine :</b> {OBSERVATION_ORIGIN}", styles["Normal"]))
    elements.append(Spacer(1, 15))

    up = len(hosts)
    total_ports = sum(len(h["ports"]) for h in hosts)
    elements.append(Paragraph(
        f"<b>Synthèse :</b> {up} hôte(s) actif(s), {total_ports} port(s) ouvert(s) au total.",
        styles["Heading2"]))
    elements.append(Spacer(1, 10))

    if not hosts:
        elements.append(Paragraph(
            "Aucun hôte actif détecté. Pare-feu bloquant le ping, mauvais "
            "périmètre, ou cible éteinte.", styles["Normal"]))
    else:
        for h in hosts:
            title = h["addr"]
            if h["hostname"]:
                title += f" ({h['hostname']})"
            elements.append(Paragraph(title, styles["Heading3"]))
            meta = []
            if h["mac"]:
                meta.append(f"MAC : {h['mac']}")
            if h["os"]:
                meta.append(f"OS probable : {h['os']}")
            if meta:
                elements.append(Paragraph(" | ".join(meta), styles["Normal"]))

            if not h["ports"]:
                elements.append(Paragraph("Aucun port ouvert détecté.", styles["Normal"]))
            else:
                rows = [["Port", "Proto", "Service", "Produit / Version"]]
                for p in h["ports"]:
                    rows.append([p["port"], p["proto"], p["service"], p["banner"]])
                t = Table(rows, colWidths=[50, 50, 100, 260])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                ]))
                elements.append(t)
            elements.append(Spacer(1, 12))

    elements.append(Spacer(1, 10))
    elements.append(Paragraph("Limites de couverture (Méthodologie) :", styles["Heading2"]))
    elements.append(Paragraph(
        "Un scan actif ne révèle que ce que la cible accepte de répondre au moment "
        "du test. Un pare-feu peut masquer des ports (filtered), un IPS peut fausser "
        "les bannières, et l'empreinte OS reste une estimation probabiliste. "
        "L'absence de port ouvert n'est pas une preuve d'absence de service.",
        styles["Normal"]))

    doc.build(elements)
    print(f"[+] Rapport PDF généré : {output_path}")
    return output_path


def main() -> int:
    require_nmap()

    parser = argparse.ArgumentParser(
        description="Énumération active orchestrée via nmap.")
    parser.add_argument("-t", "--target", default=os.getenv("CYBERDECK_TARGET", ""),
                        help="Cible (IP, plage CIDR, ou hôte). Défaut : CYBERDECK_TARGET.")
    parser.add_argument("-p", "--profile", choices=list(PROFILES), default="rapide",
                        help="Profil de scan (rapide / complet / discret).")
    parser.add_argument("--skip-confirmation", action="store_true",
                        help="Ignorer la confirmation (usage scripté encadré uniquement).")
    args = parser.parse_args()

    target = args.target.strip()
    if not target or target in ("LAN", "N/A"):
        target = input("Entrez la cible du scan (IP ou CIDR, ex: 192.168.56.0/24) : ").strip()
    if not target:
        print("[!] Aucune cible fournie. Arrêt.", file=sys.stderr)
        return 1

    if not args.skip_confirmation:
        confirm_authorization(target, args.profile)

    xml_path = run_nmap(target, args.profile)
    hosts = parse_nmap_xml(xml_path)

    print("\n" + "=" * 60)
    print(f"[+] {len(hosts)} hôte(s) actif(s) :")
    for h in hosts:
        label = h["addr"] + (f" ({h['hostname']})" if h["hostname"] else "")
        print(f"  * {label} - {len(h['ports'])} port(s) ouvert(s)"
              + (f" - {h['os']}" if h["os"] else ""))
        for p in h["ports"]:
            print(f"      {p['port']}/{p['proto']:<4} {p['service']:<12} {p['banner']}")

    generate_pdf_report(hosts, target, args.profile)

    try:
        os.remove(xml_path)
    except OSError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
