#!/usr/bin/env python3

import logging
import time
import threading
from collections import defaultdict
from flask import Flask, request, render_template_string

from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, UDP, ICMP

#####################################################
#                   CONFIGURATION
#####################################################

FIREWALL_RULES = {
    "block_ips": set(),
    "allow_ips": set(),
    "block_ports": set(),
    "allow_ports": set(),
    "block_icmp": False,
    "scan_detection_threshold": 5,
    "scan_time_window": 10,
}

scanned_ports_by_ip = defaultdict(set)
timestamps_by_ip = defaultdict(list)

logging.basicConfig(
    filename="firewall.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

#####################################################
#               FONCTION DE TRAITEMENT
#####################################################

def process_packet(packet):
    """ Callback pour NetfilterQueue. Analyse et filtre les paquets en fonction des règles. """
    scapy_packet = IP(packet.get_payload())
    src_ip = scapy_packet.src
    dst_ip = scapy_packet.dst
    proto = scapy_packet.proto 
    logging.info(f"New Packet: {src_ip} -> {dst_ip}, proto={proto}")
    if scapy_packet.haslayer(TCP):
        sport = scapy_packet[TCP].sport
        dport = scapy_packet[TCP].dport
        if should_block_ip_or_port(src_ip, dst_ip, sport, dport, "TCP"):
            packet.drop()
            return
        detect_port_scan(src_ip, dport)

    elif scapy_packet.haslayer(UDP):
        sport = scapy_packet[UDP].sport
        dport = scapy_packet[UDP].dport
        if should_block_ip_or_port(src_ip, dst_ip, sport, dport, "UDP"):
            packet.drop()
            return

    elif scapy_packet.haslayer(ICMP):
        if FIREWALL_RULES["block_icmp"]:
            logging.warning(f"ICMP blocked: {src_ip} -> {dst_ip}")
            packet.drop()
            return
    packet.accept()


def should_block_ip_or_port(src_ip, dst_ip, sport, dport, protocol):
    """ Détermine si un paquet doit être bloqué selon IP/port/protocol. """

    if src_ip in FIREWALL_RULES["block_ips"] or dst_ip in FIREWALL_RULES["block_ips"]:
        logging.warning(f"BLOCK (IP) {src_ip} -> {dst_ip}")
        return True

    if (dport in FIREWALL_RULES["block_ports"]) or (sport in FIREWALL_RULES["block_ports"]):
        logging.warning(f"BLOCK (PORT) {protocol}:{sport}->{dport} IP: {src_ip}->{dst_ip}")
        return True
    if src_ip in FIREWALL_RULES["allow_ips"] or dst_ip in FIREWALL_RULES["allow_ips"]:
        return False
    if dport in FIREWALL_RULES["allow_ports"] or sport in FIREWALL_RULES["allow_ports"]:
        return False
    return False


def detect_port_scan(src_ip, dport):
    """
    Détection d'un scan de ports :
    - On stocke la liste des ports déjà contactés par src_ip dans une fenêtre de temps.
    - Si on dépasse un seuil de ports distincts dans cette fenêtre, on bloque l’IP.
    """

    now = time.time()
    while timestamps_by_ip[src_ip] and (now - timestamps_by_ip[src_ip][0] > FIREWALL_RULES["scan_time_window"]):
        timestamps_by_ip[src_ip].pop(0)
    timestamps_by_ip[src_ip].append(now)
    scanned_ports_by_ip[src_ip].add(dport)

    if len(scanned_ports_by_ip[src_ip]) >= FIREWALL_RULES["scan_detection_threshold"]:
        FIREWALL_RULES["block_ips"].add(src_ip)
        logging.warning(f"Port scan detected from {src_ip}, IP blocked!")
        scanned_ports_by_ip[src_ip].clear()

#####################################################
#             INTERFACE WEB (FLASK)
#####################################################

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    """Page d'accueil : affiche les règles actuelles et formulaire d’ajout/suppression."""
    html_content = """
    <h1>Mini Firewall - Dashboard</h1>
    <h2>Règles courantes</h2>
    <ul>
      <li><b>Block IPs:</b> {{ block_ips }}</li>
      <li><b>Allow IPs:</b> {{ allow_ips }}</li>
      <li><b>Block Ports:</b> {{ block_ports }}</li>
      <li><b>Allow Ports:</b> {{ allow_ports }}</li>
      <li><b>Block ICMP:</b> {{ block_icmp }}</li>
    </ul>

    <form action="/update_rules" method="post">
      <label>Ajouter IP à bloquer:</label>
      <input type="text" name="block_ip" />
      <input type="submit" value="Bloquer IP"/>
    </form>

    <form action="/update_rules" method="post">
      <label>Retirer IP de la liste block:</label>
      <input type="text" name="unblock_ip" />
      <input type="submit" value="Débloquer IP"/>
    </form>

    <form action="/update_rules" method="post">
      <label>Ajouter port à bloquer:</label>
      <input type="number" name="block_port" />
      <input type="submit" value="Bloquer Port"/>
    </form>

    <form action="/update_rules" method="post">
      <label>Retirer port de la liste block:</label>
      <input type="number" name="unblock_port" />
      <input type="submit" value="Débloquer Port"/>
    </form>

    <form action="/toggle_icmp" method="post">
      <input type="submit" value="Toggle ICMP" />
    </form>

    <hr/>
    <h2>Logs</h2>
    <p>Vérifier le fichier <code>firewall.log</code> pour les logs détaillés.</p>
    """
    return render_template_string(html_content,
        block_ips=list(FIREWALL_RULES["block_ips"]),
        allow_ips=list(FIREWALL_RULES["allow_ips"]),
        block_ports=list(FIREWALL_RULES["block_ports"]),
        allow_ports=list(FIREWALL_RULES["allow_ports"]),
        block_icmp=FIREWALL_RULES["block_icmp"]
    )

@app.route("/update_rules", methods=["POST"])
def update_rules():
    """Route pour mettre à jour les règles via formulaires."""
    block_ip = request.form.get("block_ip")
    unblock_ip = request.form.get("unblock_ip")
    block_port = request.form.get("block_port")
    unblock_port = request.form.get("unblock_port")

    if block_ip:
        FIREWALL_RULES["block_ips"].add(block_ip)
        logging.info(f"User added block IP: {block_ip}")

    if unblock_ip:
        if unblock_ip in FIREWALL_RULES["block_ips"]:
            FIREWALL_RULES["block_ips"].remove(unblock_ip)
            logging.info(f"User removed block IP: {unblock_ip}")

    if block_port:
        try:
            p = int(block_port)
            FIREWALL_RULES["block_ports"].add(p)
            logging.info(f"User added block port: {p}")
        except ValueError:
            pass

    if unblock_port:
        try:
            p = int(unblock_port)
            if p in FIREWALL_RULES["block_ports"]:
                FIREWALL_RULES["block_ports"].remove(p)
                logging.info(f"User removed block port: {p}")
        except ValueError:
            pass

    return ("<p>Règles mises à jour ! <a href='/'>Revenir</a></p>")

@app.route("/toggle_icmp", methods=["POST"])
def toggle_icmp():
    FIREWALL_RULES["block_icmp"] = not FIREWALL_RULES["block_icmp"]
    logging.info(f"ICMP block toggled. New state: {FIREWALL_RULES['block_icmp']}")
    return ("<p>ICMP toggled ! <a href='/'>Revenir</a></p>")

#####################################################
#        FONCTION PRINCIPALE AVEC THREADING
#####################################################

def run_firewall():
    """Démarre le loop NetfilterQueue (bloquant)."""
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, process_packet)
    try:
        logging.info("Firewall is running ...")
        nfqueue.run()
    except KeyboardInterrupt:
        logging.info("Firewall stopped by user.")
    finally:
        nfqueue.unbind()

def run_flask():
    """Démarre l'interface web Flask en parallèle."""
    app.run(host="0.0.0.0", port=5000, debug=False)


if __name__ == "__main__":
    firewall_thread = threading.Thread(target=run_firewall)
    firewall_thread.start()

    # On lance le serveur web sur le thread principal (ou inversement)
    # Pour arrêter, Ctrl+C
    run_flask()
