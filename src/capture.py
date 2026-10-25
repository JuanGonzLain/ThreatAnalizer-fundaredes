from scapy.all import sniff
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime


PROTOCOL_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def get_protocol_name(packet):
    if TCP in packet:
        return "TCP"
    if UDP in packet:
        return "UDP"
    if ICMP in packet:
        return "ICMP"
    if ARP in packet:
        return "ARP"
    if IP in packet:
        return PROTOCOL_MAP.get(packet[IP].proto, f"IP-{packet[IP].proto}")
    if Ether in packet:
        return f"EtherType-{hex(packet[Ether].type)}"
    return "UNKNOWN"


def get_payload_size(packet):
    try:
        if TCP in packet:
            return len(packet[TCP].payload)
        if UDP in packet:
            return len(packet[UDP].payload)
        if ICMP in packet:
            return len(packet[ICMP].payload)
        if ARP in packet:
            return len(packet[ARP].payload)
        return 0
    except Exception:
        return 0


def parse_packet(packet):
    timestamp = float(packet.time)

    data = {
        "timestamp": timestamp,
        "datetime": datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S"),
        "layer": "UNKNOWN",
        "protocol": get_protocol_name(packet),

        "source_mac": None,
        "destination_mac": None,

        "source_ip": None,
        "destination_ip": None,

        "source_port": None,
        "destination_port": None,

        "size_bytes": len(packet),
        "payload_size": get_payload_size(packet),

        "is_l2_only": False,
        "is_ip": False,
        "is_arp": False,
        "parse_status": "processed",
    }

    try:
        if Ether in packet:
            data["layer"] = "L2"
            data["source_mac"] = packet[Ether].src
            data["destination_mac"] = packet[Ether].dst

        if ARP in packet:
            data["layer"] = "L2"
            data["is_arp"] = True
            data["source_ip"] = packet[ARP].psrc
            data["destination_ip"] = packet[ARP].pdst
            data["source_mac"] = packet[ARP].hwsrc
            data["destination_mac"] = packet[ARP].hwdst

        if IP in packet:
            data["layer"] = "L3"
            data["is_ip"] = True
            data["source_ip"] = packet[IP].src
            data["destination_ip"] = packet[IP].dst

        if TCP in packet:
            data["layer"] = "L4"
            data["source_port"] = packet[TCP].sport
            data["destination_port"] = packet[TCP].dport

        elif UDP in packet:
            data["layer"] = "L4"
            data["source_port"] = packet[UDP].sport
            data["destination_port"] = packet[UDP].dport

        if Ether in packet and IP not in packet:
            data["is_l2_only"] = True

        return data

    except Exception as error:
        data["parse_status"] = f"error: {str(error)}"
        return data


def capture_packets(count=50, interface=None, timeout=None):
    packets = sniff(
        count=count,
        iface=interface,
        timeout=timeout,
        store=True
    )

    results = []
    discarded_packets = 0

    for packet in packets:
        parsed = parse_packet(packet)

        if parsed["parse_status"] == "processed":
            results.append(parsed)
        else:
            discarded_packets += 1

    return {
        "packets": results,
        "total_captured": len(packets),
        "total_processed": len(results),
        "discarded_packets": discarded_packets,
    }