"""Read packet metadata during a short, user-started local capture."""
from collections import Counter
from datetime import datetime
import pandas as pd


def collect_metadata():
    from scapy.all import ICMP, IP, TCP, UDP, sniff

    counts = Counter()
    rows = []

    def record(packet):
        if IP not in packet:
            return
        protocol = next((name for layer, name in ((TCP, "TCP"), (UDP, "UDP"), (ICMP, "ICMP"))
                         if layer in packet), None)
        if protocol is None:
            return
        source = packet[IP].src
        counts[source] += 1
        rows.append({
            "Timestamp": datetime.fromtimestamp(float(packet.time)).strftime("%H:%M:%S"),
            "Protocol": protocol,
            "Data_Size": len(packet),
            "Packet_Count": counts[source],
        })

    sniff(prn=record, store=False, count=200, timeout=5)
    return pd.DataFrame(rows, columns=["Timestamp", "Protocol", "Data_Size", "Packet_Count"])
