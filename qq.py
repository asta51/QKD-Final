from scapy.all import rdpcap, TCP, IP
import pandas as pd
from collections import defaultdict
import time

# === CONFIG ===
pcap_path = "qkd_clean.pcap"
csv_out_path = "qkd_flows.csv"

# === FLOW KEY === (5-tuple)
def get_flow_key(pkt):
    ip = pkt[IP]
    src = ip.src
    dst = ip.dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    proto = ip.proto
    return (src, dst, sport, dport, proto)

# === FLOW FEATURES ===
flows = defaultdict(list)
packets = rdpcap(pcap_path)
print(f"[+] Loaded {len(packets)} packets")

for pkt in packets:
    if IP in pkt and TCP in pkt:
        key = get_flow_key(pkt)
        flows[key].append(pkt)

flow_records = []
for key, pkts in flows.items():
    times = [pkt.time for pkt in pkts]
    sizes = [len(pkt) for pkt in pkts]

    record = {
        "src_ip": key[0],
        "dst_ip": key[1],
        "src_port": key[2],
        "dst_port": key[3],
        "protocol": key[4],
        "packet_count": len(pkts),
        "byte_count": sum(sizes),
        "duration": max(times) - min(times),
        "start_time": min(times),
        "end_time": max(times),
    }
    flow_records.append(record)

# === EXPORT CSV ===
df = pd.DataFrame(flow_records)
df.to_csv(csv_out_path, index=False)
print(f"[✓] CSV saved to {csv_out_path} with {len(df)} flows")
