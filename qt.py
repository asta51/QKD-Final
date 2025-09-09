from scapy.all import rdpcap, TCP, IP
import pandas as pd
from collections import defaultdict
import os

def get_flow_key(pkt):
    ip = pkt[IP]
    return (ip.src, ip.dst, pkt[TCP].sport, pkt[TCP].dport, ip.proto)

def extract_flows(pcap_file, label):
    flows = defaultdict(list)
    packets = rdpcap(pcap_file)
    print(f"[+] {pcap_file}: Loaded {len(packets)} packets")

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
            "label": label
        }
        flow_records.append(record)
    return flow_records

# === Main Execution ===
clean_file = "qkd_clean.pcap"
ddos_file = "qkd_ddos.pcap"

clean_flows = extract_flows(clean_file, label=0)
attack_flows = extract_flows(ddos_file, label=1)

all_flows = clean_flows + attack_flows
df = pd.DataFrame(all_flows)
df.to_csv("qkd_flows_labeled.csv", index=False)

print(f"[✓] Exported labeled flows: {len(df)} rows → qkd_flows_labeled.csv")
