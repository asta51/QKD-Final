from scapy.all import sniff, TCP, IP, ARP
from collections import defaultdict
import pandas as pd
import joblib
import time
import threading
import csv
from datetime import datetime

# === Load Trained Model ===
model = joblib.load("ai_models/qkd_ids_model.pkl")
print("[✓] Model loaded")

# === Global Flow Storage and Lock ===
flows = defaultdict(lambda: {"timestamps": [], "sizes": [], "src_ip": None})
flow_lock = threading.Lock()
flow_timeout = 5  # seconds

# === CSV Log File ===
LOG_FILE = "ai_models/flow_log.csv"

# Write CSV header if not exists
with open(LOG_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["timestamp", "packet_count", "byte_count", "duration", "label", "src_ip"])

# === Helper: Get 5-tuple Flow Key ===
def get_flow_key(pkt):
    ip = pkt[IP]
    return (ip.src, ip.dst, pkt[TCP].sport, pkt[TCP].dport, ip.proto)

# === Packet Processing ===
def process_packet(pkt):
    if IP in pkt and TCP in pkt:
        key = get_flow_key(pkt)
        with flow_lock:
            flows[key]["timestamps"].append(pkt.time)
            flows[key]["sizes"].append(len(pkt))
            flows[key]["src_ip"] = pkt[IP].src  # Store source IP
    elif ARP in pkt:
        detect_arp_spoof(pkt)

# === Classify and Log Flow Data ===
def classify_flows():
    now = time.time()
    to_delete = []

    with flow_lock:
        for key, data in list(flows.items()):
            times = data["timestamps"]
            sizes = data["sizes"]
            src_ip = data["src_ip"]

            if not times or now - times[-1] < flow_timeout:
                continue  # Active flow, skip

            duration = max(times) - min(times)
            packet_count = len(times)
            byte_count = sum(sizes)

            row = pd.DataFrame([{
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration": duration
            }])

            pred = model.predict(row)[0]
            label_str = "⚠️ ATTACK" if pred == 1 else "✅ Benign"
            timestamp = datetime.now().strftime("%H:%M:%S")

            # Log to CSV with src_ip
            with open(LOG_FILE, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([timestamp, packet_count, byte_count, duration, pred, src_ip])

            # Print to terminal
            print(f"\n[FLOW] {key}")
            print(f"  Source IP: {src_ip}")
            print(f"  Packets: {packet_count} | Bytes: {byte_count} | Duration: {duration:.2f}s")
            print(f"  → Prediction: {label_str}")

            to_delete.append(key)

        for key in to_delete:
            del flows[key]

# === MITM Detection (ARP Spoofing) ===
known_macs = {}

def detect_arp_spoof(pkt):
    if pkt[ARP].op == 2:  # ARP reply
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        real_mac = known_macs.get(ip)

        if real_mac and real_mac != mac:
            print(f"\n🚨 [MITM DETECTED] IP {ip} MAC changed from {real_mac} ➝ {mac}")
        else:
            known_macs[ip] = mac

# === Background Thread: Classify Every Few Seconds ===
def flow_classifier_loop():
    while True:
        time.sleep(flow_timeout)
        classify_flows()

# === Main Function: Sniff Live Packets ===
def main():
    print("🚦 Real-Time IDS started... (Ctrl+C to stop)")
    try:
        sniff(filter="ip or arp", prn=process_packet, store=False, iface="lo")  # Adjust iface if needed
    except KeyboardInterrupt:
        print("\n🛑 Stopping IDS...")
        classify_flows()

def track_connected_clients():
    while True:
        time.sleep(3)
        rows = []
        with flow_lock:
            for key, data in flows.items():
                src_ip, dst_ip, sport, dport, proto = key
                rows.append([src_ip, dst_ip, sport, dport, proto, data.get("src_ip", "N/A")])

        with open("connected_clients.csv", "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Source IP", "Destination IP", "Sport", "Dport", "Protocol", "Reported IP"])
            writer.writerows(rows)

# === Entry Point ===
if __name__ == "__main__":
    threading.Thread(target=flow_classifier_loop, daemon=True).start()
    main()
