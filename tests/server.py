# network/server.py
import subprocess
import time
from ids.intrusion_detector import IntrusionDetector

# ⚙️ Create an instance of your IDS class
ids = IntrusionDetector()

# 👇 Simulated feature extractor for each packet (can expand later)
def parse_packet(line):
    parts = line.strip().split("\t")
    if len(parts) < 4:
        return None

    try:
        timestamp = float(parts[0])
        src_ip = parts[1]
        dst_ip = parts[2]
        proto = int(parts[3])

        return {
            "ip": src_ip,
            "timestamp": timestamp,
            "message": f"{src_ip} ➝ {dst_ip} [proto={proto}]",
            "length": len(line)
        }
    except:
        return None

def main():
    print("🚀 Starting real-time IDS with tshark...\n")
    tshark_cmd = [
        "tshark", "-i", "eth0", "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "ip.proto", "-l"
    ]

    proc = subprocess.Popen(tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    try:
        for line in proc.stdout:
            log = parse_packet(line)
            if not log:
                continue

            result = ids.process(log)
            status = "🔴 Attack" if result['anomaly'] else "🟢 Normal"
            print(f"\n📡 {result['message']}  [{status}]")
            for k, v in result["anomaly_details"].items():
                print(f"  - {k}: {'🔴' if v else '🟢'}")

    except KeyboardInterrupt:
        print("\n🛑 IDS stopped.")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
