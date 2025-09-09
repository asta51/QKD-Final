import subprocess
import pandas as pd
import numpy as np
import socket
import pickle
import time
from sklearn.preprocessing import StandardScaler

# Configuration
TSHARK_FIELDS = (
    "-e frame.time_epoch -e ip.src -e ip.dst -e ip.proto -e tcp.srcport -e tcp.dstport "
    "-e udp.srcport -e udp.dstport -e ip.len -e tcp.len -e tcp.flags -e udp.length "
    "-e frame.len -e ip.ttl -e tcp.window_size -e eth.src -e eth.dst"
)
INTERFACE = "eth0"  # Replace with your network interface
SERVER_HOST = "127.0.0.1"
SERVER_PORT = 9999
FEATURE_COUNT = 115  # Matches model input dimensions

def extract_features(packet_data):
    """
    Extract and preprocess features from tshark output to match Kitsune dataset (115 features).
    This is a simplified placeholder; adjust based on your feature extraction logic.
    """
    try:
        # Example: Parse tshark output (modify based on actual Kitsune feature set)
        # For simplicity, generate dummy features; replace with actual feature extraction
        features = np.random.rand(FEATURE_COUNT)  # Placeholder for 115 features
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return None

def main():
    # Initialize socket client
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client.connect((SERVER_HOST, SERVER_PORT))
        print(f"Connected to server at {SERVER_HOST}:{SERVER_PORT}")
    except Exception as e:
        print(f"Failed to connect to server: {e}")
        return

    # Start tshark to capture packets
    tshark_cmd = (
        f"tshark -i {INTERFACE} -T fields {TSHARK_FIELDS} -E separator=, -E quote=d "
        "-c 100"  # Limit to 100 packets for testing; adjust as needed
    )
    process = subprocess.Popen(tshark_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    try:
        while True:
            line = process.stdout.readline().decode('utf-8').strip()
            if not line:
                break
            # Extract features from packet
            features = extract_features(line)
            if features is None:
                continue

            # Send features to server
            try:
                client.send(pickle.dumps(features))
                # Receive classification result
                result = pickle.loads(client.recv(4096))
                print(f"Classification Result: {result}")
                if any(pred['anomaly'] for pred in result.values()):
                    print("🚨 ALERT: Potential threat detected!")
                    for model_name, pred in result.items():
                        if pred['anomaly']:
                            print(f"  - {model_name}: Anomaly detected (Confidence: {pred['confidence']:.4f})")
            except Exception as e:
                print(f"Error communicating with server: {e}")
                break

    except KeyboardInterrupt:
        print("Stopping IDS...")
    finally:
        process.terminate()
        client.close()

if __name__ == "__main__":
    main()
