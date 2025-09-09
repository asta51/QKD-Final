import torch
import torch.nn as nn
import joblib
import numpy as np
from scapy.all import rdpcap
import os
import sys

# 👇 Add Kitsune path (adjust if needed)
sys.path.append('./')  # if you're inside Kitsune folder

from FeatureExtractor import FE  # ✅ Kitsune’s incremental feature extractor

# 🧠 Define your trained model
class IDSModel(nn.Module):
    def __init__(self, input_dim):
        super(IDSModel, self).__init__()
        self.fc1 = nn.Linear(input_dim, 128)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(128, 64)
        self.fc3 = nn.Linear(64, 2)

    def forward(self, x):
        x = self.relu(self.fc1(x))
        x = self.relu(self.fc2(x))
        return self.fc3(x)

# ⚙️ Setup
input_dim = 115
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"[+] Using device: {device}")

# Load model
model = IDSModel(input_dim).to(device)
model.load_state_dict(torch.load("ARP_MitM_IDS.pt", map_location=device))
model.eval()

# Load scaler
scaler = joblib.load("ARP_MitM_scaler.pkl")

# 📥 Load packets
packets = rdpcap("ARP_MitM_pcap.pcapng")
print(f"[+] Loaded {len(packets)} packets from PCAP")

# 🎯 Initialize Kitsune feature extractor
feature_extractor = FE(interface=None, max_ftr=input_dim)

print("\n=== Real-Time IDS Predictions ===")
packet_count = 0
for pkt in packets:
    try:
        raw_pkt = bytes(pkt)
        features = feature_extractor.extract(raw_pkt)

        if features is None:
            continue  # still warming up Kitsune

        features = np.array(features).reshape(1, -1)
        scaled = scaler.transform(features)

        X_tensor = torch.tensor(scaled, dtype=torch.float32).to(device)
        with torch.no_grad():
            output = model(X_tensor)
            _, pred = torch.max(output, 1)
            label = "ATTACK 🚨" if pred.item() == 1 else "NORMAL ✅"
            print(f"Packet {packet_count+1}: {label}")
            packet_count += 1

    except Exception as e:
        print(f"❌ Error on packet {packet_count+1}: {e}")
