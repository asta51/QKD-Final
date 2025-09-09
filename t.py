import torch
from sklearn.preprocessing import StandardScaler
import numpy as np
from torch.serialization import add_safe_globals

# ✅ Allow both StandardScaler and NumPy scalar
add_safe_globals([
    StandardScaler,
    np._core.multiarray.scalar  # Required for numpy scalar objects
])

def check_model(path):
    try:
        data = torch.load(path, map_location="cpu", weights_only=False)  # Explicitly allow full load
        if "model_state_dict" in data and "scaler" in data:
            print(f"[✔] {path} is valid.")
            print(f"   → Keys: {data.keys()}")
        else:
            print(f"[❌] {path} is missing required keys.")
    except Exception as e:
        print(f"[⚠️] Failed to load {path}: {e}")

model_paths = [
    "ai_models/SYN_IDS_model.pt",
    "ai_models/Active_Wiretap_IDS.pt",
    "ai_models/MITM_ARP_IDS_model.pt",
    "ai_models/OS_IDS_model.pt"
]

for path in model_paths:
    check_model(path)
