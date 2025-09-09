import torch
from sklearn.preprocessing import StandardScaler
import numpy as np
import os

# ✅ Allowlist required objects
torch.serialization.add_safe_globals([
    StandardScaler,
    np.core.multiarray.scalar
])

# ✅ Define model paths
model_dir = "ai_models"
models = {
    "SYN": "SYN_IDS_model.pt",
    "MITM_ARP": "MITM_ARP_IDS_model.pt",
    "OS": "OS_IDS_model.pt",
    "Active_Wiretap": "Active_Wiretap_IDS.pt"
}

# ✅ Inspect each model
for name, filename in models.items():
    path = os.path.join(model_dir, filename)
    try:
        print(f"\n🔍 Loading {name} model from: {path}")
        data = torch.load(path, map_location="cpu", weights_only=False)

        print("✅ Model loaded successfully.")
        print("  - Keys:", list(data.keys()))

        print("  - state_dict:")
        for k, v in data['model_state_dict'].items():
            print(f"    {k:30} => {tuple(v.shape)}")

    except Exception as e:
        print(f"❌ Failed to load {name}: {e}")
