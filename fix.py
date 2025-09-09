# fix_models.py
import os
import torch
from sklearn.preprocessing import StandardScaler
from torch.serialization import add_safe_globals

# Allow sklearn scaler to be deserialized safely
add_safe_globals([StandardScaler])

CORRUPT_MODELS = [
    "SYN_IDS_model.pt",
    "Active_Wiretap_IDS.pt",
    "MITM_ARP_IDS_model.pt",
    "OS_IDS_model.pt",
]

input_dir = "ai_models/"
output_dir = "ai_models_fixed/"
os.makedirs(output_dir, exist_ok=True)

for model_file in CORRUPT_MODELS:
    try:
        model_path = os.path.join(input_dir, model_file)
        print(f"🔄 Loading: {model_file}")
        data = torch.load(model_path, map_location="cpu", weights_only=False)

        fixed_path = os.path.join(output_dir, model_file)
        torch.save(data, fixed_path)
        print(f"✅ Re-saved safely to: {fixed_path}\n")

    except Exception as e:
        print(f"❌ Failed to fix {model_file}: {e}")
