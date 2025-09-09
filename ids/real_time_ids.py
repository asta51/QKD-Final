import numpy as np
import torch
import torch.nn as nn
from collections import deque
from sklearn.preprocessing import StandardScaler
import torch.serialization

# ✅ Allow StandardScaler & numpy scalar for model loading
torch.serialization.add_safe_globals([
    StandardScaler,
    np.core.multiarray.scalar  # Legacy NumPy scalar compatibility
])

# 🔹 SYN Model (115 ➝ 256 ➝ 128 ➝ 2)
class SYNModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(115, 256),  # model.0
            nn.ReLU(),
            nn.Identity(), 
            nn.Linear(256, 128),  # model.3
            nn.ReLU(),
            nn.Linear(128, 2)     # model.5
        )

    def forward(self, x):
        return self.model(x)

# 🔹 MITM_ARP & OS Model (115 ➝ 128 ➝ 64 ➝ 2)
class MITMModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.model = nn.Sequential(
            nn.Linear(115, 128),  # model.0
            nn.ReLU(),
            nn.Identity(),
            nn.Linear(128, 64),   # model.3
            nn.ReLU(),
            nn.Linear(64, 2)      # model.5
        )

    def forward(self, x):
        return self.model(x)

# 🔹 Active Wiretap LSTM Model (115 ➝ LSTM ➝ FC ➝ 2)
class ActiveWiretapModel(nn.Module):
    def __init__(self):
        super().__init__()
        self.hidden_size = 64
        self.num_layers = 1
        self.lstm = nn.LSTM(input_size=115, hidden_size=self.hidden_size,
                            num_layers=self.num_layers, batch_first=True)
        self.fc = nn.Linear(self.hidden_size, 2)

    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
        out, _ = self.lstm(x, (h0, c0))          # out: [batch, seq, hidden]
        out = self.fc(out[:, -1, :])             # last timestep
        return out

# 🔐 Intrusion Detection System (Real-time)
class IntrusionDetector:
    def __init__(self, window=50):
        self.window = window
        self.packet_data = deque(maxlen=window)
        self.last_timestamp = {}
        self.features = 115  # Expected feature vector length
        self.models = self._load_models()

    def _load_models(self):
        return {
            "SYN": self._load_model("ai_models/SYN_IDS_model.pt", SYNModel()),
            "MITM_ARP": self._load_model("ai_models/MITM_ARP_IDS_model.pt", MITMModel()),
            "OS": self._load_model("ai_models/OS_IDS_model.pt", MITMModel()),
            "Active_Wiretap": self._load_model("ai_models/Active_Wiretap_IDS.pt", ActiveWiretapModel())
        }

    def _load_model(self, path, model):
        data = torch.load(path, map_location="cpu", weights_only=False)
        model.load_state_dict(data["model_state_dict"])
        model.eval()
        return {
            "model": model,
            "scaler": data["scaler"]
        }

    def _extract_features(self, log):
        # Create base feature vector (3 example features)
        features = [
            log.get('length', 0),
            log.get('timestamp', 0) - self.last_timestamp.get(log['ip'], log.get('timestamp', 0)),
            len(log.get('message', ''))
        ]
        # Pad to match required input size
        features += [0] * (self.features - len(features))
        return np.array(features).reshape(1, -1)

    def process(self, log):
        ip = log["ip"]
        ts = log["timestamp"]
        self.last_timestamp[ip] = ts

        features = self._extract_features(log)
        results = {}

        for name, model_data in self.models.items():
            try:
                scaled = model_data['scaler'].transform(features)

                if name == "Active_Wiretap":
                    tensor = torch.FloatTensor(scaled).unsqueeze(0)  # [1, 1, 115]
                else:
                    tensor = torch.FloatTensor(scaled)              # [1, 115]

                with torch.no_grad():
                    output = model_data['model'](tensor)
                    _, predicted = torch.max(output.data, 1)
                    results[name] = predicted.item() == 1  # 1 = anomaly
            except Exception as e:
                print(f"❌ Error in {name} model: {e}")
                results[name] = False

        log['anomaly_details'] = results
        log['anomaly'] = any(results.values())
        return log
