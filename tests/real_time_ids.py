# ids/real_time_ids.py
import torch
import numpy as np
from torch.serialization import safe_globals
from sklearn.preprocessing import StandardScaler

class RealTimeIDS:
    def __init__(self):
        self.models = {
            "SYN": self.load_model("../ai_models/SYN_IDS_model.pt"),
            "MITM_ARP": self.load_model("../ai_models/MITM_ARP_IDS_model.pt"),
            "OS": self.load_model("../ai_models/OS_IDS_model.pt"),
            "Active_Wiretap": self.load_lstm_model("../ai_models/Active_Wiretap_IDS.pt"),
        }

    def load_model(self, path):
        print(f"🔍 Loading model from: {path}")
        with safe_globals([StandardScaler]):
            data = torch.load(path, map_location=torch.device("cpu"), weights_only=False)

        class Net(torch.nn.Module):
            def __init__(self):
                super().__init__()
                self.model = torch.nn.Sequential(
                    torch.nn.Linear(115, 256),
                    torch.nn.ReLU(),
                    torch.nn.Linear(256, 128),
                    torch.nn.ReLU(),
                    torch.nn.Linear(128, 2)
                )

            def forward(self, x):
                return self.model(x)

        model = Net()
        model.load_state_dict(data['model_state_dict'])
        model.eval()
        return {"model": model, "scaler": data['scaler']}

    def load_lstm_model(self, path):
        print(f"🔍 Loading LSTM model from: {path}")
        with safe_globals([StandardScaler]):
            data = torch.load(path, map_location=torch.device("cpu"), weights_only=False)

        class LSTMNet(torch.nn.Module):
            def __init__(self):
                super().__init__()
                self.lstm = torch.nn.LSTM(input_size=115, hidden_size=64, batch_first=True)
                self.fc = torch.nn.Linear(64, 2)

            def forward(self, x):
                out, _ = self.lstm(x)
                out = self.fc(out[:, -1, :])
                return out

        model = LSTMNet()
        model.load_state_dict(data['model_state_dict'])
        model.eval()
        return {"model": model, "scaler": data['scaler'], "is_lstm": True}

    def predict(self, feature_vector):
        preds = {}
        for name, obj in self.models.items():
            model = obj["model"]
            scaler = obj["scaler"]
            features = np.array(feature_vector).reshape(1, -1)
            scaled = scaler.transform(features)
            tensor = torch.tensor(scaled, dtype=torch.float32)

            if obj.get("is_lstm"):
                tensor = tensor.unsqueeze(0)  # (1, 1, 115)
            output = model(tensor)
            pred = torch.argmax(output, dim=1).item()
            preds[name] = "🔴 Attack" if pred == 1 else "🟢 Normal"
        return preds
