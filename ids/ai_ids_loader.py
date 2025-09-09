# ✅ File: ids/ai_ids_loader.py

import torch
from sklearn.preprocessing import StandardScaler
import numpy as np
from torch.serialization import add_safe_globals
import torch.nn as nn

# Allow safe loading of StandardScaler and NumPy scalar
add_safe_globals([StandardScaler, np.core.multiarray.scalar])

# ✅ Base AI Model (Fully Connected)
class AI_IDS_Model:
    def __init__(self, model_path):
        data = torch.load(model_path, map_location="cpu", weights_only=False)
        self.model = self._build_model(model_path)

        # Prefix all keys with "model." to match architecture
        state_dict = {f"model.{k}": v for k, v in data['model_state_dict'].items()}
        self.model.load_state_dict(state_dict)
        self.model.eval()

        self.scaler = data['scaler']

    def _build_model(self, path):
        return nn.Sequential(
            nn.Linear(115, 256),
            nn.ReLU(),
            nn.Linear(256, 128),
            nn.ReLU(),
            nn.Linear(128, 2)  # Output layer for 2-class classification
        )

    def predict(self, x):
        x = self.scaler.transform([x])
        x_tensor = torch.tensor(x, dtype=torch.float32)
        with torch.no_grad():
            logits = self.model(x_tensor)
            pred = torch.argmax(logits).item()
        return pred == 1


# ✅ LSTM model loader (for Active_Wiretap)
class LSTM_IDS_Model(nn.Module):
    def __init__(self, model_path):
        super().__init__()
        data = torch.load(model_path, map_location="cpu", weights_only=False)

        self.lstm = nn.LSTM(input_size=115, hidden_size=64, batch_first=True)
        self.fc = nn.Linear(64, 2)

        self.load_state_dict(data['model_state_dict'])
        self.eval()

        self.scaler = data['scaler']

    def forward(self, x):
        x, _ = self.lstm(x)
        x = x[:, -1, :]  # Last output
        return self.fc(x)

    def predict(self, x):
        x = self.scaler.transform([x])
        x_tensor = torch.tensor(x, dtype=torch.float32).unsqueeze(0)  # Add batch dim
        with torch.no_grad():
            logits = self.forward(x_tensor)
            pred = torch.argmax(logits).item()
        return pred == 1
