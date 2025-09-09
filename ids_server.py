import os
import time
import json
import socket
import threading
import numpy as np
import torch
import torch.nn as nn
import torch.serialization
from sklearn.preprocessing import StandardScaler
from collections import deque

# Add StandardScaler to safe globals for PyTorch 2.6+
torch.serialization.add_safe_globals([StandardScaler])

# Configuration
MODEL_PATHS = {
    'SYN': 'ai_models/SYN_IDS_model.pt',
    'MITM_ARP': 'ai_models/MITM_ARP_IDS_model.pt',
    'OS': 'ai_models/OS_IDS_model.pt',
    'Active_Wiretap': 'ai_models/Active_Wiretap_IDS.pt'
}

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 9999
BUFFER_SIZE = 4096
FEATURE_SIZE = 115
MAX_QUEUE_SIZE = 100

# Load all models with weights_only=False since we trust our models
def load_model(path):
    return torch.load(path, map_location=torch.device('cpu'), weights_only=False)

# Model definitions
class SimpleNN(nn.Module):
    def __init__(self, input_size, hidden_size1, hidden_size2, output_size):
        super(SimpleNN, self).__init__()
        self.model = nn.Sequential(
            nn.Linear(input_size, hidden_size1),
            nn.ReLU(),
            nn.Linear(hidden_size1, hidden_size2),
            nn.ReLU(),
            nn.Linear(hidden_size2, output_size)
        )
    
    def forward(self, x):
        return self.model(x)

class LSTMModel(nn.Module):
    def __init__(self, input_size, hidden_size, num_layers, output_size):
        super(LSTMModel, self).__init__()
        self.hidden_size = hidden_size
        self.num_layers = num_layers
        self.lstm = nn.LSTM(input_size, hidden_size, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_size, output_size)
    
    def forward(self, x):
        h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
        c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size)
        out, _ = self.lstm(x, (h0, c0))
        out = self.fc(out[:, -1, :])
        return out

# Load models
print("🔍 Loading all detection models...")
models = {}
scalers = {}

for attack_type, path in MODEL_PATHS.items():
    try:
        checkpoint = load_model(path)
        
        if attack_type == 'Active_Wiretap':
            model = LSTMModel(input_size=FEATURE_SIZE, hidden_size=64, num_layers=1, output_size=2)
        else:
            layer_sizes = []
            for key in checkpoint['model_state_dict']:
                if 'weight' in key:
                    layer_sizes.append(checkpoint['model_state_dict'][key].shape[0])
            
            model = SimpleNN(
                input_size=FEATURE_SIZE,
                hidden_size1=layer_sizes[0],
                hidden_size2=layer_sizes[1],
                output_size=2
            )
        
        model.load_state_dict(checkpoint['model_state_dict'])
        model.eval()
        
        scaler = StandardScaler()
        scaler.fit(np.zeros((1, FEATURE_SIZE)))
        scaler.mean_ = checkpoint['scaler']['mean']
        scaler.scale_ = checkpoint['scaler']['scale']
        scaler.var_ = checkpoint['scaler']['var']
        scaler.n_features_in_ = checkpoint['scaler']['n_features_in']
        
        models[attack_type] = model
        scalers[attack_type] = scaler
        
        print(f"✅ {attack_type} model loaded successfully")
    except Exception as e:
        print(f"❌ Failed to load {attack_type} model: {str(e)}")
        raise

# Feature processing queue
feature_queue = deque(maxlen=MAX_QUEUE_SIZE)

def process_features(features):
    """Process raw features through all models"""
    results = {}
    
    # Convert to numpy array and ensure correct shape
    features = np.array(features).reshape(1, -1)
    
    for attack_type, model in models.items():
        try:
            # Scale features
            scaled_features = scalers[attack_type].transform(features)
            
            # Convert to tensor
            if attack_type == 'Active_Wiretap':
                # LSTM expects 3D input (batch, seq_len, features)
                tensor_features = torch.FloatTensor(scaled_features).unsqueeze(0)
            else:
                tensor_features = torch.FloatTensor(scaled_features)
            
            # Predict
            with torch.no_grad():
                output = model(tensor_features)
                probabilities = torch.softmax(output, dim=1)
                predicted_class = torch.argmax(probabilities, dim=1).item()
                confidence = probabilities[0][predicted_class].item()
            
            results[attack_type] = {
                'prediction': 'malicious' if predicted_class == 1 else 'benign',
                'confidence': confidence
            }
        except Exception as e:
            print(f"Error processing {attack_type}: {str(e)}")
            results[attack_type] = {
                'prediction': 'error',
                'confidence': 0.0
            }
    
    return results

def handle_client(conn, addr):
    """Handle incoming client connections"""
    print(f"🔌 New connection from {addr}")
    try:
        while True:
            data = conn.recv(BUFFER_SIZE)
            if not data:
                break
            
            try:
                # Parse received features
                features = json.loads(data.decode())
                if len(features) != FEATURE_SIZE:
                    print(f"⚠️ Invalid feature size: {len(features)} (expected {FEATURE_SIZE})")
                    continue
                
                # Add to queue and process
                feature_queue.append(features)
                results = process_features(features)
                
                # Send results back
                conn.sendall(json.dumps(results).encode())
                
                # Print alerts
                for attack_type, result in results.items():
                    if result['prediction'] == 'malicious' and result['confidence'] > 0.8:
                        print(f"🚨 {attack_type} attack detected! Confidence: {result['confidence']:.2f}")
                
            except json.JSONDecodeError:
                print("⚠️ Invalid JSON received")
            except Exception as e:
                print(f"⚠️ Processing error: {str(e)}")
                
    except ConnectionResetError:
        print(f"🔌 Connection closed by {addr}")
    finally:
        conn.close()

def start_server():
    """Start the IDS server with port conflict handling"""
    while True:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((SERVER_HOST, SERVER_PORT))
                s.listen()
                print(f"🚀 IDS Server listening on {SERVER_HOST}:{SERVER_PORT}")
                
                while True:
                    conn, addr = s.accept()
                    client_thread = threading.Thread(target=handle_client, args=(conn, addr))
                    client_thread.daemon = True
                    client_thread.start()
                    
        except OSError as e:
            if e.errno == 98:  # Address already in use
                print(f"⚠️ Port {SERVER_PORT} in use. Waiting to retry...")
                time.sleep(5)
                continue
            else:
                raise
        except KeyboardInterrupt:
            print("\n🛑 Server shutting down...")
            break

if __name__ == '__main__':
    start_server()
