import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import time
from datetime import datetime
import pandas as pd
import random

class AIIntrusionDetection:
    def __init__(self):
        self.model = IsolationForest(contamination=0.01, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False
        self.connections_log = []
        self.anomalies_log = []
        self.training_data = []
        
    def generate_training_data(self, num_samples=100):
        """Generate synthetic normal connection data"""
        print("Generating synthetic training data...")
        self.training_data = [
            {
                'duration': random.uniform(1.0, 10.0),
                'encrypted_data': 'a'*random.randint(50, 200),
                'retry_count': random.randint(0, 2),
                'data_frequency': random.uniform(0.5, 5.0),
                'error_count': random.randint(0, 1)
            }
            for _ in range(num_samples)
        ]
        self.train_model(self.training_data)
        
    def extract_features(self, connection_data):
        """Extract features for anomaly detection"""
        return np.array([
            connection_data.get('duration', 0),
            len(str(connection_data.get('encrypted_data', ''))),
            connection_data.get('retry_count', 0),
            connection_data.get('data_frequency', 0),
            connection_data.get('error_count', 0)
        ]).reshape(1, -1)
    
    def train_model(self, normal_connections):
        """Train the anomaly detection model"""
        features = np.vstack([self.extract_features(conn) for conn in normal_connections])
        self.scaler.fit(features)
        scaled_features = self.scaler.transform(features)
        self.model.fit(scaled_features)
        self.is_trained = True
        self.save_model()
        print(f"✅ Model trained on {len(normal_connections)} samples")
        
    def detect_anomaly(self, connection_data):
        """Detect anomalous connections"""
        if not self.is_trained:
            return False
            
        features = self.extract_features(connection_data)
        scaled_features = self.scaler.transform(features)
        return self.model.predict(scaled_features)[0] == -1
        
    def log_connection(self, client_ip, is_anomalous, details):
        """Log connection details"""
        entry = {
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'client_ip': client_ip,
            'is_anomalous': is_anomalous,
            'details': details
        }
        self.connections_log.append(entry)
        if is_anomalous:
            self.anomalies_log.append(entry)
    
    def save_model(self, filename='ai_model/anomaly_detector.pkl'):
        """Save trained model to file"""
        with open(filename, 'wb') as f:
            pickle.dump({
                'model': self.model,
                'scaler': self.scaler,
                'is_trained': self.is_trained
            }, f)
    
    def load_model(self, filename='ai_model/anomaly_detector.pkl'):
        """Load trained model from file"""
        try:
            with open(filename, 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.scaler = data['scaler']
                self.is_trained = data['is_trained']
                print("✅ Loaded trained model")
        except FileNotFoundError:
            print("⚠️ No saved model found")
            self.is_trained = False
