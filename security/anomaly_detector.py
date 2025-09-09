import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import json
import os
from datetime import datetime

class AnomalyDetector:
    def __init__(self, model_path='models/anomaly_detector.joblib', scaler_path='models/scaler.joblib'):
        self.model_path = model_path
        self.scaler_path = scaler_path
        self.scaler = StandardScaler()
        self.model = None
        self.load_model()
        
        # Track normal behavior statistics
        self.normal_traffic_patterns = []
        self.max_samples = 1000  # Maximum samples to keep in memory

    def load_model(self):
        """Load existing model or create new one"""
        try:
            self.model = joblib.load(self.model_path)
            self.scaler = joblib.load(self.scaler_path)
            print("Loaded existing anomaly detection model")
        except:
            print("Creating new anomaly detection model")
            self.model = IsolationForest(n_estimators=100, contamination=0.01, random_state=42)
            # Initialize with some dummy data
            dummy_data = np.random.normal(0, 1, (100, 5))
            self.scaler.fit(dummy_data)
            self.model.fit(dummy_data)
            self.save_model()

    def save_model(self):
        """Save the current model to disk"""
        os.makedirs('models', exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.scaler, self.scaler_path)

    def extract_features(self, data):
        """Extract relevant features from network/QKD data"""
        features = [
            data.get('message_length', 0),
            data.get('response_time', 0),
            data.get('key_generation_time', 0),
            data.get('error_rate', 0),
            data.get('connection_duration', 0),
            data.get('packet_frequency', 0)
        ]
        return np.array(features).reshape(1, -1)

    def update_model(self, new_data):
        """Update the model with new normal data"""
        features = self.extract_features(new_data)
        
        # Scale features
        scaled_features = self.scaler.transform(features)
        
        # Add to normal patterns (for visualization)
        self.normal_traffic_patterns.append({
            'timestamp': datetime.now().isoformat(),
            'features': scaled_features.tolist()[0],
            'is_anomaly': False
        })
        
        # Keep only recent samples
        if len(self.normal_traffic_patterns) > self.max_samples:
            self.normal_traffic_patterns = self.normal_traffic_patterns[-self.max_samples:]
        
        # Partial fitting for online learning
        try:
            self.model.fit(np.vstack([self.scaler.transform(
                np.array([x['features'] for x in self.normal_traffic_patterns if not x['is_anomaly']])
            ))
            self.save_model()
        except:
            pass

    def detect_anomaly(self, data):
        """Detect if the given data is anomalous"""
        features = self.extract_features(data)
        scaled_features = self.scaler.transform(features)
        
        # Predict anomaly (1 for normal, -1 for anomaly)
        prediction = self.model.predict(scaled_features)[0]
        anomaly_score = self.model.decision_function(scaled_features)[0]
        
        is_anomaly = prediction == -1
        
        if is_anomaly:
            print(f"🚨 Anomaly detected! Score: {anomaly_score:.2f}")
            self.normal_traffic_patterns.append({
                'timestamp': datetime.now().isoformat(),
                'features': scaled_features.tolist()[0],
                'is_anomaly': True,
                'score': anomaly_score
            })
        else:
            # Update model with normal data
            self.update_model(data)
        
        return {
            'is_anomaly': is_anomaly,
            'score': anomaly_score,
            'features': features.tolist()[0],
            'timestamp': datetime.now().isoformat()
        }

    def get_traffic_stats(self):
        """Get statistics for visualization"""
        if not self.normal_traffic_patterns:
            return []
        return self.normal_traffic_patterns
