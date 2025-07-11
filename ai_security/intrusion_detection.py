import time
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler
import joblib
import json
import os
from quantum_key_distribution.bb84 import QKDProtocol

class QuantumIntrusionDetectionSystem:
    def __init__(self, model_path="quantum_models"):
        self.model_path = model_path
        os.makedirs(model_path, exist_ok=True)

        self.timing_model = IsolationForest(contamination=0.05, random_state=42)
        self.pattern_model = OneClassSVM(nu=0.05, kernel='rbf', gamma='auto')
        self.scaler = StandardScaler()

        self.qkd_validator = QKDProtocol(key_length=256)
        self.thresholds = {
            'quantum_error_rate': 0.15,
            'timing_anomaly': -0.5,
            'pattern_anomaly': 0.0
        }

        self.intrusion_log = "intrusions.log"
        self.is_trained = False
    
    def extract_features(self, network_data):
        features = [
            np.log1p(network_data['packet_size']),
            network_data['processing_time'] * 1000,
            network_data['connection_stats']['active'],
            network_data['connection_stats']['throughput']
        ]
        if 'quantum_metrics' in network_data:
            features.extend([
                network_data['quantum_metrics']['error_rate'],
                network_data['quantum_metrics']['basis_mismatch'],
                network_data['quantum_metrics']['photon_detection']
            ])
        return np.array(features, dtype=np.float32).reshape(1, -1)
    
    def train_models(self, samples=10000):
        X_normal = np.concatenate([
            np.random.lognormal(0, 0.5, (samples, 1)),
            np.random.exponential(1, (samples, 1)),
            np.random.poisson(5, (samples, 1)),
            np.random.normal(100, 20, (samples, 1)),
            np.random.beta(2, 50, (samples, 1)),
            np.random.beta(1, 100, (samples, 1)),
            np.random.beta(2, 2, (samples, 1))
        ], axis=1)

        X_scaled = self.scaler.fit_transform(X_normal)
        self.timing_model.fit(X_scaled[:, :4])
        self.pattern_model.fit(X_scaled)
        self.is_trained = True
        self.save_models()
        return X_scaled
    
    def detect_intrusion(self, network_data):
        if not self.is_trained:
            self.load_models()
            
        features = self.extract_features(network_data)
        features_scaled = self.scaler.transform(features)

        timing_score = self.timing_model.decision_function(features_scaled[:, :4])[0]
        pattern_score = self.pattern_model.decision_function(features_scaled)[0]

        quantum_anomaly = 0.0
        if 'quantum_metrics' in network_data:
            quantum_anomaly = max(
                0,
                (network_data['quantum_metrics']['error_rate'] -
                 self.thresholds['quantum_error_rate']) / 0.05
            )

        is_intrusion = (
            timing_score < self.thresholds['timing_anomaly'] or
            pattern_score < self.thresholds['pattern_anomaly'] or
            quantum_anomaly > 0
        )

        result = {
            'is_intrusion': bool(is_intrusion),
            'confidence': float(max(
                self._sigmoid(-timing_score),
                self._sigmoid(-pattern_score),
                quantum_anomaly
            )),
            'anomaly_scores': {
                'timing': float(timing_score),
                'pattern': float(pattern_score),
                'quantum': float(quantum_anomaly)
            }
        }

        if is_intrusion:
            self._log_intrusion(network_data, result)
            
        return result
    
    def _sigmoid(self, x):
        return 1 / (1 + np.exp(-x))
    
    def _log_intrusion(self, data, result):
        log_entry = {
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'data': data,
            'result': {
                'is_intrusion': bool(result['is_intrusion']),
                'confidence': float(result['confidence']),
                'anomaly_scores': {
                    k: float(v) for k, v in result['anomaly_scores'].items()
                }
            },
            'models': {
                'timing_params': self.timing_model.get_params(),
                'pattern_params': self.pattern_model.get_params()
            }
        }

        with open(self.intrusion_log, 'a') as f:
            json.dump(log_entry, f)
            f.write('\n')
    
    def save_models(self):
        joblib.dump(self.timing_model, f"{self.model_path}/timing_model.joblib")
        joblib.dump(self.pattern_model, f"{self.model_path}/pattern_model.joblib")
        joblib.dump(self.scaler, f"{self.model_path}/scaler.joblib")
    
    def load_models(self):
        try:
            self.timing_model = joblib.load(f"{self.model_path}/timing_model.joblib")
            self.pattern_model = joblib.load(f"{self.model_path}/pattern_model.joblib")
            self.scaler = joblib.load(f"{self.model_path}/scaler.joblib")
            self.is_trained = True
        except FileNotFoundError:
            print("No trained models found. Training new models...")
            self.train_models()
