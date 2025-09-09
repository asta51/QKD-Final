import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
import torch
import torch.nn as nn
import torch.nn.functional as F
from collections import deque
import pickle
import json
import time
import logging
from typing import Dict, List, Tuple, Optional

class TrafficAnalyzer:
    """Analyzes network traffic patterns for anomalies"""
    def __init__(self, window_size=50):
        self.window_size = window_size
        self.packet_features = deque(maxlen=window_size)
        self.iforest = IsolationForest(n_estimators=100, contamination=0.05)
        self.lof = LocalOutlierFactor(n_neighbors=20, contamination=0.05)
        self.is_trained = False

    def extract_features(self, packet: Dict) -> List[float]:
        """Extract relevant features from network packet"""
        features = [
            len(packet.get('data', '')),
            packet.get('timestamp', 0),
            packet.get('source_port', 0),
            packet.get('destination_port', 0),
            len(packet.get('headers', {})),
            packet.get('protocol', 0)
        ]
        return features

    def add_packet(self, packet: Dict):
        """Add packet to analysis window"""
        features = self.extract_features(packet)
        self.packet_features.append(features)

        if len(self.packet_features) == self.window_size and not self.is_trained:
            self.train_models()

    def train_models(self):
        """Train anomaly detection models"""
        X = np.array(self.packet_features)
        self.iforest.fit(X)
        self.lof.fit(X)
        self.is_trained = True
        logging.info("AI models trained on baseline traffic")

    def detect_anomalies(self) -> Tuple[bool, float]:
        """Detect anomalies in current window"""
        if not self.is_trained or len(self.packet_features) < self.window_size:
            return False, 0.0

        X = np.array(self.packet_features)
        iforest_scores = self.iforest.decision_function(X)
        lof_scores = self.lof.negative_outlier_factor_

        combined_score = np.mean(iforest_scores) - np.mean(lof_scores)
        threshold = -0.5  # Empirical threshold

        return combined_score < threshold, combined_score

class LSTMQAnomalyDetector(nn.Module):
    def __init__(self):
        super(LSTMQAnomalyDetector, self).__init__()
        self.lstm = nn.LSTM(input_size=1, hidden_size=32, batch_first=True)
        self.fc1 = nn.Linear(32, 16)
        self.fc2 = nn.Linear(16, 1)

    def forward(self, x):
        lstm_out, _ = self.lstm(x)
        last_output = lstm_out[:, -1, :]
        x = F.relu(self.fc1(last_output))
        x = torch.sigmoid(self.fc2(x))
        return x

class QuantumChannelMonitor:
    """Monitors quantum channel for anomalies"""
    def __init__(self):
        self.baseline_error_rate = 0.05
        self.error_rates = []
        self.model = LSTMQAnomalyDetector()
        self.model.eval()

    def update_error_rate(self, qber: float):
        self.error_rates.append(qber)
        if len(self.error_rates) > 100:
            self.error_rates.pop(0)

    def check_quantum_anomaly(self) -> bool:
        if len(self.error_rates) < 10:
            return False

        recent = self.error_rates[-10:]
        if np.mean(recent) > 2 * self.baseline_error_rate:
            return True

        sequence = torch.tensor(recent, dtype=torch.float32).view(1, 10, 1)
        with torch.no_grad():
            prediction = self.model(sequence).item()
        return prediction > 0.9

class BehavioralAnalyzer:
    """Analyzes user/entity behavior patterns"""
    def __init__(self):
        self.behavior_profiles = {}  # {entity_id: behavior_profile}

    def update_behavior(self, entity_id: str, actions: List[str]):
        if entity_id not in self.behavior_profiles:
            self._initialize_profile(entity_id)

        profile = self.behavior_profiles[entity_id]
        for i in range(len(actions)-1):
            from_action, to_action = actions[i], actions[i+1]
            if from_action not in profile['transitions']:
                profile['transitions'][from_action] = {}
            profile['transitions'][from_action][to_action] = \
                profile['transitions'][from_action].get(to_action, 0) + 1
        profile['last_action'] = actions[-1]

    def detect_behavioral_anomaly(self, entity_id: str, current_action: str) -> float:
        if entity_id not in self.behavior_profiles:
            return 0.0

        profile = self.behavior_profiles[entity_id]
        last_action = profile.get('last_action', None)

        if last_action:
            total_transitions = sum(profile['transitions'][last_action].values())
            prob = profile['transitions'][last_action].get(current_action, 0) / total_transitions
            anomaly_score = 1 - prob
            return anomaly_score
        return 0.0

    def _initialize_profile(self, entity_id: str):
        self.behavior_profiles[entity_id] = {
            'transitions': {},
            'last_action': None
        }

class AIDetectionSystem:
    """Orchestrates all AI detection components"""
    def __init__(self):
        self.traffic_analyzer = TrafficAnalyzer()
        self.quantum_monitor = QuantumChannelMonitor()
        self.behavior_analyzer = BehavioralAnalyzer()
        self.thresholds = {
            'traffic': 0.7,
            'quantum': 0.8,
            'behavior': 0.9
        }

    def analyze_packet(self, packet: Dict):
        self.traffic_analyzer.add_packet(packet)
        traffic_anomaly, traffic_score = self.traffic_analyzer.detect_anomalies()
        quantum_anomaly = self.quantum_monitor.check_quantum_anomaly()

        entity_id = packet.get('source_ip', 'unknown')
        actions = [packet.get('action', '')]
        self.behavior_analyzer.update_behavior(entity_id, actions)
        behavior_score = self.behavior_analyzer.detect_behavioral_anomaly(entity_id, actions[-1])

        results = {
            'traffic_anomaly': traffic_anomaly,
            'traffic_score': traffic_score,
            'quantum_anomaly': quantum_anomaly,
            'behavior_score': behavior_score,
            'combined_threat': (traffic_score > self.thresholds['traffic']) or
                               (quantum_anomaly) or
                               (behavior_score > self.thresholds['behavior'])
        }

        return results

    def save_state(self, filepath: str):
        state = {
            'traffic_analyzer': pickle.dumps(self.traffic_analyzer),
            'behavior_profiles': self.behavior_analyzer.behavior_profiles
        }
        with open(filepath, 'wb') as f:
            pickle.dump(state, f)

    def load_state(self, filepath: str):
        with open(filepath, 'rb') as f:
            state = pickle.load(f)
        self.traffic_analyzer = pickle.loads(state['traffic_analyzer'])
        self.behavior_analyzer.behavior_profiles = state['behavior_profiles']
