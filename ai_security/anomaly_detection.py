import time
import numpy as np
from collections import deque
import json

class QuantumAnomalyDetector:
    def __init__(self, window_size=30, sensitivity=2.5):
        """
        Enhanced anomaly detector for quantum-secured communications
        """
        self.window_size = window_size
        self.sensitivity = sensitivity
        self.observation_window = deque(maxlen=window_size)
        self.baseline_metrics = {
            'mean': 0.0,
            'std': 1.0,
            'min': 0.0,
            'max': 1.0
        }
        self.anomaly_log = "anomalies.log"
        
    def update_baseline(self):
        """Recalculate baseline statistics"""
        if len(self.observation_window) >= self.window_size:
            values = np.array(self.observation_window)
            self.baseline_metrics = {
                'mean': float(np.mean(values)),
                'std': float(np.std(values)),
                'min': float(np.min(values)),
                'max': float(np.max(values))
            }
    
    def add_observation(self, value):
        """
        Record a new observation with timestamp
        Value should be a dictionary containing:
        - packet_size
        - processing_time
        - connection_count 
        """
        timestamp = time.time()
        normalized = self._normalize(value)
        observation = {
            'timestamp': float(timestamp),
            'value': value,
            'normalized': float(normalized)
        }
        self.observation_window.append(observation['normalized'])
        self.update_baseline()
        
    def _normalize(self, metrics):
        """Normalize different metrics to comparable scale"""
        return float(
            0.4 * np.log1p(metrics['packet_size']) +
            0.3 * metrics['processing_time'] * 1000 +
            0.2 * metrics['connection_count'] / 10 +
            0.1 * np.random.random()
        )
    
    def detect_anomaly(self):
        """Check current observations for anomalies"""
        if len(self.observation_window) < self.window_size:
            return False, 0.0
        
        current = self.observation_window[-1]
        z_score = abs(current - self.baseline_metrics['mean']) / max(1e-9, self.baseline_metrics['std'])
        is_anomaly = z_score > self.sensitivity
        
        if is_anomaly:
            self._log_anomaly(float(current), float(z_score))
            
        return is_anomaly, float(z_score)
    
    def _log_anomaly(self, value, score):
        """Log anomaly details with context"""
        anomaly_record = {
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'value': float(value),
            'score': float(score),
            'baseline': {k: float(v) for k, v in self.baseline_metrics.items()},
            'window': [float(v) for v in self.observation_window]
        }
        
        with open(self.anomaly_log, 'a') as f:
            json.dump(anomaly_record, f)
            f.write('\n')

    def get_metrics(self):
        return self.baseline_metrics
