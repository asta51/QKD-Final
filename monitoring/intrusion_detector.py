import numpy as np
import pandas as pd
from scipy import stats
import time
from collections import deque
import socket
import threading
import matplotlib.pyplot as plt
from datetime import datetime

class IntrusionDetector:
    def __init__(self, window_size=100, threshold=3.0):
        self.window_size = window_size
        self.threshold = threshold
        self.packet_sizes = deque(maxlen=window_size)
        self.packet_intervals = deque(maxlen=window_size)
        self.anomalies = []
        self.clients = {}
        self.lock = threading.Lock()
        self.start_time = time.time()
        
        # Initialize baseline stats
        self.baseline_mean_size = 0
        self.baseline_std_size = 0
        self.baseline_mean_interval = 0
        self.baseline_std_interval = 0
        self.initialized = False
        
    def update_baseline(self):
        """Establish baseline statistics after collecting enough data"""
        if len(self.packet_sizes) >= self.window_size:
            sizes = np.array(self.packet_sizes)
            intervals = np.array(self.packet_intervals)
            
            self.baseline_mean_size = np.mean(sizes)
            self.baseline_std_size = np.std(sizes)
            self.baseline_mean_interval = np.mean(intervals)
            self.baseline_std_interval = np.std(intervals)
            
            self.initialized = True
            return True
        return False
    
    def add_packet(self, size, src_ip):
        """Process a new network packet"""
        current_time = time.time()
        
        with self.lock:
            # Update client information
            if src_ip not in self.clients:
                self.clients[src_ip] = {
                    'first_seen': current_time,
                    'last_seen': current_time,
                    'packet_count': 1,
                    'total_bytes': size,
                    'recent_activity': deque(maxlen=10)
                }
            else:
                self.clients[src_ip]['last_seen'] = current_time
                self.clients[src_ip]['packet_count'] += 1
                self.clients[src_ip]['total_bytes'] += size
                self.clients[src_ip]['recent_activity'].append((current_time, size))
            
            # Calculate interval if we have previous packets
            if len(self.packet_sizes) > 0:
                interval = current_time - self.last_packet_time
                self.packet_intervals.append(interval)
            
            self.packet_sizes.append(size)
            self.last_packet_time = current_time
            
            # Check for anomalies if baseline is established
            anomaly = False
            if self.initialized:
                z_score_size = (size - self.baseline_mean_size) / self.baseline_std_size
                if len(self.packet_intervals) > 0:
                    last_interval = self.packet_intervals[-1]
                    z_score_interval = (last_interval - self.baseline_mean_interval) / self.baseline_std_interval
                
                if abs(z_score_size) > self.threshold or (len(self.packet_intervals) > 0 and abs(z_score_interval) > self.threshold):
                    anomaly = True
                    self.anomalies.append({
                        'timestamp': current_time,
                        'size': size,
                        'src_ip': src_ip,
                        'z_score_size': z_score_size,
                        'z_score_interval': z_score_interval if len(self.packet_intervals) > 0 else None,
                        'type': 'SIZE' if abs(z_score_size) > self.threshold else 'INTERVAL'
                    })
            
            # Update baseline periodically
            if len(self.packet_sizes) % self.window_size == 0:
                self.update_baseline()
            
            return anomaly
    
    def get_stats(self):
        """Get current statistics"""
        with self.lock:
            stats = {
                'total_packets': len(self.packet_sizes),
                'total_clients': len(self.clients),
                'current_rate': len(self.packet_sizes) / (time.time() - self.start_time) if (time.time() - self.start_time) > 0 else 0,
                'mean_packet_size': np.mean(self.packet_sizes) if len(self.packet_sizes) > 0 else 0,
                'recent_anomalies': self.anomalies[-10:] if len(self.anomalies) > 0 else [],
                'active_clients': [ip for ip, data in self.clients.items() if time.time() - data['last_seen'] < 60],
                'baseline_initialized': self.initialized
            }
            return stats
    
    def get_client_details(self, ip):
        """Get details for a specific client"""
        with self.lock:
            if ip in self.clients:
                return self.clients[ip]
        return None
