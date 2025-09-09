import numpy as np
import pandas as pd
from scipy import stats
import time
from collections import deque
import socket
import threading
import matplotlib.pyplot as plt
from datetime import datetime
import random

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

def generate_mock_traffic(detector, duration=60):
    """Generate simulated network traffic for testing"""
    start_time = time.time()
    ips = ["192.168.1." + str(i) for i in range(1, 6)]
    
    while time.time() - start_time < duration:
        # Generate normal traffic
        size = random.randint(50, 150)
        ip = random.choice(ips)
        is_anomaly = detector.add_packet(size, ip)
        
        if is_anomaly:
            print(f"🚨 Anomaly detected from {ip} - packet size: {size}")
        
        # Occasionally generate an anomaly
        if random.random() < 0.05:  # 5% chance of anomaly
            anomaly_size = random.randint(300, 1000)
            anomaly_ip = random.choice(ips)
            detector.add_packet(anomaly_size, anomaly_ip)
            print(f"🔥 Generated anomaly from {anomaly_ip} - size: {anomaly_size}")
        
        time.sleep(random.uniform(0.01, 0.2))

def print_stats(detector):
    """Print current statistics"""
    while True:
        stats = detector.get_stats()
        print("\n=== Current Stats ===")
        print(f"Total Packets: {stats['total_packets']}")
        print(f"Active Clients: {len(stats['active_clients'])}")
        print(f"Packet Rate: {stats['current_rate']:.2f} packets/sec")
        print(f"Mean Packet Size: {stats['mean_packet_size']:.2f} bytes")
        
        if stats['recent_anomalies']:
            print("\nRecent Anomalies:")
            for anomaly in stats['recent_anomalies']:
                print(f"- {anomaly['src_ip']} at {datetime.fromtimestamp(anomaly['timestamp']).strftime('%H:%M:%S')}")
        
        time.sleep(2)

def main():
    # Create intrusion detector
    detector = IntrusionDetector()
    
    # Start stats printer thread
    stats_thread = threading.Thread(target=print_stats, args=(detector,))
    stats_thread.daemon = True
    stats_thread.start()
    
    # Generate mock traffic
    print("Starting mock traffic generation...")
    generate_mock_traffic(detector, duration=120)
    
    # After traffic generation, print final report
    print("\n=== Final Report ===")
    stats = detector.get_stats()
    print(f"Total packets processed: {stats['total_packets']}")
    print(f"Total clients observed: {stats['total_clients']}")
    print(f"Total anomalies detected: {len(stats['recent_anomalies'])}")
    
    if stats['recent_anomalies']:
        print("\nAnomaly Details:")
        for anomaly in stats['recent_anomalies']:
            print(f"- {anomaly['type']} anomaly from {anomaly['src_ip']}: "
                  f"size={anomaly['size']}, z-score={anomaly['z_score_size']:.2f}")

if __name__ == "__main__":
    main()
