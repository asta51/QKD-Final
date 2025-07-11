# network/secure_server_rt.py
import socket
import threading
import base64
import time
import json
import numpy as np
from queue import Queue
from collections import deque
from cryptography.hybrid_encryption import HybridEncryption
from quantum_key_distribution.bb84 import QKDProtocol

class RealTimeSecurityMonitor:
    def __init__(self):
        self.connection_stats = {
            'total': 0,
            'active': 0,
            'throughput': deque(maxlen=60)  # Last minute throughput
        }
        self.packet_metrics = deque(maxlen=1000)  # Last 1000 packets
        self.anomaly_scores = deque(maxlen=60)  # Last minute scores
        self.event_queue = Queue()
        
    def update_connection(self, connected=True):
        if connected:
            self.connection_stats['total'] += 1
            self.connection_stats['active'] += 1
        else:
            self.connection_stats['active'] -= 1
            
    def log_packet(self, size, processing_time):
        timestamp = time.time()
        self.packet_metrics.append({
            'timestamp': timestamp,
            'size': size,
            'processing_time': processing_time
        })
        self.connection_stats['throughput'].append(timestamp)
        
    def check_real_time_anomaly(self):
        if len(self.packet_metrics) < 10:  # Need minimum samples
            return False, 0.0
            
        # Calculate moving statistics
        sizes = np.array([p['size'] for p in self.packet_metrics])
        times = np.array([p['processing_time'] for p in self.packet_metrics])
        
        # Real-time anomaly detection
        size_z = (sizes[-1] - np.mean(sizes[:-1])) / max(1e-9, np.std(sizes[:-1]))
        time_z = (times[-1] - np.mean(times[:-1])) / max(1e-9, np.std(times[:-1]))
        
        combined_score = max(abs(size_z), abs(time_z))
        threshold = 3.5  # 99.9% confidence
        
        if combined_score > threshold:
            self.anomaly_scores.append(combined_score)
            return True, combined_score
        return False, combined_score

class SecureServerRT:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port
        self.running = False
        self.qkd = QKDProtocol(key_length=512)
        self.monitor = RealTimeSecurityMonitor()
        
        # Initialize AI detectors
        self.init_ai_detectors()
        
    def init_ai_detectors(self):
        """Initialize real-time AI models"""
        # These would be more sophisticated in production
        self.size_model = self.create_size_model()
        self.timing_model = self.create_timing_model()
        
    def create_size_model(self):
        """Create baseline model for packet sizes"""
        # In reality, you'd load a pre-trained model
        return {
            'mean': 1024,
            'std': 512,
            'threshold': 3.5
        }
        
    def create_timing_model(self):
        """Create baseline model for processing times"""
        return {
            'mean': 0.1,
            'std': 0.05,
            'threshold': 3.5
        }

    def _handle_client_rt(self, conn, addr):
        """Real-time enhanced client handler"""
        self.monitor.update_connection(True)
        processing_start = time.time()
        
        try:
            # Quantum key exchange
            final_key_bits = self.qkd.generate_key()
            key_bytes = self._bits_to_bytes(final_key_bits)
            conn.sendall(base64.b64encode(key_bytes))
            crypto = HybridEncryption(key_bytes)
            
            # Real-time monitoring loop
            while self.running:
                try:
                    # Receive data
                    encrypted = conn.recv(4096)
                    if not encrypted:
                        break
                        
                    # Measure processing time
                    recv_time = time.time()
                    processing_time = recv_time - processing_start
                    
                    # Update monitoring
                    self.monitor.log_packet(len(encrypted), processing_time)
                    
                    # Real-time anomaly check
                    anomaly, score = self.monitor.check_real_time_anomaly()
                    if anomaly:
                        alert = {
                            'type': 'realtime_anomaly',
                            'client': addr,
                            'timestamp': time.time(),
                            'score': score,
                            'packet_size': len(encrypted),
                            'processing_time': processing_time
                        }
                        self.monitor.event_queue.put(alert)
                        print(f"🚨 Realtime anomaly detected from {addr} (score: {score:.2f})")
                    
                    # Process message
                    plaintext = crypto.decrypt(encrypted.decode())
                    
                    if plaintext == "CLIENT_TERMINATING":
                        break
                        
                    # Send response
                    response = input("Server: ")
                    conn.sendall(crypto.encrypt(response).encode())
                    processing_start = time.time()
                    
                except Exception as e:
                    print(f"Error with {addr}: {str(e)}")
                    break
                    
        finally:
            conn.close()
            self.monitor.update_connection(False)
            print(f"Connection closed with {addr}")

    def start_realtime(self):
        """Start server with real-time monitoring"""
        self.running = True
        
        # Start monitoring dashboard in separate thread
        monitor_thread = threading.Thread(
            target=self.run_realtime_dashboard,
            daemon=True
        )
        monitor_thread.start()
        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"Real-time server listening on {self.host}:{self.port}")

            while self.running:
                conn, addr = s.accept()
                client_thread = threading.Thread(
                    target=self._handle_client_rt,
                    args=(conn, addr)
                )
                client_thread.start()

    def run_realtime_dashboard(self):
        """Console-based real-time dashboard"""
        while self.running:
            try:
                # Process events
                while not self.monitor.event_queue.empty():
                    event = self.monitor.event_queue.get_nowait()
                    self.display_event(event)
                
                # Update stats display
                self.display_stats()
                time.sleep(0.5)
                
            except KeyboardInterrupt:
                break
                
    def display_event(self, event):
        """Display security event"""
        timestamp = time.strftime("%H:%M:%S", time.localtime(event['timestamp']))
        if event['type'] == 'realtime_anomaly':
            print(f"\n[{timestamp}] ANOMALY DETECTED from {event['client']}")
            print(f"  Score: {event['score']:.2f} | Size: {event['packet_size']} bytes")
            print(f"  Processing Time: {event['processing_time']:.4f}s")
            
    def display_stats(self):
        """Display current statistics"""
        stats = self.monitor.connection_stats
        active = stats['active']
        total = stats['total']
        throughput = len([t for t in stats['throughput'] 
                         if time.time() - t < 60])
        
        print(f"\nActive: {active} | Total: {total} | Throughput: {throughput}/min", end='\r')
