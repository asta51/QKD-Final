# ids_test_server.py
import socket
import time
import json
from threading import Thread
import numpy as np
from collections import defaultdict

# Import your IDS (make sure the path is correct)
from ids.real_time_ids import IntrusionDetector

class IDSTestServer:
    def __init__(self, host='0.0.0.0', port=9999):
        self.host = host
        self.port = port
        self.ids = IntrusionDetector(window=10)  # Smaller window for testing
        self.running = False
        self.connections = []
        self.stats = defaultdict(int)
        
    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"🚀 Server started on {self.host}:{self.port}")
        
        try:
            while self.running:
                client_socket, addr = self.server_socket.accept()
                thread = Thread(target=self.handle_client, args=(client_socket, addr))
                thread.daemon = True
                thread.start()
                self.connections.append(thread)
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.stop()
    
    def handle_client(self, client_socket, addr):
        ip, port = addr
        print(f"New connection from {ip}:{port}")
        
        try:
            while self.running:
                try:
                    data = client_socket.recv(1024)
                    if not data:
                        break
                        
                    log_entry = {
                        'ip': ip,
                        'timestamp': time.time(),
                        'length': len(data),
                        'message': data.decode('utf-8', errors='ignore'),
                        'port': port
                    }
                    
                    result = self.ids.process(log_entry)
                    
                    if result['anomaly']:
                        self.stats['anomalies'] += 1
                        print(f"\n🚨 ALERT! Detected {result['anomaly_details']}")
                        print(f"   Message: {log_entry['message'][:100]}")
                    else:
                        self.stats['normal'] += 1
                        
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"Error processing: {e}")
                    break
                    
        finally:
            client_socket.close()
            print(f"Connection closed from {ip}:{port}")
    
    def stop(self):
        self.running = False
        for thread in self.connections:
            thread.join()
        self.server_socket.close()
        print("\n📊 Statistics:")
        print(f"Normal packets: {self.stats['normal']}")
        print(f"Anomalies detected: {self.stats['anomalies']}")
        print("Server stopped")

if __name__ == "__main__":
    server = IDSTestServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
