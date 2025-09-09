# ids_test_client.py
import socket
import time
import random
import threading
import argparse

class TrafficGenerator:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        
    def normal_traffic(self, client_id):
        """Simulate normal user behavior"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server_ip, self.server_port))
                for i in range(20):
                    msg = f"NOR{client_id}-{i}: Normal data packet"
                    s.send(msg.encode())
                    time.sleep(random.uniform(0.1, 0.5))
        except Exception as e:
            print(f"Normal client {client_id} error: {e}")

    def syn_flood(self, client_id):
        """Simulate SYN flood attack"""
        print(f"Starting SYN flood attack from client {client_id}")
        try:
            for i in range(100):  # Rapid connection attempts
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    s.connect((self.server_ip, self.server_port))
                    s.send(f"SYN{client_id}-{i}: Attack packet".encode())
                    time.sleep(0.01)
                    s.close()
                except:
                    continue
        except Exception as e:
            print(f"SYN flood error: {e}")

    def mitm_attack(self, client_id):
        """Simulate MITM attack patterns"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server_ip, self.server_port))
                for i in range(50):
                    msg = f"MITM{client_id}-{i}: ARP FF:FF:FF:FF:FF:FF"
                    s.send(msg.encode())
                    time.sleep(0.05)
        except Exception as e:
            print(f"MITM attack error: {e}")

    def os_scan(self, client_id):
        """Simulate OS fingerprinting"""
        probes = [
            "\x00\x01",  # Null bytes
            "A"*500,     # Long string
            "\x1b\x1b",  # Escape sequences
            "GET / HTTP/1.0\n\n"
        ]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.server_ip, self.server_port))
                for i in range(20):
                    for probe in probes:
                        s.send(f"OS{client_id}-{i}: {probe}".encode())
                        time.sleep(0.1)
        except Exception as e:
            print(f"OS scan error: {e}")

    def run_test(self, test_type, num_clients=3):
        threads = []
        
        for i in range(num_clients):
            if test_type == "normal":
                t = threading.Thread(target=self.normal_traffic, args=(i,))
            elif test_type == "syn":
                t = threading.Thread(target=self.syn_flood, args=(i,))
            elif test_type == "mitm":
                t = threading.Thread(target=self.mitm_attack, args=(i,))
            elif test_type == "os":
                t = threading.Thread(target=self.os_scan, args=(i,))
            else:
                raise ValueError(f"Unknown test type: {test_type}")
                
            t.start()
            threads.append(t)
            time.sleep(0.2)  # Stagger client starts
            
        for t in threads:
            t.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("server_ip", help="Server IP address")
    parser.add_argument("server_port", type=int, help="Server port")
    parser.add_argument("test_type", choices=["normal", "syn", "mitm", "os"],
                       help="Type of test to run")
    parser.add_argument("-n", "--num_clients", type=int, default=3,
                       help="Number of concurrent clients")
    
    args = parser.parse_args()
    
    generator = TrafficGenerator(args.server_ip, args.server_port)
    print(f"Starting {args.test_type} test with {args.num_clients} clients...")
    generator.run_test(args.test_type, args.num_clients)
    print("Test completed")
