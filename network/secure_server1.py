import socket
import threading
import base64
from cryptography.hybrid_encryption import HybridEncryption
from quantum_key_distribution.bb84 import QKDProtocol  # Using the correct class name

class SecureServer:
    def __init__(self, host='0.0.0.0', port=65432):
        self.host = host
        self.port = port
        self.running = False
        self.qkd = QKDProtocol(key_length=512)  # Using QKDProtocol instead of BB84

    def _bits_to_bytes(self, bits):
        """Convert list of bits to bytes"""
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i+j < len(bits):
                    byte |= bits[i+j] << (7-j)
            byte_array.append(byte)
        return bytes(byte_array)

    def _handle_client(self, conn, addr):
        try:
            print(f"Quantum connection established with {addr}")
            
            # Generate quantum key
            final_key_bits = self.qkd.generate_key()
            # print(f"bits :{final_key_bits}")

            # raw_data = self.qkd.get_raw_data()
            # print(f"Alice Bits  : {raw_data['alice_bits']}")
            # symbols = {0: '+', 1: '×'}
            # alice_base_symbols = [symbols[b] for b in raw_data['alice_bases']]
            # print(f"Alice Bases : {''.join(alice_base_symbols)}")
            # bob_base_symbols = [symbols[b] for b in raw_data['bob_bases']]
            # print(f"Bob Bases   : {''.join(bob_base_symbols)}")
            # print(f"Bob Bits    : {raw_data['bob_bits']}")
            
            # Convert to bytes and send
            key_bytes = self._bits_to_bytes(final_key_bits)
            conn.sendall(base64.b64encode(key_bytes))
            
            # Initialize encryption
            crypto = HybridEncryption(key_bytes)
            
            # Secure communication phase
            while self.running:
                try:
                    encrypted = conn.recv(4096)
                    if not encrypted:
                        break
                        
                    plaintext = crypto.decrypt(encrypted.decode())
                    print(f"\nClient {addr}: {plaintext}")
                    
                    response = input("Your response: ")
                    conn.sendall(crypto.encrypt(response).encode())
                    
                except Exception as e:
                    print(f"Decryption error: {e}")
                    break
                    
        finally:
            conn.close()
            print(f"Quantum channel with {addr} closed")

    def start(self):
        self.running = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}")

            while self.running:
                conn, addr = s.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr)).start()

    def stop(self):
        self.running = False

if __name__ == "__main__":
    server = SecureServer()
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()
