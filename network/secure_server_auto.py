import socket
import threading
import base64
from cryptography.hybrid_encryption import HybridEncryption
from quantum_key_distribution.bb84 import QKDProtocol

class SecureServer:
    def __init__(self, host='0.0.0.0', port=65432):
        self.host = host
        self.port = port
        self.running = False
        self.qkd = QKDProtocol(key_length=512)

    def _bits_to_bytes(self, bits):
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i + j < len(bits):
                    byte |= bits[i + j] << (7 - j)
            byte_array.append(byte)
        return bytes(byte_array)

    def _handle_client(self, conn, addr):
        try:
            print(f"Quantum connection established with {addr}")
            key_bits = self.qkd.generate_key()
            key_bytes = self._bits_to_bytes(key_bits)
            conn.sendall(base64.b64encode(key_bytes))

            crypto = HybridEncryption(key_bytes)

            while self.running:
                encrypted = conn.recv(4096)
                if not encrypted:
                    break

                plaintext = crypto.decrypt(encrypted.decode())
                print(f"Client {addr}: {plaintext}")

                if "CLIENT_TERMINATING" in plaintext:
                    break

                response = f"ACK: {plaintext}"
                conn.sendall(crypto.encrypt(response).encode())

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            conn.close()
            print(f"Connection with {addr} closed")

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
