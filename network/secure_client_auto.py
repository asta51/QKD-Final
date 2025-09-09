import socket
import base64
import binascii
import sys
import time
import random
from cryptography.hybrid_encryption import HybridEncryption
from quantum_key_distribution.bb84 import QKDProtocol

class SecureClient:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port
        self.buffer_size = 4096
        self.key_length = 512

    def _validate_key(self, key_bytes):
        if not key_bytes or len(key_bytes) * 8 < self.key_length // 2:
            raise ValueError("Invalid or short key")

    def _establish_session(self, s):
        encoded_key = s.recv(2048)
        if not encoded_key:
            return None

        try:
            key_bytes = base64.b64decode(encoded_key)
            self._validate_key(key_bytes)
            return HybridEncryption(key_bytes)
        except (binascii.Error, ValueError):
            return None

    def _chat_loop(self, s, crypto):
        messages = [
            "Hello", "Ping", "Secure message", "Quantum channel OK",
            "How's the entropy?", "Let's test the key",
            "Iteration #{}", "Benign traffic log"
        ]
        print("💬 Sending 100 benign messages with server ACK...")

        for i in range(1000):
            try:
                msg = random.choice(messages).format(i)
                encrypted = crypto.encrypt(msg).encode()
                s.sendall(encrypted)

                response = s.recv(self.buffer_size)
                if not response:
                    print("Server closed connection")
                    break

                decrypted = crypto.decrypt(response.decode())
                print(f"[Auto] Server: {decrypted}")
                time.sleep(0.1)  # Wait before next message

            except Exception as e:
                print(f"Communication error: {e}")
                break

        # Graceful shutdown
        s.sendall(crypto.encrypt("CLIENT_TERMINATING").encode())
        print("✅ Session completed and terminated.")

    def start_session(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((self.host, self.port))
                crypto = self._establish_session(s)
                if crypto:
                    self._chat_loop(s, crypto)
        except Exception as e:
            print(f"Client error: {e}")

if __name__ == "__main__":
    client = SecureClient()
    client.start_session()
