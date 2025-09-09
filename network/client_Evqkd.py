import socket
import base64
import os
from cryptography.hybrid_encryption import HybridEncryption

class SecureClient:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port

    def _send_file(self, s, crypto, file_path):
        if not os.path.exists(file_path):
            print("❌ File not found")
            return
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = crypto.encrypt_bytes(data)
        filename = os.path.basename(file_path).encode()
        s.sendall(b"FILE_TRANSFER_START")
        s.sendall(filename + b"\n")
        s.sendall(encrypted_data)
        s.sendall(b"FILE_TRANSFER_END")
        print(f"✅ File sent: {file_path}")

    def _receive_file(self, s, crypto):
        filename = b""
        while not filename.endswith(b"\n"):
            filename += s.recv(1)
        filename = filename.strip().decode()
        file_data = b""
        while True:
            chunk = s.recv(4096)
            if chunk.endswith(b"FILE_TRANSFER_END"):
                file_data += chunk[:-len(b"FILE_TRANSFER_END")]
                break
            file_data += chunk
        decrypted_data = crypto.decrypt_bytes(file_data)
        with open("received_from_server_" + filename, 'wb') as f:
            f.write(decrypted_data)
        print(f"📥 Received file: received_from_server_{filename}")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")

            # --- Key verification ---
            encoded_indices = s.recv(1024)
            sample_indices = list(map(int, base64.b64decode(encoded_indices).decode().split(",")))

            # For simulation, client temporarily stores dummy key (same length)
            dummy_key_bits = [0]*512  # in real QKD, client gets measured key
            sample_bits = [dummy_key_bits[i] for i in sample_indices]
            s.sendall(base64.b64encode(",".join(map(str, sample_bits)).encode()))

            # Receive status
            status = s.recv(1024)
            if status != b"OK":
                print("❌ Key verification failed. Exiting.")
                return

            # Receive final key
            encoded_key = s.recv(2048)
            key_bytes = base64.b64decode(encoded_key)
            crypto = HybridEncryption(key_bytes)
            print("💬 Quantum-secured connection established!")
            print("Type 'sendfile <path>' to send a file or 'exit' to quit.")

            # --- Chat loop ---
            while True:
                msg = input("You: ").strip()
                if not msg:
                    continue
                if msg.lower() == "exit":
                    break
                if msg.startswith("sendfile "):
                    path = msg.split(" ", 1)[1]
                    self._send_file(s, crypto, path)
                    continue
                s.sendall(crypto.encrypt(msg).encode())
                resp = s.recv(4096)
                if resp == b"FILE_TRANSFER_START":
                    self._receive_file(s, crypto)
                elif resp:
                    print("Server:", crypto.decrypt(resp.decode()))

if __name__ == "__main__":
    client = SecureClient()
    client.start()
