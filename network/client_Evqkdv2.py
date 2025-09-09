import socket
import base64
import os
import random
from cryptography.hybrid_encryption import HybridEncryption
from quantum_key_distribution.bb84 import QKDProtocol
from quantum_key_distribution.entanglement_qkd import EntanglementQKD
from quantum_key_distribution.brahmagupta import brahmagupta_mapping, bits_to_bytes
from quantum_key_distribution.ramanujan import ramanujan_modular_mapping

class SecureClient:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port
        self.bb84 = QKDProtocol(key_length=512)
        self.e91 = EntanglementQKD(key_length=512)

    def _combine_keys(self, key_bb84, key_e91):
        int_bb84 = [int("".join(map(str, key_bb84[i:i+8])), 2) for i in range(0, len(key_bb84), 8)]
        int_e91 = [int("".join(map(str, key_e91[i:i+8])), 2) for i in range(0, len(key_e91), 8)]
        combined_int = brahmagupta_mapping(int_bb84, int_e91)
        combined_bits = []
        for val in combined_int:
            combined_bits.extend([(val >> (7-i)) & 1 for i in range(8)])
        final_bits = ramanujan_modular_mapping(combined_bits)
        return final_bits[:len(key_bb84)]

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

            # Generate BB84 + E91 keys and combine
            key_bb84 = self.bb84.generate_key()
            key_e91 = self.e91.generate_key()
            final_bits = self._combine_keys(key_bb84, key_e91)

            # Send sample bits back
            sample_bits = [final_bits[i] for i in sample_indices]
            s.sendall(base64.b64encode(",".join(map(str, sample_bits)).encode()))

            # Receive verification status
            status = s.recv(1024)
            if status != b"OK":
                print("❌ Key verification failed. Exiting.")
                return

            # Receive final key from server (redundant, but sync)
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
