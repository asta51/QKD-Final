import socket
import threading
import base64
import os
import random

from cryptography.hybrid_encryption import HybridEncryption
from quantum_key_distribution.bb84 import QKDProtocol
from quantum_key_distribution.entanglement_qkd import EntanglementQKD
from quantum_key_distribution.brahmagupta import brahmagupta_mapping, bits_to_bytes
from quantum_key_distribution.ramanujan import ramanujan_modular_mapping

class SecureServer:
    def __init__(self, host='0.0.0.0', port=65432):
        self.host = host
        self.port = port
        self.running = False
        self.bb84 = QKDProtocol(key_length=512)
        self.e91 = EntanglementQKD(key_length=512)
        self.verification_sample_size = 32

    def _combine_keys(self, key_bb84, key_e91):
        int_bb84 = [int("".join(map(str, key_bb84[i:i+8])), 2) for i in range(0, len(key_bb84), 8)]
        int_e91 = [int("".join(map(str, key_e91[i:i+8])), 2) for i in range(0, len(key_e91), 8)]
        combined_int = brahmagupta_mapping(int_bb84, int_e91)
        combined_bits = []
        for val in combined_int:
            combined_bits.extend([(val >> (7-i)) & 1 for i in range(8)])
        final_bits = ramanujan_modular_mapping(combined_bits)
        return final_bits[:len(key_bb84)]

    def _verify_key(self, conn, final_bits):
        sample_indices = random.sample(range(len(final_bits)), self.verification_sample_size)
        sample_bits = [final_bits[i] for i in sample_indices]

        # Send indices to client
        payload = base64.b64encode(",".join(map(str, sample_indices)).encode())
        conn.sendall(payload)

        # Receive sample bits from client
        try:
            encoded_response = conn.recv(1024)
            client_bits = list(map(int, base64.b64decode(encoded_response).decode().split(",")))
        except Exception:
            print("❌ Key verification failed (decode error).")
            conn.sendall(b"FAIL")
            return False

        mismatches = sum(1 for a, b in zip(sample_bits, client_bits) if a != b)
        if mismatches == 0:
            conn.sendall(b"OK")
            print("✅ Key verified. No eavesdropping detected.")
            return True
        else:
            conn.sendall(b"FAIL")
            print("❌ Key verification failed! Possible eavesdropping detected.")
            return False

    def _send_file(self, conn, crypto, file_path):
        if not os.path.exists(file_path):
            print("❌ File not found")
            return
        with open(file_path, 'rb') as f:
            data = f.read()
        encrypted_data = crypto.encrypt_bytes(data)
        filename = os.path.basename(file_path).encode()
        conn.sendall(b"FILE_TRANSFER_START")
        conn.sendall(filename + b"\n")
        conn.sendall(encrypted_data)
        conn.sendall(b"FILE_TRANSFER_END")
        print(f"✅ File sent: {file_path}")

    def _receive_file(self, conn, crypto):
        filename = b""
        while not filename.endswith(b"\n"):
            filename += conn.recv(1)
        filename = filename.strip().decode()
        file_data = b""
        while True:
            chunk = conn.recv(4096)
            if chunk.endswith(b"FILE_TRANSFER_END"):
                file_data += chunk[:-len(b"FILE_TRANSFER_END")]
                break
            file_data += chunk
        decrypted_data = crypto.decrypt_bytes(file_data)
        with open("received_from_client_" + filename, 'wb') as f:
            f.write(decrypted_data)
        print(f"📥 Received file: received_from_client_{filename}")

    def _handle_client(self, conn, addr):
        try:
            print(f"Quantum connection established with {addr}")

            # --- QKD: Generate keys ---
            key_bb84 = self.bb84.generate_key()
            key_e91 = self.e91.generate_key()
            final_bits = self._combine_keys(key_bb84, key_e91)
            key_bytes = bits_to_bytes(final_bits)

            # --- Key verification ---
            if not self._verify_key(conn, final_bits):
                conn.close()
                return

            # --- Send final key to client ---
            conn.sendall(base64.b64encode(key_bytes))
            crypto = HybridEncryption(key_bytes)

            # --- Chat/File loop ---
            while self.running:
                data = conn.recv(4096)
                if not data:
                    break

                if data == b"FILE_TRANSFER_START":
                    self._receive_file(conn, crypto)
                    continue

                decrypted = crypto.decrypt(data.decode())
                print(f"\nClient {addr}: {decrypted}")
                response = input("Your response: ")
                conn.sendall(crypto.encrypt(response).encode())

        finally:
            conn.close()
            print(f"Quantum channel with {addr} closed")

    def start(self):
        self.running = True
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"🔐 Server listening on {self.host}:{self.port}")
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
