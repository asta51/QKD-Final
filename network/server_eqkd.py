import socket
import threading
import base64
import os
from cryptography.hybrid_encryption import HybridEncryption
#from quantum_key_distribution.bb84 import QKDProtocol
from quantum_key_distribution.entanglement_qkd import EntanglementQKD

class SecureServer:
    def __init__(self, host='0.0.0.0', port=65432):
        self.host = host
        self.port = port
        self.running = False
        #self.qkd = QKDProtocol(key_length=512)
        self.qkd = EntanglementQKD(key_length=512)

    def _bits_to_bytes(self, bits):
        byte_array = bytearray()
        for i in range(0, len(bits), 8):
            byte = 0
            for j in range(8):
                if i+j < len(bits):
                    byte |= bits[i+j] << (7-j)
            byte_array.append(byte)
        return bytes(byte_array)

    def _send_file(self, conn, crypto, file_path):
        if not os.path.exists(file_path):
            print("❌ File not found")
            return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            encrypted_data = crypto.encrypt_bytes(data)
            filename = os.path.basename(file_path).encode('utf-8')
            conn.sendall(b"FILE_TRANSFER_START")
            conn.sendall(filename + b"\n")
            conn.sendall(encrypted_data)
            conn.sendall(b"FILE_TRANSFER_END")
            print("✅ File sent to client")
        except Exception as e:
            print(f"❌ Failed to send file: {e}")

    def _receive_file(self, conn, crypto):
        filename = b""
        while not filename.endswith(b"\n"):
            filename += conn.recv(1)
        filename = filename.strip().decode('utf-8')
        file_data = b""
        while True:
            chunk = conn.recv(4096)
            if chunk.endswith(b"FILE_TRANSFER_END"):
                file_data += chunk[:-len(b"FILE_TRANSFER_END")]
                break
            file_data += chunk
        try:
            decrypted_data = crypto.decrypt_bytes(file_data)
            with open("received_from_client_" + filename, 'wb') as f:
                f.write(decrypted_data)
            print(f"📥 Received and saved as 'received_from_client_{filename}'")
        except Exception as e:
            print(f"❌ Failed to save file: {e}")

    def _handle_client(self, conn, addr):
        try:
            print(f"Quantum connection established with {addr}")
            key_bits = self.qkd.generate_key()
            key_bytes = self._bits_to_bytes(key_bits)
            conn.sendall(base64.b64encode(key_bytes))
            crypto = HybridEncryption(key_bytes)

            while self.running:
                data = conn.recv(4096)
                if not data:
                    break

                if data == b"FILE_TRANSFER_START":
                    self._receive_file(conn, crypto)
                    continue

                try:
                    decrypted = crypto.decrypt(data.decode('utf-8'))
                    print(f"\nClient {addr}: {decrypted}")
                    if decrypted.startswith("sendfile "):
                        path = decrypted.split(" ", 1)[1]
                        self._send_file(conn, crypto, path)
                    else:
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
            
