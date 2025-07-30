import socket
import base64
import binascii
import sys
import time
import os
from cryptography.hybrid_encryption import HybridEncryption
from quantum_key_distribution.bb84 import QKDProtocol

class SecureClient:
    def __init__(self, host='localhost', port=65432):
        self.host = host
        self.port = port
        self.connection_timeout = 15.0
        self.receive_timeout = 30.0
        self.buffer_size = 4096
        self.key_length = 512
        self.max_attempts = 3
        self.retry_delay = 2.0

    def _test_connection(self):
        for attempt in range(self.max_attempts):
            try:
                with socket.create_connection((self.host, self.port), timeout=2):
                    return True
            except Exception as e:
                if attempt < self.max_attempts - 1:
                    print(f"Retrying connection ({attempt + 1}/{self.max_attempts})...")
                    time.sleep(self.retry_delay)
                else:
                    print(f"Network test failed: {str(e)}")
                    return False

    def _validate_key(self, key_bytes):
        if not key_bytes:
            raise ValueError("Empty key received")
        if len(key_bytes) * 8 < self.key_length // 2:
            raise ValueError(f"Key too short. Got {len(key_bytes)} bytes, expected at least {self.key_length//8}")

    def _establish_session(self, s):
        print("Connected to server. Establishing quantum-secured channel...")
        encoded_key = s.recv(2048)
        if not encoded_key:
            print("⚠️ Server closed connection during key exchange")
            return None
        try:
            key_bytes = base64.b64decode(encoded_key)
            self._validate_key(key_bytes)
            return HybridEncryption(key_bytes)
        except binascii.Error:
            print("🔑 Invalid key encoding received")
        except ValueError as ve:
            print(f"🔑 Key validation failed: {str(ve)}")
        return None

    def _send_file(self, s, crypto, file_path):
        if not os.path.exists(file_path):
            print("❌ File not found")
            return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            encrypted_data = crypto.encrypt_bytes(data)
            filename = os.path.basename(file_path).encode('utf-8')
            s.sendall(b"FILE_TRANSFER_START")
            time.sleep(0.2)
            s.sendall(filename + b"\n")
            time.sleep(0.2)
            s.sendall(encrypted_data)
            time.sleep(0.2)
            s.sendall(b"FILE_TRANSFER_END")
            print("✅ File sent successfully")
        except Exception as e:
            print(f"❌ File send failed: {e}")

    def _receive_file(self, s, crypto):
        filename = b""
        while not filename.endswith(b"\n"):
            filename += s.recv(1)
        filename = filename.strip().decode('utf-8')
        file_data = b""
        while True:
            chunk = s.recv(4096)
            if chunk.endswith(b"FILE_TRANSFER_END"):
                file_data += chunk[:-len(b"FILE_TRANSFER_END")]
                break
            file_data += chunk
        try:
            decrypted_data = crypto.decrypt_bytes(file_data)
            with open("received_from_server_" + filename, 'wb') as f:
                f.write(decrypted_data)
            print(f"📥 File '{filename}' received and saved as 'received_from_server_{filename}'")
        except Exception as e:
            print(f"❌ Error saving received file: {e}")

    def _chat_loop(self, s, crypto):
        print("Quantum-secured connection established!")
        print("💬 Type 'exit' to quit")
        print("📁 Type 'sendfile <path>' to send a file\n")

        while True:
            try:
                message = input("You: ").strip()
                if not message:
                    continue

                if message.lower() == 'exit':
                    s.sendall(crypto.encrypt("CLIENT_TERMINATING").encode('utf-8'))
                    print("Closing connection gracefully...")
                    break

                if message.startswith("sendfile "):
                    file_path = message.split(" ", 1)[1]
                    self._send_file(s, crypto, file_path)
                    continue

                encrypted_msg = crypto.encrypt(message).encode('utf-8')
                s.sendall(encrypted_msg)

                response = s.recv(self.buffer_size)
                if response == b"FILE_TRANSFER_START":
                    self._receive_file(s, crypto)
                elif response:
                    decrypted = crypto.decrypt(response.decode('utf-8'))
                    print(f"Server: {decrypted}")
                else:
                    print("Server closed the connection")
                    break

            except socket.timeout:
                print("No response from server - connection may be unstable")
                break
            except Exception as e:
                print(f"Communication error: {str(e)}")
                break

    def start_session(self):
        if not self._test_connection():
            print("❌ Cannot establish basic network connection.")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.connection_timeout)
                print(f"🔗 Connecting to {self.host}:{self.port}...")
                s.connect((self.host, self.port))
                crypto = self._establish_session(s)
                if not crypto:
                    return
                s.settimeout(self.receive_timeout)
                self._chat_loop(s, crypto)

        except KeyboardInterrupt:
            print("\nClient terminated by user")
        except Exception as e:
            print(f"Unexpected error: {type(e).__name__}: {str(e)}")
        finally:
            print("Session ended")

if __name__ == "__main__":
    if len(sys.argv) > 2:
        host, port = sys.argv[1], int(sys.argv[2])
    elif len(sys.argv) > 1:
        host, port = sys.argv[1], 65432
    else:
        host, port = 'localhost', 65432

    print(f"Starting quantum-secured client (connecting to {host}:{port})")
    client = SecureClient(host, port)
    client.start_session()
