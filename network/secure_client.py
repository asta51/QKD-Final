import socket
import base64
import binascii
import sys
import time
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
        self.connection_attempts = 0
        self.max_attempts = 3
        self.retry_delay = 2.0

    def _test_connection(self):
        """Test basic network connectivity with retries"""
        for attempt in range(self.max_attempts):
            try:
                #test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                #test_socket.settimeout(5.0)
                #test_socket.connect((self.host, self.port))
                #test_socket.close()
                #result = test_socket.connect_ex((self.host, self.port))  # ❗ non-intrusive test
                #test_socket.close()
                #if result == 0:
                    #return True
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
        """Validate the received quantum key"""
        if not key_bytes:
            raise ValueError("Empty key received")
        if len(key_bytes) * 8 < self.key_length // 2:
            raise ValueError(f"Key too short. Got {len(key_bytes)} bytes, expected at least {self.key_length//8}")

    def _establish_session(self, s):
        """Handle the quantum key exchange and session setup"""
        print("Connected to server. Establishing quantum-secured channel...")
        
        # Receive quantum key
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

    def _chat_loop(self, s, crypto):
        """Handle the encrypted chat session"""
        print("Quantum-secured connection established!")
        print("💬 Type 'exit' to quit\n")

        while True:
            try:
                # Send message
                message = input("You: ").strip()
                if not message:
                    continue
                    
                if message.lower() == 'exit':
                    s.sendall(crypto.encrypt("CLIENT_TERMINATING").encode('utf-8'))
                    print("Closing connection gracefully...")
                    break

                encrypted_msg = crypto.encrypt(message).encode('utf-8')
                s.sendall(encrypted_msg)

                # Receive response
                response = s.recv(self.buffer_size)
                if not response:
                    print("Server closed the connection")
                    break

                decrypted = crypto.decrypt(response.decode('utf-8'))
                print(f"Server: {decrypted}")

            except socket.timeout:
                print("No response from server - connection may be unstable")
                break
            except Exception as e:
                print(f"Communication error: {str(e)}")
                break

    def start_session(self):
        if not self._test_connection():
            print("❌ Cannot establish basic network connection. Check:")
            print(f"  - Is server running at {self.host}:{self.port}?")
            print("  - Is the network/firewall blocking the connection?")
            return

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.connection_timeout)
                print(f"🔗 Connecting to {self.host}:{self.port}...")

                try:
                    s.connect((self.host, self.port))
                except socket.timeout:
                    print("⌛ Connection timed out - server may be busy or not responding")
                    return
                except ConnectionRefusedError:
                    print("❌ Connection refused - server may not be running")
                    return

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
