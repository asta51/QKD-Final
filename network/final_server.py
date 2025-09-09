import socket
import threading
import pickle
import random
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256

# QKD modules
from quantum_key_distribution.bb84 import QKDProtocol
from quantum_key_distribution.entanglement_qkd import EntanglementQKD
from quantum_key_distribution.brahmagupta import brahmagupta_key_composition
from quantum_key_distribution.ramanujan import ramanujan_inspired_kdf, bits_to_bytes

HOST = '0.0.0.0'
PORT = 65432
KEY_LENGTH = 128
QBER_SAMPLE_SIZE = 32
QBER_THRESHOLD = 0.1


class SecureServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.bb84 = QKDProtocol(key_length=KEY_LENGTH * 4)
        self.e91 = EntanglementQKD(key_length=KEY_LENGTH * 4)

    def _send_msg(self, conn, msg):
        data = pickle.dumps(msg)
        conn.sendall(len(data).to_bytes(4, 'big'))
        conn.sendall(data)

    def _recv_msg(self, conn):
        raw_len = conn.recv(4)
        if not raw_len:
            raise ConnectionError("Client disconnected")
        length = int.from_bytes(raw_len, 'big')
        data = b''
        while len(data) < length:
            chunk = conn.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Client disconnected")
            data += chunk
        return pickle.loads(data)

    # ---------------- File Transfer Helpers ---------------- #
    CHUNK_SIZE = 64 * 1024  # 64KB per encrypted chunk

    def _send_file(self, conn, aesgcm, path):
        if not os.path.exists(path):
            print("❌ File not found.")
            return
        filesize = os.path.getsize(path)
        filename = os.path.basename(path)

        # Send metadata first
        meta = pickle.dumps({"file": filename, "size": filesize})
        nonce = os.urandom(12)
        conn.sendall(nonce + aesgcm.encrypt(nonce, meta, None))

        # Send file in chunks
        with open(path, "rb") as f:
            sent = 0
            while chunk := f.read(CHUNK_SIZE):
                payload = pickle.dumps({"chunk": chunk})
                nonce = os.urandom(12)
                conn.sendall(nonce + aesgcm.encrypt(nonce, payload, None))
                sent += len(chunk)
                print(f"📤 Sent {sent}/{filesize} bytes", end="\r")

        # Send EOF marker
        payload = pickle.dumps({"eof": True})
        nonce = os.urandom(12)
        conn.sendall(nonce + aesgcm.encrypt(nonce, payload, None))
        print(f"\n✅ File sent: {filename}")


    def _recv_file(self, data, save_prefix="recv_"):
        obj = pickle.loads(data)

        # Metadata
        if "file" in obj:
            self._current_file = {
                "name": f"{save_prefix}{os.path.basename(obj['file'])}",
                "size": obj["size"],
                "buffer": b"",
            }
            print(f"📥 Receiving file: {self._current_file['name']} ({self._current_file['size']} bytes)")
            return True

        # File chunks
        if "chunk" in obj and hasattr(self, "_current_file"):
            self._current_file["buffer"] += obj["chunk"]
            print(f"⬇️ Received {len(self._current_file['buffer'])}/{self._current_file['size']} bytes", end="\r")
            return True

        # End of file
        if "eof" in obj and hasattr(self, "_current_file"):
            with open(self._current_file["name"], "wb") as f:
                f.write(self._current_file["buffer"])
            print(f"\n✅ File received: {self._current_file['name']}")
            del self._current_file
            return True

        return False

    # ---------------- Client Handler ---------------- #
    def _handle_client(self, conn, addr):
        print(f"✅ Connection from {addr}")
        try:
            print("🚀 Quantum key exchange...")

            # --- BB84 ---
            alice_bits = self.bb84.generate_random_bits(self.bb84.key_length)
            alice_bases = self.bb84.generate_random_bits(self.bb84.key_length)
            qc_bb84 = self.bb84.encode_qubits(alice_bits, alice_bases)
            self._send_msg(conn, qc_bb84)
            bob_bases = self._recv_msg(conn)

            # --- E91 ---
            alice_bases_e91 = [random.randint(0, 1) for _ in range(self.e91.key_length)]
            e91_circuits = [self.e91._make_bell_pair_circuit(ab, 0) for ab in alice_bases_e91]
            self._send_msg(conn, e91_circuits)
            bob_bases_e91 = self._recv_msg(conn)

            # --- SIFTING & QBER ---
            sift_bb84_idx = [i for i, (a, b) in enumerate(zip(alice_bases, bob_bases)) if a == b]
            sift_bb84_bits = [alice_bits[i] for i in sift_bb84_idx]
            self._send_msg(conn, {"sifted_indices_bb84": sift_bb84_idx})

            if len(sift_bb84_bits) < QBER_SAMPLE_SIZE:
                raise ValueError("Not enough sifted bits")

            qber_idx = random.sample(range(len(sift_bb84_bits)), QBER_SAMPLE_SIZE)
            qber_sample = {i: sift_bb84_bits[i] for i in qber_idx}
            self._send_msg(conn, {"qber_indices": list(qber_idx)})

            qber_sample_bob = self._recv_msg(conn)
            mismatches = sum(1 for i in qber_idx if qber_sample[i] != qber_sample_bob[i])
            error_rate = mismatches / QBER_SAMPLE_SIZE

            if error_rate > QBER_THRESHOLD:
                print(f"❌ Eavesdrop! QBER={error_rate:.2f}")
                self._send_msg(conn, {"status": "FAIL"})
                return

            self._send_msg(conn, {"status": "OK"})
            sift_e91_idx = [i for i, (a, b) in enumerate(zip(alice_bases_e91, bob_bases_e91)) if a == b]
            self._send_msg(conn, {"sifted_indices_e91": sift_e91_idx})

            # --- FINAL KEY ---
            final_bb84_bits = [bit for i, bit in enumerate(sift_bb84_bits) if i not in qber_idx]
            sift_e91_from_bob = self._recv_msg(conn)

            key1 = bits_to_bytes(final_bb84_bits)
            key2 = bits_to_bytes(sift_e91_from_bob)
            combined = brahmagupta_key_composition(key1, key2)
            final_key = ramanujan_inspired_kdf(combined)
            aes_key = sha256(final_key).digest()[:16]
            print("🔐 Secure channel established!")

            aesgcm = AESGCM(aes_key)

            # --- Secure Communication Loop ---
            while True:
                enc = conn.recv(1024 * 64)
                if not enc:
                    break
                nonce, ciphertext = enc[:12], enc[12:]
                data = aesgcm.decrypt(nonce, ciphertext, None)

                # File or Text?
                try:
                    if self._recv_file(data):
                        continue
                except Exception:
                    pass

                msg = data.decode()
                print(f"\nClient: {msg}")

                resp = input("You: ")
                if resp.startswith("sendfile "):
                    path = resp.split(" ", 1)[1]
                    self._send_file(conn, aesgcm, path)
                    continue

                nonce = os.urandom(12)
                conn.sendall(nonce + aesgcm.encrypt(nonce, resp.encode(), None))

        except Exception as e:
            print(f"Error with {addr}: {e}")
        finally:
            conn.close()
            print(f"Connection closed: {addr}")

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.host, self.port))
            s.listen()
            print(f"Server listening on {self.host}:{self.port}")
            while True:
                conn, addr = s.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    SecureServer(HOST, PORT).start()
