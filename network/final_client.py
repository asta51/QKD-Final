import socket
import pickle
import random
import os
from qiskit_aer import AerSimulator
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256

from quantum_key_distribution.brahmagupta import brahmagupta_key_composition
from quantum_key_distribution.ramanujan import ramanujan_inspired_kdf, bits_to_bytes

HOST = 'localhost'
PORT = 65432


class SecureClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.backend = AerSimulator()

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

    # ---------------- File Transfer Helpers ---------------- #
    def _send_file(self, s, aesgcm, path):
        if not os.path.exists(path):
            print("❌ File not found.")
            return
        with open(path, "rb") as f:
            data = f.read()
        payload = pickle.dumps({"file": os.path.basename(path), "data": data})
        nonce = os.urandom(12)
        s.sendall(nonce + aesgcm.encrypt(nonce, payload, None))
        print(f"📤 Sent file: {path}")

    def _recv_file(self, data):
        obj = pickle.loads(data)
        if isinstance(obj, dict) and "file" in obj:
            filename = f"recv_{os.path.basename(obj['file'])}"
            with open(filename, "wb") as f:
                f.write(obj["data"])
            print(f"📁 Received file: {filename}")
            return True
        return False

    # ---------------- Start Client ---------------- #
    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.host, self.port))
            print(f"Connected to server at {self.host}:{self.port}")

            # --- BB84 ---
            qc_bb84 = self._recv_msg(s)
            bob_bases = [random.randint(0, 1) for _ in range(qc_bb84.num_qubits)]
            self._send_msg(s, bob_bases)
            for i, b in enumerate(bob_bases):
                if b == 1:
                    qc_bb84.h(i)
            qc_bb84.measure(range(len(bob_bases)), range(len(bob_bases)))
            result = self.backend.run(qc_bb84, shots=1, memory=True).result()
            measured_bits_bb84 = [int(b) for b in result.get_memory(qc_bb84)[0][::-1]]

            # --- E91 ---
            e91_circuits = self._recv_msg(s)
            bob_bases_e91 = [random.randint(0, 1) for _ in range(len(e91_circuits))]
            self._send_msg(s, bob_bases_e91)
            measured_bits_e91 = self._measure_entangled_qubits(e91_circuits, bob_bases_e91)

            # --- SIFTING & QBER ---
            sift_bb84_info = self._recv_msg(s)
            sift_idx_bb84 = sift_bb84_info['sifted_indices_bb84']
            sift_bb84_bits = [measured_bits_bb84[i] for i in sift_idx_bb84]

            qber_info = self._recv_msg(s)
            qber_idx = qber_info['qber_indices']
            qber_sample = {i: sift_bb84_bits[i] for i in qber_idx}
            self._send_msg(s, qber_sample)

            status = self._recv_msg(s)
            if status['status'] == "FAIL":
                print("❌ QBER failed. Abort.")
                return
            print("QBER check passed.")

            sift_e91_info = self._recv_msg(s)
            sift_idx_e91 = sift_e91_info['sifted_indices_e91']
            sift_e91_bits = [measured_bits_e91[i] for i in sift_idx_e91]

            # --- FINAL KEY ---
            final_bb84_bits = [b for i, b in enumerate(sift_bb84_bits) if i not in qber_idx]
            self._send_msg(s, sift_e91_bits)

            key1 = bits_to_bytes(final_bb84_bits)
            key2 = bits_to_bytes(sift_e91_bits)
            combined = brahmagupta_key_composition(key1, key2)
            final_key = ramanujan_inspired_kdf(combined)
            aes_key = sha256(final_key).digest()[:16]

            print("🔐 Secure channel established!")
            aesgcm = AESGCM(aes_key)

            # --- Secure Communication Loop ---
            while True:
                msg = input("You: ").strip()
                if msg.lower() == "exit":
                    break

                if msg.startswith("sendfile "):
                    path = msg.split(" ", 1)[1]
                    self._send_file(s, aesgcm, path)
                    continue

                nonce = os.urandom(12)
                s.sendall(nonce + aesgcm.encrypt(nonce, msg.encode(), None))

                resp = s.recv(1024 * 64)
                if not resp:
                    break
                nonce, ciphertext = resp[:12], resp[12:]
                data = aesgcm.decrypt(nonce, ciphertext, None)

                try:
                    if self._recv_file(data):
                        continue
                except Exception:
                    pass

                print("Server:", data.decode())


if __name__ == "__main__":
    SecureClient(HOST, PORT).start()
