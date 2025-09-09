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

    def _send_msg(self, s, msg):
        data = pickle.dumps(msg)
        s.sendall(len(data).to_bytes(4,'big'))
        s.sendall(data)

    def _recv_msg(self, s):
        raw_len = s.recv(4)
        if not raw_len:
            raise ConnectionError("Server disconnected")
        length = int.from_bytes(raw_len,'big')
        data = b''
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk: raise ConnectionError
            data += chunk
        return pickle.loads(data)

    def _measure_entangled_qubits(self, circuits, bases):
        bits = []
        for i,qc in enumerate(circuits):
            if bases[i]==1: qc.h(1)
            qc.measure(1,0)
            result = self.backend.run(qc,shots=1,memory=True).result()
            bits.append(int(result.get_memory(qc)[0]))
        return bits

    def start(self):
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as s:
            s.connect((self.host,self.port))
            print(f"Connected to server at {self.host}:{self.port}")

            # --- BB84 ---
            qc_bb84 = self._recv_msg(s)
            bob_bases = [random.randint(0,1) for _ in range(qc_bb84.num_qubits)]
            self._send_msg(s, bob_bases)
            for i,b in enumerate(bob_bases):
                if b==1: qc_bb84.h(i)
            qc_bb84.measure(range(len(bob_bases)), range(len(bob_bases)))
            result = self.backend.run(qc_bb84,shots=1,memory=True).result()
            measured_bits_bb84 = [int(b) for b in result.get_memory(qc_bb84)[0][::-1]]

            # --- E91 ---
            e91_circuits = self._recv_msg(s)
            bob_bases_e91 = [random.randint(0,1) for _ in range(len(e91_circuits))]
            self._send_msg(s,bob_bases_e91)
            measured_bits_e91 = self._measure_entangled_qubits(e91_circuits, bob_bases_e91)

            # --- SIFTING & QBER ---
            sift_bb84_info = self._recv_msg(s)
            sift_idx_bb84 = sift_bb84_info['sifted_indices_bb84']
            sift_bb84_bits = [measured_bits_bb84[i] for i in sift_idx_bb84]

            qber_info = self._recv_msg(s)
            qber_idx = qber_info['qber_indices']
            qber_sample = {i: sift_bb84_bits[i] for i in qber_idx}
            self._send_msg(s,qber_sample)

            status = self._recv_msg(s)
            if status['status']=="FAIL":
                print("❌ QBER failed. Abort."); return
            print("QBER check passed.")

            sift_e91_info = self._recv_msg(s)
            sift_idx_e91 = sift_e91_info['sifted_indices_e91']
            sift_e91_bits = [measured_bits_e91[i] for i in sift_idx_e91]

            # --- FINAL KEY ---
            final_bb84_bits = [b for i,b in enumerate(sift_bb84_bits) if i not in qber_idx]
            self._send_msg(s, sift_e91_bits)

            key1 = bits_to_bytes(final_bb84_bits)
            key2 = bits_to_bytes(sift_e91_bits)
            combined = brahmagupta_key_composition(key1,key2)
            final_key = ramanujan_inspired_kdf(combined)
            aes_key = sha256(final_key).digest()[:16]

            print("🔐 Secure channel established!")
            aesgcm = AESGCM(aes_key)

            while True:
                msg = input("You: ").strip()
                if msg.lower()=="exit": break
                nonce = os.urandom(12)
                s.sendall(nonce + aesgcm.encrypt(nonce,msg.encode(),None))
                resp = s.recv(1024)
                if not resp: break
                nonce, ciphertext = resp[:12], resp[12:]
                print("Server:", aesgcm.decrypt(nonce,ciphertext,None).decode())

if __name__=="__main__":
    SecureClient(HOST,PORT).start()
