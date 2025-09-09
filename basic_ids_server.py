# basic_ids_server.py
import socket
import threading
import time
from ids.real_time_ids import IntrusionDetector

HOST = '0.0.0.0'
PORT = 9999
ids = IntrusionDetector()

def handle_client(conn, addr):
    print(f"[+] Connection from {addr}")
    with conn:
        while True:
            data = conn.recv(4096)
            if not data:
                break

            msg = data.decode().strip()
            log = {
                "ip": addr[0],
                "timestamp": time.time(),
                "length": len(msg),
                "message": msg
            }

            result = ids.process(log)
            print(f"[LOG] From {addr}: {msg}")
            print(f"🔍 IDS: {result['anomaly']} | {result['anomaly_details']}\n")

            response = "ALERT" if result["anomaly"] else "OK"
            conn.sendall(response.encode())

def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"🚀 IDS test server running on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()

if __name__ == "__main__":
    start_server()
