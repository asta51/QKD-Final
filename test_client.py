# test_ids_client.py
import socket
import time

HOST = '127.0.0.1'
PORT = 65432

def send_message(message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        time.sleep(0.5)
        print("[*] Sending:", message)
        s.sendall(message.encode())
        try:
            response = s.recv(4096)
            print("[+] Response:", response.decode())
        except:
            pass

if __name__ == "__main__":
    # Normal behavior
    send_message("Hello, secure server.")
    
    # Abnormal behavior (long payload - mimic DoS)
    send_message("X" * 5000)

    # MITM pattern (simulate keyword)
    send_message("arp spoofing test pattern")

    # OS scan pattern (simulate nmap response)
    send_message("SYN scan detected signature")
