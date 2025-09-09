# utils/traffic_logger.py
import socket
import json
import time

LOGGING_HOST = "localhost"
LOGGING_PORT = 9999

def send_log(ip: str, direction: str, message: str, anomaly_details=None):
    log_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    data = {
        "timestamp": time.time(),
        "ip": ip,
        "direction": direction,
        "length": len(message),
        "message": message[:100],  # Truncate long messages
        "anomaly_details": anomaly_details or {}
    }
    log_socket.sendto(json.dumps(data).encode(), (LOGGING_HOST, LOGGING_PORT))
    log_socket.close()
