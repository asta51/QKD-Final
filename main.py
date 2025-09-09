# main.py
import threading
import time
import streamlit as st
from network.server import SecureServer
from monitoring.dashboard import QuantumMonitoringDashboard
from ai_monitoring.intrusion_detection import AIIntrusionDetection

def run_server(detector):
    server = SecureServer(detector)
    try:
        server.start()
    except KeyboardInterrupt:
        server.stop()

def run_dashboard(detector):
    dashboard = QuantumMonitoringDashboard(detector)
    while True:
        dashboard.display_dashboard()
        time.sleep(2)

if __name__ == "__main__":
    detector = AIIntrusionDetection()
    
    # Optional: Load existing model or initialize
    try:
        detector.load_model()
        if detector.is_trained:
            print(f"[✅] Model loaded from disk.")
        else:
            raise FileNotFoundError
    except:
        dummy_data = [
            {'duration': 5.2, 'encrypted_data': 'a'*100, 'retry_count': 0, 'data_frequency': 2.5, 'error_count': 0},
            {'duration': 3.1, 'encrypted_data': 'a'*80,  'retry_count': 0, 'data_frequency': 1.8, 'error_count': 0},
        ]
        detector.train_model(dummy_data)
        print(f"[✅] Model trained on {len(dummy_data)} real samples.")

    # Run server in separate thread with detector
    server_thread = threading.Thread(target=run_server, args=(detector,))
    server_thread.daemon = True
    server_thread.start()

    # Run dashboard
    run_dashboard(detector)
