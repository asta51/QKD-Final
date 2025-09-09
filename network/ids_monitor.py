import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
import streamlit as st
import time
import matplotlib.pyplot as plt
from datetime import datetime
import threading
import queue

class NetworkMonitor:
    def __init__(self):
        self.connections = []
        self.packet_stats = []
        self.anomalies = []
        self.lock = threading.Lock()
        self.data_queue = queue.Queue()
        self.scaler = StandardScaler()
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.is_trained = False
        self.features = [
            'packet_size', 'packet_frequency', 
            'response_time', 'key_entropy'
        ]
        
    def log_connection(self, client_ip):
        with self.lock:
            self.connections.append({
                'ip': client_ip,
                'timestamp': datetime.now(),
                'status': 'connected'
            })
            self._update_dashboard()
    
    def log_disconnection(self, client_ip):
        with self.lock:
            self.connections.append({
                'ip': client_ip,
                'timestamp': datetime.now(),
                'status': 'disconnected'
            })
            self._update_dashboard()
    
    def log_packet(self, packet_size, response_time, key_entropy):
        timestamp = datetime.now()
        with self.lock:
            # Calculate packet frequency (last 10 packets)
            freq = 1.0  # default
            if len(self.packet_stats) > 0:
                last_10_seconds = [p for p in self.packet_stats 
                                 if (timestamp - p['timestamp']).total_seconds() < 10]
                freq = len(last_10_seconds) / 10.0 if len(last_10_seconds) > 0 else 1.0
            
            packet_data = {
                'timestamp': timestamp,
                'packet_size': packet_size,
                'response_time': response_time,
                'packet_frequency': freq,
                'key_entropy': key_entropy
            }
            self.packet_stats.append(packet_data)
            self.data_queue.put(packet_data)
            self._update_dashboard()
    
    def _calculate_entropy(self, key_bits):
        """Calculate Shannon entropy of the quantum key"""
        if not key_bits:
            return 0
        _, counts = np.unique(key_bits, return_counts=True)
        probabilities = counts / counts.sum()
        return -np.sum(probabilities * np.log2(probabilities))
    
    def train_model(self):
        """Train the anomaly detection model with initial data"""
        if len(self.packet_stats) < 50:
            return False
        
        df = pd.DataFrame(self.packet_stats)
        X = df[self.features]
        self.scaler.fit(X)
        X_scaled = self.scaler.transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        return True
    
    def detect_anomalies(self):
        """Detect anomalies in recent network traffic"""
        if not self.is_trained or len(self.packet_stats) < 1:
            return []
        
        recent_data = pd.DataFrame(self.packet_stats[-100:])  # Last 100 packets
        X = recent_data[self.features]
        X_scaled = self.scaler.transform(X)
        
        # Get anomaly scores (-1 is outlier, 1 is inlier)
        anomalies = self.model.predict(X_scaled)
        recent_data['anomaly'] = anomalies
        
        # Log detected anomalies
        for _, row in recent_data[recent_data['anomaly'] == -1].iterrows():
            self.anomalies.append({
                'timestamp': row['timestamp'],
                'type': 'network_anomaly',
                'details': {
                    'packet_size': row['packet_size'],
                    'response_time': row['response_time'],
                    'score': anomalies[0]
                }
            })
        
        return recent_data[recent_data['anomaly'] == -1].to_dict('records')
    
    def _update_dashboard(self):
        """Update Streamlit dashboard in real-time"""
        if st.session_state.get('dashboard_active', False):
            st.rerun()
    
    def run_monitor(self):
        """Main monitoring loop to process data and detect anomalies"""
        while True:
            try:
                # Process new data every second
                time.sleep(1)
                
                if not self.data_queue.empty():
                    # Train model if not trained yet
                    if not self.is_trained and len(self.packet_stats) >= 50:
                        self.train_model()
                    
                    # Detect anomalies
                    if self.is_trained:
                        self.detect_anomalies()
                        
            except Exception as e:
                print(f"Monitor error: {e}")

def start_monitor_ui(monitor):
    st.set_page_config(layout="wide")
    st.title("Quantum Network Security Monitor")
    
    # Initialize session state
    if 'dashboard_active' not in st.session_state:
        st.session_state.dashboard_active = True
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["Live Traffic", "Connections", "Anomalies"])
    
    with tab1:
        st.header("Network Traffic Analysis")
        col1, col2 = st.columns(2)
        
        with col1:
            if monitor.packet_stats:
                df = pd.DataFrame(monitor.packet_stats[-100:])  # Last 100 packets
                st.line_chart(df.set_index('timestamp')[['packet_size', 'response_time']])
        
        with col2:
            if monitor.packet_stats:
                df = pd.DataFrame(monitor.packet_stats[-100:])
                st.bar_chart(df.set_index('timestamp')['packet_frequency'])
    
    with tab2:
        st.header("Active Connections")
        if monitor.connections:
            # Get unique clients
            clients = {conn['ip']: conn['status'] 
                      for conn in monitor.connections[-20:]}  # Last 20 connections
            st.dataframe(pd.DataFrame.from_dict(clients, orient='index', columns=['Status']))
    
    with tab3:
        st.header("Detected Anomalies")
        if monitor.anomalies:
            anomalies_df = pd.DataFrame(monitor.anomalies)
            st.dataframe(anomalies_df)
            
            # Plot anomaly timeline
            if not anomalies_df.empty:
                anomalies_df['timestamp'] = pd.to_datetime(anomalies_df['timestamp'])
                anomalies_df.set_index('timestamp', inplace=True)
                st.line_chart(anomalies_df.resample('1T').size().rename('Anomalies per minute'))
    
    # Auto-refresh every 5 seconds
    time.sleep(5)
    st.rerun()

if __name__ == "__main__":
    monitor = NetworkMonitor()
    # Start monitor thread
    threading.Thread(target=monitor.run_monitor, daemon=True).start()
    # Start Streamlit UI
    start_monitor_ui(monitor)
