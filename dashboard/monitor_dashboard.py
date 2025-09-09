import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import time
from datetime import datetime
from monitoring.intrusion_detector import IntrusionDetector
import socket
import threading

# Mock detector for testing (replace with actual detector from your server)
# detector = IntrusionDetector()

# In a real implementation, you would get the detector instance from your server
# For example:
# from network.secure_server_monitored import MonitoredSecureServer
# server = MonitoredSecureServer()
# detector = server.get_detector()

# For this example, we'll create a global detector
detector = IntrusionDetector()

def start_mock_traffic(detector):
    """Simulate network traffic for demo purposes"""
    import random
    ips = ["192.168.1." + str(i) for i in range(1, 6)]
    while True:
        size = random.randint(50, 150)
        if random.random() < 0.1:  # 10% chance of anomaly
            size = random.randint(300, 500)
        ip = random.choice(ips)
        detector.add_packet(size, ip)
        time.sleep(random.uniform(0.1, 0.5))

# Start mock traffic in a background thread (remove in production)
mock_thread = threading.Thread(target=start_mock_traffic, args=(detector,))
mock_thread.daemon = True
mock_thread.start()

st.set_page_config(page_title="QKD Network Monitor", layout="wide")
st.title("Quantum Key Distribution Network Monitor")

# Create layout
col1, col2 = st.columns([3, 1])

with col2:
    st.header("Network Status")
    status_placeholder = st.empty()
    
    st.header("Active Clients")
    clients_placeholder = st.empty()
    
    st.header("Recent Anomalies")
    anomalies_placeholder = st.empty()

with col1:
    st.header("Traffic Monitoring")
    tab1, tab2, tab3 = st.tabs(["Packet Size", "Traffic Rate", "Client Activity"])
    
    with tab1:
        size_fig = plt.figure(figsize=(10, 4))
        size_ax = size_fig.add_subplot(111)
        size_placeholder = st.pyplot(size_fig)
    
    with tab2:
        rate_fig = plt.figure(figsize=(10, 4))
        rate_ax = rate_fig.add_subplot(111)
        rate_placeholder = st.pyplot(rate_fig)
    
    with tab3:
        client_fig = plt.figure(figsize=(10, 4))
        client_ax = client_fig.add_subplot(111)
        client_placeholder = st.pyplot(client_fig)

# Initialize data storage for charts
if 'packet_data' not in st.session_state:
    st.session_state.packet_data = pd.DataFrame(columns=['timestamp', 'size'])
if 'rate_data' not in st.session_state:
    st.session_state.rate_data = pd.DataFrame(columns=['timestamp', 'rate'])
if 'client_data' not in st.session_state:
    st.session_state.client_data = pd.DataFrame(columns=['timestamp', 'client', 'activity'])

def update_dashboard():
    stats = detector.get_stats()
    
    # Update status panel
    with status_placeholder.container():
        st.metric("Total Packets", stats['total_packets'])
        st.metric("Packet Rate (pps)", f"{stats['current_rate']:.2f}")
        st.metric("Mean Packet Size", f"{stats['mean_packet_size']:.2f} bytes")
        st.metric("Baseline Established", "✅" if stats['baseline_initialized'] else "⏳")
    
    # Update clients panel
    with clients_placeholder.container():
        if stats['active_clients']:
            for ip in stats['active_clients']:
                client = detector.get_client_details(ip)
                if client:
                    st.text(f"IP: {ip}")
                    st.text(f"Packets: {client['packet_count']}")
                    st.text(f"Total Bytes: {client['total_bytes']}")
                    st.text(f"Last Active: {datetime.fromtimestamp(client['last_seen']).strftime('%H:%M:%S')}")
                    st.text("---")
        else:
            st.warning("No active clients")
    
    # Update anomalies panel
    with anomalies_placeholder.container():
        if stats['recent_anomalies']:
            for anomaly in reversed(stats['recent_anomalies']):
                st.warning(f"""
                **{anomaly['type']} Anomaly**  
                Time: {datetime.fromtimestamp(anomaly['timestamp']).strftime('%H:%M:%S')}  
                Size: {anomaly['size']} bytes  
                Source: {anomaly['src_ip']}  
                Z-score: {anomaly['z_score_size']:.2f} (size), {anomaly['z_score_interval']:.2f if anomaly['z_score_interval'] is not None else 'N/A'} (interval)
                """)
        else:
            st.success("No recent anomalies detected")
    
    # Update packet size chart
    if stats['total_packets'] > 0:
        # Add new data point
        new_data = pd.DataFrame({
            'timestamp': [datetime.now()],
            'size': [stats['mean_packet_size']]
        })
        st.session_state.packet_data = pd.concat([st.session_state.packet_data, new_data]).tail(30)
        
        size_ax.clear()
        size_ax.plot(st.session_state.packet_data['timestamp'], st.session_state.packet_data['size'], 'b-')
        size_ax.axhline(y=detector.baseline_mean_size, color='r', linestyle='--', label='Baseline')
        size_ax.set_title('Packet Size Over Time')
        size_ax.set_xlabel('Time')
        size_ax.set_ylabel('Packet Size (bytes)')
        size_ax.legend()
        size_ax.grid(True)
        size_placeholder.pyplot(size_fig)
    
    # Update traffic rate chart
    if stats['total_packets'] > 0:
        new_rate = pd.DataFrame({
            'timestamp': [datetime.now()],
            'rate': [stats['current_rate']]
        })
        st.session_state.rate_data = pd.concat([st.session_state.rate_data, new_rate]).tail(30)
        
        rate_ax.clear()
        rate_ax.plot(st.session_state.rate_data['timestamp'], st.session_state.rate_data['rate'], 'g-')
        rate_ax.set_title('Packet Rate Over Time')
        rate_ax.set_xlabel('Time')
        rate_ax.set_ylabel('Packets per Second')
        rate_ax.grid(True)
        rate_placeholder.pyplot(rate_fig)
    
    # Update client activity chart
    if stats['active_clients']:
        for ip in stats['active_clients']:
            client = detector.get_client_details(ip)
            if client and client['recent_activity']:
                timestamps = [datetime.fromtimestamp(t) for t, _ in client['recent_activity']]
                sizes = [s for _, s in client['recent_activity']]
                
                new_client_data = pd.DataFrame({
                    'timestamp': timestamps,
                    'client': [ip] * len(timestamps),
                    'activity': sizes
                })
                st.session_state.client_data = pd.concat([st.session_state.client_data, new_client_data])
        
        # Keep only data from active clients
        st.session_state.client_data = st.session_state.client_data[
            st.session_state.client_data['client'].isin(stats['active_clients'])
        ].tail(100)
        
        client_ax.clear()
        for ip in stats['active_clients']:
            client_df = st.session_state.client_data[st.session_state.client_data['client'] == ip]
            if not client_df.empty:
                client_ax.plot(client_df['timestamp'], client_df['activity'], label=ip)
        
        client_ax.set_title('Client Activity')
        client_ax.set_xlabel('Time')
        client_ax.set_ylabel('Packet Size (bytes)')
        client_ax.legend()
        client_ax.grid(True)
        client_placeholder.pyplot(client_fig)

# Main loop
while True:
    update_dashboard()
    time.sleep(1)
