import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import time
from datetime import datetime
import json
from threading import Lock
import socket

# Mock data generator for testing
def generate_mock_data():
    return {
        'total_clients': np.random.randint(0, 10),
        'clients': [{
            'ip': f"192.168.1.{i}",
            'port': np.random.randint(8000, 9000),
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'message_count': np.random.randint(1, 100),
            'total_bytes': np.random.randint(100, 10000),
            'anomaly_count': np.random.randint(0, 5)
        } for i in range(np.random.randint(1, 5))],
        'anomalies': [{
            'timestamp': datetime.now().isoformat(),
            'score': np.random.uniform(-1, 0),
            'client_ip': f"192.168.1.{np.random.randint(1, 5)}"
        } for _ in range(np.random.randint(0, 3))]
    }

class MonitoringDashboard:
    def __init__(self, server_host='localhost', server_port=65432):
        self.server_host = server_host
        self.server_port = server_port
        self.update_interval = 2  # seconds
        self.lock = Lock()
        self.data = {
            'total_clients': 0,
            'clients': [],
            'anomalies': []
        }
        
    def fetch_data(self):
        """Fetch data from server (in a real implementation)"""
        try:
            # In a real implementation, you would connect to the server's monitoring API
            # For now, we'll use mock data
            return generate_mock_data()
        except:
            return self.data

    def update_data(self):
        """Update the dashboard data"""
        with self.lock:
            new_data = self.fetch_data()
            self.data = new_data

    def run(self):
        """Run the Streamlit dashboard"""
        st.set_page_config(
            page_title="QKD Network Monitor",
            page_icon="🔐",
            layout="wide"
        )
        
        st.title("Quantum Key Distribution Network Monitor")
        st.markdown("""
        Real-time monitoring of quantum-secured communications with AI-powered anomaly detection.
        """)
        
        # Create placeholder elements
        status_cols = st.columns(4)
        client_placeholder = st.empty()
        anomaly_placeholder = st.empty()
        traffic_placeholder = st.empty()
        
        while True:
            self.update_data()
            
            with self.lock:
                # Status metrics
                with status_cols[0]:
                    st.metric("Total Clients", self.data['total_clients'])
                
                with status_cols[1]:
                    total_messages = sum(c['message_count'] for c in self.data['clients'])
                    st.metric("Total Messages", total_messages)
                
                with status_cols[2]:
                    total_anomalies = len(self.data['anomalies'])
                    st.metric("Anomalies Detected", total_anomalies)
                
                with status_cols[3]:
                    current_time = datetime.now().strftime("%H:%M:%S")
                    st.metric("Last Update", current_time)
                
                # Clients table
                with client_placeholder.container():
                    st.subheader("Connected Clients")
                    if self.data['clients']:
                        df_clients = pd.DataFrame(self.data['clients'])
                        st.dataframe(df_clients)
                    else:
                        st.info("No clients currently connected")
                
                # Anomalies visualization
                with anomaly_placeholder.container():
                    st.subheader("Anomaly Detection")
                    if self.data['anomalies']:
                        df_anomalies = pd.DataFrame(self.data['anomalies'])
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            fig = px.bar(
                                df_anomalies,
                                x='timestamp',
                                y='score',
                                color='client_ip',
                                title="Anomaly Scores Over Time"
                            )
                            st.plotly_chart(fig, use_container_width=True)
                        
                        with col2:
                            anomaly_counts = df_anomalies['client_ip'].value_counts().reset_index()
                            anomaly_counts.columns = ['Client IP', 'Count']
                            fig = px.pie(
                                anomaly_counts,
                                values='Count',
                                names='Client IP',
                                title="Anomalies by Client"
                            )
                            st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.success("No anomalies detected in recent traffic")
                
                # Traffic patterns (simulated)
                with traffic_placeholder.container():
                    st.subheader("Traffic Patterns")
                    # Generate some time series data
                    time_series = pd.DataFrame({
                        'time': pd.date_range(end=datetime.now(), periods=100, freq='S'),
                        'messages': np.random.poisson(5, 100).cumsum(),
                        'bytes': np.random.poisson(1000, 100).cumsum()
                    })
                    
                    fig = px.line(
                        time_series,
                        x='time',
                        y=['messages', 'bytes'],
                        title="Message and Byte Traffic Over Time",
                        labels={'value': 'Count', 'variable': 'Metric'}
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            time.sleep(self.update_interval)

if __name__ == "__main__":
    dashboard = MonitoringDashboard()
    dashboard.run()
