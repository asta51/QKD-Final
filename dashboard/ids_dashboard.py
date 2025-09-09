# dashboard/ids_dashboard.py
import streamlit as st
from intrusion_detection.ids import IntrusionDetectionSystem
import pandas as pd
import time
import plotly.express as px

def main():
    st.set_page_config(page_title="Quantum Chat IDS Dashboard", layout="wide")
    
    # Initialize IDS (would normally get this from the running server)
    ids = IntrusionDetectionSystem({
        'Active_Wiretap': 'models/Active_Wiretap_IDS.pt',
        'MITM_ARP': 'models/MITM_ARP_IDS_model.pt',
        'OS_Scan': 'models/OS_IDS_model.pt',
        'SYN_Flood': 'models/SYN_IDS_model.pt'
    })
    ids.start_monitoring()
    
    st.title("Quantum-Secured Chat - Intrusion Detection Dashboard")
    
    # Create layout
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.subheader("Real-time Traffic Metrics")
        metric1, metric2, metric3 = st.columns(3)
        
        throughput_placeholder = metric1.empty()
        packets_placeholder = metric2.empty()
        alerts_placeholder = metric3.empty()
        
        st.subheader("Attack Type Distribution")
        attack_chart = st.empty()
        
    with col2:
        st.subheader("Recent Security Alerts")
        alerts_table = st.empty()
    
    # Update dashboard in real-time
    while True:
        stats = ids.get_traffic_stats()
        alerts = ids.get_recent_alerts(10)
        
        # Update metrics
        throughput_placeholder.metric("Throughput (pps)", f"{stats['current_throughput']:.1f}")
        packets_placeholder.metric("Total Packets", stats['total_packets'])
        alerts_placeholder.metric("Suspicious Packets", stats['suspicious_packets'])
        
        # Update attack distribution chart
        if alerts:
            attack_types = pd.DataFrame([a['attack_type'] for a in alerts], columns=['Attack Type'])
            fig = px.pie(attack_types, names='Attack Type', title='Attack Type Distribution')
            attack_chart.plotly_chart(fig, use_container_width=True)
        
        # Update alerts table
        if alerts:
            df = pd.DataFrame(alerts)
            df['timestamp'] = df['timestamp'].dt.strftime('%H:%M:%S.%f')
            alerts_table.dataframe(df[['timestamp', 'attack_type', 'confidence', 'source_ip']])
        
        time.sleep(1)

if __name__ == "__main__":
    main()
