# dashboard.py
import streamlit as st
import socket
import json
import pandas as pd
import time
import plotly.graph_objs as go
from ids.real_time_ids import IntrusionDetector

# Streamlit Page Setup
st.set_page_config(page_title="Quantum IDS Dashboard", layout="wide")
st.title("🔑 Quantum-Secured Real-Time IDS")

# State Variables
log_table = []
detector = IntrusionDetector()
anomaly_count = 0

# Create columns for layout
col1, col2 = st.columns([3, 1])

with col1:
    alert_placeholder = st.empty()
    table_placeholder = st.empty()
    graph_placeholder = st.empty()

with col2:
    stats_placeholder = st.empty()
    model_placeholder = st.empty()

# Setup UDP Socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("localhost", 9999))
sock.settimeout(1)

# Main Loop
while True:
    try:
        data, _ = sock.recvfrom(4096)
        log = json.loads(data.decode())

        processed_log = detector.process(log)
        log_table.append(processed_log)

        # Update anomaly count
        if processed_log['anomaly']:
            anomaly_count += 1

        # --- Alert Box ---
        if processed_log['anomaly']:
            attack_types = [k for k, v in processed_log['anomaly_details'].items() if v]
            alert_msg = f"🚨 Attack Detected: {', '.join(attack_types)}"
            alert_placeholder.error(alert_msg, icon="⚠️")
        else:
            alert_placeholder.success("✅ All traffic normal", icon="🔑")

        # --- Data Table ---
        df = pd.DataFrame(log_table).tail(50)
        df_display = df[["timestamp", "ip", "direction", "length", "anomaly"]]
        df_display.columns = ["Timestamp", "IP", "Direction", "Size", "Anomaly"]
        table_placeholder.dataframe(df_display, use_container_width=True)

        # --- Live Line Chart ---
        recent_df = df.tail(30)
        recent_df["time"] = pd.to_datetime(recent_df["timestamp"], unit='s')

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=recent_df["time"],
            y=recent_df["length"],
            mode='lines+markers',
            line=dict(color='deepskyblue'),
            marker=dict(size=6),
            name="Packet Size"
        ))
        fig.update_layout(
            title="📈 Real-Time Packet Size Trend",
            xaxis_title="Timestamp",
            yaxis_title="Packet Size (bytes)",
            template="plotly_dark",
            height=400,
            margin=dict(l=20, r=20, t=40, b=20),
        )
        graph_placeholder.plotly_chart(fig, use_container_width=True)

        # --- Model Statistics ---
        if log_table:
            last_log = log_table[-1]
            if 'anomaly_details' in last_log:
                stats_data = {
                    "Model": list(last_log['anomaly_details'].keys()),
                    "Detection": ["✅" if v else "❌" for v in last_log['anomaly_details'].values()]
                }
                stats_df = pd.DataFrame(stats_data)
                model_placeholder.dataframe(stats_df, use_container_width=True)

        # --- Stats Box ---
        stats_placeholder.metric("Total Anomalies", anomaly_count)

        # --- Easter Egg FX ---
        if anomaly_count > 5 and anomaly_count % 5 == 0:
            st.snow()

        time.sleep(0.25)

    except socket.timeout:
        continue
    except Exception as e:
        st.error(f"❌ Error in dashboard: {e}")
        break
