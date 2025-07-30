import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import time
from datetime import datetime
import uuid

st.set_page_config(page_title="QKD IDS Dashboard", layout="wide")
st.title("🔐 Real-Time QKD IDS Dashboard")

def load_data():
    try:
        df = pd.read_csv("ai_models/flow_log.csv")
        df.columns = ["timestamp", "packet_count", "byte_count", "duration", "label", "src_ip"]
        df["label"] = df["label"].astype(int)
        return df.tail(200)
    except Exception:
        return pd.DataFrame(columns=["timestamp", "packet_count", "byte_count", "duration", "label", "src_ip"])

placeholder = st.empty()

while True:
    df = load_data()

    if df.empty:
        time.sleep(2)
        continue

    benign = df[df["label"] == 0]
    attack = df[df["label"] == 1]
    current_time = str(uuid.uuid4())  # Unique ID to avoid duplicate keys

    with placeholder.container():
        col1, col2 = st.columns([3, 1])

        with col1:
            # 📊 Live Spline Chart
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=benign["timestamp"], y=benign["packet_count"],
                mode='lines+markers', name='✅ Benign', line_shape='spline'
            ))
            fig.add_trace(go.Scatter(
                x=attack["timestamp"], y=attack["packet_count"],
                mode='lines+markers', name='⚠️ Attack', line_shape='spline'
            ))
            fig.update_layout(title="📊 Packets Per Flow (Live)", xaxis_title="Time", yaxis_title="Packet Count", height=400)
            st.plotly_chart(fig, use_container_width=True, key=f"spline-{current_time}")

        with col2:
            # 🥧 Pie Chart
            pie = go.Figure(data=[go.Pie(
                labels=["Benign", "Attack"],
                values=[len(benign), len(attack)],
                marker=dict(colors=["green", "red"])
            )])
            pie.update_layout(title="Benign vs Attack")
            st.plotly_chart(pie, use_container_width=True, key=f"pie-{current_time}")

        # 🚨 Real-Time Alerts
        if not attack.empty:
            latest_attacks = df[df["label"] == 1].tail(5)
            attacker_ips = latest_attacks["src_ip"].tolist()
            unique_times = latest_attacks["timestamp"].tolist()[-1]
            st.error(f"🚨 DDoS Detected at {unique_times}!\n📌 Last 5 Attacker IPs: {', '.join(attacker_ips)}")

        # 📦 Bar Chart
        df["class"] = df["label"].map({0: "Benign", 1: "Attack"})
        bar = px.bar(df, x="timestamp", y="packet_count", color="class",
                     color_discrete_map={"Benign": "green", "Attack": "red"},
                     title="📦 Packet Count Over Time")
        st.plotly_chart(bar, use_container_width=True, key=f"bar-{current_time}")

        # 🧾 Colored Flow Table
        st.markdown("### 🧾 Flow Table (Last 20)")
        def highlight(row):
            return ['background-color: red; color: white' if row["label"] == 1 else 'background-color: #d4edda'] * len(row)
        st.dataframe(df.tail(20).style.apply(highlight, axis=1), use_container_width=True)

        # 🔥 DDoS Heatmap
        df["hour_min"] = df["timestamp"].str.slice(0, 5)
        heat = df.groupby(["hour_min", "label"]).size().unstack(fill_value=0).reset_index()
        heat.columns.name = None
        if "hour_min" in heat.columns:
            heat["total_attacks"] = heat.get(1, 0)  # Get attack counts
            heatmap = px.density_heatmap(heat, x="hour_min", y="total_attacks",
                                         title="🔥 DDoS Trend Heatmap", labels={"hour_min": "Time"})
            st.plotly_chart(heatmap, use_container_width=True, key=f"heatmap-{current_time}")

    time.sleep(2)
