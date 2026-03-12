import streamlit as st
import pandas as pd
import time
import plotly.express as px

st.set_page_config(page_title="AI Firewall SOC", layout="wide")

st.title("🛡 AI Firewall Security Operations Center")

LOG_FILE = "firewall_logs.csv"

placeholder = st.empty()

while True:

    try:
        df = pd.read_csv(LOG_FILE)

        total_packets = len(df)
        blocked = len(df[df["decision"] == "BLOCK"])
        quarantined = len(df[df["decision"] == "QUARANTINE"])
        allowed = len(df[df["decision"] == "ALLOW"])

        col1, col2, col3, col4 = st.columns(4)

        col1.metric("Total Packets", total_packets)
        col2.metric("Blocked", blocked)
        col3.metric("Quarantined", quarantined)
        col4.metric("Allowed", allowed)

        fig = px.histogram(df, x="decision", title="Traffic Decisions")
        st.plotly_chart(fig, use_container_width=True)

        fig2 = px.line(df, y="anomaly_ratio", title="Anomaly Score Over Time")
        st.plotly_chart(fig2, use_container_width=True)

    except:
        st.write("Waiting for firewall logs...")

    time.sleep(3)
