import streamlit as st
import pandas as pd
import time
import plotly.express as px

from nft_utils import (
    block_ip,
    list_blocked_ips,
    list_whitelist_ips,
    unblock_ip,
    whitelist_ip,
    remove_whitelist_ip,
)

st.set_page_config(page_title="AI Firewall SOC", layout="wide")

st.title("🛡 AI Firewall Security Operations Center")

LOG_FILE = "firewall_logs.csv"

# Initialize session state for auto-refresh
if "last_refresh" not in st.session_state:
    st.session_state.last_refresh = time.time()

refresh_interval = st.sidebar.slider("Refresh interval (seconds)", min_value=1, max_value=10, value=3)

st.sidebar.markdown("## Admin Controls")

with st.sidebar.expander("Whitelist / Blacklist"):
    st.write("Add or remove IPs from the firewall's allow/block sets.")

    with st.form("ip_control_form"):
        ip_address = st.text_input("IP address")
        action = st.selectbox("Action", ["Whitelist", "Blacklist", "Remove from whitelist", "Remove from blacklist"])
        submitted = st.form_submit_button("Apply")

    if submitted and ip_address:
        if action == "Whitelist":
            ok = whitelist_ip(ip_address)
            st.success("Added to whitelist" if ok else "Already whitelisted or failed")
        elif action == "Blacklist":
            ok = block_ip(ip_address)
            st.success("Added to blacklist" if ok else "Already blocked or failed")
        elif action == "Remove from whitelist":
            ok = remove_whitelist_ip(ip_address)
            st.success("Removed from whitelist" if ok else "Not in whitelist")
        elif action == "Remove from blacklist":
            ok = unblock_ip(ip_address)
            st.success("Removed from blacklist" if ok else "Not in blacklist")

    st.markdown("**Current whitelist**")
    st.write(list_whitelist_ips())
    st.markdown("**Current blacklist**")
    st.write(list_blocked_ips())

# Main content
try:
    df = pd.read_csv(LOG_FILE, on_bad_lines="skip", engine="python")
except FileNotFoundError:
    st.warning("⏳ Waiting for firewall logs... Start the packet sniffer first.")
    st.info("Run: `sudo -E $(which python) packet_sniffer.py`")
    st.stop()
except pd.errors.ParserError:
    st.error("❌ Log file is malformed. Delete firewall_logs.csv and restart the sniffer.")
    st.stop()

total_packets = len(df)
blocked = len(df[df.get("decision") == "BLOCK"])
quarantined = len(df[df.get("decision") == "QUARANTINE"])
allowed = len(df[df.get("decision") == "ALLOW"])

total_bytes = 0
if "src_bytes" in df.columns and "dst_bytes" in df.columns:
    total_bytes = df["src_bytes"].sum() + df["dst_bytes"].sum()
bandwidth_mb = total_bytes / 1024 / 1024

# Simplified status message for non-technical users
if blocked > 0:
    st.error(f"⚠️ Detected {blocked} blocked event(s). Review the recent events below.")
else:
    st.success("✅ No blocked traffic detected in the last refresh period.")

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Packets", total_packets)
col2.metric("Blocked", blocked)
col3.metric("Quarantined", quarantined)
col4.metric("Allowed", allowed)

st.metric("Total Data (MB)", f"{bandwidth_mb:.2f}")

# ----- user-friendly status -----
if "event_label" in df.columns:
    label_counts = df["event_label"].value_counts().to_dict()
    if label_counts.get("Possible port scan detected", 0) > 0:
        st.warning("⚠️ Possible port scan detected. See blocked IPs below.")
    elif label_counts.get("Large packet / high bandwidth detected", 0) > 0:
        st.info("📶 High bandwidth traffic detected. Monitor health and behavior.")

st.markdown("### Recent Events")
if not df.empty:
    st.dataframe(df.tail(20), width="stretch")

# Show a concise attack report for non-technical observers
if "event_label" in df.columns:
    attacks = df[df["event_label"].isin(["Possible port scan detected", "Large packet / high bandwidth detected", "Unusual traffic detected"])].tail(10)
    if not attacks.empty:
        st.markdown("### Recent attack observations")
        st.table(attacks[["timestamp", "src_ip", "dst_ip", "event_label", "decision"]].tail(10))

# Charts - with unique session-based keys to avoid duplicates
col_hist, col_anomaly = st.columns(2)

with col_hist:
    fig = px.histogram(df, x="decision", title="Traffic Decisions")
    st.plotly_chart(fig, width="stretch")

if "anomaly_ratio" in df.columns:
    with col_anomaly:
        fig2 = px.line(df, y="anomaly_ratio", title="Anomaly Score Over Time")
        st.plotly_chart(fig2, width="stretch")

# ----- Blocked IP dashboard -----
if "blocked" in df.columns:
    blocked_df = df[df["blocked"] == True]
    if not blocked_df.empty:
        st.markdown("### Blocked IPs")
        # Summarize per IP
        summary = (
            blocked_df.groupby("src_ip")
            .agg(
                last_seen=("timestamp", "max"),
                block_count=("timestamp", "count"),
                last_label=("event_label", "last")
            )
            .reset_index()
        )
        summary["last_seen"] = pd.to_datetime(summary["last_seen"], unit="s")
        st.dataframe(summary.sort_values(by="last_seen", ascending=False), width="stretch")

        ip_to_unblock = st.selectbox(
            "Unblock an IP (select then click)",
            options=summary["src_ip"].tolist(),
        )
        if st.button("Unblock selected IP") and ip_to_unblock:
            ok = unblock_ip(ip_to_unblock)
            if ok:
                st.success(f"✅ Unblocked {ip_to_unblock}")
                st.rerun()
            else:
                st.error(f"❌ Failed to unblock {ip_to_unblock}. Is it in the blacklist?")

# Optional Suricata alert feed
try:
    suricata_df = pd.read_csv("suricata_alerts.csv")
    if not suricata_df.empty:
        st.markdown("### Suricata Alerts")
        st.dataframe(suricata_df.tail(20), width="stretch")
except FileNotFoundError:
    pass

# Auto-refresh logic at the bottom
st.divider()
col_refresh = st.columns([1, 1, 1])
with col_refresh[1]:
    st.caption(f"Last refresh: {time.strftime('%H:%M:%S', time.localtime(st.session_state.last_refresh))}")

# Implement auto-refresh by sleeping and calling rerun
time.sleep(refresh_interval)
st.rerun()
