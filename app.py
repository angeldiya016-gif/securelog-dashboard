import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import json
import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))
from modules.alerter import IncidentAlerter

st.set_page_config(page_title="SecureLog AI Framework", page_icon="🛡️", layout="wide")

st.title("🛡️ SecureLog Automated Incident Response Framework")
st.markdown("### Real-time Log Analysis, Threat Detection & Auto-Response")
st.markdown("---")

alerter = IncidentAlerter()

st.sidebar.header("📁 Log Data Input")
uploaded_file = st.sidebar.file_uploader("Upload Log File (.csv or .json)", type=['csv', 'json', 'txt'])

sample_wazuh_logs = [
    {"timestamp": "2023-10-25T10:15:23.000Z", "rule": {"description": "sshd: brute force trying to get access.", "level": 7}, "data": {"srcip": "192.168.1.100", "dstuser": "root"}},
    {"timestamp": "2023-10-25T10:15:25.000Z", "rule": {"description": "sshd: brute force trying to get access.", "level": 7}, "data": {"srcip": "192.168.1.100", "dstuser": "root"}},
    {"timestamp": "2023-10-25T10:16:01.000Z", "rule": {"description": "sshd: authentication success.", "level": 3}, "data": {"srcip": "172.16.0.10", "dstuser": "admin"}},
    {"timestamp": "2023-10-25T10:17:00.000Z", "rule": {"description": "sshd: brute force trying to get access.", "level": 7}, "data": {"srcip": "192.168.1.100", "dstuser": "admin"}},
    {"timestamp": "2023-10-25T10:18:30.000Z", "rule": {"description": "sshd: brute force trying to get access.", "level": 7}, "data": {"srcip": "10.0.0.50", "dstuser": "root"}}
]

@st.cache_data
def parse_logs(file):
    if file.name.endswith('.json'):
        logs = [json.loads(line) for line in file.read().decode('utf-8').strip().split('\n')]
        df = pd.json_normalize(logs)
        df = df.rename(columns={'data.srcip': 'ip', 'data.dstuser': 'user', 'rule.description': 'event', 'timestamp': 'timestamp'})
        df['event'] = df['event'].apply(lambda x: 'Failed Login' if 'brute force' in x.lower() else 'Successful Login')
        return df[['timestamp', 'event', 'ip', 'user']]
    else:
        return pd.read_csv(file)

if uploaded_file is not None:
    try:
        df = parse_logs(uploaded_file)
        st.sidebar.success(f"✅ Loaded {len(df)} log entries")
    except Exception as e:
        st.error(f"❌ Error parsing file: {e}")
        st.stop()
else:
    df = pd.DataFrame(sample_wazuh_logs)
    df['ip'] = df['data'].apply(lambda x: x.get('srcip', 'N/A'))
    df['user'] = df['data'].apply(lambda x: x.get('dstuser', 'N/A'))
    df['event'] = df['rule'].apply(lambda x: 'Failed Login' if 'brute force' in x.get('description', '').lower() else 'Successful Login')
    df = df[['timestamp', 'event', 'ip', 'user']]
    st.sidebar.info("⚠️ Showing sample Wazuh JSON data.")

st.subheader("📊 Security Overview")
col1, col2, col3 = st.columns(3)
total_events = len(df)
failed_logins = len(df[df['event'] == 'Failed Login'])
unique_ips = df['ip'].nunique()

col1.metric("Total Events", total_events)
col2.metric("❌ Failed Logins", failed_logins)
col3.metric("🌐 Unique IPs", unique_ips)

st.markdown("---")

st.subheader("⚙️ Automated Incident Response Engine")
failed_df = df[df['event'] == 'Failed Login']
brute_force = failed_df['ip'].value_counts()
suspicious_ips = brute_force[brute_force >= 2]

if not suspicious_ips.empty:
    st.error(f"🚨 Active Threat Detected: {len(suspicious_ips)} IP(s) triggering brute force rules!")
    
    with st.expander("🔔 View Automated System Alerts (Live)", expanded=True):
        for ip, count in suspicious_ips.items():
            alert_msg = alerter.trigger_alert(ip, count, severity="CRITICAL" if count >= 3 else "HIGH")
            st.code(alert_msg, language="text")
else:
    st.success("✅ System Normal: No brute force patterns detected.")

st.markdown("---")
st.subheader("📈 Threat Visualization")
ip_counts = df['ip'].value_counts().reset_index()
ip_counts.columns = ['IP Address', 'Count']
fig_ip = px.bar(ip_counts, x='IP Address', y='Count', color='Count', color_continuous_scale='Reds')
st.plotly_chart(fig_ip, use_container_width=True)

st.markdown("---")
st.caption("Built with Python, Streamlit & Plotly | Automated Incident Response Framework | DevSecOps Portfolio")
