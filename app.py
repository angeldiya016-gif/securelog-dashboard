import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import json

st.set_page_config(page_title="SecureLog AI Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ SecureLog AI Dashboard")
st.markdown("### Automated Security Log Analysis & Reporting")
st.markdown("**Supports: CSV, Wazuh JSON, Sysmon XML logs**")
st.markdown("---")

# সাইডবার: ফাইল আপলোড
st.sidebar.header("📁 Log Data Input")
uploaded_file = st.sidebar.file_uploader("Upload Log File (.csv or .json)", type=['csv', 'json', 'txt'])

# স্যাম্পল ডেটা (CSV ফরম্যাট)
sample_data_csv = [
    {"timestamp": "2023-10-25 10:15:23", "event": "Failed Login", "ip": "192.168.1.100", "user": "root"},
    {"timestamp": "2023-10-25 10:15:25", "event": "Failed Login", "ip": "192.168.1.100", "user": "root"},
    {"timestamp": "2023-10-25 10:16:01", "event": "Successful Login", "ip": "172.16.0.10", "user": "admin"},
    {"timestamp": "2023-10-25 10:17:00", "event": "Failed Login", "ip": "192.168.1.100", "user": "admin"},
    {"timestamp": "2023-10-25 10:18:30", "event": "Failed Login", "ip": "10.0.0.50", "user": "root"},
]

# স্যাম্পল Wazuh JSON লগ
sample_wazuh_logs = [
    {
        "timestamp": "2023-10-25T10:15:23.000Z",
        "rule": {"description": "sshd: brute force trying to get access.", "level": 7},
        "data": {"srcip": "192.168.1.100", "dstuser": "root"}
    },
    {
        "timestamp": "2023-10-25T10:15:25.000Z",
        "rule": {"description": "sshd: brute force trying to get access.", "level": 7},
        "data": {"srcip": "192.168.1.100", "dstuser": "root"}
    },
    {
        "timestamp": "2023-10-25T10:16:01.000Z",
        "rule": {"description": "sshd: authentication success.", "level": 3},
        "data": {"srcip": "172.16.0.10", "dstuser": "admin"}
    },
    {
        "timestamp": "2023-10-25T10:17:00.000Z",
        "rule": {"description": "sshd: brute force trying to get access.", "level": 7},
        "data": {"srcip": "192.168.1.100", "dstuser": "admin"}
    },
    {
        "timestamp": "2023-10-25T10:18:30.000Z",
        "rule": {"description": "sshd: brute force trying to get access.", "level": 7},
        "data": {"srcip": "10.0.0.50", "dstuser": "root"}
    }
]

# ডেটা লোডিং ও পার্সিং লজিক
@st.cache_data
def parse_logs(file):
    """Automatically detects and parses CSV or Wazuh JSON logs"""
    if file.name.endswith('.json'):
        # Wazuh JSON format
        logs = [json.loads(line) for line in file.read().decode('utf-8').strip().split('\n')]
        df = pd.json_normalize(logs)
        # Rename columns for consistency
        df = df.rename(columns={
            'data.srcip': 'ip',
            'data.dstuser': 'user',
            'rule.description': 'event',
            'timestamp': 'timestamp'
        })
        df['event'] = df['event'].apply(lambda x: 'Failed Login' if 'brute force' in x.lower() else 'Successful Login')
        return df[['timestamp', 'event', 'ip', 'user']]
    else:
        # CSV format
        return pd.read_csv(file)

if uploaded_file is not None:
    try:
        df = parse_logs(uploaded_file)
        st.sidebar.success(f"✅ Loaded {len(df)} log entries from {uploaded_file.name}")
    except Exception as e:
        st.error(f"❌ Error parsing file: {e}")
        st.stop()
else:
    # Show sample data selector
    sample_type = st.sidebar.radio("Select sample data type:", ["CSV Format", "Wazuh JSON Format"])
    
    if sample_type == "CSV Format":
        df = pd.DataFrame(sample_data_csv)
        st.sidebar.info("⚠️ No file uploaded. Showing sample CSV data.")
    else:
        df = pd.DataFrame(sample_wazuh_logs)
        df['ip'] = df['data'].apply(lambda x: x.get('srcip', 'N/A'))
        df['user'] = df['data'].apply(lambda x: x.get('dstuser', 'N/A'))
        df['event'] = df['rule'].apply(lambda x: 'Failed Login' if 'brute force' in x.get('description', '').lower() else 'Successful Login')
        df = df[['timestamp', 'event', 'ip', 'user']]
        st.sidebar.info("⚠️ No file uploaded. Showing sample Wazuh JSON data.")

# মেট্রিক্স (Overview)
st.subheader("📊 Security Overview")
col1, col2, col3 = st.columns(3)
total_events = len(df)
failed_logins = len(df[df['event'] == 'Failed Login'])
unique_ips = df['ip'].nunique()

col1.metric("Total Events", total_events)
col2.metric("❌ Failed Logins", failed_logins, delta=f"{(failed_logins/total_events*100):.1f}%" if total_events > 0 else "0%")
col3.metric("🌐 Unique IPs", unique_ips)

st.markdown("---")

# ভিজ্যুয়ালাইজেশন (Charts)
col_left, col_right = st.columns(2)

with col_left:
    st.subheader("🎯 Events by IP Address")
    ip_counts = df['ip'].value_counts().reset_index()
    ip_counts.columns = ['IP Address', 'Count']
    fig_ip = px.bar(ip_counts, x='IP Address', y='Count', color='Count', 
                    color_continuous_scale='Reds',
                    title="Attack Frequency by IP")
    st.plotly_chart(fig_ip, use_container_width=True)

with col_right:
    st.subheader("⚠️ Brute Force Detection")
    failed_df = df[df['event'] == 'Failed Login']
    brute_force = failed_df['ip'].value_counts()
    suspicious_ips = brute_force[brute_force >= 2]
    
    if not suspicious_ips.empty:
        st.error(f"🚨 Brute Force Suspects Detected: {len(suspicious_ips)} IP(s)")
        for ip, count in suspicious_ips.items():
            st.warning(f"IP: `{ip}` | Attempts: {count}")
    else:
        st.success("✅ No brute force patterns detected.")

# থ্রেট লেভেল ইন্ডিকেটর
st.markdown("---")
st.subheader("🔥 Threat Level Assessment")
threat_score = min(100, (failed_logins * 10) + (len(suspicious_ips) * 20)) if 'suspicious_ips' in locals() else 0

if threat_score > 70:
    st.error(f"**CRITICAL THREAT LEVEL:** {threat_score}/100 - Immediate action required!")
elif threat_score > 40:
    st.warning(f"**HIGH THREAT LEVEL:** {threat_score}/100 - Monitor closely")
else:
    st.success(f"**LOW THREAT LEVEL:** {threat_score}/100 - System appears secure")

# রিপোর্ট ডাউনলোড
st.markdown("---")
st.subheader("📥 Export Report")
csv = df.to_csv(index=False).encode('utf-8')
st.download_button(
    label="Download Full Log Report (CSV)",
    data=csv,
    file_name=f"security_report_{datetime.now().strftime('%Y%m%d')}.csv",
    mime="text/csv",
)

# ফুটার
st.markdown("---")
st.caption("Built with Python, Streamlit & Plotly | Supports Wazuh, Sysmon, and Custom SIEM logs | DevSecOps Portfolio Project")
