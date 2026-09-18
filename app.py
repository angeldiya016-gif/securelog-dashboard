import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime

st.set_page_config(page_title="SecureLog AI Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ SecureLog AI Dashboard")
st.markdown("### Automated Security Log Analysis & Reporting")
st.markdown("---")

st.sidebar.header("📁 Log Data Input")
uploaded_file = st.sidebar.file_uploader("Upload Log File (.csv)", type=['csv'])

sample_data = [
    {"timestamp": "2023-10-25 10:15:23", "event": "Failed Login", "ip": "192.168.1.100", "user": "root"},
    {"timestamp": "2023-10-25 10:15:25", "event": "Failed Login", "ip": "192.168.1.100", "user": "root"},
    {"timestamp": "2023-10-25 10:16:01", "event": "Successful Login", "ip": "172.16.0.10", "user": "admin"},
    {"timestamp": "2023-10-25 10:17:00", "event": "Failed Login", "ip": "192.168.1.100", "user": "admin"},
    {"timestamp": "2023-10-25 10:18:30", "event": "Failed Login", "ip": "10.0.0.50", "user": "root"},
]

if uploaded_file is not None:
    df = pd.read_csv(uploaded_file)
else:
    df = pd.DataFrame(sample_data)
    st.sidebar.info("⚠️ No file uploaded. Showing sample data.")

st.subheader("📊 Security Overview")
col1, col2, col3 = st.columns(3)
total_events = len(df)
failed_logins = len(df[df['event'] == 'Failed Login'])
unique_ips = df['ip'].nunique()

col1.metric("Total Events", total_events)
col2.metric("❌ Failed Logins", failed_logins)
col3.metric("🌐 Unique IPs", unique_ips)

st.markdown("---")

col_left, col_right = st.columns(2)

with col_left:
    st.subheader("🎯 Events by IP Address")
    ip_counts = df['ip'].value_counts().reset_index()
    ip_counts.columns = ['IP Address', 'Count']
    fig_ip = px.bar(ip_counts, x='IP Address', y='Count', color='Count', color_continuous_scale='Reds')
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

st.markdown("---")
st.subheader("📥 Export Report")
csv = df.to_csv(index=False).encode('utf-8')
st.download_button(
    label="Download Full Log Report (CSV)",
    data=csv,
    file_name=f"security_report_{datetime.now().strftime('%Y%m%d')}.csv",
    mime="text/csv",
)
