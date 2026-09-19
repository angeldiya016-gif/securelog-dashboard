import logging
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [INCIDENT_RESPONSE] - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("incident_alerts.log"),
        logging.StreamHandler()
    ]
)

class IncidentAlerter:
    def __init__(self):
        self.alert_count = 0

    def trigger_alert(self, ip_address: str, attempt_count: int, severity: str = "HIGH"):
        self.alert_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        alert_message = (
            f"🚨 SECURITY ALERT #{self.alert_count} | Severity: {severity}\n"
            f"📅 Time: {timestamp}\n"
            f"🎯 Threat: Brute Force Attack Detected\n"
            f"🌐 Source IP: {ip_address}\n"
            f"📊 Failed Attempts: {attempt_count}\n"
            f"🛡️ Action: IP flagged for monitoring. (Simulated Block)"
        )
        
        logging.warning(alert_message)
        return alert_message

    def get_recent_alerts(self):
        try:
            with open("incident_alerts.log", "r") as file:
                return file.readlines()[-10:]
        except FileNotFoundError:
            return ["No recent alerts generated."]
