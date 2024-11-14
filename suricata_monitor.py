import json
import time
import os
import matplotlib.pyplot as plt
import pandas as pd

# Define the path to Suricata's EVE JSON log file
eve_log_path = '/path/to/suricata/logs/eve.json'

# Function to read Suricata's EVE JSON log file and filter alerts
def read_suricata_log():
    with open(eve_log_path, 'r') as file:
        for line in file:
            try:
                alert = json.loads(line)
                # Process only 'alert' events (i.e., suspicious activity)
                if 'alert' in alert:
                    yield alert
            except json.JSONDecodeError:
                continue

# Function to identify suspicious activity based on custom criteria
def detect_suspicious_activity(alert):
    # Example: Detect port scanning activity based on specific rule sid
    if 'sid' in alert['alert'] and alert['alert']['sid'] == 1000001:  # example SID for a suspicious rule
        return f"Suspicious Activity Detected: {alert['alert']['msg']} at {alert['timestamp']}"
    return None

# Function to trigger an alert (e.g., send an email, log, or take action)
def trigger_alert(alert_message):
    print(f"ALERT: {alert_message}")
    # You can extend this function to send email, call an API, or block IP (e.g., using Fail2ban)
    
# Function to visualize detected attacks (simple bar chart)
def visualize_alerts(alerts):
    df = pd.DataFrame(alerts)
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.set_index('timestamp', inplace=True)
        attack_counts = df.resample('H').size()  # Count alerts by hour
        attack_counts.plot(kind='bar', figsize=(10, 6), title='Attacks Detected Over Time')
        plt.xlabel('Time')
        plt.ylabel('Number of Alerts')
        plt.show()

# Main function to monitor Suricata logs
def monitor_suricata_logs():
    alerts = []
    while True:
        for alert in read_suricata_log():
            suspicious_activity = detect_suspicious_activity(alert)
            if suspicious_activity:
                trigger_alert(suspicious_activity)
                alerts.append({
                    'timestamp': alert['timestamp'],
                    'message': suspicious_activity
                })
        
        if alerts:
            visualize_alerts(alerts)
            alerts.clear()  # Clear the list after visualization
        
        time.sleep(10)  # Check every 10 seconds

if __name__ == "__main__":
    if os.path.exists(eve_log_path):
        monitor_suricata_logs()
    else:
        print(f"Suricata log file not found at: {eve_log_path}")
