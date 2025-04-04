import streamlit as st
import pandas as pd
import numpy as np
import time
from sklearn.ensemble import IsolationForest
from datetime import datetime

# === Basic Auth ===
def login():
    st.title("🔐 DefenSys Login")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state["authenticated"] = True
        else:
            st.error("Invalid credentials")

# === Dummy monitoring and detection logic (placeholder) ===
def run_collectors():
    st.success("✅ All collectors are now running in the background.")
    time.sleep(1)
    st.info("📡 Monitoring live data streams...")

def detect_anomalies():
    st.subheader("🚨 Real-Time Anomaly Detection")
    # Simulate dummy data
    np.random.seed(42)
    X = np.random.normal(size=(100, 4))
    model = IsolationForest(contamination=0.1)
    preds = model.fit_predict(X)
    alerts = pd.DataFrame(X, columns=["Feature1", "Feature2", "Feature3", "Feature4"])
    alerts["Status"] = np.where(preds == -1, "🔴 Suspicious", "🟢 Normal")
    st.dataframe(alerts.head(10))

    st.write("🧾 Report generated at:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    csv = alerts.to_csv(index=False).encode()
    st.download_button("📥 Download Report", csv, "anomaly_report.csv", "text/csv")

def dashboard():
    st.title("🛡️ DefenSys Threat Intelligence Dashboard")
    run_collectors()
    detect_anomalies()

    st.button("🔁 Refresh Anomaly Scan", on_click=detect_anomalies)

# === App Runner ===
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False

if st.session_state["authenticated"]:
    dashboard()
else:
    login()
