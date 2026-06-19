import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.utils import preprocess_dataframe, make_prediction, model, scaler, imputer
from backend.realtime_detector import sniff_packets_and_detect

st.set_page_config(page_title="AI Cybersecurity Threat Detector", layout="wide")
st.title("🛡️ AI-Enhanced Cybersecurity Threat Detector")

if any(x is None for x in [model, scaler, imputer]):
    st.error("❌ Model files not found. Please ensure all .pkl files exist in /models.")
    st.stop()

tab1, tab2 = st.tabs(["📁 Analyze Saved Network Logs", "🌐 Live Wi-Fi Threat Monitor"])

with tab1:
    st.header("📊 Offline Threat Analysis from Network Logs")
    st.markdown("Upload past network traffic (CSV) to detect threats using the AI model.")
    uploaded_file = st.file_uploader("Upload your file", type=["csv"])

    if uploaded_file is not None:
        try:
            original_df = pd.read_csv(uploaded_file)
            original_df = original_df.head(100)
        except Exception:
            st.error("Unable to read the uploaded CSV file.")
            st.stop()
        
        if original_df.empty:
            st.error("Uploaded file is empty.")
            st.stop()

        try:
            processed_data = preprocess_dataframe(original_df)
        except ValueError as ve:
            st.error(f"❌ Validation Error: {ve}")
            st.stop()
        except Exception as e:
            st.error(f"❌ Preprocessing Error: {e}")
            st.stop()
        
        if processed_data is None:
            st.error("Uploaded file is invalid or missing required features.")
        else:
            predictions = make_prediction(processed_data)

            if predictions is None:
                st.error("Prediction failed.")
            else:
                predictions = np.array(predictions).flatten().tolist()

                # Drop the 'Label' column if present
                original_df = original_df.drop(columns=["Label"], errors="ignore")

                # Ensure lengths match before adding predictions
                if len(predictions) != len(original_df):
                    st.error("Mismatch between predictions and input data length.")
                    st.stop()

                original_df["Threat_Prediction"] = predictions
                original_df["Threat_Prediction"] = original_df["Threat_Prediction"].map({0: "✅ Normal", 1: "⚠️ Threat"})

                st.success("✅ Prediction completed!")
                st.dataframe(original_df)

                csv = original_df.to_csv(index=False).encode("utf-8")
                st.download_button("📥 Download Results as CSV", csv, "threat_predictions.csv", "text/csv")
    

with tab2:
    st.header("🛡️ Real-Time Threat Detection on Active Wi-Fi")
    st.markdown("Scan your current Wi-Fi in real-time to identify suspicious activities.")
    if st.button("Start Live Detection"):
        with st.spinner("Scanning your Wi-Fi network for threats..."):
            result, summary = sniff_packets_and_detect()

            if summary:
                st.subheader("📡 Active Network Interface")
                st.write(f"**Interface**: {summary['Interface']}")
                wifi_info = summary.get("Wi-Fi Info", {})
                if isinstance(wifi_info, dict) and "error" in wifi_info:
                    st.error(f"Wi-Fi Info Error: {wifi_info['error']}")
                else:
                    st.write(f"**SSID**: {wifi_info.get('SSID', 'N/A') if wifi_info else 'N/A'}")
                    st.write(f"**Protocol**: {wifi_info.get('Protocol', 'N/A') if wifi_info else 'N/A'}")
                    st.write(f"**Description**: {wifi_info.get('Description', 'N/A') if wifi_info else 'N/A'}")
                    st.write(f"**Network Band (Channel)**: {wifi_info.get('Network Band (Channel)', 'N/A') if wifi_info else 'N/A'}")
                st.write(f"**Packets Captured**: {summary['Packets Captured']}")

            st.subheader("🛡️ Detection Result")
            if summary and summary.get("Status") == "SCAN_FAILED":
                st.warning(result)
            elif "❌" in result:
                st.error(result)
            elif "Threat" in result:
                st.error(result)
            else:
                st.success(result)
