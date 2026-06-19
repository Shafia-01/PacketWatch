import time
import joblib
import pandas as pd
import subprocess
import re
import os
import sys
import platform
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scapy.all import sniff
from backend.feature_extraction import extract_features

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODELS_DIR = os.path.abspath(os.path.join(BASE_DIR, "../models"))

def load_models():
    try:
        model = joblib.load(os.path.join(MODELS_DIR, "threat_detection_model.pkl"))
        scaler = joblib.load(os.path.join(MODELS_DIR, "scaler.pkl"))
        imputer = joblib.load(os.path.join(MODELS_DIR, "imputer.pkl"))
        return model, scaler, imputer
    except FileNotFoundError as e:
        logger.error(f"Model file missing: {e}")
        return None, None, None

model, scaler, imputer = load_models()

def get_wifi_info():
    system = platform.system()
    try:
        if system == "Windows":
            output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
            ssid = re.search(r"^\s*SSID\s*:\s(.+)$", output, re.MULTILINE)
            protocol = re.search(r"^\s*Radio type\s*:\s(.+)$", output, re.MULTILINE)
            description = re.search(r"^\s*Description\s*:\s(.+)$", output, re.MULTILINE)
            network_band = re.search(r"^\s*Channel\s*:\s(\d+)", output, re.MULTILINE)

            return {
                "SSID": ssid.group(1) if ssid else "N/A",
                "Protocol": protocol.group(1) if protocol else "N/A",
                "Description": description.group(1) if description else "N/A",
                "Network Band (Channel)": f"{network_band.group(1)}" if network_band else "N/A"
            }
        elif system == "Linux":
            output = subprocess.check_output("iw dev", shell=True).decode()
            ssid = re.search(r"ssid (.+)", output)
            return {
                "SSID": ssid.group(1) if ssid else "N/A",
                "Protocol": "802.11",
                "Description": "Linux Wi-Fi Device",
                "Network Band (Channel)": "N/A"
            }
        elif system == "Darwin":
            output = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport", "-I"]
            ).decode()
            ssid = re.search(r"SSID: (.+)", output)
            return {
                "SSID": ssid.group(1) if ssid else "N/A",
                "Protocol": "802.11",
                "Description": "macOS Wi-Fi Device",
                "Network Band (Channel)": "N/A"
            }
        else:
            return {"error": f"Unsupported platform: {system}"}
    except Exception as e:
        logger.error(f"Wi-Fi info error: {e}")
        return None

def auto_select_interface():
    system = platform.system()
    try:
        if system == "Windows":
            output = subprocess.check_output("netsh wlan show interfaces", shell=True).decode()
            name_match = re.search(r"^\s*Name\s*:\s(.+)$", output, re.MULTILINE)
            return name_match.group(1).strip() if name_match else None
        elif system == "Linux":
            output = subprocess.check_output("iw dev", shell=True).decode()
            match = re.search(r"Interface\s+(wlan\d+|wlp\S+)", output)
            if match:
                return match.group(1)
            for iface in os.listdir('/sys/class/net'):
                if iface.startswith('wlan') or iface.startswith('wlp'):
                    return iface
            return "wlan0"
        elif system == "Darwin":
            output = subprocess.check_output("networksetup -listallhardwareports", shell=True).decode()
            match = re.search(r"Hardware Port:\s+Wi-Fi\s*\nDevice:\s+(\S+)", output, re.MULTILINE)
            if match:
                return match.group(1)
            return "en0"
        else:
            return None
    except Exception as e:
        logger.error(f"Could not auto-select interface: {e}")
        return None

def check_privileges():
    if platform.system() == "Windows":
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    else:
        return os.getuid() == 0

def process_packets(packets):
    features = extract_features(packets)
    if features is None:
        return "⚠️ No packets to process."

    df = pd.DataFrame([features])

    try:
        if any(x is None for x in [model, scaler, imputer]):
            logger.error("❌ Models not loaded. Cannot run prediction.")
            return "⚠️ Detection Failed"
        df_imputed = imputer.transform(df)
        df_scaled = scaler.transform(df_imputed)
        prediction = model.predict(df_scaled)
        return "🚨 Threat Detected!" if prediction[0] == 1 else "✅ Normal Activity"
    except Exception as e:
        logger.error(f"❌ Error in processing pipeline: {e}")
        return "⚠️ Detection Failed"

def sniff_packets_and_detect(timeout=20):
    if not check_privileges():
        return "❌ Insufficient privileges. Run as administrator/root.", None

    wifi_info = get_wifi_info()
    iface = auto_select_interface()
    if iface is None:
        return "❌ No Wi-Fi interface detected.", None

    packet_list = []

    def custom_packet_handler(packet):
        packet_list.append(packet)

    sniff(iface=iface, prn=custom_packet_handler, timeout=timeout)

    if len(packet_list) == 0:
        return "⚠️ No packets captured. Check permissions and interface.", {
            "Packets Captured": 0,
            "Interface": iface,
            "Wi-Fi Info": wifi_info,
            "Status": "SCAN_FAILED"
        }

    result = process_packets(packet_list)
    summary = {
        "Packets Captured": len(packet_list),
        "Interface": iface,
        "Wi-Fi Info": wifi_info,
        "Status": "SUCCESS"
    }

    return result, summary

if __name__ == "__main__":
    status, info = sniff_packets_and_detect()
    logger.info("\n🔍 Detection Summary:")
    logger.info(info)
    logger.info(status)
