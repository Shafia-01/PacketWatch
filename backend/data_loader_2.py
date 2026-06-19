import sys
import os
import logging
import pandas as pd
from scapy.all import sniff

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from backend.feature_extraction import extract_features

logger.info("⏳ Capturing packets... (this may take a few seconds)")
packets = sniff(count=100, timeout=10)
logger.info(f"✅ Captured {len(packets)} packets.")

features = extract_features(packets)

df = pd.DataFrame([features])
df.to_csv("models/sample_dataset3.csv", index=False)

logger.info("📄 Saved extracted features to models/sample_dataset3.csv")
