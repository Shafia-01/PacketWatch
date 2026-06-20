import pandas as pd
import joblib
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

df = pd.read_csv("models/original_dataset.csv")

feature_names = joblib.load("models/feature_names.pkl")

if "Label" in df.columns:
    df = df.drop(columns=["Label"])

df = df[feature_names]

df.to_csv("models/sample_dataset1.csv", index=False)

logger.info("sample_dataset1.csv created successfully.")
