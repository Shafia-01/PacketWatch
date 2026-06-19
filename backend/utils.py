import pandas as pd
import joblib
import traceback
import numpy as np
import os
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

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

def preprocess_dataframe(df):
    try:
        df = df.copy()
        if 'Label' in df.columns:
            df.drop(columns=['Label'], inplace=True)

        feature_names_path = os.path.join(MODELS_DIR, "feature_names.pkl")
        try:
            feature_names = joblib.load(feature_names_path)
        except FileNotFoundError as e:
            logger.error(f"Feature names file missing: {e}")
            return None

        missing = set(feature_names) - set(df.columns)
        if missing:
            raise ValueError(f"Missing required features: {', '.join(sorted(missing))}")

        df = df[feature_names]
        df.replace([np.inf, -np.inf], np.nan, inplace=True)

        if imputer is None or scaler is None:
            logger.error("❌ Imputer or scaler is not loaded.")
            return None

        df_imputed = imputer.transform(df)
        df_scaled = scaler.transform(df_imputed)

        return df_scaled

    except Exception as e:
        logger.error(f"❌ ERROR during preprocessing: {e}")
        return None

def preprocess_input(file):
    try:
        df = pd.read_csv(file, encoding='utf-8')
        return preprocess_dataframe(df)
    except Exception as e:
        logger.error(f"❌ ERROR during preprocessing: {e}")
        return None

def make_prediction(processed_data):
    try:
        if model is None:
            logger.error("❌ Model is not loaded.")
            return None
        predictions = model.predict(processed_data)

        # Ensure it's a 1D list (e.g., [0, 1, 0])
        if isinstance(predictions, (np.ndarray, list)):
            predictions = np.array(predictions).flatten().tolist()
        else:
            predictions = [predictions]

        return predictions

    except Exception as e:
        logger.error(f"[ERROR in prediction] {traceback.format_exc()}")
        return None
