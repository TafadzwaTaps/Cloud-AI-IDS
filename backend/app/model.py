import joblib
import pandas as pd
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "model", "ids_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "model", "scaler.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "model", "feature_columns.pkl")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
FEATURE_COLUMNS = joblib.load(FEATURES_PATH)

def predict(df: pd.DataFrame):
    # Ensure correct columns and order
    df = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)

    X_scaled = scaler.transform(df)
    preds = model.predict(X_scaled)
    probs = model.predict_proba(X_scaled)[:, 1]

    return preds, probs
