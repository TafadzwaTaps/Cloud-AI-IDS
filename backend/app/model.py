import joblib
import pandas as pd
import numpy as np
import os

# Deterministic path resolution: walk up from this file's own absolute
# location (backend/app/model.py -> backend/app -> backend -> repo root),
# rather than relying on dirname() chains whose correctness depends on
# the interpreter's working directory at import time.
APP_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(APP_DIR)
BASE_DIR = os.path.dirname(BACKEND_DIR)

MODEL_PATH = os.path.join(BASE_DIR, "model", "ids_model.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "model", "scaler.pkl")
FEATURES_PATH = os.path.join(BASE_DIR, "model", "feature_columns.pkl")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
FEATURE_COLUMNS = joblib.load(FEATURES_PATH)

# The model itself is the source of truth for class order (this is
# exactly the column order predict_proba returns), rather than a
# separately-saved list that could drift out of sync with it.
CLASSES = list(model.classes_)
NUM_CLASSES = len(CLASSES)


def predict(df: pd.DataFrame):
    """
    Multi-class prediction across CLASSES (e.g. Normal, DoS, DDoS,
    PortScan, BruteForce, WebAttack, Botnet).

    Returns:
      labels:     np.array of predicted class name strings, one per row
      confidence: np.array of the model's probability for its OWN
                  predicted class (i.e. how sure it is about that
                  specific call, not a fixed threshold)
      probs:      full (n_rows, n_classes) probability matrix, columns
                  in CLASSES order - useful if a caller wants the full
                  distribution rather than just the top pick
    """
    df = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)

    X_scaled = pd.DataFrame(scaler.transform(df), columns=FEATURE_COLUMNS, index=df.index)
    probs = model.predict_proba(X_scaled)

    pred_idx = np.argmax(probs, axis=1)
    labels = np.array(CLASSES)[pred_idx]
    confidence = probs[np.arange(len(probs)), pred_idx]

    return labels, confidence, probs
