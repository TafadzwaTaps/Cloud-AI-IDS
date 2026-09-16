import joblib
import pandas as pd
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

# Default matches model.predict()'s implicit 0.5 cutoff. Rare attack
# types (Infiltration, Heartbleed, Web Attack - Sql Injection, ...) tend
# to produce lower, less confident attack-probability scores than
# high-volume attacks like DDoS or PortScan, simply because the model
# saw far fewer of them even after oversampling in train_model.py.
# Lowering this (e.g. 0.3) trades some false positives for catching
# more of those borderline rare-attack cases - tune it against
# test_holdout.csv (see /stats/attack-type-performance) rather than
# guessing, and document whatever you land on in the thesis as the
# ROC-curve tradeoff it is.
DECISION_THRESHOLD = float(os.getenv("IDS_DECISION_THRESHOLD", "0.5"))


def predict(df: pd.DataFrame):
    # Ensure correct columns and order
    df = df.reindex(columns=FEATURE_COLUMNS, fill_value=0)

    X_scaled = pd.DataFrame(scaler.transform(df), columns=FEATURE_COLUMNS, index=df.index)
    probs = model.predict_proba(X_scaled)[:, 1]
    preds = (probs >= DECISION_THRESHOLD).astype(int)

    return preds, probs
