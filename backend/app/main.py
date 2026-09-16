from fastapi import FastAPI, UploadFile, File
import pandas as pd
import os
import random
from collections import deque
from app.database import get_supabase
from app.schemas import StatsSummary
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.schemas import PerformanceSummary
from sklearn.metrics import confusion_matrix
from app.schemas import ConfusionMatrixResponse
from fastapi import HTTPException
from collections import Counter
from datetime import datetime

from app.preprocess import preprocess
from app.model import predict, model as ML_MODEL, FEATURE_COLUMNS
from app.schemas import DetectionResponse

# Same deterministic path resolution as model.py: walk up from this
# file's own absolute location (backend/app/main.py -> backend/app ->
# backend -> repo root) rather than relying on the process's working
# directory, which differs between local dev, Docker, and Render.
APP_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(APP_DIR)
PROJECT_ROOT = os.path.dirname(BACKEND_DIR)
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

app = FastAPI(
    title="Cloud-Based AI Intrusion Detection System",
    description="Real-time intrusion detection using Machine Learning",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_history = []

# -------------------------
# Health Check
# -------------------------
# Moved from "/" to "/health" so the root path is free for the actual
# dashboard (see the StaticFiles mount at the bottom of this file).
# Nothing here changed - it's the same endpoint, same response, just a
# different path. Render/uptime monitors should point at /health now.
@app.get("/health")
def health_check():
    return {"status": "IDS backend running"}

# -------------------------
# Full Detection (LIMITED OUTPUT)
# -------------------------
@app.post("/detect/csv", response_model=DetectionResponse)
async def detect_intrusion(file: UploadFile = File(...)):
    df = pd.read_csv(file.file)

    df_clean = preprocess(df)
    preds, probs = predict(df_clean)

    results = []
    for i in range(len(preds)):
        results.append({
            "row": i,
            "prediction": "ATTACK" if preds[i] == 1 else "BENIGN",
            "confidence": round(float(probs[i]), 4)
        })

    MAX_RESULTS = 100  # prevent browser freeze

    return {
        "total_records": len(results),
        "attacks_detected": int(sum(preds)),
        "results": results[:MAX_RESULTS]  # return sample only
    }

# -------------------------
# Summary Endpoint (BEST PRACTICE)
# -------------------------
def generate_analysis(risk_level, ratio):
    if risk_level == "LOW":
        return "Traffic appears normal with minimal malicious activity detected."
    
    elif risk_level == "MEDIUM":
        return "Suspicious traffic patterns detected. Possible reconnaissance or low-level attacks."

    else:
        return "High volume of malicious traffic detected. System may be under active attack."


def generate_recommendations(risk_level):
    if risk_level == "LOW":
        return [
            "Continue monitoring traffic",
            "Maintain current firewall rules"
        ]

    elif risk_level == "MEDIUM":
        return [
            "Inspect suspicious IP addresses",
            "Enable intrusion prevention rules",
            "Increase logging level"
        ]

    else:
        return [
            "Block malicious IPs immediately",
            "Isolate affected systems",
            "Trigger incident response protocol"
        ]

def get_risk_level(ratio):
    if ratio < 0.05:
        return "LOW"
    elif ratio < 0.2:
        return "MEDIUM"
    return "HIGH"


@app.post("/detect/summary")
async def detect_summary(file: UploadFile = File(...)):
    df = pd.read_csv(file.file)

    df_clean = preprocess(df)
    preds, _ = predict(df_clean)

    total = len(preds)
    attacks = int(sum(preds))
    benign = total - attacks
    ratio = round(attacks / total, 4)

    # ✅ FIX: define risk_level
    risk_level = get_risk_level(ratio)

    # ---- DATABASE LOGGING ----
    supabase = get_supabase()
    supabase.table("intrusion_logs").insert({
        "total_records": total,
        "attacks_detected": attacks,
        "benign_detected": benign,
        "attack_ratio": ratio,
    }).execute()

    # ---- IN-MEMORY HISTORY ----
    scan_history.append({
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "total_records": total,
        "attacks_detected": attacks,
        "attack_ratio": ratio,
        "risk_level": risk_level  # ✅ NEW
    })

    # Keep only last 20 scans
    if len(scan_history) > 20:
        scan_history.pop(0)

    return {
        "total_records": total,
        "attacks_detected": attacks,
        "benign_detected": benign,
        "attack_ratio": ratio,
        "risk_level": risk_level,
        "analysis": generate_analysis(risk_level, ratio),
        "recommendations": generate_recommendations(risk_level)
    }


@app.post("/detect/evaluate")
async def detect_evaluate(file: UploadFile = File(...)):
    df = pd.read_csv(file.file)

    # Remove hidden spaces in column names
    df.columns = df.columns.str.strip()

    # Check label column
    if "Label" not in df.columns:
        raise HTTPException(
            status_code=400,
            detail=f"'Label' column not found. Found columns: {list(df.columns)}"
        )

    # -----------------------------
    # Convert CICIDS labels to binary
    # BENIGN = 0
    # Any other attack = 1
    # -----------------------------
    y_true = df["Label"].astype(str).str.strip().str.upper()
    y_true = y_true.apply(lambda x: 0 if x == "BENIGN" else 1)

    # Remove label from features
    df_features = df.drop(columns=["Label"])

    df_clean = preprocess(df_features)
    preds, _ = predict(df_clean)

    metrics = {
        "accuracy": round(accuracy_score(y_true, preds), 4),
        "precision": round(precision_score(y_true, preds, zero_division=0), 4),
        "recall": round(recall_score(y_true, preds, zero_division=0), 4),
        "f1_score": round(f1_score(y_true, preds, zero_division=0), 4)
    }

    return {
        "total_records": int(len(preds)),
        "metrics": metrics
    }

@app.get("/stats/summary", response_model=StatsSummary)
def stats_summary():
    supabase = get_supabase()
    # PostgREST (Supabase's REST API) doesn't do arbitrary SQL aggregates
    # like COUNT/SUM/AVG through the table query builder the way raw SQL
    # did - so we fetch the columns we need and aggregate here instead.
    # Fine for this table's scale (one row per scan, not per packet).
    # If scan volume ever exceeds Supabase's default 1000-row request
    # cap, raise "Max Rows" in Project Settings -> API, or switch this
    # to a Postgres RPC function that does the aggregation server-side.
    response = (
        supabase.table("intrusion_logs")
        .select("total_records, attacks_detected, attack_ratio")
        .execute()
    )
    rows = response.data or []
    total_scans = len(rows)

    return {
        "total_scans": total_scans,
        "total_records_processed": sum(r["total_records"] for r in rows),
        "total_attacks_detected": sum(r["attacks_detected"] for r in rows),
        "average_attack_ratio": (
            round(sum(r["attack_ratio"] for r in rows) / total_scans, 4)
            if total_scans else 0.0
        ),
    }

# Model Performance Monitoring
# -------------------------
@app.get("/stats/performance", response_model=PerformanceSummary)
def performance_stats():
    supabase = get_supabase()
    response = (
        supabase.table("intrusion_logs")
        .select("attack_ratio")
        .order("id", desc=True)
        .execute()
    )
    ratios = [float(r["attack_ratio"]) for r in (response.data or [])]
    total_scans = len(ratios)
    recent = ratios[:10]  # already ordered most-recent-first

    return {
        "total_scans": total_scans,
        "average_attack_ratio": round(sum(ratios) / total_scans, 4) if ratios else 0.0,
        "max_attack_ratio": round(max(ratios), 4) if ratios else 0.0,
        "min_attack_ratio": round(min(ratios), 4) if ratios else 0.0,
        "recent_scans": recent
    }

# Confusion Matrix Endpoint
# -------------------------
@app.post("/stats/confusion", response_model=ConfusionMatrixResponse)
async def confusion_stats(file: UploadFile = File(...)):
    df = pd.read_csv(file.file)

    # Remove hidden spaces in column names
    df.columns = df.columns.str.strip()

    # Check Label column
    if "Label" not in df.columns:
        raise HTTPException(
            status_code=400,
            detail=f"'Label' column not found. Found columns: {list(df.columns)}"
        )

    # ---------------------------------
    # Convert CICIDS labels to binary
    # BENIGN = 0
    # Any other value = ATTACK (1)
    # ---------------------------------
    y_true = df["Label"].astype(str).str.strip().str.upper()
    y_true = y_true.apply(lambda x: 0 if x == "BENIGN" else 1)

    # Remove label column for prediction
    df_features = df.drop(columns=["Label"])

    df_clean = preprocess(df_features)
    preds, _ = predict(df_clean)

    # Confusion matrix (ensure binary order)
    tn, fp, fn, tp = confusion_matrix(y_true, preds, labels=[0, 1]).ravel()

    return {
        "total_records": int(len(preds)),
        "true_positive": int(tp),
        "true_negative": int(tn),
        "false_positive": int(fp),
        "false_negative": int(fn)
    }

@app.post("/stats/attack-types")
async def attack_type_stats(file: UploadFile = File(...)):
    """
    Returns count of each attack type.
    BENIGN is excluded.
    """

    df = pd.read_csv(file.file)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise HTTPException(status_code=400, detail="CSV must contain a 'Label' column")

    # Clean labels
    labels = df["Label"].astype(str).str.strip()

    # Remove BENIGN
    attack_labels = labels[labels.str.upper() != "BENIGN"]

    if len(attack_labels) == 0:
        return {"attack_types": {}}

    counts = Counter(attack_labels)

    return {
        "total_attacks": int(len(attack_labels)),
        "attack_types": dict(counts)
    }

@app.get("/stats/history")
def get_scan_history():
    return {
        "history": scan_history[-20:]  # last 20 scans
    }

# -------------------------
# Per-Attack-Type Performance
# -------------------------
@app.post("/stats/attack-type-performance")
async def attack_type_performance(file: UploadFile = File(...)):
    """
    Detection recall broken down by the CSV's original attack-type label
    (DDoS, PortScan, Infiltration, BENIGN, ...), not just a single blended
    binary accuracy figure. For BENIGN this reports the false-positive
    rate instead of recall, since "recall" isn't meaningful for the
    negative class.

    Feed this the output of export_holdout.py (test_holdout.csv) to get
    numbers that reflect genuinely unseen data across every category in
    the dataset, rather than whichever single attack type happens to be
    in the file you upload.
    """
    df = pd.read_csv(file.file)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise HTTPException(status_code=400, detail="CSV must contain a 'Label' column")

    labels = df["Label"].astype(str).str.strip()
    df_features = df.drop(columns=["Label"])

    df_clean = preprocess(df_features)
    preds, _ = predict(df_clean)

    breakdown = {}
    for label in sorted(labels.unique()):
        mask = (labels == label).values
        total = int(mask.sum())
        flagged_as_attack = int(preds[mask].sum())

        if label.upper() == "BENIGN":
            breakdown[label] = {
                "total": total,
                "false_positives": flagged_as_attack,
                "false_positive_rate": round(flagged_as_attack / total, 4) if total else 0.0
            }
        else:
            missed = total - flagged_as_attack
            breakdown[label] = {
                "total": total,
                "detected": flagged_as_attack,
                "missed": missed,
                "recall": round(flagged_as_attack / total, 4) if total else 0.0
            }

    return {
        "total_records": int(len(df)),
        "breakdown": breakdown
    }

# =========================
# Live demo: traffic simulator
# =========================
# CIC-IDS2017's merged CSV (what this model trained on) doesn't retain
# real source/destination IPs - they were stripped upstream of the file
# this project uses. So for a "live" dashboard feel, the IP:port pairs
# below are randomly generated for DISPLAY ONLY.
#
# What is NOT fake: every simulated flow is a REAL row sampled from
# test_holdout.csv (rows this model has never been trained on), run
# through the actual preprocess()/predict() pipeline. The predicted
# label and confidence score are genuine model output, not scripted.
HOLDOUT_PATH = os.path.join(PROJECT_ROOT, "model", "test_holdout.csv")
_holdout_df = None
_holdout_by_bucket = {}

# Maps CIC-IDS2017's granular labels to the 6 categories this dashboard
# exposes as simulation buttons / filters. Infiltration is folded into
# Botnet as the closest available bucket - both are post-compromise,
# low-and-slow activity - rather than inventing a 7th button.
LABEL_TO_BUCKET = {
    "BENIGN": "Normal",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS", "Heartbleed": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Web Attack \x96 Brute Force": "WebAttack",
    "Web Attack \x96 XSS": "WebAttack",
    "Web Attack \x96 Sql Injection": "WebAttack",
    "Bot": "Botnet",
    "Infiltration": "Botnet",
}

# Real MITRE ATT&CK technique IDs commonly associated with each
# category - a static reference mapping, not a per-flow ML attribution
# (this model does not do technique classification).
MITRE_MAP = {
    "DoS": "T1499 - Endpoint Denial of Service",
    "DDoS": "T1498 - Network Denial of Service",
    "PortScan": "T1046 - Network Service Discovery",
    "BruteForce": "T1110 - Brute Force",
    "WebAttack": "T1190 - Exploit Public-Facing Application",
    "Botnet": "T1071 - Application Layer Protocol (C2)",
}

SEVERITY_MAP = {
    "DoS": "critical", "DDoS": "critical", "Botnet": "critical",
    "BruteForce": "high", "WebAttack": "high", "PortScan": "medium",
}

traffic_log = deque(maxlen=500)  # most-recent-first ring buffer, in memory


def _load_holdout():
    global _holdout_df, _holdout_by_bucket
    if _holdout_df is not None:
        return
    if not os.path.isfile(HOLDOUT_PATH):
        _holdout_df = pd.DataFrame()
        return
    df = pd.read_csv(HOLDOUT_PATH)
    df.columns = df.columns.str.strip()
    df["__bucket"] = df["Label"].astype(str).str.strip().map(LABEL_TO_BUCKET).fillna("Botnet")
    _holdout_df = df
    _holdout_by_bucket = {b: g for b, g in df.groupby("__bucket")}


def _random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _random_internal_ip():
    return f"10.0.{random.randint(0, 5)}.{random.randint(1, 254)}"


@app.post("/simulate")
def simulate_traffic(attack_type: str = "Normal", count: int = 10):
    """
    Samples `count` REAL held-out rows belonging to `attack_type`'s
    bucket and runs them through the real model. See module comment
    above for exactly what's real (the ML inference) vs. cosmetic
    (the IP addresses).
    """
    _load_holdout()
    if _holdout_df.empty:
        raise HTTPException(
            status_code=503,
            detail="test_holdout.csv not found next to the model - run "
                   "model/train_model.py (or export_holdout.py) first."
        )

    bucket = attack_type if attack_type in _holdout_by_bucket else "Normal"
    pool = _holdout_by_bucket.get(bucket)
    if pool is None or pool.empty:
        raise HTTPException(status_code=404, detail=f"No holdout rows for '{attack_type}'")

    n = min(count, len(pool)) if len(pool) < count else count
    sample = pool.sample(n=n, replace=len(pool) < count)
    labels = sample["Label"].astype(str).str.strip()
    features = sample.drop(columns=["Label", "__bucket"])

    df_clean = preprocess(features.copy())
    preds, probs = predict(df_clean)

    dest_port_col = next((c for c in features.columns if c.strip() == "Destination Port"), None)

    new_entries = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for i in range(len(sample)):
        real_label = labels.iloc[i]
        real_bucket = LABEL_TO_BUCKET.get(real_label, "Botnet")
        predicted_attack = bool(preds[i])
        port = int(features.iloc[i][dest_port_col]) if dest_port_col else random.choice([80, 443, 22, 3306])
        proto = "TCP" if port in (80, 443, 22, 3306, 21) else "UDP"

        entry = {
            "time": now,
            "source": f"{_random_ip()}:{random.randint(1024, 65000)}",
            "dest": f"{_random_internal_ip()}:{port}",
            "proto": proto,
            "port": port,
            "label": real_bucket if predicted_attack else "BENIGN",
            "true_label": real_label,
            "severity": SEVERITY_MAP.get(real_bucket, "medium") if predicted_attack else "benign",
            "confidence": round(float(probs[i]), 4),
            "mitre": MITRE_MAP.get(real_bucket, "-") if predicted_attack else "-",
        }
        new_entries.append(entry)
        traffic_log.appendleft(entry)

    return {"injected": len(new_entries), "entries": new_entries}


@app.get("/logs/traffic")
def get_traffic_logs():
    return {"logs": list(traffic_log)}


# =========================
# ML Model page
# =========================
@app.get("/model/info")
def model_info():
    return {
        "algorithm": "Random Forest",
        "n_estimators": getattr(ML_MODEL, "n_estimators", None),
        "dataset": "CIC-IDS2017",
        "num_features": len(FEATURE_COLUMNS),
    }


@app.get("/model/feature-importance")
def model_feature_importance(top_n: int = 10):
    importances = list(zip(FEATURE_COLUMNS, ML_MODEL.feature_importances_))
    importances.sort(key=lambda x: x[1], reverse=True)
    top = importances[:top_n]
    return {"features": [{"name": n, "importance": round(float(v), 5)} for n, v in top]}


@app.get("/model/performance")
def model_performance():
    """
    Auto-evaluates against test_holdout.csv (genuinely never trained on)
    - no upload needed, since this file ships alongside the model.

    Deliberately does NOT report per-class precision/recall/f1 as if
    six independent predicted classes existed: the deployed model is
    binary (ATTACK/BENIGN), not multi-class, so that would mean
    fabricating numbers a binary classifier can't actually produce.
    What IS reported per attack type (recall, i.e. "of the real X
    rows, how many did the model flag as an attack") is genuine.
    """
    _load_holdout()
    if _holdout_df.empty:
        raise HTTPException(status_code=503, detail="test_holdout.csv not found next to the model.")

    df = _holdout_df.drop(columns=["__bucket"])
    labels = df["Label"].astype(str).str.strip()
    y_true = (labels.str.upper() != "BENIGN").astype(int)
    features = df.drop(columns=["Label"])

    df_clean = preprocess(features.copy())
    preds, _ = predict(df_clean)

    tn, fp, fn, tp = confusion_matrix(y_true, preds, labels=[0, 1]).ravel()

    per_type = {}
    for label in sorted(labels.unique()):
        mask = (labels == label).values
        total = int(mask.sum())
        flagged = int(preds[mask].sum())
        if label.upper() == "BENIGN":
            per_type[label] = {
                "total": total,
                "false_positive_rate": round(flagged / total, 4) if total else 0.0
            }
        else:
            per_type[label] = {
                "total": total,
                "recall": round(flagged / total, 4) if total else 0.0
            }

    return {
        "total_records": int(len(df)),
        "accuracy": round(accuracy_score(y_true, preds), 4),
        "precision": round(precision_score(y_true, preds, zero_division=0), 4),
        "recall": round(recall_score(y_true, preds, zero_division=0), 4),
        "f1_score": round(f1_score(y_true, preds, zero_division=0), 4),
        "confusion_matrix": {
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp)
        },
        "per_type": per_type,
    }

# -------------------------
# Serve the frontend dashboard
# -------------------------
# This MUST be the last thing added to the app. FastAPI/Starlette match
# routes in the order they were registered, so every @app.get/@app.post
# route above takes priority for its own path - this mount only catches
# whatever wasn't already matched, and serves index.html for "/" (and
# for any other unmatched path, since html=True).
#
# Guarded with exists() so the backend still starts even in a setup
# where frontend/ isn't deployed alongside backend/ (e.g. if you ever
# split them into separate repos) - it'll just skip serving the UI and
# /health is still available for a deploy health check.
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
