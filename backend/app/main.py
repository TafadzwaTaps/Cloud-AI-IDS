from fastapi import FastAPI, UploadFile, File
import pandas as pd
import os
import random
from collections import deque
from app.database import get_supabase
from app.schemas import StatsSummary
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    precision_recall_fscore_support, confusion_matrix
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.schemas import PerformanceSummary
from fastapi import HTTPException
from collections import Counter
from datetime import datetime

from app.preprocess import preprocess
from app.model import predict, model as ML_MODEL, FEATURE_COLUMNS, CLASSES
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
    description="Multi-class intrusion detection using Machine Learning",
    version="2.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

scan_history = []

# =========================
# Class taxonomy (shared by every endpoint below)
# =========================
# Maps CIC-IDS2017's granular labels to the 7 classes the model now
# predicts directly (see model/train_model.py - CLASSES = the model's
# own model.classes_, this dict just maps raw dataset labels the same
# way training did, for evaluation/simulation purposes).
# KEEP THIS IN SYNC with LABEL_TO_BUCKET in model/train_model.py.
LABEL_TO_BUCKET = {
    "BENIGN": "Normal",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS", "Heartbleed": "DoS",
    "DDoS": "DDoS",
    "NetBIOS": "DDoS",   # CICDDoS2019 reflection/amplification DDoS
    "Portmap": "DDoS",   # CICDDoS2019 reflection/amplification DDoS
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Web Attack \ufffd Brute Force": "WebAttack",
    "Web Attack \ufffd XSS": "WebAttack",
    "Web Attack \ufffd Sql Injection": "WebAttack",
    "Bot": "Botnet",
    "Infiltration": "Botnet",
}

# Real MITRE ATT&CK technique IDs commonly associated with each
# category - a static reference mapping, not a per-flow ML attribution
# (the model classifies traffic type, not attacker technique).
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


def bucket_for_raw_label(raw_label: str) -> str:
    """Maps a raw CIC-IDS2017 label to one of the model's 7 classes."""
    return LABEL_TO_BUCKET.get(raw_label.strip(), "Botnet")


# -------------------------
# Health Check
# -------------------------
# Moved from "/" to "/health" so the root path is free for the actual
# dashboard (see the StaticFiles mount at the bottom of this file).
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
    labels, confidence, _ = predict(df_clean)

    results = []
    for i in range(len(labels)):
        results.append({
            "row": i,
            "prediction": str(labels[i]),
            "confidence": round(float(confidence[i]), 4)
        })

    MAX_RESULTS = 100  # prevent browser freeze

    return {
        "total_records": len(results),
        "attacks_detected": int((labels != "Normal").sum()),
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
        return ["Continue monitoring traffic", "Maintain current firewall rules"]
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
    labels, confidence, _ = predict(df_clean)

    total = len(labels)
    attacks = int((labels != "Normal").sum())
    benign = total - attacks
    ratio = round(attacks / total, 4) if total else 0.0

    risk_level = get_risk_level(ratio)

    attack_type_counts = Counter(labels[labels != "Normal"].tolist())

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
        "risk_level": risk_level
    })
    if len(scan_history) > 20:
        scan_history.pop(0)

    return {
        "total_records": total,
        "attacks_detected": attacks,
        "benign_detected": benign,
        "attack_ratio": ratio,
        "risk_level": risk_level,
        "attack_type_breakdown": dict(attack_type_counts),
        "analysis": generate_analysis(risk_level, ratio),
        "recommendations": generate_recommendations(risk_level)
    }


@app.post("/detect/evaluate")
async def detect_evaluate(file: UploadFile = File(...)):
    """
    Multi-class evaluation: maps the CSV's raw labels to the model's 7
    classes and compares against real predictions. Reports both a
    macro-averaged overall summary and genuine per-class
    precision/recall/f1 - the model is multi-class, so these per-class
    numbers are real, not derived from a binary yes/no.
    """
    df = pd.read_csv(file.file)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise HTTPException(
            status_code=400,
            detail=f"'Label' column not found. Found columns: {list(df.columns)}"
        )

    raw_labels = df["Label"].astype(str).str.strip()
    y_true = raw_labels.map(bucket_for_raw_label).values

    df_features = df.drop(columns=["Label"])
    df_clean = preprocess(df_features)
    y_pred, _, _ = predict(df_clean)

    precisions, recalls, f1s, supports = precision_recall_fscore_support(
        y_true, y_pred, labels=CLASSES, zero_division=0
    )
    per_class = {
        cls: {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1_score": round(float(f), 4),
            "support": int(s),
        }
        for cls, p, r, f, s in zip(CLASSES, precisions, recalls, f1s, supports)
    }

    metrics = {
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "f1_score": round(f1_score(y_true, y_pred, average="macro", zero_division=0), 4),
    }

    return {
        "total_records": int(len(y_pred)),
        "metrics": metrics,
        "per_class": per_class,
    }


@app.get("/stats/summary", response_model=StatsSummary)
def stats_summary():
    supabase = get_supabase()
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
    recent = ratios[:10]

    return {
        "total_scans": total_scans,
        "average_attack_ratio": round(sum(ratios) / total_scans, 4) if ratios else 0.0,
        "max_attack_ratio": round(max(ratios), 4) if ratios else 0.0,
        "min_attack_ratio": round(min(ratios), 4) if ratios else 0.0,
        "recent_scans": recent
    }

# Confusion Matrix Endpoint
# -------------------------
@app.post("/stats/confusion")
async def confusion_stats(file: UploadFile = File(...)):
    """
    Real 7x7 multi-class confusion matrix (rows=actual, cols=predicted,
    order given by `labels`). Replaces the old binary 2x2 response
    shape now that the model predicts the actual class, not just
    ATTACK/BENIGN.
    """
    df = pd.read_csv(file.file)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise HTTPException(
            status_code=400,
            detail=f"'Label' column not found. Found columns: {list(df.columns)}"
        )

    raw_labels = df["Label"].astype(str).str.strip()
    y_true = raw_labels.map(bucket_for_raw_label).values

    df_features = df.drop(columns=["Label"])
    df_clean = preprocess(df_features)
    y_pred, _, _ = predict(df_clean)

    matrix = confusion_matrix(y_true, y_pred, labels=CLASSES)

    return {
        "total_records": int(len(y_pred)),
        "labels": CLASSES,
        "matrix": matrix.tolist(),
    }

@app.post("/stats/attack-types")
async def attack_type_stats(file: UploadFile = File(...)):
    """Returns count of each raw attack-type label in the uploaded CSV. BENIGN is excluded."""
    df = pd.read_csv(file.file)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise HTTPException(status_code=400, detail="CSV must contain a 'Label' column")

    labels = df["Label"].astype(str).str.strip()
    attack_labels = labels[labels.str.upper() != "BENIGN"]

    if len(attack_labels) == 0:
        return {"attack_types": {}}

    counts = Counter(attack_labels)
    return {"total_attacks": int(len(attack_labels)), "attack_types": dict(counts)}

@app.get("/stats/history")
def get_scan_history():
    return {"history": scan_history[-20:]}

# -------------------------
# Per-Attack-Type Performance
# -------------------------
@app.post("/stats/attack-type-performance")
async def attack_type_performance(file: UploadFile = File(...)):
    """
    Real recall broken down by the CSV's ORIGINAL fine-grained label
    (e.g. 'DoS Hulk', 'SSH-Patator'), checking whether the model's
    multi-class prediction matches that label's expected bucket exactly
    - a stricter, more informative check than "flagged as any attack",
    now that the model actually distinguishes attack types.
    """
    df = pd.read_csv(file.file)
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        raise HTTPException(status_code=400, detail="CSV must contain a 'Label' column")

    raw_labels = df["Label"].astype(str).str.strip()
    df_features = df.drop(columns=["Label"])
    df_clean = preprocess(df_features)
    y_pred, _, _ = predict(df_clean)

    breakdown = {}
    for label in sorted(raw_labels.unique()):
        mask = (raw_labels == label).values
        total = int(mask.sum())
        expected_bucket = bucket_for_raw_label(label)

        if label.upper() == "BENIGN":
            false_positives = int((y_pred[mask] != "Normal").sum())
            breakdown[label] = {
                "total": total,
                "false_positives": false_positives,
                "false_positive_rate": round(false_positives / total, 4) if total else 0.0
            }
        else:
            correct = int((y_pred[mask] == expected_bucket).sum())
            breakdown[label] = {
                "total": total,
                "expected_class": expected_bucket,
                "correctly_classified": correct,
                "missed": total - correct,
                "recall": round(correct / total, 4) if total else 0.0
            }

    return {"total_records": int(len(df)), "breakdown": breakdown}

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
# CLASS and confidence score are genuine multi-class model output.
HOLDOUT_PATH = os.path.join(PROJECT_ROOT, "model", "test_holdout.csv")
_holdout_df = None
_holdout_by_bucket = {}

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
    df["__bucket"] = df["Label"].astype(str).str.strip().map(bucket_for_raw_label)
    _holdout_df = df
    _holdout_by_bucket = {b: g for b, g in df.groupby("__bucket")}


def _random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _random_internal_ip():
    return f"10.0.{random.randint(0, 5)}.{random.randint(1, 254)}"


@app.post("/simulate")
def simulate_traffic(attack_type: str = "Normal", count: int = 10):
    """
    Samples `count` REAL held-out rows whose TRUE label belongs to
    `attack_type`'s bucket, then runs them through the real multi-class
    model. Severity/MITRE mapping is based on what the MODEL predicted
    (not the ground truth), since this is now a genuine classification
    decision rather than a binary yes/no.
    """
    _load_holdout()
    if _holdout_df.empty:
        raise HTTPException(
            status_code=503,
            detail="test_holdout.csv not found next to the model - run model/train_model.py first."
        )

    bucket = attack_type if attack_type in _holdout_by_bucket else "Normal"
    pool = _holdout_by_bucket.get(bucket)
    if pool is None or pool.empty:
        raise HTTPException(status_code=404, detail=f"No holdout rows for '{attack_type}'")

    n = min(count, len(pool)) if len(pool) < count else count
    sample = pool.sample(n=n, replace=len(pool) < count)
    raw_labels = sample["Label"].astype(str).str.strip()
    features = sample.drop(columns=["Label", "__bucket"])

    df_clean = preprocess(features.copy())
    pred_labels, confidence, _ = predict(df_clean)

    dest_port_col = next((c for c in features.columns if c.strip() == "Destination Port"), None)

    new_entries = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for i in range(len(sample)):
        true_label = raw_labels.iloc[i]
        true_bucket = bucket_for_raw_label(true_label)
        predicted_class = str(pred_labels[i])
        port = int(features.iloc[i][dest_port_col]) if dest_port_col else random.choice([80, 443, 22, 3306])
        proto = "TCP" if port in (80, 443, 22, 3306, 21) else "UDP"

        entry = {
            "time": now,
            "source": f"{_random_ip()}:{random.randint(1024, 65000)}",
            "dest": f"{_random_internal_ip()}:{port}",
            "proto": proto,
            "port": port,
            "label": predicted_class,
            "true_label": true_label,
            "correct": predicted_class == true_bucket,
            "severity": SEVERITY_MAP.get(predicted_class, "medium") if predicted_class != "Normal" else "benign",
            "confidence": round(float(confidence[i]), 4),
            "mitre": MITRE_MAP.get(predicted_class, "-") if predicted_class != "Normal" else "-",
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
        "dataset": "CIC-IDS2017 + CICDDoS2019 (NetBIOS, Portmap)",
        "num_features": len(FEATURE_COLUMNS),
        "num_classes": len(CLASSES),
        "classes": CLASSES,
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
    Auto-evaluates against test_holdout.csv (genuinely never trained
    on) - no upload needed, since this file ships alongside the model.

    Now that the model is truly multi-class, this reports REAL
    per-class precision/recall/f1 (via sklearn's
    precision_recall_fscore_support) and a REAL 7x7 confusion matrix -
    no more binary-only compromise.
    """
    _load_holdout()
    if _holdout_df.empty:
        raise HTTPException(status_code=503, detail="test_holdout.csv not found next to the model.")

    df = _holdout_df.drop(columns=["__bucket"])
    raw_labels = df["Label"].astype(str).str.strip()
    y_true = raw_labels.map(bucket_for_raw_label).values
    features = df.drop(columns=["Label"])

    df_clean = preprocess(features.copy())
    y_pred, _, _ = predict(df_clean)

    matrix = confusion_matrix(y_true, y_pred, labels=CLASSES)

    precisions, recalls, f1s, supports = precision_recall_fscore_support(
        y_true, y_pred, labels=CLASSES, zero_division=0
    )
    per_class = {
        cls: {
            "precision": round(float(p), 4),
            "recall": round(float(r), 4),
            "f1_score": round(float(f), 4),
            "support": int(s),
        }
        for cls, p, r, f, s in zip(CLASSES, precisions, recalls, f1s, supports)
    }

    # Also keep the finer-grained, original-label recall breakdown -
    # useful for spotting a specific weak attack subtype (e.g.
    # "DoS slowloris" vs the coarser "DoS" bucket average).
    per_original_label = {}
    for label in sorted(raw_labels.unique()):
        mask = (raw_labels == label).values
        total = int(mask.sum())
        expected_bucket = bucket_for_raw_label(label)
        if label.upper() == "BENIGN":
            fp = int((y_pred[mask] != "Normal").sum())
            per_original_label[label] = {"total": total, "false_positive_rate": round(fp / total, 4) if total else 0.0}
        else:
            correct = int((y_pred[mask] == expected_bucket).sum())
            per_original_label[label] = {"total": total, "recall": round(correct / total, 4) if total else 0.0}

    return {
        "total_records": int(len(df)),
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "f1_score": round(f1_score(y_true, y_pred, average="macro", zero_division=0), 4),
        "confusion_matrix": {"labels": CLASSES, "matrix": matrix.tolist()},
        "per_class": per_class,
        "per_type": per_original_label,
    }

# -------------------------
# Serve the frontend dashboard
# -------------------------
# This MUST be the last thing added to the app. FastAPI/Starlette match
# routes in the order they were registered, so every @app.get/@app.post
# route above takes priority for its own path - this mount only catches
# whatever wasn't already matched, and serves index.html for "/" (and
# for any other unmatched path, since html=True).
if os.path.isdir(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
