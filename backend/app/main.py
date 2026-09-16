from fastapi import FastAPI, UploadFile, File
import pandas as pd
from app.database import get_connection
from app.schemas import StatsSummary
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from fastapi.middleware.cors import CORSMiddleware
from app.schemas import PerformanceSummary
from sklearn.metrics import confusion_matrix
from app.schemas import ConfusionMatrixResponse
from fastapi import HTTPException
from collections import Counter
from datetime import datetime

from app.preprocess import preprocess
from app.model import predict
from app.schemas import DetectionResponse

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
@app.get("/")
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
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO intrusion_logs 
        (total_records, attacks_detected, benign_detected, attack_ratio)
        VALUES (%s, %s, %s, %s)
        """,
        (total, attacks, benign, ratio)
    )

    conn.commit()
    conn.close()

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
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT 
            COUNT(*) AS total_scans,
            SUM(total_records) AS total_records_processed,
            SUM(attacks_detected) AS total_attacks_detected,
            AVG(attack_ratio) AS average_attack_ratio
        FROM intrusion_logs
    """)

    row = cursor.fetchone()
    conn.close()

    return {
        "total_scans": row[0] or 0,
        "total_records_processed": row[1] or 0,
        "total_attacks_detected": row[2] or 0,
        "average_attack_ratio": round(float(row[3]), 4) if row[3] is not None else 0.0
    }

# Model Performance Monitoring
# -------------------------
@app.get("/stats/performance", response_model=PerformanceSummary)
def performance_stats():
    conn = get_connection()
    cursor = conn.cursor()

    # Overall performance stats
    cursor.execute("""
        SELECT 
            COUNT(*) AS total_scans,
            AVG(attack_ratio),
            MAX(attack_ratio),
            MIN(attack_ratio)
        FROM intrusion_logs
    """)

    row = cursor.fetchone()

    # Last 10 scans
    cursor.execute("""
        SELECT attack_ratio
        FROM intrusion_logs
        ORDER BY id DESC
        LIMIT 10
    """)

    recent = [float(r[0]) for r in cursor.fetchall()]

    conn.close()

    return {
        "total_scans": row[0] or 0,
        "average_attack_ratio": round(float(row[1]), 4) if row[1] else 0.0,
        "max_attack_ratio": round(float(row[2]), 4) if row[2] else 0.0,
        "min_attack_ratio": round(float(row[3]), 4) if row[3] else 0.0,
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
