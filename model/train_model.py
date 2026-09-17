import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix
)

import joblib

# =========================
# Config
# =========================
MIN_TRAIN_SAMPLES_PER_CLASS = 2000

# Maps CIC-IDS2017's granular labels to the 7 classes this system
# predicts. KEEP THIS IN SYNC with LABEL_TO_BUCKET in
# backend/app/main.py - both must agree on the same class taxonomy,
# or the live simulator's "true label" comparisons go wrong.
LABEL_TO_BUCKET = {
    "BENIGN": "Normal",
    "DoS Hulk": "DoS", "DoS GoldenEye": "DoS", "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS", "Heartbleed": "DoS",
    "DDoS": "DDoS",
    "NetBIOS": "DDoS",
    "Portmap": "DDoS",
    "DrDoS_NetBIOS": "DDoS",
    "DrDoS_DNS": "DDoS",
    "LDAP": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce", "SSH-Patator": "BruteForce",
    "Web Attack � Brute Force": "WebAttack",
    "Web Attack � XSS": "WebAttack",
    "Web Attack � Sql Injection": "WebAttack",
    "Bot": "Botnet",
    "Infiltration": "Botnet",
}

# =========================
# Load merged dataset
# =========================
_raw_cols = pd.read_csv("CIC_IDS_2017.csv", nrows=0).columns.tolist()
_label_col = next(c for c in _raw_cols if c.strip() == "Label")
_dtype_map = {c: "float32" for c in _raw_cols if c != _label_col}

df = pd.read_csv("CIC_IDS_2017.csv", dtype=_dtype_map, low_memory=False)

df.columns = df.columns.str.strip()

columns_to_drop = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
df = df.drop(columns=[col for col in columns_to_drop if col in df.columns])

original_label = df["Label"].astype(str).str.strip()

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
original_label = original_label.loc[df.index]

# Multi-class target: map to the 7-class taxonomy instead of binary.
df["Label"] = original_label.map(LABEL_TO_BUCKET)
unmapped = df["Label"].isna()
if unmapped.any():
    print(f"WARNING: {int(unmapped.sum())} rows had an unmapped label, dropping:",
          original_label[unmapped].unique())
    df = df[~unmapped]
    original_label = original_label[~unmapped]

print("Class distribution (7-class):")
print(df["Label"].value_counts())

X = df.drop("Label", axis=1)
y = df["Label"]

# =========================
# Train-test split
# =========================
# Stratify on the ORIGINAL fine-grained label (not the bucket) so even
# rare raw categories land proportionally in both sets, same rationale
# as the binary version.
try:
    X_train, X_test, y_train, y_test, orig_train, orig_test = train_test_split(
        X, y, original_label,
        test_size=0.2, random_state=42, stratify=original_label
    )
except ValueError as e:
    print(f"\nWARNING: falling back to bucket-level stratify: {e}")
    X_train, X_test, y_train, y_test, orig_train, orig_test = train_test_split(
        X, y, original_label,
        test_size=0.2, random_state=42, stratify=y
    )

# =========================
# Feature scaling
# =========================
scaler = StandardScaler()
X_train_scaled = pd.DataFrame(
    scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index
)
X_test_scaled = scaler.transform(X_test)

# =========================
# Oversample rare classes (training set only)
# =========================
rng = np.random.RandomState(42)
oversampled_frames = [X_train_scaled]
oversampled_labels = [y_train]

for cls in y_train.unique():
    if cls == "Normal":
        continue
    mask = (y_train == cls).values
    count = int(mask.sum())
    if count == 0 or count >= MIN_TRAIN_SAMPLES_PER_CLASS:
        continue
    subset_X = X_train_scaled[mask]
    subset_y = y_train[mask]
    extra_needed = MIN_TRAIN_SAMPLES_PER_CLASS - count
    sample_idx = rng.choice(subset_X.index, size=extra_needed, replace=True)
    oversampled_frames.append(subset_X.loc[sample_idx])
    oversampled_labels.append(subset_y.loc[sample_idx])
    print(f"  Oversampled '{cls}': {count} -> {MIN_TRAIN_SAMPLES_PER_CLASS} rows")

X_train_final = pd.concat(oversampled_frames, axis=0)
y_train_final = pd.concat(oversampled_labels, axis=0)

shuffle_idx = rng.permutation(len(X_train_final))
X_train_final = X_train_final.iloc[shuffle_idx]
y_train_final = y_train_final.iloc[shuffle_idx]

print(f"\nTraining set size before oversampling: {len(X_train_scaled)}")
print(f"Training set size after oversampling:  {len(X_train_final)}")

# =========================
# Multi-class model
# =========================
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)
model.fit(X_train_final, y_train_final)

CLASSES = list(model.classes_)  # canonical class order used by predict_proba

# =========================
# Evaluation (real, untouched, held-out test data only)
# =========================
y_pred = model.predict(X_test_scaled)

print("\nOverall Performance Metrics (7-class, macro-averaged, held-out test set):")
print("Accuracy:", accuracy_score(y_test, y_pred))
print("Precision (macro):", precision_score(y_test, y_pred, average="macro", zero_division=0))
print("Recall (macro):", recall_score(y_test, y_pred, average="macro", zero_division=0))
print("F1 (macro):", f1_score(y_test, y_pred, average="macro", zero_division=0))

print("\nPer-class report:")
print(classification_report(y_test, y_pred, labels=CLASSES, zero_division=0))

print("\nConfusion Matrix (rows=actual, cols=predicted), class order:", CLASSES)
print(confusion_matrix(y_test, y_pred, labels=CLASSES))

print("\nRecall by ORIGINAL attack type (held-out test set, finer than bucket):")
for label in sorted(orig_test.unique()):
    if label.upper() == "BENIGN":
        continue
    mask = (orig_test == label).values
    total = int(mask.sum())
    if total == 0:
        continue
    expected_bucket = LABEL_TO_BUCKET.get(label)
    detected = int((y_pred[mask] == expected_bucket).sum())
    print(f"  {label:30s} {detected:>6d} / {total:<6d}  recall={detected/total:.3f}")

# =========================
# Feature Importance Plot
# =========================
importances = model.feature_importances_
feature_names = X.columns
indices = np.argsort(importances)[::-1][:15]

plt.figure(figsize=(10, 6))
plt.title("Top 15 Feature Importances (Multi-Class IDS)")
plt.bar(range(len(indices)), importances[indices])
plt.xticks(range(len(indices)), feature_names[indices], rotation=90)
plt.tight_layout()
plt.savefig("feature_importances.png")
print("\nFeature importance plot saved to feature_importances.png")

FEATURE_COLUMNS = X.columns.tolist()
joblib.dump(FEATURE_COLUMNS, "feature_columns.pkl")

# =========================
# Save final model & scaler
# =========================
joblib.dump(model, "ids_model.pkl")
joblib.dump(scaler, "scaler.pkl")
joblib.dump(CLASSES, "class_labels.pkl")

# =========================
# Export the genuine held-out test set - keeps the ORIGINAL
# fine-grained label (e.g. "DDoS", "Heartbleed"), same as the binary
# version, so /model/performance and /stats/attack-type-performance
# can report both bucket-level and original-label-level results.
# =========================
holdout = X_test.copy()
holdout["Label"] = orig_test.values
holdout.to_csv("test_holdout.csv", index=False)
print(f"\nDone: test_holdout.csv written: {len(holdout)} rows (never used in training)")

print("\nFinal multi-class model, scaler, feature list, and class labels saved.")
