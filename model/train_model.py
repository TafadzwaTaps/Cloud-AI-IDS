import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

import joblib

# =========================
# Config
# =========================
# Any attack subtype (DDoS, PortScan, Infiltration, Heartbleed, ...) with
# fewer than this many rows in the TRAINING split gets oversampled (with
# replacement) up to this count. class_weight="balanced" below only
# balances BENIGN vs ATTACK as two buckets - it does nothing for the
# imbalance *within* ATTACK, where DoS Hulk (~230k rows in the full
# CIC-IDS2017 dataset) drowns out Heartbleed (~11 rows) or Infiltration
# (~36 rows). Without this, the RandomForest has almost no signal to
# learn what those rare attack types look like, and recall on them
# suffers even though overall "accuracy" looks fine.
MIN_TRAIN_SAMPLES_PER_ATTACK_TYPE = 2000

# =========================
# Load merged dataset
# =========================
# Specify float32 dtype upfront rather than letting pandas default to
# float64 and downcasting afterward - on a multi-million-row file the
# default read briefly doubles memory usage, and sklearn's tree code
# converts to float32 internally anyway, so this avoids a redundant
# conversion too. Precision loss at float32 is not meaningful for
# RandomForest split decisions on these feature ranges.
_raw_cols = pd.read_csv("CIC_IDS_2017.csv", nrows=0).columns.tolist()
_label_col = next(c for c in _raw_cols if c.strip() == "Label")
_dtype_map = {c: "float32" for c in _raw_cols if c != _label_col}

df = pd.read_csv("CIC_IDS_2017.csv", dtype=_dtype_map, low_memory=False)

print(df.columns.tolist())

df.columns = df.columns.str.strip()

columns_to_drop = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
df = df.drop(columns=[col for col in columns_to_drop if col in df.columns])

# Keep the real attack-type name (DDoS, PortScan, Heartbleed, BENIGN, ...)
# before it gets collapsed to 0/1. We need it for two things: (a) a
# stratified split that guarantees even the rarest attack types show up
# in both train and test in their correct proportion, and (b) targeted
# oversampling of only the rare attack types, not everything.
attack_type = df["Label"].astype(str).str.strip()

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
attack_type = attack_type.loc[df.index]  # keep aligned with dropna

df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

print("Dataset shape after cleaning:", df.shape)
print("Binary class distribution:")
print(df["Label"].value_counts())
print("\nAttack-type distribution:")
print(attack_type.value_counts())

# =========================
# Feature / label split
# =========================
X = df.drop("Label", axis=1)
y = df["Label"]

# =========================
# Train-test split
# =========================
# Stratify on the ORIGINAL attack-type label, not just the binary one.
# Binary stratify only guarantees the overall attack/benign ratio is
# preserved - it says nothing about whether Heartbleed's ~11 rows end
# up split sensibly between train and test. Multi-class stratify here
# guarantees every attack type is represented proportionally in both.
try:
    X_train, X_test, y_train, y_test, type_train, type_test = train_test_split(
        X, y, attack_type,
        test_size=0.2,
        random_state=42,
        stratify=attack_type
    )
except ValueError as e:
    # sklearn requires every stratify class to have at least 2 members.
    # If some ultra-rare attack type has only 1 row in the whole
    # dataset, multi-class stratify isn't possible - fall back to
    # binary stratify rather than crashing the run.
    print(f"\n⚠️  Falling back to binary stratify: {e}")
    X_train, X_test, y_train, y_test, type_train, type_test = train_test_split(
        X, y, attack_type,
        test_size=0.2,
        random_state=42,
        stratify=y
    )

# =========================
# Feature scaling
# =========================
# Fit the scaler on the REAL (pre-oversampling) training distribution.
# Oversampling happens after scaling, on the scaled values, so the
# scaler itself isn't skewed toward whatever we duplicate.
scaler = StandardScaler()
X_train_scaled = pd.DataFrame(
    scaler.fit_transform(X_train), columns=X_train.columns, index=X_train.index
)
X_test_scaled = scaler.transform(X_test)

# =========================
# Oversample rare attack types (training set only)
# =========================
# Plain duplication-with-replacement, not SMOTE: several attack types in
# CIC-IDS2017 (Heartbleed, Infiltration, Web Attack - Sql Injection) have
# single-digit-to-low-double-digit row counts in the TRAINING split.
# SMOTE's k-nearest-neighbor interpolation needs more neighbors than
# that to work at all, and duplication is easier to justify and explain
# in a methodology write-up.
rng = np.random.RandomState(42)
oversampled_frames = [X_train_scaled]
oversampled_labels = [y_train]

for label in type_train.unique():
    if label.upper() == "BENIGN":
        continue
    mask = (type_train == label).values
    count = int(mask.sum())
    if count == 0 or count >= MIN_TRAIN_SAMPLES_PER_ATTACK_TYPE:
        continue
    subset_X = X_train_scaled[mask]
    subset_y = y_train[mask]
    extra_needed = MIN_TRAIN_SAMPLES_PER_ATTACK_TYPE - count
    sample_idx = rng.choice(subset_X.index, size=extra_needed, replace=True)
    oversampled_frames.append(subset_X.loc[sample_idx])
    oversampled_labels.append(subset_y.loc[sample_idx])
    print(f"  Oversampled '{label}': {count} -> {MIN_TRAIN_SAMPLES_PER_ATTACK_TYPE} rows")

X_train_final = pd.concat(oversampled_frames, axis=0)
y_train_final = pd.concat(oversampled_labels, axis=0)

# Shuffle - otherwise the oversampled rows are all clumped at the end,
# which doesn't matter for RandomForest (row order is irrelevant to it)
# but is good hygiene in case this ever feeds a batch/online learner.
shuffle_idx = rng.permutation(len(X_train_final))
X_train_final = X_train_final.iloc[shuffle_idx]
y_train_final = y_train_final.iloc[shuffle_idx]

print(f"\nTraining set size before oversampling: {len(X_train_scaled)}")
print(f"Training set size after oversampling:  {len(X_train_final)}")

# =========================
# Model with class imbalance handling
# =========================
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train_final, y_train_final)

# =========================
# Evaluation (on real, untouched, held-out test data only)
# =========================
y_pred = model.predict(X_test_scaled)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\nOverall Performance Metrics (binary, on held-out test set):")
print("Accuracy:", accuracy)
print("Precision:", precision)
print("Recall:", recall)
print("F1-score:", f1)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# =========================
# Recall broken down by attack type (the number that actually answers
# "did oversampling help the rare attack types", not just the blended
# binary number above)
# =========================
print("\nRecall by attack type (held-out test set):")
for label in sorted(type_test.unique()):
    if label.upper() == "BENIGN":
        continue
    mask = (type_test == label).values
    total = int(mask.sum())
    if total == 0:
        continue
    detected = int(y_pred[mask].sum())
    print(f"  {label:30s} {detected:>6d} / {total:<6d}  recall={detected/total:.3f}")

# =========================
# Feature Importance Plot
# =========================
importances = model.feature_importances_
feature_names = X.columns

indices = np.argsort(importances)[::-1][:15]

plt.figure(figsize=(10, 6))
plt.title("Top 15 Feature Importances for AI-Based IDS")
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

# =========================
# Export the genuine held-out test set (raw, unscaled features + real
# attack-type label) so the live API's /detect/evaluate, /stats/confusion
# and /stats/attack-type-performance can be run against data this model
# has truly never seen - no separate export_holdout.py step needed
# anymore, this is now the single source of truth for the split.
# =========================
holdout = X_test.copy()
holdout["Label"] = type_test.values
holdout.to_csv("test_holdout.csv", index=False)
print(f"\n✅ test_holdout.csv written: {len(holdout)} rows (never used in training)")

print("\n✅ Final model, scaler, and feature list saved successfully.")
