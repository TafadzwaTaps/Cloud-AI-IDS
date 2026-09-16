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
# Load merged dataset
# =========================
df = pd.read_csv("CIC_IDS_2017.csv")

# Inspect columns (run once, then you can comment this out)
print(df.columns.tolist())

# Remove leading/trailing spaces from column names
df.columns = df.columns.str.strip()


# Safely drop irrelevant columns (if present)
columns_to_drop = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
df = df.drop(columns=[col for col in columns_to_drop if col in df.columns])

# Convert labels to binary
df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Drop rows with missing values
df.dropna(inplace=True)

print("Dataset shape after cleaning:", df.shape)

print("Class distribution:")
print(df["Label"].value_counts())

# =========================
# Feature / label split
# =========================
X = df.drop("Label", axis=1)
y = df["Label"]

# =========================
# Train-test split
# =========================
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# =========================
# Feature scaling
# =========================
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# =========================
# Model with class imbalance handling
# =========================
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)

model.fit(X_train_scaled, y_train)

# =========================
# Evaluation
# =========================
y_pred = model.predict(X_test_scaled)

accuracy = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred)
recall = recall_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred)

print("\nPerformance Metrics:")
print("Accuracy:", accuracy)
print("Precision:", precision)
print("Recall:", recall)
print("F1-score:", f1)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# =========================
# Feature Importance Plot
# =========================
importances = model.feature_importances_
feature_names = X.columns

indices = np.argsort(importances)[::-1][:15]  # Top 15 features

plt.figure(figsize=(10, 6))
plt.title("Top 15 Feature Importances for AI-Based IDS")
plt.bar(range(len(indices)), importances[indices])
plt.xticks(range(len(indices)), feature_names[indices], rotation=90)
plt.tight_layout()
plt.show()


FEATURE_COLUMNS = X.columns.tolist()
joblib.dump(FEATURE_COLUMNS, "feature_columns.pkl")

# =========================
# Save final model & scaler
# =========================
joblib.dump(model, "ids_model.pkl")
joblib.dump(scaler, "scaler.pkl")


print("\n✅ Final model and scaler saved successfully.")
