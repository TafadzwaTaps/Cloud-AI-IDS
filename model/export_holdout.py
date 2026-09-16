"""
Recovers the genuine held-out test set for the trained ids_model.pkl,
without retraining.

NOTE: train_model.py now writes test_holdout.csv itself as its last
step, using this exact split - you normally won't need to run this
separately. Keep this script around as a standalone recovery tool: if
you ever lose test_holdout.csv but still have CIC_IDS_2017.csv and
haven't changed the split logic in train_model.py, this reproduces the
identical held-out rows (same random_state, same stratify column, same
preprocessing order) without needing to refit the model.
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

df = pd.read_csv("CIC_IDS_2017.csv")

df.columns = df.columns.str.strip()

columns_to_drop = ["Flow ID", "Source IP", "Destination IP", "Timestamp"]
df = df.drop(columns=[c for c in columns_to_drop if c in df.columns])

original_label = df["Label"].astype(str).str.strip()

df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)
original_label = original_label.loc[df.index]

df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

X = df.drop("Label", axis=1)
y = df["Label"]

try:
    X_train, X_test, y_train, y_test, type_train, type_test = train_test_split(
        X, y, original_label,
        test_size=0.2, random_state=42, stratify=original_label
    )
except ValueError:
    X_train, X_test, y_train, y_test, type_train, type_test = train_test_split(
        X, y, original_label,
        test_size=0.2, random_state=42, stratify=y
    )

holdout = X_test.copy()
holdout["Label"] = type_test.values
holdout.to_csv("test_holdout.csv", index=False)

print(f"\n✅ test_holdout.csv written: {len(holdout)} rows")
print("These rows were never used to train ids_model.pkl / scaler.pkl.\n")
print("Attack-type composition of the held-out set:")
print(type_test.value_counts())
