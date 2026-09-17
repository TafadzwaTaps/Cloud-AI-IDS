"""
Builds CIC_IDS_2017.csv (the file train_model.py reads) by combining
CIC-IDS2017 with CICDDoS2019 attack files, rather than CIC-IDS2017
alone. This is the reproducible version of a merge done interactively
once - re-run this whenever you add another compatible-schema source.

Why this works without feature-engineering changes: CICDDoS2019's
per-attack CSVs (NetBIOS.csv, Portmap.csv, LDAP.csv, MSSQL.csv, ...)
are extracted with the SAME CICFlowMeter tool as CIC-IDS2017, so all
78 feature columns match by name exactly - only extra identifier
columns (Flow ID, Source/Destination IP, Source Port, Protocol,
Timestamp, Unnamed: 0, SimillarHTTP, Inbound) need dropping, and Label
needs the same treatment as any other CIC-IDS2017 attack label.

This does NOT work for arbitrary IDS datasets - NSL-KDD, UNSW-NB15,
etc. use entirely different feature-extraction pipelines and would
need real feature-engineering work, not just a merge like this one.

Usage:
    python merge_multi_dataset.py
Expects, in the current directory:
    CIC_IDS_2017.csv   - from merge_cic_ids2017.py (the 8 CIC-IDS2017 days)
    NetBIOS.csv        - CICDDoS2019, unzipped
    Portmap.csv        - CICDDoS2019
(any of the CICDDoS2019 files can be added the same way - see ADDITIONAL_SOURCES)

Writes CIC_IDS_2017.csv back out, overwriting it with the combined set
(back up the CIC-IDS2017-only version first if you want to keep both).
"""

import pandas as pd
import numpy as np
import joblib
import os

CAP_PER_ATTACK_SOURCE = 40000  # keep each added source roughly comparable in scale
RANDOM_STATE = 42

# Maps a CICDDoS2019 source file to (its attack label in that file's
# Label column, the fine-grained name to store - usually the same).
# Add more entries here as you bring in more CICDDoS2019 files.
ADDITIONAL_SOURCES = [
    {"file": "Portmap.csv", "attack_label": "Portmap"},
    {"file": "NetBIOS.csv", "attack_label": "NetBIOS"},
    # {"file": "LDAP.csv", "attack_label": "LDAP"},
    # {"file": "MSSQL.csv", "attack_label": "MSSQL"},
    # {"file": "Syn.csv", "attack_label": "Syn"},
]


def sample_source(path, attack_label, feature_cols, cap, rng):
    """Streams a CICDDoS2019 CSV, keeps all BENIGN rows plus up to `cap`
    randomly-sampled attack rows, restricted to our exact feature schema."""
    keep_cols = feature_cols + ["Label"]
    frames = []
    total_attack_seen = 0

    # First pass: count attack rows so we know the sampling rate
    # (streamed - never holds the whole file in memory).
    total_attack = 0
    for chunk in pd.read_csv(path, usecols=[" Label"], chunksize=300000):
        total_attack += int((chunk[" Label"] == attack_label).sum())

    rate = min(1.0, cap / total_attack) if total_attack else 0.0
    print(f"{path}: {total_attack} '{attack_label}' rows found, sampling rate {rate:.4f}")

    for chunk in pd.read_csv(path, chunksize=300000, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        lbl = chunk["Label"]
        rnd = rng.random_sample(len(chunk))
        keep_mask = ((lbl == attack_label) & (rnd < rate)) | (lbl == "BENIGN")
        frames.append(chunk[keep_mask][keep_cols])

    return pd.concat(frames, axis=0, ignore_index=True)


def main():
    feature_cols = joblib.load("feature_columns.pkl")
    rng = np.random.RandomState(RANDOM_STATE)

    base = pd.read_csv("CIC_IDS_2017.csv", low_memory=False)
    base.columns = base.columns.str.strip()
    base = base[feature_cols + ["Label"]]
    print(f"CIC-IDS2017 base: {len(base)} rows")

    parts = [base]
    for source in ADDITIONAL_SOURCES:
        if not os.path.isfile(source["file"]):
            print(f"Skipping {source['file']} - not found in current directory")
            continue
        sample = sample_source(source["file"], source["attack_label"], feature_cols, CAP_PER_ATTACK_SOURCE, rng)
        print(f"{source['file']}: added {len(sample)} rows")
        parts.append(sample)

    combined = pd.concat(parts, axis=0, ignore_index=True)
    print(f"\nCombined total: {len(combined)} rows")
    print(combined["Label"].value_counts())

    combined.to_csv("CIC_IDS_2017.csv", index=False)
    print("\nWrote combined CIC_IDS_2017.csv - now run train_model.py")


if __name__ == "__main__":
    main()
