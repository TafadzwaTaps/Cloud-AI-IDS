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

# Maps a CICDDoS2019 source file to the attack label(s) present in that
# file's Label column. Most files contain one attack type, but some
# (e.g. LDAP.csv) contain a second attack's traffic mixed in - CICDDoS2019's
# capture days sometimes overlapped with the tail of a previous attack.
# Add more entries here as you bring in more CICDDoS2019 files.
ADDITIONAL_SOURCES = [
    {"file": "NetBIOS.csv", "attack_labels": ["NetBIOS"]},                 # Day2
    {"file": "Portmap.csv", "attack_labels": ["Portmap"]},                 # Day2
    {"file": "DrDoS_NetBIOS.csv", "attack_labels": ["DrDoS_NetBIOS"]},     # Day1
    {"file": "DrDoS_DNS.csv", "attack_labels": ["DrDoS_DNS"]},             # Day1
    {"file": "LDAP.csv", "attack_labels": ["LDAP", "NetBIOS"]},            # Day2 - contains both
    # {"file": "MSSQL.csv", "attack_labels": ["MSSQL"]},
    # {"file": "Syn.csv", "attack_labels": ["Syn"]},
]


def sample_source(path, attack_labels, feature_cols, cap, rng):
    """Streams a CICDDoS2019 CSV, keeps all BENIGN rows plus up to `cap`
    randomly-sampled rows PER label in attack_labels, restricted to our
    exact feature schema."""
    keep_cols = feature_cols + ["Label"]

    # First pass: count each target label (streamed - narrow column,
    # never holds the whole file in memory).
    counts = {l: 0 for l in attack_labels}
    for chunk in pd.read_csv(path, usecols=[" Label"], chunksize=300000):
        vc = chunk[" Label"].value_counts()
        for l in attack_labels:
            counts[l] += int(vc.get(l, 0))
    rates = {l: (min(1.0, cap / counts[l]) if counts[l] else 0.0) for l in attack_labels}
    print(f"{path}: counts={counts}, sampling rates={rates}")

    frames = []
    for chunk in pd.read_csv(path, chunksize=300000, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        lbl = chunk["Label"]
        rnd = rng.random_sample(len(chunk))
        keep_rate = lbl.map(lambda l: rates.get(l, 1.0 if l == "BENIGN" else 0.0)).values
        keep_mask = rnd < keep_rate
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
        sample = sample_source(source["file"], source["attack_labels"], feature_cols, CAP_PER_ATTACK_SOURCE, rng)
        print(f"{source['file']}: added {len(sample)} rows")
        parts.append(sample)

    combined = pd.concat(parts, axis=0, ignore_index=True)
    print(f"\nCombined total: {len(combined)} rows")
    print(combined["Label"].value_counts())

    combined.to_csv("CIC_IDS_2017.csv", index=False)
    print("\nWrote combined CIC_IDS_2017.csv - now run train_model.py")


if __name__ == "__main__":
    main()
