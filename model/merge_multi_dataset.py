"""
Builds CIC_IDS_2017.csv (the file train_model.py reads) by combining
CIC-IDS2017 with CICDDoS2019 and UNSW-NB15 attack files, rather than
CIC-IDS2017 alone. This is the reproducible version of a merge done
interactively in a memory-constrained sandbox - written for a local
machine with more RAM, so the caps below default much higher than what
that sandbox could handle.

Why CICDDoS2019 works without feature-engineering changes: its
per-attack CSVs (NetBIOS.csv, Portmap.csv, LDAP.csv, ...) are extracted
with the SAME CICFlowMeter tool as CIC-IDS2017, so all 78 feature
columns match by name exactly - only extra identifier columns (Flow
ID, Source/Destination IP, Source Port, Protocol, Timestamp, Unnamed:
0, SimillarHTTP, Inbound) need dropping.

UNSW-NB15 (CICFlowMeter_out.csv) is different: it's UNSW-NB15's raw
traffic re-extracted through CICFlowMeter by a third party, using a
NEWER CICFlowMeter column-naming convention (e.g. "Total Fwd Packet"
instead of "Total Fwd Packets", "FWD Init Win Bytes" instead of
"Init_Win_bytes_forward"). UNSW_RENAME_MAP below was built and
VERIFIED programmatically against feature_columns.pkl (every one of
our 78 features confirmed present under its renamed form - see the
project's chat history for the verification) - not guessed.

Usage:
    python merge_multi_dataset.py
Expects, in the current directory:
    CIC_IDS_2017.csv       - from merge_cic_ids2017.py (the 8 CIC-IDS2017 days)
    NetBIOS.csv            - CICDDoS2019 Day2
    Portmap.csv            - CICDDoS2019 Day2
    DrDoS_NetBIOS.csv      - CICDDoS2019 Day1
    DrDoS_DNS.csv          - CICDDoS2019 Day1
    LDAP.csv               - CICDDoS2019 Day2 (contains LDAP + NetBIOS mixed)
    CICFlowMeter_out.csv   - UNSW-NB15, re-extracted via CICFlowMeter
Any file not present is skipped with a message - you don't need all of
them to run this.

Writes CIC_IDS_2017.csv back out, overwriting it with the combined set
(back up the CIC-IDS2017-only version first if you want to keep both).
"""

import pandas as pd
import numpy as np
import joblib
import os
import subprocess

RANDOM_STATE = 42

# ============================================================
# Tunable caps - raise or lower based on your machine's RAM.
# These are generous defaults for a local machine (not the ~4GB
# sandbox these scripts were originally developed in). Every class
# below its cap is kept in FULL - only classes that exceed the cap get
# randomly subsampled. Rare classes (Worms, Analysis, Backdoor, ...)
# are always far under any of these caps, so they're always kept whole
# regardless of what you set here.
# ============================================================
CICDDOS_ATTACK_CAP = 100000   # per attack label, per CICDDoS2019 file (was 40,000 in the sandbox)
UNSW_ATTACK_CAP = 100000      # per attack category (UNSW's largest, Exploits, is ~31k - this keeps ALL of them)
UNSW_BENIGN_CAP = 300000      # UNSW's own BENIGN pool is 3.45M rows - CIC-IDS2017 already contributes plenty of BENIGN

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

# Verified against feature_columns.pkl (see model/merge_multi_dataset.py
# docstring). Only needed for CICFlowMeter_out.csv (UNSW-NB15).
UNSW_RENAME_MAP = {
    'Dst Port': 'Destination Port',
    'Total Fwd Packet': 'Total Fwd Packets',
    'Total Bwd packets': 'Total Backward Packets',
    'Total Length of Fwd Packet': 'Total Length of Fwd Packets',
    'Total Length of Bwd Packet': 'Total Length of Bwd Packets',
    'Packet Length Min': 'Min Packet Length',
    'Packet Length Max': 'Max Packet Length',
    'CWR Flag Count': 'CWE Flag Count',
    'Fwd Segment Size Avg': 'Avg Fwd Segment Size',
    'Bwd Segment Size Avg': 'Avg Bwd Segment Size',
    'Fwd Bytes/Bulk Avg': 'Fwd Avg Bytes/Bulk',
    'Fwd Packet/Bulk Avg': 'Fwd Avg Packets/Bulk',
    'Fwd Bulk Rate Avg': 'Fwd Avg Bulk Rate',
    'Bwd Bytes/Bulk Avg': 'Bwd Avg Bytes/Bulk',
    'Bwd Packet/Bulk Avg': 'Bwd Avg Packets/Bulk',
    'Bwd Bulk Rate Avg': 'Bwd Avg Bulk Rate',
    'FWD Init Win Bytes': 'Init_Win_bytes_forward',
    'Bwd Init Win Bytes': 'Init_Win_bytes_backward',
    'Fwd Act Data Pkts': 'act_data_pkt_fwd',
    'Fwd Seg Size Min': 'min_seg_size_forward',
}

# UNSW-NB15 categories that fold into existing buckets rather than
# becoming their own class - kept in sync with LABEL_TO_BUCKET in
# train_model.py and backend/app/main.py.
UNSW_BENIGN_LABEL = "Benign"     # gets rewritten to "BENIGN" to match CIC-IDS2017's convention


def _open_csv(path, **kwargs):
    """Reads path directly, or transparently unzips it first if a
    same-named .zip exists instead (path.csv -> path-compressed.zip
    containing path.csv), so you don't have to unzip everything by hand."""
    if os.path.isfile(path):
        return pd.read_csv(path, **kwargs)
    zip_guess = path.replace(".csv", "-compressed.zip")
    if os.path.isfile(zip_guess):
        proc = subprocess.Popen(["unzip", "-p", zip_guess], stdout=subprocess.PIPE)
        return pd.read_csv(proc.stdout, **kwargs)
    return None


def sample_cicddos_source(path, attack_labels, feature_cols, cap, rng):
    """Streams a CICDDoS2019 CSV, keeps all BENIGN rows plus up to `cap`
    randomly-sampled rows PER label in attack_labels, restricted to our
    exact feature schema."""
    keep_cols = feature_cols + ["Label"]

    counts = {l: 0 for l in attack_labels}
    header_chunk = _open_csv(path, usecols=[" Label"], chunksize=300000)
    if header_chunk is None:
        return None
    for chunk in header_chunk:
        vc = chunk[" Label"].value_counts()
        for l in attack_labels:
            counts[l] += int(vc.get(l, 0))
    rates = {l: (min(1.0, cap / counts[l]) if counts[l] else 0.0) for l in attack_labels}
    print(f"{path}: counts={counts}, sampling rates={rates}")

    frames = []
    for chunk in _open_csv(path, chunksize=300000, low_memory=False):
        chunk.columns = chunk.columns.str.strip()
        lbl = chunk["Label"]
        rnd = rng.random_sample(len(chunk))
        keep_rate = lbl.map(lambda l: rates.get(l, 1.0 if l == "BENIGN" else 0.0)).values
        keep_mask = rnd < keep_rate
        frames.append(chunk[keep_mask][keep_cols])

    return pd.concat(frames, axis=0, ignore_index=True)


def sample_unsw_source(path, feature_cols, attack_cap, benign_cap, rng):
    """Streams CICFlowMeter_out.csv (UNSW-NB15), renaming columns to our
    schema, capping BENIGN but keeping every attack category up to
    attack_cap (which defaults high enough to keep ALL of them - the
    largest, Exploits, is only ~31k rows)."""
    keep_cols = feature_cols + ["Label"]

    header_chunk = _open_csv(path, usecols=["Label"], chunksize=400000)
    if header_chunk is None:
        return None
    counts = {}
    for chunk in header_chunk:
        vc = chunk["Label"].value_counts()
        for l, v in vc.items():
            counts[l] = counts.get(l, 0) + int(v)
    print(f"{path}: counts={counts}")

    caps = {l: (benign_cap if l == UNSW_BENIGN_LABEL else attack_cap) for l in counts}
    rates = {l: (min(1.0, caps[l] / counts[l]) if counts[l] else 0.0) for l in counts}
    print(f"{path}: sampling rates={rates}")

    frames = []
    for chunk in _open_csv(path, chunksize=300000, low_memory=False):
        chunk = chunk.rename(columns=UNSW_RENAME_MAP)
        chunk["Fwd Header Length.1"] = chunk["Fwd Header Length"]  # tool-duplicate column
        lbl = chunk["Label"]
        rnd = rng.random_sample(len(chunk))
        keep_rate = lbl.map(lambda l: rates.get(l, 0.0)).values
        keep_mask = rnd < keep_rate
        kept = chunk[keep_mask][keep_cols].copy()
        kept["Label"] = kept["Label"].replace({UNSW_BENIGN_LABEL: "BENIGN"})
        frames.append(kept)

    return pd.concat(frames, axis=0, ignore_index=True)


def main():
    feature_cols = joblib.load("feature_columns.pkl")
    rng = np.random.RandomState(RANDOM_STATE)

    # dtype optimization avoids a transient float64 memory spike on the
    # full CIC-IDS2017 file (~1GB, 2.8M rows) - same technique already
    # used in train_model.py.
    raw_cols = pd.read_csv("CIC_IDS_2017.csv", nrows=0).columns.tolist()
    label_col_raw = next(c for c in raw_cols if c.strip() == "Label")
    dtype_map = {c: "float32" for c in raw_cols if c != label_col_raw}
    base = pd.read_csv("CIC_IDS_2017.csv", dtype=dtype_map, low_memory=False)
    base.columns = base.columns.str.strip()
    base = base[feature_cols + ["Label"]]
    print(f"CIC-IDS2017 base: {len(base)} rows")

    parts = [base]

    for source in ADDITIONAL_SOURCES:
        sample = sample_cicddos_source(source["file"], source["attack_labels"], feature_cols, CICDDOS_ATTACK_CAP, rng)
        if sample is None:
            print(f"Skipping {source['file']} - not found (looked for the .csv and a -compressed.zip)")
            continue
        print(f"{source['file']}: added {len(sample)} rows")
        parts.append(sample)

    unsw_sample = sample_unsw_source("CICFlowMeter_out.csv", feature_cols, UNSW_ATTACK_CAP, UNSW_BENIGN_CAP, rng)
    if unsw_sample is None:
        print("Skipping CICFlowMeter_out.csv - not found")
    else:
        print(f"CICFlowMeter_out.csv: added {len(unsw_sample)} rows")
        parts.append(unsw_sample)

    combined = pd.concat(parts, axis=0, ignore_index=True)
    print(f"\nCombined total: {len(combined)} rows")
    print(combined["Label"].value_counts())

    combined.to_csv("CIC_IDS_2017.csv", index=False)
    print("\nWrote combined CIC_IDS_2017.csv - now run train_model.py")


if __name__ == "__main__":
    main()
