# Training locally (full accuracy, no sandbox memory limits)

The model in this repo was trained in a resource-constrained sandbox
(~4GB RAM), which forced small dataset caps and a size-constrained
RandomForest to keep it deployable. Your local machine almost
certainly has more RAM - this doc walks through training the
most accurate version there, then dropping the result straight into
this repo.

## 1. Requirements

```bash
pip install pandas numpy scikit-learn joblib matplotlib
```

## 2. Put your dataset files here

In this `model/` folder (same folder as the two scripts below), place:

- `CIC_IDS_2017.csv` - the merged 8-day CIC-IDS2017 file (from `merge_cic_ids2017.py`, if you don't already have it)
- `NetBIOS.csv`, `Portmap.csv`, `DrDoS_NetBIOS.csv`, `DrDoS_DNS.csv`, `LDAP.csv` - CICDDoS2019
- `CICFlowMeter_out.csv` - UNSW-NB15, re-extracted via CICFlowMeter

You don't need all of them - `merge_multi_dataset.py` skips anything
it can't find and tells you what it skipped. It also accepts a
`<name>-compressed.zip` in place of any `<name>.csv` and unzips it on
the fly, so you don't have to manually extract everything first.

## 3. Merge

```bash
cd model
python merge_multi_dataset.py
```

This overwrites `CIC_IDS_2017.csv` with the combined dataset (back up
the original first if you want to keep the CIC-IDS2017-only version
separately). Open the script first if you want to raise the caps
further - `CICDDOS_ATTACK_CAP`, `UNSW_ATTACK_CAP`, `UNSW_BENIGN_CAP`
are all plain constants near the top, currently set to values that
were generous for the sandbox this was developed in but conservative
for most local machines.

## 4. Train

```bash
python train_model.py
```

Reads the merged `CIC_IDS_2017.csv`, trains, and writes these files
directly into this same folder - exactly where the backend already
expects them, so there's no copying step:

- `ids_model.pkl`, `scaler.pkl`, `feature_columns.pkl`, `class_labels.pkl`
- `test_holdout.csv` - genuine held-out test data, used by `/model/performance` and `/simulate`
- `feature_importances.png`

Watch the console output - it prints real accuracy/precision/recall/F1
per class, the confusion matrix, and recall by original attack-type
label. That's your thesis evidence; save the console log too (e.g.
`python train_model.py | tee train_run_log.txt`).

## 5. Check the model size before deploying

```bash
ls -la ids_model.pkl
```

- **Fits your deploy target** (e.g. under ~100MB for Render's free
  tier, accounting for everything else already loaded) -> you're done,
  just redeploy.
- **Too large** -> either upgrade your Render plan to match, or open
  `train_model.py` and change `PRESET = "ACCURATE"` to
  `PRESET = "DEPLOYABLE"` near the top, then retrain. That preset's
  real, measured cost is documented right next to it in the script -
  it trades away precision specifically on the smallest/hardest
  classes (Backdoor, Analysis, Shellcode, Botnet), not the
  well-established ones (DDoS, BruteForce, WebAttack, DoS stay ~97%+
  either way).

## 6. Ship it

Commit the new `.pkl`/`.csv`/`.png` files in `model/` and redeploy to
Render as usual - `main.py` picks up whatever's in this folder at
startup, no code changes needed.
