import numpy as np
import pandas as pd

DROP_COLS = [
    "Flow ID", "Source IP", "Destination IP", "Timestamp"
]

def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    # CIC-IDS2017 CSVs ship with leading/trailing spaces in column headers
    # (e.g. " Destination Port"). feature_columns.pkl was saved from a
    # stripped DataFrame during training, so every prediction call must
    # strip here too, or reindex() in model.py silently zero-fills every
    # column and the model ends up scoring an all-zero vector.
    df.columns = df.columns.str.strip()

    # Drop non-numeric / identifier columns if present
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns], errors="ignore")

    # Replace inf and NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    return df
