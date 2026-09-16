import numpy as np
import pandas as pd

DROP_COLS = [
    "Flow ID", "Source IP", "Destination IP", "Timestamp"
]

def preprocess(df: pd.DataFrame) -> pd.DataFrame:
    # Drop non-numeric / identifier columns if present
    df = df.drop(columns=[c for c in DROP_COLS if c in df.columns], errors="ignore")

    # Replace inf and NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    return df
