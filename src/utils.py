from typing import Tuple
import pandas as pd
import numpy as np

def ensure_schema(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize column names and coerce expected types."""
    df = df.copy()
    # standardize columns
    rename_map = {
        "Year": "year",
        "Industry": "industry",
        "AttackVector": "attack_vector",
        "Attack Vector": "attack_vector",
        "Records": "records_exposed",
        "RecordsAffected": "records_exposed",
        "Records Exposed": "records_exposed",
        "OrgSize": "org_size",
        "Org Size": "org_size",
        "Country": "country"
    }
    df.columns = [c.strip() for c in df.columns]
    df = df.rename(columns=rename_map)

    # required columns
    required = ["year", "industry", "attack_vector", "records_exposed"]
    for col in required:
        if col not in df.columns:
            df[col] = np.nan

    # coerce types
    df["year"] = pd.to_numeric(df["year"], errors="coerce").astype("Int64")
    df["records_exposed"] = pd.to_numeric(df["records_exposed"], errors="coerce").astype("Int64")
    for col in ["industry", "attack_vector", "org_size", "country"]:
        if col in df.columns:
            df[col] = df[col].astype("string").str.strip()

    return df

def classify_severity(records: int) -> str:
    """Map count of exposed records to a categorical severity label.
    Thresholds can be tuned; here we use a simple, interpretable scale.
    """
    if pd.isna(records):
        return "Unknown"
    r = int(records)
    if r < 10_000:
        return "Low"
    elif r < 100_000:
        return "Medium"
    elif r < 1_000_000:
        return "High"
    else:
        return "Critical"
