import os
import pickle
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler, LabelEncoder
from imblearn.over_sampling import SMOTE

RAW_DATA_DIR = os.path.join("data", "raw")
PROCESSED_DATA_DIR = os.path.join("data", "processed")
MODEL_DIR = os.path.join("models")

os.makedirs(PROCESSED_DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

def preprocess_unsw():
    print("[*] Processing UNSW-NB15 Dataset...")
    train_path = os.path.join(RAW_DATA_DIR, "UNSW_NB15_training-set.csv")
    test_path = os.path.join(RAW_DATA_DIR, "UNSW_NB15_testing-set.csv")

    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)
    df = pd.concat([df_train, df_test], ignore_index=True)

    df.columns = df.columns.str.strip()
    drop_cols = ['id', 'attack_cat']
    df = df.drop(columns=[c for c in drop_cols if c in df.columns])

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    cat_cols = df.select_dtypes(include=['object', 'string']).columns
    for col in cat_cols:
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))

    X = df.drop(columns=['label'])
    y = df['label'].astype(int)

    return X, y, X.columns.tolist()

def preprocess_ids2018():
    print("[*] Processing CSE-CIC-IDS2018 Sample Datasets...")
    files = ["02-14-2018.csv", "02-15-2018.csv"]
    dfs = []
    
    for f in files:
        file_path = os.path.join(RAW_DATA_DIR, f)
        if os.path.exists(file_path):
            print(f"    - Reading {f}...")
            # Sample up to 100k rows per file to keep memory within limit
            df_temp = pd.read_csv(file_path, low_memory=False, nrows=100000)
            dfs.append(df_temp)

    if not dfs:
        return None, None, None

    df = pd.concat(dfs, ignore_index=True)
    df.columns = df.columns.str.strip()

    # Drop non-predictive metadata columns
    drop_cols = ['Timestamp', 'Flow ID', 'Src IP', 'Dst IP']
    df = df.drop(columns=[c for c in drop_cols if c in df.columns])

    # Convert binary targets
    df['Label'] = df['Label'].astype(str).apply(lambda x: 0 if x.strip().lower() == 'benign' else 1)

    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)

    # Coerce object types to numeric where possible
    for col in df.columns:
        if col != 'Label' and df[col].dtype == 'object':
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)

    X = df.drop(columns=['Label'])
    y = df['Label'].astype(int)

    return X, y, X.columns.tolist()

def run_pipeline():
    # Process UNSW-NB15 as primary baseline array
    X, y, feature_names = preprocess_unsw()

    print(f"[*] Raw UNSW Dataset Shape: {X.shape}")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    with open(os.path.join(MODEL_DIR, "scaler.pkl"), "wb") as f:
        pickle.dump(scaler, f)
    with open(os.path.join(MODEL_DIR, "feature_names.pkl"), "wb") as f:
        pickle.dump(feature_names, f)

    print("[*] Synthesizing minority attack samples via SMOTE...")
    smote = SMOTE(random_state=42)
    X_resampled, y_resampled = smote.fit_resample(X_scaled, y)

    print(f"[+] Post-SMOTE Dataset Shape: {X_resampled.shape}")

    np.savez_compressed(
        os.path.join(PROCESSED_DATA_DIR, "unsw_processed.npz"),
        X=X_resampled,
        y=y_resampled
    )
    
    # Also process and save IDS2018 artifact separately
    X_ids, y_ids, ids_features = preprocess_ids2018()
    if X_ids is not None:
        scaler_ids = StandardScaler()
        X_ids_scaled = scaler_ids.fit_transform(X_ids)
        np.savez_compressed(
            os.path.join(PROCESSED_DATA_DIR, "ids2018_processed.npz"),
            X=X_ids_scaled,
            y=y_ids.values
        )
        with open(os.path.join(MODEL_DIR, "ids2018_features.pkl"), "wb") as f:
            pickle.dump(ids_features, f)
        print(f"[+] IDS2018 sampled dataset saved ({X_ids.shape[0]} rows).")

    print("[SUCCESS] Data Preprocessing Complete!")

if __name__ == "__main__":
    run_pipeline()