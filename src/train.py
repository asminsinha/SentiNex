import os
import pickle
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score
from sklearn.ensemble import RandomForestClassifier
try:
    import lightgbm as lgb
except ImportError:
    lgb = None
import xgboost as xgb
import tensorflow as tf

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DATA_PATH = os.path.join(BASE_DIR, "data", "processed", "unsw_processed.npz")
MODEL_DIR = os.path.join(BASE_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

def load_data():
    data = np.load(PROCESSED_DATA_PATH)
    X, y = data['X'], data['y']
    return train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

def train_mlp(X_train, y_train, X_test, y_test):
    print("\n[+] Training Deep Learning Neural Network (MLP)...")
    mlp = tf.keras.Sequential([
        tf.keras.layers.Input(shape=(X_train.shape[1],)),
        tf.keras.layers.Dense(128, activation='relu'),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.3),
        tf.keras.layers.Dense(64, activation='relu'),
        tf.keras.layers.BatchNormalization(),
        tf.keras.layers.Dropout(0.2),
        tf.keras.layers.Dense(32, activation='relu'),
        tf.keras.layers.Dense(1, activation='sigmoid')
    ])
    mlp.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
    mlp.fit(X_train, y_train, epochs=5, batch_size=512, validation_data=(X_test, y_test), verbose=1)
    mlp.save(os.path.join(MODEL_DIR, "sentinex_mlp.keras"))
    print("[+] Saved sentinex_mlp.keras successfully!")
    return mlp

def train_all():
    X_train, X_test, y_train, y_test = load_data()

    # 1. Random Forest
    print("\n[+] Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    with open(os.path.join(MODEL_DIR, "sentinex_rf.pkl"), "wb") as f:
        pickle.dump(rf, f)

    # 2. XGBoost
    print("\n[+] Training XGBoost...")
    xgb_model = xgb.XGBClassifier(n_estimators=100, random_state=42, n_jobs=-1, eval_metric='logloss')
    xgb_model.fit(X_train, y_train)
    xgb_auc = roc_auc_score(y_test, xgb_model.predict_proba(X_test)[:, 1])
    print(f"XGBoost ROC-AUC: {xgb_auc:.4f}")
    with open(os.path.join(MODEL_DIR, "sentinex_xgb.pkl"), "wb") as f:
        pickle.dump(xgb_model, f)

    # 3. Deep Learning MLP (Keras)
    train_mlp(X_train, y_train, X_test, y_test)

    print("\n[SUCCESS] All Models (RF, XGBoost, Deep Learning MLP) successfully trained!")

if __name__ == "__main__":
    train_all()