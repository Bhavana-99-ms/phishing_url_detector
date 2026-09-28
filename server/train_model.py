"""
train_model.py
---------------
Trains a phishing-URL classifier on the feature subset defined in
feature_extraction.py, using the labelled dataset in ../data.

Run:
    python3 train_model.py

Outputs (into ../model/):
    phishing_model.pkl   -> trained sklearn Pipeline (scaler + classifier)
    metrics.json         -> accuracy / precision / recall / F1 / confusion matrix
    feature_importance.png
"""

import json
import os
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score
)

from feature_extraction import FEATURE_NAMES

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(HERE, "..", "data", "phishing_features_from_raw.csv")
MODEL_DIR = os.path.join(HERE, "..", "model")
os.makedirs(MODEL_DIR, exist_ok=True)


def main():
    print(f"Loading dataset from {DATA_PATH} ...")
    df = pd.read_csv(DATA_PATH)
    print(f"Rows: {len(df)}   Columns: {list(df.columns)}")

    X = df[FEATURE_NAMES].values
    y = df["phishing"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=150,
            max_depth=16,
            min_samples_leaf=3,
            n_jobs=-1,
            random_state=42,
            class_weight="balanced",
        )),
    ])

    print("Training RandomForestClassifier ...")
    pipeline.fit(X_train, y_train)

    print("Running 5-fold cross-validation ...")
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=5, scoring="f1")
    print(f"CV F1 scores: {cv_scores}  mean={cv_scores.mean():.4f}")

    y_pred = pipeline.predict(X_test)
    y_proba = pipeline.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision": precision_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1_score": f1_score(y_test, y_pred),
        "roc_auc": roc_auc_score(y_test, y_proba),
        "cv_f1_mean": float(cv_scores.mean()),
        "cv_f1_std": float(cv_scores.std()),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "n_train": len(X_train),
        "n_test": len(X_test),
        "feature_names": FEATURE_NAMES,
    }

    print(json.dumps(metrics, indent=2))
    print(classification_report(y_test, y_pred, target_names=["legitimate", "phishing"]))

    with open(os.path.join(MODEL_DIR, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    # Feature importance plot
    importances = pipeline.named_steps["clf"].feature_importances_
    order = np.argsort(importances)[::-1]
    plt.figure(figsize=(9, 8))
    plt.barh(
        [FEATURE_NAMES[i] for i in order][::-1],
        importances[order][::-1],
    )
    plt.title("Feature importance (Random Forest)")
    plt.tight_layout()
    plt.savefig(os.path.join(MODEL_DIR, "feature_importance.png"), dpi=120)
    print("Saved feature_importance.png")

    model_path = os.path.join(MODEL_DIR, "phishing_model.pkl")
    joblib.dump({"pipeline": pipeline, "feature_names": FEATURE_NAMES}, model_path, compress=3)
    size_mb = os.path.getsize(model_path) / (1024 * 1024)
    print(f"Saved model -> {model_path}  ({size_mb:.1f} MB)")


if __name__ == "__main__":
    main()
