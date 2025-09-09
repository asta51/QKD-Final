import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, accuracy_score
import joblib

# === 1. Load preprocessed dataset ===
print("[INFO] Loading preprocessed NSL-KDD dataset...")
train_df = pd.read_csv("nslkdd_train.csv")
test_df = pd.read_csv("nslkdd_test.csv")

# Last column is label
X_train = train_df.iloc[:, :-1].values
y_train = train_df.iloc[:, -1].values
X_test = test_df.iloc[:, :-1].values
y_test = test_df.iloc[:, -1].values

# Binary labels: 1 = attack, 0 = normal
y_test_binary = (y_test != 0).astype(int)

# === 2. Train Isolation Forest ===
contamination = 0.5  # initial contamination rate
print(f"[INFO] Using contamination rate: {contamination:.4f}")
iso = IsolationForest(
    n_estimators=200,
    max_samples="auto",
    contamination=contamination,
    random_state=42,
    n_jobs=-1
)
print("[INFO] Training tuned Isolation Forest...")
iso.fit(X_train)

# Save model (optional)
joblib.dump(iso, "isolation_forest_model.joblib")

# === 3. Score test set ===
scores = iso.decision_function(X_test)  # higher = more normal
print(f"[INFO] Score range: {scores.min():.4f} to {scores.max():.4f}")

# === 4. Try multiple thresholds ===
percentiles = [50, 55, 60, 65, 70, 75, 80]
results = []

for p in percentiles:
    threshold = np.percentile(scores, p)
    y_pred_binary = (scores < threshold).astype(int)  # 1 = attack

    acc = accuracy_score(y_test_binary, y_pred_binary)
    report = classification_report(y_test_binary, y_pred_binary, digits=4, output_dict=True)

    results.append({
        "percentile": p,
        "threshold": threshold,
        "accuracy": acc,
        "precision_attack": report['1']['precision'],
        "recall_attack": report['1']['recall'],
        "f1_attack": report['1']['f1-score']
    })

# === 5. Display summary ===
print("\n[RESULT] Precision–Recall trade-off for attacks (label=1):")
print(f"{'Percentile':>10} {'Acc':>8} {'Prec':>8} {'Recall':>8} {'F1':>8}")
for r in results:
    print(f"{r['percentile']:>10} {r['accuracy']:.4f} {r['precision_attack']:.4f} {r['recall_attack']:.4f} {r['f1_attack']:.4f}")

# === 6. Show best report for your chosen threshold ===
best_p = 60  # example choice: higher recall
best_threshold = np.percentile(scores, best_p)
y_pred_best = (scores < best_threshold).astype(int)
print(f"\n[INFO] Classification report at {best_p}th percentile threshold:")
print(classification_report(y_test_binary, y_pred_best, digits=4))
