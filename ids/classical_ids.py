# file: classical_ids.py
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# Load processed data
train_data = np.load("ids/data/train.npy")
test_data = np.load("ids/data/test.npy")

# Split features/labels
X_train, y_train = train_data[:, :-1], train_data[:, -1]
X_test, y_test = test_data[:, :-1], test_data[:, -1]

# Train a classical baseline model
print("[INFO] Training RandomForest classifier...")
clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
clf.fit(X_train, y_train)

# Predict
y_pred = clf.predict(X_test)

# Evaluate
acc = accuracy_score(y_test, y_pred)
print(f"[RESULT] Accuracy: {acc:.4f}")
print(classification_report(y_test, y_pred))
