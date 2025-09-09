# train_ids_model.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib

# Load your dataset
df = pd.read_csv("qkd_flows_labeled.csv")

# Feature columns
features = ["packet_count", "byte_count", "duration"]
X = df[features]
y = df["label"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train Random Forest
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print(classification_report(y_test, y_pred))

# Save model
joblib.dump(model, "qkd_ids_model.pkl")
print("[✓] Model saved as qkd_ids_model.pkl")
