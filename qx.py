# train_ids_model_visual.py
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
import joblib

# === Load dataset ===
df = pd.read_csv("qkd_flows_labeled.csv")

# === Feature columns ===
features = ["packet_count", "byte_count", "duration"]
X = df[features]
y = df["label"]

# === Train-test split ===
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# === Train model ===
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# === Predictions ===
y_pred = model.predict(X_test)

# === Evaluation Report ===
print("\n=== Classification Report ===")
print(classification_report(y_test, y_pred))

# === Confusion Matrix ===
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6,5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=["Benign","Attack"], yticklabels=["Benign","Attack"])
plt.title("Confusion Matrix")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.show()

# === Feature Importance ===
importances = model.feature_importances_
plt.figure(figsize=(6,4))
sns.barplot(x=features, y=importances)
plt.title("Feature Importance (Random Forest)")
plt.ylabel("Importance Score")
plt.show()

# === Data Distribution ===
plt.figure(figsize=(6,4))
sns.countplot(x="label", data=df, palette="Set2")
plt.title("Distribution of Flows (Benign vs Attack)")
plt.xticks([0,1], ["Benign","Attack"])
plt.show()

# === Save model ===
joblib.dump(model, "qkd_ids_model.pkl")
print("\n[✓] Model saved as qkd_ids_model.pkl")
