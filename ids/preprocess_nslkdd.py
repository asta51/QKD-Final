import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
import urllib.request

# Data folder and file paths
DATA_DIR = "ids/data"
TRAIN_FILE = os.path.join(DATA_DIR, "KDDTrain+.txt")
TEST_FILE = os.path.join(DATA_DIR, "KDDTest+.txt")

# Create data folder if missing
os.makedirs(DATA_DIR, exist_ok=True)

# URLs for NSL-KDD data
TRAIN_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"

# Download if missing
if not os.path.exists(TRAIN_FILE):
    print("[INFO] Downloading training data...")
    urllib.request.urlretrieve(TRAIN_URL, TRAIN_FILE)

if not os.path.exists(TEST_FILE):
    print("[INFO] Downloading test data...")
    urllib.request.urlretrieve(TEST_URL, TEST_FILE)

# Column names (from NSL-KDD documentation)
col_names = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label", "difficulty"
]

print("[INFO] Loading datasets...")
train_df = pd.read_csv(TRAIN_FILE, names=col_names)
test_df = pd.read_csv(TEST_FILE, names=col_names)

# Drop 'difficulty' column (not a feature)
train_df.drop(columns=["difficulty"], inplace=True)
test_df.drop(columns=["difficulty"], inplace=True)

# Encode categorical columns jointly to avoid unseen label errors
cat_cols = ["protocol_type", "service", "flag"]
encoders = {}
for col in cat_cols:
    le = LabelEncoder()
    combined = pd.concat([train_df[col], test_df[col]], axis=0)
    le.fit(combined)
    train_df[col] = le.transform(train_df[col])
    test_df[col] = le.transform(test_df[col])
    encoders[col] = le

# Encode target labels
label_encoder = LabelEncoder()
combined_labels = pd.concat([train_df["label"], test_df["label"]], axis=0)
label_encoder.fit(combined_labels)
train_df["label"] = label_encoder.transform(train_df["label"])
test_df["label"] = label_encoder.transform(test_df["label"])

# Scale numeric features to [0, 1]
features = train_df.columns.drop("label")
scaler = MinMaxScaler()
scaler.fit(pd.concat([train_df[features], test_df[features]], axis=0))
train_df[features] = scaler.transform(train_df[features])
test_df[features] = scaler.transform(test_df[features])

# Save as numpy arrays
np.save(os.path.join(DATA_DIR, "train.npy"), train_df.to_numpy())
np.save(os.path.join(DATA_DIR, "test.npy"), test_df.to_numpy())

print("[INFO] Preprocessing complete.")
print("[INFO] Train shape:", train_df.shape)
print("[INFO] Test shape:", test_df.shape)
