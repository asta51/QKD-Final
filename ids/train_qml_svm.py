# train_qml_svm.py
import os
import time
import joblib
import numpy as np
import pennylane as qml
from pennylane import numpy as pnp
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, accuracy_score
from sklearn.model_selection import train_test_split

# ---------- Config ----------
DATA_TRAIN = "ids/data/train.npy"
DATA_TEST = "ids/data/test.npy"
OUT_MODEL = "qml_model.pkl"
N_QUBITS = 8
MAX_TRAIN_SAMPLES = 800   # keep this modest for speed; increase if you want longer runs
RANDOM_SEED = 42

# ---------- Load data ----------
print("[*] Loading preprocessed NSL-KDD data...")
train_all = np.load(DATA_TRAIN)
test_all = np.load(DATA_TEST)

X_all = train_all[:, :-1]
y_all = train_all[:, -1]

X_test_full = test_all[:, :-1]
y_test_full = test_all[:, -1]

# Convert NSL-KDD labels to binary: normal vs attack
# Earlier pipeline encoded 'normal' possibly as a particular integer.
# We'll treat the most frequent label in training as 'normal'
# (or you can modify to use the known label value).
unique, counts = np.unique(y_all, return_counts=True)
most_common_label = unique[np.argmax(counts)]
print("[*] Assuming label", most_common_label, "is NORMAL class")
y_binary = (y_all != most_common_label).astype(int)
y_test_binary = (y_test_full != most_common_label).astype(int)

# ---------- Feature selection (reduce to N_QUBITS dims) ----------
# Choose first N_QUBITS features for simplicity (you can customize)
X = X_all[:, :N_QUBITS]
X_test = X_test_full[:, :N_QUBITS]

# ---------- Scale features ----------
scaler = StandardScaler().fit(np.vstack([X, X_test]))
X = scaler.transform(X)
X_test = scaler.transform(X_test)

# ---------- Subsample for speed ----------
np.random.seed(RANDOM_SEED)
idx = np.random.permutation(len(X))[:MAX_TRAIN_SAMPLES]
X_train_used = X[idx]
y_train_used = y_binary[idx]

print(f"[*] Training samples used: {len(X_train_used)} (max {MAX_TRAIN_SAMPLES})")

# ---------- PennyLane statevector device ----------
dev = qml.device("default.qubit", wires=N_QUBITS)

@qml.qnode(dev, interface="autograd")
def state_circuit(x):
    """Return statevector for input x using angle encoding (RY)."""
    # angle encoding scaled to [-pi, pi] roughly
    for i in range(N_QUBITS):
        qml.RY(float(x[i]), wires=i)
    return qml.state()

# Cache statevectors to speed kernel computation
def compute_statevectors(Xv):
    svs = []
    for i, x in enumerate(Xv):
        sv = state_circuit(x)
        svs.append(np.array(sv, dtype=complex))
        if (i+1) % 100 == 0:
            print(f"  computed {i+1}/{len(Xv)} statevectors")
    return np.array(svs)

print("[*] Computing statevectors for training set...")
sv_train = compute_statevectors(X_train_used)

print("[*] Computing quantum kernel (train x train)...")
# K_train[i,j] = |<psi(x_i) | psi(x_j)>|^2  (fidelity)
K_train = np.abs(np.matmul(sv_train.conj(), sv_train.T)) ** 2
print("[*] Kernel shape:", K_train.shape)

# ---------- Train SVM with precomputed kernel ----------
print("[*] Training SVM (precomputed kernel)...")
svc = SVC(kernel="precomputed", probability=False, random_state=RANDOM_SEED)
svc.fit(K_train, y_train_used)

# ---------- Evaluate on test set (compute kernel between test and train) ----------
print("[*] Computing statevectors for test set (subset for speed)...")
# we'll use up to 1000 test samples for quick eval
MAX_TEST_EVAL = 1000
test_use_idx = np.random.permutation(len(X_test))[:MAX_TEST_EVAL]
X_test_used = X_test[test_use_idx]
y_test_used = y_test_binary[test_use_idx]

sv_test = compute_statevectors(X_test_used)

# compute kernel between test and train: K_test[i,j] = |<psi(x_test_i)|psi(x_train_j)>|^2
K_test = np.abs(np.matmul(sv_test.conj(), sv_train.T)) ** 2

print("[*] Running predictions on test set...")
y_pred = svc.predict(K_test)
print("[RESULT] Test accuracy (subset):", accuracy_score(y_test_used, y_pred))
print(classification_report(y_test_used, y_pred))

# ---------- Save model artifacts ----------
model_bundle = {
    "svc": svc,
    "X_train": X_train_used,     # scaled training vectors used to compute kernel
    "scaler": scaler,
    "n_qubits": N_QUBITS
}
joblib.dump(model_bundle, OUT_MODEL)
print(f"[*] Saved QML SVM bundle to {OUT_MODEL}")
