# test_env.py — sanity check for QML + libs
import sys
print("Python:", sys.version.splitlines()[0])

# -- classical libs
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
print("numpy, pandas, sklearn OK")

# -- scapy (import only; sniffing needs root)
try:
    import scapy.all as scapy
    print("scapy OK (import succeeded)")
except Exception as e:
    print("scapy import failed:", e)

# -- PennyLane minimal circuit test (default.qubit simulator)
import pennylane as qml
from pennylane import numpy as pnp

dev = qml.device("default.qubit", wires=2)

@qml.qnode(dev)
def simple_vqc(params, x):
    # angle encoding
    qml.RY(x[0], wires=0)
    qml.RY(x[1], wires=1)
    # variational layer
    qml.RY(params[0], wires=0)
    qml.RY(params[1], wires=1)
    qml.CNOT(wires=[0,1])
    return qml.expval(qml.PauliZ(0) @ qml.PauliZ(1))

if __name__ == "__main__":
    params = pnp.array([0.1, 0.2], requires_grad=True)
    x = pnp.array([0.3, 0.4])
    print("PennyLane device:", type(dev).__name__)  # updated for new API
    print("VQC expectation:", float(simple_vqc(params, x)))
