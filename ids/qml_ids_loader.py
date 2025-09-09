# qml_ids_loader.py
import os
import joblib
import numpy as np
import pennylane as qml

class QMLPredictor:
    def __init__(self, model_path="/home/asta/final/hybrid-cybersecurity-system/ids/qml_model.pkl"):

        bundle = joblib.load(model_path)
        self.svc = bundle["svc"]
        self.X_train = bundle["X_train"]
        self.scaler = bundle["scaler"]
        self.n_qubits = int(bundle.get("n_qubits", 8))

        self.dev = qml.device("default.qubit", wires=self.n_qubits)

        @qml.qnode(self.dev, interface="autograd")
        def state_circ(x):
            for i in range(self.n_qubits):
                qml.RY(float(x[i]), wires=i)
            return qml.state()

        self._state_circ = state_circ
        self._sv_cache = [self._state_circ(x) for x in self.X_train]

    def _kernel_test_train(self, X):
        svs = [self._state_circ(x) for x in X]
        K = np.zeros((len(X), len(self._sv_cache)), dtype=float)
        for i, sv in enumerate(svs):
            for j, svt in enumerate(self._sv_cache):
                K[i, j] = abs(np.vdot(sv, svt)) ** 2
        return K

    def predict(self, X_raw):
        X = np.array(X_raw, dtype=float)
        if X.ndim == 1:
            X = X.reshape(1, -1)
        Xs = self.scaler.transform(X)
        Xs = Xs[:, : self.n_qubits]
        K = self._kernel_test_train(Xs)
        return self.svc.predict(K)
