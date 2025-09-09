# E91 Entanglement-based QKD Simulation with Graphical Representation

from qiskit import QuantumCircuit, transpile
from qiskit_aer import AerSimulator
import matplotlib.pyplot as plt
import numpy as np
import random

# Create entangled pair (Bell state)
qc = QuantumCircuit(2, 2)
qc.h(0)          # Hadamard on Alice’s qubit
qc.cx(0, 1)      # Entangle with Bob's qubit

# Add measurements
qc.measure([0, 1], [0, 1])

# Simulate
sim = AerSimulator()
compiled = transpile(qc, sim)
result = sim.run(compiled, shots=1024).result()
counts = result.get_counts()

print("Measurement counts:", counts)

# --- Graphical Representation ---
# Convert to correlation graph
outcomes = list(counts.keys())
freqs = list(counts.values())

# Prepare for correlation calculation
def correlation(counts):
    corr = 0
    total = sum(counts.values())
    for outcome, c in counts.items():
        a, b = int(outcome[1]), int(outcome[0])  # (Alice,Bob)
        if a == b:
            corr += c
    return corr / total

corr = correlation(counts)
print(f"Correlation between Alice & Bob: {corr:.2f}")

# Plot bar chart of outcomes
plt.bar(outcomes, freqs, color='purple')
plt.title("E91 Entanglement Measurement Outcomes")
plt.xlabel("Alice-Bob measurement result")
plt.ylabel("Frequency")
plt.show()

# Graphical explanation in text form
print("\nGraphical Representation (Textual):")
print("------------------------------------------------")
print(" Alice qubit ----||==== entangled ====||---- Bob qubit")
print("                  |                   |")
print("                 (H)                 (CX)")
print("                  |                   |")
print(" After measurement:")
print("   - Alice: 0 => Bob: 0 (high correlation)")
print("   - Alice: 1 => Bob: 1 (high correlation)")
print(" Any mismatch => potential eavesdropper!")
print("------------------------------------------------")
