"""
entanglement_qkd_e91.py

Entanglement-based QKD (E91-style) demo + CHSH (Bell) test.

Requirements:
  - qiskit (>=2.x)
  - qiskit-aer
  - numpy

This script:
  - Runs 'num_rounds' rounds.
  - Each round is either a KEY round or a TEST (CHSH) round.
  - Key rounds: Alice & Bob measure in Z (0) or X (1) bases.
  - Test rounds: Alice uses settings A0 (0 rad) or A1 (pi/4), Bob uses B0 (pi/8) or B1 (-pi/8).
  - After running, we:
      * extract raw bits,
      * build final key from matching key-basis rounds,
      * compute CHSH correlators and S parameter from test rounds,
      * print a human-readable ASCII table of rounds and results.
"""

import math
import random
from qiskit import QuantumCircuit
from qiskit_aer import AerSimulator
import numpy as np

# --------- Configuration ----------
NUM_ROUNDS = 200            # total rounds (pairs)
TEST_FRACTION = 0.3         # fraction of rounds used for CHSH tests (rest for key)
KEY_BASES = [0, 1]          # 0 -> Z, 1 -> X

# CHSH measurement angles (in radians)
# Standard choice: A0 = 0, A1 = pi/4, B0 = pi/8, B1 = -pi/8
A0 = 0.0
A1 = math.pi / 4
B0 = math.pi / 8
B1 = -math.pi / 8

# ----------------------------------


def make_entangled_pair_circuit(alice_setting, bob_setting):
    """
    Create a circuit for one entangled pair, measure Alice & Bob
    using the provided measurement-setting angles (in radians).
    We'll rotate each qubit by RY(-theta) so that measuring in Z
    yields measurement in the desired basis (X-Z plane).
    We map:
      qubit 0 -> Alice
      qubit 1 -> Bob
    classical bit 0 -> Alice's measurement result (c0)
    classical bit 1 -> Bob's measurement result (c1)
    """
    qc = QuantumCircuit(2, 2)
    # Create Bell pair |Φ+> = (|00> + |11>)/sqrt(2)
    qc.h(0)
    qc.cx(0, 1)

    # Rotate Alice's qubit to desired measurement basis:
    # to measure in basis at angle theta in X-Z plane, apply RY(-theta) then measure Z.
    qc.ry(-alice_setting, 0)
    qc.ry(-bob_setting, 1)

    # Measure qubits into classical bits:
    qc.measure(0, 0)  # Alice -> c0
    qc.measure(1, 1)  # Bob   -> c1

    return qc


def run_protocol(num_rounds=NUM_ROUNDS, test_fraction=TEST_FRACTION):
    rng = random.SystemRandom()
    simulator = AerSimulator()

    # Decide which rounds are test rounds vs key rounds
    rounds = []
    for i in range(num_rounds):
        is_test = rng.random() < test_fraction
        rounds.append({"index": i, "is_test": is_test})

    # For each round, choose measurement settings
    circuits = []
    metadata = []   # keep track of what setting and purpose each circuit used
    for r in rounds:
        if r["is_test"]:
            # CHSH test round: choose A0/A1 for Alice and B0/B1 for Bob
            alice_choice = rng.choice([0, 1])  # 0 -> A0, 1 -> A1
            bob_choice = rng.choice([0, 1])    # 0 -> B0, 1 -> B1
            alice_angle = A0 if alice_choice == 0 else A1
            bob_angle = B0 if bob_choice == 0 else B1
            purpose = "TEST"
        else:
            # Key round: choose Z (0) or X (1)
            alice_choice = rng.choice(KEY_BASES)
            bob_choice = rng.choice(KEY_BASES)
            alice_angle = 0.0 if alice_choice == 0 else math.pi / 2  # H-basis (X) ~ RY(-pi/2) then measure Z
            bob_angle = 0.0 if bob_choice == 0 else math.pi / 2
            purpose = "KEY"

        qc = make_entangled_pair_circuit(alice_angle, bob_angle)
        circuits.append(qc)
        metadata.append({
            "purpose": purpose,
            "alice_choice": alice_choice,
            "bob_choice": bob_choice,
            "alice_angle": alice_angle,
            "bob_angle": bob_angle
        })

    # Run all circuits in a batch (shots=1 each)
    job = simulator.run(circuits, shots=1)
    result = job.result()

    # Parse outcomes unambiguously:
    # For each circuit i, result.get_counts(i) returns something like {'10': 1}
    # The bitstring ordering is [c1 c0] (leftmost = c1). To map to Alice/Bob,
    # we reverse the string so index 0 maps to c0 (Alice), index1 -> c1 (Bob).
    alice_bits = []
    bob_bits = []
    outcomes = []
    for i in range(len(circuits)):
        counts = result.get_counts(i)  # dict
        bitstr = list(counts.keys())[0]  # e.g. '10' (length 2)
        rev = bitstr[::-1]               # now rev[0] == c0 (Alice), rev[1] == c1 (Bob)
        a_bit = int(rev[0])
        b_bit = int(rev[1])
        alice_bits.append(a_bit)
        bob_bits.append(b_bit)
        outcomes.append(bitstr)

    # Build key from KEY rounds where bases matched
    raw_key_indices = []
    key_bits = []
    for i, meta in enumerate(metadata):
        if meta["purpose"] == "KEY" and meta["alice_choice"] == meta["bob_choice"]:
            raw_key_indices.append(i)
            # take Alice's bit (should equal Bob's if no Eve)
            key_bits.append(alice_bits[i])

    # Prepare CHSH statistics from TEST rounds
    # We'll compute correlators E(Ai, Bj) for i in {0,1}, j in {0,1}
    # E = (N00 + N11 - N01 - N10) / N_total for that setting pair
    # We'll gather counts for each pair of settings
    counts_AB = {
        (0, 0): [],  # list of (a,b) outcomes for A0,B0
        (0, 1): [],  # A0,B1
        (1, 0): [],  # A1,B0
        (1, 1): []   # A1,B1
    }

    for i, meta in enumerate(metadata):
        if meta["purpose"] == "TEST":
            # alice_choice: 0->A0,1->A1 ; bob_choice: 0->B0,1->B1
            pair = (meta["alice_choice"], meta["bob_choice"])
            counts_AB[pair].append((alice_bits[i], bob_bits[i]))

    # Compute E for each pair
    def compute_E(pairs):
        if len(pairs) == 0:
            return None  # no data
        n00 = sum(1 for (a, b) in pairs if (a, b) == (0, 0))
        n11 = sum(1 for (a, b) in pairs if (a, b) == (1, 1))
        n01 = sum(1 for (a, b) in pairs if (a, b) == (0, 1))
        n10 = sum(1 for (a, b) in pairs if (a, b) == (1, 0))
        total = n00 + n11 + n01 + n10
        return (n00 + n11 - n01 - n10) / total if total > 0 else None

    E00 = compute_E(counts_AB[(0, 0)])
    E01 = compute_E(counts_AB[(0, 1)])
    E10 = compute_E(counts_AB[(1, 0)])
    E11 = compute_E(counts_AB[(1, 1)])

    # CHSH S = E(A0,B0) + E(A0,B1) + E(A1,B0) - E(A1,B1)
    # If any E is None (no samples), we can't compute S reliably.
    S = None
    if None not in (E00, E01, E10, E11):
        S = E00 + E01 + E10 - E11

    # ---- Print clear textual output ----
    print("\n==== Entanglement QKD (E91-style) run summary ====\n")
    print(f"Total rounds: {num_rounds}")
    n_test = sum(1 for m in metadata if m["purpose"] == "TEST")
    n_key = sum(1 for m in metadata if m["purpose"] == "KEY")
    print(f"Test rounds: {n_test}, Key rounds: {n_key}")
    print(f"Rounds used for final key (matching bases): {len(raw_key_indices)}\n")

    # ASCII table of first 40 rounds for readability
    print(" Round | Purpose | A_choice | B_choice |  A_bit  B_bit  | outcome")
    print("-------+---------+----------+----------+----------------+---------")
    max_show = min(40, num_rounds)
    for i in range(max_show):
        meta = metadata[i]
        purpose = meta["purpose"]
        a_choice = meta["alice_choice"]
        b_choice = meta["bob_choice"]
        a_bit = alice_bits[i]
        b_bit = bob_bits[i]
        out = outcomes[i]
        print(f" {i:3d}   | {purpose:7s} |   {a_choice}      |    {b_choice}     |    {a_bit}     {b_bit}   |  {out}")

    if num_rounds > max_show:
        print(f"... ({num_rounds - max_show} more rounds)\n")
    else:
        print()

    # Key details
    print("Final key (first 128 bits shown):")
    if len(key_bits) == 0:
        print("  [No bits — no matching bases in KEY rounds]")
    else:
        key_str = ''.join(str(b) for b in key_bits)
        print(f"  length = {len(key_bits)}")
        print(f"  key    = {key_str[:128]}{('...' if len(key_bits) > 128 else '')}")

    # CHSH results
    print("\nCHSH (Bell) test results (from TEST rounds):")
    def fmt_e(x):
        return f"{x:.3f}" if x is not None else "N/A"
    print(f"  E(A0,B0) = {fmt_e(E00)}  (pairs = {len(counts_AB[(0,0)])})")
    print(f"  E(A0,B1) = {fmt_e(E01)}  (pairs = {len(counts_AB[(0,1)])})")
    print(f"  E(A1,B0) = {fmt_e(E10)}  (pairs = {len(counts_AB[(1,0)])})")
    print(f"  E(A1,B1) = {fmt_e(E11)}  (pairs = {len(counts_AB[(1,1)])})")
    if S is not None:
        print(f"\n  CHSH S = {S:.3f}")
        if S > 2.0:
            print("  => Bell inequality violated (S > 2). Good — indicates quantum entanglement and no simple local-hidden-variable eavesdropper.")
        else:
            print("  => NO Bell violation detected (S <= 2). This suggests entanglement may be broken — potential eavesdropping or noise.")
    else:
        print("\n  CHSH S = N/A (not enough TEST samples for all setting pairs)")

    print("\n=== End of run ===\n")

    # Return structured data in case you want to programmatically inspect
    return {
        "metadata": metadata,
        "alice_bits": alice_bits,
        "bob_bits": bob_bits,
        "key_bits": key_bits,
        "chsh": {
            "E00": E00, "E01": E01, "E10": E10, "E11": E11, "S": S
        },
        "counts_AB": counts_AB
    }


if __name__ == "__main__":
    # Run the protocol
    data = run_protocol(num_rounds=NUM_ROUNDS, test_fraction=TEST_FRACTION)
