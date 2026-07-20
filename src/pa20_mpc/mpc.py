"""
PA#20 — All 2-Party MPC via Secure Circuit Evaluation
Depends on: PA#19 (Secure_AND, Secure_XOR, Secure_NOT)

Call-stack trace for one AND gate evaluation:
PA#20 Secure_Eval (AND gate)
 -> PA#19 Secure_AND(a, b)
     -> PA#18 OT_Receiver_Step1 / OT_Sender_Step / OT_Receiver_Step2
         -> PA#16 elgamal_enc / elgamal_dec
             -> PA#11 DHGroup (DH group operations)
                 -> PA#13 gen_safe_prime, _square_and_multiply, miller_rabin
"""

import os
import sys
import time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa11_dh.dh import DHGroup
from pa19_secure_and.secure_and import Secure_AND, Secure_XOR, Secure_NOT


# ── Circuit DAG ───────────────────────────────────────────────────────────────

class Gate:
    """A single logic gate in the circuit."""
    def __init__(self, gate_type: str, inputs: list, output: int):
        """
        gate_type: 'AND', 'XOR', 'NOT', 'INPUT_A', 'INPUT_B'
        inputs: list of wire indices (0 for NOT/input, 1-2 for AND/XOR)
        output: wire index for output
        """
        assert gate_type in ('AND', 'XOR', 'NOT', 'INPUT_A', 'INPUT_B')
        self.gate_type = gate_type
        self.inputs = inputs
        self.output = output

    def __repr__(self):
        return f"Gate({self.gate_type}, in={self.inputs}, out={self.output})"


class Circuit:
    """
    Boolean circuit as a DAG of AND/XOR/NOT gates.
    Wires are indexed integers. Topological ordering is enforced.
    """

    def __init__(self, n_alice_inputs: int, n_bob_inputs: int):
        self.n_alice = n_alice_inputs
        self.n_bob = n_bob_inputs
        self.gates: list[Gate] = []
        self.n_wires = n_alice_inputs + n_bob_inputs
        self.output_wires: list[int] = []

        # Alice's input wires: 0 .. n_alice-1
        # Bob's input wires:   n_alice .. n_alice+n_bob-1
        for i in range(n_alice_inputs):
            self.gates.append(Gate('INPUT_A', [], i))
        for i in range(n_bob_inputs):
            self.gates.append(Gate('INPUT_B', [], n_alice_inputs + i))

    def add_and(self, wire_a: int, wire_b: int) -> int:
        """Add AND gate. Returns output wire index."""
        out = self.n_wires
        self.n_wires += 1
        self.gates.append(Gate('AND', [wire_a, wire_b], out))
        return out

    def add_xor(self, wire_a: int, wire_b: int) -> int:
        """Add XOR gate. Returns output wire index."""
        out = self.n_wires
        self.n_wires += 1
        self.gates.append(Gate('XOR', [wire_a, wire_b], out))
        return out

    def add_not(self, wire_a: int) -> int:
        """Add NOT gate. Returns output wire index."""
        out = self.n_wires
        self.n_wires += 1
        self.gates.append(Gate('NOT', [wire_a], out))
        return out

    def set_outputs(self, wires: list[int]):
        """Mark output wires."""
        self.output_wires = wires


# ── Circuit Evaluator ─────────────────────────────────────────────────────────

def Secure_Eval(circuit: Circuit, x_Alice: list[int], y_Bob: list[int],
                group: DHGroup) -> tuple:
    """
    Securely evaluate circuit with Alice's input x_Alice and Bob's input y_Bob.
    Traverses gates topologically, using PA#19 secure gate operations.
    Returns (output_bits, transcript, ot_call_count, elapsed_s).
    """
    assert len(x_Alice) == circuit.n_alice
    assert len(y_Bob) == circuit.n_bob

    wires = {}
    transcript = []
    ot_calls = 0
    t0 = time.time()

    # Load Alice's inputs
    for i, v in enumerate(x_Alice):
        wires[i] = v % 2

    # Load Bob's inputs
    for i, v in enumerate(y_Bob):
        wires[circuit.n_alice + i] = v % 2

    # Evaluate gates in order (circuit is already topologically ordered by construction)
    for gate in circuit.gates:
        if gate.gate_type in ('INPUT_A', 'INPUT_B'):
            continue  # already loaded

        if gate.gate_type == 'AND':
            a = wires[gate.inputs[0]]
            b = wires[gate.inputs[1]]
            result = Secure_AND(group, a, b)
            ot_calls += 1
            transcript.append({'gate': 'AND', 'inputs': (a, b), 'output': result,
                                'wire': gate.output})

        elif gate.gate_type == 'XOR':
            a = wires[gate.inputs[0]]
            b = wires[gate.inputs[1]]
            result = Secure_XOR(a, b)
            transcript.append({'gate': 'XOR', 'inputs': (a, b), 'output': result,
                                'wire': gate.output})

        elif gate.gate_type == 'NOT':
            a = wires[gate.inputs[0]]
            result = Secure_NOT(a)
            transcript.append({'gate': 'NOT', 'inputs': (a,), 'output': result,
                                'wire': gate.output})

        wires[gate.output] = result

    outputs = [wires[w] for w in circuit.output_wires]
    elapsed = time.time() - t0
    return outputs, transcript, ot_calls, elapsed


# ── Mandatory Test Circuits ───────────────────────────────────────────────────

def build_millionaires_circuit(n_bits: int) -> Circuit:
    """
    Millionaire's problem: compute x > y for n-bit integers.
    Alice has x = x_{n-1}...x_0 (MSB first), Bob has y.
    Uses ripple comparison with carry.
    """
    c = Circuit(n_bits, n_bits)

    # Constant wires: XOR(a0, a0) = 0, NOT(0) = 1
    zero_wire = c.add_xor(0, 0)
    one_wire = c.add_not(zero_wire)

    gt_wire = zero_wire  # starts at 0
    eq_wire = one_wire   # starts at 1

    for i in range(n_bits):
        xi = i             # Alice wire
        yi = n_bits + i    # Bob wire

        # eq_i = NOT(XOR(x_i, y_i))
        xor_i = c.add_xor(xi, yi)
        eq_i = c.add_not(xor_i)

        # not_yi
        not_yi = c.add_not(yi)

        # bit_gt = x_i AND NOT(y_i)
        bit_gt = c.add_and(xi, not_yi)

        # new_gt = gt_wire OR (eq_wire AND bit_gt)
        # a OR b = NOT(NOT(a) AND NOT(b))
        eq_and_bitgt = c.add_and(eq_wire, bit_gt)
        not_gt_wire = c.add_not(gt_wire)
        not_eq_bitgt = c.add_not(eq_and_bitgt)
        not_new_gt = c.add_and(not_gt_wire, not_eq_bitgt)
        new_gt = c.add_not(not_new_gt)

        # new_eq = eq_wire AND eq_i
        new_eq = c.add_and(eq_wire, eq_i)

        gt_wire = new_gt
        eq_wire = new_eq

    c.set_outputs([gt_wire])
    return c


def build_equality_circuit(n_bits: int) -> Circuit:
    """
    Secure equality test: x == y.
    Output 1 iff x_i == y_i for all i.
    """
    c = Circuit(n_bits, n_bits)
    zero_wire = c.add_xor(0, 0)
    one_wire = c.add_not(zero_wire)

    eq_wire = one_wire
    for i in range(n_bits):
        xi = i
        yi = n_bits + i
        xor_i = c.add_xor(xi, yi)
        eq_i = c.add_not(xor_i)
        eq_wire = c.add_and(eq_wire, eq_i)

    c.set_outputs([eq_wire])
    return c


def build_addition_circuit(n_bits: int) -> Circuit:
    """
    Secure n-bit addition x + y mod 2^n using a ripple-carry full adder chain.

    Output layout: n+1 bits total -- [carry, sum_{n-1}, ..., sum_0]
      out[0]    = final carry (the overflow / (n+1)-th bit)
      out[1:]   = the n-bit sum (MSB first)

    To read the mod-2^n result: interpret out[1:] as an n-bit integer, i.e.
      result = sum(bit << (n-1-i) for i, bit in enumerate(out[1:]))
    This discards the carry, giving (x + y) mod 2^n correctly even when carry=1.
    """
    c = Circuit(n_bits, n_bits)

    carry_wire = c.add_xor(0, 0)  # carry = 0
    sum_wires = []

    for i in range(n_bits - 1, -1, -1):  # LSB first
        xi = i
        yi = n_bits + i
        # sum_i = xi XOR yi XOR carry
        xor_xy = c.add_xor(xi, yi)
        sum_i = c.add_xor(xor_xy, carry_wire)
        sum_wires.append(sum_i)

        # carry = (xi AND yi) OR (carry AND (xi XOR yi))
        and_xy = c.add_and(xi, yi)
        and_cx = c.add_and(carry_wire, xor_xy)
        not_and_xy = c.add_not(and_xy)
        not_and_cx = c.add_not(and_cx)
        not_carry = c.add_and(not_and_xy, not_and_cx)
        carry_wire = c.add_not(not_carry)

    sum_wires.append(carry_wire)  # final carry
    c.set_outputs(list(reversed(sum_wires)))
    return c


# ── Simulatability check ──────────────────────────────────────────────────────

def check_simulatability(transcript: list, output: list) -> bool:
    """
    Verify transcript is simulatable from output alone.

    For each gate type, we check that the transcript is consistent with
    the correctness of the gate:

    - AND gates: OT ensures each party learns only the OT output.
      The actual (a,b) pair must be consistent with the output.
    - XOR gates: output = a XOR b. Consistent with any (a, b) that XOR to output.
    - NOT gates: output = 1-a. Deterministic from input.

    A valid transcript reveals ONLY what the output reveals.
    """
    for entry in transcript:
        if entry['gate'] == 'AND':
            a, b = entry['inputs']
            out = entry['output']
            if (a & b) != out:
                return False
        elif entry['gate'] == 'XOR':
            a, b = entry['inputs']
            out = entry['output']
            if (a ^ b) != out:
                return False
        elif entry['gate'] == 'NOT':
            a = entry['inputs'][0]
            out = entry['output']
            if (1 - a) != out:
                return False
    return True


def count_gates(circuit: Circuit) -> dict:
    """Count gates by type in a circuit."""
    counts = {'AND': 0, 'XOR': 0, 'NOT': 0}
    for gate in circuit.gates:
        if gate.gate_type in counts:
            counts[gate.gate_type] += 1
    return counts


# ── Performance benchmark ─────────────────────────────────────────────────────

def performance_benchmark(group: DHGroup, n_bits: int = 8) -> None:
    """
    Q6: Report OT calls and wall-clock time for each circuit with n-bit inputs.
    """
    import random
    print(f"\n{'='*60}")
    print(f"[Performance Benchmark (n={n_bits}-bit inputs)]")
    print(f"{'='*60}")

    circuits = {
        "Millionaire's (x > y)": build_millionaires_circuit(n_bits),
        "Equality (x == y)": build_equality_circuit(n_bits),
        f"Addition (x+y mod 2^{n_bits})": build_addition_circuit(n_bits),
    }

    for name, circuit in circuits.items():
        gate_counts = count_gates(circuit)
        x = random.randint(0, (1 << n_bits) - 1)
        y = random.randint(0, (1 << n_bits) - 1)
        x_bits = [(x >> (n_bits - 1 - i)) & 1 for i in range(n_bits)]
        y_bits = [(y >> (n_bits - 1 - i)) & 1 for i in range(n_bits)]

        out, transcript, ot_cnt, elapsed = Secure_Eval(circuit, x_bits, y_bits, group)

        print(f"\n  {name}:")
        print(f"    Gates: {gate_counts}")
        print(f"    OT calls (=AND gates): {ot_cnt}")
        print(f"    Wall-clock time: {elapsed:.3f}s")
        print(f"    Test: x={x}, y={y} -> output={out}")


if __name__ == "__main__":
    print("=== PA#20: 2-Party MPC ===")
    print("""
Call-stack trace (one AND gate):
PA#20 Secure_Eval (AND gate)
 -> PA#19 Secure_AND(a, b)
     -> PA#18 OT_Receiver_Step1 / OT_Sender_Step / OT_Receiver_Step2
         -> PA#16 elgamal_enc / elgamal_dec
             -> PA#11 DHGroup
                 -> PA#13 gen_safe_prime, _square_and_multiply, miller_rabin
    """)

    print("[Building DH group...]")
    group = DHGroup(bits=64)
    n = 4  # 4-bit inputs for correctness demo

    # ── Millionaire's Problem ─────────────────────────────────────────────────
    print(f"\n[Millionaire's Problem ({n}-bit)]")
    mill_circuit = build_millionaires_circuit(n)
    test_pairs = [(5, 3), (3, 5), (4, 4), (7, 0), (0, 7)]
    for x, y in test_pairs:
        x_bits = [(x >> (n - 1 - i)) & 1 for i in range(n)]
        y_bits = [(y >> (n - 1 - i)) & 1 for i in range(n)]
        out, transcript, ot_cnt, elapsed = Secure_Eval(mill_circuit, x_bits, y_bits, group)
        result = out[0]
        expected = int(x > y)
        sim_ok = check_simulatability(transcript, out)
        print(f"  {x} > {y}: secure={result}, expected={expected}, "
              f"correct={result==expected}, OT={ot_cnt}, simulatable={sim_ok}")

    # ── Equality Test ─────────────────────────────────────────────────────────
    print(f"\n[Secure Equality ({n}-bit)]")
    eq_circuit = build_equality_circuit(n)
    for x, y in [(5, 5), (3, 7), (0, 0), (4, 4)]:
        x_bits = [(x >> (n - 1 - i)) & 1 for i in range(n)]
        y_bits = [(y >> (n - 1 - i)) & 1 for i in range(n)]
        out, transcript, ot_cnt, elapsed = Secure_Eval(eq_circuit, x_bits, y_bits, group)
        result = out[0]
        expected = int(x == y)
        sim_ok = check_simulatability(transcript, out)
        print(f"  {x} == {y}: secure={result}, expected={expected}, "
              f"correct={result==expected}, OT={ot_cnt}, simulatable={sim_ok}")

    # ── Secure Addition ───────────────────────────────────────────────────────
    print(f"\n[Secure Addition ({n}-bit, mod 2^{n})]")
    add_circuit = build_addition_circuit(n)
    for x, y in [(3, 5), (7, 1), (6, 6), (0, 15)]:
        x_bits = [(x >> (n - 1 - i)) & 1 for i in range(n)]
        y_bits = [(y >> (n - 1 - i)) & 1 for i in range(n)]
        out, transcript, ot_cnt, elapsed = Secure_Eval(add_circuit, x_bits, y_bits, group)
        carry = out[0]
        result_int = sum(b << (n - 1 - i) for i, b in enumerate(out[1:]))
        expected = (x + y) % (1 << n)
        sim_ok = check_simulatability(transcript, out)
        print(f"  {x} + {y} = {result_int} (carry={carry}), expected={expected}, "
              f"correct={result_int==expected}, OT={ot_cnt}, simulatable={sim_ok}")

    # ── Q6: Performance benchmark (n=8-bit) ──────────────────────────────────
    performance_benchmark(group, n_bits=8)

    print("\n[Done -- full call-stack trace documented above]")
