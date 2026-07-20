"""
PA#19 — Secure 2-Party AND, XOR, NOT Gates
Depends on: PA#18 (OT)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa11_dh.dh import DHGroup
from pa18_ot.ot import OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2


# ── Secure AND via OT ─────────────────────────────────────────────────────────

def Secure_AND(group: DHGroup, a: int, b: int) -> int:
    """
    Secure AND gate via OT.
    Alice holds a in {0,1}, Bob holds b in {0,1}.
    Alice is OT Sender with messages (0, a).
    Bob is OT Receiver with choice b.
    Bob receives a AND b = messages[b].
    """
    assert a in (0, 1) and b in (0, 1)
    # Alice's OT messages: m0=0 (if b=0, AND=0), m1=a (if b=1, AND=a)
    m0 = 0
    m1 = a

    # Bob acts as OT Receiver
    pk_0, pk_1, state = OT_Receiver_Step1(group, b)
    # Alice acts as OT Sender
    C_0, C_1 = OT_Sender_Step(group, pk_0, pk_1, m0, m1)
    # Bob decrypts
    result = OT_Receiver_Step2(state, C_0, C_1)
    return result % 2  # ensure bit


# ── Secure XOR via additive secret sharing ────────────────────────────────────

def Secure_XOR(a: int, b: int) -> int:
    """
    Secure XOR via additive secret sharing over Z_2.
    No OT required.

    Protocol:
    1. Alice samples random r in {0,1}, sends r to Bob.
    2. Alice computes her share: s_A = a XOR r
    3. Bob computes his share:   s_B = b XOR r
    4. Output = s_A XOR s_B = (a XOR r) XOR (b XOR r) = a XOR b

    Security: Alice's share s_A is uniformly random (masked by r),
    so Bob learns nothing about a from r alone. Similarly, Alice
    learns nothing about b (she never sees s_B or b).

    Since the protocol is deterministic on the shares, we implement
    the final output directly (both parties can compute it locally
    from their shares, or one reveals their share to the other).
    """
    assert a in (0, 1) and b in (0, 1)
    # Simulate the sharing protocol
    r = int.from_bytes(os.urandom(1), 'big') & 1  # random mask
    s_A = a ^ r    # Alice's share
    s_B = b ^ r    # Bob's share (Bob receives r from Alice)
    output = s_A ^ s_B   # = a ^ b
    return output


# ── Secure NOT ────────────────────────────────────────────────────────────────

def Secure_NOT(a: int) -> int:
    """
    Secure NOT: local bit flip.
    No communication required. Alice (or the party holding the share) flips locally.
    """
    assert a in (0, 1)
    return 1 - a


# ── Verification suite ────────────────────────────────────────────────────────

def verify_all_gates(group: DHGroup, trials_each: int = 50) -> dict:
    """Verify AND, XOR, NOT across all input combinations, repeated trials."""
    results = {}

    # AND: 50 actual OT-backed trials per (a,b) combination
    and_correct = 0
    and_total = 0
    for _ in range(trials_each):
        for a in range(2):
            for b in range(2):
                result = Secure_AND(group, a, b)
                expected = a & b
                if result == expected:
                    and_correct += 1
                and_total += 1
    results['AND'] = {'correct': and_correct, 'total': and_total}

    # XOR: 50 actual trials per (a,b) combination
    xor_correct = 0
    xor_total = 0
    for _ in range(trials_each):
        for a in range(2):
            for b in range(2):
                result = Secure_XOR(a, b)
                expected = a ^ b
                if result == expected:
                    xor_correct += 1
                xor_total += 1
    results['XOR'] = {'correct': xor_correct, 'total': xor_total}

    # NOT: 50 actual trials per (a) value
    not_correct = 0
    not_total = 0
    for _ in range(trials_each):
        for a in range(2):
            result = Secure_NOT(a)
            expected = 1 - a
            if result == expected:
                not_correct += 1
            not_total += 1
    results['NOT'] = {'correct': not_correct, 'total': not_total}

    return results


# ── Privacy argument ──────────────────────────────────────────────────────────

PRIVACY_ARGUMENT = """
Privacy Argument for Secure AND (OT-based):

1. Bob's view: Bob receives m_b = a AND b from the OT.
   - If b=0: Bob receives 0, which tells him nothing about a
     (a AND 0 = 0 for any a).
   - If b=1: Bob receives a, which is exactly the AND output.
   Bob learns only a AND b — nothing more about a beyond what
   a AND b reveals. (This follows from OT sender privacy.)

2. Alice's view: Alice sees only (pk_0, pk_1) from the OT setup.
   Both keys are elements of the order-q subgroup, indistinguishable
   under DDH. Alice encrypts under both keys but cannot determine
   which one Bob can decrypt. Alice learns NOTHING about b.
   (This follows from OT receiver privacy.)

3. Secure XOR: uses additive secret sharing over Z_2.
   Alice sends random r; her share is a XOR r, Bob's share is b XOR r.
   Output = (a XOR r) XOR (b XOR r) = a XOR b.
   - Alice's share s_A = a XOR r is uniformly random → reveals nothing about a.
   - Bob only sees r (uniform random) → learns nothing about a.
   Each party's view is simulatable from the output alone.

4. Secure NOT: local operation, no communication, no leakage.
   Only the party holding the bit performs the flip.
"""


if __name__ == "__main__":
    print("=== PA#19: Secure AND, XOR, NOT ===\n")

    print("[Building DH group...]")
    group = DHGroup(bits=64)

    # Truth table verification
    print("\n[Gate truth tables]")
    for a in range(2):
        for b in range(2):
            and_r = Secure_AND(group, a, b)
            xor_r = Secure_XOR(a, b)
            not_r = Secure_NOT(a)
            print(f"  a={a}, b={b}: AND={and_r} (exp={a&b}), "
                  f"XOR={xor_r} (exp={a^b}), NOT(a)={not_r} (exp={1-a})")

    # Full verification (50 trials each)
    print("\n[Verification (50 trials x each combination)]")
    results = verify_all_gates(group, trials_each=50)
    for gate, r in results.items():
        acc = r['correct'] / r['total']
        print(f"  {gate}: {r['correct']}/{r['total']} correct ({acc:.1%})")
        assert r['correct'] == r['total'], f"{gate} gate has failures!"

    print("\n" + PRIVACY_ARGUMENT)
