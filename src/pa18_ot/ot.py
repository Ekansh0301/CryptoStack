"""
PA#18 — Oblivious Transfer (1-out-of-2 OT)
Depends on: PA#16 (ElGamal)
Receiver gets m_b without sender learning b; sender's m_{1-b} stays hidden.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa11_dh.dh import DHGroup
from pa16_elgamal.elgamal import ElGamal_KeyPair, elgamal_keygen, elgamal_enc, elgamal_dec
from pa13_miller_rabin.miller_rabin import _square_and_multiply


# ── OT Protocol ───────────────────────────────────────────────────────────────

def OT_Receiver_Step1(group: DHGroup, b: int) -> tuple:
    """
    Receiver step 1 (choice bit b in {0,1}).
    - Generate pk_b honestly (with sk_b).
    - Generate pk_{1-b} as a random element in the order-q subgroup (no trapdoor).
    Returns (pk_0, pk_1, state).
    state = (b, sk_b, group) -- kept secret by receiver.
    """
    assert b in (0, 1)

    # Honest keypair for index b
    x_b = group.random_exponent()
    pk_b = group.power(group.g, x_b)   # g^{x_b}

    # Fake public key for index 1-b: random element in the order-q subgroup.
    # We sample a random r and compute g^r, but discard r.
    # This ensures pk_fake is in the subgroup (indistinguishable from pk_b)
    # but the receiver does NOT know the discrete log.
    r_fake = group.random_exponent()
    pk_fake = group.power(group.g, r_fake)
    # Discard r_fake — receiver cannot decrypt C_{1-b}
    # (In a real protocol, receiver would use a hash-based construction
    #  or a verifiable random function to prove they don't know the trapdoor.
    #  For this educational demo, we rely on the protocol's structure.)

    if b == 0:
        pk_0, pk_1 = pk_b, pk_fake
    else:
        pk_0, pk_1 = pk_fake, pk_b

    state = {'b': b, 'sk_b': x_b, 'group': group}
    return pk_0, pk_1, state


def OT_Sender_Step(group: DHGroup, pk_0: int, pk_1: int,
                   m0: int, m1: int) -> tuple:
    """
    Sender step: encrypt both messages.
    C_i = ElGamal_enc(pk_i, m_i) for i in {0, 1}.
    Returns (C_0, C_1).
    """
    C_0 = elgamal_enc((group, pk_0), m0)
    C_1 = elgamal_enc((group, pk_1), m1)
    return C_0, C_1


def OT_Receiver_Step2(state: dict, C_0: tuple, C_1: tuple) -> int:
    """
    Receiver step 2: decrypt only C_b using sk_b.
    Returns m_b.
    """
    b = state['b']
    sk_b = state['sk_b']
    group = state['group']
    C_b = C_0 if b == 0 else C_1
    c1, c2 = C_b
    return elgamal_dec((group, sk_b), c1, c2)


# ── Privacy demonstrations ────────────────────────────────────────────────────

def demo_receiver_privacy(group: DHGroup, trials: int = 5) -> None:
    """
    Receiver privacy: Sender cannot determine b from (pk_0, pk_1).
    Both keys are elements of the order-q subgroup, computationally
    indistinguishable under DDH.
    """
    print("\n[Receiver Privacy Demo]")
    print("  Sender sees two public keys (pk_0, pk_1).")
    print("  Both are in the order-q subgroup -- indistinguishable under DDH.\n")
    for _ in range(trials):
        b = int.from_bytes(os.urandom(1), 'big') % 2
        pk_0, pk_1, state = OT_Receiver_Step1(group, b)
        # Both keys are valid subgroup elements
        # Sender would need to solve DDH to distinguish
        pk0_in_subgroup = group.power(pk_0, group.q) == 1
        pk1_in_subgroup = group.power(pk_1, group.q) == 1
        print(f"  b={b}: pk_0 in subgroup: {pk0_in_subgroup}, "
              f"pk_1 in subgroup: {pk1_in_subgroup} "
              f"[both look random to sender]")


def demo_sender_privacy(group: DHGroup, m0: int, m1: int) -> None:
    """
    Sender privacy: Receiver cannot decrypt C_{1-b} because they
    don't know the discrete log of pk_{1-b}.
    For small parameters, we attempt brute-force and show it requires
    solving DLP (exponential in group size).
    """
    print("\n[Sender Privacy Demo]")
    b = 0
    pk_0, pk_1, state = OT_Receiver_Step1(group, b)
    C_0, C_1 = OT_Sender_Step(group, pk_0, pk_1, m0, m1)

    # Receiver correctly gets m0
    m_b = OT_Receiver_Step2(state, C_0, C_1)
    print(f"  Receiver (b={b}) correctly recovers m_{b} = {m_b}")
    print(f"  m0={m0}, recovered={m_b}, correct={m_b == m0}")

    # Receiver tries to decrypt C_1 (the one they DON'T have sk for)
    c1, c2 = C_1
    print(f"\n  Receiver trying to decrypt C_1 (has no sk_1)...")
    print(f"  To decrypt, need sk_1 = dlog_g(pk_1), which requires solving DLP")
    print(f"  Group order q = {group.q} ({group.q.bit_length()}-bit)")
    print(f"  Brute-force cost: O(q) = O(2^{group.q.bit_length()}) -- infeasible!")

    # Try a few random keys -- they produce garbage, not m1
    print(f"  Attempting with 5 random secret keys:")
    for i in range(5):
        fake_sk = group.random_exponent()
        m_try = elgamal_dec((group, fake_sk), c1, c2)
        print(f"    sk={str(fake_sk)[:10]}... -> dec = {m_try} "
              f"{'= m1 (lucky!)' if m_try == m1 else '!= m1'}")

    print(f"  Without solving DLP, receiver cannot recover m1.")
    print(f"  Sender privacy holds!")


# ── Correctness over 100 trials ───────────────────────────────────────────────

def run_correctness_trials(group: DHGroup, trials: int = 100) -> dict:
    """Run OT protocol for all (b, m0, m1) combinations, verify correctness."""
    correct = 0
    for _ in range(trials):
        b = int.from_bytes(os.urandom(1), 'big') % 2
        m0 = int.from_bytes(os.urandom(4), 'big') % (group.p - 1) + 1
        m1 = int.from_bytes(os.urandom(4), 'big') % (group.p - 1) + 1
        pk_0, pk_1, state = OT_Receiver_Step1(group, b)
        C_0, C_1 = OT_Sender_Step(group, pk_0, pk_1, m0, m1)
        m_b = OT_Receiver_Step2(state, C_0, C_1)
        expected = m0 if b == 0 else m1
        if m_b == expected:
            correct += 1
    return {'trials': trials, 'correct': correct, 'accuracy': correct / trials}


if __name__ == "__main__":
    print("=== PA#18: Oblivious Transfer ===\n")

    print("[Building DH group...]")
    group = DHGroup(bits=64)

    # Q4: Correctness (100 trials)
    print("\n[OT correctness trials (100 random)]")
    result = run_correctness_trials(group, trials=100)
    print(f"  {result}")
    assert result['correct'] == result['trials'], "OT must be 100% correct!"

    # Example with both choices
    print("\n[OT example: b=0 and b=1]")
    m0, m1 = 42, 99
    for b in [0, 1]:
        pk_0, pk_1, state = OT_Receiver_Step1(group, b)
        C_0, C_1 = OT_Sender_Step(group, pk_0, pk_1, m0, m1)
        m_b = OT_Receiver_Step2(state, C_0, C_1)
        expected = m0 if b == 0 else m1
        print(f"  b={b}: received m_{b}={m_b}, expected={expected}, correct={m_b==expected}")

    # Q2: Receiver privacy
    demo_receiver_privacy(group, trials=5)

    # Q3: Sender privacy
    demo_sender_privacy(group, m0=42, m1=99)
