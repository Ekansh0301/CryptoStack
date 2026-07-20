"""
PA#16 — ElGamal Public-Key Encryption
Depends on: PA#11 (DHGroup)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa11_dh.dh import DHGroup
from pa13_miller_rabin.miller_rabin import _square_and_multiply


# ── ElGamal Key Generation ────────────────────────────────────────────────────

class ElGamal_KeyPair:
    def __init__(self, group: DHGroup, x: int, h: int):
        self.group = group
        self.x = x   # private key
        self.h = h   # public key h = g^x mod p

    @property
    def public_key(self):
        return (self.group, self.h)

    @property
    def private_key(self):
        return (self.group, self.x)


def elgamal_keygen(group: DHGroup) -> ElGamal_KeyPair:
    """Sample x <- Zq, compute h = g^x mod p."""
    x = group.random_exponent()
    h = group.power(group.g, x)
    return ElGamal_KeyPair(group, x, h)


# ── ElGamal Encryption / Decryption ──────────────────────────────────────────

def elgamal_enc(pk: tuple, m: int) -> tuple[int, int]:
    """
    Encrypt m in Zp.
    Sample fresh r <- Zq.
    c1 = g^r mod p, c2 = m * h^r mod p.
    Returns (c1, c2).
    """
    group, h = pk
    r = group.random_exponent()
    c1 = group.power(group.g, r)
    c2 = (m * group.power(h, r)) % group.p
    return c1, c2


def elgamal_dec(sk: tuple, c1: int, c2: int) -> int:
    """
    Decrypt: m = c2 / c1^x mod p = c2 * c1^{-x} mod p.
    """
    group, x = sk
    s = group.power(c1, x)  # c1^x = g^{rx}
    # Modular inverse of s via Fermat's little theorem
    s_inv = _square_and_multiply(s, group.p - 2, group.p)
    m = (c2 * s_inv) % group.p
    return m


# ── Malleability Demo ─────────────────────────────────────────────────────────

def demo_malleability(kp: ElGamal_KeyPair) -> None:
    """
    Demonstrate ElGamal malleability: (c1, 2*c2) decrypts to 2m.
    This breaks CCA security.
    """
    print("\n[ElGamal Malleability Demo]")
    pk = kp.public_key
    sk = kp.private_key
    group = kp.group

    m = 42
    c1, c2 = elgamal_enc(pk, m)
    m_dec = elgamal_dec(sk, c1, c2)
    print(f"  Enc({m}) -> decrypt -> {m_dec}")

    # Malleable: multiply c2 by 2
    c2_prime = (2 * c2) % group.p
    m_malleable = elgamal_dec(sk, c1, c2_prime)
    expected = (2 * m) % group.p
    print(f"  (c1, 2*c2) -> decrypt -> {m_malleable}  (expected {expected})")
    print(f"  Malleability confirmed: {m_malleable == expected}")
    assert m_malleable == expected

    # Multiple rounds to show it always works
    success_count = 0
    for _ in range(20):
        m_test = group.random_exponent() % 1000 + 1
        c1_t, c2_t = elgamal_enc(pk, m_test)
        c2_doubled = (2 * c2_t) % group.p
        m_doubled = elgamal_dec(sk, c1_t, c2_doubled)
        if m_doubled == (2 * m_test) % group.p:
            success_count += 1
    print(f"  Malleability success rate: {success_count}/20 (should be 20/20)")
    print(f"  -> ElGamal is NOT CCA-secure (adversary can transform ciphertexts)")


# ── IND-CPA Game ──────────────────────────────────────────────────────────────

def ind_cpa_elgamal(kp: ElGamal_KeyPair, trials: int = 100) -> float:
    """
    IND-CPA game for ElGamal with dummy adversary.
    Expected advantage ~ 0 when DDH is hard (large group).
    """
    import random
    pk = kp.public_key
    group = kp.group

    correct = 0
    for _ in range(trials):
        b = random.randint(0, 1)
        m0 = group.random_exponent() % (group.p - 1) + 1
        m1 = group.random_exponent() % (group.p - 1) + 1
        m_challenge = m0 if b == 0 else m1
        c1, c2 = elgamal_enc(pk, m_challenge)
        b_guess = 0  # dummy adversary
        if b_guess == b:
            correct += 1

    return abs(correct / trials - 0.5)


# ── Small-Group Distinguisher ─────────────────────────────────────────────────

def small_group_distinguisher(bits: int = 12, trials: int = 100) -> float:
    """
    When the group is tiny (q ~ 2^10), an adversary can break IND-CPA
    by brute-forcing the discrete log from c1 = g^r to recover r,
    then computing h^r directly and checking if c2 / h^r == m0 or m1.

    This demonstrates that DDH (and hence ElGamal CPA security) depends
    on the group being large enough to prevent brute-force DLP.
    """
    import random

    print(f"\n[Small-Group Distinguisher (q ~ 2^{bits-2})]")
    small_group = DHGroup(bits=bits)
    kp = elgamal_keygen(small_group)
    pk = kp.public_key
    sk = kp.private_key
    g, p, q = small_group.g, small_group.p, small_group.q

    correct = 0
    for _ in range(trials):
        b = random.randint(0, 1)
        m0 = random.randint(2, p - 2)
        m1 = random.randint(2, p - 2)
        while m1 == m0:
            m1 = random.randint(2, p - 2)
        m_ch = m0 if b == 0 else m1
        c1, c2 = elgamal_enc(pk, m_ch)

        # Adversary brute-forces DLP: find r such that g^r = c1
        r_found = None
        for r_try in range(q + 1):
            if _square_and_multiply(g, r_try, p) == c1:
                r_found = r_try
                break

        if r_found is not None:
            # Compute h^r and recover m = c2 * (h^r)^{-1}
            hr = _square_and_multiply(kp.h, r_found, p)
            hr_inv = _square_and_multiply(hr, p - 2, p)
            m_recovered = (c2 * hr_inv) % p

            # Check which message it is
            if m_recovered == m0:
                b_guess = 0
            elif m_recovered == m1:
                b_guess = 1
            else:
                b_guess = random.randint(0, 1)
        else:
            b_guess = random.randint(0, 1)

        if b_guess == b:
            correct += 1

    advantage = abs(correct / trials - 0.5)
    print(f"  Group: p={p.bit_length()}-bit, q={q.bit_length()}-bit")
    print(f"  Brute-force DLP in O(q) = O({q}) per query")
    print(f"  Distinguisher advantage: {advantage:.3f} (expected ~ 0.5)")
    print(f"  Correct guesses: {correct}/{trials}")
    print(f"  -> DDH is EASY in small groups, so ElGamal is NOT CPA-secure here!")
    return advantage


if __name__ == "__main__":
    print("=== PA#16: ElGamal Encryption ===\n")

    print("[Building DH group (64-bit)...]")
    group = DHGroup(bits=64)
    kp = elgamal_keygen(group)
    pk = kp.public_key
    sk = kp.private_key

    # Q1: Key generation
    print(f"\n[ElGamal keygen]")
    print(f"  p = {group.p.bit_length()}-bit")
    print(f"  Private x = {str(kp.x)[:20]}...")
    print(f"  Public  h = g^x = {str(kp.h)[:20]}...")

    # Q2: Encrypt/decrypt test
    print("\n[Encrypt/Decrypt]")
    for m in [1, 100, 999, group.random_exponent() % 1000]:
        c1, c2 = elgamal_enc(pk, m)
        m_dec = elgamal_dec(sk, c1, c2)
        print(f"  m={m}: enc->dec={m_dec}, correct={m==m_dec}")
        assert m == m_dec

    # Q3: Malleability
    demo_malleability(kp)

    # Q4: IND-CPA with large group (advantage ~ 0)
    adv_large = ind_cpa_elgamal(kp, trials=200)
    print(f"\n[IND-CPA game (64-bit group)]")
    print(f"  Dummy adversary advantage: {adv_large:.3f} (expected ~ 0)")
    print(f"  DDH is hard in this group -> ElGamal is CPA-secure")

    # Q4 continued: Small group distinguisher (q ~ 2^10)
    adv_small = small_group_distinguisher(bits=12, trials=100)
