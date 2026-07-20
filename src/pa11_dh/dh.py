"""
PA#11 — Diffie-Hellman Key Exchange
Depends on: PA#13 (gen_safe_prime, _square_and_multiply)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa13_miller_rabin.miller_rabin import gen_safe_prime, _square_and_multiply, is_prime


class DHGroup:
    """
    Diffie-Hellman group parameters: safe prime p = 2q+1, generator g of order q.
    """

    def __init__(self, bits: int = 128):
        print(f"  [DH] Generating {bits}-bit safe prime...")
        self.p, self.q = gen_safe_prime(bits)
        # Find a generator of the prime-order subgroup
        h = 2
        self.g = _square_and_multiply(h, 2, self.p)
        assert self.g != 1
        self.bits = bits
        print(f"  [DH] p={self.p.bit_length()}-bit ready")

    def random_exponent(self) -> int:
        """Sample a uniform random exponent from Zq."""
        return int.from_bytes(os.urandom((self.q.bit_length() + 7) // 8), 'big') % self.q

    def power(self, base: int, exp: int) -> int:
        """Modular exponentiation in the group."""
        return _square_and_multiply(base, exp, self.p)


# ── DH Key Exchange Protocol ──────────────────────────────────────────────────

def dh_alice_step1(group: DHGroup) -> tuple[int, int]:
    """
    Alice step 1: sample secret a, compute A = g^a mod p.
    Returns (a_secret, A_public).
    """
    a = group.random_exponent()
    A = group.power(group.g, a)
    return a, A


def dh_bob_step1(group: DHGroup) -> tuple[int, int]:
    """
    Bob step 1: sample secret b, compute B = g^b mod p.
    Returns (b_secret, B_public).
    """
    b = group.random_exponent()
    B = group.power(group.g, b)
    return b, B


def dh_alice_step2(group: DHGroup, a: int, B: int) -> int:
    """Alice step 2: compute shared key K_A = B^a mod p."""
    return group.power(B, a)


def dh_bob_step2(group: DHGroup, b: int, A: int) -> int:
    """Bob step 2: compute shared key K_B = A^b mod p."""
    return group.power(A, b)


# ── MITM Adversary ────────────────────────────────────────────────────────────

class Eve_MITM:
    """
    Eve performs a Man-in-the-Middle attack on DH.
    Intercepts A and B, substitutes her own g^e, relays modified messages.
    """

    def __init__(self, group: DHGroup):
        self.group = group
        self.e = group.random_exponent()
        self.E = group.power(group.g, self.e)
        self.key_with_alice = None
        self.key_with_bob = None

    def intercept_alice(self, A: int) -> int:
        """Intercept Alice's public key, compute key with Alice, return g^e to Bob."""
        self.key_with_alice = self.group.power(A, self.e)
        return self.E  # send Eve's key to Bob

    def intercept_bob(self, B: int) -> int:
        """Intercept Bob's public key, compute key with Bob, return g^e to Alice."""
        self.key_with_bob = self.group.power(B, self.e)
        return self.E  # send Eve's key to Alice


# ── CDH Hardness Demo ─────────────────────────────────────────────────────────

def demo_cdh_hardness(bits: int = 22) -> None:
    """
    Demonstrate CDH hardness: given g^a and g^b, compute g^{ab}
    WITHOUT knowing a or b. For small q ~ 2^20 we brute-force the
    discrete log to recover a, then compute g^{ab} = (g^b)^a.
    This shows computing CDH requires solving DLP (brute-force O(q)).
    """
    import time

    print(f"\n[CDH Hardness Demo -- brute-force with q ~ 2^{bits-2}]")
    small_group = DHGroup(bits=bits)
    g, p, q = small_group.g, small_group.p, small_group.q

    # Alice and Bob do honest DH
    a, A = dh_alice_step1(small_group)
    b, B = dh_bob_step1(small_group)
    real_K = dh_alice_step2(small_group, a, B)  # g^{ab} -- the target

    print(f"  p = {p} ({p.bit_length()}-bit)")
    print(f"  q = {q} ({q.bit_length()}-bit)")
    print(f"  g^a = {A}")
    print(f"  g^b = {B}")
    print(f"  Goal: compute g^{{ab}} from g^a and g^b alone")

    # Brute-force: try all x in [0, q) until g^x == A, then K = B^x
    t0 = time.time()
    found_a = None
    for x in range(q):
        if _square_and_multiply(g, x, p) == A:
            found_a = x
            break
    elapsed = time.time() - t0

    if found_a is not None:
        K_brute = _square_and_multiply(B, found_a, p)
        print(f"\n  Brute-force found a = {found_a} in {elapsed:.3f}s ({q} candidates)")
        print(f"  Computed g^{{ab}} = B^a = {K_brute}")
        print(f"  Real g^{{ab}}          = {real_K}")
        print(f"  Match: {K_brute == real_K}")
        assert K_brute == real_K
    else:
        print(f"  Could not find a in {elapsed:.3f}s (unexpected)")

    print(f"\n  For real parameters (2048-bit), q ~ 2^2048.")
    print(f"  Brute-force O(q) is completely infeasible.")
    print(f"  CDH security underlies all DH-based key exchange.")


if __name__ == "__main__":
    print("=== PA#11: Diffie-Hellman Key Exchange ===\n")

    group = DHGroup(bits=64)

    # Q2: Honest DH exchange
    print("\n[Honest DH exchange]")
    a, A = dh_alice_step1(group)
    b, B = dh_bob_step1(group)
    KA = dh_alice_step2(group, a, B)
    KB = dh_bob_step2(group, b, A)
    print(f"  A = g^a mod p = {str(A)[:20]}...")
    print(f"  B = g^b mod p = {str(B)[:20]}...")
    print(f"  K_Alice = {str(KA)[:20]}...")
    print(f"  K_Bob   = {str(KB)[:20]}...")
    print(f"  Keys match: {KA == KB}")
    assert KA == KB, "Shared keys must match!"

    # Q3: MITM attack
    print("\n[Eve's MITM attack]")
    eve = Eve_MITM(group)
    a2, A2 = dh_alice_step1(group)
    b2, B2 = dh_bob_step1(group)

    # Eve intercepts
    A_to_bob = eve.intercept_alice(A2)   # Eve sends E to Bob instead
    B_to_alice = eve.intercept_bob(B2)   # Eve sends E to Alice instead

    # Alice and Bob compute keys with Eve (not with each other!)
    KA_mitm = dh_alice_step2(group, a2, B_to_alice)  # K_A = (g^e)^a = g^{ae}
    KB_mitm = dh_bob_step2(group, b2, A_to_bob)       # K_B = (g^e)^b = g^{be}
    print(f"  Eve's secret exponent e (hidden):  [withheld]")
    print(f"  Eve knows key with Alice: {str(eve.key_with_alice)[:20]}...")
    print(f"  Eve knows key with Bob:   {str(eve.key_with_bob)[:20]}...")
    print(f"  Alice's key == Eve-Alice key: {KA_mitm == eve.key_with_alice}")
    print(f"  Bob's key == Eve-Bob key:     {KB_mitm == eve.key_with_bob}")
    print(f"  Alice and Bob think they share a key, but Eve has both!")
    print(f"  Eve can decrypt, read, re-encrypt, and relay all traffic.")

    # Q4: CDH hardness demo (small parameters, q ~ 2^20)
    demo_cdh_hardness(bits=22)

