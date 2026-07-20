"""
PA#14 — Chinese Remainder Theorem + Hastad Broadcast Attack
Depends on: PA#12 (RSA, mod_inverse), PA#13 (gen_prime)
"""

import os
import sys
import time
import math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa12_rsa.rsa import (rsa_keygen, rsa_enc, rsa_dec, extended_gcd,
                           mod_inverse, rsa_enc_pkcs1, pkcs1_v15_unpad,
                           RSA_KeyPair)
from pa13_miller_rabin.miller_rabin import _square_and_multiply, gen_prime


# ── CRT implementation ────────────────────────────────────────────────────────

def crt(residues: list[int], moduli: list[int]) -> int:
    """
    Chinese Remainder Theorem solver.
    Given residues r_i and moduli m_i (pairwise coprime),
    find x such that x = r_i (mod m_i) for all i.
    Returns x in [0, product of moduli).
    """
    assert len(residues) == len(moduli)
    M = 1
    for m in moduli:
        M *= m

    result = 0
    for r, m in zip(residues, moduli):
        Mi = M // m
        yi = mod_inverse(Mi, m)
        result += r * Mi * yi

    return result % M


# ── RSA key generation with e=3 ───────────────────────────────────────────────

def rsa_keygen_e3(bits: int = 512) -> RSA_KeyPair:
    """
    Generate RSA key pair with e=3.
    Need p, q such that gcd(3, (p-1)(q-1)) = 1, i.e. p != 1 mod 3 and q != 1 mod 3.
    """
    e = 3
    half = bits // 2
    while True:
        p = gen_prime(half)
        q = gen_prime(half)
        if p == q:
            continue
        if p % 3 == 1 or q % 3 == 1:
            continue  # need gcd(e, phi) = 1
        n = p * q
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        try:
            d = mod_inverse(e, phi)
        except ValueError:
            continue
        return RSA_KeyPair(n, e, d, p, q)


# ── RSA-CRT decryption (Garner's algorithm) ───────────────────────────────────

def rsa_dec_crt(kp, c: int) -> int:
    """
    RSA decryption using CRT (Garner's algorithm). ~3-4x faster.
    m_p = c^dp mod p
    m_q = c^dq mod q
    Combine with CRT to get m.
    """
    m_p = _square_and_multiply(c % kp.p, kp.dp, kp.p)
    m_q = _square_and_multiply(c % kp.q, kp.dq, kp.q)
    # Garner's formula: m = m_q + q * (q_inv * (m_p - m_q) mod p)
    h = (kp.q_inv * (m_p - m_q)) % kp.p
    m = m_q + kp.q * h
    return m % kp.n


def verify_crt_correctness(kp, n_messages: int = 100) -> bool:
    """Verify CRT decryption matches standard decryption for n random messages."""
    for _ in range(n_messages):
        m = int.from_bytes(os.urandom(16), 'big') % (kp.n - 2) + 1
        c = rsa_enc(kp.public_key, m)
        m_std = rsa_dec(kp.private_key, c)
        m_crt = rsa_dec_crt(kp, c)
        if m_std != m_crt:
            return False
    return True


def benchmark_crt_speedup(kp, n_trials: int = 1000) -> dict:
    """Benchmark CRT vs standard decryption."""
    c = rsa_enc(kp.public_key, 12345)

    t0 = time.time()
    for _ in range(n_trials):
        rsa_dec(kp.private_key, c)
    t_standard = (time.time() - t0) / n_trials

    t0 = time.time()
    for _ in range(n_trials):
        rsa_dec_crt(kp, c)
    t_crt = (time.time() - t0) / n_trials

    return {
        'standard_ms': t_standard * 1000,
        'crt_ms': t_crt * 1000,
        'speedup': t_standard / t_crt if t_crt > 0 else float('inf'),
    }


# ── Integer nth root via Newton's method ─────────────────────────────────────

def integer_nth_root(n: int, e: int) -> tuple[int, bool]:
    """
    Compute integer e-th root of n via Newton's method.
    Returns (root, is_exact).
    """
    if n == 0:
        return 0, True
    if e == 1:
        return n, True

    # Initial guess: use bit length for a better starting point
    bits = n.bit_length()
    x = 1 << ((bits + e - 1) // e)

    while True:
        x1 = ((e - 1) * x + n // (x ** (e - 1))) // e
        if x1 >= x:
            break
        x = x1

    # Verify
    exact = x ** e == n
    return x, exact


# ── Hastad Broadcast Attack ───────────────────────────────────────────────────

def hastad_attack(ciphertexts: list[int], moduli: list[int], e: int) -> tuple[int, bool]:
    """
    Hastad's broadcast attack for small exponent e.
    Given e ciphertexts c_i = m^e mod n_i (same m, different n_i, e=3),
    apply CRT to get m^e mod (n_1 * n_2 * ... * n_e),
    then take integer e-th root to recover m.
    """
    assert len(ciphertexts) == e == len(moduli)
    # CRT to get m^e mod product
    m_e = crt(ciphertexts, moduli)
    # Integer e-th root
    m, is_exact = integer_nth_root(m_e, e)
    return m, is_exact


def demo_hastad_attack(bits: int = 256) -> None:
    """Demonstrate Hastad attack with e=3 using proper e=3 keys."""
    print(f"\n[Hastad Broadcast Attack (e=3, {bits}-bit moduli)]")
    e = 3
    print(f"  Generating {e} RSA key pairs with e={e}...")

    # Generate 3 key pairs with e=3
    keypairs = []
    for i in range(e):
        kp = rsa_keygen_e3(bits)
        keypairs.append(kp)
        print(f"    N_{i+1} = {str(kp.n)[:20]}... ({kp.n.bit_length()}-bit)")

    moduli = [kp.n for kp in keypairs]

    # Choose a message small enough that m^3 < N1*N2*N3
    N_prod = 1
    for n in moduli:
        N_prod *= n
    max_m, _ = integer_nth_root(N_prod, e)
    m = int.from_bytes(os.urandom(bits // (8 * e)), 'big')  # small message
    if m >= max_m:
        m = max_m - 1
    if m < 2:
        m = 42

    print(f"  Message m = {m} ({m.bit_length()}-bit)")
    print(f"  m^3 < N1*N2*N3: {m**3 < N_prod}")

    # Each recipient gets same message encrypted under their key with e=3
    ciphertexts = [rsa_enc((kp.n, e), m) for kp in keypairs]
    for i, c in enumerate(ciphertexts):
        print(f"    c_{i+1} = m^3 mod N_{i+1} = {str(c)[:20]}...")

    # Attack
    m_recovered, is_exact = hastad_attack(ciphertexts, moduli, e)
    print(f"\n  CRT recovered m^3 mod (N1*N2*N3)")
    print(f"  Integer cube root: m = {m_recovered}")
    print(f"  Exact integer root: {is_exact}")
    print(f"  Match original: {m_recovered == m}")
    assert m_recovered == m and is_exact, "Hastad attack must succeed!"


# ── Attack boundary analysis ─────────────────────────────────────────────────

def attack_boundary_analysis() -> None:
    """
    Q5: Determine the maximum message length (in bytes) for which
    Hastad's attack with e=3 succeeds, given three 1024-bit moduli.
    """
    print("\n[Attack Boundary Analysis]")
    bits = 1024
    e = 3

    # For three 1024-bit moduli: N1*N2*N3 ~ 2^3072
    # Attack succeeds when m^3 < N1*N2*N3, i.e. m < (N1*N2*N3)^{1/3}
    # Since each N_i ~ 2^1024, the product is ~ 2^3072
    # So m < 2^1024 (roughly), i.e. max message is ~1024 bits = 128 bytes
    n_bytes = bits // 8  # 128 bytes for 1024-bit modulus

    # But m must be < each N_i individually (RSA constraint)
    # So max m ~ N_min which is ~2^1024, giving max ~128 bytes
    max_msg_bits = bits  # each N_i is bits-bit, m < N_i
    max_msg_bytes = max_msg_bits // 8

    print(f"  With e=3 and three {bits}-bit moduli:")
    print(f"    N1*N2*N3 ~ 2^{3*bits}")
    print(f"    Attack requires: m^3 < N1*N2*N3")
    print(f"    So m < (N1*N2*N3)^(1/3) ~ 2^{bits}")
    print(f"    Max message: ~{max_msg_bytes} bytes = {max_msg_bits} bits")
    print(f"\n  Why messages with m^3 >= N1*N2*N3 are safe from THIS attack:")
    print(f"    CRT recovers m^3 mod N1*N2*N3, but if m^3 >= N1*N2*N3 then")
    print(f"    the recovered value is m^3 - k*(N1*N2*N3) for some k > 0,")
    print(f"    and the integer cube root of this reduced value is NOT m.")
    print(f"    (Though such messages may still be insecure for other reasons,")
    print(f"     e.g. the RSA problem itself may be easy for small e.)")


# ── Padding defeats the attack ────────────────────────────────────────────────

def demo_padding_defeats_hastad(bits: int = 256) -> None:
    """
    Q6: Show PKCS#1 v1.5 padding defeats Hastad's broadcast attack.
    With padding, each c_i = (padded_m_i)^e mod N_i, where padded_m_i
    are all different (random PS bytes). CRT recovers some value, but
    its cube root is not a meaningful message.
    """
    print(f"\n[PKCS#1 v1.5 Defeats Hastad Attack]")
    e = 3

    keypairs = []
    for i in range(e):
        kp = rsa_keygen_e3(bits)
        keypairs.append(kp)

    moduli = [kp.n for kp in keypairs]
    m_bytes = b"secret"

    # Without padding: same m -> attack works
    m_int = int.from_bytes(m_bytes, 'big')
    ciphertexts_raw = [rsa_enc((kp.n, e), m_int) for kp in keypairs]
    m_recovered, is_exact = hastad_attack(ciphertexts_raw, moduli, e)
    print(f"  WITHOUT padding:")
    print(f"    Same m = {m_int} encrypted under 3 keys")
    print(f"    Hastad recovers m = {m_recovered} (exact={is_exact}, match={m_recovered == m_int})")

    # With PKCS#1 v1.5 padding: different padded m's -> attack fails
    ciphertexts_padded = [rsa_enc_pkcs1((kp.n, e), m_bytes) for kp in keypairs]
    m_padded_recovered, is_exact_p = hastad_attack(ciphertexts_padded, moduli, e)
    n_bytes = (keypairs[0].n.bit_length() + 7) // 8

    print(f"\n  WITH PKCS#1 v1.5 padding:")
    print(f"    Each padded plaintext has different random PS bytes")
    print(f"    CRT still works, but the cube root is not an integer:")
    print(f"    Exact integer root: {is_exact_p}")
    if is_exact_p:
        # Very unlikely but check
        rec_bytes = m_padded_recovered.to_bytes(n_bytes, 'big')
        try:
            rec_msg = pkcs1_v15_unpad(rec_bytes)
            print(f"    Recovered: {rec_msg!r} (unexpected!)")
        except ValueError:
            print(f"    Unpadding the result fails -> garbage")
    else:
        print(f"    Root = {str(m_padded_recovered)[:30]}... is NOT m^3")
        print(f"    Attack fails: different padding means different plaintexts,")
        print(f"    so CRT does NOT recover m^3.")


if __name__ == "__main__":
    print("=== PA#14: CRT + Hastad Broadcast Attack ===\n")

    # Q1: CRT test
    print("[CRT correctness]")
    r = crt([2, 3, 2], [3, 5, 7])
    print(f"  x = 2 (mod 3), x = 3 (mod 5), x = 2 (mod 7) -> x = {r}")
    assert r % 3 == 2 and r % 5 == 3 and r % 7 == 2
    print(f"  Verified: {r} mod 3={r%3}, mod 5={r%5}, mod 7={r%7}")

    # Q2: CRT decryption correctness (100 random messages)
    print("\n[CRT Decryption Correctness (100 random messages)]")
    kp_test = rsa_keygen(bits=512)
    ok = verify_crt_correctness(kp_test, n_messages=100)
    print(f"  rsa_dec_crt == rsa_dec for 100 random messages: {ok}")
    assert ok, "CRT decryption must match standard!"

    # Q3: Performance benchmark (1024-bit and 2048-bit, 1000 decryptions)
    print("\n[CRT vs Standard RSA Decryption Benchmark (1000 decryptions)]")
    for bits in [1024, 2048]:
        print(f"  Generating {bits}-bit key pair...")
        kp = rsa_keygen(bits)
        result = benchmark_crt_speedup(kp, n_trials=1000)
        print(f"  {bits}-bit: standard={result['standard_ms']:.2f}ms, "
              f"CRT={result['crt_ms']:.2f}ms, speedup={result['speedup']:.1f}x")

    # Q4: Hastad broadcast attack
    demo_hastad_attack(bits=256)

    # Q5: Attack boundary analysis
    attack_boundary_analysis()

    # Q6: Padding defeats the attack
    demo_padding_defeats_hastad(bits=256)
