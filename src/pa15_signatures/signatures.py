"""
PA#15 — Digital Signatures (RSA + DLP Hash)
Depends on: PA#12 (RSA), PA#8 (DLP_Hash)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa12_rsa.rsa import rsa_keygen, rsa_enc, rsa_dec, RSA_KeyPair
from pa08_dlp_crhf.dlp_crhf import DLP_Hash
from pa13_miller_rabin.miller_rabin import _square_and_multiply


# ── RSA Digital Signature ─────────────────────────────────────────────────────

class RSA_Signature:
    """
    RSA digital signature with DLP hash.
    Sign(sk, m) = H(m)^d mod n
    Verify(pk, m, sigma) = (sigma^e mod n == H(m))
    """

    def __init__(self, kp: RSA_KeyPair, hash_fn: DLP_Hash):
        self.kp = kp
        self.H = hash_fn
        self.n_bytes = (kp.n.bit_length() + 7) // 8

    def _hash_to_int(self, m: bytes) -> int:
        """Hash message and convert to integer, reduced mod n."""
        h = self.H.hash(m)
        h_int = int.from_bytes(h, 'big') % self.kp.n
        # Ensure non-zero (0^d = 0 is trivially forgeable)
        if h_int == 0:
            h_int = 1
        return h_int

    def Sign(self, sk: tuple, m: bytes) -> int:
        """Sign message m. Returns signature sigma = H(m)^d mod n."""
        n, d = sk
        h_int = self._hash_to_int(m)
        sigma = _square_and_multiply(h_int, d, n)
        return sigma

    def Verify(self, pk: tuple, m: bytes, sigma: int) -> bool:
        """Verify signature. Returns True iff sigma^e = H(m) (mod n)."""
        n, e = pk
        recovered = _square_and_multiply(sigma, e, n)
        h_int = self._hash_to_int(m)
        return recovered == h_int


# ── Hash-then-Sign Argument ───────────────────────────────────────────────────

def demo_multiplicative_forgery(kp: RSA_KeyPair, sig: RSA_Signature) -> None:
    """
    Demonstrate:
    Part 1: Raw RSA signing (no hash) is vulnerable to multiplicative forgery.
    Part 2: Hash-then-Sign defeats the same attack.
    """
    print("\n[Hash-then-Sign: why hashing is necessary]")

    # --- Part 1: Raw RSA signing (NO hash) -> forgery SUCCEEDS ---
    print("\n  Part 1: Raw RSA signing (no hash)")

    def raw_sign(m_int: int) -> int:
        return _square_and_multiply(m_int, kp.d, kp.n)

    def raw_verify(m_int: int, sigma: int) -> bool:
        recovered = _square_and_multiply(sigma, kp.e, kp.n)
        return recovered == m_int

    m1 = 100
    m2 = 200
    sigma_1 = raw_sign(m1)
    sigma_2 = raw_sign(m2)

    # Forged signature for m1*m2 without knowing d
    m_forged = (m1 * m2) % kp.n
    sigma_forged = (sigma_1 * sigma_2) % kp.n

    valid = raw_verify(m_forged, sigma_forged)
    print(f"    sigma_1 = Sign_raw({m1}), sigma_2 = Sign_raw({m2})")
    print(f"    Forged sig for {m_forged} = sigma_1 * sigma_2 mod N")
    print(f"    Raw verify({m_forged}, forged_sig) = {valid}  <- FORGERY SUCCEEDS!")
    assert valid, "Raw forgery should succeed"

    # --- Part 2: Hash-then-Sign -> same attack FAILS ---
    print("\n  Part 2: Hash-then-Sign (with DLP hash)")
    pk = kp.public_key
    sk = kp.private_key

    m1_bytes = m1.to_bytes(8, 'big')
    m2_bytes = m2.to_bytes(8, 'big')
    m_product_bytes = m_forged.to_bytes(8, 'big')

    sigma_h1 = sig.Sign(sk, m1_bytes)
    sigma_h2 = sig.Sign(sk, m2_bytes)

    # Adversary tries same trick: sigma_forged = sigma_h1 * sigma_h2
    sigma_h_forged = (sigma_h1 * sigma_h2) % kp.n

    # Verify on m1*m2
    valid_hashed = sig.Verify(pk, m_product_bytes, sigma_h_forged)
    print(f"    sigma_h1 = Sign(H({m1})), sigma_h2 = Sign(H({m2}))")
    print(f"    Forged sig = sigma_h1 * sigma_h2 mod N")
    print(f"    Verify(H({m_forged}), forged) = {valid_hashed}  <- FORGERY FAILS!")

    # Explain why
    h_m1 = sig._hash_to_int(m1_bytes)
    h_m2 = sig._hash_to_int(m2_bytes)
    h_product = sig._hash_to_int(m_product_bytes)
    print(f"\n    Why: H(m1)*H(m2) mod N = {(h_m1 * h_m2) % kp.n}")
    print(f"         H(m1*m2)          = {h_product}")
    print(f"         Equal? {(h_m1 * h_m2) % kp.n == h_product}  <- Hash is NOT homomorphic!")


# ── EUF-CMA Game ──────────────────────────────────────────────────────────────

def euf_cma_signature(sig: RSA_Signature, pk: tuple, sk: tuple, queries: int = 50) -> dict:
    """
    EUF-CMA game for signatures.
    Adversary gets signing oracle, tries to forge signature on new message.
    """
    signed = {}
    for _ in range(queries):
        m = os.urandom(16)
        s = sig.Sign(sk, m)
        signed[m] = s

    forgeries = 0
    for _ in range(10):
        m_new = os.urandom(16)
        if m_new in signed:
            continue
        # Adversary tries random signature
        sigma_guess = int.from_bytes(os.urandom(sig.n_bytes), 'big') % sig.kp.n
        if sig.Verify(pk, m_new, sigma_guess):
            forgeries += 1

    return {'queries': queries, 'forgeries': forgeries}


if __name__ == "__main__":
    print("=== PA#15: Digital Signatures ===\n")

    print("[Building components...]")
    kp = rsa_keygen(bits=512)
    dlp = DLP_Hash(bits=32)
    sig = RSA_Signature(kp, dlp)

    # Q1: Sign/verify
    print("\n[Sign and Verify]")
    pk = kp.public_key
    sk = kp.private_key
    for m in [b"Hello", b"Sign this message", b"A" * 100]:
        sigma = sig.Sign(sk, m)
        v = sig.Verify(pk, m, sigma)
        # Tamper with signature
        sigma_bad = (sigma + 1) % kp.n
        v_bad = sig.Verify(pk, m, sigma_bad)
        print(f"  Sign({m[:20]!r}): verify={v}, tampered={v_bad}")

    # Tamper with message
    sigma_test = sig.Sign(sk, b"message A")
    v_wrong = sig.Verify(pk, b"message B", sigma_test)
    print(f"\n  Sign('message A'), Verify('message B'): {v_wrong} (expected False)")

    # Q2: Hash-then-sign argument
    demo_multiplicative_forgery(kp, sig)

    # Q3: EUF-CMA game
    result = euf_cma_signature(sig, pk, sk, queries=50)
    print(f"\n[EUF-CMA game] {result}")
