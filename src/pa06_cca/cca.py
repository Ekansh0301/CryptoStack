"""
PA#6 — CCA-Secure Encryption (Encrypt-then-MAC)
Depends on: PA#3 (CPA_Cipher), PA#5 (CBC_MAC)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa02_prf.prf import AES_PRF
from pa03_cpa.cpa import CPA_Cipher
from pa05_mac.mac import CBC_MAC, _constant_time_eq

BLOCK_SIZE = 16
BOTTOM = None  # ⊥ sentinel


class CCA_Cipher:
    """
    CCA-secure encryption via Encrypt-then-MAC.
    CCA_Enc(kE, kM, m) = (r, c, t) where (r, c) = CPA_Enc(kE, m), t = MAC(kM, r||c)
    CCA_Dec(kE, kM, r, c, t): verify t first, return ⊥ on failure, then CPA_Dec.
    """

    def __init__(self, prf: AES_PRF = None):
        self.prf = prf or AES_PRF()
        self.cpa = CPA_Cipher(self.prf)
        self.mac = CBC_MAC(self.prf)

    def Enc(self, kE: bytes, kM: bytes, m: bytes) -> tuple:
        """Encrypt-then-MAC. Returns (r, c, t)."""
        assert len(kE) == BLOCK_SIZE and len(kM) == BLOCK_SIZE
        r, c = self.cpa.encrypt(kE, m)
        t = self.mac.Mac(kM, r + c)
        return r, c, t

    def Dec(self, kE: bytes, kM: bytes, r: bytes, c: bytes, t: bytes):
        """MAC-then-decrypt. Returns plaintext or ⊥."""
        assert len(kE) == BLOCK_SIZE and len(kM) == BLOCK_SIZE
        # Verify MAC first
        expected_t = self.mac.Mac(kM, r + c)
        if not _constant_time_eq(expected_t, t):
            return BOTTOM
        return self.cpa.decrypt(kE, r, c)


def demo_key_reuse(prf: AES_PRF) -> None:
    """Demonstrate key-reuse vulnerability (kE == kM)."""
    print("\n[Key-Reuse Vulnerability]")
    k = os.urandom(BLOCK_SIZE)
    cipher = CCA_Cipher(prf)

    # With same key for encryption and MAC, the scheme may be insecure
    m = b"Test message!!!!"
    r, c, t = cipher.Enc(k, k, m)  # kE == kM — insecure!

    # The tag is computed over ciphertext using same key used for encryption
    # An adversary who knows this may exploit the structure
    print(f"  kE == kM = {k.hex()}")
    print(f"  Tag computed with encryption key — scheme is insecure!")
    print(f"  Always use independent keys kE ≠ kM")


def demo_malleability_attack(prf: AES_PRF, kE: bytes, kM: bytes) -> None:
    """
    Demonstrate malleability attack on CPA alone vs CCA.
    On CPA-only cipher, flipping ciphertext bits flips plaintext bits.
    CCA cipher rejects tampered ciphertext.
    """
    print("\n[Malleability Attack Demo]")
    cpa = CPA_Cipher(prf)
    cca = CCA_Cipher(prf)

    m = b"Hello, World!!!!".ljust(BLOCK_SIZE)[:BLOCK_SIZE]

    # CPA: malleable
    r, c = cpa.encrypt(kE, m)
    c_tampered = bytearray(c)
    c_tampered[0] ^= 0xFF  # flip bits in first block
    c_tampered = bytes(c_tampered)
    try:
        m_tampered = cpa.decrypt(kE, r, c_tampered)
        print(f"  CPA accepts tampered ciphertext → m_tampered = {m_tampered!r}")
    except Exception as e:
        print(f"  CPA error on tampered (padding): {e}")

    # CCA: rejects tampered ciphertext
    r2, c2, t2 = cca.Enc(kE, kM, m)
    c2_tampered = bytearray(c2)
    c2_tampered[0] ^= 0xFF
    result = cca.Dec(kE, kM, r2, bytes(c2_tampered), t2)
    print(f"  CCA result on tampered ciphertext: {result} (expected ⊥ = None)")


def ind_cca2_game(cipher: CCA_Cipher, kE: bytes, kM: bytes, trials: int = 50) -> float:
    """
    IND-CCA2 game with dummy adversary.
    Adversary gets decryption oracle but cannot decrypt challenge ciphertext.
    """
    import random
    correct = 0
    for _ in range(trials):
        b = random.randint(0, 1)
        m0 = b"Message zero!!!!"
        m1 = b"Message one!!!!!"
        m_challenge = m0 if b == 0 else m1
        r_c, c_c, t_c = cipher.Enc(kE, kM, m_challenge)

        # Dummy adversary: can query decryption on other ciphertexts
        # but not (r_c, c_c, t_c) itself
        other_r, other_c = cipher.cpa.encrypt(kE, b"query message!!!")
        other_t = cipher.mac.Mac(kM, other_r + other_c)
        dec = cipher.Dec(kE, kM, other_r, other_c, other_t)

        # Guess b = 0 always (no information)
        b_guess = 0
        if b_guess == b:
            correct += 1

    advantage = abs(correct / trials - 0.5)
    return advantage


if __name__ == "__main__":
    print("=== PA#6: CCA-Secure Encryption ===\n")

    prf = AES_PRF()
    kE = os.urandom(BLOCK_SIZE)
    kM = os.urandom(BLOCK_SIZE)
    cipher = CCA_Cipher(prf)

    # Basic correctness
    print("[Encrypt-then-MAC correctness]")
    m = b"CCA secure message!"
    r, c, t = cipher.Enc(kE, kM, m)
    dec = cipher.Dec(kE, kM, r, c, t)
    print(f"  plaintext:  {m!r}")
    print(f"  decrypted:  {dec!r}")
    print(f"  correct: {m == dec}")

    # Tampered ciphertext → ⊥
    t_bad = bytes(x ^ 1 for x in t)
    result = cipher.Dec(kE, kM, r, c, t_bad)
    print(f"\n  Dec with bad tag: {result} (expected ⊥)")

    # IND-CCA2
    adv = ind_cca2_game(cipher, kE, kM, trials=100)
    print(f"\n[IND-CCA2 game] advantage ≈ {adv:.3f}")

    demo_malleability_attack(prf, kE, kM)
    demo_key_reuse(prf)
