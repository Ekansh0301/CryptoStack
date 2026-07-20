"""
PA#17 — CCA-Secure Public-Key Encryption (ElGamal + RSA Signatures)
Depends on: PA#15 (RSA_Signature), PA#16 (ElGamal)
Lineage: PA#17 → PA#15 → PA#12 → PA#13
         PA#17 → PA#16 → PA#11 → PA#13
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa11_dh.dh import DHGroup
from pa12_rsa.rsa import rsa_keygen, RSA_KeyPair
from pa15_signatures.signatures import RSA_Signature
from pa16_elgamal.elgamal import ElGamal_KeyPair, elgamal_keygen, elgamal_enc, elgamal_dec
from pa08_dlp_crhf.dlp_crhf import DLP_Hash


BOTTOM = None  # ⊥


class CCA_PKC:
    """
    CCA-Secure PKC via Sign-then-Encrypt.
    CCA_Enc(pk_enc, sk_sign, m): encrypt with ElGamal, sign the ciphertext.
    CCA_Dec(sk_enc, vk_sign, CE, sigma): verify signature, then decrypt.
    """

    def __init__(self, elgamal_kp: ElGamal_KeyPair, rsa_kp: RSA_KeyPair, hash_fn: DLP_Hash):
        self.elgamal_kp = elgamal_kp
        self.rsa_kp = rsa_kp
        self.sig = RSA_Signature(rsa_kp, hash_fn)

    def Enc(self, pk_enc: tuple, sk_sign: tuple, m: int) -> tuple:
        """
        Encrypt m with ElGamal pk_enc, sign the ciphertext with sk_sign.
        Returns (c1, c2, sigma).
        """
        # Encrypt
        c1, c2 = elgamal_enc(pk_enc, m)
        # Sign the ciphertext (c1 || c2 serialized)
        p_bytes = (self.elgamal_kp.group.p.bit_length() + 7) // 8
        ct_bytes = c1.to_bytes(p_bytes, 'big') + c2.to_bytes(p_bytes, 'big')
        sigma = self.sig.Sign(sk_sign, ct_bytes)
        return c1, c2, sigma

    def Dec(self, sk_enc: tuple, vk_sign: tuple, c1: int, c2: int, sigma: int):
        """
        Verify signature first, return ⊥ on failure. Then decrypt.
        """
        # Verify signature
        p_bytes = (self.elgamal_kp.group.p.bit_length() + 7) // 8
        ct_bytes = c1.to_bytes(p_bytes, 'big') + c2.to_bytes(p_bytes, 'big')
        if not self.sig.Verify(vk_sign, ct_bytes, sigma):
            return BOTTOM  # ⊥
        # Decrypt
        return elgamal_dec(sk_enc, c1, c2)


def ind_cca2_game(cca: CCA_PKC, trials: int = 50) -> float:
    """
    IND-CCA2 game. Adversary cannot tamper with challenge ciphertext.
    Tampered ciphertexts are rejected by signature verification.
    """
    import random
    pk_enc = cca.elgamal_kp.public_key
    sk_enc = cca.elgamal_kp.private_key
    pk_sign = cca.rsa_kp.public_key
    sk_sign = cca.rsa_kp.private_key
    group = cca.elgamal_kp.group

    correct = 0
    tampered_rejected = 0

    for _ in range(trials):
        b = random.randint(0, 1)
        m0 = group.random_exponent() % 1000 + 1
        m1 = group.random_exponent() % 1000 + 1
        m_c = m0 if b == 0 else m1

        # Challenge ciphertext
        c1, c2, sigma = cca.Enc(pk_enc, sk_sign, m_c)

        # Adversary tries tampered ciphertext
        c2_tampered = (c2 + 1) % group.p
        result_tampered = cca.Dec(sk_enc, pk_sign, c1, c2_tampered, sigma)
        if result_tampered is BOTTOM:
            tampered_rejected += 1

        # Dummy adversary guesses b=0
        b_guess = 0
        if b_guess == b:
            correct += 1

    advantage = abs(correct / trials - 0.5)
    return advantage, tampered_rejected


def contrast_with_elgamal_malleability(cca: CCA_PKC) -> None:
    """
    Show plain ElGamal is malleable but CCA version is not.
    """
    print("\n[Malleability Contrast: plain ElGamal vs CCA-PKC]")
    pk_enc = cca.elgamal_kp.public_key
    sk_enc = cca.elgamal_kp.private_key
    pk_sign = cca.rsa_kp.public_key
    sk_sign = cca.rsa_kp.private_key
    group = cca.elgamal_kp.group

    m = 42
    c1, c2, sigma = cca.Enc(pk_enc, sk_sign, m)

    # Try malleability on CCA ciphertext
    c2_prime = (2 * c2) % group.p
    result = cca.Dec(sk_enc, pk_sign, c1, c2_prime, sigma)
    print(f"  CCA-PKC: tampered (c1, 2c2) → {result} (expected ⊥)")

    # Plain ElGamal: malleable
    c1_eg, c2_eg = elgamal_enc(pk_enc, m)
    c2_eg_prime = (2 * c2_eg) % group.p
    m_mal = elgamal_dec(sk_enc, c1_eg, c2_eg_prime)
    print(f"  Plain ElGamal: tampered (c1, 2c2) → {m_mal} = 2*{m} mod p: {m_mal == (2*m)%group.p}")


if __name__ == "__main__":
    print("=== PA#17: CCA-Secure PKC ===")
    print("""
  Call-stack lineage (documented per plan):
  PA#17 Enc/Dec
  ├── PA#15 RSA_Signature (Sign/Verify)
  │   ├── PA#12 rsa_enc / rsa_dec / rsa_keygen
  │   │   └── PA#13 gen_prime, _square_and_multiply, miller_rabin
  │   └── PA#8 DLP_Hash
  │       ├── PA#7 MerkleDamgard
  │       └── PA#13 gen_safe_prime
  └── PA#16 elgamal_enc / elgamal_dec
      └── PA#11 DHGroup
          └── PA#13 gen_safe_prime, _square_and_multiply
    """)

    print("[Building components...]")
    dlp = DLP_Hash(bits=32)
    group = DHGroup(bits=64)
    elgamal_kp = elgamal_keygen(group)
    rsa_kp = rsa_keygen(bits=512)

    cca = CCA_PKC(elgamal_kp, rsa_kp, dlp)
    pk_enc = elgamal_kp.public_key
    sk_enc = elgamal_kp.private_key
    pk_sign = rsa_kp.public_key
    sk_sign = rsa_kp.private_key

    # Basic correctness
    print("\n[CCA-PKC Encrypt/Decrypt]")
    for m in [1, 100, 42]:
        c1, c2, sigma = cca.Enc(pk_enc, sk_sign, m)
        m_dec = cca.Dec(sk_enc, pk_sign, c1, c2, sigma)
        print(f"  Enc({m}) → Dec → {m_dec}, correct: {m == m_dec}")

    # Tampered ciphertext
    m = 99
    c1, c2, sigma = cca.Enc(pk_enc, sk_sign, m)
    c2_bad = (c2 + 1) % group.p
    result = cca.Dec(sk_enc, pk_sign, c1, c2_bad, sigma)
    print(f"\n  Tampered c2: Dec result = {result} (expected ⊥)")

    # IND-CCA2 game
    adv, rejected = ind_cca2_game(cca, trials=50)
    print(f"\n[IND-CCA2] advantage ≈ {adv:.3f}, tampered ciphertexts rejected: {rejected}/50")

    contrast_with_elgamal_malleability(cca)
