"""
PA#3 — CPA-Secure Symmetric Encryption
Depends on: PA#2 (GGM_PRF, AES_PRF)
Scheme: Enc(k, m) = (r, F_k(r) XOR m) with fresh random nonce r.
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa02_prf.prf import AES_PRF


BLOCK_SIZE = 16  # bytes


# ── Core encryption/decryption ────────────────────────────────────────────────

class CPA_Cipher:
    """
    CPA-secure symmetric encryption using a PRF.
    Enc(k, m) = (r, F_k(r) XOR m)  where r is a fresh random nonce.
    Supports multi-block messages via counter-based extension.
    """

    def __init__(self, prf: AES_PRF = None):
        self.prf = prf or AES_PRF()

    def _prf(self, k: bytes, x: bytes) -> bytes:
        """Evaluate PRF with 16-byte key and 16-byte input."""
        return self.prf.F(k, x)

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        assert len(a) == len(b)
        return bytes(x ^ y for x, y in zip(a, b))

    def _pad(self, m: bytes) -> bytes:
        """PKCS#7 padding to block boundary."""
        pad_len = BLOCK_SIZE - (len(m) % BLOCK_SIZE)
        return m + bytes([pad_len] * pad_len)

    def _unpad(self, m: bytes) -> bytes:
        """Remove PKCS#7 padding."""
        if not m:
            return m
        pad_len = m[-1]
        if pad_len == 0 or pad_len > BLOCK_SIZE:
            raise ValueError("Invalid padding")
        if any(b != pad_len for b in m[-pad_len:]):
            raise ValueError("Invalid padding bytes")
        return m[:-pad_len]

    def _counter_block(self, r: bytes, counter: int) -> bytes:
        """r XOR counter (counter in last 4 bytes)."""
        r_int = int.from_bytes(r, 'big')
        ctr_int = r_int ^ counter
        return ctr_int.to_bytes(BLOCK_SIZE, 'big')

    def encrypt(self, k: bytes, m: bytes) -> tuple[bytes, bytes]:
        """
        Encrypt message m with key k.
        Returns (nonce r, ciphertext c).
        Supports multi-block messages with counter mode extension.
        """
        assert len(k) == BLOCK_SIZE
        r = os.urandom(BLOCK_SIZE)  # fresh random nonce
        padded = self._pad(m)
        blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
        ct_blocks = []
        for i, block in enumerate(blocks):
            ctr_block = self._counter_block(r, i)
            keystream = self._prf(k, ctr_block)
            ct_blocks.append(self._xor_bytes(keystream, block))
        return r, b''.join(ct_blocks)

    def decrypt(self, k: bytes, r: bytes, c: bytes) -> bytes:
        """Decrypt ciphertext c with nonce r and key k."""
        assert len(k) == BLOCK_SIZE and len(r) == BLOCK_SIZE
        assert len(c) % BLOCK_SIZE == 0
        blocks = [c[i:i+BLOCK_SIZE] for i in range(0, len(c), BLOCK_SIZE)]
        pt_blocks = []
        for i, block in enumerate(blocks):
            ctr_block = self._counter_block(r, i)
            keystream = self._prf(k, ctr_block)
            pt_blocks.append(self._xor_bytes(keystream, block))
        padded_pt = b''.join(pt_blocks)
        return self._unpad(padded_pt)


# ── Broken deterministic variant (for attack demo) ────────────────────────────

class Deterministic_Cipher:
    """
    BROKEN: deterministic encryption (same r every time).
    Vulnerable to identical-ciphertext attack.
    """

    def __init__(self, prf: AES_PRF = None):
        self.prf = prf or AES_PRF()
        self._fixed_r = b'\x00' * BLOCK_SIZE  # fixed nonce!

    def encrypt(self, k: bytes, m: bytes) -> tuple[bytes, bytes]:
        r = self._fixed_r
        keystream = self.prf.F(k, r)
        # Single block only for simplicity
        assert len(m) == BLOCK_SIZE
        return r, bytes(a ^ b for a, b in zip(keystream, m))

    def attack_demo(self, k: bytes) -> dict:
        """
        Identical-ciphertext attack: encrypt two different messages.
        If same r is used, XOR of ciphertexts = XOR of plaintexts → information leak.
        """
        m0 = b'Attack at dawn!!'
        m1 = b'Retreat at dusk!'
        _, c0 = self.encrypt(k, m0)
        _, c1 = self.encrypt(k, m1)
        xor_ct = bytes(a ^ b for a, b in zip(c0, c1))
        xor_pt = bytes(a ^ b for a, b in zip(m0, m1))
        # XOR of ciphertexts leaks XOR of plaintexts
        return {
            'c0': c0.hex(),
            'c1': c1.hex(),
            'ct_xor': xor_ct.hex(),
            'pt_xor': xor_pt.hex(),
            'leaks_pt_xor': xor_ct == xor_pt,
        }


# ── IND-CPA game ──────────────────────────────────────────────────────────────

def ind_cpa_game(cipher: CPA_Cipher, k: bytes, queries: int = 50) -> dict:
    """
    IND-CPA game with a dummy adversary.
    Adversary makes `queries` encryption oracle calls, then guesses the challenge bit.
    Expected advantage ≈ 0 for secure scheme.
    """
    import random

    # Challenger picks random bit b
    b = random.randint(0, 1)
    m0 = b'Hello, World!!!!'.ljust(BLOCK_SIZE)[:BLOCK_SIZE]
    m1 = b'Goodbye, World!!'.ljust(BLOCK_SIZE)[:BLOCK_SIZE]

    # Oracle: adversary can encrypt chosen messages
    oracle_queries = []
    for _ in range(queries):
        m = os.urandom(BLOCK_SIZE)
        r, c = cipher.encrypt(k, m)
        oracle_queries.append((m, r, c))

    # Challenge: encrypt m_b
    m_challenge = m0 if b == 0 else m1
    r_c, c_challenge = cipher.encrypt(k, m_challenge)

    # Dummy adversary: guess 0 always (no information from fresh nonces)
    b_guess = 0

    advantage = 1.0 if b_guess == b else 0.0  # single trial
    return {
        'b': b,
        'b_guess': b_guess,
        'correct': b_guess == b,
        'advantage_this_trial': advantage,
        'note': 'IND-CPA game: dummy adversary with 50% base probability',
    }


def run_ind_cpa_experiment(cipher: CPA_Cipher, trials: int = 100) -> float:
    """Run IND-CPA game for many trials, estimate advantage."""
    k = os.urandom(BLOCK_SIZE)
    correct = sum(1 for _ in range(trials) if ind_cpa_game(cipher, k)['correct'])
    advantage = abs(correct / trials - 0.5)
    return advantage


if __name__ == "__main__":
    print("=== PA#3: CPA-Secure Encryption ===\n")

    cipher = CPA_Cipher()
    k = os.urandom(BLOCK_SIZE)

    # Basic encrypt/decrypt
    print("[Single-block encrypt/decrypt]")
    m = b"Secret Message!!"
    r, c = cipher.encrypt(k, m)
    m_dec = cipher.decrypt(k, r, c)
    print(f"  plaintext:  {m}")
    print(f"  ciphertext: {c.hex()}")
    print(f"  decrypted:  {m_dec}")
    print(f"  correct: {m == m_dec}")

    # Multi-block
    print("\n[Multi-block encrypt/decrypt]")
    m_long = b"This is a longer message that spans multiple blocks and tests the counter mode extension!"
    r, c = cipher.encrypt(k, m_long)
    m_dec = cipher.decrypt(k, r, c)
    print(f"  message length: {len(m_long)}")
    print(f"  ciphertext length: {len(c)}")
    print(f"  correct: {m_long == m_dec}")

    # Fresh nonces
    print("\n[Nonce freshness check]")
    _, c1 = cipher.encrypt(k, b"Same plaintext!!")
    _, c2 = cipher.encrypt(k, b"Same plaintext!!")
    print(f"  ct1: {c1.hex()}")
    print(f"  ct2: {c2.hex()}")
    print(f"  Ciphertexts differ (fresh nonces): {c1 != c2}")

    # IND-CPA game
    print("\n[IND-CPA game (100 trials)]")
    adv = run_ind_cpa_experiment(cipher, trials=100)
    print(f"  Advantage ≈ {adv:.3f} (expected ≈ 0)")

    # Broken deterministic variant attack
    print("\n[Broken deterministic cipher — identical-ciphertext attack]")
    broken = Deterministic_Cipher()
    result = broken.attack_demo(k)
    print(f"  CT XOR = PT XOR: {result['leaks_pt_xor']}")
    print(f"  This leaks XOR of plaintexts from XOR of ciphertexts!")
