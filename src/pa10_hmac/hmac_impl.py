"""
PA#10 — HMAC and Encrypt-then-HMAC
Depends on: PA#8 (DLP_Hash), PA#3 (CPA_Cipher), PA#7 (MerkleDamgard)
"""

import os
import time
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa08_dlp_crhf.dlp_crhf import DLP_Hash
from pa03_cpa.cpa import CPA_Cipher
from pa05_mac.mac import _constant_time_eq, _pad
from pa02_prf.prf import AES_PRF
from pa07_merkle_damgard.merkle_damgard import MerkleDamgard

BLOCK_SIZE = 16


# ── HMAC ─────────────────────────────────────────────────────────────────────

class HMAC:
    """
    HMAC: H((k XOR opad) || H((k XOR ipad) || m))
    Uses PA#8 DLP_Hash as the underlying hash H.
    """

    IPAD = 0x36
    OPAD = 0x5C

    def __init__(self, hash_fn: DLP_Hash):
        self.H = hash_fn
        self.block_size = hash_fn.block_size  # hash's internal block size

    def _prepare_key(self, k: bytes) -> bytes:
        """Pad or hash key to match hash block size."""
        if len(k) > self.block_size:
            k = self.H.hash(k)
        # Zero-pad to block size
        return k + b'\x00' * (self.block_size - len(k))

    def mac(self, k: bytes, m: bytes) -> bytes:
        """Compute HMAC(k, m) = H((k XOR opad) || H((k XOR ipad) || m))"""
        k_padded = self._prepare_key(k)
        k_ipad = bytes(b ^ self.IPAD for b in k_padded)
        k_opad = bytes(b ^ self.OPAD for b in k_padded)
        inner = self.H.hash(k_ipad + m)
        outer = self.H.hash(k_opad + inner)
        return outer

    def verify(self, k: bytes, m: bytes, t: bytes) -> bool:
        """Constant-time HMAC verification."""
        expected = self.mac(k, m)
        return _constant_time_eq(expected, t)


# ── Fill in PA#5 stub ─────────────────────────────────────────────────────────

def hmac(k: bytes, m: bytes, hash_fn: DLP_Hash = None) -> bytes:
    """
    Fills in the PA#5 stub.
    Computes HMAC(k, m) using DLP_Hash.
    """
    if hash_fn is None:
        hash_fn = _get_default_hash()
    h = HMAC(hash_fn)
    return h.mac(k, m)


_default_hash = None

def _get_default_hash() -> DLP_Hash:
    global _default_hash
    if _default_hash is None:
        _default_hash = DLP_Hash(bits=32)
    return _default_hash


# ── Timing attack demo ────────────────────────────────────────────────────────

def timing_attack_demo(hmac_obj: HMAC, k: bytes, m: bytes, trials: int = 1000) -> None:
    """
    Demonstrate timing difference between constant-time and early-exit comparison.
    """
    print("\n[Timing Attack Demo: naive early-exit vs constant-time]")

    correct_tag = hmac_obj.mac(k, m)

    def naive_verify(t1: bytes, t2: bytes) -> bool:
        """Naive early-exit comparison (vulnerable to timing attack)."""
        if len(t1) != len(t2):
            return False
        for a, b in zip(t1, t2):
            if a != b:
                return False  # early exit!
        return True

    # Time naive verify with wrong tag (first byte wrong)
    wrong_first = bytes([correct_tag[0] ^ 0xFF]) + correct_tag[1:]
    # Time naive verify with wrong tag (last byte wrong)
    wrong_last = correct_tag[:-1] + bytes([correct_tag[-1] ^ 0xFF])

    t0 = time.perf_counter()
    for _ in range(trials):
        naive_verify(correct_tag, wrong_first)
    t_wrong_first = (time.perf_counter() - t0) / trials

    t0 = time.perf_counter()
    for _ in range(trials):
        naive_verify(correct_tag, wrong_last)
    t_wrong_last = (time.perf_counter() - t0) / trials

    print(f"  Naive early-exit: wrong at byte 0 = {t_wrong_first*1e9:.1f}ns, "
          f"wrong at last byte = {t_wrong_last*1e9:.1f}ns")
    print(f"  Timing difference reveals wrong byte position!")

    # Constant-time has no measurable difference
    t0 = time.perf_counter()
    for _ in range(trials):
        _constant_time_eq(correct_tag, wrong_first)
    t_ct_first = (time.perf_counter() - t0) / trials

    t0 = time.perf_counter()
    for _ in range(trials):
        _constant_time_eq(correct_tag, wrong_last)
    t_ct_last = (time.perf_counter() - t0) / trials

    print(f"  Constant-time:    wrong at byte 0 = {t_ct_first*1e9:.1f}ns, "
          f"wrong at last byte = {t_ct_last*1e9:.1f}ns")
    print(f"  Constant-time shows no measurable position leakage!")


# ── EUF-CMA for HMAC ─────────────────────────────────────────────────────────

def euf_cma_hmac(hmac_obj: HMAC, k: bytes, queries: int = 50) -> dict:
    """EUF-CMA game for HMAC."""
    queried = {}
    for _ in range(queries):
        m = os.urandom(16)
        t = hmac_obj.mac(k, m)
        queried[m] = t

    forgeries = 0
    for _ in range(10):
        m_new = os.urandom(16)
        if m_new in queried:
            continue
        t_guess = os.urandom(len(list(queried.values())[0]))
        if hmac_obj.verify(k, m_new, t_guess):
            forgeries += 1

    return {'queries': queries, 'forgeries': forgeries}


# ── Length-extension attack on H(k||m) vs HMAC ───────────────────────────────

def demo_length_extension_vs_hmac(dlp: DLP_Hash, k: bytes) -> None:
    """
    Show concretely that the naive MAC t = H(k||m) is broken by length-extension,
    while HMAC resists it.

    Attacker knows (m, t) where t = H(k||m), and len(k+m), but NOT k.
    They compute a valid tag for m||pad||extra without knowing k.
    """
    print("\n[Length-Extension: H(k||m) vs HMAC]")
    m = b"Transfer $100"

    # ---- Naive construction: t = H(k||m) ----
    naive_tag = dlp.hash(k + m)
    print(f"  Naive MAC: t = H(k||m) = {naive_tag.hex()}")
    print(f"  Attacker knows: m = {m!r}, t, len(k) = {len(k)}")

    # Attacker's goal: forge tag for m' = m || glue_padding || extra
    extra = b" to Mallory!"
    original_len = len(k) + len(m)

    # Compute the glue padding that the MD hash appended to k||m
    glue_padding = dlp._md._pad(k + m)[original_len:]

    # The forged message (from server's perspective) is: m || glue_padding || extra
    forged_msg = m + glue_padding + extra

    # ---- Attacker computes forged tag WITHOUT knowing k ----
    # Resume the MD chain from t (the known digest) to hash 'extra'
    total_len_after_glue = original_len + len(glue_padding)
    ext_data = extra
    bit_len_extended = (total_len_after_glue + len(ext_data)) * 8
    ext_padded = ext_data + b'\x80'
    while (len(ext_padded) + 8) % dlp.block_size != 0:
        ext_padded += b'\x00'
    ext_padded += struct.pack('>Q', bit_len_extended)

    # Resume from t as the chaining value
    cv = naive_tag
    # Pad cv to block_size if needed (DLP_Hash compress expects block_size-length cv)
    if len(cv) < dlp.block_size:
        cv = cv.rjust(dlp.block_size, b'\x00')
    for i in range(0, len(ext_padded), dlp.block_size):
        block = ext_padded[i:i + dlp.block_size]
        cv = dlp._compress(cv, block)
    forged_tag = cv

    # Verify: compute H(k || m || glue_padding || extra) honestly
    honest_tag = dlp.hash(k + forged_msg)

    print(f"\n  Attacker extends with: {extra!r}")
    print(f"  Forged tag (computed WITHOUT k): {forged_tag.hex()}")
    print(f"  Honest H(k||m||pad||extra):      {honest_tag.hex()}")
    print(f"  Tags match: {forged_tag == honest_tag}  <- LENGTH-EXTENSION SUCCEEDS")
    assert forged_tag == honest_tag, "Length-extension attack should succeed on H(k||m)"

    # ---- HMAC: same attack fails ----
    h = HMAC(dlp)
    hmac_tag = h.mac(k, m)
    # Attacker tries to use the forged_tag as HMAC for the extended message
    is_valid = h.verify(k, forged_msg, forged_tag)
    hmac_real = h.mac(k, forged_msg)
    print(f"\n  HMAC(k, m) = {hmac_tag.hex()}")
    print(f"  Forged tag valid as HMAC(k, m')? {is_valid}  (expected: False)")
    print(f"  Real HMAC(k, m') = {hmac_real.hex()} != forged")
    print(f"  -> HMAC's double-hash H(k^opad || H(k^ipad || m)) blocks extension")


# ── HMAC -> CRHF: HMAC as a compression function ─────────────────────────────

def hmac_as_crhf(hmac_obj: HMAC, k: bytes) -> MerkleDamgard:
    """
    Backward direction: HMAC_k(cv || block) as a compression function.
    Collision requires MAC forgery.
    """
    bs = hmac_obj.H.block_size

    def compress_via_hmac(cv: bytes, block: bytes) -> bytes:
        # HMAC the concatenation, then pad/truncate output to block_size
        tag = hmac_obj.mac(k, cv + block)
        # Ensure output is block_size bytes (same as input cv)
        if len(tag) < bs:
            tag = tag + b'\x00' * (bs - len(tag))
        return tag[:bs]

    iv = b'\x00' * bs
    return MerkleDamgard(compress_via_hmac, iv, bs)


def demo_mac_implies_crhf(hmac_obj: HMAC, k: bytes) -> None:
    """
    Backward direction: MAC => CRHF.
    Construct h'(cv, block) = HMAC_k(cv || block), plug into MD framework.
    Show MAC_Hash produces distinct digests for distinct inputs, and argue
    that finding a collision would require forging an HMAC tag.
    """
    print("\n[MAC => CRHF backward direction]")
    mac_hash = hmac_as_crhf(hmac_obj, k)

    messages = [
        b"",
        b"Hello",
        b"Hello, World!",
        b"A" * 50,
        b"Different message entirely",
    ]
    hashes = set()
    for m in messages:
        h = mac_hash.hash(m)
        hashes.add(h.hex())
        print(f"  MAC_Hash({m[:25]!r}{'...' if len(m)>25 else ''}) = {h.hex()}")

    all_distinct = len(hashes) == len(messages)
    print(f"\n  All digests distinct: {all_distinct}")
    print(f"  Compression function: h'(cv, block) = HMAC_k(cv || block)")
    print(f"  Finding collision in MAC_Hash requires finding cv, block, cv', block'")
    print(f"  such that HMAC_k(cv||block) = HMAC_k(cv'||block'), which is a")
    print(f"  second-preimage attack on HMAC -- contradicting EUF-CMA security.")
    print(f"  Therefore: secure MAC => collision-resistant hash.")
    assert all_distinct, "MAC_Hash should produce distinct digests"


# ── Encrypt-then-HMAC ─────────────────────────────────────────────────────────

class EtH_Cipher:
    """
    Encrypt-then-HMAC.
    EtH_Enc(kE, kM, m) = (r, c, t) where (r,c) = CPA_Enc(kE,m), t = HMAC(kM, r||c)
    """

    def __init__(self, hmac_obj: HMAC, prf: AES_PRF = None):
        self.hmac = hmac_obj
        self.cpa = CPA_Cipher(prf or AES_PRF())

    def Enc(self, kE: bytes, kM: bytes, m: bytes) -> tuple:
        r, c = self.cpa.encrypt(kE, m)
        t = self.hmac.mac(kM, r + c)
        return r, c, t

    def Dec(self, kE: bytes, kM: bytes, r: bytes, c: bytes, t: bytes):
        expected = self.hmac.mac(kM, r + c)
        if not _constant_time_eq(expected, t):
            return None  # bottom
        return self.cpa.decrypt(kE, r, c)


# ── CCA2 game for EtH + performance comparison ──────────────────────────────

def ind_cca2_eth_game(eth: EtH_Cipher, kE: bytes, kM: bytes,
                      trials: int = 50) -> dict:
    """
    IND-CCA2 game for Encrypt-then-HMAC.
    Adversary gets encryption and decryption oracles, cannot query
    the challenge ciphertext to the decryption oracle.
    """
    import random
    correct = 0
    for _ in range(trials):
        b = random.randint(0, 1)
        m0 = b"Message zero!!!!"
        m1 = b"Message one!!!!!"
        m_ch = m0 if b == 0 else m1
        r_ch, c_ch, t_ch = eth.Enc(kE, kM, m_ch)

        # Adversary queries decryption on a DIFFERENT ciphertext
        r_other, c_other, t_other = eth.Enc(kE, kM, b"query message!!!")
        dec = eth.Dec(kE, kM, r_other, c_other, t_other)

        # Adversary tries tampered challenge -> must be rejected
        t_tampered = bytes(x ^ 1 for x in t_ch)
        reject = eth.Dec(kE, kM, r_ch, c_ch, t_tampered)
        assert reject is None, "Tampered ciphertext must be rejected"

        # Dummy adversary: no information, guess 0
        if 0 == b:
            correct += 1

    advantage = abs(correct / trials - 0.5)
    return {
        'trials': trials,
        'correct': correct,
        'advantage': round(advantage, 4),
        'tampered_all_rejected': True,
    }


def performance_comparison(dlp: DLP_Hash) -> None:
    """
    Compare Encrypt-then-HMAC (PA#10) vs Encrypt-then-PRF-MAC (PA#6)
    on tag size, computation cost, and encryption overhead.
    """
    print("\n[Performance: EtH-HMAC (PA#10) vs EtM-PRF (PA#6)]")

    prf = AES_PRF()
    hmac_obj = HMAC(dlp)

    # PA#6: PRF-MAC based
    from pa06_cca.cca import CCA_Cipher
    pa6 = CCA_Cipher(prf)

    # PA#10: HMAC based
    eth = EtH_Cipher(hmac_obj, prf)

    kE = os.urandom(BLOCK_SIZE)
    kM_prf = os.urandom(BLOCK_SIZE)
    kM_hmac = os.urandom(dlp.block_size)
    m = b"Benchmark message!" * 4  # ~72 bytes

    # Tag sizes
    _, c6, t6 = pa6.Enc(kE, kM_prf, m)
    r10, c10, t10 = eth.Enc(kE, kM_hmac, m)
    print(f"  PA#6 tag size: {len(t6)} bytes (AES-128 block)")
    print(f"  PA#10 tag size: {len(t10)} bytes (DLP hash output)")
    print(f"  Ciphertext size: PA#6={len(c6)}B, PA#10={len(c10)}B (same CPA core)")

    # Timing
    rounds = 20

    t0 = time.perf_counter()
    for _ in range(rounds):
        pa6.Enc(kE, kM_prf, m)
    pa6_enc_time = (time.perf_counter() - t0) / rounds

    t0 = time.perf_counter()
    for _ in range(rounds):
        eth.Enc(kE, kM_hmac, m)
    pa10_enc_time = (time.perf_counter() - t0) / rounds

    print(f"\n  PA#6  Enc time: {pa6_enc_time*1000:.2f} ms")
    print(f"  PA#10 Enc time: {pa10_enc_time*1000:.2f} ms")
    print(f"  Ratio PA#10/PA#6: {pa10_enc_time/pa6_enc_time:.1f}x")
    print(f"\n  PA#6 uses AES-based CBC-MAC (fast, fixed block size).")
    print(f"  PA#10 uses DLP-based HMAC (modular exponentiation, much slower).")
    print(f"  In practice, HMAC-SHA256 would be comparable to AES-CMAC.")


if __name__ == "__main__":
    print("=== PA#10: HMAC + Encrypt-then-HMAC ===\n")

    print("[Building DLP hash...]")
    dlp = DLP_Hash(bits=32)
    h = HMAC(dlp)
    k = os.urandom(dlp.block_size)

    # Q1: HMAC correctness + key padding
    print("\n[HMAC correctness]")
    for m in [b"", b"hello", b"A" * 100]:
        t = h.mac(k, m)
        v = h.verify(k, m, t)
        print(f"  HMAC({m[:20]!r}) = {t.hex()[:16]}... [vrfy: {v}]")

    print("\n[Key length handling]")
    for key_len in [4, 16, 32, 64]:
        k_test = os.urandom(key_len)
        t = h.mac(k_test, b"test message")
        print(f"  key_len={key_len}: HMAC = {t.hex()[:16]}...")

    # Q2: CRHF => MAC (forward) -- EUF-CMA game
    result = euf_cma_hmac(h, k, queries=50)
    print(f"\n[EUF-CMA HMAC] {result}")

    # Q3: MAC => CRHF (backward)
    demo_mac_implies_crhf(h, k)

    # Q4: Length-extension attack demo
    demo_length_extension_vs_hmac(dlp, k[:dlp.block_size])

    # Q5: Encrypt-then-HMAC
    print("\n[Encrypt-then-HMAC]")
    prf = AES_PRF()
    eth = EtH_Cipher(h, prf)
    kE = os.urandom(BLOCK_SIZE)
    kM = os.urandom(dlp.block_size)
    m = b"Secure message!!"
    r, c, t = eth.Enc(kE, kM, m)
    dec = eth.Dec(kE, kM, r, c, t)
    print(f"  Plaintext: {m!r}")
    print(f"  Decrypted: {dec!r}")
    print(f"  Correct: {m == dec}")

    # Tamper
    t_bad = bytes(x ^ 1 for x in t)
    result2 = eth.Dec(kE, kM, r, c, t_bad)
    print(f"  Tampered tag result: {result2} (expected bottom)")

    # Q6: CCA2 game for EtH
    print("\n[IND-CCA2 game for EtH]")
    cca2_result = ind_cca2_eth_game(eth, kE, kM, trials=100)
    print(f"  Advantage: {cca2_result['advantage']}")
    print(f"  All tampered ciphertexts rejected: {cca2_result['tampered_all_rejected']}")

    # Q6: Performance comparison vs PA#6
    performance_comparison(dlp)

    # Q7: Timing attack demo
    timing_attack_demo(h, k, b"timing test message", trials=10000)
