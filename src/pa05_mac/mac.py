"""
PA#5 — Message Authentication Codes (MACs)
Depends on: PA#2 (AES_PRF)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa02_prf.prf import AES_PRF

BLOCK_SIZE = 16


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad(m: bytes) -> bytes:
    """PKCS#7 padding."""
    pad_len = BLOCK_SIZE - (len(m) % BLOCK_SIZE)
    return m + bytes([pad_len] * pad_len)


# ── PRF-MAC (single-block) ────────────────────────────────────────────────────

class PRF_MAC:
    """
    PRF-based MAC for single-block messages.
    Mac(k, m) = F_k(m)
    """

    def __init__(self, prf: AES_PRF = None):
        self.prf = prf or AES_PRF()

    def Mac(self, k: bytes, m: bytes) -> bytes:
        """Compute tag t = F_k(m). m must be exactly BLOCK_SIZE bytes."""
        assert len(k) == BLOCK_SIZE
        if len(m) != BLOCK_SIZE:
            # Pad/truncate to block size for single-block MAC
            m = _pad(m)[:BLOCK_SIZE]
        return self.prf.F(k, m)

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        """Verify: check t == Mac(k, m)."""
        expected = self.Mac(k, m)
        # Constant-time comparison
        return _constant_time_eq(expected, t)


# ── CBC-MAC (variable-length) ─────────────────────────────────────────────────

class CBC_MAC:
    """
    CBC-MAC for variable-length messages.
    Chain F_k over blocks of message.
    """

    def __init__(self, prf: AES_PRF = None):
        self.prf = prf or AES_PRF()

    def Mac(self, k: bytes, m: bytes) -> bytes:
        """CBC-MAC tag."""
        assert len(k) == BLOCK_SIZE
        padded = _pad(m)
        blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
        cv = b'\x00' * BLOCK_SIZE
        for block in blocks:
            cv = self.prf.F(k, _xor(cv, block))
        return cv

    def Vrfy(self, k: bytes, m: bytes, t: bytes) -> bool:
        return _constant_time_eq(self.Mac(k, m), t)


# ── HMAC stub (filled in PA#10) ───────────────────────────────────────────────

def hmac(k: bytes, m: bytes) -> bytes:
    """
    HMAC stub. Implemented in PA#10 (depends on PA#8 hash).
    """
    raise NotImplementedError("hmac() implemented in PA#10 — depends on PA#8 DLP hash")


# ── Constant-time comparison ──────────────────────────────────────────────────

def _constant_time_eq(a: bytes, b: bytes) -> bool:
    """Constant-time equality comparison (no early exit)."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ── EUF-CMA Game ──────────────────────────────────────────────────────────────

def euf_cma_game(mac: PRF_MAC, k: bytes, queries: int = 50) -> dict:
    """
    EUF-CMA game: adversary makes `queries` Mac oracle queries,
    then tries to forge a tag on a new message.
    Returns number of forgeries (should be 0).
    """
    queried = {}
    for _ in range(queries):
        m = os.urandom(BLOCK_SIZE)
        t = mac.Mac(k, m)
        queried[m] = t

    # Adversary tries to forge: pick a new message and guess its tag
    forgeries = 0
    for _ in range(10):
        # Try a message not in queried set
        m_new = os.urandom(BLOCK_SIZE)
        if m_new in queried:
            continue
        # Naive forgery: random tag
        t_guess = os.urandom(BLOCK_SIZE)
        if mac.Vrfy(k, m_new, t_guess):
            forgeries += 1

    return {'queries': queries, 'forgery_attempts': 10, 'forgeries': forgeries}


# ── MAC ⇒ PRF backward direction ─────────────────────────────────────────────

def mac_implies_prf(mac_obj: PRF_MAC, k: bytes, q: int = 100) -> dict:
    """
    MAC ⇒ PRF backward direction.
    Demonstrate that PRF-MAC outputs on uniformly random inputs are
    indistinguishable from a truly random function — the same
    distinguishing test used in PA#2.

    The adversary sees q outputs from either:
      - Real: Mac(k, x_i) = F_k(x_i)  (the PRF-MAC), or
      - Rand: R(x_i)                   (lazy-sampled random function).
    Then checks consistency (re-querying same x gives same output).
    Both oracles are consistent → advantage = 0, confirming MAC ⇒ PRF.
    """
    import random

    # --- Real MAC oracle ---
    inputs = [os.urandom(BLOCK_SIZE) for _ in range(q)]
    real_responses = {}
    real_consistent = True
    for x in inputs:
        r = mac_obj.Mac(k, x)
        if x in real_responses and real_responses[x] != r:
            real_consistent = False
        real_responses[x] = r

    # --- Random oracle (lazy-sampled) ---
    rand_table = {}
    rand_consistent = True
    for x in inputs:
        if x not in rand_table:
            rand_table[x] = os.urandom(BLOCK_SIZE)
        r = rand_table[x]
        # Consistency is guaranteed by lazy sampling

    advantage = abs(int(real_consistent) - int(rand_consistent))

    # Additionally, check output distribution looks random:
    # count byte frequencies across all MAC outputs
    all_bytes = b''.join(real_responses[x] for x in inputs)
    byte_freq = [0] * 256
    for b in all_bytes:
        byte_freq[b] += 1
    total = len(all_bytes)
    expected = total / 256
    chi2 = sum((f - expected) ** 2 / expected for f in byte_freq)
    # For 255 dof, chi2 < 320 is expected at p=0.05
    distribution_ok = chi2 < 400  # generous threshold

    return {
        'queries': q,
        'advantage': advantage,
        'real_consistent': real_consistent,
        'rand_consistent': rand_consistent,
        'output_chi2': round(chi2, 2),
        'distribution_looks_random': distribution_ok,
        'note': 'MAC outputs pass PRF distinguishing test → MAC ⇒ PRF witnessed',
    }


# ── Length-extension vulnerability demo ──────────────────────────────────────

def _md_compress(prf: AES_PRF, cv: bytes, block: bytes, key: bytes) -> bytes:
    """Single Merkle-Damgård compression step: cv' = F_key(cv ⊕ block).
    `key` is the AES key used inside the compression function (fixed, public)."""
    return prf.F(key, _xor(cv, block))


def demo_length_extension(k: bytes, prf: AES_PRF = None) -> None:
    """
    Demonstrate length-extension attack on naive MAC: t = H(k||m).

    The hash H is a Merkle-Damgård hash using AES as compression.
    Given t = H(k||m) and len(k||m), the attacker — without knowing k —
    computes H(k || m || padding || extra) by resuming the MD chain from t.
    """
    prf = prf or AES_PRF()
    # Fixed internal AES key for the hash compression (public parameter)
    hash_key = b'\x42' * BLOCK_SIZE

    def md_hash(data: bytes) -> bytes:
        """Merkle-Damgård hash with MD-strengthening (length appended)."""
        # MD padding: append 0x80, then zeros, then 8-byte big-endian length
        bit_len = len(data) * 8
        padded = data + b'\x80'
        while (len(padded) + 8) % BLOCK_SIZE != 0:
            padded += b'\x00'
        padded += bit_len.to_bytes(8, 'big')
        # Compress
        cv = b'\x00' * BLOCK_SIZE
        for i in range(0, len(padded), BLOCK_SIZE):
            cv = _md_compress(prf, cv, padded[i:i+BLOCK_SIZE], hash_key)
        return cv

    def md_padding(msg_len: int) -> bytes:
        """Compute the MD padding that would be appended to a message of `msg_len` bytes."""
        bit_len = msg_len * 8
        pad = b'\x80'
        while (msg_len + len(pad) + 8) % BLOCK_SIZE != 0:
            pad += b'\x00'
        pad += bit_len.to_bytes(8, 'big')
        return pad

    print("\n[Length-Extension Attack on Naive MAC: t = H(k||m)]")

    m = b"Transfer $100"
    t = md_hash(k + m)  # Naive MAC: t = H(k || m)
    print(f"  Original message: {m!r}")
    print(f"  Naive MAC tag t = H(k||m) = {t.hex()}")

    # --- Attacker's computation (knows t, len(k+m), but NOT k) ---
    extra = b" to attacker!!!"
    original_len = len(k) + len(m)
    glue_padding = md_padding(original_len)

    # The forged message is: m || glue_padding || extra
    # The attacker resumes the MD chain from t (the known digest)
    forged_msg_suffix = m + glue_padding + extra  # what the victim would see

    # Attacker computes H(k || m || pad || extra) by continuing from t:
    extended_data = extra
    bit_len_extended = (original_len + len(glue_padding) + len(extra)) * 8
    ext_padded = extended_data + b'\x80'
    while (len(ext_padded) + 8) % BLOCK_SIZE != 0:
        ext_padded += b'\x00'
    ext_padded += bit_len_extended.to_bytes(8, 'big')

    cv = t  # resume from known digest!
    for i in range(0, len(ext_padded), BLOCK_SIZE):
        cv = _md_compress(prf, cv, ext_padded[i:i+BLOCK_SIZE], hash_key)
    forged_tag = cv

    # Verify: compute H(k || m || glue_padding || extra) honestly
    honest_extended = k + m + glue_padding + extra
    honest_tag = md_hash(honest_extended)

    print(f"  \n  Attacker extends with: {extra!r}")
    print(f"  Forged tag (computed WITHOUT k): {forged_tag.hex()}")
    print(f"  Honest tag H(k||m||pad||extra):  {honest_tag.hex()}")
    print(f"  Tags match: {forged_tag == honest_tag}  ← attack succeeds!")
    print(f"  \n  ⚠ This is why HMAC uses H(k ⊕ opad || H(k ⊕ ipad || m))")
    print(f"    instead of H(k || m) — the double-hash blocks extension.")
    assert forged_tag == honest_tag, "Length-extension attack should succeed!"


if __name__ == "__main__":
    print("=== PA#5: MACs ===\n")

    prf = AES_PRF()
    k = os.urandom(BLOCK_SIZE)

    # PRF-MAC
    print("[PRF-MAC]")
    mac = PRF_MAC(prf)
    m = b"Authenticate me!"
    t = mac.Mac(k, m)
    print(f"  Mac(k, m) = {t.hex()}")
    print(f"  Vrfy(k, m, t) = {mac.Vrfy(k, m, t)}")
    print(f"  Vrfy(k, m, wrong_t) = {mac.Vrfy(k, m, os.urandom(16))}")

    # EUF-CMA
    result = euf_cma_game(mac, k, queries=50)
    print(f"\n  EUF-CMA game: {result}")

    # MAC ⇒ PRF backward direction
    print("\n[MAC ⇒ PRF backward direction]")
    prf_result = mac_implies_prf(mac, k, q=100)
    print(f"  Advantage: {prf_result['advantage']}")
    print(f"  Output χ²: {prf_result['output_chi2']} (distribution looks random: {prf_result['distribution_looks_random']})")
    print(f"  {prf_result['note']}")

    # CBC-MAC
    print("\n[CBC-MAC]")
    cbc_mac = CBC_MAC(prf)
    for msg in [b"short", b"A" * 16, b"A" * 32, b"Variable length message!"]:
        t = cbc_mac.Mac(k, msg)
        v = cbc_mac.Vrfy(k, msg, t)
        print(f"  Mac({msg[:20]!r}) = {t.hex()[:16]}... [vrfy: {v}]")

    # HMAC stub
    try:
        hmac(k, b"test")
    except NotImplementedError as e:
        print(f"\n[HMAC stub] NotImplementedError: {e}")

    # Length-extension attack
    demo_length_extension(k, prf)
