"""
PA#8 — DLP-based Collision-Resistant Hash Function (CRHF)
Depends on: PA#7 (MerkleDamgard), PA#13 (gen_safe_prime)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa13_miller_rabin.miller_rabin import gen_safe_prime, _square_and_multiply
from pa07_merkle_damgard.merkle_damgard import MerkleDamgard


# ── DLP-based Compression Function ───────────────────────────────────────────

class DLP_Hash:
    """
    DLP-based CRHF via Merkle-Damgård.
    Compression: compress(x, y) = g^x * h^y mod p
    where p = 2q+1 (safe prime), g generates the subgroup of order q,
    h = g^alpha mod p for a randomly discarded alpha.
    """

    def __init__(self, bits: int = 64):
        print(f"  [DLP-Hash] Generating {bits}-bit safe prime...")
        self.p, self.q = gen_safe_prime(bits)
        self.bits = bits
        self.output_size = (bits + 7) // 8  # digest size in bytes
        # MD block_size must be large enough to hold the 8-byte length field.
        # Use max(output_size, 16) so padding arithmetic is always valid.
        self.block_size = max(self.output_size, 16)

        # Generator g: h = 2^2 mod p (squares give subgroup)
        h_base = 2
        self.g = _square_and_multiply(h_base, 2, self.p)
        assert self.g != 1, "g must not be 1"

        # h = g^alpha mod p for random discarded alpha
        alpha = int.from_bytes(os.urandom(self.output_size), 'big') % self.q
        self.h_hat = _square_and_multiply(self.g, alpha, self.p)
        # alpha is discarded: knowing it would allow collision finding

        # IV: fixed constant (padded to block_size)
        self.iv = (1).to_bytes(self.block_size, 'big')

        # Build MD framework
        self._md = MerkleDamgard(self._compress, self.iv, self.block_size)
        print(f"  [DLP-Hash] p={self.p.bit_length()}-bit, ready")

    def _compress(self, cv: bytes, block: bytes) -> bytes:
        """compress(x, y) = g^x * h^y mod p. Output is block_size bytes (padded)."""
        x = int.from_bytes(cv, 'big') % self.q
        y = int.from_bytes(block, 'big') % self.q
        result = (_square_and_multiply(self.g, x, self.p) *
                  _square_and_multiply(self.h_hat, y, self.p)) % self.p
        # Return padded to block_size
        raw = result.to_bytes(self.output_size, 'big')
        return raw.rjust(self.block_size, b'\x00')

    def hash(self, message: bytes) -> bytes:
        """Hash a message of arbitrary length. Returns digest bytes."""
        return self._md.hash(message)

    def __call__(self, message: bytes) -> bytes:
        return self.hash(message)


# ── Brute-force collision finder (toy parameters) ────────────────────────────

def find_collision_brute_force(dlp_hash: DLP_Hash, max_attempts: int = 100000) -> tuple:
    """
    Brute-force birthday collision finder for small (toy) hash.
    Returns (m1, m2, evaluations) with h(m1) == h(m2) and m1 != m2,
    or (None, None, evaluations) if no collision found.
    """
    seen = {}
    for i in range(max_attempts):
        m = i.to_bytes(4, 'big')
        h = dlp_hash.hash(m)
        h_key = h.hex()
        if h_key in seen and seen[h_key] != m:
            return seen[h_key], m, i + 1
        seen[h_key] = m
    return None, None, max_attempts


def find_collision_truncated(dlp_hash: DLP_Hash, trunc_bits: int = 16,
                             max_attempts: int = 10000) -> tuple:
    """
    Birthday collision finder on a TRUNCATED hash output.
    Truncates to `trunc_bits` bits before comparison.
    Returns (m1, m2, evaluations, trunc_hash_hex) or (None, None, evals, None).

    The full DLP hash is collision-resistant (by DLP hardness), so
    finding full collisions is infeasible. By truncating to n bits,
    we reduce the effective output space to 2^n, making birthday
    collisions achievable in O(2^{n/2}) evaluations.
    """
    trunc_bytes = (trunc_bits + 7) // 8
    mask = (1 << trunc_bits) - 1
    seen = {}
    for i in range(max_attempts):
        m = i.to_bytes(4, 'big')
        h = dlp_hash.hash(m)
        # Truncate: take last trunc_bytes, mask to exact bit count
        h_int = int.from_bytes(h[-trunc_bytes:], 'big') & mask
        h_key = format(h_int, f'0{(trunc_bits + 3) // 4}x')
        if h_key in seen and seen[h_key] != m:
            return seen[h_key], m, i + 1, h_key
        seen[h_key] = m
    return None, None, max_attempts, None


# ── Collision resistance argument ───────────────────────────────────────────

def collision_resistance_argument() -> str:
    """
    Return the formal argument for why finding collisions in h(x,y) = g^x · ĥ^y mod p
    requires computing log_g ĥ.
    """
    return """
    DLP Collision-Resistance Argument
    ═════════════════════════════════════
    Compression function: h(x, y) = g^x · ĥ^y mod p

    Claim: Finding (x,y) ≠ (x',y') with h(x,y) = h(x',y') ⇒ computing log_g ĥ.

    Proof:
      Suppose h(x,y) = h(x',y'), i.e., g^x · ĥ^y = g^x' · ĥ^y' (mod p).
      Then: g^(x-x') = ĥ^(y'-y) (mod p).
      If y' ≠ y (guaranteed since (x,y) ≠ (x',y')):
        ĥ = g^{(x-x') / (y'-y) mod q}  (mod p)
      So: α = log_g ĥ = (x - x') · (y' - y)^{-1} mod q.
      This recovers the secret α that was discarded at setup.

    Since α was chosen randomly and discarded, and the DLP is hard in
    the order-q subgroup of Z*_p, no efficient adversary can find α,
    and therefore cannot find collisions in h.
    """


if __name__ == "__main__":
    import math

    print("=== PA#8: DLP-CRHF ===\n")

    # Integration test: 32-bit hash for distinct-digest verification
    dlp = DLP_Hash(bits=32)

    print("\n[Integration test — 5 messages of different lengths]")
    messages = [
        b"",
        b"Hello",
        b"Hello, World!",
        b"A" * 50,
        b"The quick brown fox jumps over the lazy dog",
    ]
    hashes = set()
    for m in messages:
        h = dlp.hash(m)
        hashes.add(h.hex())
        print(f"  H({m[:20]!r}{'...' if len(m)>20 else ''}) = {h.hex()}")

    print(f"\n  All hashes distinct: {len(hashes) == len(messages)}")
    assert len(hashes) == len(messages), "Distinct inputs must produce distinct digests"

    # DLP hardness argument
    print("\n[Collision-resistance argument]")
    print(collision_resistance_argument())

    # Birthday collision demo with TRUNCATED output
    # Spec: "q ≈ 2^16, truncated to 16-bit output for the collision demo"
    # The full DLP hash is collision-resistant (injective for distinct inputs).
    # Truncation reduces the output space so birthday collisions are feasible.
    # Birthday bound on 16-bit output: O(2^8) = 256 evaluations.
    trunc_n = 16
    birthday_bound = 1 << (trunc_n // 2)  # 2^8 = 256

    print(f"[Birthday collision demo (truncated to {trunc_n}-bit output)]")
    print(f"  Using {dlp.bits}-bit DLP hash, truncated to {trunc_n} bits for demo")
    print(f"  Output space: 2^{trunc_n} = {1 << trunc_n}")
    print(f"  Birthday bound: O(2^{trunc_n//2}) = {birthday_bound}")
    print(f"  Searching for collision...")

    m1, m2, evals, h_trunc = find_collision_truncated(
        dlp, trunc_bits=trunc_n, max_attempts=birthday_bound * 20
    )
    if m1 is not None:
        h1_full = dlp.hash(m1)
        h2_full = dlp.hash(m2)
        print(f"\n  ✓ Collision found after {evals} evaluations!")
        print(f"  m1 = {m1.hex()}")
        print(f"  m2 = {m2.hex()}")
        print(f"  H(m1) = {h1_full.hex()}")
        print(f"  H(m2) = {h2_full.hex()}")
        print(f"  Truncated({trunc_n}-bit) match: 0x{h_trunc}")
        print(f"  Full hashes differ:  {h1_full != h2_full}  (as expected — CRHF is secure)")
        print(f"\n  Evaluations: {evals}  vs  birthday bound 2^{trunc_n//2} = {birthday_bound}")
        print(f"  Ratio evals/bound = {evals/birthday_bound:.2f}x  (expected O(1))")
    else:
        print(f"  No collision in {evals} attempts")
