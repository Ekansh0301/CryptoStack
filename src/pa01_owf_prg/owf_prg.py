"""
PA#1 — One-Way Functions (OWF) and Pseudorandom Generators (PRG)
Depends on: PA#13 (gen_prime, gen_safe_prime)
"""

import os
import math
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa13_miller_rabin.miller_rabin import gen_safe_prime, is_prime, _square_and_multiply


# ── One-Way Function: DLP-based f(x) = g^x mod p ────────────────────────────

class DLPOneWayFunction:
    """
    OWF based on the Discrete Logarithm Problem.
    f(x) = g^x mod p, where p = 2q+1 is a safe prime, g generates the subgroup of order q.
    """

    def __init__(self, bits: int = 256):
        print(f"  [DLP-OWF] Generating {bits}-bit safe prime...")
        self.p, self.q = gen_safe_prime(bits)
        # Find generator of order-q subgroup
        # Any element h != 1, h != p-1 gives g = h^2 mod p as generator of Zq
        while True:
            h = 2 + int.from_bytes(os.urandom(bits // 8), 'big') % (self.p - 3)
            g = _square_and_multiply(h, 2, self.p)
            if g != 1:
                self.g = g
                break
        print(f"  [DLP-OWF] p={self.p.bit_length()}-bit, g={self.g.bit_length()}-bit")

    def evaluate(self, x: int) -> int:
        """f(x) = g^x mod p"""
        return _square_and_multiply(self.g, x % self.q, self.p)

    def random_input(self) -> int:
        """Sample a uniform random x from Zq."""
        return int.from_bytes(os.urandom(len(self.q.to_bytes((self.q.bit_length() + 7) // 8, 'big'))), 'big') % self.q

    def verify_hardness(self, trials: int = 5) -> None:
        """Demonstrate that random inversion fails (brute-force infeasible)."""
        print("\n  [OWF hardness] Inversion attempts (should all fail):")
        for _ in range(trials):
            x = self.random_input()
            y = self.evaluate(x)
            # Try brute-force for tiny range only (demonstration)
            found = None
            for candidate in range(min(10000, self.q)):
                if _square_and_multiply(self.g, candidate, self.p) == y:
                    found = candidate
                    break
            status = f"found={found}" if found is not None else "NOT FOUND in [0,10000]"
            print(f"    f({x % 10000}...) = {str(y)[:20]}... → inversion: {status}")


# ── Hard-core predicate (Goldreich-Levin bit) ────────────────────────────────

def goldreich_levin_bit(x: int, r: int, bit_length: int) -> int:
    """
    Goldreich-Levin hard-core predicate: inner product of x and r over Z_2.
    bit = popcount(x & r) mod 2
    """
    return bin(x & r).count('1') % 2


# ── PRG from OWF (HILL iterative construction) ────────────────────────────────

class OWF_PRG:
    """
    Pseudorandom Generator built from a DLP-OWF via HILL construction.
    For each iteration: seed s_i → f(s_i) = s_{i+1}, extract GL-bit as pseudorandom output.
    """

    def __init__(self, owf: DLPOneWayFunction):
        self.owf = owf
        self._state: int = 0
        self._r: int = 0  # GL random mask (fixed per seed)

    def seed(self, s: int) -> None:
        """Initialize with seed s ∈ Zq."""
        self._state = s % self.owf.q
        # Sample random mask r for GL predicate (fixed for this seeding)
        self._r = int.from_bytes(os.urandom((self.owf.q.bit_length() + 7) // 8), 'big') % self.owf.q

    def _next_bit(self) -> int:
        """Apply one OWF iteration and extract one pseudorandom bit."""
        bit = goldreich_levin_bit(self._state, self._r, self.owf.q.bit_length())
        self._state = self.owf.evaluate(self._state)
        return bit

    def next_bits(self, n: int) -> bytes:
        """Generate n pseudorandom bits, returned as ceil(n/8) bytes."""
        bits = [self._next_bit() for _ in range(n)]
        # Pack bits into bytes (MSB first)
        output = []
        for i in range(0, len(bits), 8):
            byte_bits = bits[i:i + 8]
            while len(byte_bits) < 8:
                byte_bits.append(0)
            byte_val = sum(b << (7 - j) for j, b in enumerate(byte_bits))
            output.append(byte_val)
        return bytes(output)

    def next_bytes(self, n_bytes: int) -> bytes:
        """Generate n_bytes of pseudorandom output."""
        return self.next_bits(n_bytes * 8)


# ── PRG from OWF (backward direction): f(s) = G(s) ──────────────────────────

class PRG_as_OWF:
    """
    Backward direction: Use PRG output as a OWF.
    f_G(s) = G(s) — inverting this recovers the PRG seed, which is hard.
    """

    def __init__(self, prg: OWF_PRG, output_bits: int = 64):
        self.prg = prg
        self.output_bits = output_bits

    def evaluate(self, s: int) -> bytes:
        """f(s) = G(s): run PRG from seed s, output fixed number of bits."""
        self.prg.seed(s)
        return self.prg.next_bits(self.output_bits)


# ── NIST SP 800-22 Statistical Tests ─────────────────────────────────────────

def _bits_from_bytes(data: bytes) -> list[int]:
    bits = []
    for byte in data:
        for i in range(7, -1, -1):
            bits.append((byte >> i) & 1)
    return bits


def nist_frequency_test(bits: list[int]) -> float:
    """Frequency (Monobit) Test. Returns p-value."""
    n = len(bits)
    s = sum(1 if b == 1 else -1 for b in bits)
    s_obs = abs(s) / math.sqrt(n)
    # Complementary error function approximation
    p_value = math.erfc(s_obs / math.sqrt(2))
    return p_value


def nist_runs_test(bits: list[int]) -> float:
    """Runs Test. Returns p-value."""
    n = len(bits)
    pi = sum(bits) / n
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0  # prerequisite fails

    v = 1 + sum(1 for i in range(n - 1) if bits[i] != bits[i + 1])
    num = abs(v - 2 * n * pi * (1 - pi))
    den = 2 * math.sqrt(2 * n) * pi * (1 - pi)
    p_value = math.erfc(num / den)
    return p_value


def nist_serial_test(bits: list[int]) -> float:
    """Serial (2-bit pattern) Test. Returns approximate p-value."""
    n = len(bits)
    # Count 2-bit patterns
    counts = {(0, 0): 0, (0, 1): 0, (1, 0): 0, (1, 1): 0}
    for i in range(n - 1):
        counts[(bits[i], bits[i + 1])] += 1
    total_pairs = n - 1
    # Chi-squared statistic (uniform expectation = total_pairs/4)
    expected = total_pairs / 4
    chi2 = sum((c - expected) ** 2 / expected for c in counts.values())
    # p-value from chi2 with 3 dof (approximate)
    import math
    # Use regularized incomplete gamma via series for chi2/2 with k/2=1.5
    # Simple approximation: use normal approximation for large n
    z = (chi2 - 3) / math.sqrt(6)  # standardized
    p_value = 0.5 * math.erfc(abs(z) / math.sqrt(2))
    return p_value


def run_nist_tests(data: bytes, label: str = "") -> dict:
    """Run three NIST tests and return p-values."""
    bits = _bits_from_bytes(data)
    results = {
        'frequency': nist_frequency_test(bits),
        'runs': nist_runs_test(bits),
        'serial': nist_serial_test(bits),
    }
    if label:
        print(f"\n  NIST tests [{label}]:")
        for name, p in results.items():
            status = "PASS" if p > 0.01 else "FAIL"
            print(f"    {name:12s}: p={p:.4f} [{status}]")
    return results


if __name__ == "__main__":
    print("=== PA#1: OWF + PRG ===\n")

    # Build OWF
    owf = DLPOneWayFunction(bits=128)

    # OWF evaluation demo
    print("\n[OWF] Evaluating f(x) = g^x mod p:")
    for _ in range(3):
        x = owf.random_input()
        y = owf.evaluate(x)
        print(f"  f({x.bit_length()}-bit x) = {str(y)[:30]}...")

    owf.verify_hardness()

    # Build PRG
    print("\n[PRG] HILL construction from OWF:")
    prg = OWF_PRG(owf)
    seed_val = owf.random_input()
    prg.seed(seed_val)

    output = prg.next_bytes(128)
    print(f"  PRG output (128 bytes): {output[:16].hex()}...")
    run_nist_tests(output, "PRG output")

    # Backward direction
    print("\n[PRG→OWF backward direction]:")
    prg_owf = PRG_as_OWF(prg, output_bits=64)
    s1 = owf.random_input()
    s2 = owf.random_input()
    out1 = prg_owf.evaluate(s1)
    out2 = prg_owf.evaluate(s2)
    print(f"  f_G(s1) = {out1.hex()}")
    print(f"  f_G(s2) = {out2.hex()}")
    print(f"  Outputs differ: {out1 != out2}")
