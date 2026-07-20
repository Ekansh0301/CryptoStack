"""
PA#13 — Miller-Rabin Primality Test
No external crypto dependencies. Uses Python's built-in arbitrary-precision integers.
"""

import os
import time


def _square_and_multiply(base: int, exp: int, mod: int) -> int:
    """Own square-and-multiply modular exponentiation (benchmark/demo use)."""
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result


def miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin probabilistic primality test.
    k = number of witness rounds (k=40 gives error prob < 4^(-40)).
    Returns True if n is probably prime, False if definitely composite.
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d with d odd
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        # Pick random a in [2, n-2]
        a = 2 + int.from_bytes(os.urandom(32), 'big') % (n - 3)
        x = _square_and_multiply(a, d, n)

        if x == 1 or x == n - 1:
            continue

        composite = True
        for _ in range(r - 1):
            x = (x * x) % n
            if x == n - 1:
                composite = False
                break

        if composite:
            return False

    return True


def is_prime(n: int) -> bool:
    """Public interface: returns True if n is (probably) prime."""
    return miller_rabin(n, k=40)


def gen_prime(bits: int) -> int:
    """
    Generate a probable prime of exactly `bits` bits.
    Loops until a candidate passes 40 Miller-Rabin rounds,
    then sanity-checks with 100 rounds.
    """
    while True:
        # Generate random odd number with top bit set
        byte_len = (bits + 7) // 8
        candidate = int.from_bytes(os.urandom(byte_len), 'big')
        # Mask to exact bit count, then force top bit and bottom bit
        candidate &= (1 << bits) - 1
        candidate |= (1 << (bits - 1))  # set MSB
        candidate |= 1                   # make odd
        if miller_rabin(candidate, k=40):
            # Sanity check with 100 rounds as spec requires
            assert miller_rabin(candidate, k=100), "Sanity check failed!"
            return candidate


def gen_safe_prime(bits: int) -> tuple[int, int]:
    """
    Generate safe prime p = 2q + 1 where both p and q are prime.
    Returns (p, q).
    """
    while True:
        q = gen_prime(bits - 1)
        p = 2 * q + 1
        if miller_rabin(p, k=40):
            return p, q


def benchmark_prime_generation(bit_sizes: list[int], trials: int = 3) -> None:
    """
    Benchmark prime generation: report average candidates-before-prime
    and compare to the theoretical O(ln n) prediction from PNT.
    """
    import math
    print("\n=== Prime Generation Benchmark ===")
    print(f"  PNT prediction: ~b*ln(2)/2 odd candidates for a b-bit prime")
    print(f"  (density of primes near N is 1/ln(N); testing only odds halves it)\n")

    for bits in bit_sizes:
        times = []
        for _ in range(trials):
            count = 0
            t0 = time.time()
            while True:
                byte_len = (bits + 7) // 8
                candidate = int.from_bytes(os.urandom(byte_len), 'big')
                candidate &= (1 << bits) - 1
                candidate |= (1 << (bits - 1))
                candidate |= 1
                count += 1
                if miller_rabin(candidate, k=40):
                    break
            elapsed = time.time() - t0
            times.append((count, elapsed))
        avg_count = sum(t[0] for t in times) / trials
        avg_time = sum(t[1] for t in times) / trials
        theoretical = bits * math.log(2) / 2  # PNT: ln(2^b) / 2 for odd candidates
        print(f"  {bits:>5}-bit: avg {avg_count:>6.1f} candidates, "
              f"theory {theoretical:>6.1f} (ratio {avg_count/theoretical:.2f}), "
              f"{avg_time:.3f}s")


def naive_fermat_test(n: int, k: int = 20) -> bool:
    """
    Naive Fermat primality test: check a^{n-1} = 1 (mod n) for random a.
    Carmichael numbers fool this test (for witnesses coprime to n).
    """
    import math
    if n < 2:
        return False
    if n < 4:
        return True
    for _ in range(k):
        a = 2 + int.from_bytes(os.urandom(4), 'big') % (n - 3)
        # Skip witnesses that share a factor with n (real Fermat tests do this)
        if math.gcd(a, n) != 1:
            continue
        if _square_and_multiply(a, n - 1, n) != 1:
            return False
    return True  # Fermat says "probably prime"


def demonstrate_carmichael():
    """
    Demonstrate that 561 (smallest Carmichael number) passes naive Fermat
    but is correctly rejected by Miller-Rabin.
    """
    n = 561  # = 3 * 11 * 17
    print(f"\n=== Carmichael Number Demo ===")
    print(f"  561 = 3 x 11 x 17 (smallest Carmichael number)")
    print(f"  Carmichael numbers satisfy a^(n-1) = 1 mod n for all gcd(a,n)=1")
    print(f"  This fools the Fermat test but NOT Miller-Rabin.\n")

    # Fermat test: 561 passes (WRONG answer)
    fermat_result = naive_fermat_test(n, k=20)
    print(f"  naive_fermat_test(561, k=20) = {fermat_result}  (WRONG: says prime!)")

    # Miller-Rabin: 561 fails (CORRECT answer)
    mr_result = miller_rabin(n, k=40)
    print(f"  miller_rabin(561, k=40)      = {mr_result}  (CORRECT: composite)")
    assert not mr_result, "Miller-Rabin should detect 561 as composite!"

    # Test more Carmichael numbers
    carmichaels = [1105, 1729, 2465, 2821, 6601]
    print(f"\n  Other Carmichael numbers:")
    for c in carmichaels:
        f = naive_fermat_test(c, k=20)
        m = miller_rabin(c, k=40)
        print(f"    {c}: Fermat={f} (wrong), Miller-Rabin={m} (correct)")
        assert not m


if __name__ == "__main__":
    print("=== PA#13: Miller-Rabin Primality Test ===\n")

    # Basic correctness
    known_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 101, 1009, 104729]
    known_composites = [4, 6, 8, 9, 15, 100, 1000, 104730]

    print("Known primes (expect True):")
    for p in known_primes:
        print(f"  is_prime({p}) = {is_prime(p)}")

    print("\nKnown composites (expect False):")
    for c in known_composites:
        print(f"  is_prime({c}) = {is_prime(c)}")

    demonstrate_carmichael()

    print("\n=== Generating primes ===")
    for bits in [64, 128, 256]:
        t0 = time.time()
        p = gen_prime(bits)
        elapsed = time.time() - t0
        print(f"  {bits}-bit prime: {p} (generated in {elapsed:.3f}s)")

    benchmark_prime_generation([512, 1024, 2048], trials=2)

    print("\n=== Generating safe prime (small) ===")
    p, q = gen_safe_prime(64)
    print(f"  q = {q}")
    print(f"  p = 2q+1 = {p}")
    print(f"  is_prime(q) = {is_prime(q)}, is_prime(p) = {is_prime(p)}")
