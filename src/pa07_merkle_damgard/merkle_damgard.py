"""
PA#7 — Merkle-Damgård Hash Framework
No crypto dependencies. Generic MD construction with proper padding.
"""

import struct
from typing import Callable


class MerkleDamgard:
    """
    Generic Merkle-Damgård hash construction.
    Given a compression function, IV, and block size, hashes arbitrary messages.
    
    MD-strengthening padding:
      M || 0x80 || 0x00* || <|M|>_64bit_bigendian
    padded to a multiple of block_size bytes.
    """

    def __init__(self, compress_fn: Callable[[bytes, bytes], bytes], iv: bytes, block_size: int):
        """
        compress_fn(chaining_value: bytes, block: bytes) -> bytes
        iv: initial chaining value (must be block_size bytes)
        block_size: in bytes
        """
        self.compress_fn = compress_fn
        self.iv = iv
        self.block_size = block_size

    def _pad(self, message: bytes) -> bytes:
        """
        Apply MD-strengthening (Merkle-Damgård) padding.
        Appends: 0x80 byte, zero bytes to fill, 8-byte big-endian length (in bits).
        Total length is a multiple of block_size.
        """
        msg_len_bits = len(message) * 8
        # Append 0x80
        padded = message + b'\x80'
        # Append zeros until length ≡ block_size - 8 (mod block_size)
        target = (self.block_size - 8) % self.block_size
        while len(padded) % self.block_size != target:
            padded += b'\x00'
        # Append 64-bit big-endian length
        padded += struct.pack('>Q', msg_len_bits)
        assert len(padded) % self.block_size == 0
        return padded

    def hash(self, message: bytes) -> bytes:
        """
        Hash `message` using the Merkle-Damgård construction.
        Returns the final chaining value as bytes.
        """
        padded = self._pad(message)
        cv = self.iv  # current chaining value
        for i in range(0, len(padded), self.block_size):
            block = padded[i:i + self.block_size]
            cv = self.compress_fn(cv, block)
        return cv

    def __call__(self, message: bytes) -> bytes:
        return self.hash(message)


# ── Toy compression functions for testing ────────────────────────────────────

def toy_xor_compress(cv: bytes, block: bytes) -> bytes:
    """XOR-based toy compression: cv XOR block (same length)."""
    assert len(cv) == len(block)
    return bytes(a ^ b for a, b in zip(cv, block))


def build_toy_hash(block_size: int = 16) -> MerkleDamgard:
    """Build a toy hash using XOR compression and zero IV."""
    iv = b'\x00' * block_size
    return MerkleDamgard(toy_xor_compress, iv, block_size)


# ── Collision propagation demo ────────────────────────────────────────────────

def demonstrate_collision_propagation(md: MerkleDamgard) -> None:
    """
    Show the MD security reduction: if two inputs collide under the
    compression function, they also collide under the full MD hash.
    This concretely illustrates why security of H reduces to security of h.
    """
    bs = md.block_size
    print("\n=== Collision Propagation Demo ===")
    print(f"  Compression function: toy_xor_compress (cv XOR block)")
    print(f"  Block size: {bs} bytes\n")

    # --- Step 1: Construct two blocks that collide under compression ---
    # For XOR compression: compress(cv, block) = cv XOR block
    # So compress(cv, block1) == compress(cv, block2) iff block1 == block2.
    # To get a real collision we need a different approach:
    # Build two MESSAGES M1, M2 that after MD padding, differ in one block
    # but produce the same final hash.
    #
    # For XOR: h(cv, B) = cv ^ B. If cv1 ^ B1 == cv2 ^ B2 at ANY step,
    # all subsequent chaining values match → full collision.
    #
    # Concrete construction: find M1, M2 whose padded forms differ in block 1
    # but where the first compression step produces the same output.
    # With IV=0: h(0, B1) = B1, h(0, B2) = B2. These only collide if B1==B2.
    #
    # Better: use the fact that XOR is its own inverse.
    # h(cv, B) = cv ^ B. So for any cv:
    #   h(cv, B) = h(cv ^ B ^ B', B')  (not useful directly)
    #
    # Simplest real collision for XOR: two multi-block messages where
    # blocks are rearranged s.t. final XOR is the same.
    # XOR is commutative, so any permutation of blocks gives the same
    # final chaining value! (This is exactly why XOR is a bad compression.)

    # Build two messages that, after padding, have the same blocks in
    # different order → same hash (XOR commutativity).
    # We construct raw padded content directly to control block order.

    # Two distinct blocks (besides the padding block)
    block_A = b'\x01' * bs
    block_B = b'\x02' * bs
    # Padding block: will be the same for both since total length is the same
    pad_block = struct.pack('>Q', (2 * bs) * 8).rjust(bs, b'\x80')
    # Actually, let's just use 2-block messages with swapped blocks.
    # M1 = blockA || blockB (raw, pre-padding)
    # M2 = blockB || blockA
    # After MD padding both get the same pad block appended.
    # XOR hash: IV ^ B1 ^ B2 ^ pad == IV ^ B2 ^ B1 ^ pad (commutative!)

    M1 = block_A + block_B
    M2 = block_B + block_A
    assert M1 != M2, "Messages must differ"

    H1 = md.hash(M1)
    H2 = md.hash(M2)

    print(f"  M1 = {block_A[:4].hex()}... || {block_B[:4].hex()}...  ({len(M1)} bytes)")
    print(f"  M2 = {block_B[:4].hex()}... || {block_A[:4].hex()}...  ({len(M2)} bytes)")
    print(f"  M1 ≠ M2: {M1 != M2}")
    print(f"\n  H(M1) = {H1.hex()}")
    print(f"  H(M2) = {H2.hex()}")
    print(f"  H(M1) == H(M2): {H1 == H2}  ← collision!")

    # Trace the chaining values to show where they converge
    print(f"\n  Chain trace for M1:")
    padded1 = md._pad(M1)
    cv = md.iv
    for i in range(0, len(padded1), bs):
        block = padded1[i:i + bs]
        cv_next = md.compress_fn(cv, block)
        print(f"    h({cv.hex()[:8]}..., {block.hex()[:8]}...) = {cv_next.hex()[:8]}...")
        cv = cv_next

    print(f"\n  Chain trace for M2:")
    padded2 = md._pad(M2)
    cv = md.iv
    for i in range(0, len(padded2), bs):
        block = padded2[i:i + bs]
        cv_next = md.compress_fn(cv, block)
        print(f"    h({cv.hex()[:8]}..., {block.hex()[:8]}...) = {cv_next.hex()[:8]}...")
        cv = cv_next

    print(f"\n  ⇒ XOR compression is commutative, so swapping blocks")
    print(f"    preserves the final digest. A secure compression function")
    print(f"    (like the DLP-based one in PA#8) prevents this.")
    assert H1 == H2, "Collision propagation should succeed for XOR compression"


if __name__ == "__main__":
    print("=== PA#7: Merkle-Damgård Framework ===\n")

    md = build_toy_hash(block_size=16)

    # Test cases
    test_cases = [
        (b"", "empty message"),
        (b"A" * 15, "15 bytes (single block - 1)"),
        (b"A" * 16, "16 bytes (exactly one block)"),
        (b"A" * 17, "17 bytes (one block + 1)"),
        (b"A" * 48, "48 bytes (three blocks)"),
        (b"Hello, World!", "arbitrary message"),
    ]

    print("Hash correctness tests:")
    for msg, desc in test_cases:
        h = md.hash(msg)
        print(f"  [{desc}] H({msg[:20]!r}{'...' if len(msg) > 20 else ''}) = {h.hex()}")

    # Determinism
    msg = b"determinism check"
    assert md.hash(msg) == md.hash(msg), "Hash must be deterministic!"
    print(f"\n  Determinism check passed.")

    # Distinct messages → distinct digests (toy hash, best effort)
    messages = [b"a", b"b", b"aa", b"ab", b"ba"]
    hashes = [md.hash(m).hex() for m in messages]
    print(f"\n  Distinct messages → distinct digests: {len(set(hashes)) == len(hashes)}")

    demonstrate_collision_propagation(md)
