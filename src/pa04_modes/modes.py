"""
PA#4 — Block Cipher Modes of Operation (CBC, OFB, CTR)
Depends on: PA#3 (CPA_Cipher, AES_PRF)
"""

import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from pa02_prf.prf import AES_PRF
from pa03_cpa.cpa import CPA_Cipher

BLOCK_SIZE = 16


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _pad(m: bytes) -> bytes:
    pad_len = BLOCK_SIZE - (len(m) % BLOCK_SIZE)
    return m + bytes([pad_len] * pad_len)


def _unpad(m: bytes) -> bytes:
    pad_len = m[-1]
    return m[:-pad_len]


# ── ECB Mode ──────────────────────────────────────────────────────────────────

def ecb_encrypt(prf: AES_PRF, k: bytes, m: bytes) -> tuple[bytes, bytes]:
    """ECB encryption. Each block encrypted independently — NOT IND-CPA secure."""
    padded = _pad(m)
    blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    ct_blocks = [prf.encrypt_block(k, block) for block in blocks]
    iv = bytes(BLOCK_SIZE)  # ECB has no IV; return zero bytes as placeholder
    return iv, b''.join(ct_blocks)


def ecb_decrypt(prf: AES_PRF, k: bytes, ct: bytes) -> bytes:
    """ECB decryption."""
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    pt_blocks = []
    for block in blocks:
        dec = _aes_decrypt_block(prf, k, block)
        pt_blocks.append(dec)
    return _unpad(b''.join(pt_blocks))


# ── CBC Mode ──────────────────────────────────────────────────────────────────

def cbc_encrypt(prf: AES_PRF, k: bytes, m: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    """CBC encryption. Returns (iv, ciphertext)."""
    iv = iv or os.urandom(BLOCK_SIZE)
    padded = _pad(m)
    blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    prev = iv
    ct_blocks = []
    for block in blocks:
        xored = _xor(block, prev)
        enc = prf.encrypt_block(k, xored)
        ct_blocks.append(enc)
        prev = enc
    return iv, b''.join(ct_blocks)


def cbc_decrypt(prf: AES_PRF, k: bytes, iv: bytes, ct: bytes) -> bytes:
    """CBC decryption."""
    SBOX_INV = _aes_inv_sbox()
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    prev = iv
    pt_blocks = []
    for block in blocks:
        dec = _aes_decrypt_block(prf, k, block)
        pt_blocks.append(_xor(dec, prev))
        prev = block
    return _unpad(b''.join(pt_blocks))


# ── OFB Mode ──────────────────────────────────────────────────────────────────

def ofb_encrypt(prf: AES_PRF, k: bytes, m: bytes, iv: bytes = None) -> tuple[bytes, bytes]:
    """OFB mode encryption (symmetric — same function for decryption)."""
    iv = iv or os.urandom(BLOCK_SIZE)
    padded = _pad(m)
    blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    ks_block = iv
    ct_blocks = []
    for block in blocks:
        ks_block = prf.encrypt_block(k, ks_block)
        ct_blocks.append(_xor(block, ks_block))
    return iv, b''.join(ct_blocks)


def ofb_decrypt(prf: AES_PRF, k: bytes, iv: bytes, ct: bytes) -> bytes:
    """OFB decryption: generate keystream from IV, XOR with ciphertext, then unpad."""
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    ks_block = iv
    pt_blocks = []
    for block in blocks:
        ks_block = prf.encrypt_block(k, ks_block)
        pt_blocks.append(_xor(block, ks_block))
    return _unpad(b''.join(pt_blocks))


# ── CTR Mode ──────────────────────────────────────────────────────────────────

def ctr_encrypt(prf: AES_PRF, k: bytes, m: bytes, nonce: bytes = None) -> tuple[bytes, bytes]:
    """CTR mode encryption."""
    nonce = nonce or os.urandom(8)
    padded = _pad(m)
    blocks = [padded[i:i+BLOCK_SIZE] for i in range(0, len(padded), BLOCK_SIZE)]
    ct_blocks = []
    for i, block in enumerate(blocks):
        ctr_block = nonce + i.to_bytes(BLOCK_SIZE - len(nonce), 'big')
        ks = prf.encrypt_block(k, ctr_block)
        ct_blocks.append(_xor(block, ks))
    return nonce, b''.join(ct_blocks)


def ctr_decrypt(prf: AES_PRF, k: bytes, nonce: bytes, ct: bytes) -> bytes:
    """CTR decryption: same keystream XOR, then unpad."""
    blocks = [ct[i:i+BLOCK_SIZE] for i in range(0, len(ct), BLOCK_SIZE)]
    pt_blocks = []
    for i, block in enumerate(blocks):
        ctr_block = nonce + i.to_bytes(BLOCK_SIZE - len(nonce), 'big')
        ks = prf.encrypt_block(k, ctr_block)
        pt_blocks.append(_xor(block, ks))
    return _unpad(b''.join(pt_blocks))


# ── Unified API ───────────────────────────────────────────────────────────────

def Encrypt(mode: str, k: bytes, m: bytes, prf: AES_PRF = None) -> tuple[bytes, bytes]:
    """Encrypt using specified mode. Returns (iv/nonce, ciphertext)."""
    prf = prf or AES_PRF()
    if mode == 'ECB':
        return ecb_encrypt(prf, k, m)
    elif mode == 'CBC':
        return cbc_encrypt(prf, k, m)
    elif mode == 'OFB':
        return ofb_encrypt(prf, k, m)
    elif mode == 'CTR':
        return ctr_encrypt(prf, k, m)
    else:
        raise ValueError(f"Unknown mode: {mode}")


def Decrypt(mode: str, k: bytes, iv: bytes, c: bytes, prf: AES_PRF = None) -> bytes:
    """Decrypt using specified mode."""
    prf = prf or AES_PRF()
    if mode == 'ECB':
        return ecb_decrypt(prf, k, c)
    elif mode == 'CBC':
        return cbc_decrypt(prf, k, iv, c)
    elif mode == 'OFB':
        return ofb_decrypt(prf, k, iv, c)
    elif mode == 'CTR':
        return ctr_decrypt(prf, k, iv, c)
    else:
        raise ValueError(f"Unknown mode: {mode}")


# ── AES inverse (for CBC decryption) ─────────────────────────────────────────

def _aes_inv_sbox():
    sbox = AES_PRF.SBOX
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv

INV_SBOX = None

def _aes_decrypt_block(prf: AES_PRF, key: bytes, ciphertext: bytes) -> bytes:
    """AES-128 decryption (inverse operations)."""
    global INV_SBOX
    if INV_SBOX is None:
        INV_SBOX = _aes_inv_sbox()

    def inv_shift_rows(state):
        for r in range(1, 4):
            state[r] = state[r][-r:] + state[r][:-r]
        return state

    def inv_sub_bytes(state):
        for r in range(4):
            for c in range(4):
                state[r][c] = INV_SBOX[state[r][c]]
        return state

    def inv_mix_columns(state):
        for c in range(4):
            s0,s1,s2,s3 = state[0][c],state[1][c],state[2][c],state[3][c]
            state[0][c] = prf._gmul(s0,14)^prf._gmul(s1,11)^prf._gmul(s2,13)^prf._gmul(s3,9)
            state[1][c] = prf._gmul(s0,9)^prf._gmul(s1,14)^prf._gmul(s2,11)^prf._gmul(s3,13)
            state[2][c] = prf._gmul(s0,13)^prf._gmul(s1,9)^prf._gmul(s2,14)^prf._gmul(s3,11)
            state[3][c] = prf._gmul(s0,11)^prf._gmul(s1,13)^prf._gmul(s2,9)^prf._gmul(s3,14)
        return state

    round_keys = prf._key_expansion(key)
    state = prf._state_from_bytes(ciphertext)
    state = prf._add_round_key(state, round_keys[10])
    for rnd in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = prf._add_round_key(state, round_keys[rnd])
        state = inv_mix_columns(state)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = prf._add_round_key(state, round_keys[0])
    return prf._state_to_bytes(state)


# ── Attack demonstrations ──────────────────────────────────────────────────────

def demo_cbc_iv_reuse(prf: AES_PRF, k: bytes) -> None:
    """CBC IV-reuse attack: equal plaintext blocks → equal ciphertext blocks."""
    print("\n[CBC IV-Reuse Attack]")
    fixed_iv = b'\x00' * BLOCK_SIZE
    m0 = b"Attack at dawn!!Secret payload!!"  # two blocks
    m1 = b"Attack at dawn!!Different data!!"  # same first block, different second
    _, c0 = cbc_encrypt(prf, k, m0, iv=fixed_iv)
    _, c1 = cbc_encrypt(prf, k, m1, iv=fixed_iv)
    # First blocks identical → first ciphertext blocks identical
    print(f"  Same plaintext block → same ciphertext block: {c0[:BLOCK_SIZE] == c1[:BLOCK_SIZE]}")
    # Second blocks differ → ciphertext blocks differ
    print(f"  Different plaintext block → different ciphertext block: {c0[BLOCK_SIZE:2*BLOCK_SIZE] != c1[BLOCK_SIZE:2*BLOCK_SIZE]}")

def demo_ofb_keystream_reuse(prf: AES_PRF, k: bytes) -> None:
    """OFB keystream-reuse: two messages with same IV → XOR reveals both."""
    print("\n[OFB Keystream-Reuse Attack]")
    fixed_iv = b'\x00' * BLOCK_SIZE
    m0 = b"Confidential Msg"
    m1 = b"TopSecret Info!!"
    _, c0 = ofb_encrypt(prf, k, m0, iv=fixed_iv)
    _, c1 = ofb_encrypt(prf, k, m1, iv=fixed_iv)
    xor_ct = _xor(c0[:BLOCK_SIZE], c1[:BLOCK_SIZE])
    xor_pt = _xor(m0[:BLOCK_SIZE], m1[:BLOCK_SIZE])
    print(f"  ct_xor = pt_xor: {xor_ct == xor_pt}")
    print(f"  Attacker who knows m0 can recover m1!")


if __name__ == "__main__":
    print("=== PA#4: Modes of Operation ===\n")
    prf = AES_PRF()
    k = os.urandom(BLOCK_SIZE)

    for mode in ['CBC', 'OFB', 'CTR']:
        print(f"[{mode} mode]")
        test_cases = [
            (b"Short msg", "< 1 block"),
            (b"Exactly sixteen.", "= 1 block"),
            (b"This message is longer than one block!", "> 1 block"),
        ]
        for m, desc in test_cases:
            iv, c = Encrypt(mode, k, m, prf)
            dec = Decrypt(mode, k, iv, c, prf)
            ok = m == dec
            print(f"  [{desc}] correct: {ok}")
        print()

    demo_cbc_iv_reuse(prf, k)
    demo_ofb_keystream_reuse(prf, k)
