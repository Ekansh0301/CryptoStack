"""
CS8.401 — Comprehensive Test Suite
Tests all PAs in dependency order.
Run: python tests/test_all.py
"""

import sys
import os
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []


def test(name, fn):
    try:
        fn()
        results.append((name, True, None))
        print(f"  {PASS}: {name}")
    except Exception as e:
        results.append((name, False, str(e)))
        print(f"  {FAIL}: {name} — {e}")
        if os.getenv("DEBUG"):
            traceback.print_exc()


# ═══════════════════════════════════════════════════════════════════════════════
# PA#13 — Miller-Rabin
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#13: Miller-Rabin ━━━")

from pa13_miller_rabin.miller_rabin import miller_rabin, is_prime, gen_prime, gen_safe_prime, _square_and_multiply

def t_mr_primes():
    for p in [2, 3, 5, 7, 11, 13, 17, 101, 104729]:
        assert is_prime(p), f"{p} should be prime"

def t_mr_composites():
    for c in [4, 6, 9, 15, 100, 1000]:
        assert not is_prime(c), f"{c} should be composite"

def t_mr_carmichael():
    for c in [561, 1105, 1729]:
        assert not is_prime(c), f"Carmichael {c} should be detected composite"

def t_mr_gen_prime():
    p = gen_prime(128)
    assert p.bit_length() >= 127, "prime bit length"
    assert is_prime(p), "generated prime should be prime"

def t_mr_gen_safe_prime():
    p, q = gen_safe_prime(64)
    assert is_prime(p) and is_prime(q), "both p and q must be prime"
    assert p == 2 * q + 1, "p = 2q+1"

def t_mr_square_and_multiply():
    assert _square_and_multiply(2, 10, 1000) == pow(2, 10, 1000)
    assert _square_and_multiply(3, 100, 97) == pow(3, 100, 97)

test("known primes identified", t_mr_primes)
test("known composites rejected", t_mr_composites)
test("carmichael numbers detected", t_mr_carmichael)
test("gen_prime produces valid prime", t_mr_gen_prime)
test("gen_safe_prime p=2q+1", t_mr_gen_safe_prime)
test("square-and-multiply correctness", t_mr_square_and_multiply)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#7 — Merkle-Damgård
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#7: Merkle-Damgård ━━━")

from pa07_merkle_damgard.merkle_damgard import MerkleDamgard, build_toy_hash

def t_md_empty():
    md = build_toy_hash(16)
    h = md.hash(b"")
    assert len(h) == 16

def t_md_deterministic():
    md = build_toy_hash(16)
    m = b"test message"
    assert md.hash(m) == md.hash(m)

def t_md_different_lengths():
    md = build_toy_hash(16)
    hashes = [md.hash(b"a" * i) for i in range(5)]
    # At least some should differ
    assert len(set(h.hex() for h in hashes)) > 1

def t_md_padding_multiple():
    md = build_toy_hash(16)
    for length in [0, 1, 15, 16, 17, 32, 33, 100]:
        padded = md._pad(b"x" * length)
        assert len(padded) % 16 == 0, f"padding should be block-aligned for len={length}"

test("MD hash of empty message", t_md_empty)
test("MD hash is deterministic", t_md_deterministic)
test("MD hash differs for different lengths", t_md_different_lengths)
test("MD padding is block-aligned", t_md_padding_multiple)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#2 — AES PRF (used throughout)
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#2: AES PRF ━━━")

import os
from pa02_prf.prf import AES_PRF

def t_aes_deterministic():
    prf = AES_PRF()
    k = os.urandom(16)
    x = os.urandom(16)
    assert prf.F(k, x) == prf.F(k, x)

def t_aes_different_keys():
    prf = AES_PRF()
    x = b"\x00" * 16
    k1, k2 = os.urandom(16), os.urandom(16)
    assert prf.F(k1, x) != prf.F(k2, x)

def t_aes_different_inputs():
    prf = AES_PRF()
    k = os.urandom(16)
    assert prf.F(k, b"\x00" * 16) != prf.F(k, b"\xff" * 16)

def t_aes_known_vector():
    # AES-128 known answer test (NIST FIPS 197 Appendix B)
    prf = AES_PRF()
    k = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    ct = prf.encrypt_block(k, pt)
    expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")
    assert ct == expected, f"AES KAT failed: {ct.hex()} != {expected.hex()}"

def t_aes_known_vector_c1():
    # AES-128 KAT (NIST FIPS 197 Appendix C.1, verified with PyCryptodome)
    prf = AES_PRF()
    k = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    ct = prf.encrypt_block(k, pt)
    expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert ct == expected, f"AES C.1 KAT failed: {ct.hex()}"

def t_aes_all_zeros():
    prf = AES_PRF()
    ct = prf.encrypt_block(b'\x00'*16, b'\x00'*16)
    expected = bytes.fromhex("66e94bd4ef8a2c3b884cfa59ca342b2e")
    assert ct == expected, f"AES zeros KAT failed: {ct.hex()}"

test("AES PRF deterministic", t_aes_deterministic)
test("AES PRF different keys → different outputs", t_aes_different_keys)
test("AES PRF different inputs → different outputs", t_aes_different_inputs)
test("AES-128 KAT Appendix B", t_aes_known_vector)
test("AES-128 KAT Appendix C.1", t_aes_known_vector_c1)
test("AES-128 all-zeros KAT", t_aes_all_zeros)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#3 — CPA-Secure Encryption
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#3: CPA Encryption ━━━")

from pa03_cpa.cpa import CPA_Cipher, run_ind_cpa_experiment

def t_cpa_single_block():
    c = CPA_Cipher()
    k = os.urandom(16)
    m = b"Hello, World!!!!"
    r, ct = c.encrypt(k, m)
    assert c.decrypt(k, r, ct) == m

def t_cpa_multi_block():
    c = CPA_Cipher()
    k = os.urandom(16)
    m = b"A" * 100
    r, ct = c.encrypt(k, m)
    assert c.decrypt(k, r, ct) == m

def t_cpa_fresh_nonces():
    c = CPA_Cipher()
    k = os.urandom(16)
    m = b"Same message!!!!"
    r1, c1 = c.encrypt(k, m)
    r2, c2 = c.encrypt(k, m)
    assert r1 != r2 or c1 != c2, "fresh nonces should produce different ciphertexts"

def t_cpa_advantage():
    c = CPA_Cipher()
    adv = run_ind_cpa_experiment(c, trials=100)
    assert adv < 0.15, f"IND-CPA advantage too high: {adv}"

test("CPA single-block encrypt/decrypt", t_cpa_single_block)
test("CPA multi-block encrypt/decrypt", t_cpa_multi_block)
test("CPA fresh nonces each encryption", t_cpa_fresh_nonces)
test("IND-CPA advantage ≈ 0", t_cpa_advantage)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#4 — Modes of Operation
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#4: Modes ━━━")

from pa04_modes.modes import Encrypt, Decrypt

prf4 = AES_PRF()
k4 = os.urandom(16)

def t_modes_cbc():
    for m in [b"short", b"x" * 16, b"y" * 50]:
        iv, c = Encrypt('CBC', k4, m, prf4)
        assert Decrypt('CBC', k4, iv, c, prf4) == m

def t_modes_ofb():
    for m in [b"short", b"x" * 16, b"y" * 50]:
        iv, c = Encrypt('OFB', k4, m, prf4)
        assert Decrypt('OFB', k4, iv, c, prf4) == m

def t_modes_ctr():
    for m in [b"short", b"x" * 16, b"y" * 50]:
        nonce, c = Encrypt('CTR', k4, m, prf4)
        assert Decrypt('CTR', k4, nonce, c, prf4) == m

test("CBC mode correctness", t_modes_cbc)
test("OFB mode correctness", t_modes_ofb)
test("CTR mode correctness", t_modes_ctr)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#5 — MACs
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#5: MACs ━━━")

from pa05_mac.mac import PRF_MAC, CBC_MAC

def t_prf_mac_verify():
    mac = PRF_MAC()
    k = os.urandom(16)
    m = b"Authenticate!!"
    t = mac.Mac(k, m)
    assert mac.Vrfy(k, m, t)
    assert not mac.Vrfy(k, m, os.urandom(16))

def t_cbc_mac_verify():
    mac = CBC_MAC()
    k = os.urandom(16)
    for m in [b"a", b"b" * 16, b"c" * 100]:
        t = mac.Mac(k, m)
        assert mac.Vrfy(k, m, t)

def t_mac_key_binding():
    mac = PRF_MAC()
    k1, k2 = os.urandom(16), os.urandom(16)
    m = b"Test message!!!!"
    t1 = mac.Mac(k1, m)
    assert not mac.Vrfy(k2, m, t1), "tag under k1 should fail under k2"

test("PRF-MAC verify", t_prf_mac_verify)
test("CBC-MAC verify multi-length", t_cbc_mac_verify)
test("MAC tag is key-bound", t_mac_key_binding)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#6 — CCA Encryption
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#6: CCA Encryption ━━━")

from pa06_cca.cca import CCA_Cipher

def t_cca_encrypt_decrypt():
    c = CCA_Cipher()
    kE, kM = os.urandom(16), os.urandom(16)
    m = b"CCA secure msg!!"
    r, ct, t = c.Enc(kE, kM, m)
    assert c.Dec(kE, kM, r, ct, t) == m

def t_cca_reject_tampered():
    c = CCA_Cipher()
    kE, kM = os.urandom(16), os.urandom(16)
    m = b"Message to test!"
    r, ct, t = c.Enc(kE, kM, m)
    bad_t = bytes(x ^ 1 for x in t)
    assert c.Dec(kE, kM, r, ct, bad_t) is None

def t_cca_reject_tampered_ct():
    c = CCA_Cipher()
    kE, kM = os.urandom(16), os.urandom(16)
    m = b"Message to test!"
    r, ct, t = c.Enc(kE, kM, m)
    bad_ct = bytes(x ^ 1 for x in ct)
    assert c.Dec(kE, kM, r, bad_ct, t) is None

test("CCA encrypt/decrypt", t_cca_encrypt_decrypt)
test("CCA rejects tampered tag", t_cca_reject_tampered)
test("CCA rejects tampered ciphertext", t_cca_reject_tampered_ct)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#8 — DLP-CRHF
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#8: DLP-CRHF ━━━")

from pa08_dlp_crhf.dlp_crhf import DLP_Hash

print("  [Building DLP hash — may take a moment...]")
dlp8 = DLP_Hash(bits=32)

def t_dlp_deterministic():
    assert dlp8.hash(b"hello") == dlp8.hash(b"hello")

def t_dlp_distinct():
    hashes = [dlp8.hash(b"msg" + bytes([i])) for i in range(10)]
    assert len(set(h.hex() for h in hashes)) > 5

def t_dlp_empty():
    h = dlp8.hash(b"")
    assert isinstance(h, bytes) and len(h) > 0

test("DLP hash deterministic", t_dlp_deterministic)
test("DLP hash distinct for different inputs", t_dlp_distinct)
test("DLP hash handles empty message", t_dlp_empty)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#9 — Birthday Attack
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#9: Birthday Attack ━━━")

from pa09_birthday.birthday import birthday_attack_naive, toy_hash_n_bits

def t_birthday_finds_collision():
    fn = lambda m: toy_hash_n_bits(m, 8)
    m1, m2, evals = birthday_attack_naive(fn, 8)
    assert fn(m1) == fn(m2), "should find collision"
    assert m1 != m2, "distinct messages"

def t_birthday_scales():
    fn8  = lambda m: toy_hash_n_bits(m, 8)
    fn16 = lambda m: toy_hash_n_bits(m, 16)
    _, _, e8  = birthday_attack_naive(fn8,  8)
    _, _, e16 = birthday_attack_naive(fn16, 16)
    assert e16 > e8, "16-bit needs more evaluations than 8-bit"

test("birthday attack finds collision (8-bit)", t_birthday_finds_collision)
test("birthday scales with hash size", t_birthday_scales)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#10 — HMAC
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#10: HMAC ━━━")

from pa10_hmac.hmac_impl import HMAC, EtH_Cipher

h10 = HMAC(dlp8)
k10 = os.urandom(dlp8.block_size)

def t_hmac_verify():
    t = h10.mac(k10, b"test message")
    assert h10.verify(k10, b"test message", t)

def t_hmac_wrong_key():
    t = h10.mac(k10, b"test")
    k2 = os.urandom(dlp8.block_size)
    assert not h10.verify(k2, b"test", t)

def t_hmac_wrong_msg():
    t = h10.mac(k10, b"test")
    assert not h10.verify(k10, b"test2", t)

def t_eth_correctness():
    eth = EtH_Cipher(h10)
    kE, kM = os.urandom(16), os.urandom(dlp8.block_size)
    m = b"Secure msg!!"
    r, c, t = eth.Enc(kE, kM, m)
    assert eth.Dec(kE, kM, r, c, t) == m

def t_eth_rejects_tamper():
    eth = EtH_Cipher(h10)
    kE, kM = os.urandom(16), os.urandom(dlp8.block_size)
    m = b"Secure msg!!"
    r, c, t = eth.Enc(kE, kM, m)
    assert eth.Dec(kE, kM, r, c, bytes(x^1 for x in t)) is None

test("HMAC verify", t_hmac_verify)
test("HMAC fails wrong key", t_hmac_wrong_key)
test("HMAC fails wrong message", t_hmac_wrong_msg)
test("Encrypt-then-HMAC correctness", t_eth_correctness)
test("Encrypt-then-HMAC rejects tamper", t_eth_rejects_tamper)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#11 — Diffie-Hellman
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#11: Diffie-Hellman ━━━")

from pa11_dh.dh import DHGroup, dh_alice_step1, dh_bob_step1, dh_alice_step2, dh_bob_step2

print("  [Building DH group...]")
dh_group = DHGroup(bits=64)

def t_dh_key_agreement():
    a, A = dh_alice_step1(dh_group)
    b, B = dh_bob_step1(dh_group)
    KA = dh_alice_step2(dh_group, a, B)
    KB = dh_bob_step2(dh_group, b, A)
    assert KA == KB, "shared secrets must match"

def t_dh_fresh_each_time():
    a1, A1 = dh_alice_step1(dh_group)
    a2, A2 = dh_alice_step1(dh_group)
    assert A1 != A2 or a1 != a2, "fresh exponents each call"

test("DH key agreement: KA == KB", t_dh_key_agreement)
test("DH generates fresh exponents", t_dh_fresh_each_time)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#12 — RSA
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#12: RSA ━━━")

from pa12_rsa.rsa import rsa_keygen, rsa_enc, rsa_dec, rsa_enc_pkcs1, rsa_dec_pkcs1, mod_inverse, extended_gcd

print("  [Generating RSA key pair...]")
rsa_kp = rsa_keygen(bits=512)

def t_rsa_enc_dec():
    m = 42
    c = rsa_enc(rsa_kp.public_key, m)
    assert rsa_dec(rsa_kp.private_key, c) == m

def t_rsa_deterministic():
    m = 123
    c1 = rsa_enc(rsa_kp.public_key, m)
    c2 = rsa_enc(rsa_kp.public_key, m)
    assert c1 == c2, "textbook RSA is deterministic"

def t_rsa_pkcs1():
    m = b"Hello RSA"
    c = rsa_enc_pkcs1(rsa_kp.public_key, m)
    assert rsa_dec_pkcs1(rsa_kp.private_key, c) == m

def t_rsa_pkcs1_random():
    m = b"Same"
    c1 = rsa_enc_pkcs1(rsa_kp.public_key, m)
    c2 = rsa_enc_pkcs1(rsa_kp.public_key, m)
    assert c1 != c2, "PKCS#1 v1.5 is randomized"

def t_ext_gcd():
    g, x, y = extended_gcd(35, 15)
    assert g == 5
    assert 35 * x + 15 * y == 5

def t_mod_inverse():
    assert mod_inverse(3, 11) == 4  # 3*4=12≡1 mod 11
    assert mod_inverse(7, 26) == 15

test("RSA encrypt/decrypt", t_rsa_enc_dec)
test("RSA textbook is deterministic", t_rsa_deterministic)
test("RSA PKCS#1 v1.5 round-trip", t_rsa_pkcs1)
test("RSA PKCS#1 v1.5 is randomized", t_rsa_pkcs1_random)
test("extended GCD", t_ext_gcd)
test("modular inverse", t_mod_inverse)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#14 — CRT
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#14: CRT ━━━")

from pa14_crt.crt import crt, rsa_dec_crt, integer_nth_root

def t_crt_basic():
    x = crt([2, 3, 2], [3, 5, 7])
    assert x % 3 == 2 and x % 5 == 3 and x % 7 == 2

def t_crt_dec_matches():
    m = 100
    c = rsa_enc(rsa_kp.public_key, m)
    assert rsa_dec_crt(rsa_kp, c) == rsa_dec(rsa_kp.private_key, c)

def t_integer_nth_root():
    root, exact = integer_nth_root(27, 3)
    assert root == 3 and exact
    root2, exact2 = integer_nth_root(1024, 10)
    assert root2 == 2 and exact2

test("CRT basic", t_crt_basic)
test("CRT decryption matches standard", t_crt_dec_matches)
test("integer nth root", t_integer_nth_root)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#15 — Signatures
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#15: Signatures ━━━")

from pa15_signatures.signatures import RSA_Signature

sig15 = RSA_Signature(rsa_kp, dlp8)
pk15, sk15 = rsa_kp.public_key, rsa_kp.private_key

def t_sig_verify():
    m = b"Sign me"
    sigma = sig15.Sign(sk15, m)
    assert sig15.Verify(pk15, m, sigma)

def t_sig_wrong_msg():
    sigma = sig15.Sign(sk15, b"message A")
    assert not sig15.Verify(pk15, b"message B", sigma)

def t_sig_tampered():
    m = b"Original"
    sigma = sig15.Sign(sk15, m)
    assert not sig15.Verify(pk15, m, (sigma + 1) % rsa_kp.n)

test("signature sign and verify", t_sig_verify)
test("signature fails on wrong message", t_sig_wrong_msg)
test("signature fails on tampered sigma", t_sig_tampered)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#16 — ElGamal
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#16: ElGamal ━━━")

from pa16_elgamal.elgamal import elgamal_keygen, elgamal_enc, elgamal_dec

eg_kp = elgamal_keygen(dh_group)

def t_eg_enc_dec():
    m = 42
    c1, c2 = elgamal_enc(eg_kp.public_key, m)
    assert elgamal_dec(eg_kp.private_key, c1, c2) == m

def t_eg_malleable():
    m = 50
    c1, c2 = elgamal_enc(eg_kp.public_key, m)
    c2p = (2 * c2) % dh_group.p
    m2 = elgamal_dec(eg_kp.private_key, c1, c2p)
    assert m2 == (2 * m) % dh_group.p

test("ElGamal encrypt/decrypt", t_eg_enc_dec)
test("ElGamal malleability (c1, 2c2) → 2m", t_eg_malleable)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#17 — CCA-PKC
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#17: CCA-PKC ━━━")

from pa17_cca_pkc.cca_pkc import CCA_PKC

cca17 = CCA_PKC(eg_kp, rsa_kp, dlp8)
pk_e = eg_kp.public_key
sk_e = eg_kp.private_key
pk_s = rsa_kp.public_key
sk_s = rsa_kp.private_key

def t_cca_pkc_correct():
    m = 100
    c1, c2, sigma = cca17.Enc(pk_e, sk_s, m)
    assert cca17.Dec(sk_e, pk_s, c1, c2, sigma) == m

def t_cca_pkc_rejects_tamper():
    m = 100
    c1, c2, sigma = cca17.Enc(pk_e, sk_s, m)
    c2_bad = (c2 + 1) % dh_group.p
    assert cca17.Dec(sk_e, pk_s, c1, c2_bad, sigma) is None

test("CCA-PKC correct", t_cca_pkc_correct)
test("CCA-PKC rejects tampered ciphertext", t_cca_pkc_rejects_tamper)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#18 — Oblivious Transfer
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#18: Oblivious Transfer ━━━")

from pa18_ot.ot import OT_Receiver_Step1, OT_Sender_Step, OT_Receiver_Step2

def t_ot_correct_b0():
    m0, m1 = 42, 99
    pk0, pk1, state = OT_Receiver_Step1(dh_group, 0)
    C0, C1 = OT_Sender_Step(dh_group, pk0, pk1, m0, m1)
    assert OT_Receiver_Step2(state, C0, C1) == m0

def t_ot_correct_b1():
    m0, m1 = 42, 99
    pk0, pk1, state = OT_Receiver_Step1(dh_group, 1)
    C0, C1 = OT_Sender_Step(dh_group, pk0, pk1, m0, m1)
    assert OT_Receiver_Step2(state, C0, C1) == m1

def t_ot_many_trials():
    correct = 0
    for _ in range(20):
        b = int.from_bytes(os.urandom(1), 'big') % 2
        m0 = int.from_bytes(os.urandom(3), 'big') % (dh_group.p - 1) + 1
        m1 = int.from_bytes(os.urandom(3), 'big') % (dh_group.p - 1) + 1
        pk0, pk1, state = OT_Receiver_Step1(dh_group, b)
        C0, C1 = OT_Sender_Step(dh_group, pk0, pk1, m0, m1)
        got = OT_Receiver_Step2(state, C0, C1)
        if got == (m0 if b == 0 else m1):
            correct += 1
    assert correct == 20, f"OT failed {20-correct}/20 trials"

test("OT: receiver gets m0 when b=0", t_ot_correct_b0)
test("OT: receiver gets m1 when b=1", t_ot_correct_b1)
test("OT: 20 random trials", t_ot_many_trials)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#19 — Secure Gates
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#19: Secure Gates ━━━")

from pa19_secure_and.secure_and import Secure_AND, Secure_XOR, Secure_NOT

def t_and_truth_table():
    for a in range(2):
        for b in range(2):
            assert Secure_AND(dh_group, a, b) == (a & b)

def t_xor_truth_table():
    for a in range(2):
        for b in range(2):
            assert Secure_XOR(a, b) == (a ^ b)

def t_not_truth_table():
    for a in range(2):
        assert Secure_NOT(a) == (1 - a)

test("Secure AND truth table", t_and_truth_table)
test("Secure XOR truth table", t_xor_truth_table)
test("Secure NOT truth table", t_not_truth_table)


# ═══════════════════════════════════════════════════════════════════════════════
# PA#20 — MPC Circuits
# ═══════════════════════════════════════════════════════════════════════════════
print("\n━━━ PA#20: MPC Circuits ━━━")

from pa20_mpc.mpc import (build_equality_circuit, build_millionaires_circuit,
                           build_addition_circuit, Secure_Eval)

def t_equality_circuit():
    c = build_equality_circuit(4)
    for x, y, expected in [(5, 5, 1), (3, 4, 0), (0, 0, 1), (15, 14, 0)]:
        xb = [(x >> (3-i)) & 1 for i in range(4)]
        yb = [(y >> (3-i)) & 1 for i in range(4)]
        out, _, _, _ = Secure_Eval(c, xb, yb, dh_group)
        assert out[0] == expected, f"equality({x},{y}) expected {expected} got {out[0]}"

def t_millionaires_circuit():
    c = build_millionaires_circuit(4)
    for x, y, expected in [(5, 3, 1), (3, 5, 0), (4, 4, 0)]:
        xb = [(x >> (3-i)) & 1 for i in range(4)]
        yb = [(y >> (3-i)) & 1 for i in range(4)]
        out, _, _, _ = Secure_Eval(c, xb, yb, dh_group)
        assert out[0] == expected, f"gt({x},{y}) expected {expected} got {out[0]}"

def t_addition_circuit():
    # Circuit outputs n+1 bits: [carry, sum_{n-1}, ..., sum_0]
    # mod-2^n result = interpret out[1:] (drop carry bit out[0])
    c = build_addition_circuit(4)
    n = 4
    for x, y in [(3, 5), (0, 0), (7, 1), (15, 1), (8, 8), (15, 15)]:
        xb = [(x >> (n-1-i)) & 1 for i in range(n)]
        yb = [(y >> (n-1-i)) & 1 for i in range(n)]
        out, _, _, _ = Secure_Eval(c, xb, yb, dh_group)
        # out[0] is carry; out[1:] are the n sum bits (MSB first)
        carry = out[0]
        result = sum(b << (n-1-i) for i, b in enumerate(out[1:]))
        expected = (x + y) % (1 << n)
        assert result == expected, (
            f"add({x},{y}): got {result} (carry={carry}), expected {expected}"
        )

test("equality circuit", t_equality_circuit)
test("millionaire's circuit", t_millionaires_circuit)
test("addition circuit", t_addition_circuit)


# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════
print("\n" + "═" * 60)
total = len(results)
passed = sum(1 for _, ok, _ in results if ok)
failed = total - passed
print(f"\nResults: {passed}/{total} passed, {failed} failed")
if failed:
    print("\nFailed tests:")
    for name, ok, err in results:
        if not ok:
            print(f"  ✗ {name}: {err}")
print()
sys.exit(0 if failed == 0 else 1)
