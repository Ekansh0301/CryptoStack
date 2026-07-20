# CS8.401 — Cryptographic Primitives Project

End-to-end implementation of 20 Programming Assignments covering the full cryptographic primitive stack — from One-Way Functions to 2-party MPC — plus a FastAPI backend and an interactive React dashboard for "learning-by-breaking" security simulations.

---

## Repository Structure

```
cs8401/
├── src/
│   ├── pa01_owf_prg/          owf_prg.py          — OWF + PRG (HILL) + NIST tests
│   ├── pa02_prf/              prf.py              — PRF (GGM tree) + AES-128 from scratch
│   ├── pa03_cpa/              cpa.py              — CPA-secure encryption
│   ├── pa04_modes/            modes.py            — ECB, CBC, OFB, CTR modes
│   ├── pa05_mac/              mac.py              — PRF-MAC, CBC-MAC, HMAC stub
│   ├── pa06_cca/              cca.py              — Encrypt-then-MAC (CCA-secure)
│   ├── pa07_merkle_damgard/   merkle_damgard.py   — Merkle-Damgård framework
│   ├── pa08_dlp_crhf/         dlp_crhf.py         — DLP-based CRHF
│   ├── pa09_birthday/         birthday.py         — Birthday attack
│   ├── pa10_hmac/             hmac_impl.py        — HMAC + Encrypt-then-HMAC
│   ├── pa11_dh/               dh.py               — Diffie-Hellman key exchange
│   ├── pa12_rsa/              rsa.py              — RSA + PKCS#1 v1.5
│   ├── pa13_miller_rabin/     miller_rabin.py     — Miller-Rabin + prime generation
│   ├── pa14_crt/              crt.py              — CRT + Håstad broadcast attack
│   ├── pa15_signatures/       signatures.py       — RSA digital signatures
│   ├── pa16_elgamal/          elgamal.py          — ElGamal PKE
│   ├── pa17_cca_pkc/          cca_pkc.py          — CCA-secure PKC (ElGamal + RSA sig)
│   ├── pa18_ot/               ot.py               — 1-out-of-2 Oblivious Transfer
│   ├── pa19_secure_and/       secure_and.py       — Secure AND / XOR / NOT gates
│   └── pa20_mpc/              mpc.py              — 2-party MPC circuits (comparison, equality, addition)
├── tests/
│   └── test_all.py            — Comprehensive test suite (all PAs)
├── backend/
│   └── api.py                 — FastAPI v2.0.0 backend (50+ HTTP endpoints)
├── webapp/
│   ├── src/
│   │   ├── App.jsx            — Main React app (sidebar navigation, page routing)
│   │   ├── api.js             — API client + PA metadata registry
│   │   ├── index.css          — Full design system
│   │   ├── main.jsx           — Entry point
│   │   └── pages/
│   │       ├── PA01_06.jsx    — Foundations + Symmetric crypto pages
│   │       ├── PA07_12.jsx    — Hash + Public Key pages
│   │       └── PA13_20.jsx    — Primality, Signatures, PKC + MPC pages
│   ├── dist/                  — Production build output
│   ├── index.html
│   ├── package.json           — React 18 + Vite 5
│   └── vite.config.js
└── requirements.txt           — FastAPI, uvicorn, pydantic
```

---

## Setup

**Requirements:** Python 3.10+, Node 18+ (only for the webapp).

```bash
# Clone
git clone https://github.com/<your-username>/cs8401.git
cd cs8401

# (Optional) virtual environment
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate

# Install API dependencies (only needed for the webapp)
pip install -r requirements.txt

# Install webapp dependencies
cd webapp && npm install && cd ..
```

All cryptographic implementations (PA#1–PA#20) use **only the Python standard library**.
`requirements.txt` only contains FastAPI/uvicorn/pydantic for the optional web UI.

---

## Quick Start

### 1. Run all tests

```bash
cd cs8401
python tests/test_all.py
```

### 2. Run individual PAs

```bash
# Phase 1 — Number Theory (no dependencies)
python src/pa13_miller_rabin/miller_rabin.py
python src/pa07_merkle_damgard/merkle_damgard.py

# Phase 2 — Symmetric Cryptography
python src/pa01_owf_prg/owf_prg.py
python src/pa02_prf/prf.py
python src/pa03_cpa/cpa.py
python src/pa04_modes/modes.py
python src/pa05_mac/mac.py
python src/pa06_cca/cca.py

# Phase 3 — Hashing
python src/pa08_dlp_crhf/dlp_crhf.py
python src/pa09_birthday/birthday.py
python src/pa10_hmac/hmac_impl.py

# Phase 4 — Public-Key Cryptography
python src/pa11_dh/dh.py
python src/pa12_rsa/rsa.py
python src/pa14_crt/crt.py
python src/pa15_signatures/signatures.py
python src/pa16_elgamal/elgamal.py
python src/pa17_cca_pkc/cca_pkc.py

# Phase 5 — Multi-Party Computation
python src/pa18_ot/ot.py
python src/pa19_secure_and/secure_and.py
python src/pa20_mpc/mpc.py
```

### 3. Start the backend API

```bash
pip install fastapi uvicorn
cd cs8401
uvicorn backend.api:app --reload --port 8000
```

### 4. Start the React webapp

```bash
cd cs8401/webapp
npm install
npm run dev
# Open http://localhost:5173
```

---

## Dependency Graph

```
PA#13 ────────────────────────────────────────────┐
  ├─▶ PA#7 (Merkle-Damgård)                        │
  │     └─▶ PA#8 (DLP-CRHF) ──▶ PA#9 (Birthday)   │
  │           └─▶ PA#10 (HMAC)                      │
  ├─▶ PA#1 (OWF+PRG) ─▶ PA#2 (PRF) ─▶ PA#3 (CPA)  │
  │                           ├─▶ PA#4 (Modes)      │
  │                           ├─▶ PA#5 (MAC) ───────┤
  │                           │     └─▶ PA#6 (CCA)  │
  │                           └─▶ PA#10 (HMAC)      │
  ├─▶ PA#11 (DH) ──▶ PA#16 (ElGamal) ──────────────┤
  │         └─▶ PA#18 (OT) ──▶ PA#19 (Secure gates) │
  │               └─▶ PA#20 (MPC circuits)          │
  └─▶ PA#12 (RSA) ──▶ PA#14 (CRT + Håstad)         │
              ├─▶ PA#15 (Signatures) ───────────────┤
              └─▶ PA#17 (CCA-PKC) ◀─ PA#15+PA#16   │
```

---

## PA#20: Full Call-Stack Trace

One AND gate evaluation in PA#20 traces through the entire project:

```
PA#20 Secure_Eval(circuit, x_Alice, y_Bob, group)
└── gate.type == 'AND':
    └── PA#19 Secure_AND(group, a, b)
        ├── PA#18 OT_Receiver_Step1(group, b)
        │   └── PA#11 DHGroup.random_exponent()
        │       └── os.urandom() [allowed]
        ├── PA#18 OT_Sender_Step(group, pk_0, pk_1, m0, m1)
        │   └── PA#16 elgamal_enc((group, pk_i), m_i)
        │       └── PA#11 DHGroup.power(g, r)
        │           └── PA#13 _square_and_multiply(g, r, p)
        └── PA#18 OT_Receiver_Step2(state, C_0, C_1)
            └── PA#16 elgamal_dec((group, sk_b), c1, c2)
                └── PA#13 _square_and_multiply(c1, sk_b, p)

Group initialization (PA#11 DHGroup):
└── PA#13 gen_safe_prime(bits)
    ├── PA#13 gen_prime(bits-1)  [Miller-Rabin loop]
    │   └── PA#13 miller_rabin(candidate, k=40)
    │       └── PA#13 _square_and_multiply(a, d, n)
    └── PA#13 miller_rabin(p=2q+1, k=40)
```

---

## Bidirectional Reductions

### PA#1 — OWF ↔ PRG
- **OWF → PRG**: HILL construction. For seed s, iterate f repeatedly, extract Goldreich-Levin hard-core bit per step.
- **PRG → OWF**: Define f_G(s) = G(s). Inverting G recovers s (PRG seed), which is hard by PRG security.

### PA#2 — PRG ↔ PRF
- **PRG → PRF**: GGM binary tree. Parse input x = b₁...bₙ, walk tree applying G_{b_i} at each level.
- **PRF → PRG**: G(s) = F_s(0ⁿ) ∥ F_s(1ⁿ). Security reduces to PRF security.

### PA#10 — CRHF ↔ HMAC ↔ MAC (6 directions)
- **CRHF → HMAC**: HMAC construction using CRHF as underlying hash.
- **HMAC → CRHF**: Use HMAC_k(cv ∥ block) as compression function in MD framework.
- **HMAC → MAC**: HMAC satisfies EUF-CMA (proven from CRHF security).
- **MAC → CRHF**: A secure MAC serves as collision-resistant compression.
- **CRHF → MAC**: Via HMAC bridge.
- **MAC → HMAC**: Mac forgery implies HMAC forgery.

---

## Allowed Library Exceptions (per spec)

1. `int` — Python's arbitrary-precision integers
2. `os.urandom` — cryptographically secure randomness
3. `pow(a, b, n)` — Python's built-in modular exponentiation (only where noted; own `_square_and_multiply` also implemented for benchmarks)

All other cryptographic operations are implemented from scratch.

---

## Backend API Endpoints

### Infrastructure

| Endpoint | Method | Description |
|---|---|---|
| `/` | GET | Root health check |
| `/health` | GET | API health status |
| `/shutdown` | POST | Graceful server shutdown |

### PA#1 — OWF & PRG

| Endpoint | Method | Description |
|---|---|---|
| `/pa01/owf` | POST | Evaluate DLP-based one-way function f(x) = g^x mod p |
| `/pa01/prg` | POST | Generate pseudorandom bits from OWF-PRG (HILL construction) |
| `/pa01/randomness_test` | POST | Run NIST statistical tests on PRG output |

### PA#2 — PRF (GGM)

| Endpoint | Method | Description |
|---|---|---|
| `/pa02/prf` | POST | Evaluate AES-based PRF: F(k, x) |
| `/pa02/ggm_tree` | POST | Build full GGM binary tree and highlight query path |

### PA#3 — CPA Encryption

| Endpoint | Method | Description |
|---|---|---|
| `/pa03/encrypt` | POST | CPA-secure encryption |
| `/pa03/decrypt` | POST | CPA-secure decryption |
| `/pa03/cpa_challenge` | POST | IND-CPA challenge game (with optional nonce-reuse demo) |

### PA#4 — Block Cipher Modes

| Endpoint | Method | Description |
|---|---|---|
| `/pa04/encrypt` | POST | Encrypt with mode (CBC / OFB / CTR) |
| `/pa04/decrypt` | POST | Encrypt + decrypt round-trip |
| `/pa04/ecb_demo` | POST | ECB determinism demo — same block → identical ciphertext vs. CBC/CTR |

### PA#5 — MACs

| Endpoint | Method | Description |
|---|---|---|
| `/pa05/mac` | POST | Compute PRF-MAC or CBC-MAC tag |
| `/pa05/verify` | POST | Verify a MAC tag |
| `/pa05/tamper_test` | POST | Tamper detection demo — flip message/tag bits and verify |

### PA#6 — CCA Encryption

| Endpoint | Method | Description |
|---|---|---|
| `/pa06/encrypt` | POST | Encrypt-then-MAC (CCA-secure) |
| `/pa06/bitflip` | POST | Bitflip attack demo — CPA ciphertext corrupts silently, CCA rejects |

### PA#7 — Merkle-Damgård

| Endpoint | Method | Description |
|---|---|---|
| `/pa07/hash` | POST | Compute Merkle-Damgård toy hash |
| `/pa07/chain` | POST | Full chain visualization — blocks, chaining values, padding |

### PA#8 — DLP-CRHF

| Endpoint | Method | Description |
|---|---|---|
| `/pa08/hash` | POST | DLP-based collision-resistant hash |

### PA#9 — Birthday Attack

| Endpoint | Method | Description |
|---|---|---|
| `/pa09/birthday` | POST | Run birthday attack to find hash collision |
| `/pa09/birthday_curve` | POST | Birthday paradox curve — attempts vs. bit-size across multiple trials |

### PA#10 — HMAC

| Endpoint | Method | Description |
|---|---|---|
| `/pa10/hmac` | POST | Compute HMAC tag |
| `/pa10/hmac_verify` | POST | Verify HMAC tag |

### PA#11 — Diffie-Hellman

| Endpoint | Method | Description |
|---|---|---|
| `/pa11/dh_exchange` | GET | Full DH key exchange demo (summary) |
| `/pa11/dh_interactive` | GET | Detailed DH exchange — all parameters, private/public keys, shared secret |
| `/pa11/mitm` | POST | Man-in-the-Middle attack simulation — Eve intercepts and creates separate shared keys |

### PA#12 — RSA

| Endpoint | Method | Description |
|---|---|---|
| `/pa12/keygen` | GET | RSA key generation info |
| `/pa12/encrypt` | POST | RSA encrypt + decrypt round-trip |
| `/pa12/determinism` | POST | Textbook RSA determinism vs. PKCS#1 v1.5 randomized padding |

### PA#13 — Miller-Rabin

| Endpoint | Method | Description |
|---|---|---|
| `/pa13/is_prime` | POST | Miller-Rabin primality test |
| `/pa13/miller_rabin_rounds` | POST | Round-by-round Miller-Rabin trace |
| `/pa13/carmichael_demo` | GET | Carmichael number detection (561, 1105, 1729, …) |

### PA#14 — CRT & Håstad

| Endpoint | Method | Description |
|---|---|---|
| `/pa14/crt` | POST | Chinese Remainder Theorem solver |
| `/pa14/hastad` | POST | Håstad broadcast attack — recover m from 3 RSA ciphertexts (e=3) |

### PA#15 — Digital Signatures

| Endpoint | Method | Description |
|---|---|---|
| `/pa15/sign` | POST | RSA signature with hash + full verification trace |
| `/pa15/verify` | POST | Signature verification + tamper detection |
| `/pa15/forgery` | POST | Multiplicative homomorphism forgery demo: σ(m₁·m₂) = σ(m₁)·σ(m₂) |

### PA#16 — ElGamal

| Endpoint | Method | Description |
|---|---|---|
| `/pa16/encrypt` | POST | ElGamal encryption + decryption |
| `/pa16/malleability` | POST | Malleability demo — multiply c₂ by 2, decryption yields 2m |
| `/pa16/malleability_batch` | POST | Batch malleability verification across multiple trials |

### PA#17 — CCA-PKC

| Endpoint | Method | Description |
|---|---|---|
| `/pa17/encrypt` | POST | CCA-secure PKC (ElGamal + RSA signature) — tamper → rejection |
| `/pa17/contrast` | POST | Side-by-side: plain ElGamal (malleable) vs. CCA-PKC (tamper-proof) |

### PA#18 — Oblivious Transfer

| Endpoint | Method | Description |
|---|---|---|
| `/pa18/ot` | POST | 1-out-of-2 OT protocol — receiver gets m_b without learning m_{1-b} |

### PA#19 — Secure Gates

| Endpoint | Method | Description |
|---|---|---|
| `/pa19/secure_and` | POST | Secure AND gate (via OT) |
| `/pa19/secure_xor` | POST | Secure XOR gate (additive sharing) |
| `/pa19/truth_table` | POST | Full truth table for AND, XOR, NOT gates |

### PA#20 — MPC Circuits

| Endpoint | Method | Description |
|---|---|---|
| `/pa20/millionaires` | POST | Millionaire's problem — secure comparison |
| `/pa20/equality` | POST | Secure equality test |
| `/pa20/addition` | POST | Secure binary addition with carry |

### Reductions

| Endpoint | Method | Description |
|---|---|---|
| `/reductions/{A}/{B}` | GET | Bidirectional reduction routing table (OWF↔PRG, PRG↔PRF, PRF↔MAC, CRHF↔HMAC) |

---

## Security Simulation Endpoints

The API includes several **"learning-by-breaking"** endpoints designed to demonstrate why insecure primitives fail:

| Simulation | Endpoint | What It Shows |
|---|---|---|
| ECB Determinism | `/pa04/ecb_demo` | Same plaintext block → identical ciphertext in ECB; CBC/CTR produce different blocks |
| CPA Nonce Reuse | `/pa03/cpa_challenge` | With `reuse_nonce: true`, attacker can distinguish messages |
| CCA Bitflip | `/pa06/bitflip` | Flipping a ciphertext bit in CPA-only mode corrupts plaintext silently; CCA rejects |
| MAC Tampering | `/pa05/tamper_test` | Flipping message or tag bits causes MAC verification to fail |
| DH MITM | `/pa11/mitm` | Eve intercepts DH exchange, establishes separate keys with Alice and Bob |
| RSA Determinism | `/pa12/determinism` | Textbook RSA produces identical ciphertexts; PKCS#1 v1.5 randomizes |
| Signature Forgery | `/pa15/forgery` | Multiplicative homomorphism: forge σ(m₁·m₂) from σ(m₁) and σ(m₂) without private key |
| ElGamal Malleability | `/pa16/malleability` | Multiply c₂ by scalar → decryption yields scaled plaintext |
| CCA-PKC vs ElGamal | `/pa17/contrast` | Plain ElGamal is malleable; CCA-PKC (with RSA sig) detects and rejects tampering |

---

## Webapp Architecture

The React dashboard (`webapp/`) is organized into three page modules, each handling a group of PAs:

| Module | PAs | Topics |
|---|---|---|
| `PA01_06.jsx` | PA#1 – PA#6 | Foundations (OWF, PRG, PRF, GGM) + Symmetric (CPA, Modes, MAC, CCA) |
| `PA07_12.jsx` | PA#7 – PA#12 | Hash (Merkle-Damgård, DLP-CRHF, Birthday, HMAC) + Public Key (DH, RSA) |
| `PA13_20.jsx` | PA#13 – PA#20 | Primality, CRT, Signatures, ElGamal, CCA-PKC, OT, Secure Gates, MPC |

Each PA page provides:
- Interactive input forms with hex/integer fields
- Real-time API calls to the backend
- Visual result panels showing cryptographic parameters
- Security simulation widgets (where applicable)

Navigation uses a grouped sidebar (`Foundations → Symmetric → Hash → Public Key → Signatures & PKC → MPC`).

---

## Implementation Notes

- **AES-128**: Fully implemented from scratch (S-box, key schedule, MixColumns, ShiftRows, AddRoundKey, inverses). Verified against NIST KAT vector.
- **Miller-Rabin**: 40 rounds, correctly identifies all tested Carmichael numbers (561, 1105, 1729, ...).
- **Safe primes**: Both gen_safe_prime and gen_prime use own Miller-Rabin.
- **ElGamal**: Uses PA#11 group; modular inverse via Fermat's little theorem (p prime).
- **OT**: Receiver privacy: pk_{1-b} is a random group element with no known dlog. Sender privacy: receiver cannot decrypt C_{1-b} without sk_{1-b}.
- **MPC circuits**: Topologically ordered DAG; AND gates use OT (PA#18), XOR uses additive sharing, NOT is local. Supports comparison, equality, and addition circuits.
- **Lazy-loaded singletons**: The backend caches expensive objects (AES PRF, DH group, RSA keypair, ElGamal keypair, DLP hash, RSA signature) to avoid regeneration on each request.
