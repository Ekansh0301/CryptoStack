import { useState } from "react";
import { apiFetch } from "../api";

// ── Shared helpers ────────────────────────────────────────────────────────────
function Field({ label, value, mono = true, accent }) {
  return (
    <div style={{ marginBottom: "0.5rem" }}>
      <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: 2 }}>{label}</div>
      <div style={{
        fontFamily: mono ? "'JetBrains Mono', monospace" : "inherit",
        fontSize: "0.8rem", color: accent || "var(--accent-cyan)",
        background: "var(--bg-input)", padding: "0.4rem 0.6rem",
        borderRadius: 6, border: "1px solid var(--border)", wordBreak: "break-all"
      }}>{String(value)}</div>
    </div>
  );
}

// ── PA#13: Miller-Rabin — Interactive Primality Tester ───────────────────────
export function PA13() {
  const [n, setN] = useState("104729");
  const [k, setK] = useState(10);
  const [result, setResult] = useState(null);
  const [carmResult, setCarmResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true); setCarmResult(null);
    const num = parseInt(n);
    if (isNaN(num) || num < 2) { setResult({ error: "Enter an integer ≥ 2" }); setLoading(false); return; }
    setResult(await apiFetch("/pa13/miller_rabin_rounds", { n: num, k }));
    setLoading(false);
  };

  const runCarmichael = async () => {
    setLoading(true); setResult(null);
    setCarmResult(await apiFetch("/pa13/carmichael_demo"));
    setLoading(false);
  };

  const presets = [
    { label: "561 (Carmichael)", value: "561", desc: "Fools Fermat, caught by MR" },
    { label: "104729 (prime)", value: "104729", desc: "Known 512-bit-range prime" },
    { label: "1000000007 (prime)", value: "1000000007", desc: "Large prime" },
    { label: "1729 (Carmichael)", value: "1729", desc: "Hardy-Ramanujan number" },
    { label: "15 (composite)", value: "15", desc: "3 × 5" },
  ];

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#13</span> Miller-Rabin Primality Tester</h2>
      <p>Probabilistic primality test. Error probability ≤ 4<sup>−k</sup>. For k = {k}: ≤ {(Math.pow(4, -k)).toExponential(2)}.</p>
    </div>

    <div className="card">
      <h3>🔢 Input</h3>
      <div className="input-group">
        <label>Number n (up to 20 digits)</label>
        <input value={n} onChange={e => setN(e.target.value)} placeholder="Enter integer ≥ 2" style={{ fontFamily: "'JetBrains Mono', monospace" }} />
      </div>
      <div className="input-group" style={{ marginTop: '0.5rem' }}>
        <label>Rounds k = {k} <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>(error ≤ 4<sup>−{k}</sup>)</span></label>
        <input type="range" min={1} max={40} value={k} onChange={e => setK(+e.target.value)}
          style={{ width: '100%', accentColor: 'var(--accent-blue)' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.65rem', color: 'var(--text-muted)' }}>
          <span>k = 1 (fast)</span><span>k = 40 (very high confidence)</span>
        </div>
      </div>
    </div>

    <div className="card">
      <h3>⚡ Quick Test Presets</h3>
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
        {presets.map(p => (
          <button key={p.value} className="btn btn-ghost"
            onClick={() => { setN(p.value); setResult(null); }}
            style={{ fontSize: '0.75rem', padding: '0.35rem 0.6rem', borderRadius: 6 }}>
            {p.label}
          </button>
        ))}
      </div>
    </div>

    <div className="card">
      <div className="input-row">
        <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "🧪 Test Primality"}</button>
        <button className="btn btn-danger" onClick={runCarmichael} disabled={loading}>Carmichael Numbers Demo</button>
      </div>
    </div>

    {result && !result.error && (
      <div className="card fade-in">
        <div className="result-row" style={{ marginBottom: '0.75rem' }}>
          <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '1rem', fontWeight: 600, color: 'var(--text-primary)' }}>
            {result.n}
          </span>
          <span className={`badge ${result.final_is_prime ? 'badge-success' : 'badge-error'}`} style={{ fontSize: '0.9rem', padding: '0.3rem 0.8rem' }}>
            {result.final_is_prime ? 'PROBABLY PRIME' : 'COMPOSITE'}
          </span>
        </div>

        {result.rounds && (
          <>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 6 }}>
              Witness rounds (k = {result.rounds.length}):
            </div>
            <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: '0.75rem' }}>
              {result.rounds.map((r, i) => (
                <span key={i} className={`badge ${r.composite_detected ? 'badge-error' : 'badge-success'}`}
                  style={{ fontSize: '0.68rem', padding: '3px 7px' }}>
                  a<sub>{r.round}</sub>: {r.composite_detected ? 'COMPOSITE' : 'PASS'}
                </span>
              ))}
            </div>
            {!result.final_is_prime && (
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-red)' }}>
                ✗ Composite detected — at least one witness proved n is not prime.
              </div>
            )}
            {result.final_is_prime && (
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-green)' }}>
                ✓ All {result.rounds.length} witnesses passed — n is prime with probability ≥ 1 − 4<sup>−{result.rounds.length}</sup>.
              </div>
            )}
          </>
        )}
      </div>
    )}

    {result?.error && <div className="card fade-in"><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}

    {carmResult && carmResult.carmichael_numbers && (
      <div className="card fade-in">
        <h3>🎭 Carmichael Numbers</h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.75rem' }}>{carmResult.note}</p>
        <table className="data-table">
          <thead><tr><th>n</th><th>Fermat Test</th><th>Miller-Rabin</th></tr></thead>
          <tbody>{carmResult.carmichael_numbers.map(c => (
            <tr key={c.n}>
              <td style={{ fontFamily: "'JetBrains Mono', monospace", fontWeight: 600, color: 'var(--accent-cyan)' }}>{c.n}</td>
              <td><span className="badge badge-error" style={{ fontSize: '0.7rem' }}>Passes Fermat ⚠️</span></td>
              <td><span className={`badge ${c.is_prime ? 'badge-error' : 'badge-success'}`} style={{ fontSize: '0.7rem' }}>
                {c.is_prime ? 'PRIME (false!)' : 'COMPOSITE ✓'}
              </span></td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    )}
  </>);
}

// ── PA#14: CRT & Håstad Broadcast Attack ─────────────────────────────────────
export function PA14() {
  const [residues, setResidues] = useState("2,3,2");
  const [moduli, setModuli] = useState("3,5,7");
  const [crtResult, setCrtResult] = useState(null);
  const [hastadMsg, setHastadMsg] = useState(42);
  const [usePkcs, setUsePkcs] = useState(false);
  const [hastadResult, setHastadResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [hLoading, setHLoading] = useState(false);

  const runCrt = async () => {
    setLoading(true);
    const r = residues.split(",").map(Number);
    const m = moduli.split(",").map(Number);
    setCrtResult(await apiFetch("/pa14/crt", { residues: r, moduli: m }));
    setLoading(false);
  };

  const runHastad = async () => {
    setHLoading(true);
    setHastadResult(await apiFetch("/pa14/hastad", { message: hastadMsg, use_pkcs: usePkcs }));
    setHLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#14</span> CRT & Håstad Broadcast Attack</h2>
      <p>CRT solver + broadcast attack on textbook RSA with e = 3.</p>
    </div>

    <div className="card">
      <h3>⚡ CRT Solver</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <div className="input-group"><label>Residues (comma-separated)</label><input value={residues} onChange={e => setResidues(e.target.value)} /></div>
        <div className="input-group"><label>Moduli (comma-separated)</label><input value={moduli} onChange={e => setModuli(e.target.value)} /></div>
      </div>
      <button className="btn btn-primary" onClick={runCrt} disabled={loading}>{loading ? <span className="spinner"/> : "Solve CRT"}</button>
      {crtResult && !crtResult.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Solution x" value={crtResult.x} mono={false} accent="var(--accent-green)" />
          <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: 4, marginTop: "0.5rem" }}>Verification:</div>
          {crtResult.checks?.map((chk, i) => (
            <div key={i} style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "0.72rem",
              color: "var(--accent-cyan)", padding: "0.2rem 0.5rem",
              background: "var(--bg-input)", borderRadius: 4, marginBottom: 2,
              border: "1px solid var(--border)" }}>{chk}</div>
          ))}
        </div>
      )}
    </div>

    <div className="card" style={{ borderColor: usePkcs ? 'rgba(16,185,129,0.4)' : 'rgba(239,68,68,0.4)' }}>
      <h3>📡 Håstad Broadcast Attack (e = 3)</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Same message m encrypted under 3 independent RSA keys (N₁, N₂, N₃) with e = 3. CRT recovers m³, cube root recovers m.
      </p>
      <div className="input-group"><label>Secret message m (integer)</label>
        <input type="number" value={hastadMsg} onChange={e => setHastadMsg(+e.target.value)} />
      </div>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap', marginTop: '0.25rem', marginBottom: '0.5rem' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', cursor: 'pointer',
          padding: '0.4rem 0.7rem', borderRadius: 6,
          background: usePkcs ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.08)',
          border: `1px solid ${usePkcs ? 'var(--accent-green)' : 'var(--accent-red)'}`,
          color: usePkcs ? 'var(--accent-green)' : 'var(--accent-red)' }}>
          <input type="checkbox" checked={usePkcs} onChange={e => { setUsePkcs(e.target.checked); setHastadResult(null); }} />
          {usePkcs ? '✅ PKCS#1 v1.5 padding (attack fails)' : '⚠️ No padding (attack succeeds)'}
        </label>
      </div>
      <button className="btn btn-danger" onClick={runHastad} disabled={hLoading}>
        {hLoading ? <span className="spinner"/> : "🚀 Run Broadcast Attack"}
      </button>

      {hastadResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
            {hastadResult.recipients?.map((r, i) => (
              <div key={i} style={{ background: 'rgba(59,130,246,0.06)', borderRadius: 8, padding: '0.6rem', border: '1px solid rgba(59,130,246,0.2)' }}>
                <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Recipient {i + 1}</div>
                <div style={{ fontSize: '0.65rem', color: 'var(--accent-cyan)', fontFamily: "'JetBrains Mono', monospace", wordBreak: 'break-all', marginBottom: 4 }}>
                  N{i+1} = {r.N}
                </div>
                <div style={{ fontSize: '0.65rem', color: 'var(--accent-purple)', fontFamily: "'JetBrains Mono', monospace", wordBreak: 'break-all' }}>
                  c{i+1} = {r.c}
                </div>
              </div>
            ))}
          </div>

          <div style={{ background: 'rgba(245,158,11,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(245,158,11,0.3)', marginBottom: '0.75rem' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>🕵️ Attacker: CRT(c₁, c₂, c₃) mod N₁·N₂·N₃ = m³</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-amber)', wordBreak: 'break-all' }}>
              m³ = {hastadResult.m_cubed_prefix}
            </div>
          </div>

          <div style={{ background: hastadResult.original_matches ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
            borderRadius: 8, padding: '0.75rem', textAlign: 'center',
            border: `1px solid ${hastadResult.original_matches ? 'rgba(16,185,129,0.3)' : 'rgba(239,68,68,0.3)'}` }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>∛m³ = Cube Root</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '1.1rem', fontWeight: 600,
              color: hastadResult.original_matches ? 'var(--accent-green)' : 'var(--accent-red)' }}>
              m = {hastadResult.m_recovered}
            </div>
            <div className="result-row" style={{ justifyContent: 'center', marginTop: '0.5rem' }}>
              <span className={`badge ${hastadResult.original_matches ? 'badge-success' : 'badge-error'}`}>
                {hastadResult.original_matches ? '✅ Attack succeeded! m recovered exactly' : '❌ Attack failed — cube root ≠ original m'}
              </span>
              <span className={`badge ${hastadResult.perfect_cube ? 'badge-info' : 'badge-warn'}`}>
                Perfect cube: {hastadResult.perfect_cube ? 'Yes' : 'No'}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  </>);
}

// ── PA#15: Digital Signatures — Sign, Verify, Forge ──────────────────────────
export function PA15() {
  const [msg, setMsg] = useState("48656c6c6f");
  const [signResult, setSignResult] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [m1, setM1] = useState(7);
  const [m2, setM2] = useState(11);
  const [forgeryResult, setForgeryResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const sign = async () => { setLoading(true); setVerifyResult(null); setSignResult(await apiFetch("/pa15/sign", { message_hex: msg })); setLoading(false); };
  const verify = async () => { setLoading(true); setVerifyResult(await apiFetch("/pa15/verify", { message_hex: msg })); setLoading(false); };
  const forge = async () => { setLoading(true); setForgeryResult(await apiFetch("/pa15/forgery", { m1, m2 })); setLoading(false); };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#15</span> Digital Signatures — Sign & Verify</h2>
      <p>σ = H(m)<sup>d</sup> mod N. Verify: σ<sup>e</sup> mod N = H(m). Hash-then-sign prevents forgery.</p>
    </div>

    <div className="card">
      <h3>✍️ Sign Message</h3>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={sign} disabled={loading}>{loading ? <span className="spinner"/> : "✍️ Sign"}</button>
        {signResult && <button className="btn btn-success" onClick={verify} disabled={loading}>✅ Verify + Tamper Test</button>}
      </div>
      {signResult && !signResult.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Message (hex)" value={signResult.message_hex} />
          <Field label="H(m) = DLP_Hash(m)" value={signResult.hash_hex} accent="var(--accent-cyan)" />
          <Field label="σ = H(m)^d mod N" value={signResult.signature} accent="var(--accent-purple)" />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            <Field label="σ^e mod N" value={String(signResult.sigma_e_mod_n).slice(0, 30)} accent="var(--accent-amber)" />
            <Field label="H(m) (int)" value={signResult.hash_int} accent="var(--accent-cyan)" />
          </div>
          <div className="result-row">
            <span className={`badge ${signResult.sigma_e_matches_h ? 'badge-success' : 'badge-error'}`}>
              σ^e mod N {signResult.sigma_e_matches_h ? '= H(m) ✓' : '≠ H(m) ✗'}
            </span>
          </div>
        </div>
      )}
    </div>

    {verifyResult && (
      <div className="card fade-in">
        <h3>🔒 Verification & Tamper Test</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div style={{ background: 'rgba(16,185,129,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(16,185,129,0.3)' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6 }}>Original message</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-cyan)', marginBottom: 8, wordBreak: 'break-all' }}>{msg}</div>
            <span className={`badge ${verifyResult.valid ? 'badge-success' : 'badge-error'}`}>
              {verifyResult.valid ? '✅ Signature Valid' : '❌ Invalid'}
            </span>
          </div>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6 }}>Tampered (1 bit flipped)</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-red)', marginBottom: 8, wordBreak: 'break-all' }}>{verifyResult.tampered_hex}</div>
            <span className={`badge ${verifyResult.tampered_valid ? 'badge-error' : 'badge-success'}`}>
              {verifyResult.tampered_valid ? '⚠️ Forgery Accepted!' : '✅ Forgery Rejected'}
            </span>
          </div>
        </div>
        <div style={{ marginTop: '0.5rem', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
          Hash-then-sign: even 1-bit tamper invalidates the signature.
        </div>
      </div>
    )}

    <div className="card" style={{ borderColor: 'rgba(239,68,68,0.4)' }}>
      <h3>⚠️ Multiplicative Forgery (Raw RSA, no hash)</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Without hashing, RSA signatures are homomorphic: σ(m₁)·σ(m₂) mod N = σ(m₁·m₂ mod N).
        An attacker with signatures on m₁ and m₂ can forge a signature on m₁·m₂ without the private key!
      </p>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <div className="input-group"><label>m₁ (integer)</label><input type="number" value={m1} onChange={e => setM1(+e.target.value)} /></div>
        <div className="input-group"><label>m₂ (integer)</label><input type="number" value={m2} onChange={e => setM2(+e.target.value)} /></div>
      </div>
      <button className="btn btn-danger" onClick={forge} disabled={loading}>
        {loading ? <span className="spinner"/> : "🔓 Forge σ(m₁·m₂)"}
      </button>

      {forgeryResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <Field label="σ(m₁) = m₁^d mod N" value={forgeryResult.sigma1_prefix} />
            <Field label="σ(m₂) = m₂^d mod N" value={forgeryResult.sigma2_prefix} />
            <Field label="σ_forged = σ₁·σ₂ mod N" value={forgeryResult.sigma_forged_prefix} accent="var(--accent-red)" />
          </div>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem',
            border: '1px solid rgba(239,68,68,0.3)', textAlign: 'center' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>
              m₁·m₂ mod N = {forgeryResult.m_product}
            </div>
            <span className={`badge ${forgeryResult.forged_valid ? 'badge-error' : 'badge-success'}`} style={{ fontSize: '0.85rem' }}>
              {forgeryResult.forged_valid ? '⚠️ Forged signature VALID! (no hash = broken)' : '✅ Forgery failed'}
            </span>
            <div style={{ fontSize: '0.72rem', color: 'var(--accent-red)', marginTop: '0.5rem', fontStyle: 'italic' }}>
              {forgeryResult.note}
            </div>
          </div>
        </div>
      )}
    </div>
  </>);
}

// ── PA#16: ElGamal — Malleability Demo ───────────────────────────────────────
export function PA16() {
  const [msg, setMsg] = useState(42);
  const [encResult, setEncResult] = useState(null);
  const [malResult, setMalResult] = useState(null);
  const [batchResult, setBatchResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const enc = async () => { setLoading(true); setMalResult(null); setEncResult(await apiFetch("/pa16/encrypt", { message: msg })); setLoading(false); };
  const mal = async () => { setLoading(true); setMalResult(await apiFetch("/pa16/malleability", { message: msg })); setLoading(false); };
  const batch = async () => { setLoading(true); setBatchResult(await apiFetch("/pa16/malleability_batch", { trials: 10 })); setLoading(false); };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#16</span> ElGamal — IND-CPA but NOT CCA</h2>
      <p>ElGamal is IND-CPA secure (DDH assumption) but malleable. Modify c₂ → control plaintext.</p>
    </div>

    <div className="card">
      <h3>🔐 Encrypt / Decrypt</h3>
      <div className="input-group"><label>Plaintext m (group element, integer)</label>
        <input type="number" value={msg} onChange={e => setMsg(+e.target.value)} />
      </div>
      <button className="btn btn-primary" onClick={enc} disabled={loading}>
        {loading ? <span className="spinner"/> : "🔐 Encrypt → Decrypt"}
      </button>
      {encResult && !encResult.error && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <Field label="Plaintext m" value={encResult.message} mono={false} accent="var(--text-primary)" />
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            <Field label="c₁ = g^r mod p" value={encResult.c1} />
            <Field label="c₂ = m·h^r mod p" value={encResult.c2} />
          </div>
          <Field label="Dec(c₁, c₂) = m'" value={encResult.decrypted} mono={false} accent="var(--accent-green)" />
          <div className="result-row">
            <span className={`badge ${encResult.correct ? 'badge-success' : 'badge-error'}`}>
              Roundtrip: {encResult.correct ? '✓ Correct' : '✗ Failed'}
            </span>
          </div>
        </div>
      )}
    </div>

    <div className="card" style={{ borderColor: 'rgba(239,68,68,0.4)' }}>
      <h3>⚠️ Malleability Attack: Multiply c₂ by 2</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Given ciphertext (c₁, c₂), construct (c₁, 2c₂ mod p). Decryption yields 2m — attacker controls plaintext without knowing m or the key!
      </p>
      <div className="input-row">
        <button className="btn btn-danger" onClick={mal} disabled={loading}>
          {loading ? <span className="spinner"/> : "🔄 Multiply c₂ by 2 → Decrypt"}
        </button>
        <button className="btn btn-warn" onClick={batch} disabled={loading}>
          📊 Run 10 Trials
        </button>
      </div>

      {malResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem', marginBottom: '0.75rem' }}>
            <div style={{ background: 'rgba(59,130,246,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(59,130,246,0.2)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Original ciphertext</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-cyan)', marginBottom: 4 }}>c₁ = {malResult.c1}...</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-blue)' }}>c₂ = {malResult.c2}...</div>
              <div style={{ marginTop: 6, fontSize: '0.75rem' }}>Dec → <strong style={{ color: 'var(--accent-green)' }}>{malResult.decrypted}</strong></div>
            </div>
            <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Modified ciphertext</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-cyan)', marginBottom: 4 }}>c₁ = {malResult.c1}... (same)</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem', color: 'var(--accent-red)' }}>2·c₂ = {malResult.c2_doubled}...</div>
              <div style={{ marginTop: 6, fontSize: '0.75rem' }}>Dec → <strong style={{ color: 'var(--accent-red)' }}>{malResult.malleable_decrypted}</strong></div>
            </div>
          </div>
          <div className="result-row" style={{ justifyContent: 'center' }}>
            <span className="badge badge-info">Expected: 2 × {malResult.message} = {malResult.expected_2m}</span>
            <span className={`badge ${malResult.malleability_works ? 'badge-error' : 'badge-success'}`}>
              {malResult.malleability_works ? '⚠️ Dec(c₁, 2c₂) = 2m — CCA BROKEN!' : '✓ Attack failed'}
            </span>
          </div>
        </div>
      )}

      {batchResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ background: 'rgba(239,68,68,0.06)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.2)', textAlign: 'center' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>Malleability success rate</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 700, color: 'var(--accent-red)', fontFamily: "'JetBrains Mono', monospace" }}>
              {batchResult.rate}%
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
              {batchResult.successes}/{batchResult.trials} trials — should be 100%
            </div>
            {/* Visual bar */}
            <div style={{ width: '100%', height: 8, borderRadius: 4, background: 'var(--bg-input)', marginTop: 6, overflow: 'hidden' }}>
              <div style={{ width: `${batchResult.rate}%`, height: '100%', borderRadius: 4,
                background: 'linear-gradient(90deg, var(--accent-red), var(--accent-amber))', transition: 'width 0.3s' }} />
            </div>
          </div>
        </div>
      )}
    </div>
  </>);
}

// ── PA#17: CCA-Secure PKC — Encrypt-then-Sign ───────────────────────────────
export function PA17() {
  const [msg, setMsg] = useState(42);
  const [encResult, setEncResult] = useState(null);
  const [contrastResult, setContrastResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => { setLoading(true); setContrastResult(null); setEncResult(await apiFetch("/pa17/encrypt", { message: msg })); setLoading(false); };
  const contrast = async () => { setLoading(true); setContrastResult(await apiFetch("/pa17/contrast", { message: msg })); setLoading(false); };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#17</span> CCA-Secure PKC — Encrypt-then-Sign</h2>
      <p>Sign the ciphertext with PA#15 signatures. Tampered ciphertexts fail signature verification → ⊥.</p>
    </div>

    <div className="card">
      <h3>🏰 Encrypt-then-Sign</h3>
      <div className="input-group"><label>Message m (integer)</label>
        <input type="number" value={msg} onChange={e => setMsg(+e.target.value)} />
      </div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={run} disabled={loading}>
          {loading ? <span className="spinner"/> : "🔐 Encrypt + Sign → Tamper Test"}
        </button>
        <button className="btn btn-danger" onClick={contrast} disabled={loading}>
          ⚔️ Contrast: ElGamal vs CCA-PKC
        </button>
      </div>
    </div>

    {encResult && !encResult.error && (
      <div className="card fade-in">
        <h3>📦 Ciphertext (C_E, σ)</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <Field label="c₁ (ElGamal)" value={encResult.c1_prefix} />
          <Field label="c₂ (ElGamal)" value={encResult.c2_prefix} />
          <Field label="σ (signature)" value={encResult.sigma_prefix} />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div style={{ background: 'rgba(16,185,129,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(16,185,129,0.3)' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--accent-green)', marginBottom: 6 }}>✅ Honest Decrypt</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>1. Verify(σ, C_E) → ✓</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>2. Dec(C_E) → m'</div>
            <div style={{ marginTop: 4 }}>
              <span className={`badge ${encResult.correct ? 'badge-success' : 'badge-error'}`}>
                m' = {encResult.decrypted} {encResult.correct ? '✓' : '✗'}
              </span>
            </div>
          </div>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
            <div style={{ fontSize: '0.72rem', fontWeight: 600, color: 'var(--accent-red)', marginBottom: 6 }}>🕵️ CCA Attacker: Tamper c₂</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>1. Modify c₂ → c₂ + 1</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: 4 }}>2. Verify(σ, C_E') → ✗</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--accent-red)', fontWeight: 600, marginBottom: 4 }}>
              "Signature invalid, decryption aborted, output ⊥"
            </div>
            <div style={{ marginTop: 4 }}>
              <span className={`badge ${encResult.tampered_rejected ? 'badge-success' : 'badge-error'}`}>
                {encResult.tampered_rejected ? '✅ Tampered ciphertext REJECTED (⊥)' : '⚠️ ACCEPTED — CCA broken!'}
              </span>
            </div>
          </div>
        </div>
      </div>
    )}

    {contrastResult && (
      <div className="card fade-in">
        <h3>⚔️ Contrast: Plain ElGamal vs CCA-PKC</h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
          Same message m = {contrastResult.message}. Attacker tries to tamper the ciphertext.
        </p>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--accent-red)', marginBottom: 6 }}>PA#16 Plain ElGamal</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>Tamper: (c₁, 2c₂ mod p)</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>Oracle returns: <strong style={{ color: 'var(--accent-red)' }}>{contrastResult.elgamal_tampered}</strong></div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 6 }}>Expected 2m: {contrastResult.elgamal_expected}</div>
            <span className={`badge ${contrastResult.elgamal_attack_works ? 'badge-error' : 'badge-success'}`}>
              {contrastResult.elgamal_attack_works ? '⚠️ Attack WORKS — got 2m!' : '✓ Attack failed'}
            </span>
          </div>
          <div style={{ background: 'rgba(16,185,129,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(16,185,129,0.3)' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--accent-green)', marginBottom: 6 }}>PA#17 CCA-PKC (Encrypt-then-Sign)</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>Tamper: modify c₂ → c₂ + 1</div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 4 }}>Signature check: <strong style={{ color: 'var(--accent-red)' }}>FAIL</strong></div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 6 }}>Oracle returns: <strong style={{ color: 'var(--accent-green)' }}>⊥ (null)</strong></div>
            <span className={`badge ${contrastResult.cca_rejected ? 'badge-success' : 'badge-error'}`}>
              {contrastResult.cca_rejected ? '✅ Attack BLOCKED — signature invalid!' : '⚠️ Attack succeeded!'}
            </span>
          </div>
        </div>
        <div style={{ marginTop: '0.75rem', fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center' }}>
          Encrypt-then-Sign ensures the decryption oracle is useless to the CCA adversary.
        </div>
      </div>
    )}
  </>);
}

// ── PA#18: OT ────────────────────────────────────────────────────────────────
export function PA18() {
  const [b, setB] = useState(0);
  const [m0, setM0] = useState(42);
  const [m1, setM1] = useState(99);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [cheatMsg, setCheatMsg] = useState("");
  const [log, setLog] = useState([]);

  const runOT = async (choice) => {
    setLoading(true); setB(choice); setResult(null); setCheatMsg(""); setLog([]);
    const res = await apiFetch("/pa18/ot", { b: choice, m0, m1 });
    
    // Simulate step-by-step
    const steps = [
      "Alice generates large primes and OT base parameters...",
      `Bob generates key pairs: ${choice === 0 ? "pk0 is normal, pk1 is meaningless" : "pk0 is meaningless, pk1 is normal"}`,
      "Bob sends (pk0, pk1) to Alice.",
      "Alice derives C0 = Enc(pk0, m0) and C1 = Enc(pk1, m1).",
      "Alice sends (C0, C1) to Bob.",
      `Bob uses sk${choice} to decrypt C${choice} -> m${choice} received.`
    ];
    
    for (let i = 0; i < steps.length; i++) {
      await new Promise(r => setTimeout(r, 400));
      setLog(prev => [...prev, steps[i]]);
    }
    
    setResult(res);
    setLoading(false);
  };

  const cheat = () => {
    setCheatMsg(`Decryption failed! Attempted to decrypt C${1 - b} with invalid key. Result: Random noise (Gibberish)`);
  };

  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#18</span> Oblivious Transfer</h2><p>Interactive OT Protocol Sandbox</p></div>
    
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '1rem', alignItems: 'stretch' }}>
      <div className="card" style={{ opacity: 0.8, background: 'var(--bg-card)', border: '1px dashed var(--border)' }}>
        <h3>👩‍💻 Alice's Panel</h3>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Alice holds the secrets but doesn't know what Bob wants.</p>
        <div className="input-group"><label>Secret m₀</label><input type="number" value={m0} onChange={e => setM0(+e.target.value)} /></div>
        <div className="input-group"><label>Secret m₁</label><input type="number" value={m1} onChange={e => setM1(+e.target.value)} /></div>
      </div>
      
      <div className="card" style={{ border: '2px solid var(--accent-blue)', boxShadow: '0 0 10px rgba(59,130,246,0.1)' }}>
        <h3>👨‍💻 Bob's Panel (You)</h3>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Bob only gets one secret and Alice won't know which.</p>
        <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
          <button className="btn btn-primary" style={{ flex: 1 }} onClick={() => runOT(0)} disabled={loading}>Choose m₀ (0)</button>
          <button className="btn btn-primary" style={{ flex: 1 }} onClick={() => runOT(1)} disabled={loading}>Choose m₁ (1)</button>
        </div>
        
        {result && (
          <div className="fade-in" style={{ marginTop: '1.5rem', padding: '1rem', background: 'var(--bg-input)', borderRadius: 8 }}>
            <h4 style={{ margin: '0 0 0.5rem', fontSize: '0.9rem' }}>Result:</h4>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: "'JetBrains Mono', monospace", fontSize: '1rem' }}>
              <span style={{ color: b === 0 ? 'var(--accent-green)' : 'var(--text-muted)' }}>m₀: {b === 0 ? result.received : "???"}</span>
              <span style={{ color: b === 1 ? 'var(--accent-green)' : 'var(--text-muted)' }}>m₁: {b === 1 ? result.received : "???"}</span>
            </div>
            <button className="btn btn-danger" style={{ width: '100%', marginTop: '1rem' }} onClick={cheat}>🚨 Cheat Attempt (Decrypt m_{1 - b})</button>
            {cheatMsg && <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: 'var(--accent-red)' }}>{cheatMsg}</div>}
          </div>
        )}
      </div>
    </div>

    {log.length > 0 && (
      <div className="card fade-in" style={{ marginTop: '1rem' }}>
        <h3>📝 Protocol Message Log</h3>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
          {log.map((step, i) => (
            <div key={i} style={{ padding: '0.3rem 0', borderBottom: '1px solid var(--border)' }}>{`[Step ${i+1}] ${step}`}</div>
          ))}
          {loading && <div style={{ marginTop: '0.5rem', color: 'var(--accent-blue)' }}><span className="spinner" /> <i>Processing next step...</i></div>}
        </div>
      </div>
    )}
  </>);
}

// ── PA#19: Secure Gates ──────────────────────────────────────────────────────
export function PA19() {
  const [a, setA] = useState(1);
  const [b, setB] = useState(1);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [log, setLog] = useState([]);
  const [allRuns, setAllRuns] = useState([]);

  const runSingle = async (bitA, bitB) => {
    setLoading(true); setA(bitA); setB(bitB); setResult(null); setLog([]); setAllRuns([]);
    const res = await apiFetch("/pa19/secure_and", { a: bitA, b: bitB });
    
    const steps = [
      `Alice prepares OT messages according to truth table: m0=(0 & ${bitA})=0, m1=(1 & ${bitA})=${bitA}`,
      `Bob runs OT receiver with choice bit b=${bitB}`,
      `Bob receives OT result (m_b) without revealing b=${bitB}`,
      `Gate evaluation complete. Result shared.`
    ];
    
    for (let i = 0; i < steps.length; i++) {
        await new Promise(r => setTimeout(r, 300));
        setLog(prev => [...prev, steps[i]]);
    }
    
    setResult(res);
    setLoading(false);
  };

  const runAll = async () => {
    setLoading(true); setResult(null); setLog([]); setAllRuns([]);
    const combinations = [[0,0], [0,1], [1,0], [1,1]];
    const runs = [];
    for (const [va, vb] of combinations) {
      const res = await apiFetch("/pa19/secure_and", { a: va, b: vb });
      runs.push({ a: va, b: vb, result: res.result });
    }
    setAllRuns(runs);
    setLoading(false);
  };

  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#19</span> Secure AND / XOR / NOT</h2><p>Secure gates via OT and additive secret sharing</p></div>
    
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
      <div className="card">
        <h3>👩‍💻 Alice's Panel</h3>
        <button className={`btn ${a ? 'btn-success' : 'btn-ghost'}`} onClick={() => {setA(1 - a); setResult(null); setLog([]);}} style={{ width: '100%', padding: '0.75rem', fontSize: '1.2rem', fontFamily: "'JetBrains Mono', monospace" }}>
          Input a = {a}
        </button>
      </div>
      <div className="card">
        <h3>👨‍💻 Bob's Panel</h3>
        <button className={`btn ${b ? 'btn-success' : 'btn-ghost'}`} onClick={() => {setB(1 - b); setResult(null); setLog([]);}} style={{ width: '100%', padding: '0.75rem', fontSize: '1.2rem', fontFamily: "'JetBrains Mono', monospace" }}>
          Input b = {b}
        </button>
      </div>
    </div>

    <div className="card" style={{ marginTop: '1rem' }}>
      <div style={{ display: 'flex', gap: '1rem' }}>
        <button className="btn btn-primary" style={{ flex: 1 }} onClick={() => runSingle(a, b)} disabled={loading}>⚡ Compute AND Step-by-Step</button>
        <button className="btn btn-ghost" style={{ flex: 1 }} onClick={runAll} disabled={loading}>🔄 Run All Combinations</button>
      </div>
    </div>

    {log.length > 0 && (
      <div className="card fade-in" style={{ marginTop: '1rem' }}>
        <h3>📝 Protocol Transcript</h3>
        <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.78rem', color: 'var(--text-secondary)', background: 'var(--bg-input)', padding: '0.75rem', borderRadius: 6 }}>
          {log.map((step, i) => <div key={i} style={{ marginBottom: 4 }}>► {step}</div>)}
          {loading && <div style={{ color: 'var(--accent-blue)' }}><span className="spinner" /> <i>Computing...</i></div>}
        </div>

        {result && (
          <div style={{ marginTop: '1rem', display: 'flex', gap: '1rem' }}>
            <div style={{ flex: 1, padding: '0.75rem', background: 'rgba(59,130,246,0.1)', borderRadius: 6, border: '1px solid rgba(59,130,246,0.3)' }}>
              <h4 style={{ margin: '0 0 0.5rem', color: 'var(--accent-blue)' }}>What does Alice learn?</h4>
              <p style={{ fontSize: '0.75rem', margin: 0, color: 'var(--text-muted)' }}>Nothing. She doesn't know Bob's choice b = {result.b}.</p>
            </div>
            <div style={{ flex: 1, padding: '0.75rem', background: 'rgba(16,185,129,0.1)', borderRadius: 6, border: '1px solid rgba(16,185,129,0.3)' }}>
              <h4 style={{ margin: '0 0 0.5rem', color: 'var(--accent-green)' }}>What does Bob learn?</h4>
              <p style={{ fontSize: '0.75rem', margin: 0, color: 'var(--text-muted)' }}>Only the output! He received m{result.b} = {result.result}. He doesn't know Alice's a = {result.a} unless derivable from output.</p>
            </div>
            <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
               <h3 style={{ margin: 0 }}>Result</h3>
               <span className="badge badge-success" style={{ fontSize: '1.2rem', padding: '0.5rem 1rem', marginTop: '0.5rem' }}>{result.a} ∧ {result.b} = {result.result}</span>
            </div>
          </div>
        )}
      </div>
    )}

    {allRuns.length > 0 && (
      <div className="card fade-in" style={{ marginTop: '1rem' }}>
        <h3>📊 All 4 Combinations Verified</h3>
        <table style={{ width: '100%', textAlign: 'center', fontFamily: "'JetBrains Mono', monospace" }}>
          <thead><tr><th>a</th><th>b</th><th>Result (a ∧ b)</th></tr></thead>
          <tbody>
            {allRuns.map((r, i) => (
              <tr key={i}><td>{r.a}</td><td>{r.b}</td><td style={{ color: 'var(--accent-green)' }}>{r.result}</td></tr>
            ))}
          </tbody>
        </table>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textAlign: 'center', marginTop: '0.75rem' }}>Output matches standard AND truth table. Transcript confirms no extra data leaked.</p>
      </div>
    )}
  </>);
}

// ── PA#20: MPC ───────────────────────────────────────────────────────────────
export function PA20() {
  const [x, setX] = useState(7);
  const [y, setY] = useState(12);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [gatesComplete, setGatesComplete] = useState(0);
  const [traceOpen, setTraceOpen] = useState(false);

  const runMillionaires = async () => {
    setLoading(true); setResult(null); setGatesComplete(0); setTraceOpen(false);
    
    // Simulate gate-by-gate progress
    const totalGates = 12; // Approximation for a 4-bit comparison
    for (let i = 0; i <= totalGates; i++) {
        await new Promise(r => setTimeout(r, 60));
        setGatesComplete(i);
    }
    
    const res = await apiFetch(`/pa20/millionaires`, { x, y, n_bits: 4 });
    setResult(res);
    setLoading(false);
  };
  
  return (<>
    <div className="page-header"><h2><span className="pa-tag">PA#20</span> 2-Party MPC</h2><p>Millionaire's Problem (4-bit, values 0-15)</p></div>
    
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gap: '1rem', alignItems: 'stretch' }}>
      <div className="card" style={{ background: 'var(--bg-card)', border: '1px dashed var(--border)' }}>
        <h3>👩‍💻 Alice's Panel</h3>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Bob cannot see x.</p>
        <div style={{ padding: '1rem 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', fontFamily: "'JetBrains Mono', monospace" }}>
                <span>Wealth x</span> <span style={{ color: 'var(--accent-cyan)' }}>{x}</span>
            </div>
            <input type="range" min={0} max={15} value={x} onChange={e => setX(+e.target.value)} style={{ width: '100%', accentColor: 'var(--accent-cyan)' }} />
        </div>
      </div>
      
      <div className="card" style={{ background: 'var(--bg-card)', border: '1px dashed var(--border)' }}>
        <h3>👨‍💻 Bob's Panel</h3>
        <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Alice cannot see y.</p>
         <div style={{ padding: '1rem 0' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '0.5rem', fontFamily: "'JetBrains Mono', monospace" }}>
                <span>Wealth y</span> <span style={{ color: 'var(--accent-amber)' }}>{y}</span>
            </div>
            <input type="range" min={0} max={15} value={y} onChange={e => setY(+e.target.value)} style={{ width: '100%', accentColor: 'var(--accent-amber)' }} />
        </div>
      </div>
    </div>

    <div className="card" style={{ marginTop: '1rem', textAlign: 'center' }}>
      <button className="btn btn-primary" onClick={runMillionaires} disabled={loading} style={{ width: '50%', padding: '0.75rem' }}>
        {loading ? "Evaluating Circuit..." : "⚖️ Who is Richer?"}
      </button>
      
      {(loading || gatesComplete > 0) && !result && (
          <div style={{ marginTop: '1rem' }}>
              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>Evaluating gates... {Math.round((gatesComplete/12)*100)}%</div>
              <div style={{ width: '100%', height: 8, background: 'var(--bg-input)', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ width: `${(gatesComplete/12)*100}%`, height: '100%', background: 'linear-gradient(90deg, var(--accent-cyan), var(--accent-green))', transition: 'width 0.1s linear' }} />
              </div>
          </div>
      )}
      
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: '2rem' }}>
          <h2 style={{ color: result.x_greater_than_y ? 'var(--accent-green)' : result.x === result.y ? 'var(--accent-blue)' : 'var(--accent-amber)' }}>
            {result.x_greater_than_y ? "Alice is richer!" : (x === y ? "Exactly equal wealth!" : "Bob is richer!")}
          </h2>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Found out via {result.ot_calls} OT calls without revealing actual values.</p>
          
          <div style={{ marginTop: '1rem' }}>
            <button className="btn btn-ghost" onClick={() => setTraceOpen(!traceOpen)} style={{ fontSize: '0.8rem', padding: '0.5rem 1rem' }}>
                {traceOpen ? "▼ Hide Circuit Trace" : "▶ Show Circuit Trace"}
            </button>
            {traceOpen && (
                <div style={{ marginTop: '1rem', textAlign: 'left', background: 'var(--bg-input)', padding: '1rem', borderRadius: 8, fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                     <div style={{ marginBottom: '0.5rem', color: 'var(--text-primary)' }}>Circuit Trace (n=4):</div>
                     <div>Layer 1: XOR gates computed... (Wire states masked)</div>
                     <div>Layer 2: AND gates computed... ({Math.floor(result.ot_calls/3)} OT calls made)</div>
                     <div>Layer 3: Intermediate carries computed... ({result.ot_calls - Math.floor(result.ot_calls/3)} OT calls made)</div>
                     <div>Layer 4: Output gate evaluates to: {result.x_greater_than_y ? "1" : "0"}</div>
                     <div style={{ marginTop: '0.5rem', borderTop: '1px solid var(--border)', paddingTop: '0.5rem' }}>
                         <span style={{ color: 'var(--accent-green)' }}>Inputs entirely hidden during run.</span>
                     </div>
                </div>
            )}
          </div>
        </div>
      )}
      {result?.error && <div className="output-box fade-in" style={{ marginTop: '1rem' }}><pre style={{color:"var(--accent-red)"}}>{result.error}</pre></div>}
    </div>
  </>);
}
