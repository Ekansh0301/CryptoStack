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

// ── PA#7: Merkle-Damgård Chain Viewer ────────────────────────────────────────
export function PA07() {
  const [msg, setMsg] = useState("48656c6c6f20576f726c64");
  const [hashResult, setHashResult] = useState(null);
  const [chainResult, setChainResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    const [h, c] = await Promise.all([
      apiFetch("/pa07/hash", { message_hex: msg }),
      apiFetch("/pa07/chain", { message_hex: msg }),
    ]);
    setHashResult(h); setChainResult(c); setLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#7</span> Merkle-Damgård Chain Viewer</h2>
      <p>Type a message → see block splitting, MD-strengthening padding, and chaining values z₀ → h(zᵢ, Mᵢ) → digest.</p>
    </div>

    <div className="card">
      <h3>🔗 Hash Message</h3>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)}
        style={{ fontFamily: "'JetBrains Mono', monospace" }} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>
        {loading ? <span className="spinner"/> : "🔗 Hash + Show Chain"}
      </button>
      {hashResult && !hashResult.error && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem' }}>
            <Field label="Input Message (hex)" value={hashResult.message_hex} />
            <Field label="Digest (hex)" value={hashResult.digest_hex} accent="var(--accent-green)" />
          </div>
          <Field label="Digest Size" value={`${hashResult.digest_bytes} bytes`} mono={false} accent="var(--text-secondary)" />
        </div>
      )}
    </div>

    {chainResult && chainResult.blocks && (
      <div className="card fade-in">
        <h3>📦 Padded Message & Blocks</h3>
        <Field label="Padded message (hex)" value={chainResult.padded_hex} />
        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 6 }}>
          Block size: {chainResult.block_size} bytes • {chainResult.num_blocks} block(s)
        </div>
        <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginBottom: '0.5rem' }}>
          {chainResult.blocks.map((blk, i) => (
            <div key={i} style={{ background: 'rgba(59,130,246,0.08)', borderRadius: 6, padding: '0.4rem 0.6rem',
              border: '1px solid rgba(59,130,246,0.2)', minWidth: 60 }}>
              <div style={{ fontSize: '0.6rem', color: 'var(--text-muted)', marginBottom: 2 }}>M{i+1}</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>{blk}</div>
            </div>
          ))}
        </div>
      </div>
    )}

    {chainResult && chainResult.chain && (
      <div className="card fade-in">
        <h3>⛓️ Chaining Values</h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexWrap: 'wrap', overflowX: 'auto' }}>
          {chainResult.chain.map((z, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <div style={{ background: i === 0 ? 'rgba(139,92,246,0.12)' : i === chainResult.chain.length - 1 ? 'rgba(16,185,129,0.12)' : 'rgba(59,130,246,0.08)',
                borderRadius: 8, padding: '0.5rem 0.6rem',
                border: `1px solid ${i === chainResult.chain.length - 1 ? 'rgba(16,185,129,0.4)' : 'rgba(59,130,246,0.2)'}`,
                minWidth: 50, textAlign: 'center' }}>
                <div style={{ fontSize: '0.58rem', color: 'var(--text-muted)', marginBottom: 2 }}>
                  {i === 0 ? 'z₀ (IV)' : i === chainResult.chain.length - 1 ? 'Digest' : `z${i}`}
                </div>
                <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.68rem',
                  color: i === chainResult.chain.length - 1 ? 'var(--accent-green)' : i === 0 ? 'var(--accent-purple)' : 'var(--accent-cyan)',
                  wordBreak: 'break-all' }}>{z}</div>
              </div>
              {i < chainResult.chain.length - 1 && (
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0 }}>
                  <div style={{ fontSize: '0.55rem', color: 'var(--accent-amber)' }}>h(z{i}, M{i+1})</div>
                  <div style={{ fontSize: '1rem', color: 'var(--accent-amber)' }}>→</div>
                </div>
              )}
            </div>
          ))}
        </div>
        <div style={{ marginTop: '0.75rem', fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center' }}>
          Each chaining value zᵢ₊₁ = h(zᵢ, Mᵢ₊₁). The final value is the digest.
        </div>
      </div>
    )}
  </>);
}

// ── PA#8: DLP-CRHF + Collision Hunt ──────────────────────────────────────────
export function PA08() {
  const [msg, setMsg] = useState("48656c6c6f");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [collision, setCollision] = useState(null);
  const [collLoading, setCollLoading] = useState(false);
  const [multiHash, setMultiHash] = useState(null);
  const [multiLoading, setMultiLoading] = useState(false);

  const run = async () => { setLoading(true); setResult(await apiFetch("/pa08/hash", { message_hex: msg })); setLoading(false); };

  const runCollision = async () => {
    setCollLoading(true); setCollision(null);
    const r = await apiFetch("/pa09/birthday", { bit_size: 16 });
    setCollision(r); setCollLoading(false);
  };

  const runMultiHash = async () => {
    setMultiLoading(true);
    const msgs = ["48656c6c6f", "576f726c64", "00", "deadbeef", "48656c6c6f20576f726c6421"];
    const results = [];
    for (const m of msgs) {
      const r = await apiFetch("/pa08/hash", { message_hex: m });
      results.push({ input: m, digest: r?.digest_hex || "error" });
    }
    setMultiHash(results);
    setMultiLoading(false);
  };

  const expected = 256; // 2^(16/2)

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#8</span> DLP-Based CRHF — Live Hash & Collision Hunt</h2>
      <p>h(x,y) = g<sup>x</sup> · ĥ<sup>y</sup> mod p — collision resistance from DLP hardness.</p>
    </div>

    <div className="card">
      <h3>#️⃣ Live DLP Hash</h3>
      <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Hash"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Input Message (hex)" value={result.message_hex} />
          <Field label="DLP Digest (hex)" value={result.digest_hex} accent="var(--accent-green)" />
          <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginTop: 4 }}>
            h(m) = g<sup>m₁</sup> · ĥ<sup>m₂</sup> mod p — collision resistance follows from DLP hardness
          </div>
        </div>
      )}
    </div>

    <div className="card">
      <h3>🔍 Collision Hunt (n = 16-bit truncated)</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Brute-force birthday attack on 16-bit truncated output. Expected ≈ {expected} evaluations (2<sup>n/2</sup>).
      </p>
      <button className="btn btn-danger" onClick={runCollision} disabled={collLoading}>
        {collLoading ? <><span className="spinner" style={{marginRight:6}}/> Searching...</> : "🎯 Run Collision Hunt"}
      </button>

      {collision && collision.collision_found && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div className="result-row" style={{ marginBottom: '0.5rem' }}>
            <span className="badge badge-success">💥 Collision in {collision.attempts} evals</span>
            <span className="badge badge-info">Expected: ≈ {collision.expected_attempts}</span>
            <span className="badge badge-warn">Ratio: {(collision.attempts / collision.expected_attempts).toFixed(2)}×</span>
          </div>

          {/* Progress bar */}
          <div style={{ marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 2 }}>
              <span>0</span><span>2<sup>n/2</sup> = {expected}</span><span>{Math.max(collision.attempts, expected)}</span>
            </div>
            <div style={{ width: '100%', height: 10, borderRadius: 5, background: 'var(--bg-input)', overflow: 'hidden', border: '1px solid var(--border)' }}>
              <div style={{ width: `${Math.min(100, (collision.attempts / Math.max(collision.attempts, expected * 1.5)) * 100)}%`,
                height: '100%', borderRadius: 5,
                background: collision.attempts <= expected * 1.5 ? 'linear-gradient(90deg, var(--accent-green), var(--accent-cyan))' : 'linear-gradient(90deg, var(--accent-amber), var(--accent-red))',
                transition: 'width 0.3s' }} />
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div style={{ background: 'rgba(59,130,246,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(59,130,246,0.2)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Message m₁</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.78rem', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>{collision.m1_hex}</div>
            </div>
            <div style={{ background: 'rgba(139,92,246,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(139,92,246,0.2)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Message m₂</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.78rem', color: 'var(--accent-purple)', wordBreak: 'break-all' }}>{collision.m2_hex}</div>
            </div>
          </div>
          {collision.h1 && (
            <div style={{ background: 'linear-gradient(135deg, rgba(239,68,68,0.1), rgba(245,158,11,0.08))',
              borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)', textAlign: 'center', marginTop: '0.75rem' }}>
              <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>Shared truncated hash (16-bit)</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '1.1rem', color: 'var(--accent-red)', fontWeight: 600 }}>
                H(m₁) = H(m₂) = {collision.h1}
              </div>
            </div>
          )}
        </div>
      )}
    </div>

    <div className="card">
      <h3>🧪 Integration Test — 5 Distinct Inputs</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Hash 5 different messages; confirm distinct inputs → distinct digests.
      </p>
      <button className="btn btn-primary" onClick={runMultiHash} disabled={multiLoading}>
        {multiLoading ? <span className="spinner"/> : "Run Integration Test"}
      </button>
      {multiHash && (
        <div className="fade-in" style={{ marginTop: '0.75rem', overflowX: 'auto' }}>
          <table className="data-table">
            <thead><tr><th>#</th><th>Input (hex)</th><th>Digest (hex)</th><th>Unique?</th></tr></thead>
            <tbody>{multiHash.map((r, i) => {
              const dup = multiHash.findIndex((o, j) => j !== i && o.digest === r.digest);
              return (
                <tr key={i}>
                  <td>{i + 1}</td>
                  <td style={{ color: 'var(--accent-cyan)' }}>{r.input}</td>
                  <td style={{ color: 'var(--accent-green)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{r.digest?.slice(0, 16)}...</td>
                  <td><span className={`badge ${dup === -1 ? 'badge-success' : 'badge-error'}`}>{dup === -1 ? '✓' : '✗'}</span></td>
                </tr>
              );
            })}</tbody>
          </table>
        </div>
      )}
    </div>
  </>);
}

// ── PA#9: Birthday Attack (Live chart) ───────────────────────────────────────
export function PA09() {
  const [bits, setBits] = useState(12);
  const [result, setResult] = useState(null);
  const [curve, setCurve] = useState(null);
  const [loading, setLoading] = useState(false);
  const [curveLoading, setCurveLoading] = useState(false);

  const run = async () => { setLoading(true); setResult(await apiFetch("/pa09/birthday", { bit_size: bits })); setLoading(false); };
  const runCurve = async () => { setCurveLoading(true); setCurve(await apiFetch("/pa09/birthday_curve", { bit_size: bits, num_trials: 20 })); setCurveLoading(false); };

  const expected = Math.pow(2, bits / 2);
  const chartW = 560, chartH = 220, pad = { l: 50, r: 20, t: 10, b: 40 };
  const innerW = chartW - pad.l - pad.r, innerH = chartH - pad.t - pad.b;

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#9</span> Birthday Attack — Live Collision Search</h2>
      <p>Find hash collisions in O(2<sup>n/2</sup>) time. Expected ≈ {Math.round(expected)} evaluations for {bits}-bit hash.</p>
    </div>

    <div className="card">
      <h3>🎂 Attack Configuration</h3>
      <div className="input-group">
        <label>Hash output bit-length n</label>
        <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
          {[8, 10, 12, 14, 16].map(n => (
            <button key={n} onClick={() => { setBits(n); setResult(null); }}
              style={{ padding: '0.4rem 0.8rem', borderRadius: 6, border: '2px solid',
                borderColor: bits === n ? 'var(--accent-blue)' : 'var(--border)',
                background: bits === n ? 'rgba(59,130,246,0.2)' : 'var(--bg-input)',
                color: bits === n ? 'var(--accent-blue)' : 'var(--text-muted)',
                fontFamily: "'JetBrains Mono', monospace", fontSize: '0.85rem',
                fontWeight: 600, cursor: 'pointer', transition: 'all 0.15s' }}>{n}</button>
          ))}
          <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', alignSelf: 'center', marginLeft: 8 }}>
            2<sup>{bits}</sup> = {Math.pow(2, bits).toLocaleString()} hash space
          </span>
        </div>
      </div>
      <div className="input-row" style={{ marginTop: '0.5rem' }}>
        <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "🚀 Run Attack"}</button>
        <button className="btn btn-success" onClick={runCurve} disabled={curveLoading}>{curveLoading ? <span className="spinner"/> : "📊 Empirical Curve (all n)"}</button>
      </div>
    </div>

    {result && result.collision_found && (
      <div className="card fade-in">
        <h3>💥 Collision Found!</h3>
        <div className="result-row" style={{ marginBottom: '0.5rem' }}>
          <span className="badge badge-success">Found in {result.attempts} evaluations</span>
          <span className="badge badge-info">Expected: ≈ {result.expected_attempts}</span>
          <span className="badge badge-warn">Ratio: {(result.attempts / result.expected_attempts).toFixed(2)}×</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <Field label="Message m₁" value={result.m1_hex} />
          <Field label="Message m₂" value={result.m2_hex} />
        </div>
        {result.h1 && (
          <div style={{ background: 'linear-gradient(135deg, rgba(239,68,68,0.1), rgba(245,158,11,0.08))',
            borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)', textAlign: 'center' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 4 }}>Shared truncated hash</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '1.1rem', color: 'var(--accent-red)', fontWeight: 600 }}>
              H(m₁) = H(m₂) = {result.h1}
            </div>
          </div>
        )}
      </div>
    )}

    {curve?.curve_data && (
      <div className="card fade-in">
        <h3>📊 Empirical Birthday Curve ({curve.curve_data[0]?.trials} trials per n)</h3>
        {(() => {
          const data = curve.curve_data;
          const maxVal = Math.max(...data.map(d => Math.max(d.avg_attempts, d.expected_2n2)));
          const barW = innerW / data.length;
          return (
            <svg width={chartW} height={chartH} style={{ display: 'block', margin: '0 auto' }}>
              {[0, 0.25, 0.5, 0.75, 1].map(f => (
                <g key={f}>
                  <line x1={pad.l} y1={pad.t + innerH * (1-f)} x2={pad.l + innerW} y2={pad.t + innerH * (1-f)}
                    stroke="#2a3040" strokeWidth={1} strokeDasharray={f === 0 ? 'none' : '3,3'} />
                  <text x={pad.l - 6} y={pad.t + innerH * (1-f) + 4} textAnchor="end" fill="#64748b" fontSize={9} fontFamily="JetBrains Mono">{Math.round(maxVal * f)}</text>
                </g>
              ))}
              {data.map((d, i) => {
                const cx = pad.l + barW * i + barW / 2;
                const empH = (d.avg_attempts / maxVal) * innerH;
                const expH = (d.expected_2n2 / maxVal) * innerH;
                return (
                  <g key={d.bit_size}>
                    <rect x={cx - 16} y={pad.t + innerH - expH} width={14} height={expH} fill="none" stroke="#06b6d4" strokeWidth={1.5} strokeDasharray="4,2" rx={3} />
                    <rect x={cx + 2} y={pad.t + innerH - empH} width={14} height={empH} fill="rgba(59,130,246,0.6)" stroke="#3b82f6" strokeWidth={1} rx={3} />
                    <text x={cx} y={pad.t + innerH - Math.max(empH, expH) - 6} textAnchor="middle" fill="#e2e8f0" fontSize={8} fontWeight={600} fontFamily="JetBrains Mono">{d.ratio_vs_expected}×</text>
                    <text x={cx} y={chartH - 8} textAnchor="middle" fill="#94a3b8" fontSize={10} fontFamily="JetBrains Mono">n={d.bit_size}</text>
                  </g>
                );
              })}
              <rect x={chartW - 150} y={8} width={10} height={10} fill="rgba(59,130,246,0.6)" rx={2} />
              <text x={chartW - 136} y={17} fill="#94a3b8" fontSize={9}>Empirical avg</text>
              <rect x={chartW - 150} y={22} width={10} height={10} fill="none" stroke="#06b6d4" strokeDasharray="3,2" rx={2} />
              <text x={chartW - 136} y={31} fill="#94a3b8" fontSize={9}>Expected 2^(n/2)</text>
            </svg>
          );
        })()}
        <div style={{ overflowX: 'auto', marginTop: '0.75rem' }}>
          <table className="data-table">
            <thead><tr>{['n', '2^n', '2^(n/2)', 'Avg', 'Min', 'Max', 'Ratio'].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>{curve.curve_data.map(d => (
              <tr key={d.bit_size}>
                <td style={{color:'var(--accent-blue)', fontWeight:600}}>{d.bit_size}</td>
                <td>{Math.pow(2, d.bit_size)}</td><td style={{color:'var(--accent-cyan)'}}>{d.expected_2n2}</td>
                <td style={{color:'var(--accent-green)', fontWeight:600}}>{d.avg_attempts}</td>
                <td>{d.min_attempts}</td><td>{d.max_attempts}</td>
                <td><span className={`badge ${Math.abs(d.ratio_vs_expected - 1) < 0.5 ? 'badge-success' : 'badge-warn'}`} style={{fontSize:'0.7rem'}}>{d.ratio_vs_expected}×</span></td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </div>
    )}

    {curve?.probability_curve && (() => {
      const pc = curve.probability_curve;
      const cW = 560, cH = 200, cP = { l: 45, r: 20, t: 15, b: 35 };
      const iW = cW - cP.l - cP.r, iH = cH - cP.t - cP.b;
      const maxK = pc[pc.length - 1]?.k || 1;
      const xS = k => cP.l + (k / maxK) * iW, yS = p => cP.t + (1 - p) * iH;
      const expK = curve.expected_collision_point;
      const pathD = pc.map((pt, i) => `${i === 0 ? 'M' : 'L'} ${xS(pt.k).toFixed(1)} ${yS(pt.p).toFixed(1)}`).join(' ');
      return (
        <div className="card fade-in">
          <h3>📈 Collision Probability vs Hashes Computed (n={curve.selected_bit_size})</h3>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
            P(collision) = 1 − e<sup>−k²/2N</sup>. Vertical marker at 2<sup>{curve.selected_bit_size}/2</sup> ≈ {Math.round(expK)}.
          </p>
          <svg width={cW} height={cH} style={{ display: 'block', margin: '0 auto' }}>
            {[0, 0.25, 0.5, 0.75, 1].map(f => (
              <g key={f}><line x1={cP.l} y1={yS(f)} x2={cP.l+iW} y2={yS(f)} stroke="#2a3040" strokeDasharray="3,3" />
              <text x={cP.l-5} y={yS(f)+4} textAnchor="end" fill="#64748b" fontSize={8} fontFamily="JetBrains Mono">{(f*100).toFixed(0)}%</text></g>
            ))}
            <path d={pathD} fill="none" stroke="url(#pg)" strokeWidth={2} />
            <defs><linearGradient id="pg" x1="0" y1="0" x2="1" y2="0"><stop offset="0%" stopColor="#3b82f6"/><stop offset="100%" stopColor="#ef4444"/></linearGradient></defs>
            <line x1={xS(expK)} y1={cP.t} x2={xS(expK)} y2={cP.t+iH} stroke="#f59e0b" strokeWidth={1.5} strokeDasharray="5,3" />
            <text x={xS(expK)} y={cP.t-2} textAnchor="middle" fill="#f59e0b" fontSize={8} fontFamily="JetBrains Mono" fontWeight={600}>2^({curve.selected_bit_size}/2)={Math.round(expK)}</text>
            <text x={cP.l+iW/2} y={cH-5} textAnchor="middle" fill="#64748b" fontSize={9}>Hashes computed (k)</text>
          </svg>
        </div>
      );
    })()}
  </>);
}

// ── PA#10: HMAC — Visual Construction + Verify/Forge ─────────────────────────
export function PA10() {
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [msg, setMsg] = useState("48656c6c6f");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifyLoading, setVerifyLoading] = useState(false);

  const run = async () => { setLoading(true); setResult(await apiFetch("/pa10/hmac", { key_hex: key, message_hex: msg })); setLoading(false); };

  const runVerify = async () => {
    if (!result?.tag_hex) return;
    setVerifyLoading(true);
    const valid = await apiFetch("/pa10/hmac_verify", { key_hex: key, message_hex: msg, tag_hex: result.tag_hex });
    // Tampered message
    const tamperedMsg = msg.slice(0, -2) + (msg.slice(-2) === "00" ? "ff" : "00");
    const invalid = await apiFetch("/pa10/hmac_verify", { key_hex: key, message_hex: tamperedMsg, tag_hex: result.tag_hex });
    setVerifyResult({ valid: valid?.valid, invalid: invalid?.valid, tamperedMsg });
    setVerifyLoading(false);
  };

  // SVG HMAC construction diagram
  const DiagramSVG = () => (
    <svg width="560" height="140" style={{ display: 'block', margin: '0.5rem auto' }}>
      {/* k ⊕ ipad */}
      <rect x="10" y="10" width="80" height="30" rx="6" fill="rgba(59,130,246,0.15)" stroke="#3b82f6" strokeWidth="1.5"/>
      <text x="50" y="30" textAnchor="middle" fill="#3b82f6" fontSize="10" fontWeight="600" fontFamily="JetBrains Mono">k ⊕ ipad</text>
      {/* concat */}
      <text x="100" y="30" textAnchor="middle" fill="#64748b" fontSize="14">‖</text>
      {/* message */}
      <rect x="110" y="10" width="60" height="30" rx="6" fill="rgba(6,182,212,0.15)" stroke="#06b6d4" strokeWidth="1.5"/>
      <text x="140" y="30" textAnchor="middle" fill="#06b6d4" fontSize="10" fontWeight="600" fontFamily="JetBrains Mono">m</text>
      {/* arrow to inner H */}
      <line x1="170" y1="25" x2="200" y2="25" stroke="#64748b" strokeWidth="1.5" markerEnd="url(#arrowH)"/>
      {/* inner H */}
      <rect x="200" y="5" width="70" height="40" rx="8" fill="rgba(139,92,246,0.15)" stroke="#8b5cf6" strokeWidth="1.5"/>
      <text x="235" y="22" textAnchor="middle" fill="#8b5cf6" fontSize="9" fontWeight="600" fontFamily="JetBrains Mono">H(inner)</text>
      <text x="235" y="36" textAnchor="middle" fill="#64748b" fontSize="7" fontFamily="JetBrains Mono">DLP-Hash</text>
      {/* arrow down to second row */}
      <line x1="235" y1="45" x2="235" y2="70" stroke="#64748b" strokeWidth="1.5"/>
      {/* k ⊕ opad */}
      <rect x="110" y="75" width="80" height="30" rx="6" fill="rgba(245,158,11,0.15)" stroke="#f59e0b" strokeWidth="1.5"/>
      <text x="150" y="95" textAnchor="middle" fill="#f59e0b" fontSize="10" fontWeight="600" fontFamily="JetBrains Mono">k ⊕ opad</text>
      {/* concat */}
      <text x="200" y="95" textAnchor="middle" fill="#64748b" fontSize="14">‖</text>
      {/* inner result */}
      <rect x="210" y="75" width="60" height="30" rx="6" fill="rgba(139,92,246,0.1)" stroke="#8b5cf6" strokeWidth="1" strokeDasharray="3,2"/>
      <text x="240" y="95" textAnchor="middle" fill="#8b5cf6" fontSize="9" fontFamily="JetBrains Mono">h_inner</text>
      {/* arrow to outer H */}
      <line x1="270" y1="90" x2="310" y2="90" stroke="#64748b" strokeWidth="1.5"/>
      {/* outer H */}
      <rect x="310" y="70" width="70" height="40" rx="8" fill="rgba(16,185,129,0.15)" stroke="#10b981" strokeWidth="1.5"/>
      <text x="345" y="87" textAnchor="middle" fill="#10b981" fontSize="9" fontWeight="600" fontFamily="JetBrains Mono">H(outer)</text>
      <text x="345" y="101" textAnchor="middle" fill="#64748b" fontSize="7" fontFamily="JetBrains Mono">DLP-Hash</text>
      {/* arrow to tag */}
      <line x1="380" y1="90" x2="420" y2="90" stroke="#64748b" strokeWidth="1.5"/>
      {/* tag output */}
      <rect x="420" y="75" width="70" height="30" rx="6" fill="rgba(16,185,129,0.2)" stroke="#10b981" strokeWidth="2"/>
      <text x="455" y="95" textAnchor="middle" fill="#10b981" fontSize="11" fontWeight="700" fontFamily="JetBrains Mono">TAG</text>
      <defs><marker id="arrowH" markerWidth="6" markerHeight="6" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6" fill="#64748b"/></marker></defs>
    </svg>
  );

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#10</span> HMAC — Hash-Based MAC</h2>
      <p>HMAC = H((k ⊕ opad) ‖ H((k ⊕ ipad) ‖ m)) using DLP-Hash from PA#8.</p>
    </div>

    <div className="card">
      <h3>🔧 HMAC Construction</h3>
      <DiagramSVG />
      <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center', marginTop: 4 }}>
        ipad = 0x36 repeated, opad = 0x5c repeated. H = DLP_Hash from PA#8.
      </div>
    </div>

    <div className="card">
      <h3>🏷️ Compute HMAC Tag</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <div className="input-group"><label>Key k (hex)</label><input value={key} onChange={e => setKey(e.target.value)} /></div>
        <div className="input-group"><label>Message m (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      </div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "🏷️ Compute HMAC"}</button>
        {result?.tag_hex && <button className="btn btn-success" onClick={runVerify} disabled={verifyLoading}>{verifyLoading ? <span className="spinner"/> : "✅ Verify + Forgery Test"}</button>}
      </div>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="HMAC Tag (hex)" value={result.tag_hex} accent="var(--accent-green)" />
        </div>
      )}
    </div>

    {verifyResult && (
      <div className="card fade-in">
        <h3>🔒 Verification & Forgery Demo</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
          <div style={{ background: 'rgba(16,185,129,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(16,185,129,0.3)' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6 }}>Original message</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--accent-cyan)', marginBottom: 8, wordBreak: 'break-all' }}>{msg}</div>
            <span className={`badge ${verifyResult.valid ? 'badge-success' : 'badge-error'}`}>
              {verifyResult.valid ? '✅ HMAC Valid' : '❌ HMAC Invalid'}
            </span>
          </div>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6 }}>Tampered message</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--accent-red)', marginBottom: 8, wordBreak: 'break-all' }}>{verifyResult.tamperedMsg}</div>
            <span className={`badge ${verifyResult.invalid ? 'badge-error' : 'badge-success'}`}>
              {verifyResult.invalid ? '⚠️ Forgery Accepted!' : '✅ Forgery Rejected'}
            </span>
          </div>
        </div>
        <div style={{ marginTop: '0.75rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          Even a 1-bit change to the message invalidates the tag — EUF-CMA security.
        </div>
      </div>
    )}
  </>);
}

// ── PA#11: Diffie-Hellman (Two-panel + MITM) ────────────────────────────────
export function PA11() {
  const [result, setResult] = useState(null);
  const [mitmResult, setMitmResult] = useState(null);
  const [enableEve, setEnableEve] = useState(false);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState(0);

  const runExchange = async () => {
    setLoading(true); setMitmResult(null); setStep(1);
    const r = await apiFetch("/pa11/dh_interactive");
    setResult(r);
    setTimeout(() => setStep(2), 600);
    setTimeout(() => setStep(3), 1200);
    setLoading(false);
  };

  const runMitm = async () => {
    setLoading(true); setResult(null);
    const r = await apiFetch("/pa11/mitm", { enable_eve: enableEve });
    setMitmResult(r); setStep(3); setLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#11</span> Diffie-Hellman Key Exchange</h2>
      <p>Two parties establish a shared secret over an insecure channel. Enable Eve for MITM.</p>
    </div>

    <div className="card">
      <h3>⚙️ Exchange Controls</h3>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <button className="btn btn-primary" onClick={runExchange} disabled={loading}>
          {loading ? <span className="spinner"/> : "🤝 Run DH Exchange"}
        </button>
        <button className="btn btn-danger" onClick={runMitm} disabled={loading}>
          {loading ? <span className="spinner"/> : enableEve ? "🕵️ Run with Eve (MITM)" : "🤝 Run (no Eve)"}
        </button>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', cursor: 'pointer',
          color: enableEve ? 'var(--accent-red)' : 'var(--text-secondary)' }}>
          <input type="checkbox" checked={enableEve} onChange={e => setEnableEve(e.target.checked)} />
          🕵️ Enable Eve (MITM)
        </label>
      </div>
    </div>

    {result && (
      <div className="fade-in">
        <div className="card" style={{ padding: '0.75rem' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
            Group: p = {result.p?.slice(0, 16)}..., g = {result.g?.slice(0, 10)}...
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: '0.75rem', alignItems: 'stretch' }}>
          <div className="card" style={{ borderColor: 'rgba(59,130,246,0.4)' }}>
            <h3 style={{ color: 'var(--accent-blue)' }}>👩 Alice</h3>
            <Field label="Private key a" value={result.alice?.private} />
            {step >= 1 && <Field label="Public A = gᵃ mod p" value={result.alice?.public} accent="var(--accent-blue)" />}
            {step >= 3 && <Field label="Shared K = Bᵃ mod p" value={result.alice_shared} accent="var(--accent-green)" />}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: '1.5rem', padding: '0 0.5rem' }}>
            {step >= 2 && (<>
              <div className="fade-in" style={{ textAlign: 'center', fontSize: '0.7rem', color: 'var(--accent-blue)' }}>A →<div style={{ fontSize: '1.2rem' }}>→</div></div>
              <div className="fade-in" style={{ textAlign: 'center', fontSize: '0.7rem', color: 'var(--accent-purple)' }}>← B<div style={{ fontSize: '1.2rem' }}>←</div></div>
            </>)}
          </div>
          <div className="card" style={{ borderColor: 'rgba(139,92,246,0.4)' }}>
            <h3 style={{ color: 'var(--accent-purple)' }}>👨 Bob</h3>
            <Field label="Private key b" value={result.bob?.private} />
            {step >= 1 && <Field label="Public B = gᵇ mod p" value={result.bob?.public} accent="var(--accent-purple)" />}
            {step >= 3 && <Field label="Shared K = Aᵇ mod p" value={result.bob_shared} accent="var(--accent-green)" />}
          </div>
        </div>
        {step >= 3 && (
          <div className="card fade-in" style={{
            background: result.keys_match ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)',
            borderColor: result.keys_match ? 'var(--accent-green)' : 'var(--accent-red)', textAlign: 'center' }}>
            <span className={`badge ${result.keys_match ? 'badge-success' : 'badge-error'}`} style={{ fontSize: '0.9rem' }}>
              {result.keys_match ? '✅ Keys Match! K_A = K_B' : '❌ Keys Do NOT Match'}
            </span>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--accent-green)', marginTop: '0.5rem', wordBreak: 'break-all' }}>
              Shared secret: {result.shared_key}
            </div>
          </div>
        )}
      </div>
    )}

    {mitmResult && (
      <div className="fade-in">
        <div style={{ display: 'grid', gridTemplateColumns: mitmResult.mitm_active ? '1fr 1fr 1fr' : '1fr 1fr', gap: '0.75rem' }}>
          <div className="card" style={{ borderColor: 'rgba(59,130,246,0.4)' }}>
            <h3 style={{ color: 'var(--accent-blue)' }}>👩 Alice</h3>
            <Field label="Public A" value={mitmResult.alice?.public} accent="var(--accent-blue)" />
            <Field label="Thinks shared K =" value={mitmResult.alice?.thinks_shared} accent={mitmResult.mitm_active ? 'var(--accent-amber)' : 'var(--accent-green)'} />
          </div>
          {mitmResult.mitm_active && mitmResult.eve && (
            <div className="card fade-in" style={{ borderColor: 'rgba(239,68,68,0.5)', background: 'rgba(239,68,68,0.05)' }}>
              <h3 style={{ color: 'var(--accent-red)' }}>🕵️ Eve (MITM)</h3>
              <Field label="Public E (sent to both)" value={mitmResult.eve.public} accent="var(--accent-red)" />
              <Field label="Key with Alice" value={mitmResult.eve.key_with_alice} accent="var(--accent-amber)" />
              <Field label="Key with Bob" value={mitmResult.eve.key_with_bob} accent="var(--accent-amber)" />
              <span className="badge badge-error" style={{ fontSize: '0.7rem' }}>Eve reads ALL traffic!</span>
            </div>
          )}
          <div className="card" style={{ borderColor: 'rgba(139,92,246,0.4)' }}>
            <h3 style={{ color: 'var(--accent-purple)' }}>👨 Bob</h3>
            <Field label="Public B" value={mitmResult.bob?.public} accent="var(--accent-purple)" />
            <Field label="Thinks shared K =" value={mitmResult.bob?.thinks_shared} accent={mitmResult.mitm_active ? 'var(--accent-amber)' : 'var(--accent-green)'} />
          </div>
        </div>
        <div className="card" style={{
          background: mitmResult.mitm_active ? 'rgba(239,68,68,0.08)' : 'rgba(16,185,129,0.08)',
          borderColor: mitmResult.mitm_active ? 'var(--accent-red)' : 'var(--accent-green)', textAlign: 'center' }}>
          {mitmResult.mitm_active ? (<>
            <span className="badge badge-error" style={{ fontSize: '0.85rem' }}>⚠️ MITM Successful — Alice & Bob have DIFFERENT keys!</span>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.5rem' }}>Eve can decrypt, read, re-encrypt, and forward all messages.</p>
          </>) : (
            <span className="badge badge-success" style={{ fontSize: '0.85rem' }}>✅ No MITM — Keys match: {mitmResult.keys_match ? 'YES' : 'NO'}</span>
          )}
        </div>
      </div>
    )}
  </>);
}

// ── PA#12: RSA — Determinism Attack Demo ─────────────────────────────────────
export function PA12() {
  const [msg, setMsg] = useState(42);
  const [result, setResult] = useState(null);
  const [detResult, setDetResult] = useState(null);
  const [usePkcs, setUsePkcs] = useState(false);
  const [loading, setLoading] = useState(false);
  const [detLoading, setDetLoading] = useState(false);

  const run = async () => { setLoading(true); setResult(await apiFetch("/pa12/encrypt", { message: msg })); setLoading(false); };
  const runDet = async () => {
    setDetLoading(true);
    const r = await apiFetch("/pa12/determinism", { message: msg, use_pkcs: usePkcs });
    setDetResult(r); setDetLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#12</span> RSA — Textbook vs PKCS#1 v1.5</h2>
      <p>Textbook RSA is deterministic → identical ciphertexts leak plaintext. PKCS random padding fixes this.</p>
    </div>

    <div className="card">
      <h3>🗝️ RSA Encrypt/Decrypt (Textbook)</h3>
      <div className="input-group"><label>Message m (integer)</label><input type="number" value={msg} onChange={e => setMsg(+e.target.value)} /></div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>{loading ? <span className="spinner"/> : "Encrypt → Decrypt"}</button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <div className="result-row" style={{ marginBottom: "0.75rem" }}>
            <span className={`badge ${result.correct ? "badge-success" : "badge-error"}`}>
              Roundtrip: {result.correct ? "✓ Correct" : "✗ Failed"}
            </span>
          </div>
          <Field label="Plaintext m" value={result.message} mono={false} accent="var(--text-primary)" />
          <Field label="Ciphertext c = m^e mod N (prefix)" value={result.ciphertext_prefix} />
          <Field label="Decrypted m' = c^d mod N" value={result.decrypted} mono={false} accent="var(--accent-green)" />
        </div>
      )}
    </div>

    <div className="card" style={{ borderColor: usePkcs ? 'rgba(16,185,129,0.4)' : 'rgba(239,68,68,0.4)' }}>
      <h3>🔬 Determinism Attack Demo</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Click "Encrypt Twice" — in Textbook mode, both ciphertexts are <strong>identical</strong> (deterministic = information leaks!).
        Switch to PKCS#1 v1.5 — random PS padding makes each ciphertext different.
      </p>
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.82rem', cursor: 'pointer',
          padding: '0.4rem 0.7rem', borderRadius: 6,
          background: usePkcs ? 'rgba(16,185,129,0.12)' : 'rgba(239,68,68,0.08)',
          border: `1px solid ${usePkcs ? 'var(--accent-green)' : 'var(--accent-red)'}`,
          color: usePkcs ? 'var(--accent-green)' : 'var(--accent-red)' }}>
          <input type="checkbox" checked={usePkcs} onChange={e => { setUsePkcs(e.target.checked); setDetResult(null); }} />
          {usePkcs ? '✅ PKCS#1 v1.5 (randomized)' : '⚠️ Textbook RSA (deterministic)'}
        </label>
      </div>
      <button className="btn btn-danger" onClick={runDet} disabled={detLoading}>
        {detLoading ? <span className="spinner"/> : "🔄 Encrypt Twice (same m)"}
      </button>

      {detResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div className="result-row" style={{ marginBottom: '0.75rem' }}>
            <span className="badge badge-info">Mode: {detResult.mode}</span>
            <span className={`badge ${detResult.identical ? 'badge-error' : 'badge-success'}`}>
              {detResult.identical ? '⚠️ Ciphertexts IDENTICAL — plaintext leaked!' : '✅ Ciphertexts DIFFER — safe'}
            </span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div style={{ background: 'rgba(59,130,246,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(59,130,246,0.2)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Encryption #1</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>{detResult.c1_prefix}...</div>
            </div>
            <div style={{ background: 'rgba(139,92,246,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(139,92,246,0.2)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginBottom: 4 }}>Encryption #2</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--accent-purple)', wordBreak: 'break-all' }}>{detResult.c2_prefix}...</div>
            </div>
          </div>

          {detResult.identical && (
            <div style={{ background: 'linear-gradient(135deg, rgba(239,68,68,0.12), rgba(245,158,11,0.08))',
              borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)', textAlign: 'center', marginTop: '0.75rem' }}>
              <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--accent-red)' }}>
                🚨 Identical ciphertexts: plaintext leaked!
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 4 }}>
                An attacker sees c₁ = c₂ and knows the same message was sent both times.
              </div>
            </div>
          )}

          {detResult.ps1_hex && (
            <div className="card" style={{ marginTop: '0.75rem', background: 'rgba(16,185,129,0.05)', borderColor: 'rgba(16,185,129,0.3)' }}>
              <h3 style={{ fontSize: '0.85rem', color: 'var(--accent-green)' }}>🎲 Random Padding Bytes (PS)</h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
                <Field label="PS₁ (random, non-zero)" value={detResult.ps1_hex} accent="var(--accent-blue)" />
                <Field label="PS₂ (random, non-zero)" value={detResult.ps2_hex} accent="var(--accent-purple)" />
              </div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 4 }}>
                Format: 00 ‖ 02 ‖ PS ‖ 00 ‖ m — random PS makes each encryption unique.
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  </>);
}
