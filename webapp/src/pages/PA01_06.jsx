import { useState, useEffect, useCallback } from "react";
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

function StatusBadge({ ok, trueLabel, falseLabel }) {
  return (
    <span className={`badge ${ok ? "badge-success" : "badge-error"}`}>
      {ok ? trueLabel : falseLabel}
    </span>
  );
}

// ── PA#1: OWF & PRG ──────────────────────────────────────────────────────────
export function PA01() {
  const [seed, setSeed] = useState("deadbeefcafebabe");
  const [owfInput, setOwfInput] = useState("deadbeefcafebabe");
  const [outputBits, setOutputBits] = useState(128);
  const [prg, setPrg] = useState(null);
  const [owf, setOwf] = useState(null);
  const [nist, setNist] = useState(null);
  const [loading, setLoading] = useState(false);
  const [owfLoading, setOwfLoading] = useState(false);
  const [nistLoading, setNistLoading] = useState(false);

  const fetchPrg = useCallback(async () => {
    if (!seed) return;
    setLoading(true);
    const r = await apiFetch("/pa01/prg", { seed_hex: seed, output_bits: outputBits });
    setPrg(r);
    setNist(null);
    setLoading(false);
  }, [seed, outputBits]);

  useEffect(() => {
    const t = setTimeout(fetchPrg, 300);
    return () => clearTimeout(t);
  }, [fetchPrg]);

  const runOwf = async () => {
    if (!owfInput) return;
    setOwfLoading(true);
    const r = await apiFetch("/pa01/owf", { input_hex: owfInput });
    setOwf(r);
    setOwfLoading(false);
  };

  const runNist = async () => {
    setNistLoading(true);
    const r = await apiFetch("/pa01/randomness_test", { seed_hex: seed, output_bits: Math.max(outputBits, 128) });
    setNist(r);
    setNistLoading(false);
  };

  const onesRatio = prg?.ones_ratio ?? 0.5;
  const onesPercent = Math.round(onesRatio * 100);

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#1</span> OWF &amp; PRG — Live Output Viewer</h2>
      <p>DLP-based OWF with Goldreich-Levin hard-core bit PRG. Slide to expand.</p>
    </div>

    {/* OWF Section */}
    <div className="card">
      <h3>🔐 One-Way Function f(x) = g^x mod p</h3>
      <div className="input-group">
        <label>Input x (hex)</label>
        <input value={owfInput} onChange={e => setOwfInput(e.target.value)} placeholder="e.g. deadbeefcafebabe" />
      </div>
      <button className="btn btn-primary" onClick={runOwf} disabled={owfLoading}>
        {owfLoading ? <span className="spinner"/> : "Evaluate OWF"}
      </button>
      {owf && !owf.error && (
        <div className="fade-in" style={{ marginTop: "0.75rem" }}>
          <Field label="Input x (integer)" value={owf.input} />
          <Field label="Output f(x) = g^x mod p" value={owf.output} accent="var(--accent-green)" />
          <Field label="One-way property" value={owf.note} mono={false} accent="var(--text-secondary)" />
          <div className="result-row">
            <StatusBadge ok={owf.one_way} trueLabel="✓ One-Way" falseLabel="✗ Not One-Way" />
          </div>
        </div>
      )}
      {owf?.error && <div className="output-box fade-in"><pre style={{color:"var(--accent-red)"}}>{owf.error}</pre></div>}
    </div>

    {/* PRG Section */}
    <div className="card">
      <h3>🔑 Seed Input</h3>
      <div className="input-group">
        <label>Seed s (hex)</label>
        <input value={seed} onChange={e => setSeed(e.target.value)} placeholder="e.g. deadbeefcafebabe" />
      </div>
    </div>

    <div className="card">
      <h3>📏 Output Length ℓ = {outputBits} bits ({outputBits / 8} bytes)</h3>
      <input type="range" min={8} max={512} step={8} value={outputBits}
        onChange={e => setOutputBits(+e.target.value)}
        style={{ width: '100%', accentColor: 'var(--accent-blue)', marginBottom: '0.75rem' }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', color: 'var(--text-muted)' }}>
        <span>8 bits</span><span>512 bits</span>
      </div>
    </div>

    <div className="card">
      <h3>📡 Live PRG Output G(s) {loading && <span className="spinner" style={{marginLeft:6}}/>}</h3>
      {prg?.output_hex && (
        <div className="fade-in">
          <div style={{ fontSize: "0.68rem", color: "var(--text-muted)", marginBottom: 4 }}>Output hex (seed={prg.seed})</div>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: '0.72rem',
            background: 'var(--bg-input)', borderRadius: 8, padding: '0.75rem',
            border: '1px solid var(--border)', wordBreak: 'break-all', lineHeight: 1.8,
            color: 'var(--accent-cyan)', letterSpacing: '0.05em'
          }}>
            {prg.output_hex.match(/.{1,2}/g)?.map((byte, i) => (
              <span key={i} style={{
                padding: '2px 3px', margin: 1, borderRadius: 3,
                background: i % 2 === 0 ? 'rgba(6,182,212,0.08)' : 'transparent'
              }}>{byte}</span>
            ))}
          </div>
          <div style={{ marginTop: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: 4 }}>
              <span style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
                Bit ratio: {prg.ones_count} ones / {prg.zeros_count} zeros ({onesPercent}% ones)
              </span>
              <span className={`badge ${Math.abs(onesPercent - 50) < 10 ? 'badge-success' : 'badge-warn'}`} style={{fontSize:'0.68rem'}}>
                {Math.abs(onesPercent - 50) < 10 ? '≈ 50%' : 'Skewed'}
              </span>
            </div>
            <div style={{ width: '100%', height: 10, borderRadius: 5, background: 'var(--bg-input)', overflow: 'hidden', border: '1px solid var(--border)' }}>
              <div style={{ width: `${onesPercent}%`, height: '100%', borderRadius: 5,
                background: `linear-gradient(90deg, var(--accent-blue), var(--accent-cyan))`,
                transition: 'width 0.3s ease' }} />
            </div>
          </div>
        </div>
      )}
    </div>

    <div className="card">
      <h3>🧪 NIST Randomness Tests</h3>
      <p style={{fontSize:'0.78rem', color:'var(--text-secondary)', marginBottom:'0.75rem'}}>
        Runs frequency (monobit), runs, and serial tests on the PRG output.
      </p>
      <button className="btn btn-primary" onClick={runNist} disabled={nistLoading}>
        {nistLoading ? <span className="spinner"/> : "Run Randomness Tests"}
      </button>
      {nist && !nist.error && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          {Object.entries(nist).filter(([k]) => k !== 'label' && typeof nist[k] === 'number').map(([testName, pVal]) => {
            const passed = pVal > 0.01;
            return (
              <div key={testName} style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.4rem 0', borderBottom: '1px solid var(--border)' }}>
                <span className={`badge ${passed ? 'badge-success' : 'badge-error'}`} style={{minWidth:60, justifyContent:'center'}}>
                  {passed ? 'PASS' : 'FAIL'}
                </span>
                <span style={{ fontSize: '0.8rem', fontWeight: 500, textTransform: 'capitalize' }}>{testName}</span>
                <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginLeft: 'auto' }}>p = {pVal.toFixed(4)}</span>
              </div>
            );
          })}
        </div>
      )}
      {nist?.error && <div className="output-box fade-in"><pre style={{color:'var(--accent-red)'}}>{nist.error}</pre></div>}
    </div>
  </>);
}

// ── PA#2: GGM Tree Visualiser ────────────────────────────────────────────────
export function PA02() {
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [queryBits, setQueryBits] = useState("0110");
  const [tree, setTree] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchTree = useCallback(async () => {
    if (!key || !queryBits) return;
    setLoading(true);
    const r = await apiFetch("/pa02/ggm_tree", { key_hex: key, query_bits: queryBits });
    setTree(r);
    setLoading(false);
  }, [key, queryBits]);

  useEffect(() => {
    const t = setTimeout(fetchTree, 400);
    return () => clearTimeout(t);
  }, [fetchTree]);

  const toggleBit = (i) => {
    const bits = queryBits.split('');
    bits[i] = bits[i] === '0' ? '1' : '0';
    setQueryBits(bits.join(''));
  };

  const depth = queryBits.length;
  const nodeR = 28;
  const levelH = 70;
  const svgW = Math.max(600, (2 ** depth) * 70);
  const svgH = (depth + 1) * levelH + 60;

  const getNodePos = (id, level) => {
    if (level === 0) return { x: svgW / 2, y: 40 };
    const idx = parseInt(id, 2);
    const count = 2 ** level;
    const spacing = svgW / (count + 1);
    return { x: spacing * (idx + 1), y: 40 + level * levelH };
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#2</span> GGM Tree Visualiser</h2>
      <p>Interactive PRF tree — click bits to re-route the path instantly</p>
    </div>

    <div className="card">
      <h3>🔑 Key &amp; Query</h3>
      <div className="input-group">
        <label>Key k (hex, 16 bytes)</label>
        <input value={key} onChange={e => setKey(e.target.value)} />
      </div>
      <div className="input-group">
        <label>Query x (bit string, n ≤ 8) — click bits to toggle</label>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 4 }}>
          {queryBits.split('').map((b, i) => (
            <button key={i} onClick={() => toggleBit(i)}
              style={{
                width: 36, height: 36, borderRadius: 6, border: '2px solid',
                borderColor: b === '1' ? 'var(--accent-blue)' : 'var(--border)',
                background: b === '1' ? 'rgba(59,130,246,0.2)' : 'var(--bg-input)',
                color: b === '1' ? 'var(--accent-blue)' : 'var(--text-muted)',
                fontFamily: "'JetBrains Mono', monospace", fontSize: '1rem',
                fontWeight: 700, cursor: 'pointer', transition: 'all 0.15s'
              }}>
              {b}
            </button>
          ))}
          <button className="btn btn-ghost" style={{fontSize:'0.7rem'}} onClick={() => setQueryBits(queryBits + '0')}>+ bit</button>
          {queryBits.length > 1 && <button className="btn btn-ghost" style={{fontSize:'0.7rem'}} onClick={() => setQueryBits(queryBits.slice(0,-1))}>− bit</button>}
        </div>
      </div>
    </div>

    {tree?.leaf_hex && (
      <div className="card" style={{ background: 'linear-gradient(135deg, rgba(59,130,246,0.12), rgba(6,182,212,0.08))', borderColor: 'var(--accent-blue)' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: 4 }}>{tree.leaf_label}</div>
          <div style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: '1.1rem',
            color: 'var(--accent-cyan)', fontWeight: 600, letterSpacing: '0.05em',
            wordBreak: 'break-all'
          }}>
            {tree.leaf_hex}
          </div>
        </div>
      </div>
    )}

    <div className="card" style={{ overflow: 'auto' }}>
      <h3>🌳 GGM Binary Tree (depth {depth}) {loading && <span className="spinner" style={{marginLeft:6}}/>}</h3>
      {tree?.tree && (
        <svg width={svgW} height={svgH} style={{ display: 'block', margin: '0 auto' }}>
          {tree.tree.filter(n => n.level > 0).map(node => {
            const parentId = node.id.slice(0, -1);
            const parentLvl = node.level - 1;
            const p = getNodePos(parentId || '0', parentLvl);
            const c = getNodePos(node.id, node.level);
            return (
              <line key={`e_${node.id}`} x1={p.x} y1={p.y + nodeR} x2={c.x} y2={c.y - nodeR}
                stroke={node.on_path ? '#3b82f6' : '#2a3040'} strokeWidth={node.on_path ? 2.5 : 1}
                opacity={node.on_path ? 1 : 0.4} />
            );
          })}
          {tree.tree.filter(n => n.level > 0).map(node => {
            const parentId = node.id.slice(0, -1);
            const parentLvl = node.level - 1;
            const p = getNodePos(parentId || '0', parentLvl);
            const c = getNodePos(node.id, node.level);
            const bit = node.id[node.id.length - 1];
            return (
              <text key={`el_${node.id}`} x={(p.x + c.x) / 2 + (bit === '0' ? -10 : 10)}
                y={(p.y + c.y) / 2 + 4}
                fill={node.on_path ? '#60a5fa' : '#475569'} fontSize={11} fontWeight={600}
                textAnchor="middle" fontFamily="JetBrains Mono, monospace">
                {bit === '0' ? 'G₀' : 'G₁'}
              </text>
            );
          })}
          {tree.tree.map(node => {
            const pos = getNodePos(node.id || '0', node.level);
            return (
              <g key={`n_${node.id || 'root'}`}>
                <circle cx={pos.x} cy={pos.y} r={nodeR}
                  fill={node.on_path ? (node.is_leaf ? 'rgba(6,182,212,0.25)' : 'rgba(59,130,246,0.2)') : 'rgba(42,48,64,0.5)'}
                  stroke={node.on_path ? (node.is_leaf ? '#06b6d4' : '#3b82f6') : '#2a3040'}
                  strokeWidth={node.on_path ? 2 : 1} />
                <text x={pos.x} y={pos.y - 4} textAnchor="middle"
                  fill={node.on_path ? '#e2e8f0' : '#64748b'} fontSize={9}
                  fontFamily="JetBrains Mono, monospace" fontWeight={node.on_path ? 600 : 400}>
                  {node.label}
                </text>
                <text x={pos.x} y={pos.y + 10} textAnchor="middle"
                  fill={node.on_path ? '#06b6d4' : '#475569'} fontSize={7.5}
                  fontFamily="JetBrains Mono, monospace">
                  {node.hex}
                </text>
              </g>
            );
          })}
        </svg>
      )}
    </div>
  </>);
}

// ── PA#3: IND-CPA Game ───────────────────────────────────────────────────────
export function PA03() {
  const [m0, setM0] = useState("48656c6c6f000000000000000000000000");
  const [m1, setM1] = useState("576f726c64000000000000000000000000");
  const [reuseNonce, setReuseNonce] = useState(false);
  const [challenge, setChallenge] = useState(null);
  const [guessed, setGuessed] = useState(false);
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  const encrypt = async () => {
    setLoading(true);
    setGuessed(false);
    const r = await apiFetch("/pa03/cpa_challenge", { m0_hex: m0, m1_hex: m1, reuse_nonce: reuseNonce });
    setChallenge(r);
    setLoading(false);
  };

  const guess = (g) => {
    if (!challenge || guessed) return;
    const correct = g === challenge.b;
    setGuessed(true);
    setHistory(prev => [...prev, { round: prev.length + 1, guess: g, actual: challenge.b, correct,
      nonce: challenge.nonce_hex, reuse: challenge.reuse_nonce }]);
  };

  const correctCount = history.filter(h => h.correct).length;
  const total = history.length;
  const advantage = total > 0 ? Math.abs((correctCount / total) - 0.5) * 2 : 0;

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#3</span> IND-CPA Game — Play the Adversary</h2>
      <p>Can you distinguish which message was encrypted? Advantage should ≈ 0 in secure mode.</p>
    </div>

    <div className="card">
      <h3>📝 Step 1: Choose Two Messages</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <div className="input-group">
          <label>m₀ (hex)</label>
          <input value={m0} onChange={e => setM0(e.target.value)} />
        </div>
        <div className="input-group">
          <label>m₁ (hex)</label>
          <input value={m1} onChange={e => setM1(e.target.value)} />
        </div>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.25rem' }}>
        <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem', cursor: 'pointer', color: reuseNonce ? 'var(--accent-red)' : 'var(--text-secondary)' }}>
          <input type="checkbox" checked={reuseNonce} onChange={e => { setReuseNonce(e.target.checked); setHistory([]); }} />
          ⚠️ Reuse Nonce (breaks CPA security)
        </label>
      </div>
    </div>

    <div className="card">
      <h3>🔒 Step 2: Challenger Encrypts</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Challenger picks random b ∈ {'{0,1}'}, encrypts m<sub>b</sub>, shows you C* = Enc<sub>k</sub>(m<sub>b</sub>).
      </p>
      <button className="btn btn-primary" onClick={encrypt} disabled={loading}>
        {loading ? <span className="spinner"/> : "🎲 Encrypt (pick random b)"}
      </button>
      {challenge && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <Field label="Nonce r" value={challenge.nonce_hex} />
          <Field label="Ciphertext C*" value={challenge.ciphertext_hex} accent="var(--accent-blue)" />
        </div>
      )}
    </div>

    {challenge && !guessed && (
      <div className="card fade-in" style={{ borderColor: 'var(--accent-amber)' }}>
        <h3>🤔 Step 3: Guess b</h3>
        <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
          Was m₀ or m₁ encrypted?
        </p>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-primary" onClick={() => guess(0)} style={{ flex: 1, fontSize: '1rem', padding: '0.75rem' }}>
            b = 0 (m₀)
          </button>
          <button className="btn btn-danger" onClick={() => guess(1)} style={{ flex: 1, fontSize: '1rem', padding: '0.75rem' }}>
            b = 1 (m₁)
          </button>
        </div>
      </div>
    )}

    {guessed && (
      <div className="card fade-in" style={{ borderColor: history[history.length-1]?.correct ? 'var(--accent-green)' : 'var(--accent-red)' }}>
        <h3>{history[history.length-1]?.correct ? '✅ Correct!' : '❌ Wrong!'}</h3>
        <div className="result-row">
          <span className={`badge ${history[history.length-1]?.correct ? 'badge-success' : 'badge-error'}`}>
            Actual b = {challenge.b}, you guessed {history[history.length-1]?.guess}
          </span>
        </div>
        <button className="btn btn-primary" onClick={encrypt} style={{ marginTop: '0.5rem' }}>
          Next Round →
        </button>
      </div>
    )}

    {history.length > 0 && (
      <div className="card">
        <h3>📊 Advantage Counter ({total} rounds)</h3>
        <div style={{ display: 'flex', gap: '1rem', alignItems: 'center', flexWrap: 'wrap', marginBottom: '0.75rem' }}>
          <span className="badge badge-info">Correct: {correctCount}/{total} ({total > 0 ? (correctCount/total*100).toFixed(0) : 0}%)</span>
          <span className={`badge ${advantage < 0.2 ? 'badge-success' : 'badge-error'}`}>
            Advantage: {advantage.toFixed(3)} {advantage < 0.15 ? '≈ 0 ✓' : '(security broken!)'}
          </span>
          {reuseNonce && <span className="badge badge-error">⚠️ Nonce reuse active</span>}
        </div>
        <div style={{ width: '100%', height: 8, borderRadius: 4, background: 'var(--bg-input)', overflow: 'hidden', border: '1px solid var(--border)' }}>
          <div style={{ width: `${total > 0 ? (correctCount/total)*100 : 50}%`, height: '100%',
            background: advantage < 0.2 ? 'var(--accent-green)' : 'var(--accent-red)',
            transition: 'width 0.3s ease' }} />
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.65rem', color: 'var(--text-muted)', marginTop: 2 }}>
          <span>0% (always wrong)</span><span>50% (random)</span><span>100% (always right)</span>
        </div>
        <div style={{ marginTop: '0.75rem', display: 'flex', gap: 3, flexWrap: 'wrap' }}>
          {history.map(h => (
            <span key={h.round} className={`badge ${h.correct ? 'badge-success' : 'badge-error'}`}
              style={{ fontSize: '0.6rem', padding: '2px 5px' }}>
              R{h.round}: {h.correct ? '✓' : '✗'}
            </span>
          ))}
        </div>
        <button className="btn btn-ghost" onClick={() => setHistory([])} style={{ marginTop: '0.5rem', fontSize: '0.72rem' }}>
          Reset Counter
        </button>
      </div>
    )}
  </>);
}

// ── PA#4: Modes — ECB Determinism Demo ───────────────────────────────────────
export function PA04() {
  const [mode, setMode] = useState("CTR");
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [msg, setMsg] = useState("48656c6c6f20576f726c642121212121");
  const [result, setResult] = useState(null);
  const [ecbResult, setEcbResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [ecbLoading, setEcbLoading] = useState(false);

  const run = async () => {
    setLoading(true);
    const r = await apiFetch("/pa04/decrypt", { mode, key_hex: key, message_hex: msg });
    setResult(r); setLoading(false);
  };

  const runEcb = async () => {
    setEcbLoading(true);
    const r = await apiFetch("/pa04/ecb_demo", { key_hex: key, block_hex: msg.slice(0, 32) });
    setEcbResult(r); setEcbLoading(false);
  };

  const modes = ["ECB", "CBC", "OFB", "CTR"];
  const modeInfo = { ECB: "⚠️ Deterministic, no IV", CBC: "✅ IV-based chaining", OFB: "✅ Stream from IV", CTR: "✅ Counter-based stream" };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#4</span> Block Cipher Modes of Operation</h2>
      <p>ECB, CBC, OFB, CTR — encrypt and decrypt with roundtrip verification.</p>
    </div>

    <div className="card">
      <h3>🧱 Encrypt → Decrypt Roundtrip</h3>
      <div style={{ display: 'flex', gap: 6, marginBottom: '0.5rem', flexWrap: 'wrap' }}>
        {modes.map(m => (
          <button key={m} className={`btn ${mode === m ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => { setMode(m); setResult(null); }}
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.7rem' }}>
            {m}
          </button>
        ))}
      </div>
      <div style={{ fontSize: '0.72rem', color: mode === 'ECB' ? 'var(--accent-red)' : 'var(--accent-green)', marginBottom: '0.5rem' }}>
        {modeInfo[mode]}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <div className="input-group"><label>Key (hex, 16 bytes)</label><input value={key} onChange={e => setKey(e.target.value)} /></div>
        <div className="input-group"><label>Plaintext (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      </div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>
        {loading ? <span className="spinner"/> : `🔐 Encrypt (${mode}) → Decrypt`}
      </button>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div className="result-row" style={{ marginBottom: '0.5rem' }}>
            <span className="badge badge-info">Mode: {result.mode}</span>
            {result.mode === 'ECB' && <span className="badge badge-warn">⚠ No IV — NOT IND-CPA secure</span>}
            <span className={`badge ${result.roundtrip ? 'badge-success' : 'badge-error'}`}>
              Roundtrip: {result.roundtrip ? '✓' : '✗'}
            </span>
          </div>
          {result.mode !== 'ECB' && <Field label="IV / Nonce (hex)" value={result.iv_hex} />}
          <Field label="Ciphertext (hex)" value={result.ciphertext_hex} accent="var(--accent-purple)" />
          <Field label="Decrypted (hex)" value={result.plaintext_hex} accent="var(--accent-green)" />
        </div>
      )}
    </div>

    <div className="card" style={{ borderColor: 'rgba(239,68,68,0.4)' }}>
      <h3>🔬 ECB Determinism Demo</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Same plaintext block encrypted twice: ECB produces <strong>identical</strong> ciphertext blocks (information leak!). CBC and CTR produce different blocks.
      </p>
      <button className="btn btn-danger" onClick={runEcb} disabled={ecbLoading}>
        {ecbLoading ? <span className="spinner"/> : "🧪 Encrypt Same Block Twice (ECB vs CBC vs CTR)"}
      </button>

      {ecbResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginBottom: 6 }}>
            Plaintext block (repeated): <span style={{ color: 'var(--accent-cyan)', fontFamily: "'JetBrains Mono', monospace" }}>{ecbResult.block_hex}</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem' }}>
            {[
              { name: 'ECB', data: ecbResult.ecb, color: 'rgba(239,68,68,0.08)', border: 'rgba(239,68,68,0.3)' },
              { name: 'CBC', data: ecbResult.cbc, color: 'rgba(16,185,129,0.08)', border: 'rgba(16,185,129,0.3)' },
              { name: 'CTR', data: ecbResult.ctr, color: 'rgba(59,130,246,0.08)', border: 'rgba(59,130,246,0.3)' },
            ].map(({ name, data, color, border }) => (
              <div key={name} style={{ background: color, borderRadius: 8, padding: '0.6rem', border: `1px solid ${border}` }}>
                <div style={{ fontSize: '0.75rem', fontWeight: 600, marginBottom: 4, color: data.identical ? 'var(--accent-red)' : 'var(--accent-green)' }}>{name}</div>
                <div style={{ fontSize: '0.62rem', fontFamily: "'JetBrains Mono', monospace", color: 'var(--accent-cyan)', wordBreak: 'break-all', marginBottom: 2 }}>
                  C₁: {data.c1}
                </div>
                <div style={{ fontSize: '0.62rem', fontFamily: "'JetBrains Mono', monospace", color: 'var(--accent-purple)', wordBreak: 'break-all', marginBottom: 4 }}>
                  C₂: {data.c2}
                </div>
                <span className={`badge ${data.identical ? 'badge-error' : 'badge-success'}`} style={{ fontSize: '0.65rem' }}>
                  {data.identical ? '⚠ C₁ = C₂ (leak!)' : '✅ C₁ ≠ C₂'}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  </>);
}

// ── PA#5: MAC — Compute, Verify, Tamper ──────────────────────────────────────
export function PA05() {
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [msg, setMsg] = useState("48656c6c6f");
  const [macType, setMacType] = useState("prf");
  const [result, setResult] = useState(null);
  const [tamperResult, setTamperResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const run = async () => {
    setLoading(true); setTamperResult(null);
    setResult(await apiFetch("/pa05/mac", { key_hex: key, message_hex: msg, mac_type: macType }));
    setLoading(false);
  };

  const runTamper = async () => {
    setLoading(true);
    setTamperResult(await apiFetch("/pa05/tamper_test", { key_hex: key, message_hex: msg, mac_type: macType }));
    setLoading(false);
  };

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#5</span> Message Authentication Codes</h2>
      <p>PRF-MAC and CBC-MAC — EUF-CMA secure. Any tampering invalidates the tag.</p>
    </div>

    <div className="card">
      <h3>✅ Compute MAC Tag</h3>
      <div style={{ display: 'flex', gap: 6, marginBottom: '0.5rem' }}>
        {["prf", "cbc"].map(t => (
          <button key={t} className={`btn ${macType === t ? 'btn-primary' : 'btn-ghost'}`}
            onClick={() => { setMacType(t); setResult(null); setTamperResult(null); }}
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.7rem' }}>
            {t === 'prf' ? 'PRF-MAC' : 'CBC-MAC'}
          </button>
        ))}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <div className="input-group"><label>Key (hex)</label><input value={key} onChange={e => setKey(e.target.value)} /></div>
        <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      </div>
      <div className="input-row">
        <button className="btn btn-primary" onClick={run} disabled={loading}>
          {loading ? <span className="spinner"/> : `🏷️ Compute ${macType === 'prf' ? 'PRF' : 'CBC'}-MAC`}
        </button>
        <button className="btn btn-danger" onClick={runTamper} disabled={loading}>
          🔬 Tamper Test (EUF-CMA)
        </button>
      </div>
      {result && !result.error && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div className="result-row" style={{ marginBottom: '0.5rem' }}>
            <span className="badge badge-info">Type: {result.mac_type?.toUpperCase()}-MAC</span>
          </div>
          <Field label="Authentication Tag (hex)" value={result.tag_hex} accent="var(--accent-green)" />
        </div>
      )}
    </div>

    {tamperResult && (
      <div className="card fade-in">
        <h3>🔒 Tamper Resistance (EUF-CMA)</h3>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.75rem' }}>
          <div style={{ background: 'rgba(16,185,129,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(16,185,129,0.3)' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6 }}>✅ Original (m, tag)</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.68rem', color: 'var(--accent-cyan)', marginBottom: 4, wordBreak: 'break-all' }}>{msg}</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.68rem', color: 'var(--accent-green)', marginBottom: 6, wordBreak: 'break-all' }}>{tamperResult.tag_hex?.slice(0, 16)}...</div>
            <span className={`badge ${tamperResult.original_valid ? 'badge-success' : 'badge-error'}`}>
              {tamperResult.original_valid ? '✅ Valid' : '❌ Invalid'}
            </span>
          </div>
          <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6 }}>🔀 Tampered message</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.68rem', color: 'var(--accent-red)', marginBottom: 4, wordBreak: 'break-all' }}>{tamperResult.tampered_msg_hex}</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.68rem', color: 'var(--accent-green)', marginBottom: 6, wordBreak: 'break-all' }}>{tamperResult.tag_hex?.slice(0, 16)}... (same tag)</div>
            <span className={`badge ${tamperResult.msg_tampered_valid ? 'badge-error' : 'badge-success'}`}>
              {tamperResult.msg_tampered_valid ? '⚠️ Accepted!' : '✅ Rejected'}
            </span>
          </div>
          <div style={{ background: 'rgba(245,158,11,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(245,158,11,0.3)' }}>
            <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', marginBottom: 6 }}>🏷️ Tampered tag</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.68rem', color: 'var(--accent-cyan)', marginBottom: 4, wordBreak: 'break-all' }}>{msg} (same msg)</div>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.68rem', color: 'var(--accent-amber)', marginBottom: 6, wordBreak: 'break-all' }}>{tamperResult.tampered_tag_hex?.slice(0, 16)}...</div>
            <span className={`badge ${tamperResult.tag_tampered_valid ? 'badge-error' : 'badge-success'}`}>
              {tamperResult.tag_tampered_valid ? '⚠️ Accepted!' : '✅ Rejected'}
            </span>
          </div>
        </div>
        <div style={{ marginTop: '0.75rem', fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center' }}>
          Any modification to the message or tag causes verification to fail — EUF-CMA security.
        </div>
      </div>
    )}
  </>);
}

// ── PA#6: CCA — Malleability Attack Panel ────────────────────────────────────
export function PA06() {
  const [key, setKey] = useState("000102030405060708090a0b0c0d0e0f");
  const [msg, setMsg] = useState("48656c6c6f");
  const [encResult, setEncResult] = useState(null);
  const [flipBit, setFlipBit] = useState(0);
  const [flipResult, setFlipResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [flipLoading, setFlipLoading] = useState(false);

  const run = async () => {
    setLoading(true); setFlipResult(null);
    setEncResult(await apiFetch("/pa06/encrypt", { key_hex: key, message_hex: msg }));
    setLoading(false);
  };

  const runFlip = async () => {
    setFlipLoading(true);
    setFlipResult(await apiFetch("/pa06/bitflip", { key_hex: key, message_hex: msg, flip_bit: flipBit }));
    setFlipLoading(false);
  };

  const maxBit = Math.max(msg.length * 4 - 1, 7);

  return (<>
    <div className="page-header">
      <h2><span className="pa-tag">PA#6</span> CCA-Secure Encryption — Malleability Attack</h2>
      <p>Encrypt-then-MAC (IND-CCA2). Flip a bit: CPA-only shows corrupted plaintext, CCA rejects with ⊥.</p>
    </div>

    <div className="card">
      <h3>🛡️ Encrypt-then-MAC</h3>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
        <div className="input-group"><label>Key (hex, 16B → k_E, k_M derived)</label><input value={key} onChange={e => setKey(e.target.value)} /></div>
        <div className="input-group"><label>Message (hex)</label><input value={msg} onChange={e => setMsg(e.target.value)} /></div>
      </div>
      <button className="btn btn-primary" onClick={run} disabled={loading}>
        {loading ? <span className="spinner"/> : "🔐 CCA Encrypt"}
      </button>
      {encResult && !encResult.error && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '0.5rem' }}>
            <Field label="Nonce r (hex)" value={encResult.nonce_hex} />
            <Field label="Ciphertext c (hex)" value={encResult.ciphertext_hex} accent="var(--accent-purple)" />
            <Field label="MAC tag t (hex)" value={encResult.tag_hex} accent="var(--accent-green)" />
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: 4 }}>
            {encResult.note}
          </div>
        </div>
      )}
    </div>

    <div className="card" style={{ borderColor: 'rgba(239,68,68,0.4)' }}>
      <h3>🔬 Bit-Flip Malleability Attack</h3>
      <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginBottom: '0.5rem' }}>
        Flip bit <strong>{flipBit}</strong> in the ciphertext. CPA-only: corrupted plaintext leaks through.
        CCA (Encrypt-then-MAC): MAC verification fails → output ⊥.
      </p>
      <div className="input-group">
        <label>Flip bit position: {flipBit} <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>(byte {Math.floor(flipBit/8)}, bit {flipBit%8})</span></label>
        <input type="range" min={0} max={maxBit} value={flipBit} onChange={e => setFlipBit(+e.target.value)}
          style={{ width: '100%', accentColor: 'var(--accent-red)' }} />
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.65rem', color: 'var(--text-muted)' }}>
          <span>bit 0</span><span>bit {maxBit}</span>
        </div>
      </div>
      <button className="btn btn-danger" onClick={runFlip} disabled={flipLoading}>
        {flipLoading ? <span className="spinner"/> : `⚡ Flip Bit ${flipBit} → Compare`}
      </button>

      {flipResult && (
        <div className="fade-in" style={{ marginTop: '0.75rem' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.75rem' }}>
            <div style={{ background: 'rgba(239,68,68,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(239,68,68,0.3)' }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--accent-red)', marginBottom: 6 }}>
                CPA-Only (CTR, no MAC)
              </div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 2 }}>Original ciphertext:</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: 'var(--accent-cyan)', wordBreak: 'break-all', marginBottom: 4 }}>{flipResult.cpa?.ciphertext_hex}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 2 }}>Flipped ciphertext:</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: 'var(--accent-red)', wordBreak: 'break-all', marginBottom: 6 }}>{flipResult.cpa?.flipped_hex}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 2 }}>Decrypted (corrupted):</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.75rem', color: 'var(--accent-amber)', wordBreak: 'break-all', marginBottom: 6 }}>{flipResult.cpa?.decrypted_hex}</div>
              <span className={`badge ${flipResult.cpa?.corrupted ? 'badge-error' : 'badge-success'}`}>
                {flipResult.cpa?.corrupted ? '⚠️ Corrupted plaintext leaked!' : '✓ Unchanged'}
              </span>
            </div>

            <div style={{ background: 'rgba(16,185,129,0.08)', borderRadius: 8, padding: '0.75rem', border: '1px solid rgba(16,185,129,0.3)' }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--accent-green)', marginBottom: 6 }}>
                CCA (Encrypt-then-MAC)
              </div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 2 }}>Original ciphertext:</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: 'var(--accent-cyan)', wordBreak: 'break-all', marginBottom: 4 }}>{flipResult.cca?.ciphertext_hex}</div>
              <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)', marginBottom: 2 }}>Flipped ciphertext:</div>
              <div style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: '0.65rem', color: 'var(--accent-red)', wordBreak: 'break-all', marginBottom: 6 }}>{flipResult.cca?.flipped_hex}</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-green)', fontWeight: 600, marginBottom: 6 }}>
                MAC Verify → ✗ FAIL
              </div>
              <span className={`badge ${flipResult.cca?.rejected ? 'badge-success' : 'badge-error'}`}>
                {flipResult.cca?.rejected ? '✅ Rejected → output ⊥' : '⚠️ Accepted!'}
              </span>
            </div>
          </div>
          <div style={{ marginTop: '0.5rem', fontSize: '0.72rem', color: 'var(--text-muted)', textAlign: 'center' }}>
            CPA-only: adversary controls plaintext bits. CCA: MAC catches every modification.
          </div>
        </div>
      )}
    </div>
  </>);
}
