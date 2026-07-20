const API = "http://localhost:8000";

export async function apiFetch(path, body = null) {
  const opts = body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : { method: "GET" };
  try {
    const r = await fetch(API + path, opts);
    return await r.json();
  } catch (e) {
    return { error: e.message };
  }
}

export const PA_LIST = [
  { id: "pa01", num: "PA#1", name: "OWF & PRG", icon: "🔑", group: "Foundations" },
  { id: "pa02", num: "PA#2", name: "PRF (GGM)", icon: "🎲", group: "Foundations" },
  { id: "pa03", num: "PA#3", name: "CPA Encryption", icon: "🔒", group: "Symmetric" },
  { id: "pa04", num: "PA#4", name: "Block Cipher Modes", icon: "🧱", group: "Symmetric" },
  { id: "pa05", num: "PA#5", name: "MACs", icon: "✅", group: "Symmetric" },
  { id: "pa06", num: "PA#6", name: "CCA Encryption", icon: "🛡️", group: "Symmetric" },
  { id: "pa07", num: "PA#7", name: "Merkle-Damgård", icon: "🔗", group: "Hash" },
  { id: "pa08", num: "PA#8", name: "DLP-CRHF", icon: "#️⃣", group: "Hash" },
  { id: "pa09", num: "PA#9", name: "Birthday Attack", icon: "🎂", group: "Hash" },
  { id: "pa10", num: "PA#10", name: "HMAC", icon: "🏷️", group: "Hash" },
  { id: "pa11", num: "PA#11", name: "Diffie-Hellman", icon: "🤝", group: "Public Key" },
  { id: "pa12", num: "PA#12", name: "RSA", icon: "🗝️", group: "Public Key" },
  { id: "pa13", num: "PA#13", name: "Miller-Rabin", icon: "🔢", group: "Public Key" },
  { id: "pa14", num: "PA#14", name: "CRT & Håstad", icon: "⚡", group: "Public Key" },
  { id: "pa15", num: "PA#15", name: "Signatures", icon: "✍️", group: "Signatures & PKC" },
  { id: "pa16", num: "PA#16", name: "ElGamal", icon: "🔐", group: "Signatures & PKC" },
  { id: "pa17", num: "PA#17", name: "CCA-PKC", icon: "🏰", group: "Signatures & PKC" },
  { id: "pa18", num: "PA#18", name: "Oblivious Transfer", icon: "📨", group: "MPC" },
  { id: "pa19", num: "PA#19", name: "Secure Gates", icon: "🚪", group: "MPC" },
  { id: "pa20", num: "PA#20", name: "MPC Circuits", icon: "🤑", group: "MPC" },
];
