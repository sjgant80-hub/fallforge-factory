// FallForge Factory — the capstone kernel. Layer 6 of the sovereign-node factory: the factory
// that runs itself. It composes the five layers into one body and PROVES the chain is unbroken —
// a gate receipt's hash lives inside a mint manifest, whose hash is the catalogue listing's
// manifestHash, whose node is a mesh member carrying that same manifest hash. One provenance
// chain: the proof the gate wrote is the proof the mesh relies on, end to end. This kernel owns
// the composition law; each layer's own kernel owns its own proof.
// No I/O. Pure and total: garbage in → { ok:false, why }, never a throw.

export const LAYERS = Object.freeze(['gate', 'mint', 'node', 'catalogue', 'mesh']);

const isStr = (v) => typeof v === 'string';
const isInt = (v) => Number.isInteger(v);
const isObj = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);
const HEX = /^[0-9a-f]+$/;
const isHash = (v) => isStr(v) && v.length === 64 && HEX.test(v);

// ── SHA-256 + canonical JSON (the estate's proven pair) ─────────────────────────────────────────
const K256 = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

export function sha256(text) {
  if (!isStr(text)) return { ok: false, why: 'sha256 takes a string' };
  const data = new TextEncoder().encode(text);
  const len = data.length;
  const padded = new Uint8Array((((len + 8) >> 6) << 6) + 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  const bitLen = len * 8;
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 4294967296));
  dv.setUint32(padded.length - 4, bitLen >>> 0);
  let h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
  let h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;
  const w = new Uint32Array(64);
  for (let i = 0; i < padded.length; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const x = w[t - 15], y = w[t - 2];
      const s0 = (((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3)) >>> 0;
      const s1 = (((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10)) >>> 0;
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) >>> 0;
    }
    let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, hh = h7;
    for (let t = 0; t < 64; t++) {
      const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) >>> 0;
      const ch = ((e & f) ^ (~e & g)) >>> 0;
      const t1 = (hh + S1 + ch + K256[t] + w[t]) >>> 0;
      const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) >>> 0;
      const maj = ((a & b) ^ (a & c) ^ (b & c)) >>> 0;
      const t2 = (S0 + maj) >>> 0;
      hh = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    h0 = (h0 + a) >>> 0; h1 = (h1 + b) >>> 0; h2 = (h2 + c) >>> 0; h3 = (h3 + d) >>> 0;
    h4 = (h4 + e) >>> 0; h5 = (h5 + f) >>> 0; h6 = (h6 + g) >>> 0; h7 = (h7 + hh) >>> 0;
  }
  const hex = (n) => n.toString(16).padStart(8, '0');
  return { ok: true, hash: hex(h0) + hex(h1) + hex(h2) + hex(h3) + hex(h4) + hex(h5) + hex(h6) + hex(h7) };
}

export function canon(v) {
  if (v === null || typeof v === 'number' || typeof v === 'boolean') return JSON.stringify(v);
  if (typeof v === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
  if (typeof v === 'object') return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
  return '"?"';
}

// ── the provenance chain: the proof the gate wrote is the proof the mesh relies on ──────────────
/** verifyProvenance({ node, receiptHash, manifest, listing, meshMember }) — walk the four links
 *  a minted node's proof travels. Each link is a hash equality; a break is named, in order. */
export function verifyProvenance(p) {
  if (!isObj(p)) return { ok: false, why: 'provenance takes { node, receiptHash, manifest, listing, meshMember }' };
  if (!isStr(p.node) || p.node.length === 0) return { ok: false, why: 'provenance needs a node name' };
  if (!isHash(p.receiptHash)) return { ok: false, why: 'receiptHash must be a 64-hex hash' };
  if (!isObj(p.manifest) || !isHash(p.manifest.hash) || !Array.isArray(p.manifest.receipts)) return { ok: false, why: 'manifest needs a hash and a receipts array' };
  if (!isObj(p.listing) || !isHash(p.listing.manifestHash) || !isStr(p.listing.node)) return { ok: false, why: 'listing needs a manifestHash and a node' };
  if (!isObj(p.meshMember) || !isStr(p.meshMember.node) || !isHash(p.meshMember.manifestHash)) return { ok: false, why: 'meshMember needs a node and a manifestHash' };

  const links = [];
  // 1 · the gate receipt is one of the receipts the mint manifest was built from
  const inManifest = p.manifest.receipts.some((r) => isObj(r) && r.hash === p.receiptHash);
  links.push({ link: 'gate→mint', ok: inManifest, of: 'the gate receipt is inside the mint manifest' });
  if (!inManifest) return { ok: true, intact: false, brokenAt: 'gate→mint', links, why: 'the receipt is not among the manifest’s receipts — the mint did not gate this proof' };
  // 2 · the catalogue listing points at exactly this manifest
  const listingMatches = p.listing.manifestHash === p.manifest.hash && p.listing.node === p.node;
  links.push({ link: 'mint→catalogue', ok: listingMatches, of: 'the catalogue listing carries this manifest hash' });
  if (!listingMatches) return { ok: true, intact: false, brokenAt: 'mint→catalogue', links, why: 'the listing does not point at this manifest — the shelf lists a different build' };
  // 3 · the mesh member is this node, carrying the same manifest hash
  const meshMatches = p.meshMember.node === p.node && p.meshMember.manifestHash === p.manifest.hash;
  links.push({ link: 'catalogue→mesh', ok: meshMatches, of: 'the mesh member carries this manifest hash' });
  if (!meshMatches) return { ok: true, intact: false, brokenAt: 'catalogue→mesh', links, why: 'the mesh member does not carry this manifest — the coupled node is not the shelved one' };

  return { ok: true, intact: true, node: p.node, links, why: 'unbroken: the proof the gate wrote is the proof the mesh relies on' };
}

// ── the factory manifest: the five layers as one body, content-addressed ────────────────────────
function validLayer(l) {
  if (!isObj(l)) return 'a layer is an object';
  if (!isStr(l.name) || !LAYERS.includes(l.name)) return 'layer name must be one of ' + LAYERS.join(', ');
  if (!isStr(l.url) || !/^https:\/\//.test(l.url)) return 'layer ' + l.name + ' needs an https url';
  if (!isHash(l.kernelHash)) return 'layer ' + l.name + ' needs a 64-hex kernel hash';
  if (!isInt(l.killed) || l.killed < 0) return 'layer ' + l.name + ' needs a non-negative killed count';
  if (!isInt(l.total) || l.total < l.killed) return 'layer ' + l.name + ' total must be at least its killed count';
  return null;
}

export function buildFactory(layers) {
  if (!Array.isArray(layers)) return { ok: false, why: 'the factory takes an array of layers' };
  if (layers.length !== LAYERS.length) return { ok: false, why: 'the factory has exactly ' + LAYERS.length + ' layers' };
  const seen = new Set();
  const clean = [];
  for (const [i, l] of layers.entries()) {
    const bad = validLayer(l);
    if (bad) return { ok: false, why: 'layer ' + i + ': ' + bad };
    if (seen.has(l.name)) return { ok: false, why: 'duplicate layer: ' + l.name };
    seen.add(l.name);
    clean.push({ name: l.name, url: l.url, kernelHash: l.kernelHash, killed: l.killed, total: l.total });
  }
  // exactly LAYERS.length distinct entries, each a valid LAYERS name → by pigeonhole all are present,
  // so no separate "missing layer" check is needed (and it would only shadow the name-validity guard)
  // keep the layers in factory order (gate→mint→node→catalogue→mesh), not sorted alphabetically
  clean.sort((a, b) => LAYERS.indexOf(a.name) - LAYERS.indexOf(b.name));
  const body = { v: 1, kind: 'fallforge-factory', layers: clean,
    scope: 'each layer is proved by its own mutation gate; this manifest binds them into one chain' };
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  return { ok: true, factory: { ...body, hash: h.hash } };
}

export function verifyFactory(f) {
  if (!isObj(f) || f.kind !== 'fallforge-factory' || !isStr(f.hash)) return { ok: false, why: 'not a fallforge factory' };
  const body = { ...f };
  delete body.hash;
  const h = sha256(canon(body));
  if (!h.ok) return { ok: false, why: h.why };
  if (h.hash !== f.hash) return { ok: true, valid: false, why: 'hash mismatch — the factory does not match its own layers' };
  if (!Array.isArray(f.layers) || f.layers.length !== LAYERS.length) return { ok: true, valid: false, why: 'the factory must carry all ' + LAYERS.length + ' layers' };
  return { ok: true, valid: true, why: 'factory intact — five gated layers, one chain' };
}

/** demand(useCase, servedUseCases) — the seam: a demand is served by the factory only if a
 *  minted node covers it; otherwise it is an OPENING (mint one), never faked. */
export function demand(useCase, servedUseCases) {
  if (!isStr(useCase) || useCase.length === 0) return { ok: false, why: 'a demand names a use-case' };
  if (!Array.isArray(servedUseCases)) return { ok: false, why: 'servedUseCases is an array' };
  for (const u of servedUseCases) if (!isStr(u)) return { ok: false, why: 'each served use-case is a string' };
  const served = servedUseCases.includes(useCase);
  return { ok: true, served, action: served ? 'route-to-node' : 'mint-opening',
    why: served ? 'a sovereign node already serves ' + useCase : 'no node serves ' + useCase + ' yet — this is an opening the factory can mint' };
}
