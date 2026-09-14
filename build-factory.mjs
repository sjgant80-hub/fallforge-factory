#!/usr/bin/env node
// build-factory.mjs — seal the whole factory and PROVE the real chain. Reads each layer's shipped
// kernel + gate score, binds them into one content-addressed factory manifest, then walks the
// actual provenance of a real minted node (triage-1b) across all four downstream artifacts.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { sha256, buildFactory, verifyFactory, verifyProvenance, demand } from './kernel.mjs';

const kernelHash = (path) => sha256(readFileSync(path, 'utf8').replace(/\r\n/g, '\n')).hash;
const B = 'https://sjgant80-hub.github.io/';

const LAYERS = [
  { name: 'gate', url: B + 'fallforge-gate/', path: 'C:/Users/sjgan/fallforge-gate/kernel.mjs', killed: 93, total: 95 },
  { name: 'mint', url: B + 'fallforge-mint/', path: 'C:/Users/sjgan/fallforge-mint/kernel.mjs', killed: 79, total: 80 },
  { name: 'node', url: B + 'fallnode/', path: 'C:/Users/sjgan/fallnode/kernel.mjs', killed: 61, total: 64 },
  { name: 'catalogue', url: B + 'fallforge-catalogue/', path: 'C:/Users/sjgan/fallforge-catalogue/kernel.mjs', killed: 71, total: 72 },
  { name: 'mesh', url: B + 'fallforge-mesh/', path: 'C:/Users/sjgan/fallforge-mesh/kernel.mjs', killed: 65, total: 66 },
];
const layers = LAYERS.map((l) => ({ name: l.name, url: l.url, kernelHash: kernelHash(l.path), killed: l.killed, total: l.total }));
const f = buildFactory(layers);
if (!f.ok) { console.error('factory refused: ' + f.why); process.exit(1); }
if (verifyFactory(f.factory).valid !== true) { console.error('factory self-verify failed'); process.exit(1); }
console.log('factory sealed: ' + f.factory.layers.length + ' layers, hash ' + f.factory.hash.slice(0, 16) + '\u2026');

// the real provenance of triage-1b, across four repos
const receipt = JSON.parse(readFileSync('C:/Users/sjgan/fallforge-mint/out/triage-1b.receipt-base.json', 'utf8'));
const manifest = JSON.parse(readFileSync('C:/Users/sjgan/fallforge-mint/out/triage-1b.manifest.json', 'utf8'));
const listings = JSON.parse(readFileSync('C:/Users/sjgan/fallforge-catalogue/catalogue/listings.json', 'utf8'));
const mesh = JSON.parse(readFileSync('C:/Users/sjgan/fallforge-mesh/demo/mesh.json', 'utf8'));
const listing = listings.find((l) => l.node === 'triage-1b');
const meshMember = mesh.members.find((m) => m.node === 'triage-1b');

const prov = verifyProvenance({
  node: 'triage-1b', receiptHash: receipt.hash,
  manifest: { hash: manifest.hash, receipts: manifest.receipts },
  listing: { node: listing.node, manifestHash: listing.manifestHash },
  meshMember: { node: meshMember.node, manifestHash: meshMember.manifestHash },
});
console.log('provenance triage-1b: ' + (prov.intact ? 'UNBROKEN — ' + prov.links.map((l) => l.link).join(' → ') : 'BROKEN at ' + prov.brokenAt));

// the seam: which of the estate's top use-cases the factory already serves vs the openings
const served = ['support-triage', 'code-review'];
const topUseCases = ['support-triage', 'code-review', 'legal-review', 'finance-extract', 'doc-classify'];
const demands = topUseCases.map((u) => ({ useCase: u, ...demand(u, served) }));

writeFileSync('factory/factory.json', JSON.stringify({
  factory: f.factory,
  provenance: { node: 'triage-1b', intact: prov.intact, links: prov.links, why: prov.why,
    receiptHash: receipt.hash, manifestHash: manifest.hash },
  demands,
}, null, 2) + '\n');
console.log('written: factory/factory.json');
