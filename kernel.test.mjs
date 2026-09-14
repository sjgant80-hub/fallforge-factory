import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LAYERS, sha256, canon, verifyProvenance, buildFactory, verifyFactory, demand } from './kernel.mjs';

test('sha256 + canon + LAYERS pinned', () => {
  assert.equal(sha256('abc').hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(sha256('').hash, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(sha256(2).ok, false);
  assert.equal(canon({ b: 1, a: 2 }), canon({ a: 2, b: 1 }));
  assert.notEqual(canon({ x: 5 }), canon({ x: '5' }));
  assert.notEqual(canon({ x: null }), canon({ x: 0 }));
  assert.deepEqual([...LAYERS], ['gate', 'mint', 'node', 'catalogue', 'mesh']);
});

// ── provenance: the chain the gate's proof travels to the mesh
const R = 'a'.repeat(64), M = 'b'.repeat(64);
const good = {
  node: 'triage-1b', receiptHash: R,
  manifest: { hash: M, receipts: [{ hash: R, vs: 'llama3.2:1b' }, { hash: 'c'.repeat(64), vs: 'qwen2.5:7b' }] },
  listing: { node: 'triage-1b', manifestHash: M },
  meshMember: { node: 'triage-1b', manifestHash: M },
};

test('verifyProvenance: an unbroken chain, and each break named in order', () => {
  const v = verifyProvenance(good);
  assert.equal(v.intact, true);
  assert.equal(v.links.length, 3);
  assert.match(v.why, /the proof the gate wrote/);
  // break 1: the receipt is not in the manifest
  assert.equal(verifyProvenance({ ...good, receiptHash: 'd'.repeat(64) }).intact, false);
  assert.equal(verifyProvenance({ ...good, receiptHash: 'd'.repeat(64) }).brokenAt, 'gate→mint');
  // break 2: the listing points at a different manifest
  assert.equal(verifyProvenance({ ...good, listing: { node: 'triage-1b', manifestHash: 'e'.repeat(64) } }).brokenAt, 'mint→catalogue');
  // break 2b: the listing is for a different node
  assert.equal(verifyProvenance({ ...good, listing: { node: 'other', manifestHash: M } }).brokenAt, 'mint→catalogue');
  // break 3: the mesh member carries a different manifest
  assert.equal(verifyProvenance({ ...good, meshMember: { node: 'triage-1b', manifestHash: 'f'.repeat(64) } }).brokenAt, 'catalogue→mesh');
  // break 3b: the mesh member is a different node
  assert.equal(verifyProvenance({ ...good, meshMember: { node: 'other', manifestHash: M } }).brokenAt, 'catalogue→mesh');
});

test('verifyProvenance: every guard refuses malformed input', () => {
  assert.equal(verifyProvenance(null).ok, false);
  assert.equal(verifyProvenance({ ...good, node: '' }).ok, false);
  assert.equal(verifyProvenance({ ...good, receiptHash: 'short' }).ok, false);
  assert.equal(verifyProvenance({ ...good, receiptHash: 'z'.repeat(64) }).ok, false);
  assert.equal(verifyProvenance({ ...good, manifest: { hash: M } }).ok, false);         // no receipts
  assert.equal(verifyProvenance({ ...good, manifest: { hash: 'x', receipts: [] } }).ok, false);
  assert.equal(verifyProvenance({ ...good, listing: { node: 't' } }).ok, false);         // no manifestHash
  assert.equal(verifyProvenance({ ...good, meshMember: { node: 't' } }).ok, false);
  // a receipt entry that is not an object must not crash the containment scan
  assert.equal(verifyProvenance({ ...good, manifest: { hash: M, receipts: [null, { hash: R }] } }).intact, true);
});

// ── the factory manifest
function layer(name, killed, total) { return { name, url: 'https://sjgant80-hub.github.io/x/', kernelHash: 'a'.repeat(64), killed, total }; }
const FIVE = [layer('gate', 93, 95), layer('mint', 79, 80), layer('node', 61, 64), layer('catalogue', 71, 72), layer('mesh', 65, 66)];

test('buildFactory + verifyFactory: five layers in order, sealed, tamper shows', () => {
  const f = buildFactory([...FIVE].reverse());   // any input order
  assert.equal(f.ok, true);
  assert.deepEqual(f.factory.layers.map((l) => l.name), ['gate', 'mint', 'node', 'catalogue', 'mesh']);   // factory order, not alphabetical
  assert.equal(verifyFactory(f.factory).valid, true);
  assert.equal(verifyFactory({ ...f.factory, hash: 'f'.repeat(64) }).valid, false);
  const tampered = { ...f.factory, layers: f.factory.layers.map((l, i) => i === 0 ? { ...l, killed: 1 } : l) };
  assert.equal(verifyFactory(tampered).valid, false);   // changed killed count breaks the hash
  assert.equal(verifyFactory({ kind: 'fallforge-factory' }).ok, false);
  assert.equal(verifyFactory('x').ok, false);
});

test('buildFactory: guards — exactly five known layers, each well-formed', () => {
  assert.equal(buildFactory(FIVE.slice(0, 4)).ok, false);                 // too few
  assert.equal(buildFactory([...FIVE, layer('gate', 1, 1)]).ok, false);   // six / duplicate
  assert.equal(buildFactory([...FIVE.slice(1), layer('vibes', 1, 1)]).ok, false);   // unknown layer name
  assert.equal(buildFactory(FIVE.map((l) => ({ ...l, url: 'http://x' }))).ok, false);   // non-https
  assert.equal(buildFactory(FIVE.map((l) => ({ ...l, kernelHash: 'z'.repeat(64) }))).ok, false);
  assert.equal(buildFactory(FIVE.map((l) => ({ ...l, killed: 5, total: 4 }))).ok, false);   // total < killed
  assert.equal(buildFactory(FIVE.map((l) => ({ ...l, killed: -1 }))).ok, false);
  assert.equal(buildFactory('x').ok, false);
  // total === killed is valid (a perfect gate)
  assert.equal(buildFactory(FIVE.map((l) => ({ ...l, killed: 10, total: 10 }))).ok, true);
});

test('kill: buildFactory layer guards isolated — a forged array layer is refused', () => {
  const arrLayer = Object.assign([], layer('gate', 1, 1));
  assert.equal(buildFactory([arrLayer, ...FIVE.slice(1)]).ok, false);
  assert.equal(buildFactory([{ ...layer('gate', 1, 1), name: 7 }, ...FIVE.slice(1)]).ok, false);
  assert.equal(buildFactory([{ ...layer('gate', 1, 1), killed: 1.5 }, ...FIVE.slice(1)]).ok, false);
});

test('kill: killed-count zero boundary and forged guards', () => {
  assert.equal(buildFactory(FIVE.map((l) => ({ ...l, killed: 0, total: 0 }))).ok, true);   // a zero-gate is valid input (kills < vs <=)
  // meshMember guard clauses isolated
  const arrMember = Object.assign([], { node: 'triage-1b', manifestHash: 'b'.repeat(64) });
  assert.equal(verifyProvenance({ ...good, meshMember: arrMember }).ok, false);
  assert.equal(verifyProvenance({ ...good, meshMember: { node: 7, manifestHash: 'b'.repeat(64) } }).ok, false);
  // verifyFactory type-guard: forged array with kind+hash
  const fakeF = Object.assign([], { kind: 'fallforge-factory', hash: 'a'.repeat(64) });
  assert.equal(verifyFactory(fakeF).ok, false);
});

test('kill: verifyFactory layers-length guard fires when the hash matches', () => {
  const f = buildFactory(FIVE).factory;
  // forge a body whose layers array is short but recompute the hash so the hash check passes —
  // only the layers.length !== LAYERS.length clause stands between the forgery and valid
  const body = { v: f.v, kind: f.kind, layers: f.layers.slice(0, 3), scope: f.scope };
  const forged = { ...body, hash: sha256(canon(body)).hash };
  const v = verifyFactory(forged);
  assert.equal(v.valid, false);
  assert.match(v.why, /all 5 layers|five/i);
});

// ── the seam
test('demand: served routes to a node; an unserved use-case is an OPENING, never faked', () => {
  assert.deepEqual(demand('support-triage', ['support-triage', 'code-review']),
    { ok: true, served: true, action: 'route-to-node', why: 'a sovereign node already serves support-triage' });
  const opening = demand('legal-review', ['support-triage', 'code-review']);
  assert.equal(opening.served, false);
  assert.equal(opening.action, 'mint-opening');
  assert.match(opening.why, /opening the factory can mint/);
  assert.equal(demand('', []).ok, false);
  assert.equal(demand('x', 'y').ok, false);
  assert.equal(demand('x', [7]).ok, false);
});
