# FallForge Factory

> **Superseded, not deleted.** This repo's `verifyProvenance` hash-walk pattern is the direct
> ancestor of the converging [fallforge](https://github.com/sjgant80-hub/fallforge) hub's own
> provenance organ (`chain.html`), generalized to the current, shorter chain: a
> [fallforgemint](https://github.com/sjgant80-hub/fallforgemint) manifest → a
> [fallforge-catalogue](https://github.com/sjgant80-hub/fallforge-catalogue) listing → served
> ([fallnode](https://github.com/sjgant80-hub/fallnode)) or audited (Veridia). This page stays live
> and gated as a historical record of the original five-layer factory's capstone.

**LIVE: https://sjgant80-hub.github.io/fallforge-factory/**

The capstone of the sovereign-node factory — the factory that runs itself. Five gated layers
composed into one body, and the claim isn't a slogan: **the proof the gate wrote is the proof
the mesh relies on**, one unbroken provenance chain, verified in your browser across four repos.

## The five layers

| Layer | Does | Gate | Live |
|---|---|---|---|
| [gate](https://sjgant80-hub.github.io/fallforge-gate/) | proves an SLM beats its base | 93/95 | proof-of-play receipts |
| [mint](https://sjgant80-hub.github.io/fallforge-mint/) | forges an owned node | 79/80 | signed manifests |
| [node](https://sjgant80-hub.github.io/fallnode/) | serves it private | 61/64 | capability-gated runtime |
| [catalogue](https://sjgant80-hub.github.io/fallforge-catalogue/) | shelves nodes per use-case | 71/72 | own-vs-rent shelf |
| [mesh](https://sjgant80-hub.github.io/fallforge-mesh/) | couples them | 65/66 | no node dominates |

Six kernels (this capstone included), six mutation gates, one content-addressed factory manifest
binding all five kernel hashes and gate scores.

## One unbroken chain

The capstone walks a real minted node's proof across four repositories:

```
gate receipt ─→ [gate→mint]      the receipt is inside the mint manifest
             ─→ [mint→catalogue] the manifest hash is the listing's manifestHash
             ─→ [catalogue→mesh] the mesh member carries that same manifest hash
```

For `triage-1b` this chain is **UNBROKEN** — the same SHA-256 links all four artifacts. Break any
link and the kernel names exactly where. The live page recomputes the whole verdict in-browser.

## The seam

A demand for a use-case is **served** (a sovereign node covers it) or an **opening** (the factory
can mint one) — never faked by a node pretending to cover it. Today: support-triage and
code-review served; legal-review, finance-extract, doc-classify are openings.

## Honest limits

v1 mints prompt-tuned nodes (LoRA is v2, same stages). Signatures prove the issuer's key, not
identity; receipts and savings are scoped. **This is a public composition surface, not the
estate's private orchestrator** — it proves the factory chain, it does not run anyone's private
mesh. The money rail (licensing, payments) stays behind legal counsel. Not audited — proof of
construction, not a security certification.

```bash
node --test kernel.test.mjs
node tools/witness.mjs mutate kernel.mjs --timeout 20000 --cap 500 --test node --test kernel.test.mjs
node build-factory.mjs && node make-page.mjs
```

Kernel mutation-witnessed in CI (51/52, one argued equivalent); the shipped factory and its
provenance chain are re-verified against the kernel on every push. MIT.
