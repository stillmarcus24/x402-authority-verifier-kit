# x402 Authority Verifier Kit

Independent conformance kit for two companion x402 proposals:

- [x402-foundation/x402#3220](https://github.com/x402-foundation/x402/pull/3220) (whawk46) — the `authority` extension: a compact, signed, offline-verifiable spending mandate.
- [x402-foundation/x402#3376](https://github.com/x402-foundation/x402/pull/3376) (saneGuy) — `authorization-evidence`, the TypeScript extension that carries opaque evidence to a pluggable External Verifier Contract v1 (EVC) verifier.

Built from the published spec text and vectors alone — not a port of either
PR's code. Zero dependencies; every check runs on Node's built-in `crypto`.

## Reproduce it

```sh
git clone https://github.com/stillmarcus24/x402-authority-verifier-kit
cd x402-authority-verifier-kit
npm test        # node vectors/run_conformance.cjs
```

Exits `0` on full pass, `1` on any failure. As of commit `<COMMIT_SHA>`:
**39/39 applicable cases pass**, reproducing #3220's `authority-vectors.json`
(pinned at `72c3704`) byte-for-byte for every value that requires it, and
matching every accept/refuse verdict.

## What's checked

- Mandate shape validation (§3): unknown-member rejection, recipient-scope
  rules, timestamp strictness, UTF-16 well-formedness.
- JCS canonicalization and the mandate digest (§4–§5).
- The preimage binding (§7), all three scheme encodings: EIP-3009, Permit2, XRPL.
- Single-payment pre-settlement authorization (§6): signature, digest,
  subject, asset, recipient scope, amount vs. `perPayment`/`cap`, expiry.
- Delegation narrowing (§12): cap/expiry/recipient narrowing across a
  parent-child chain, sibling-budget arithmetic, root-issuer recovery.
- Post-settlement decode-and-compare (§6 "Settled payments", §13 rule 4):
  reads amount/recipient/asset/payer from the settled artifact, never a
  presented field, and keeps the two `settledUnderReport` refusals
  (commitment mismatch, decoded-amount-over-bound) distinct.
- `securityFixes`: bad-`alg` refusal, unknown-member refusal on both
  mandates and commitments, and the totality property (a malformed
  `purpose` field with an unpaired UTF-16 surrogate refuses without
  throwing).
- One additional case found during this implementation, not in the
  published fixture: partial binding info (`scheme` present without
  `bindingSlot`, or vice versa) now fails closed as `malformed_input`
  instead of being silently treated the same as a full, spec-sanctioned
  omission of both fields.

**Not implemented, and not counted in the 39/39:** §8 (spend log / RFC 6962
Merkle) and §9 (committed head / freshness floor). #3376's current wire
request carries a single payment's context; there is no carriage path today
for a spend log or a committed head, so there is nothing on the wire to
verify that part of the spec against. `strangerVetoResisted` is a §11 Model B
(`accountant: "payees"`) property — the Model A / single-payment path this
kit covers has no attestation surface for a stranger to exploit in the first
place. Full accounting in `docs/SOURCE_PINS.md`.

## What's here

- `lib/canon.cjs` — RFC 8785 JCS canonicalizer, Ed25519 sign/verify via `node:crypto`, UTF-16 well-formedness.
- `lib/mandate.cjs` — §3 shape validation, §5 digest, §12 delegation narrowing and root-issuer recovery.
- `lib/binding.cjs` — §7 preimage binding and its three scheme encodings.
- `lib/authorize.cjs` — §6 pre-settlement single-payment authorization.
- `lib/settle.cjs` — §6/§13 post-settlement decode-and-compare.
- `lib/receipt.cjs` — signed, hash-chained evidence receipt for a verifier's own decisions.
- `verifier/evc_verifier.cjs` — the EVC verifier subprocess: one JSON request on stdin, one closed JSON verdict on stdout, no network calls, no callback to StillOS. This is the process role `createCommandVerifier` in #3376 spawns.
- `verifier/post_settlement_verifier.cjs` — a separate CLI for the post-settlement check, since #3376's current wire protocol has no post-settlement channel.
- `vectors/run_conformance.cjs` — the full conformance run.
- `keys/` — the public key StillOS's own operated instance signs receipts under. See `keys/README.md`.

## Running the verifier directly

```sh
echo '<EVC request JSON>' | node verifier/evc_verifier.cjs
```

stdin is one JSON object shaped like #3376's `buildEvidenceVerifierRequest`
output (`version`, `bundle`, `request`, `now_unix`, `x402_evc`). `bundle` is
this kit's own evidence-bundle format (§3376 leaves it opaque by design):

```json
{ "v": "stillos-evidence-bundle/1",
  "chain": [ { "mandate": {...}, "alg": "Ed25519", "sig": "..." } ],
  "paymentId": "pay-001" }
```

`chain` is root-first; a length-1 chain is an undelegated grant, length > 1
is checked hop-by-hop against §12. stdout is exactly one JSON object,
`{"verdict":"allow",...}` or `{"verdict":"deny","code":...,"message":...}`,
schema-checked against #3376's own `evcHost.ts` `isClosedVerdict` logic
before publishing this kit.

## What a receipt proves, and what it doesn't

Every verdict this verifier issues is recorded in a signed, hash-chained
receipt (`lib/receipt.cjs`), same construction as StillOS's own decision log
and notary bond. A receipt proves that, at evaluation time, a specific
presented evidence bundle was checked against a specific mandate, at a
specific policy version, and got a specific decision. It does not prove the
eventual settlement complied — that is the separate, explicit
`verifier/post_settlement_verifier.cjs` check — nor that the mandate's
issuer is trustworthy, nor that delivery or execution happened.

## Source pins

Full commit pins and the explicit scope-cut rationale: `docs/SOURCE_PINS.md`.
Independent-implementation report: `docs/CROSS_IMPLEMENTATION_REPORT.md`.
