# Cross-implementation report — StillOS x402 `authority` EVC verifier

Independent third implementation of the authority-mandate check that
[x402-foundation/x402#3220](https://github.com/x402-foundation/x402/pull/3220)
(whawk46) specifies and
[x402-foundation/x402#3376](https://github.com/x402-foundation/x402/pull/3376)
(saneGuy) consumes via the External Verifier Contract v1 (`bolyra/bolyra`)
boundary. Built from the spec text and the pinned fixture only — not a port
of either PR's code. Exact SHAs in `SOURCE_PINS.md`.

## What was built

`interop/x402-authority/`:
- `lib/canon.cjs` — JCS (RFC 8785) canonicalizer, Ed25519 sign/verify via `node:crypto` (no external crypto dependency), UTF-16 well-formedness check.
- `lib/mandate.cjs` — §3 mandate shape validation, §5 digest, §12 delegation narrowing + root-issuer recovery.
- `lib/binding.cjs` — §7 preimage binding, all 3 scheme encodings (EIP-3009/Permit2/XRPL).
- `lib/authorize.cjs` — §6 pre-settlement single-payment authorization (signature, digest, subject, asset, recipient scope, amount vs. perPayment/cap, expiry).
- `lib/settle.cjs` — §6 settled-payment decode-and-compare + §13 rule 4 (the amount-binding property): commitment-mismatch and decoded-amount-over-bound kept as two distinct checks, per the spec's own framing.
- `lib/receipt.cjs` — signed StillOS evidence receipt (Ed25519 hash-chain, own dedicated key `secrets/x402-authority-verifier-signing.key`, same pattern as `core/decision_log.cjs`/`core/notary_bond.cjs`).
- `verifier/evc_verifier.cjs` — the actual EVC verifier subprocess: one JSON request on stdin, one closed JSON verdict on stdout, never calls a StillOS-hosted service.
- `verifier/post_settlement_verifier.cjs` — separate CLI for the post-settlement check (not part of the EVC wire protocol — see "wire protocol" below).
- `vectors/run_conformance.cjs` — reproduces every case in the pinned fixture.

## Vector score

**39/39** tier-1 (crypto/wire byte-for-byte) and tier-2 (accept/refuse verdict) checks pass against `authority-vectors.json` (whawk46 @ `72c3704`), covering: JCS/digest/signature, all 3 binding encodings, the accepted payment + 5 refusal categories, 5 mandate-shape refusals, 4 delegation-widening refusals + sibling-budget arithmetic, all 5 applicable `securityFixes` (including the two-part `settledUnderReport` split the spec itself calls out as easy to conflate), and 5 binding-level mutation cases (mutated `paymentId`, wrong `binding_slot` for the declared scheme, partial binding info, total binding omission, correct-binding baseline).

**One real defect found and fixed during a second review pass, not present in the original 34/34 result:** partial binding info — `scheme` present without `bindingSlot`, or vice versa — was being silently skipped by the same code path that correctly allows a full, spec-sanctioned omission of both fields. That conflated "no binding info offered" (valid per §7/§13, binding enforcement is a settlement-time property) with "malformed binding info offered" (should fail closed). Fixed in `lib/authorize.cjs`: the two cases are now distinguished, and partial presence returns `malformed_input`. Caught by re-deriving the original ask's adversarial matrix (N1/N2/N9) as explicit test cases rather than trusting the first pass's fixture-only coverage.

**9 explicitly scoped out**, not silently dropped — logged as `SKIP` with reasons in the conformance output:
- 8 cases under §8 (spend log/Merkle) and §9 (committed-head/freshness-floor): `fullLogAgainstHead_lastSeq0`, `fullLog_lastSeqNull_ok`, `fullLog_lastSeqNull_warned`, `truncatedLogRefused`, `fakeAccountantRefused`, `rollbackRefused`, `duplicatePaymentIdRefused`, `postSettleInclusion`. Reason: #3376's actual wire request (`x402_evc`) never carries a spend log or committed head — there is no carriage path for these today (see `SOURCE_PINS.md`). Building §8/§9 against a boundary that doesn't exist would be uncalled-for engineering, not conformance.
- `strangerVetoResisted`: a §11 Model B (`accountant: "payees"`) property. Model A (the only accountant model in scope here) has no attestation surface for a stranger to exploit in the first place — not fabricated, just structurally not applicable.

## EVC wire-protocol conformance (independent of authority.md)

Read #3376's actual TypeScript source (`types.ts`, `server.ts`, `verify.ts`,
`evcHost.ts` @ `2649525`) to get the real request/response shapes rather than
guessing from the PR description. Two real findings from that reading:

1. **The generic EVC `request.{agent_name,project_key,program,model,granted_capabilities}` object is a separate, bolyra-owned capability-token vocabulary** — not part of authority.md at all. `x402_evc` is a second, additive envelope member that "profile-unaware conformant verifiers ignore" (verify.ts's own docstring). StillOS's verifier reads `x402_evc` and treats `request.*` as informative context, which is exactly the composition #3376 intends.
2. **`@bolyra/evc-conformance` (real npm package, published by saneGuy, the #3376 author) tests the HOST role, not the verifier role.** Ran it (`npx @bolyra/evc-conformance --host "node verifier/evc_verifier.cjs"`) — 0/30 passed, because it expects a full host implementation (spawns a verifier per `HUT_VERIFIER_CMD`, enforces timeout/output-bound, emits a `{decision:"allow"|"deny",...}` envelope) — that's `evcHost.ts`'s role, which #3376 already ships. StillOS built the verifier, which is what the plan called for and what `createCommandVerifier` actually spawns. Logging this plainly rather than hiding the failed run: this was the wrong tool for this artifact, not a defect in it.
3. **Real substitute check performed instead:** ported `evcHost.ts`'s actual `isClosedVerdict()` schema function (not reimplemented from memory — copied from the real pulled source) and ran every verdict StillOS's verifier produces through it. All pass — `evc_verifier.cjs`'s stdout is schema-valid against #3376's real host logic, byte-for-byte, not against a guess at the schema.

## Post-settlement (§6/§13 amount-binding property)

Separate CLI, deliberately not shoehorned into the EVC wire protocol (there is
no post-settlement channel in #3376's current scope — §19 of authority.md
defers it explicitly). Verified against the fixture's `settledUnderReport`
scenario: an agent that logs amount `1` but settles `1,000,000` gets **both**
of the spec's distinct refusals — commitment-mismatch (`1 != 1000000`,
under-report detected) and decoded-amount-over-bound (`1000000 > 250000`
perPayment, cap enforcement, would also fire on an honest settlement of that
size) — matching the spec's own insistence that these are not the same
property.

## On a third wire state ("indeterminate" / "unbindable")

The original scope for this sprint asked for a distinct verdict when a
payment lacks enough information to establish resource binding, rather than
treating absence of proof as proof of violation. Checked against the real
EVC contract (`types.ts`'s `EvcDecision` type, `evcHost.ts`'s
`isClosedVerdict`): the wire protocol is strictly binary, `allow` or `deny`,
over a closed denial-code registry with no third state. A literal
"INDETERMINATE" verdict is not representable on the boundary #3376 actually
built. The substantive version of that requirement that the protocol *can*
carry, and which this kit implements: total absence of binding info is a
spec-sanctioned omission (§7 is enforced at settlement, not required
pre-settlement) and must still evaluate the other six §6 rules normally;
partial presence is genuinely malformed and fails closed. See the fix above.

## What this proves and does not prove

**Proves:** an independent implementation, built from spec text and public
vectors alone, reproduces whawk46's cryptographic and wire values
byte-for-byte, and produces closed verdicts that schema-validate against
saneGuy's real host-parsing logic. That's real evidence #3376's "any
conformant external verifier" claim holds for a third, unrelated
implementation.

**Does not prove:** that either PR is correct in some absolute sense, that
StillOS's evidence-bundle format (`stillos-evidence-bundle/1` — StillOS's own
design, since #3376 deliberately leaves the bundle opaque) is what any other
implementation would choose, that a pre-settlement `allow` verdict means the
eventual settlement complied (that's the separate, explicit
`POST_SETTLEMENT_REFUTED` check), or that any receipt this verifier issues
constitutes proof of delivery/execution. No divergence with either PR's own
published values was found — nothing here required treating a mismatch as a
defect report.

## Not done in this pass

- No live test against a running #3376 integration server (their own test
  suite runs the full flow in-process; this cross-check is offline/static
  against their source + published vectors, which is what the plan asked
  for and what "offline-verifiable" is supposed to mean anyway).
- `state/receipts.jsonl` (the signed receipt ledger) is currently empty —
  every entry from this build/test session was cleared as dev-test noise
  before writing this report, since none represent a real evaluated payment.
- `state/trusted-issuers.json` does not exist yet, so `untrusted_root` is
  never returned in practice — there is no real StillOS registry of trusted
  mandate issuers today (this sprint has no counterparty relationship that
  would populate one). The mechanism is wired; the registry is empty by
  honest default, not a fake pass.
