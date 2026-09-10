# Source pins — x402 authority-evidence interop sprint

All conformance/cross-implementation claims in this directory are against
these exact commits. Re-pin and re-run before citing a result against a newer
push to either PR.

| Source | PR | Author | Head SHA | Base (main) SHA | Pulled |
|---|---|---|---|---|---|
| `authority` mandate spec + vectors | [x402-foundation/x402#3220](https://github.com/x402-foundation/x402/pull/3220) | whawk46 | `72c3704dfb89851fb7b1f0dca4d327b804faee5c` | `7d5363a6d51750dc246041f2b0ed5819dd46a0d7` | 2026-09-08 |
| `authorization-evidence` TS extension | [x402-foundation/x402#3376](https://github.com/x402-foundation/x402/pull/3376) | saneGuy | `2649525285bcf73dd317326234765393700e1640` | `4e15690028cf6d66b35e44a8128da47da9b92a4d` | 2026-09-08 |

Both PRs are **open, unmerged** as of the pull date. Neither StillOS's
implementation nor this pin file constitutes acceptance/endorsement by either
author or the x402-foundation maintainers.

Files pulled verbatim and stored locally for reproducibility:
- `vectors/fixtures/authority.md` — full spec text, from whawk46 `72c3704`.
- `vectors/fixtures/authority-vectors.json` — deterministic conformance vectors, from whawk46 `72c3704`.
- The `External Verifier Contract v1` wire shapes (request/response JSON, denial-code registry) were read from #3376's `typescript/packages/extensions/src/authorization-evidence/{types,server,verify,evcHost}.ts` at `2649525`. EVC itself is a **third-party spec** (`github.com/bolyra/bolyra`), not authored by either PR — #3376 is a consumer of it, not its owner. Not vendored locally (TypeScript, informative only — StillOS's verifier is a from-scratch Node implementation against the wire contract, not a port of this code).

## Explicit scope cut (documented, not silent)

`authority.md` (§8 spend log / RFC 6962 Merkle, §9 Model A committed heads, §10
on-chain anchoring, §11 Model B payee-attestation reconciliation) defines
**cumulative multi-payment completeness** across a mandate's whole lifetime.
This sprint does **not** implement those. Reason: #3376's actual EVC request
shape (`x402_evc.{resource,amount,asset,network,payee,payment}`) only ever
carries **one payment's** context — there is no wire path in #3376 today for
a verifier to receive a spend log, a committed head, or payee attestations.
Building §8-11 would be real, uncalled-for engineering against a boundary
that doesn't exist yet in the carriage layer. In scope: §3 (mandate shape),
§4-5 (canonicalization/digest), §6 (single-payment authorization, both
pre-settlement and settled-artifact decode-compare), §7 (preimage binding,
all 3 schemes), §12 (delegation narrowing) — everything the real wire
protocol can actually exercise today. If #3376's companion carriage doc
(referenced in authority.md §19) later adds a spend-log/head channel, this
cut should be revisited.
