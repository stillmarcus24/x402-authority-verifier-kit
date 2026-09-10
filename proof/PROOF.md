# PROOF

What this directory establishes, how to re-run it yourself, and — stated as
plainly as the results — what it does not establish.

Every claim below is against the exact revisions pinned in
[`SOURCE_PINS.json`](SOURCE_PINS.json). Re-pin
(`node proof/tools/pin_sources.cjs`) and re-run before citing any number
against a newer push.

## Reproduce

```sh
./prove.sh
```

No network. No dependencies. Node ≥ 18 and Python ≥ 3.8 (standard library
only — the Python side does not import `cryptography` or `nacl`). Exits `0`
only if all three stages pass.

## Result

Run on `node v22.22.1` / `Python 3.14.4`:

| Stage | Check | Result |
|---|---|---|
| 1 | Frozen corpus regenerates byte-identically from its builder | pass |
| 2 | 69 adversarial vectors / 83 ops, two independent implementations | **69/69**, 1 documented unspecified divergence |
| 3 | Upstream conformance vs. x402#3220's own vectors @ `72c3704` | **39/39**, 9 explicitly scoped out |

A stage-2 vector passes only when **both** implementations agree with the
expectation **and** with each other, field by field. The expectation is never
edited to match an implementation. Failures print; they are not summarized
away.

## What "independent" means here

The differential test is only worth something if the two sides can actually
disagree. What is and is not shared:

- **Implementation B** (`impl-py/assurance.py`, Python) is written from the
  normative text. It shares no algorithm code with implementation A and none
  with the kit's `lib/`. **Ed25519 verification is implemented from RFC 8032
  in pure integer arithmetic**, so the two sides cross unrelated crypto
  stacks — OpenSSL via `node:crypto` on one side, field arithmetic on the
  other — rather than being two callers of one library.
- **Implementation A** (`impl-node/assurance.cjs`, Node) re-derives JCS, the
  digest triple, limbs, origin tags, the v3 batch, `BASE_SETTLEMENT_V1` and
  the notary receipt preimage from the spec text, independently of B.
- **Stated openly, because it bounds the claim:** A's *authority* half
  (`#3220` §3/§5/§6/§7) is not re-derived — it calls the kit's existing
  `lib/`, which already reproduces #3220's own published vectors 39/39 at the
  pinned commit. B implements those sections from the spec text from scratch.
  So for the authority sections the test is *from-scratch B vs. a
  vector-validated reference*, which is the stronger comparison; re-guessing
  already-conformance-checked constants a second time would have weakened it,
  not strengthened it.
- The two implementations share **fixture files** — the same inputs — and
  nothing else. Signing material is x402#3220's own published issuer seed at
  the pinned commit (upstream test material, already public). **No StillOS
  private key appears anywhere in this repository.**
- Both sides are driven through an identical op interface by
  `tools/run_corpus.cjs`, so a divergence is a real disagreement and not an
  artifact of two different call shapes.
- SHA-256 itself is not re-derived on either side (`node:crypto` and
  CPython's `hashlib`). That would test OpenSSL against CPython, which is not
  the property under test. Declared, not quietly assumed.

## What the corpus attacks

69 vectors, each carrying what it attacks, the exact input ops, and the
expected result. Fixed verifier clock `2026-09-10T00:00:00Z`; no randomness.

| Family | n | Target |
|---|---|---|
| `canon-*` | 6 | RFC 8785 JCS: UTF-16 code-**unit** key order (not code point), NFC≠NFD (JCS MUST NOT normalize), lone surrogates, number-vs-string ambiguity |
| `triple-*` | 10 | stark-receipt §2.1/§2.2 `{alg,enc,hex}`: missing/unknown `enc` and `alg` fail closed, lowercase hex, no silent zero-pad, `0x`-prefix equivalence, **felt252 masking materially changes 31 of 32 digests — and the 1-in-32 case where it is a no-op and a broken verifier still passes** |
| `leaf-*` | 10 | stark-receipt §4.1–§4.4: limb round-trip, refusals F1–F4, same digest under two labels is legitimate, K=0 with F≥1 is legal, unknown origin tag ⇒ indeterminate and never absent |
| `base-*` | 9 | stark-receipt §4.6 `BASE_SETTLEMENT_V1`: seven fields and nothing else, `payTo` sorts before `payer` under UTF-16 (a case-insensitive sort would not), amounts are strings, CAIP-2 network case preserved |
| `receipt-*` | 9 | StillOS notary receipt v1 against **two real production receipts pulled verbatim from the live ledger**, including a real chain link, the real retired key, and the 5-field vs 6-field preimage split (`resolver_hash` omitted ≠ `null`) |
| `auth-*` | 14 | #3220 §3/§6: inclusive boundaries at `perPayment` and `cap`, one-unit-over denials, recipient scope, expiry on the **verifier** clock, a payer-supplied `at` that must not extend authorization, `alg`/unknown-member refusals, totality under a malformed `purpose` |
| `bind-*` | 4 | #3220 §7 preimage binding, all three scheme renderings, `sha256:` prefix retention, out-of-grammar `paymentId` |
| `split-*` | 7 | The pre-settlement/post-settlement split: ALLOW then REFUTED on amount and on recipient, `settledUnderReport`, partial binding info failing closed |

## Defects found

Three. All are gaps in the specifications as pinned, not bugs in the
proposals' code, and all three are reported here rather than worked around
silently.

### D-1 — no normative mapping from an authority refusal to an EVC denial code

`authority.md` §19 defers **"refusal signaling — the error shape returned on
an authority refusal"** to a companion carriage document that does not exist
yet. §16 makes the fixture's diagnostic strings explicitly *informative
only*: a refusal case is conformant when the accept/refuse verdict matches.
Meanwhile #3376's EVC boundary is a **closed** denial-code registry —
`evcHost.ts`'s `isClosedVerdict` accepts exactly `delegation_invalid`,
`expired`, `internal_error`, `invalid_bundle`, `invalid_proof`,
`invalid_signature`, `malformed_input`, `request_mismatch`, `scope_exceeded`,
`unsupported_version`, and rejects the verdict otherwise.

So the two proposals compose today only if each verifier author privately
invents the mapping from #3220's prose reasons to #3376's ten codes. Two
implementations can be fully conformant to both documents, refuse the same
payment, emit different codes, and no host can tell. This kit's codes are
taken from `isClosedVerdict` at the pinned commit — the machine-readable
source — not from descriptive names read out of #3220's prose. **The fix is
one normative table in the carriage doc.**

### D-2 — found by the differential run itself, in this kit

`lib/settle.cjs` returns `{verdict: 'SETTLED_OK'|'POST_SETTLEMENT_REFUTED',
reasons: [...]}`. Implementation A's op adapter initially read it as
`{ok, code}` — the shape every *other* lib function uses. `undefined` is
falsy, so **every compliant settlement was silently turned into a refusal**,
and a fail-closed verifier looks correct while it is refusing honest
payments. Nothing in the upstream fixture catches this: it is an adapter
defect, not a spec defect. It surfaced within seconds of implementation B —
which has no such adapter — disagreeing on `split-03-authorized-and-complied`.
This is the case for building the second implementation, stated as a fact
about this repository rather than as an argument.

### D-3 — `scheme` has no normative wire token

#3220 §7's table names the three schemes in prose — "EIP-3009", "Permit2",
"XRPL" — and never defines the token that appears on the wire in a settled
artifact's `scheme` field. The only machine-readable evidence is the object
key in #3220's own fixture: `eip3009`. An implementer reading the prose
alone plausibly emits `eip-3009`, and a correctly fail-closed verifier then
**refutes a settlement that complied in every substantive respect** — right
mandate, right amount, right recipient, right binding slot.

`split-07-undefined-scheme-token-refuted` is a frozen reproduction. The
fail-closed behavior is right; the missing token is the defect. **The fix is
three literals in §7's table.**

## The one documented divergence

`split-07` also carries a second facet, and it is the honest limit of what
the corpus can assert. Both implementations refute — the security-relevant
property — but they disagree on the reason code: A says `invalid_proof`, B
says `malformed_input`. No spec text supports either. Rather than picking one
and calling the disagreement resolved, the vector asserts only that both
refute, and the runner **records the code divergence in the results file**
(`results/adversarial-results.json`, field
`documented_unspecified_divergence`) and prints it. This is D-1 showing up as
a measurement rather than as an argument.

Forcing agreement here would have manufactured a 69/69 that meant less than
the one printed above.

## Inferences — readings, not spec text

Recorded so a reader can disagree with them:

1. **"The four hex fields are lowercase"** (stark-receipt §4.6) does not
   enumerate *which* four. `asset`, `payTo`, `payer`, `transaction` are the
   only hex-valued fields in the seven, so that is the reading both
   implementations use. If the profile means something else, `base-07` is
   testing the wrong four.
2. **Non-integer JSON numbers are refused, not canonicalized.** RFC 8785
   §3.2.2.3 requires ECMAScript `Number`→`String` (Ryu shortest round-trip).
   Every numeric field in #3220 §4 and stark-receipt §4.6 is carried as a
   decimal **string** precisely to avoid this, so both implementations refuse
   out-of-profile floats rather than approximate them. **Ryu is therefore not
   tested here** — declared, not claimed.
3. **First-reason reporting.** Several checks can fail at once; both
   implementations report the first refusal in evaluation order. The specs do
   not order them.

## Out of scope, and why

§8 (spend log / RFC 6962 Merkle), §9 (committed head / freshness floor), §10
(on-chain anchoring) and §11 (Model B payee attestation) are **not
implemented**, and are excluded from both numbers above rather than counted
as passes. #3376's actual EVC request carries a single payment's context;
there is no wire path today by which a verifier could receive a spend log, a
committed head, or payee attestations. `strangerVetoResisted` is a §11 Model
B property — the Model A path this kit covers has no attestation surface for
a stranger to exploit. Full accounting in
[`../docs/SOURCE_PINS.md`](../docs/SOURCE_PINS.md).

If the companion carriage document referenced in §19 later adds those
channels, this cut should be revisited.

## What this does not prove

- **Not that either proposal is correct.** It proves two unrelated
  implementations reading the same text reach the same values and the same
  verdicts, and it names three places where the text does not determine the
  answer.
- **Not an endorsement, and not endorsed.** Both x402 PRs are third-party,
  open and unmerged; the stark-receipt profile is a third-party draft.
  Nothing here constitutes review or acceptance by whawk46, saneGuy,
  seritalien, Vauban Pay, Coinbase or the x402-foundation maintainers.
- **Not that a settlement complied.** A pre-settlement `allow` is a statement
  about authorization at evaluation time. Compliance is the separate,
  explicit post-settlement check — `split-01` and `split-02` exist to show
  ALLOW followed by REFUTED on the same mandate.
- **Not that a receipt proves delivery, execution, or issuer
  trustworthiness.** A receipt proves a specific bundle was checked against a
  specific mandate at a specific policy version and got a specific decision.
  Nothing more.
- **Not a live integration test.** Everything here is offline and static
  against pinned sources — which is what "offline-verifiable" is supposed to
  mean, but it is not the same as having run against a live counterparty.
- **Not a proof that the corpus is complete.** 69 vectors is 69 vectors. The
  families above are the attack surface we could name; absence of a vector is
  not evidence of absence of a defect.
