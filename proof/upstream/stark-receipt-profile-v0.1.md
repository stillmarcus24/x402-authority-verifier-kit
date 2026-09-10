<!--
This is the English rendering of the working document
`docs/standards/x402-stark-receipt-profile-v0.1.md` of Vauban Pay, published
here so that the people we discuss it with (x402-foundation/x402 #3389) can
read the same text we work from. The mirror `vauban-org/x402-starknet` is a
`git subtree split` of this package's directory ; this file is not part of the
npm tarball (`files` in package.json).
-->
# stark-receipt : an anchoring profile for `extension-offer-and-receipt`, v0.1 (draft, 2026-09-08)

Status : draft, for the next revision of x402-foundation/x402 #3389 and, if the
foundation answers yes to the question asked there, a PR under
`specs/extensions/`. This document keeps its promises with measured facts and
names what it does not do ; where the current mechanism cannot yet do what the
profile describes, it says so instead of leaving it out.

## 1. What the profile adds, and nothing else

`extension-offer-and-receipt` gives x402 signed receipts and devotes a section
to the hard question : who answers for the key that signs. This profile changes
neither the receipt, nor its envelope, nor the semantics of 402. It adds an
**anchor** : the settlement is bound by a STARK proof, the proof by a fact
written in a public registry, so that a receipt verifies offline against
public parameters and is read back in a public registry, with no key to trust.
Other anchoring profiles (EAS attestations, transparency logs) remain sibling
profiles : the decomposition of #2887 (one record, several anchoring profiles)
is the frame, not a competitor.

## 2. The anchored record

An anchored receipt carries, in addition to the extension's receipt :

```json
{
  "anchor": {
    "profile": "stark-receipt/v0.1",
    "batch_root":    { "alg": "poseidon-252", "enc": "none", "hex": "0x…" },
    "fact":          { "alg": "poseidon-252", "enc": "none", "hex": "0x…" },
    "leaf_index": 12,
    "batch_size": 59,
    "registry": { "chain": "starknet:SN_SEPOLIA", "contract": "0x…", "kind": "integrity-fact-registry" },
    "epoch": { "id": 8, "root": { "alg": "keccak-256", "enc": "none", "hex": "0x…" },
               "chains": ["eip155:11155111"] }
  }
}
```

A note on `chains`, added 2026-09-08 : the field lists the chains where the
epoch seal is RECORDED, not those where a mirror exists. Apodix verified that
day that only epoch 1 carries its Base receipts ; epochs 2 to 8 have `null` for
the Base transaction hashes, and their manifests say the mirror was READ on the
contract, not written by a transaction. A mirror without a receipt therefore
does not go into `chains` : a verifier reading `eip155:84532` there would look
for a transaction that does not exist and return "refuted" where the truth is
"not recorded".

### 2.1 Digests : a triple, never a bare value

Every digest in the profile is an object `{alg, enc, hex}` :
- `alg` names the function : `sha-256`, `keccak-256`, `poseidon-252`, `blake2s-256` ;
- `enc` names the encoding the verifier must apply BEFORE comparing : `none`,
  or `felt252-masked-251` (the 256-bit digest is stored in a 251-bit field
  element, `x & ((1 << 251) - 1)`) ;
- `hex` is the value, lowercase, `0x` prefix, no superfluous leading zero.

A digest without `enc` is invalid, not defaulted. Why : a bare digest compares
literally, and a verifier that compares a full SHA-256 to its masked form
returns a false negative on thirty-one receipts out of thirty-two (measured on
our own verifier before the mask became normative) ; a verifier that receives
`0x0abc…` and `0xabc…` for the same felt returns a false negative on a
spelling difference (measured on 2026-09-07 on a real fact, fixed at Apodix
the same day). Converged with Tamga (goun7) on 2026-09-08 : their `{alg, hex}`
pair becomes this triple with `enc: "none"`.

### 2.2 Canonical rendering of identifiers

A verifier compares values as integers and renders a single form (lowercase,
`0x`, no leading zero). A conformance test of the profile carries a vector
whose most significant byte is zero, so that the omission shows.

## 3. What the fact commits to

The fact is the public output of a Cairo program proved by Stone (preset
`recursive_with_poseidon / keccak_160_lsb / stone6 / strict`, 60 bits) and
registered in Integrity's FactRegistry on Starknet ; it commits to
`batch_root`, and `batch_root` is

```
Poseidon([ 'VZKPAY_AGGROOT_V2', K, currency_id, subject_type,
           (subject_1, nullifier_1, amount_1), …, (subject_K, nullifier_K, amount_K) ])
```

a flat typed list of K settlements of one currency and one subject type,
without timestamp (A-1.2, replayed by the Rust mirror `aggregate_root_v2_felts`
and by the circuit). The inclusion path of a receipt is therefore **the
preimage itself and its position `leaf_index`**, not a Merkle path :
recomputing the root requires the K triples. This is a cost choice (a flat
preimage hashes in a single Poseidon inside the circuit) with an honest
consequence for §4.

What the fact establishes : that these K settlements, with these amounts and
these nullifiers, were verified by the program whose `program_hash` is the
fact's, before the block of the registration. What it does not establish : who
is behind a subject (identity stays off-circuit), that the good was delivered,
that the price was fair.

## 4. Foreign leaves : the batch root v3, built

A hash-chained receipt registry (Tamga) or a bonded dispute record (StillOS)
produces a 32-byte digest ; the cross example agreed with Tamga on 2026-09-08
is to make it a leaf of a batch. The **v2** circuit cannot : its preimage
admits only typed settlements, and a foreign digest has no subject, no
nullifier and no amount there. Three routes were named ; the third has been
**built since 2026-09-08**, in a separate Cairo program
(`vauban_zkpay_batch_foreign`), with its Rust mirror and its cross golden
vector.

The two routes set aside, with their why-not, which stays true :

1. Encoding the foreign digest as a triple `(subject = tag, nullifier =
   digest, amount = 0)` : rejected, because it would pass a chain head off
   as a zero settlement and confuse two kinds of facts under one tag ;
2. A second program whose preimage is `Poseidon(['VZKPAY_FOREIGN_V1',
   origin_tag, digest])` per leaf and a Merkle tree above : one fact per
   foreign leaf, full cost per leaf (about 14 STRK on testnet).

### 4.1 The v3 preimage, normative

```
Poseidon([ 'VZKPAY_AGGROOT_V3', K, currency_id, subject_type,
           (subject_1, nullifier_1, amount_1), …, (subject_K, nullifier_K, amount_K),
           F, (origin_tag_1, digest_lo_1, digest_hi_1), …,
              (origin_tag_F, digest_lo_F, digest_hi_F) ])
```

- `origin_tag` is a short identifier of the origin registry, written as a
  Cairo short string (at most 31 ASCII bytes packed in a felt252), for
  example `'APODIX_EPOCH_ROOT_V1'` or `'TAMGA_CHAIN_HEAD_V1'` ;
- the F leaves come AFTER the K settlements, in a single preimage, hence
  under a single fact. Anchoring cost : **unchanged**, it depends neither on
  K nor on F (§6) ;
- **K and F are BOTH length prefixes**, and that is what separates the
  shapes. Without the second, six felts would read equally as two
  settlements (`K=2, F=0`) or as one settlement followed by one leaf
  (`K=1, F=1`) ; a foreign digest could then be presented as a settlement,
  and the reverse. Under A-1.2 the root IS the identity of the batch
  subject, so a shape collision is an identity collision. This is the M-5
  injectivity, applied twice because there are two lists, and it is under
  test on both sides (`collision_de_forme_k2f0_vs_k1f1` in Cairo,
  `v3_span_shape_closes_the_k2f0_vs_k1f1_collision` in Rust).

### 4.2 Encoding the digest : two 128-bit limbs, lossless

The digest `D` is the big-endian 256-bit integer of the 32 bytes. It enters
as TWO felts : `digest_lo = D mod 2^128` then `digest_hi = D >> 128`, in that
order, which is the order of Cairo's `u256` fields (`{ low, high }`). The
profile therefore declares `enc: "none"` for a leaf : **no bit is lost**.

Why not a masked felt : a felt252 has only 251 useful bits, and
`x & ((1 << 251) - 1)` would drop 5 bits, making 32 digests
indistinguishable. That is the exact silent bug the profile refuses in §2.1
for masked digests, and there is no reason to reintroduce it where two felts
suffice.

In Cairo both limbs are typed `u128` : the range check comes from the TYPE,
not from a hand-written constraint one could forget to wire, and a `u128`
serialises as ONE felt (only a `u256` splits), so a leaf weighs exactly 3
felts on the wire as in the preimage.

### 4.3 The four refusals, named

A v3 batch is UNPROVABLE if any of these constraints gives way ; there is
then no proof to present. The refusal names the constraint, never "a
constraint failed".

| refusal | condition | why |
|---|---|---|
| **F1** | `origin_tag == 0` | a digest without a label is a number : the origin registry is what gives it meaning |
| **F2** | `digest_lo == 0 && digest_hi == 0` | no hash function returns zero on a known input ; in practice it is an unfilled field, and accepting it would let an empty promise into the root, indistinguishable from a real one |
| **F3** | two leaves with the SAME triple `(tag, lo, hi)` | a leaf counted twice inflates F without adding anything. The bound is the TRIPLE : the same digest under two labels is LEGITIMATE, it is the same object seen by two registries |
| **F4** | `F > 64` | a CHOSEN bound, not a measured one : it keeps the quadratic F3 deduplication at 2,016 comparisons worst case, which allows comparing whole triples rather than hashing them into a dictionary key (hence no collision-resistance assumption) |

Two edge cases, settled :

- `K = 0` with `F >= 1` is **LEGAL** : it is the pure-leaf batch, a fact whose
  only role is to commit foreign digests. Without it, anchoring an epoch
  root would require fabricating a fake payment ;
- `K = 0` **and** `F = 0` is refused : a batch that commits nothing would
  produce a constant root, hence a fact that attests nothing while looking
  like an anchor.

### 4.4 What the fact establishes for a foreign leaf

**That this digest was presented under this label in this batch**, before
the block of the fact's registration, by the program whose `program_hash` is
the fact's.

**NOTHING about its validity in the origin registry.** The circuit verifies
no foreign proof, knows no rule of Tamga's or Apodix's, and does not claim
that the digest is the head of a well-formed chain nor the root of a closed
epoch. A v3 batch is a **record of presentation**, not a cross validation.

The profile rule, independent of the route : a foreign leaf carries its
origin label in the preimage, and a verifier that does not know the label
concludes nothing (indeterminate), never "absent".

### 4.5 A v3 batch is NOT a v2 batch, even at F = 0

Two things separate them : the domain tag (M-4) and the trailing `F` prefix
(M-5), present even when `F = 0`. A v3 batch without leaves therefore remains
an object of ANOTHER shape, never a synonym of the v2 batch of the same
settlements. This is intended, and under test (`f0_v3_n_est_pas_v2`).

Operational consequence : v3 is a SECOND program, with its own identity
(`program_hash`), next to the v2 that carries the daily anchoring rail. A
receipt says which one it is through its `root_domain_tag`, and carries its
leaves in the clear under `foreign_leaves` ; the two halves go together or
not at all, a v3 tag without a leaf vector being refused just like leaves
under a v2 tag.

### 4.6 A settlement from ANOTHER chain : `'BASE_SETTLEMENT_V1'`

The first label that designates neither an epoch root nor a chain head, but
**one individual settlement that was settled elsewhere**. It exists because the
x402 merchant already takes payment on Base : recounted at the source on
2026-09-08, the discovery index's offers give 133 `eip155:8453` offers across a
hundred resources, 34 Solana, zero Starknet. Asking such a merchant to come and
settle on Starknet is a chain migration ; under this label, they change nothing.

**The digest** is the SHA-256 of the JCS (RFC 8785) form of a JSON object of
**seven fields**, and of nothing else :

```
{ "amount", "asset", "network", "payTo", "payer", "resource", "transaction" }
```

The keys are the ones x402 v2 already uses (`payTo`, not `pay_to`) : a verifier
copies the fields across from its receipt, it does not translate them. The
values are STRINGS ; `amount` is decimal, in the asset's smallest unit, because
a `u256` does not survive a round trip through JSON numbers in most languages.
The four hex fields are lowercase ; `network` keeps its case, a CAIP-2 reference
being case-sensitive (`starknet:SN_SEPOLIA`). Sorted by UTF-16 code units,
`payTo` comes BEFORE `payer` : a case-insensitive sort would yield a different
digest.

**Why exactly these seven.** They are exactly the ones a third party can both
reconstruct from the x402 receipt it holds and read back on the chain. Six are
on the chain (the `Transfer` gives four, the emitting contract the fifth, the
chain id the sixth) ; the seventh, `resource`, comes from the merchant's 402
challenge, and it is in the preimage because a digest that did not name what was
bought would commit to a transfer, not to the settlement of a resource. Two
fields are deliberately ABSENT : **no timestamp** (it is not in the receipt, and
the chain's is not the merchant's ; carrying one would make the digest
computable by exactly one of the two parties) and **no `success`** (a failed
receipt has nothing to anchor, and carrying the flag would make "this failure
was presented in that batch" expressible, which nobody asked for and which a
reader would misread as a payment).

A verifier holding a receipt whose `resource` differs by one character computes
a different digest and renders **refuted**, not indeterminate. That is the
correct verdict : it is not the same settlement record.

**What the fact establishes for such a leaf** is §4.4 and not one comma more :
that this digest was presented under the label `'BASE_SETTLEMENT_V1'` in this
batch, before the block of the fact's registration, by the program whose
`program_hash` is the fact's. **NOTHING about the validity of the Base
transaction** : not that it was included, not that it succeeded, not that the
amount moved. The circuit reads no EVM chain. The reader reads Base back for
all of that, and can do so without us : the six chain fields are readable with
`cast receipt`, the seventh is in their receipt, and the recipe fits on one line.

The `V1` in the label is not decoration : the label names a RECIPE, and the day
the seven fields change, the label changes with them rather than meaning two
things at once.

Recipe, golden vector and two digests of REAL settlements :
`docs/testing/recensement-base-2026-09-08.md` (internal). The two
implementations (`receipt_digest.rs` in Rust, `recenser-reglements-base.py` in
python) are checked against each other on the same vector by a bench that reads
the constant pinned on the other side.

## 5. Verification procedure (offline, then read-back)

1. Recompute the receipt's digest according to the extension's
   `canon_version` (JCS RFC 8785 + SHA-256), and check that the receipt is
   the one the triple `(subject, nullifier, amount)` designates at
   `leaf_index` (the receipt-to-triple link is defined by the receipt's
   issuer and published with it).
2. Recompute `batch_root` from the K triples, or : if the receipt carries
   `foreign_leaves`, hence if its `root_domain_tag` is `VZKPAY_AGGROOT_V3` :
   from the K triples THEN the F leaves, length prefixes included (§4.1) ;
   compare as integers after applying `enc`. A leaf whose label is unknown
   to the verifier still enters the computation : the root is not recomputed
   halfway. What the verifier returns as **indeterminate** for that leaf is
   what it MEANS, never its inclusion.
3. Read the fact back in the named registry
   (`get_all_verifications_for_fact_hash` on Integrity) ; an absent fact is
   "not anchored", never "invalid".
4. If `epoch` is present : recompute the epoch root from the public manifest
   and compare it to what the anchoring contract sealed on each listed chain ;
   two raw files and python suffice (measured by a third party on
   2026-09-08 : red on the first statement, green after a fix).

Three distinct verdicts, never merged : established, refuted, indeterminate.
And two NAMED indeterminates, never conflated (Tamga's reading, 2026-09-08) :
`indeterminate:label` (an origin label the verifier does not know : the leaf
is in the root, its meaning is not established) and `indeterminate:anchor`
(an unreachable registry or a fact not read back : the root is recomputed,
the anchoring is not observed). A digest that does not match after applying
`enc` is **refuted**, not indeterminate.

## 6. What is measured, what is not (2026-09-08)

- Anchoring cost on Starknet Sepolia : 14.62 STRK (K=1), 14.79 (K=59 real),
  15.75 (K=550), 14.07 (K=10, daily batch of 2026-09-08) ; the spread is L1
  price drift, not K. 7,562 is the largest K proved, not an anchoring
  measurement.
- Epoch inclusion verified by a third party without the anchorer's
  repository or tooling : done, epoch 8, two raw files.

### 6.1 The v3 batch, measured (2026-09-08)

The v3 circuit was executed on REAL batches with a REAL foreign leaf : the
leaf is `('APODIX_EPOCH_ROOT_V1', keccak-256 root of Apodix's epoch 8,
0x0340584b…d51d, published in `anchors/epoch-0008.json`)`, sealed on Ethereum
Sepolia. A mirror on Base Sepolia exists, but Apodix verified on 2026-09-08
that only epoch 1 has its Base receipts recorded : epochs 2 to 8 carry `null`
for the Base transaction hashes, and the manifests say the mirror was read on
the contract rather than transacted. So this profile does NOT promise a Base
seal, and a reader who asks for the Base receipt of epoch 8 is right to be
told there is none.

| quantity | K=2 (committed fixture of 2026-09-04) + F=1 | K=7 (real daily batch of 2026-09-07) + F=1 |
|---|---|---|
| `program_hash` v3, scarb 2.13.1 (Stone rail) | `0x016b9737cbaa4d3430622450bf44a2ce78ba349f7ac156357fd89169cf041a09` | same |
| CairoVM steps | 2,038 | 5,155 |
| public output size (`N = 7 + 5K + 3F`) | 20 felts | 45 felts |
| `batch_root` v3 committed at `page[3]` | `0x07ed43fe4f28ace4dae363bd179959e23f7785f3140d47192cc4889ede759ebd` | `0x051ca97a26ed4666ff335bc04fa15384b118e9c8280bc5177aeff500552ccea5` |
| predicted fact (Stone rail recipe) | `0x02566a70b4808e89c44e1a568f3a8ff0c60596c3b4af85d2d2c719cf2fe1c7a5` | `0x02362521254a8ca4f75097267655f6aeb8524217a25c261f60538edc367136e2` |

**The root the circuit commits is the root the mirror recomputes**, on both
real executions and not only on a test vector : Cairo (in the PIE), Rust
(`aggregate_root_v3_felts`) and python (`poseidon-py`, the rail's predictor)
agree to the felt. This is the check that matters, because it bears on what
the PIE contains and not on what the code should produce.

Cost landmark : the daily K=10 batch weighs 6,548 steps and fills 6.3 % of
the 2^22 Stone bucket ; at 5,155 steps the v3 K=7/F=1 fills 0.05 %. A leaf
costs 3 preimage felts and nothing else in the channel.

**A STARK proof of a v3 batch, verified by our verifier.** The same K=7/F=1
batch was proved and verified on the evening of 2026-09-08, which moves the
statement from "the circuit commits the right root" to "a proof of this
circuit is accepted, and a tampered proof is refused". Toolchain **scarb
2.17.0** (the Rust work plan's, distinct from the 2.13.1 of the table above) :

| quantity | value (K=7, F=1, scarb 2.17.0) |
|---|---|
| `program_hash` v3 = `BATCH_FOREIGN_VK`, pinned | `0x55ab9e6f44cecaaee5dfe605d539acb48affec42e6e572c3b22872311cdb5b5` |
| `batch_root` v3 at `output[3]` | `0x051ca97a26ed4666ff335bc04fa15384b118e9c8280bc5177aeff500552ccea5` |
| `scarb prove`, wall clock | **1 min 17 s** (11.3 GiB peak, 8-core / 31 GiB workstation) |
| proof, committed compressed | **1.85 MiB** (12.70 MiB uncompressed) |
| verdict | **ESTABLISHED** by the mixed-batch verification path on the real Stwo backend |

The root at `output[3]` is **the same felt under 2.13.1 and under 2.17.0**,
while the `program_hash` differs between them (`0x016b9737…` against the value
above). A matching root is therefore NOT evidence that two proofs attest the
same program : only `output[2]` says that, which is why identity binding is a
gate separate from root binding.

### 6.2 What is NOT measured

- **No v3 anchoring on-chain yet.** The facts in the §6.1 table are PREDICTED ;
  the K=7 one is on its way through the Stone rail (Apodix porter) at the time
  of writing, and this section will carry the registered fact, the block and
  the real cost when it lands. Until then the cost of a v3 anchor is an
  extrapolation from the five v2 anchors (the cost depends neither on K nor
  on F, but that remains to be observed on a v3 fact).
- **No v3 proof on the Stone rail.** The proof verified above is a Stwo proof
  on the **blake2s** channel, the only channel our Rust verifier can read
  back. A poseidon252 proof, the one Starknet would verify natively, and the
  one the Stone rail consumes, has not been produced for a v3 batch.
- **No real Tamga leaf.** The measured leaf comes from Apodix ; the exact
  shape of Tamga's chain head is not fixed yet, and the profile does not
  claim to know it.
- An anchored receipt consumed by an x402 client that is not ours.
