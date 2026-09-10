#!/usr/bin/env node
'use strict';
// Phase 4 -- builds the frozen adversarial corpus at proof/corpus/adversarial.json.
//
// Every vector carries: id, what it attacks, the exact INPUT ops, and the
// EXPECTED result. The runner (proof/tools/run_corpus.cjs) then records the
// actual Node result and the actual Python result. A vector PASSES only when
// BOTH independent implementations agree with the expectation.
//
// Signing keys: the mandates here are signed with the seed published in
// #3220's OWN fixture (`keys.issuer.seedB64url` at the pinned upstream
// commit). That is upstream test material, already public, and is never a
// StillOS production key. No private key of ours appears in this repository.

const fs = require('fs');
const path = require('path');
const canon = require('../../lib/canon.cjs');
const libMandate = require('../../lib/mandate.cjs');
const libBinding = require('../../lib/binding.cjs');

const ROOT = path.join(__dirname, '..', '..');
const FIX = JSON.parse(fs.readFileSync(path.join(ROOT, 'vectors/fixtures/authority-vectors.json'), 'utf8'));
const SEG = JSON.parse(fs.readFileSync(path.join(ROOT, 'proof/artifact/notary-chain-segment.json'), 'utf8'));
const PEM = fs.readFileSync(path.join(ROOT, 'proof/artifact/stillos-notary-ed25519-v1.pub'), 'utf8');
const PEM_RETIRED = fs.readFileSync(path.join(ROOT, 'proof/artifact/stillos-notary-ed25519-retired-2026-07-31.pub'), 'utf8');

const ISSUER_SEED = FIX.keys.issuer.seedB64url;
const BASE = FIX.modelA.mandate;
const NOW = '2026-09-10T00:00:00Z';   // fixed verifier clock -- determinism

function sign(m) {
  return { mandate: m, alg: 'Ed25519', sig: canon.signEd25519(libMandate.MANDATE_TAG, m, ISSUER_SEED) };
}
function withMandate(patch, drop = []) {
  const m = { ...BASE, ...patch };
  for (const d of drop) delete m[d];
  return m;
}

const ENV = sign(BASE);
const DIGEST = libMandate.mandateDigest(BASE);
const PAYMENT_ID = 'pay-001';
const BIND = libBinding.computeAllEncodings(DIGEST, PAYMENT_ID);

// A mandate with no perPayment, so the pure `cap` boundary is reachable.
const NO_PP = withMandate({ nonce: 'authority-vec-a-001-nopp' }, ['perPayment']);
const ENV_NO_PP = sign(NO_PP);
const DIGEST_NO_PP = libMandate.mandateDigest(NO_PP);

const EXPIRED = withMandate({ notAfter: '2020-01-01T00:00:00Z', nonce: 'expired-001' });
const ENV_EXPIRED = sign(EXPIRED);
const DIGEST_EXPIRED = libMandate.mandateDigest(EXPIRED);

function payment(over = {}) {
  return {
    payer: BASE.subject, recipient: 'merchant.example', asset: 'FCUSD',
    amount: '1000', mandateDigest: DIGEST, paymentId: PAYMENT_ID, ...over,
  };
}
function settled(over = {}) {
  return {
    payer: BASE.subject, recipient: 'merchant.example', asset: 'FCUSD',
    amount: '1000', scheme: 'eip3009', slot: BIND.eip3009, ...over,
  };
}

// Two real SHA-256 digests chosen so felt252 masking is load-bearing on one
// and a no-op on the other. Recomputed here, not copied, so the corpus cannot
// drift from its own claim.
const crypto = require('crypto');
const HIGH_BIT = SEG.target.receipt_hash;                                   // top5 = 12
let LOW_BIT = null;
for (let i = 0; i < 4096 && !LOW_BIT; i++) {
  const h = crypto.createHash('sha256').update('stillos-conformance-probe-' + i).digest('hex');
  if (BigInt('0x' + h) >> 251n === 0n) LOW_BIT = { hex: h, preimage: 'stillos-conformance-probe-' + i };
}

const mut = (s, i, c) => s.slice(0, i) + c + s.slice(i + 1);
const flipHex = (s, i) => mut(s, i, s[i] === '0' ? '1' : '0');

const V = [];
const add = (id, attacks, ops, expect, note) => V.push({ id, attacks, ops, expect, note: note || null });

// --- canonicalization -------------------------------------------------------
add('canon-01-field-reordering', 'canonical field reordering must not change the digest',
  [{ id: 'a', op: 'jcs', args: { value: { b: '2', a: '1', c: '3' } } },
   { id: 'b', op: 'jcs', args: { value: { c: '3', a: '1', b: '2' } } }],
  { a_equals_b: true, canonical: '{"a":"1","b":"2","c":"3"}' });

add('canon-02-utf16-key-order-astral', 'RFC 8785 3.2.3 sorts keys by UTF-16 code UNITS, not code points',
  [{ id: 'a', op: 'jcs', args: { value: { '\u{1F600}': 1, '＀': 2 } } }],
  { canonical_first_key_is_astral: true },
  'U+1F600 encodes to the surrogate pair D83D DE00, so under UTF-16 it sorts BEFORE U+FF00. Under Python-style code-point ordering it would sort AFTER. A sorted() with no key function diverges here.');

add('canon-03-unicode-nfc-vs-nfd', 'JCS MUST NOT normalize; NFC and NFD are different digests',
  [{ id: 'nfc', op: 'jcs', args: { value: { k: 'é' } } },
   { id: 'nfd', op: 'jcs', args: { value: { k: 'é' } } }],
  { nfc_equals_nfd: false },
  'Silent NFC normalization would make two distinct records hash alike.');

add('canon-04-lone-surrogate-refused', 'an unpaired surrogate cannot be UTF-8 encoded',
  [{ id: 'a', op: 'jcs', args: { value: { k: '\uD800' } } }],
  { ok: false, error: 'jcs_lone_surrogate' });

add('canon-05-integer-string-ambiguity', 'a numeric amount and its decimal string are NOT the same record',
  [{ id: 'num', op: 'jcs', args: { value: { amount: 1000 } } },
   { id: 'str', op: 'jcs', args: { value: { amount: '1000' } } }],
  { num_equals_str: false });

add('canon-06-non-integer-refused', 'out-of-profile floats are refused, never approximated',
  [{ id: 'a', op: 'jcs', args: { value: { amount: 0.1 } } }],
  { ok: false, error: 'jcs_non_integer_number_out_of_profile' });

// --- Vauban digest triple, section 2.1 / 2.2 -------------------------------
add('triple-01-high-bit-masking-material', 'felt252 masking CHANGES the value (31 of 32 digests)',
  [{ id: 'a', op: 'digest_triple', args: { triple: { alg: 'sha-256', enc: 'felt252-masked-251', hex: HIGH_BIT } } }],
  { valid: true, top5bits: 12, masking_is_noop: false });

add('triple-02-low-bit-masking-noop', 'the 1-in-32 digest where masking is a no-op and a BROKEN verifier still passes',
  [{ id: 'a', op: 'digest_triple', args: { triple: { alg: 'sha-256', enc: 'felt252-masked-251', hex: LOW_BIT.hex } } }],
  { valid: true, top5bits: 0, masking_is_noop: true },
  'Passing this alone proves nothing. It exists so that passing cannot be mistaken for conformance.');

add('triple-03-missing-enc', 'a digest without enc is INVALID, not defaulted to none',
  [{ id: 'a', op: 'digest_triple', args: { triple: { alg: 'sha-256', hex: HIGH_BIT } } }],
  { valid: false, error: 'missing_enc' });

add('triple-04-unknown-enc', 'an unrecognised enc must fail closed',
  [{ id: 'a', op: 'digest_triple', args: { triple: { alg: 'sha-256', enc: 'felt252-masked-252', hex: HIGH_BIT } } }],
  { valid: false, error: 'unknown_enc' });

add('triple-05-missing-alg', 'an unlabelled digest invites fake cross-ledger agreement',
  [{ id: 'a', op: 'digest_triple', args: { triple: { enc: 'none', hex: HIGH_BIT } } }],
  { valid: false, error: 'missing_alg' });

add('triple-06-unknown-alg', 'an unknown digest function must fail closed',
  [{ id: 'a', op: 'digest_triple', args: { triple: { alg: 'md5', enc: 'none', hex: HIGH_BIT } } }],
  { valid: false, error: 'unknown_alg' });

add('triple-07-uppercase-hex', 'section 2.1 requires lowercase; uppercase must not silently pass',
  [{ id: 'a', op: 'digest_triple', args: { triple: { alg: 'sha-256', enc: 'none', hex: HIGH_BIT.toUpperCase() } } }],
  { valid: false, error: 'hex_not_lowercase' });

add('triple-08-short-hex', 'truncation must not be silently zero-padded',
  [{ id: 'a', op: 'digest_triple', args: { triple: { alg: 'sha-256', enc: 'none', hex: HIGH_BIT.slice(0, 62) } } }],
  { valid: false, error: 'bad_hex_length' });

add('triple-09-0x-prefix-equivalence', 'section 2.2: 0x-prefixed and bare forms are the SAME value',
  [{ id: 'bare', op: 'digest_triple', args: { triple: { alg: 'sha-256', enc: 'none', hex: HIGH_BIT } } },
   { id: 'pref', op: 'digest_triple', args: { triple: { alg: 'sha-256', enc: 'none', hex: '0x' + HIGH_BIT } } }],
  { bare_equals_pref: true });

add('triple-10-leading-zero-rendering', 'a digest whose most significant byte is zero must render canonically',
  [{ id: 'a', op: 'digest_triple', args: { triple: { alg: 'sha-256', enc: 'none', hex: '00' + HIGH_BIT.slice(2) } } }],
  { valid: true, comparison_hex_has_no_leading_zero: true },
  'The exact false-negative Apodix hit on 2026-09-07: 0x0abc... vs 0xabc... compared as strings.');

// --- Vauban foreign leaf, sections 4.1-4.3 ---------------------------------
add('leaf-01-limb-roundtrip', 'section 4.2 limbs are lossless, low then high',
  [{ id: 'enc', op: 'digest_limbs', args: { hex: HIGH_BIT } },
   { id: 'dec', op: 'limbs_to_hex', args: { digest_lo: BigInt('0x' + HIGH_BIT.slice(32)).toString(10), digest_hi: BigInt('0x' + HIGH_BIT.slice(0, 32)).toString(10) } }],
  { roundtrip_equals_input: true });

add('leaf-02-F1-empty-origin-tag', 'refusal F1: a digest without a label is a number',
  [{ id: 'a', op: 'v3_batch', args: { K: 1, leaves: [{ origin_tag: '', digest_lo: '1', digest_hi: '1' }] } }],
  { provable: false, refusals_include: 'F1@0' });

add('leaf-03-F2-zero-digest', 'refusal F2: an all-zero digest is an unfilled field',
  [{ id: 'a', op: 'v3_batch', args: { K: 1, leaves: [{ origin_tag: 'STILLOS_NOTARY_RECEIPT_V1', digest_lo: '0', digest_hi: '0' }] } }],
  { provable: false, refusals_include: 'F2@0' });

add('leaf-04-F3-duplicate-triple', 'refusal F3: the bound is the TRIPLE, not the digest',
  [{ id: 'a', op: 'v3_batch', args: { K: 0, leaves: [
    { origin_tag: 'STILLOS_NOTARY_RECEIPT_V1', digest_lo: '5', digest_hi: '7' },
    { origin_tag: 'STILLOS_NOTARY_RECEIPT_V1', digest_lo: '5', digest_hi: '7' }] } }],
  { provable: false, refusals_include: 'F3@1' });

add('leaf-05-same-digest-two-labels-is-legal', 'section 4.3: the same digest under two labels is LEGITIMATE',
  [{ id: 'a', op: 'v3_batch', args: { K: 0, leaves: [
    { origin_tag: 'STILLOS_NOTARY_RECEIPT_V1', digest_lo: '5', digest_hi: '7' },
    { origin_tag: 'TAMGA_CHAIN_HEAD_V1', digest_lo: '5', digest_hi: '7' }] } }],
  { provable: true },
  'It is the same object seen by two registries. A verifier that dedupes on the digest alone wrongly refuses this.');

add('leaf-06-F4-over-64-leaves', 'refusal F4: a chosen bound of 64',
  [{ id: 'a', op: 'v3_batch', args: { K: 0, leaves: Array.from({ length: 65 }, (_, i) => ({ origin_tag: 'T', digest_lo: String(i + 1), digest_hi: '1' })) } }],
  { provable: false, refusals_include: 'F4' });

add('leaf-07-K0-F0-refused', 'a batch that commits nothing would produce a constant root',
  [{ id: 'a', op: 'v3_batch', args: { K: 0, leaves: [] } }],
  { provable: false, refusals_include: 'K0F0' });

add('leaf-08-K0-F1-pure-leaf-legal', 'K=0 with F>=1 is LEGAL -- anchoring without fabricating a payment',
  [{ id: 'a', op: 'v3_batch', args: { K: 0, leaves: [{ origin_tag: 'STILLOS_NOTARY_RECEIPT_V1', digest_lo: '5', digest_hi: '7' }] } }],
  { provable: true, pure_leaf_batch: true });

add('leaf-09-origin-tag-31-byte-bound', 'a Cairo short string is at most 31 ASCII bytes',
  [{ id: 'ok', op: 'origin_tag', args: { origin_tag: 'STILLOS_NOTARY_RECEIPT_V1' } },
   { id: 'over', op: 'origin_tag', args: { origin_tag: 'A'.repeat(32) } }],
  { ok_len: 25, over_error: 'tag_over_31_bytes' });

add('leaf-10-unknown-origin-tag-is-indeterminate', 'section 4.4: unknown label => indeterminate, NEVER absent',
  [{ id: 'a', op: 'v3_batch', args: { K: 0, leaves: [{ origin_tag: 'SOME_REGISTRY_WE_DO_NOT_KNOW', digest_lo: '5', digest_hi: '7' }] } }],
  { provable: true },
  'The leaf still enters the root computation. What is indeterminate is its MEANING, never its inclusion.');

// --- BASE_SETTLEMENT_V1, section 4.6 ---------------------------------------
const BS = {
  amount: '1000000', asset: '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913',
  network: 'eip155:8453', payTo: '0xa3a05818d4051bfa759fb7d936b57c072e4e0caf',
  payer: '0x1111111111111111111111111111111111111111',
  resource: 'https://stillosdigitalholdings.com/notary/screen-url',
  transaction: '0x2222222222222222222222222222222222222222222222222222222222222222',
};
add('base-01-seven-field-digest', 'section 4.6 golden vector, computed independently by both implementations',
  [{ id: 'a', op: 'base_settlement_v1', args: { fields: BS } }],
  { valid: true, node_equals_python: true },
  'Vauban publishes the RECIPE normatively but its golden vector lives in an internal document. This is a public one.');

add('base-02-payTo-before-payer', 'UTF-16 sort puts payTo BEFORE payer; a case-insensitive sort would not',
  [{ id: 'a', op: 'base_settlement_v1', args: { fields: BS } }],
  { jcs_has_payTo_before_payer: true });

add('base-03-eighth-field-refused', '"seven fields, and of nothing else"',
  [{ id: 'a', op: 'base_settlement_v1', args: { fields: { ...BS, timestamp: '2026-09-10T00:00:00Z' } } }],
  { valid: false, error: 'unknown_field_timestamp' });

add('base-04-missing-resource', 'a digest that did not name what was bought would commit to a transfer, not a settlement',
  [{ id: 'a', op: 'base_settlement_v1', args: { fields: (() => { const c = { ...BS }; delete c.resource; return c; })() } }],
  { valid: false, error: 'missing_field_resource' });

add('base-05-amount-as-number', '"The values are STRINGS" -- a u256 does not survive JSON numbers',
  [{ id: 'a', op: 'base_settlement_v1', args: { fields: { ...BS, amount: 1000000 } } }],
  { valid: false, error: 'field_not_a_string_amount' });

add('base-06-amount-leading-zero', 'a leading-zero amount is a different string for the same value',
  [{ id: 'a', op: 'base_settlement_v1', args: { fields: { ...BS, amount: '01000000' } } }],
  { valid: false, error: 'amount_not_canonical_decimal' });

add('base-07-uppercase-hex-field', '"The four hex fields are lowercase"',
  [{ id: 'a', op: 'base_settlement_v1', args: { fields: { ...BS, payTo: BS.payTo.toUpperCase().replace('0X', '0x') } } }],
  { valid: false, error: 'hex_field_not_lowercase_0x_payTo' });

add('base-08-resource-one-character-differs', 'a receipt whose resource differs by one character is REFUTED, not indeterminate',
  [{ id: 'a', op: 'base_settlement_v1', args: { fields: BS } },
   { id: 'b', op: 'base_settlement_v1', args: { fields: { ...BS, resource: BS.resource + 's' } } }],
  { a_digest_differs_from_b: true });

add('base-09-network-case-preserved', 'a CAIP-2 reference is case-sensitive and MUST NOT be lowercased',
  [{ id: 'a', op: 'base_settlement_v1', args: { fields: { ...BS, network: 'starknet:SN_SEPOLIA' } } },
   { id: 'b', op: 'base_settlement_v1', args: { fields: { ...BS, network: 'starknet:sn_sepolia' } } }],
  { a_digest_differs_from_b: true });

// --- notary receipt, STILLOS_NOTARY_RECEIPT_V1 -----------------------------
add('receipt-01-real-production-verdict', 'a real production receipt verifies offline against a pinned key',
  [{ id: 'a', op: 'notary_receipt', args: { receipt: SEG.target, pubkey_pem: PEM } }],
  { hash_ok: true, sig_ok: true, field_count: 6 });

add('receipt-02-real-production-claim-5-field', 'resolver_hash OMITTED (not null) yields the 5-field preimage',
  [{ id: 'a', op: 'notary_receipt', args: { receipt: SEG.prev, pubkey_pem: PEM } }],
  { hash_ok: true, sig_ok: true, field_count: 5 });

add('receipt-03-resolver-hash-null-not-omitted', 'null is NOT the same as omitted -- it changes the preimage',
  [{ id: 'a', op: 'notary_receipt', args: { receipt: { ...SEG.prev, resolver_hash: null }, pubkey_pem: PEM } }],
  { hash_ok: false });

add('receipt-04-mutated-content', 'a one-character change to a committed field breaks the digest',
  [{ id: 'a', op: 'notary_receipt', args: { receipt: { ...SEG.target, agent: SEG.target.agent + 'x' }, pubkey_pem: PEM } }],
  { hash_ok: false, sig_ok: true },
  'sig_ok stays true because the signature is over the STATED receipt_hash. Detection comes from hash_ok. Collapsing the two into one boolean would hide exactly this.');

add('receipt-05-mutated-receipt-hash', 'mutating the claimed digest breaks both the recomputation and the signature',
  [{ id: 'a', op: 'notary_receipt', args: { receipt: { ...SEG.target, receipt_hash: flipHex(SEG.target.receipt_hash, 0) }, pubkey_pem: PEM } }],
  { hash_ok: false, sig_ok: false });

add('receipt-06-mutated-signature', 'a one-byte signature mutation must fail verification',
  [{ id: 'a', op: 'notary_receipt', args: { receipt: { ...SEG.target, signature: (() => { const b = Buffer.from(SEG.target.signature, 'base64'); b[0] ^= 1; return b.toString('base64'); })() }, pubkey_pem: PEM } }],
  { hash_ok: true, sig_ok: false });

add('receipt-07-wrong-signing-key-real-retired', 'verified against the REAL retired StillOS key, not a synthetic one',
  [{ id: 'a', op: 'notary_receipt', args: { receipt: SEG.target, pubkey_pem: PEM_RETIRED } }],
  { hash_ok: true, sig_ok: false },
  'notary_fp 21de0669 vs the retired 921e3af5. A verifier that ignores notary_fp would try the wrong key and must still refuse.');

add('receipt-08-broken-chain-link', 'prev_hash must equal the previous receipt_hash',
  [{ id: 'a', op: 'notary_receipt', args: { receipt: { ...SEG.target, prev_hash: flipHex(SEG.target.prev_hash, 0) }, pubkey_pem: PEM } }],
  { hash_ok: false },
  'prev_hash is inside the hashed preimage, so breaking the chain also breaks the digest -- that binding is the point.');

add('receipt-09-jcs-would-be-wrong', 'the notary preimage is FIXED-ORDER, not JCS -- sorting the keys changes the digest',
  [{ id: 'fixed', op: 'notary_receipt', args: { receipt: SEG.target, pubkey_pem: PEM } },
   { id: 'jcs', op: 'jcs', args: { value: { agent: SEG.target.agent, claim_sha256: SEG.target.claim_sha256, ts: SEG.target.ts, prev_hash: SEG.target.prev_hash, notary_fp: SEG.target.notary_fp, resolver_hash: SEG.target.resolver_hash } } }],
  { jcs_sha256_differs_from_receipt_hash: true },
  'An implementer who assumes "canonical JSON" means JCS everywhere gets a wrong digest on every receipt.');

// --- authority: pre-settlement (section 6) ---------------------------------
add('auth-01-amount-exactly-at-per-payment', 'the boundary is inclusive',
  [{ id: 'a', op: 'authorize', args: { envelope: ENV, payment: payment({ amount: '250000' }), now_iso: NOW } }],
  { verdict: 'allow' });

add('auth-02-one-unit-above-per-payment', 'one minor unit over must deny',
  [{ id: 'a', op: 'authorize', args: { envelope: ENV, payment: payment({ amount: '250001' }), now_iso: NOW } }],
  { verdict: 'deny', code: 'scope_exceeded' });

add('auth-03-amount-exactly-at-cap', 'with no perPayment, cap is the inclusive bound',
  [{ id: 'a', op: 'authorize', args: { envelope: ENV_NO_PP, payment: payment({ amount: '1000000', mandateDigest: DIGEST_NO_PP }), now_iso: NOW } }],
  { verdict: 'allow' });

add('auth-04-one-unit-above-cap', 'no single payment may exceed the cumulative cap',
  [{ id: 'a', op: 'authorize', args: { envelope: ENV_NO_PP, payment: payment({ amount: '1000001', mandateDigest: DIGEST_NO_PP }), now_iso: NOW } }],
  { verdict: 'deny', code: 'scope_exceeded' });

add('auth-05-unauthorized-recipient', 'recipient scope fails closed',
  [{ id: 'a', op: 'authorize', args: { envelope: ENV, payment: payment({ recipient: 'evil.example' }), now_iso: NOW } }],
  { verdict: 'deny', code: 'request_mismatch' });

add('auth-06-wrong-asset', 'asset must match exactly',
  [{ id: 'a', op: 'authorize', args: { envelope: ENV, payment: payment({ asset: 'USDC' }), now_iso: NOW } }],
  { verdict: 'deny', code: 'request_mismatch' });

add('auth-07-expired-authority', 'expiry uses the VERIFIER clock',
  [{ id: 'a', op: 'authorize', args: { envelope: ENV_EXPIRED, payment: payment({ mandateDigest: DIGEST_EXPIRED }), now_iso: NOW } }],
  { verdict: 'deny', code: 'expired' });

add('auth-08-payer-at-does-not-extend', 'a payer-supplied `at` is advisory and MUST NOT extend authorization',
  [{ id: 'a', op: 'authorize', args: { envelope: ENV_EXPIRED, payment: payment({ mandateDigest: DIGEST_EXPIRED, at: '2019-01-01T00:00:00Z' }), now_iso: NOW } }],
  { verdict: 'deny', code: 'expired' });

add('auth-09-bad-alg-refused', 'Ed25519 is the sole legal alg',
  [{ id: 'a', op: 'authorize', args: { envelope: { ...ENV, alg: 'ES256' }, payment: payment(), now_iso: NOW } }],
  { verdict: 'deny', code: 'invalid_signature' });

add('auth-10-unknown-member-refused', 'an unknown mandate member must refuse, not be ignored',
  [{ id: 'a', op: 'mandate_shape', args: { mandate: { ...BASE, extraField: 'x' } } }],
  { ok: false, code: 'invalid_bundle' });

add('auth-11-wildcard-mixed-invalid', '"*" mixed with any other element is INVALID',
  [{ id: 'a', op: 'mandate_shape', args: { mandate: { ...BASE, recipients: ['*', 'merchant.example'] } } }],
  { ok: false, code: 'invalid_bundle' });

add('auth-12-empty-recipients-invalid', 'an empty recipient array fails closed',
  [{ id: 'a', op: 'mandate_shape', args: { mandate: { ...BASE, recipients: [] } } }],
  { ok: false, code: 'invalid_bundle' });

add('auth-13-overflowing-date-invalid', 'a shape-valid but overflowing date must not be leniently normalized',
  [{ id: 'a', op: 'mandate_shape', args: { mandate: { ...BASE, notAfter: '2027-02-30T00:00:00Z' } } }],
  { ok: false, code: 'invalid_bundle' });

add('auth-14-lone-surrogate-purpose-totality', 'a malformed purpose refuses WITHOUT throwing (section 6 totality)',
  [{ id: 'a', op: 'mandate_shape', args: { mandate: { ...BASE, purpose: 'bad\uD800' } } }],
  { ok: false, code: 'invalid_bundle' });

// --- binding (section 7) ---------------------------------------------------
add('bind-01-three-scheme-encodings', 'one B, three renderings: 0x-lowerhex, decimal uint256, UPPERCASE hex',
  [{ id: 'a', op: 'binding', args: { mandateDigest: DIGEST, paymentId: PAYMENT_ID } }],
  { ok: true, node_equals_python: true });

add('bind-02-wrong-payment-id', 'a different paymentId yields a different binding',
  [{ id: 'a', op: 'binding', args: { mandateDigest: DIGEST, paymentId: PAYMENT_ID } },
   { id: 'b', op: 'binding', args: { mandateDigest: DIGEST, paymentId: 'pay-002' } }],
  { a_differs_from_b: true });

add('bind-03-digest-prefix-must-be-retained', 'the sha256: prefix is part of the preimage; stripping it changes B',
  [{ id: 'a', op: 'binding', args: { mandateDigest: DIGEST, paymentId: PAYMENT_ID } },
   { id: 'b', op: 'binding', args: { mandateDigest: DIGEST.replace('sha256:', ''), paymentId: PAYMENT_ID } }],
  { b_refused_or_differs: true });

add('bind-04-out-of-grammar-payment-id', 'a paymentId with an anchor-grammar separator must be refused',
  [{ id: 'a', op: 'binding', args: { mandateDigest: DIGEST, paymentId: 'pay;001' } }],
  { ok: false });

// --- THE LOAD-BEARING PAIR: authority ALLOW, settlement REFUTED ------------
add('split-01-authorized-then-overspent', 'ALLOW pre-settlement, REFUTED post-settlement on AMOUNT',
  [{ id: 'pre', op: 'authorize', args: { envelope: ENV, payment: payment({ amount: '1000' }), now_iso: NOW } },
   { id: 'post', op: 'settle_compare', args: { envelope: ENV, paymentId: PAYMENT_ID, settled: settled({ amount: '900000' }) } }],
  { pre_verdict: 'allow', post_verdict: 'refuted' },
  'The agent was authorized for 1000 and the rail actually moved 900000. The binding slot still matches -- the slot binds (mandate, paymentId) and CANNOT constrain value. This is the whole thesis in two verdicts.');

add('split-02-authorized-then-wrong-recipient', 'ALLOW pre-settlement, REFUTED post-settlement on RECIPIENT',
  [{ id: 'pre', op: 'authorize', args: { envelope: ENV, payment: payment(), now_iso: NOW } },
   { id: 'post', op: 'settle_compare', args: { envelope: ENV, paymentId: PAYMENT_ID, settled: settled({ recipient: 'evil.example' }) } }],
  { pre_verdict: 'allow', post_verdict: 'refuted' });

add('split-03-authorized-and-complied', 'the honest case: ALLOW and COMPLIED',
  [{ id: 'pre', op: 'authorize', args: { envelope: ENV, payment: payment(), now_iso: NOW } },
   { id: 'post', op: 'settle_compare', args: { envelope: ENV, paymentId: PAYMENT_ID, settled: settled() } }],
  { pre_verdict: 'allow', post_verdict: 'complied' });

add('split-04-settled-under-report', 'a smaller COMMITTED amount than the decoded one is a commitment mismatch',
  [{ id: 'post', op: 'settle_compare', args: { envelope: ENV, paymentId: PAYMENT_ID, settled: settled({ amount: '5000' }), committedAmount: '1000' } }],
  { post_verdict: 'refuted', code: 'request_mismatch' });

add('split-05-wrong-binding-slot', 'the slot is read from the settled artifact and must match',
  [{ id: 'post', op: 'settle_compare', args: { envelope: ENV, paymentId: PAYMENT_ID, settled: settled({ slot: '0x' + '00'.repeat(32) }) } }],
  { post_verdict: 'refuted' });

add('split-06-partial-binding-info', 'scheme without slot fails closed, not treated as a sanctioned omission of both',
  [{ id: 'post', op: 'settle_compare', args: { envelope: ENV, paymentId: PAYMENT_ID, settled: (() => { const s = settled(); delete s.slot; return s; })() } }],
  { post_verdict: 'refuted', code: 'malformed_input' });

add('split-07-undefined-scheme-token-refuted', 'the spec defines NO wire token for `scheme`; a plausible reading refutes a COMPLIANT settlement',
  [{ id: 'post', op: 'settle_compare', args: { envelope: ENV, paymentId: PAYMENT_ID, settled: settled({ scheme: 'eip-3009' }) } }],
  { post_verdict: 'refuted', code_unspecified_divergence: ['code'] },
  'FROZEN REPRODUCTION of defect D-3. Everything here is correct -- right mandate, right amount, right recipient, right binding slot -- and the settlement is still refuted, purely because "EIP-3009" from the prose table was written as `eip-3009` instead of the `eip3009` used as an object key in the fixture. Fail-closed is the right behaviour; the missing normative token is the defect. SECOND FACET: the two implementations also disagree on the reason CODE (invalid_proof vs malformed_input) because the spec names neither. The vector therefore asserts only the security-relevant property -- BOTH refute -- and records the code divergence rather than forcing agreement on a value no spec text supports.');

const out = {
  schema: 'stillos-assurance-adversarial-corpus/1',
  generated_from: 'proof/tools/build_corpus.cjs',
  determinism: 'No randomness. Fixed verifier clock ' + NOW + '. Regenerating this file from the same inputs reproduces it byte for byte.',
  reason_code_registry: 'Refusal codes are #3376\'s CLOSED EVC denial-code registry (delegation_invalid, expired, internal_error, invalid_bundle, invalid_proof, invalid_signature, malformed_input, request_mismatch, scope_exceeded, unsupported_version) as read from evcHost.ts isClosedVerdict at the pinned commit -- NOT descriptive names derived from #3220 prose. See PROOF.md defect D-1.',
  signing_keys: 'Mandates are signed with the issuer seed published in x402#3220\'s own authority-vectors.json at the pinned commit. Upstream test material. No StillOS private key appears in this repository.',
  low_bit_probe: LOW_BIT,
  vector_count: V.length,
  vectors: V,
};
fs.writeFileSync(path.join(ROOT, 'proof/corpus/adversarial.json'), JSON.stringify(out, null, 2) + '\n');
console.log(`wrote proof/corpus/adversarial.json -- ${V.length} vectors`);
