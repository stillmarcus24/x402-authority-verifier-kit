#!/usr/bin/env node
'use strict';
// ============================================================================
// IMPLEMENTATION A -- Node.js, standard library only (`node:crypto`).
//
// Written from the normative specification text, NOT ported from any other
// implementation in this repository. It deliberately does NOT require
// ../../lib/*.cjs: implementations A and B share fixture FILES, never
// algorithm CODE. See proof/PROOF.md "What 'independent' means here".
//
// Normative sources (pinned in proof/SOURCE_PINS.json):
//   [S1] x402#3220 authority.md  -- mandate shape, JCS digest, binding,
//        pre-settlement authorization, post-settlement decode-and-compare.
//   [S2] x402#3376              -- EVC closed-verdict wire shape.
//   [S3] vauban-org/x402-starknet docs/stark-receipt-profile-v0.1.md
//        §2.1 {alg,enc,hex} triple, §2.2 canonical rendering,
//        §4.1 v3 preimage shape, §4.2 digest limbs, §4.3 refusals F1-F4,
//        §4.5 v2/v3 separation, §4.6 BASE_SETTLEMENT_V1, §5 verdicts.
//   [S4] STILLOS_NOTARY_RECEIPT_V1.md -- frozen receipt preimage + digest.
//   [S5] RFC 8785 (JCS), RFC 8032 (Ed25519), FIPS 180-4 (SHA-256).
// ============================================================================

const crypto = require('crypto');

// ---------------------------------------------------------------------------
// RFC 8785 JCS  [S5]
// ---------------------------------------------------------------------------

// RFC 8785 §3.2.3: object members are sorted by their keys as sequences of
// UTF-16 code units. That is NOT the same as sorting by Unicode code point:
// an astral character encodes to a surrogate pair (0xD800-0xDFFF) and
// therefore sorts BEFORE U+E000..U+FFFF under UTF-16, and AFTER them under
// code-point ordering. JS strings ARE UTF-16 code-unit sequences, so the
// default `<` comparison is already correct here -- but we compare explicitly
// so the rule is legible and so implementation B can be checked against it.
function utf16Units(s) {
  const out = [];
  for (let i = 0; i < s.length; i++) out.push(s.charCodeAt(i));
  return out;
}

function compareUtf16(a, b) {
  const ua = utf16Units(a), ub = utf16Units(b);
  const n = Math.min(ua.length, ub.length);
  for (let i = 0; i < n; i++) {
    if (ua[i] !== ub[i]) return ua[i] < ub[i] ? -1 : 1;
  }
  if (ua.length === ub.length) return 0;
  return ua.length < ub.length ? -1 : 1;
}

// RFC 8785 §3.2.2.2 string escaping (the ECMAScript JSON.stringify rules).
const ESCAPES = { 0x08: '\\b', 0x09: '\\t', 0x0a: '\\n', 0x0c: '\\f', 0x0d: '\\r', 0x22: '\\"', 0x5c: '\\\\' };

function jcsString(s) {
  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (ESCAPES[c] !== undefined) out += ESCAPES[c];
    else if (c < 0x20) out += '\\u' + c.toString(16).padStart(4, '0');
    else out += s[i];
  }
  return out + '"';
}

class JcsError extends Error {}

function jcs(value) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'string') {
    // A lone surrogate cannot be encoded to UTF-8; JCS output is UTF-8 bytes.
    if (!isWellFormedUtf16(value)) throw new JcsError('jcs_lone_surrogate');
    return jcsString(value);
  }
  if (t === 'number') {
    if (!Number.isFinite(value)) throw new JcsError('jcs_non_finite_number');
    // SCOPE CUT, stated not hidden: RFC 8785 §3.2.2.3 requires ECMAScript
    // Number->String (Ryu shortest round-trip) for non-integers. Every numeric
    // field in [S1] §4 and [S3] §4.6 is carried as a decimal STRING precisely
    // to avoid this, so non-integer numbers are refused rather than
    // approximated. Implementation B refuses identically. Declared NOT TESTED
    // in PROOF.md rather than claimed.
    if (!Number.isInteger(value)) throw new JcsError('jcs_non_integer_number_out_of_profile');
    if (!Number.isSafeInteger(value)) throw new JcsError('jcs_unsafe_integer');
    return String(value);
  }
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(value).sort(compareUtf16);
    return '{' + keys.map(k => jcsString(k) + ':' + jcs(value[k])).join(',') + '}';
  }
  throw new JcsError('jcs_unsupported_type_' + t);
}

function isWellFormedUtf16(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const n = s.charCodeAt(i + 1);
      if (Number.isNaN(n) || n < 0xdc00 || n > 0xdfff) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

const sha256hex = (b) => crypto.createHash('sha256').update(b).digest('hex');

// ---------------------------------------------------------------------------
// Ed25519 verification via node:crypto (OpenSSL).
// Implementation B uses a from-scratch RFC 8032 implementation instead, so the
// differential test crosses two unrelated crypto stacks, not two callers of
// the same one.
// ---------------------------------------------------------------------------

function rawPubFromPem(pem) {
  const b64 = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, '').replace(/\s+/g, '');
  const der = Buffer.from(b64, 'base64');
  // RFC 8410 SubjectPublicKeyInfo for Ed25519 is a fixed 44-byte DER: a
  // 12-byte prefix then the raw 32-byte key.
  if (der.length !== 44) throw new Error('unexpected_spki_length_' + der.length);
  return der.subarray(12);
}

function ed25519VerifyRaw(msgBuf, sigBuf, rawPub32) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  const key = crypto.createPublicKey({
    key: Buffer.concat([prefix, rawPub32]), format: 'der', type: 'spki',
  });
  return crypto.verify(null, msgBuf, key, sigBuf);
}

// ---------------------------------------------------------------------------
// STILLOS_NOTARY_RECEIPT_V1  [S4]
// ---------------------------------------------------------------------------
// Preimage: exactly these fields in exactly this order. `resolver_hash` is
// OMITTED ENTIRELY (not null) on a claim receipt -- 5 fields; present on a
// verdict receipt -- 6 fields. Canonicalization is compact JSON in this fixed
// field order, which is NOT JCS: JCS would sort the keys alphabetically and
// produce a different digest. Both implementations therefore build the string
// positionally.
const NOTARY_FIELD_ORDER = ['agent', 'claim_sha256', 'ts', 'prev_hash', 'notary_fp', 'resolver_hash'];

function notaryPreimage(receipt) {
  const parts = [];
  for (const f of NOTARY_FIELD_ORDER) {
    if (f === 'resolver_hash' && receipt.resolver_hash === undefined) continue;
    if (receipt[f] === undefined) throw new Error('notary_missing_field_' + f);
    parts.push(jcsString(f) + ':' + jcs(receipt[f]));
  }
  return '{' + parts.join(',') + '}';
}

function notaryVerify(receipt, rawPub32) {
  const preimage = notaryPreimage(receipt);
  const computed = sha256hex(Buffer.from(preimage, 'utf8'));
  const hashOk = computed === receipt.receipt_hash;
  let sigOk = false, sigError = null;
  try {
    // [S4]: the signature is over the UTF-8 bytes of the 64-char hex STRING,
    // NOT over the 32 raw digest bytes.
    sigOk = ed25519VerifyRaw(
      Buffer.from(receipt.receipt_hash, 'utf8'),
      Buffer.from(receipt.signature, 'base64'),
      rawPub32);
  } catch (e) { sigError = String(e.message || e); }
  return {
    preimage,
    field_count: preimage === '{}' ? 0 : (preimage.match(/","/g) || []).length + 1,
    computed_hash: computed,
    hash_ok: hashOk,
    sig_ok: sigOk,
    sig_error: sigError,
  };
}

// ---------------------------------------------------------------------------
// Vauban §2.1 digest triple {alg, enc, hex}  [S3]
// ---------------------------------------------------------------------------
const KNOWN_ALG = new Set(['sha-256', 'keccak-256', 'poseidon-252', 'blake2s-256']);
const KNOWN_ENC = new Set(['none', 'felt252-masked-251']);
const MASK_251 = (1n << 251n) - 1n;

function digestTriple(t) {
  if (t === null || typeof t !== 'object' || Array.isArray(t)) return { valid: false, error: 'not_an_object' };
  if (t.alg === undefined) return { valid: false, error: 'missing_alg' };
  // §2.1: "A digest without `enc` is invalid, not defaulted."
  if (t.enc === undefined) return { valid: false, error: 'missing_enc' };
  if (t.hex === undefined) return { valid: false, error: 'missing_hex' };
  if (!KNOWN_ALG.has(t.alg)) return { valid: false, error: 'unknown_alg' };
  if (!KNOWN_ENC.has(t.enc)) return { valid: false, error: 'unknown_enc' };
  if (typeof t.hex !== 'string') return { valid: false, error: 'hex_not_a_string' };
  const bare = t.hex.startsWith('0x') || t.hex.startsWith('0X') ? t.hex.slice(2) : t.hex;
  if (!/^[0-9a-fA-F]*$/.test(bare) || bare.length === 0) return { valid: false, error: 'hex_not_hex' };
  if (bare.length !== 64) return { valid: false, error: 'bad_hex_length' };
  if (bare !== bare.toLowerCase()) return { valid: false, error: 'hex_not_lowercase' };

  const D = BigInt('0x' + bare);
  const stored = t.enc === 'felt252-masked-251' ? (D & MASK_251) : D;
  const top5 = Number(D >> 251n);
  return {
    valid: true,
    alg: t.alg,
    enc: t.enc,
    full_hex: '0x' + bare,
    // §2.2 canonical rendering: lowercase, 0x, no leading zero. Compared as
    // integers, rendered in one form.
    comparison_hex: '0x' + stored.toString(16),
    comparison_decimal: stored.toString(10),
    top5bits: top5,
    masking_is_noop: stored === D,
    full_equals_stored: stored === D,
  };
}

// §4.2 -- digest limbs, low then high, lossless, enc:"none".
function digestLimbs(hex64) {
  const bare = hex64.startsWith('0x') ? hex64.slice(2) : hex64;
  if (!/^[0-9a-f]{64}$/.test(bare)) throw new Error('expected_64_lowercase_hex');
  const D = BigInt('0x' + bare);
  const TWO128 = 1n << 128n;
  const lo = D % TWO128;
  const hi = D / TWO128;
  if (hi !== (D >> 128n)) throw new Error('limb_derivation_disagreement');
  return {
    digest_D_decimal: D.toString(10),
    digest_lo: lo.toString(10), digest_hi: hi.toString(10),
    digest_lo_hex: '0x' + lo.toString(16), digest_hi_hex: '0x' + hi.toString(16),
  };
}

function limbsToHex(loStr, hiStr) {
  const TWO128 = 1n << 128n;
  const lo = BigInt(loStr), hi = BigInt(hiStr);
  if (lo < 0n || lo >= TWO128) throw new Error('digest_lo_out_of_u128_range');
  if (hi < 0n || hi >= TWO128) throw new Error('digest_hi_out_of_u128_range');
  return (hi * TWO128 + lo).toString(16).padStart(64, '0');
}

// §4.1 origin_tag: Cairo short string, at most 31 ASCII bytes packed in a felt252.
function originTagFelt(tag) {
  if (typeof tag !== 'string') return { ok: false, error: 'tag_not_a_string' };
  const bytes = Buffer.from(tag, 'utf8');
  if (bytes.length > 31) return { ok: false, error: 'tag_over_31_bytes' };
  for (const b of bytes) if (b > 0x7f) return { ok: false, error: 'tag_not_ascii' };
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return { ok: true, felt_decimal: v.toString(10), felt_hex: '0x' + v.toString(16), byte_length: bytes.length };
}

// §4.3 the four named refusals + the two settled edge cases. A refusal names
// the constraint, never "a constraint failed".
function v3BatchCheck(K, leaves) {
  const refusals = [];
  if (!Array.isArray(leaves)) return { provable: false, refusals: ['MALFORMED_LEAVES'] };
  const F = leaves.length;
  if (F > 64) refusals.push('F4');                       // more than 64 leaves
  if (K === 0 && F === 0) refusals.push('K0F0');         // commits nothing
  const seen = new Set();
  leaves.forEach((lf, i) => {
    const tag = originTagFelt(lf.origin_tag);
    if (!tag.ok || tag.felt_decimal === '0') refusals.push(`F1@${i}`);   // empty/absent label
    const lo = BigInt(lf.digest_lo || '0'), hi = BigInt(lf.digest_hi || '0');
    if (lo === 0n && hi === 0n) refusals.push(`F2@${i}`);                // zero digest
    const key = `${lf.origin_tag}|${lf.digest_lo}|${lf.digest_hi}`;
    if (seen.has(key)) refusals.push(`F3@${i}`);                          // duplicate TRIPLE
    seen.add(key);
  });
  return {
    provable: refusals.length === 0,
    refusals,
    K, F,
    // §4.5: a v3 batch is not a v2 batch even at F=0.
    root_domain_tag: 'VZKPAY_AGGROOT_V3',
    pure_leaf_batch: K === 0 && F >= 1,   // legal per §4.3
  };
}

// §4.6 BASE_SETTLEMENT_V1 -- SHA-256 over the JCS form of exactly seven fields.
const BASE_SETTLEMENT_FIELDS = ['amount', 'asset', 'network', 'payTo', 'payer', 'resource', 'transaction'];
const BASE_SETTLEMENT_HEX_FIELDS = ['asset', 'payTo', 'payer', 'transaction'];

function baseSettlementV1(obj) {
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) return { valid: false, error: 'not_an_object' };
  const keys = Object.keys(obj);
  // "...of seven fields, and of nothing else".
  for (const f of BASE_SETTLEMENT_FIELDS) if (!(f in obj)) return { valid: false, error: 'missing_field_' + f };
  for (const k of keys) if (!BASE_SETTLEMENT_FIELDS.includes(k)) return { valid: false, error: 'unknown_field_' + k };
  // "The values are STRINGS".
  for (const f of BASE_SETTLEMENT_FIELDS) if (typeof obj[f] !== 'string') return { valid: false, error: 'field_not_a_string_' + f };
  // "`amount` is decimal, in the asset's smallest unit".
  if (!/^(0|[1-9][0-9]*)$/.test(obj.amount)) return { valid: false, error: 'amount_not_canonical_decimal' };
  // "The four hex fields are lowercase". The profile does not enumerate which
  // four; asset/payTo/payer/transaction are the only hex-valued ones, so that
  // reading is recorded here explicitly and flagged as an inference in PROOF.md.
  for (const f of BASE_SETTLEMENT_HEX_FIELDS) {
    if (!/^0x[0-9a-f]+$/.test(obj[f])) return { valid: false, error: 'hex_field_not_lowercase_0x_' + f };
  }
  // "`network` keeps its case, a CAIP-2 reference being case-sensitive".
  if (!/^[-a-zA-Z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$/.test(obj.network)) return { valid: false, error: 'network_not_caip2' };
  const canonical = jcs(obj);
  return { valid: true, jcs: canonical, digest_hex: sha256hex(Buffer.from(canonical, 'utf8')) };
}

// ---------------------------------------------------------------------------
// x402#3220 authority -- mandate digest, binding, authorize, settle  [S1]
// ---------------------------------------------------------------------------
// These four constructions are NOT re-derived here. Implementation A's
// authority half is the kit's existing `lib/`, which already reproduces
// #3220's own `authority-vectors.json` 39/39 at the pinned upstream commit
// (see ../../docs/SOURCE_PINS.md). Re-guessing normative constants that are
// already conformance-checked would weaken the differential test, not
// strengthen it: the point of implementation B is to disagree with a
// VALIDATED reference, not with a fresh second guess.
//
// Implementation B (proof/impl-py/assurance.py) implements §3/§5/§6/§7 from
// the spec text independently, and the differential harness compares B
// against these.
const libMandate = require('../../lib/mandate.cjs');
const libBinding = require('../../lib/binding.cjs');
const libAuthorize = require('../../lib/authorize.cjs');
const libSettle = require('../../lib/settle.cjs');

// ---------------------------------------------------------------------------
// Uniform op dispatch -- the differential harness drives A and B through this
// identical interface, so a divergence is a real disagreement and not an
// artefact of two different call shapes.
// ---------------------------------------------------------------------------
const OPS = {
  jcs: (a) => {
    try { const c = jcs(a.value); return { ok: true, canonical: c, sha256: sha256hex(Buffer.from(c, 'utf8')) }; }
    catch (e) { return { ok: false, error: e instanceof JcsError ? e.message : 'jcs_error' }; }
  },
  notary_receipt: (a) => {
    try {
      const raw = a.pubkey_pem ? rawPubFromPem(a.pubkey_pem) : Buffer.from(a.pubkey_hex, 'hex');
      return { ok: true, ...notaryVerify(a.receipt, raw) };
    } catch (e) { return { ok: false, error: String(e.message || e) }; }
  },
  digest_triple: (a) => digestTriple(a.triple),
  digest_limbs: (a) => { try { return { ok: true, ...digestLimbs(a.hex) }; } catch (e) { return { ok: false, error: String(e.message || e) }; } },
  limbs_to_hex: (a) => { try { return { ok: true, hex: limbsToHex(a.digest_lo, a.digest_hi) }; } catch (e) { return { ok: false, error: String(e.message || e) }; } },
  origin_tag: (a) => originTagFelt(a.origin_tag),
  v3_batch: (a) => v3BatchCheck(a.K, a.leaves),
  base_settlement_v1: (a) => { try { return baseSettlementV1(a.fields); } catch (e) { return { valid: false, error: String(e.message || e) }; } },
  // --- authority ops, answered by the kit's already-conformant lib/ ---
  // Only the fields both implementations must agree on are surfaced. Human
  // -readable `message` strings are deliberately NOT compared: two
  // implementations agreeing on a verdict and a reason CODE is the property
  // that matters; agreeing on prose would be testing a coincidence.
  mandate_shape: (a) => {
    const r = libMandate.validateMandateShape(a.mandate);
    return { ok: !!r.ok, code: r.ok ? null : r.code };
  },
  mandate_digest: (a) => {
    const r = libMandate.validateMandateShape(a.mandate);
    if (!r.ok) return { ok: false, code: r.code };
    try { return { ok: true, digest: libMandate.mandateDigest(a.mandate) }; }
    catch (e) { return { ok: false, code: 'malformed_input' }; }
  },
  binding: (a) => {
    try {
      const enc = libBinding.computeAllEncodings(a.mandateDigest, a.paymentId);
      return { ok: true, eip3009: enc.eip3009, permit2: enc.permit2, xrpl: enc.xrpl };
    } catch (e) {
      // Compare a CODE, never prose: two implementations agreeing on an error
      // MESSAGE would be testing a coincidence of wording.
      return { ok: false, error: 'malformed_input' };
    }
  },
  authorize: (a) => {
    const r = libAuthorize.authorizePayment(a.envelope, a.payment, a.now_iso);
    return { verdict: r.ok ? 'allow' : 'deny', code: r.ok ? null : r.code };
  },
  settle_compare: (a) => {
    // verifyPostSettlement returns {verdict:'SETTLED_OK'|'POST_SETTLEMENT_REFUTED',
    // reasons:[{code,...}]} -- NOT {ok, code}. Reading it as {ok, code} silently
    // turned every compliant settlement into a refusal. Found by the
    // differential run, recorded in PROOF.md as defect D-2.
    const r = libSettle.verifyPostSettlement(a.envelope, a.paymentId, a.settled, a.committedAmount);
    const complied = r.verdict === 'SETTLED_OK';
    return {
      verdict: complied ? 'complied' : 'refuted',
      // The spec permits several independent reasons to fail at once; both
      // implementations report the FIRST in evaluation order.
      code: complied ? null : ((r.reasons && r.reasons[0] && r.reasons[0].code) || 'malformed_input'),
    };
  },
};

function runOps(ops) {
  return ops.map((o) => {
    const fn = OPS[o.op];
    if (!fn) return { id: o.id, error: 'unknown_op_' + o.op };
    let res;
    try { res = fn(o.args || {}); } catch (e) { res = { fatal: String(e.message || e) }; }
    return { id: o.id, op: o.op, result: res };
  });
}

if (require.main === module) {
  const fs = require('fs');
  const input = JSON.parse(fs.readFileSync(process.argv[2] === '-' || !process.argv[2] ? 0 : process.argv[2], 'utf8'));
  const ops = Array.isArray(input) ? input : (input.ops || [input]);
  process.stdout.write(JSON.stringify({ impl: 'node', results: runOps(ops) }) + '\n');
}

module.exports = {
  jcs, sha256hex, compareUtf16, isWellFormedUtf16, jcsString,
  notaryPreimage, notaryVerify, rawPubFromPem, ed25519VerifyRaw,
  digestTriple, digestLimbs, limbsToHex, originTagFelt, v3BatchCheck, baseSettlementV1,
  BASE_SETTLEMENT_FIELDS, MASK_251, runOps, OPS,
};
