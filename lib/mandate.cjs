'use strict';
// authority.md §3 (mandate shape), §5 (digest), §12 (delegation narrowing).
// Independent implementation from spec text -- see SOURCE_PINS.md.

const canon = require('./canon.cjs');

const MANDATE_TAG = 'x402-mandate/1\n';
const AMOUNT_RE = /^(0|[1-9][0-9]*)$/;
const TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const PARENT_RE = /^sha256:[0-9a-f]{64}$/;

const MANDATE_FIELDS = new Set([
  'v', 'issuer', 'subject', 'asset', 'cap', 'perPayment', 'recipients',
  'accountant', 'purpose', 'notAfter', 'nonce', 'parent',
]);
const REQUIRED_MANDATE_FIELDS = ['v', 'issuer', 'subject', 'asset', 'cap', 'recipients', 'accountant', 'purpose', 'notAfter', 'nonce'];

// A refusal is {ok:false, code, message}; success is {ok:true}. Never throws
// on a malformed mandate -- §6/§3 totality: refusal verdict, not an
// exception, no matter how bent the input is.
function validateMandateShape(mandate) {
  try {
    if (typeof mandate !== 'object' || mandate === null || Array.isArray(mandate)) {
      return refuse('malformed_input', 'mandate is not an object');
    }
    for (const k of Object.keys(mandate)) {
      if (!MANDATE_FIELDS.has(k)) {
        return refuse('invalid_bundle', `mandate carries an unknown member '${k}' — the object is closed (fail closed on unknown fields)`);
      }
    }
    for (const k of REQUIRED_MANDATE_FIELDS) {
      if (!(k in mandate)) return refuse('invalid_bundle', `mandate missing required field '${k}'`);
    }
    if (mandate.v !== 'x402-mandate/1') {
      return refuse('unsupported_version', `mandate.v must be exactly 'x402-mandate/1', got '${mandate.v}'`);
    }
    if (typeof mandate.issuer !== 'string' || !canon.ED25519_KEY_RE.test(mandate.issuer)) {
      return refuse('invalid_bundle', 'mandate.issuer must be a raw 32-byte Ed25519 public key, base64url, 43 chars');
    }
    if (typeof mandate.subject !== 'string' || mandate.subject.length === 0) {
      return refuse('invalid_bundle', 'mandate.subject must be a non-empty string');
    }
    // Well-formed UTF-16 check across every string field (§3 validity rule).
    for (const field of ['issuer', 'subject', 'asset', 'cap', 'accountant', 'purpose', 'notAfter', 'nonce', 'parent']) {
      const v = mandate[field];
      if (v !== undefined && !canon.isWellFormedUtf16(v)) {
        return refuse('invalid_bundle', `mandate.${field} is not well-formed UTF-16 (unpaired surrogate)`);
      }
    }
    for (const r of mandate.recipients || []) {
      if (!canon.isWellFormedUtf16(r)) return refuse('invalid_bundle', 'a recipients element is not well-formed UTF-16 (unpaired surrogate)');
    }
    if (typeof mandate.cap !== 'string' || !AMOUNT_RE.test(mandate.cap)) {
      return refuse('invalid_bundle', 'mandate.cap must be an integer minor-unit string');
    }
    if (mandate.perPayment !== undefined) {
      if (typeof mandate.perPayment !== 'string' || !AMOUNT_RE.test(mandate.perPayment)) {
        return refuse('invalid_bundle', 'mandate.perPayment must be an integer minor-unit string');
      }
      if (BigInt(mandate.perPayment) > BigInt(mandate.cap)) {
        return refuse('invalid_bundle', 'mandate.perPayment exceeds cap — a per-payment bound above the cumulative cap is incoherent');
      }
    }
    if (!Array.isArray(mandate.recipients) || mandate.recipients.length === 0) {
      return refuse('invalid_bundle', "mandate.recipients is empty — use [ANY_RECIPIENT] for an explicit unconstrained opt-in");
    }
    if (!mandate.recipients.every(r => typeof r === 'string')) {
      return refuse('invalid_bundle', 'mandate.recipients elements must be strings');
    }
    if (mandate.recipients.includes('*') && mandate.recipients.length > 1) {
      return refuse('invalid_bundle', "'*' must be the SOLE element to opt into an unconstrained recipient set");
    }
    if (mandate.accountant !== 'payees' && !canon.ED25519_KEY_RE.test(mandate.accountant)) {
      return refuse('invalid_bundle', "mandate.accountant must be an Ed25519 key or the literal 'payees'");
    }
    if (mandate.accountant === 'payees') {
      for (const r of mandate.recipients) {
        if (r !== '*' && !canon.ED25519_KEY_RE.test(r)) {
          return refuse('invalid_bundle', `under accountant 'payees', recipient '${r}' must itself be an Ed25519 key`);
        }
      }
    }
    if (typeof mandate.notAfter !== 'string' || !TIMESTAMP_RE.test(mandate.notAfter) || !strictTimestampRoundTrips(mandate.notAfter)) {
      return refuse('invalid_bundle', 'mandate.notAfter must be strict RFC 3339 UTC (…Z)');
    }
    if (typeof mandate.nonce !== 'string' || mandate.nonce.length === 0) {
      return refuse('invalid_bundle', 'mandate.nonce must be a non-empty string');
    }
    if (mandate.parent !== undefined && !PARENT_RE.test(mandate.parent)) {
      return refuse('invalid_bundle', 'mandate.parent must match ^sha256:[0-9a-f]{64}$');
    }
    return { ok: true };
  } catch (e) {
    return refuse('internal_error', `shape validation threw: ${e.message}`);
  }
}

// A lenient parser like `new Date('...-02-30...')` normalizes into March —
// this rejects that by requiring the UTC field values to survive unchanged.
function strictTimestampRoundTrips(ts) {
  const m = ts.match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/);
  if (!m) return false;
  const [, y, mo, d, h, mi, s] = m;
  const ms = Date.UTC(+y, +mo - 1, +d, +h, +mi, +s);
  if (!Number.isFinite(ms)) return false;
  const dt = new Date(ms);
  return dt.getUTCFullYear() === +y && dt.getUTCMonth() === +mo - 1 && dt.getUTCDate() === +d &&
    dt.getUTCHours() === +h && dt.getUTCMinutes() === +mi && dt.getUTCSeconds() === +s;
}

function refuse(code, message) { return { ok: false, code, message }; }

function mandateDigest(mandate) {
  return canon.sha256digest(canon.taggedBytes(MANDATE_TAG, mandate));
}

function verifyMandateEnvelope(envelope) {
  if (typeof envelope !== 'object' || envelope === null) return refuse('malformed_input', 'envelope is not an object');
  const { mandate, alg, sig } = envelope;
  if (alg !== 'Ed25519') return refuse('invalid_signature', `alg must be 'Ed25519', got '${alg}'`);
  const shape = validateMandateShape(mandate);
  if (!shape.ok) return shape;
  if (typeof sig !== 'string' || !canon.ED25519_SIG_RE.test(sig)) {
    return refuse('invalid_signature', 'sig must be base64url, 86 chars (raw 64-byte Ed25519 signature)');
  }
  let sigOk;
  try {
    sigOk = canon.verifyEd25519(MANDATE_TAG, mandate, sig, mandate.issuer);
  } catch (e) {
    return refuse('invalid_signature', `signature verification threw: ${e.message}`);
  }
  if (!sigOk) return refuse('invalid_signature', 'mandate signature does not verify against issuer key');
  return { ok: true, digest: mandateDigest(mandate) };
}

// authority.md §12 narrowing rules only, no signature/crypto involved --
// isolated so it's directly testable against unsigned mutated children (the
// vectors' `wideningRefusals` give reasons, not re-signed objects).
function checkNarrowing(child, parentMandate, parentDigest) {
  if (!canon.ED25519_KEY_RE.test(parentMandate.subject)) {
    return refuse('delegation_invalid', "parent's subject is not an Ed25519 key — parent is not delegable");
  }
  if (child.parent !== parentDigest) {
    return refuse('delegation_invalid', 'child.parent does not equal the parent mandateDigest');
  }
  if (child.issuer !== parentMandate.subject) {
    return refuse('delegation_invalid', "child.issuer must equal the parent's subject");
  }
  if (child.asset !== parentMandate.asset) {
    return refuse('delegation_invalid', 'child.asset must equal the parent asset');
  }
  if (child.accountant !== parentMandate.accountant) {
    return refuse('delegation_invalid', 'child.accountant must equal the parent accountant (one accounting domain per chain)');
  }
  if (BigInt(child.cap) > BigInt(parentMandate.cap)) {
    return refuse('delegation_invalid', `refusing a widening delegation: child cap ${child.cap} exceeds parent cap ${parentMandate.cap}`);
  }
  const childPerPayment = child.perPayment !== undefined ? BigInt(child.perPayment) : BigInt(child.cap);
  const parentPerPayment = parentMandate.perPayment !== undefined ? BigInt(parentMandate.perPayment) : BigInt(parentMandate.cap);
  if (childPerPayment > parentPerPayment) {
    return refuse('delegation_invalid', 'refusing a widening delegation: child effective per-payment bound exceeds the parent\'s');
  }
  if (child.notAfter > parentMandate.notAfter) {
    return refuse('delegation_invalid', "refusing a widening delegation: child expiry is later than the parent's");
  }
  const parentIsStar = parentMandate.recipients.length === 1 && parentMandate.recipients[0] === '*';
  const childIsStar = child.recipients.length === 1 && child.recipients[0] === '*';
  if (childIsStar && !parentIsStar) {
    return refuse('delegation_invalid', 'refusing a widening delegation: child cannot opt into ANY_RECIPIENT under a scoped parent');
  }
  if (!parentIsStar) {
    for (const r of child.recipients) {
      if (!parentMandate.recipients.includes(r)) {
        return refuse('delegation_invalid', `refusing a widening delegation: child recipient ${r} is outside the parent scope`);
      }
    }
  }
  return { ok: true };
}

// authority.md §12 -- every bound may only narrow from parent to child.
// Full check: envelope crypto (signature over the child) + narrowing rules.
function verifyDelegation(childEnvelope, parentMandate, parentDigest) {
  const childVerify = verifyMandateEnvelope(childEnvelope);
  if (!childVerify.ok) return childVerify;
  const child = childEnvelope.mandate;
  const narrow = checkNarrowing(child, parentMandate, parentDigest);
  if (!narrow.ok) return narrow;
  return { ok: true, digest: childVerify.digest };
}

// authority.md §12 -- recover the root issuer at any depth, entirely offline.
// `chain` is [{mandate, alg, sig}, ...] (signature envelopes) ordered
// root-first; root MUST have no parent.
function recoverRootIssuer(chain) {
  if (!Array.isArray(chain) || chain.length === 0) return refuse('delegation_invalid', 'empty chain');
  if (typeof chain[0] !== 'object' || chain[0] === null || typeof chain[0].mandate !== 'object' || chain[0].mandate === null) {
    return refuse('invalid_bundle', 'chain[0] is not a valid mandate envelope');
  }
  const root = chain[0].mandate;
  if (root.parent !== undefined) return refuse('delegation_invalid', 'chain root carries a parent — not a root');
  const rootVerify = verifyMandateEnvelope(chain[0]);
  if (!rootVerify.ok) return rootVerify;
  let prevMandate = root;
  let prevDigest = rootVerify.digest;
  for (let i = 1; i < chain.length; i++) {
    if (typeof chain[i] !== 'object' || chain[i] === null || typeof chain[i].mandate !== 'object' || chain[i].mandate === null) {
      return refuse('invalid_bundle', `chain[${i}] is not a valid mandate envelope`);
    }
    const d = verifyDelegation(chain[i], prevMandate, prevDigest);
    if (!d.ok) return d;
    prevMandate = chain[i].mandate;
    prevDigest = d.digest;
  }
  return { ok: true, rootIssuer: root.issuer, leafDigest: prevDigest };
}

module.exports = {
  MANDATE_TAG, AMOUNT_RE, TIMESTAMP_RE,
  validateMandateShape, mandateDigest, verifyMandateEnvelope,
  checkNarrowing, verifyDelegation, recoverRootIssuer, refuse,
};
