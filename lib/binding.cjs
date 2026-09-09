'use strict';
// authority.md §7 -- the preimage binding, and its 3 per-scheme encodings.
// B = SHA-256("x402-mandate-binding/1\n" || UTF8(mandateDigest || "\n" || paymentId))
// mandateDigest MUST retain its literal lowercase "sha256:" prefix in the
// preimage -- stripping to bare hex yields a different (wrong) B.

const crypto = require('crypto');

const PAYMENT_ID_RE = /^[A-Za-z0-9._~-]{1,64}$/;
const MANDATE_DIGEST_RE = /^sha256:[0-9a-f]{64}$/;

function computeBinding(mandateDigest, paymentId) {
  if (!MANDATE_DIGEST_RE.test(mandateDigest)) {
    throw new Error('computeBinding: mandateDigest must be the full 71-char "sha256:"-prefixed form');
  }
  if (!PAYMENT_ID_RE.test(paymentId)) {
    throw new Error('computeBinding: paymentId out of grammar, refusing to derive/verify a binding');
  }
  const preimage = Buffer.from(mandateDigest + '\n' + paymentId, 'utf8');
  const tag = Buffer.from('x402-mandate-binding/1\n', 'utf8');
  return crypto.createHash('sha256').update(Buffer.concat([tag, preimage])).digest(); // raw 32 bytes
}

function encodeEip3009(bRaw) {
  return '0x' + bRaw.toString('hex'); // lowercase
}

function encodePermit2(bRaw) {
  // Big-endian unsigned 256-bit integer, decimal, no leading zeros/sign.
  return BigInt('0x' + bRaw.toString('hex')).toString(10);
}

function encodeXrpl(bRaw) {
  return bRaw.toString('hex').toUpperCase();
}

function computeAllEncodings(mandateDigest, paymentId) {
  const b = computeBinding(mandateDigest, paymentId);
  return {
    raw: b,
    eip3009: encodeEip3009(b),
    permit2: encodePermit2(b),
    xrpl: encodeXrpl(b),
  };
}

// Verify a presented/settled scheme slot value against the derived binding
// for one scheme. Returns boolean; never throws on a malformed slot (that's
// a verifier-input concern handled by the caller, per §6 totality).
function verifySlot(scheme, mandateDigest, paymentId, slotValue) {
  const enc = computeAllEncodings(mandateDigest, paymentId);
  switch (scheme) {
    case 'eip3009': return typeof slotValue === 'string' && slotValue.toLowerCase() === enc.eip3009;
    case 'permit2': return typeof slotValue === 'string' && slotValue === enc.permit2;
    case 'xrpl': return typeof slotValue === 'string' && slotValue.toUpperCase() === slotValue && slotValue === enc.xrpl;
    default: return false;
  }
}

module.exports = { PAYMENT_ID_RE, MANDATE_DIGEST_RE, computeBinding, computeAllEncodings, verifySlot };
