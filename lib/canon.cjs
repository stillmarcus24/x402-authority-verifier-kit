'use strict';
// JCS (RFC 8785) canonicalizer + shared crypto/encoding helpers for the
// x402 `authority` extension (x402-foundation/x402#3220). Independent
// implementation from the spec text (interop/x402-authority/vectors/fixtures/authority.md),
// not ported from either PR's code. See docs/interop/x402-authority/SOURCE_PINS.md.

const crypto = require('crypto');

// RFC 8785 4.10: canonical number serialization for this profile is a
// non-issue in practice because authority.md restricts every numeric field
// to integers |n| <= 2^52 signed as decimal strings (§4) -- but the
// canonicalizer itself must still handle a bare JS number correctly for
// defense-in-depth (a caller passing 0 instead of "0"). Node's default
// Number->string round-trips the safe-integer range identically to
// ECMA-262 ToString, which is what JCS requires.
function canonicalize(value) {
  return canonValue(value);
}

function canonValue(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return v ? 'true' : 'false';
  if (t === 'number') {
    if (!Number.isFinite(v)) throw new Error('JCS: non-finite number cannot be canonicalized');
    return String(v);
  }
  if (t === 'string') return JSON.stringify(v);
  if (Array.isArray(v)) return '[' + v.map(canonValue).join(',') + ']';
  if (t === 'object') {
    const keys = Object.keys(v).sort();
    return '{' + keys.map(k => JSON.stringify(k) + ':' + canonValue(v[k])).join(',') + '}';
  }
  throw new Error(`JCS: unsupported value type ${t}`);
}

function sha256hex(bufOrStr) {
  return crypto.createHash('sha256').update(bufOrStr).digest('hex');
}

function sha256digest(bufOrStr) {
  return 'sha256:' + sha256hex(bufOrStr);
}

// UTF8 tag || JCS(object) -- the signable/digestible input for every
// domain-separated construction in §4.
function taggedBytes(tag, obj) {
  return Buffer.from(tag + canonicalize(obj), 'utf8');
}

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

function b64urlToBuf(s) {
  if (!B64URL_RE.test(s)) throw new Error('not valid unpadded base64url');
  let b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return Buffer.from(b64, 'base64');
}

function bufToB64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// authority.md §15: Ed25519 public key = raw 32-byte key, base64url, 43 chars.
const ED25519_KEY_RE = /^[A-Za-z0-9_-]{43}$/;
// authority.md §15: Ed25519 signature = raw 64 bytes, base64url, 86 chars.
const ED25519_SIG_RE = /^[A-Za-z0-9_-]{86}$/;

function rawEd25519PublicKeyToKeyObject(rawB64url) {
  const raw = b64urlToBuf(rawB64url);
  if (raw.length !== 32) throw new Error('Ed25519 public key must decode to 32 bytes');
  // DER SubjectPublicKeyInfo wrapper for a raw Ed25519 public key (RFC 8410).
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  return crypto.createPublicKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'spki' });
}

function rawEd25519PrivateKeyToKeyObject(rawB64url) {
  const raw = b64urlToBuf(rawB64url);
  if (raw.length !== 32) throw new Error('Ed25519 seed must decode to 32 bytes');
  // DER PrivateKeyInfo wrapper for a raw Ed25519 seed (RFC 8410).
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  return crypto.createPrivateKey({ key: Buffer.concat([prefix, raw]), format: 'der', type: 'pkcs8' });
}

function verifyEd25519(tag, obj, sigB64url, pubKeyB64url) {
  if (!ED25519_SIG_RE.test(sigB64url)) return false;
  if (!ED25519_KEY_RE.test(pubKeyB64url)) return false;
  const data = taggedBytes(tag, obj);
  const sig = b64urlToBuf(sigB64url);
  const pub = rawEd25519PublicKeyToKeyObject(pubKeyB64url);
  return crypto.verify(null, data, pub, sig);
}

function signEd25519(tag, obj, privKeyB64url) {
  const data = taggedBytes(tag, obj);
  const priv = rawEd25519PrivateKeyToKeyObject(privKeyB64url);
  const sig = crypto.sign(null, data, priv);
  return bufToB64url(sig);
}

// Well-formed-UTF-16 check per authority.md §3's validity rule -- a value
// with an unpaired surrogate is INVALID. JS strings are UTF-16 code units,
// so this walks for lone surrogates directly rather than round-tripping
// through an encoder.
function isWellFormedUtf16(s) {
  if (typeof s !== 'string') return false;
  if (typeof s.isWellFormed === 'function') return s.isWellFormed();
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const next = s.charCodeAt(i + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) {
      return false;
    }
  }
  return true;
}

module.exports = {
  canonicalize, sha256hex, sha256digest, taggedBytes,
  b64urlToBuf, bufToB64url,
  ED25519_KEY_RE, ED25519_SIG_RE,
  rawEd25519PublicKeyToKeyObject, rawEd25519PrivateKeyToKeyObject,
  verifyEd25519, signEd25519,
  isWellFormedUtf16,
};
