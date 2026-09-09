'use strict';
// StillOS signed authority-decision receipt. Same hash-chain + Ed25519
// pattern as core/decision_log.cjs and core/notary_bond.cjs, applied to this
// verifier's own decisions -- a dedicated keypair, never the production
// Notary signing key (which stays scoped to customer-facing receipts) and
// never the governance-signing key (which stays scoped to StillOS's own
// decision log).
//
// WHAT THIS PROVES: that, at evaluation time, a specific presented evidence
// bundle was checked against a specific mandate/binding/scope, by this
// verifier, at this policy version, and got this decision.
// WHAT THIS DOES NOT PROVE: that the eventual settlement complied (a
// pre-settlement ALLOW is not proof of settlement -- see verifier/*.cjs and
// lib/settle.cjs for the separate post-settlement check), that the mandate's
// issuer is trustworthy, or that delivery/execution happened.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// KEY_FILE/PUB_FILE default to a local, gitignored path so a fresh clone
// generates its own deployment-local signing identity on first run rather
// than writing into this repo's tree. `keys/` (repo root) is a separate,
// frozen record of the StillOS-operated production key this repo's own
// authors publish receipts under -- see keys/README.md -- independent of
// whatever identity a given clone generates for itself.
const DIR = path.join(__dirname, '..', 'state');
const KEY_FILE = process.env.STILLOS_X402_AUTHORITY_KEY_FILE || path.join(DIR, '.secrets', 'signing.key');
const PUB_FILE = path.join(DIR, 'signing-pubkey.pem');
const LEDGER = path.join(DIR, 'receipts.jsonl');
const RECEIPT_VERSION = 'stillos-x402-authority-receipt/1';

function ensureKeypair() {
  if (fs.existsSync(KEY_FILE) && fs.existsSync(PUB_FILE)) return;
  fs.mkdirSync(DIR, { recursive: true });
  fs.mkdirSync(path.dirname(KEY_FILE), { recursive: true });
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(KEY_FILE, privateKey.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
  fs.writeFileSync(PUB_FILE, publicKey.export({ type: 'spki', format: 'pem' }));
}

function loadKeys() {
  ensureKeypair();
  const privateKey = crypto.createPrivateKey(fs.readFileSync(KEY_FILE, 'utf8'));
  const publicKeyPem = fs.readFileSync(PUB_FILE, 'utf8');
  return { privateKey, publicKeyPem };
}

function sha256hex(s) { return crypto.createHash('sha256').update(s).digest('hex'); }

function readEntries() {
  if (!fs.existsSync(LEDGER)) return [];
  return fs.readFileSync(LEDGER, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l));
}

function lastHash() {
  const e = readEntries();
  return e.length ? e[e.length - 1].receipt_hash : 'GENESIS';
}

// fields: {request_digest, mandate_digest, payment_id, scheme, binding_slot,
//   amount, asset, payee, verifier_policy, decision, code, detail?, ts?}
function issue(fields) {
  const { privateKey } = loadKeys();
  const ts = fields.ts || new Date().toISOString();
  const prev_receipt_hash = lastHash();
  const core = { v: RECEIPT_VERSION, ts, prev_receipt_hash, ...fields };
  delete core.ts0; // defensive, never persisted
  const receipt_hash = sha256hex(JSON.stringify(core));
  const signature = crypto.sign(null, Buffer.from(receipt_hash), privateKey).toString('base64');
  const receipt = { ...core, receipt_hash, signature };
  fs.mkdirSync(DIR, { recursive: true });
  fs.appendFileSync(LEDGER, JSON.stringify(receipt) + '\n');
  return receipt;
}

function verifyChain() {
  const { publicKeyPem } = loadKeys();
  const publicKey = crypto.createPublicKey(publicKeyPem);
  const entries = readEntries();
  let prev = 'GENESIS';
  const results = [];
  for (const e of entries) {
    const { receipt_hash, signature, ...core } = e;
    const recomputed = sha256hex(JSON.stringify(core));
    const hashOk = recomputed === receipt_hash;
    const chainOk = core.prev_receipt_hash === prev;
    const sigOk = crypto.verify(null, Buffer.from(receipt_hash), publicKey, Buffer.from(signature, 'base64'));
    results.push({ ts: e.ts, decision: e.decision, code: e.code, hashOk, chainOk, sigOk });
    prev = receipt_hash;
  }
  return results;
}

module.exports = { issue, verifyChain, readEntries, RECEIPT_VERSION, PUB_FILE, LEDGER };
