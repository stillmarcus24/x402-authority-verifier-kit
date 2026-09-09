#!/usr/bin/env node
'use strict';
// StillOS EVC verifier for x402-foundation/x402#3376's `authorization-evidence`
// extension, evaluating the `authority` mandate model from
// x402-foundation/x402#3220. Independent implementation from spec text, not
// a port of either PR's code (see docs/interop/x402-authority/SOURCE_PINS.md).
//
// Contract: External Verifier Contract v1 (github.com/bolyra/bolyra) --
// exactly one JSON request on stdin, exactly one closed JSON verdict on
// stdout, non-zero-byte stdout ELSE, never call a StillOS hosted service to
// decide, never throw uncaught (every path resolves to a stdout verdict).
//
// Evidence bundle format (STILLOS_EVIDENCE_BUNDLE/1, this verifier's own
// design -- #3376 deliberately leaves the bundle contents to the verifier):
//   { "v": "stillos-evidence-bundle/1",
//     "chain": [ {mandate, alg, sig}, ... ],  // root-first, length >= 1
//     "paymentId": "..." }
// The chain's LAST element is the operative (leaf) mandate authorizing this
// payment; a length-1 chain is an unde legated grant. Every hop is checked
// for §12 narrowing; the root's issuer is the human-rooted origin.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const mandateLib = require('../lib/mandate.cjs');
const authorizeLib = require('../lib/authorize.cjs');
const receipt = require('../lib/receipt.cjs');

const POLICY_VERSION = 'stillos-x402-authority-evc-verifier/1';
const TRUSTED_ISSUERS_FILE = path.join(__dirname, '..', 'state', 'trusted-issuers.json');

function loadTrustedIssuers() {
  if (!fs.existsSync(TRUSTED_ISSUERS_FILE)) return null; // null = not enforced (documented gap, see CROSS_IMPLEMENTATION_REPORT.md)
  try {
    const list = JSON.parse(fs.readFileSync(TRUSTED_ISSUERS_FILE, 'utf8'));
    return Array.isArray(list) ? list : null;
  } catch {
    return null;
  }
}

function deny(code, message, detail, kind) {
  const out = { verdict: 'deny', code, message };
  if (kind) out.kind = kind;
  if (detail !== undefined) out.detail = detail;
  return out;
}

function allow(kind) {
  const out = { verdict: 'allow' };
  if (kind) out.kind = kind;
  return out;
}

function readStdin() {
  return new Promise((resolve, reject) => {
    const chunks = [];
    process.stdin.on('data', c => chunks.push(c));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks)));
    process.stdin.on('error', reject);
  });
}

async function main() {
  const raw = await readStdin();
  const requestDigest = 'sha256:' + crypto.createHash('sha256').update(raw).digest('hex');
  let verdict;
  let receiptFields = { verifier_policy: POLICY_VERSION, request_digest: requestDigest };

  try {
    let req;
    try {
      req = JSON.parse(raw.toString('utf8'));
    } catch {
      verdict = deny('malformed_input', 'stdin is not valid JSON');
      return finish(verdict, receiptFields);
    }

    if (req.version !== 1) {
      verdict = deny('unsupported_version', `request.version must be 1, got ${JSON.stringify(req.version)}`);
      return finish(verdict, receiptFields);
    }
    if (typeof req.bundle !== 'string' || req.bundle.length === 0) {
      verdict = deny('invalid_bundle', 'request.bundle must be a non-empty string');
      return finish(verdict, receiptFields);
    }
    const evc = req.x402_evc;
    if (typeof evc !== 'object' || evc === null) {
      verdict = deny('malformed_input', 'request.x402_evc missing or not an object');
      return finish(verdict, receiptFields);
    }
    for (const f of ['amount', 'asset', 'payee']) {
      if (typeof evc[f] !== 'string' || evc[f].length === 0) {
        verdict = deny('malformed_input', `request.x402_evc.${f} missing or not a non-empty string`);
        return finish(verdict, receiptFields);
      }
    }
    if (typeof req.now_unix !== 'number' || !Number.isFinite(req.now_unix)) {
      verdict = deny('malformed_input', 'request.now_unix missing or not a number');
      return finish(verdict, receiptFields);
    }

    let bundle;
    try {
      bundle = JSON.parse(req.bundle);
    } catch {
      verdict = deny('invalid_bundle', 'request.bundle is not valid JSON');
      return finish(verdict, receiptFields);
    }
    if (bundle.v !== 'stillos-evidence-bundle/1') {
      verdict = deny('unsupported_version', `bundle.v must be 'stillos-evidence-bundle/1', got ${JSON.stringify(bundle.v)}`);
      return finish(verdict, receiptFields);
    }
    if (!Array.isArray(bundle.chain) || bundle.chain.length === 0) {
      verdict = deny('invalid_bundle', 'bundle.chain must be a non-empty array, root-first');
      return finish(verdict, receiptFields);
    }
    if (typeof bundle.paymentId !== 'string' || bundle.paymentId.length === 0) {
      verdict = deny('invalid_bundle', 'bundle.paymentId must be a non-empty string');
      return finish(verdict, receiptFields);
    }

    const chainResult = mandateLib.recoverRootIssuer(bundle.chain);
    if (!chainResult.ok) {
      verdict = deny(chainResult.code, chainResult.message);
      receiptFields.payment_id = bundle.paymentId;
      return finish(verdict, receiptFields);
    }

    const trusted = loadTrustedIssuers();
    if (trusted !== null && !trusted.includes(chainResult.rootIssuer)) {
      verdict = deny('untrusted_root', `root issuer ${chainResult.rootIssuer} is not in the configured trusted-issuers list`);
      receiptFields.payment_id = bundle.paymentId;
      return finish(verdict, receiptFields);
    }

    const leafEnvelope = bundle.chain[bundle.chain.length - 1];
    const paymentBinding = evc.payment || {};
    const payment = {
      payer: leafEnvelope.mandate && leafEnvelope.mandate.subject,
      recipient: evc.payee,
      asset: evc.asset,
      amount: evc.amount,
      mandateDigest: chainResult.leafDigest,
      paymentId: bundle.paymentId,
    };
    if (typeof paymentBinding.scheme === 'string') payment.scheme = paymentBinding.scheme;
    if (typeof paymentBinding.binding_slot === 'string') payment.bindingSlot = paymentBinding.binding_slot;
    if (typeof paymentBinding.payment_id === 'string' && paymentBinding.payment_id !== bundle.paymentId) {
      verdict = deny('request_mismatch', 'x402_evc.payment.payment_id disagrees with bundle.paymentId');
      receiptFields.payment_id = bundle.paymentId;
      return finish(verdict, receiptFields);
    }

    const clockNowIso = new Date(req.now_unix * 1000).toISOString();
    const result = authorizeLib.authorizePayment(leafEnvelope, payment, clockNowIso);

    receiptFields = {
      ...receiptFields,
      mandate_digest: chainResult.leafDigest,
      payment_id: bundle.paymentId,
      scheme: payment.scheme,
      binding_slot: payment.bindingSlot,
      amount: evc.amount,
      asset: evc.asset,
      payee: evc.payee,
      root_issuer: chainResult.rootIssuer,
      delegation_depth: bundle.chain.length,
    };

    if (result.ok) {
      verdict = allow('classical');
    } else {
      verdict = deny(result.code, result.message, undefined, 'classical');
    }
    return finish(verdict, receiptFields);
  } catch (e) {
    verdict = deny('internal_error', `verifier threw: ${e && e.message}`);
    return finish(verdict, receiptFields);
  }
}

function finish(verdict, receiptFields) {
  try {
    receipt.issue({
      ...receiptFields,
      decision: verdict.verdict,
      code: verdict.code,
      detail: verdict.detail,
    });
  } catch (e) {
    process.stderr.write(`receipt write failed (non-fatal, verdict still stands): ${e && e.message}\n`);
  }
  process.stdout.write(JSON.stringify(verdict));
}

main().catch(e => {
  process.stdout.write(JSON.stringify(deny('internal_error', `unhandled: ${e && e.message}`)));
});
