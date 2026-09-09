#!/usr/bin/env node
'use strict';
// StillOS post-settlement decode-and-compare verifier (authority.md §6
// "Settled payments" + §13 rule 4). NOT part of the External Verifier
// Contract v1 wire protocol (that boundary is pre-settlement-only, per
// #3376's own scope) -- this is a separate, StillOS-defined CLI for the
// second half of the property authority.md §16/§13 requires: a pre-settlement
// ALLOW is not proof the eventual settlement complied, and this is the check
// that closes that gap by reading amount/recipient/asset out of the actual
// settled artifact, never a presented/claimed field.
//
// stdin:  { "chain": [{mandate,alg,sig}, ...],   // root-first, leaf = operative mandate
//           "paymentId": "...",
//           "settled": {scheme, slot, payer, recipient, asset, amount},  // decoded on-chain artifact
//           "committedAmount"?: "..." }           // optional self-reported/logged amount
// stdout: exactly one JSON object:
//   {"verdict":"SETTLED_OK"}
//   {"verdict":"POST_SETTLEMENT_REFUTED","reasons":[{code,message},...]}
//   {"verdict":"ERROR","code":"malformed_input"|"invalid_bundle"|"internal_error","message":"..."}

const crypto = require('crypto');
const mandateLib = require('../lib/mandate.cjs');
const settleLib = require('../lib/settle.cjs');
const receipt = require('../lib/receipt.cjs');

const POLICY_VERSION = 'stillos-x402-authority-post-settlement-verifier/1';

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
  let out;
  let receiptFields = { verifier_policy: POLICY_VERSION, request_digest: requestDigest };
  try {
    let req;
    try {
      req = JSON.parse(raw.toString('utf8'));
    } catch {
      out = { verdict: 'ERROR', code: 'malformed_input', message: 'stdin is not valid JSON' };
      return finish(out, receiptFields);
    }
    if (!Array.isArray(req.chain) || req.chain.length === 0) {
      out = { verdict: 'ERROR', code: 'invalid_bundle', message: 'chain must be a non-empty array, root-first' };
      return finish(out, receiptFields);
    }
    if (typeof req.paymentId !== 'string' || req.paymentId.length === 0) {
      out = { verdict: 'ERROR', code: 'invalid_bundle', message: 'paymentId must be a non-empty string' };
      return finish(out, receiptFields);
    }
    if (typeof req.settled !== 'object' || req.settled === null) {
      out = { verdict: 'ERROR', code: 'malformed_input', message: 'settled must be an object' };
      return finish(out, receiptFields);
    }

    const chainResult = mandateLib.recoverRootIssuer(req.chain);
    if (!chainResult.ok) {
      out = { verdict: 'ERROR', code: chainResult.code, message: chainResult.message };
      receiptFields.payment_id = req.paymentId;
      return finish(out, receiptFields);
    }
    const leafEnvelope = req.chain[req.chain.length - 1];

    const result = settleLib.verifyPostSettlement(leafEnvelope, req.paymentId, req.settled, req.committedAmount);

    receiptFields = {
      ...receiptFields,
      mandate_digest: chainResult.leafDigest,
      payment_id: req.paymentId,
      scheme: req.settled.scheme,
      binding_slot: req.settled.slot,
      amount: req.settled.amount,
      asset: req.settled.asset,
      payee: req.settled.recipient,
      root_issuer: chainResult.rootIssuer,
      delegation_depth: req.chain.length,
    };
    out = result;
    return finish(out, receiptFields);
  } catch (e) {
    out = { verdict: 'ERROR', code: 'internal_error', message: `verifier threw: ${e && e.message}` };
    return finish(out, receiptFields);
  }
}

function finish(out, receiptFields) {
  try {
    receipt.issue({
      ...receiptFields,
      decision: out.verdict,
      code: out.code,
      detail: out.reasons,
    });
  } catch (e) {
    process.stderr.write(`receipt write failed (non-fatal, verdict still stands): ${e && e.message}\n`);
  }
  process.stdout.write(JSON.stringify(out));
}

main().catch(e => {
  process.stdout.write(JSON.stringify({ verdict: 'ERROR', code: 'internal_error', message: `unhandled: ${e && e.message}` }));
});
