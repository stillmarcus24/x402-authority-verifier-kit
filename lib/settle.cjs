'use strict';
// authority.md §6 "Settled payments" rule + §13 rule 4 (BINDING) + §16's
// settledUnderReport scenario: the preimage binding (§7) proves WHICH
// (mandate, paymentId) a settlement commits to; it does NOT constrain the
// transferred amount/recipient/asset. Those MUST be decoded from the
// settled artifact and compared back to the mandate/committed entry.
// Two genuinely distinct checks, kept separate per the spec's own framing:
//   (a) commitment-mismatch: committed/self-reported entry vs. settled artifact
//   (b) decoded-amount: settled artifact vs. the mandate's own bound (cap/perPayment)
// A payment that cleared pre-settlement authorization but fails either of
// these post-settlement checks is POST_SETTLEMENT_REFUTED, not silently
// re-litigated as "was never authorized" -- the pre-settlement ALLOW was a
// true statement about the presented evidence at that time (§13).

const mandate = require('./mandate.cjs');
const binding = require('./binding.cjs');

// settled: {scheme, slot, payer, recipient, asset, amount} -- every field
// decoded from the actual on-chain/settlement artifact, NEVER from a
// presented/claimed object.
function verifySettledSlot(settled, mandateDigestStr, paymentId) {
  if (typeof settled !== 'object' || settled === null) {
    return mandate.refuse('malformed_input', 'settled artifact is not an object');
  }
  for (const f of ['scheme', 'slot', 'payer', 'recipient', 'asset', 'amount']) {
    if (typeof settled[f] !== 'string' || settled[f].length === 0) {
      return mandate.refuse('malformed_input', `settled.${f} missing or not a non-empty string`);
    }
  }
  let slotOk;
  try {
    slotOk = binding.verifySlot(settled.scheme, mandateDigestStr, paymentId, settled.slot);
  } catch (e) {
    return mandate.refuse('invalid_proof', `binding check threw: ${e.message}`);
  }
  if (!slotOk) {
    return mandate.refuse('invalid_proof', 'settled slot does not equal the derived (mandate, paymentId) binding');
  }
  return { ok: true };
}

// Rule (a): commitment mismatch. `committedAmount` is whatever the agent
// self-reported/logged (a spend-log entry, an accountant-committed head
// total delta, etc.) for this same paymentId.
function checkCommitmentMatch(committedAmount, settledAmount) {
  if (!mandate.AMOUNT_RE.test(String(committedAmount)) || !mandate.AMOUNT_RE.test(String(settledAmount))) {
    return mandate.refuse('malformed_input', 'committedAmount/settledAmount must be integer minor-unit strings');
  }
  if (BigInt(committedAmount) !== BigInt(settledAmount)) {
    return mandate.refuse('request_mismatch', `committed entry amount ${committedAmount} != settled amount ${settledAmount} — under-reported spend`);
  }
  return { ok: true };
}

// Rule (b): decoded-amount enforcement against the mandate's own bound.
// This fires on ANY settlement exceeding the bound, honest or not -- it is
// cap enforcement, not under-report detection (§16 makes this distinction
// explicit; conflating the two is exactly the failure mode the spec calls out).
function checkDecodedAmountWithinBound(mandateObj, settledAmount) {
  if (!mandate.AMOUNT_RE.test(String(settledAmount))) {
    return mandate.refuse('malformed_input', 'settledAmount must be an integer minor-unit string');
  }
  const amt = BigInt(settledAmount);
  if (mandateObj.perPayment !== undefined && amt > BigInt(mandateObj.perPayment)) {
    return mandate.refuse('scope_exceeded', `settled amount ${settledAmount} exceeds per-payment bound ${mandateObj.perPayment}`);
  }
  if (amt > BigInt(mandateObj.cap)) {
    return mandate.refuse('scope_exceeded', `settled amount ${settledAmount} exceeds mandate cap ${mandateObj.cap}`);
  }
  return { ok: true };
}

// Full post-settlement verdict for one payment. Returns:
//   {verdict:'SETTLED_OK'}                      -- everything matches, within bound
//   {verdict:'POST_SETTLEMENT_REFUTED', reasons} -- one or both checks failed
// mandateEnvelope/paymentId identify which grant+slot to check against;
// settled is the decoded on-chain artifact; committedAmount is optional
// (the self-reported/logged amount for the same paymentId, when available).
function verifyPostSettlement(mandateEnvelope, paymentId, settled, committedAmount) {
  const envVerify = mandate.verifyMandateEnvelope(mandateEnvelope);
  if (!envVerify.ok) return { verdict: 'POST_SETTLEMENT_REFUTED', reasons: [envVerify] };
  const m = mandateEnvelope.mandate;

  const slotCheck = verifySettledSlot(settled, envVerify.digest, paymentId);
  if (!slotCheck.ok) return { verdict: 'POST_SETTLEMENT_REFUTED', reasons: [slotCheck] };

  // §13 rule 4: independently read amount/recipient/asset from the settled
  // artifact and require they equal the mandate scope (recipient/asset) and
  // the SpendEntry's values when a commitment is presented (amount).
  const reasons = [];
  if (settled.asset !== m.asset) {
    reasons.push(mandate.refuse('request_mismatch', `settled.asset '${settled.asset}' != mandate.asset '${m.asset}'`));
  }
  const isStar = m.recipients.length === 1 && m.recipients[0] === '*';
  if (!isStar && !m.recipients.includes(settled.recipient)) {
    reasons.push(mandate.refuse('request_mismatch', `settled.recipient '${settled.recipient}' outside mandate.recipients`));
  }
  if (settled.payer !== m.subject) {
    reasons.push(mandate.refuse('request_mismatch', `settled.payer != mandate.subject`));
  }

  const decodedCheck = checkDecodedAmountWithinBound(m, settled.amount);
  if (!decodedCheck.ok) reasons.push(decodedCheck);

  if (committedAmount !== undefined) {
    const commitCheck = checkCommitmentMatch(committedAmount, settled.amount);
    if (!commitCheck.ok) reasons.push(commitCheck);
  }

  if (reasons.length > 0) return { verdict: 'POST_SETTLEMENT_REFUTED', reasons };
  return { verdict: 'SETTLED_OK' };
}

module.exports = { verifySettledSlot, checkCommitmentMatch, checkDecodedAmountWithinBound, verifyPostSettlement };
