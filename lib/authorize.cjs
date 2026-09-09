'use strict';
// authority.md §6 -- pre-settlement single-payment authorization check.
// Verifiers MUST be total: every path returns a verdict, never throws.

const mandate = require('./mandate.cjs');
const binding = require('./binding.cjs');

// payment: {payer, recipient, asset, amount, mandateDigest, paymentId, at?}
// mandateEnvelope: {mandate, alg, sig}
// clockNowIso: verifier's own clock (§6 rule 7 -- MUST use verifier's clock,
// not the payer-supplied `at`, which is advisory only and MUST NOT extend
// authorization).
function authorizePayment(mandateEnvelope, payment, clockNowIso) {
  if (typeof payment !== 'object' || payment === null) {
    return mandate.refuse('malformed_input', 'payment is not an object');
  }
  for (const f of ['payer', 'recipient', 'asset', 'amount', 'mandateDigest']) {
    if (typeof payment[f] !== 'string' || payment[f].length === 0) {
      return mandate.refuse('malformed_input', `payment.${f} missing or not a non-empty string`);
    }
  }
  if (payment.at !== undefined) {
    if (typeof payment.at !== 'string' || !mandate.TIMESTAMP_RE.test(payment.at)) {
      return mandate.refuse('malformed_input', 'payment.at, when present, must be a strict RFC 3339 UTC timestamp');
    }
  }

  // 1. mandate signature authentic
  const envVerify = mandate.verifyMandateEnvelope(mandateEnvelope);
  if (!envVerify.ok) return envVerify;
  const m = mandateEnvelope.mandate;

  // 2. payment.mandateDigest equals the recomputed digest
  if (payment.mandateDigest !== envVerify.digest) {
    return mandate.refuse('request_mismatch', 'payment.mandateDigest does not equal the recomputed mandate digest');
  }

  // 3. payer equals mandate subject
  if (payment.payer !== m.subject) {
    return mandate.refuse('request_mismatch', 'payment.payer does not equal mandate.subject');
  }

  // 4. asset equals mandate asset
  if (payment.asset !== m.asset) {
    return mandate.refuse('request_mismatch', `payment.asset '${payment.asset}' does not equal mandate.asset '${m.asset}'`);
  }

  // 5. recipient within scope
  const isStar = m.recipients.length === 1 && m.recipients[0] === '*';
  let warning;
  if (!isStar && !m.recipients.includes(payment.recipient)) {
    return mandate.refuse('request_mismatch', `payment.recipient '${payment.recipient}' is outside mandate.recipients`);
  }
  if (isStar) warning = 'recipient authorized only via the sole "*" (ANY_RECIPIENT) opt-in';

  // 6. amount: valid integer, <= perPayment when present, <= cap unconditionally
  if (!mandate.AMOUNT_RE.test(payment.amount)) {
    return mandate.refuse('malformed_input', 'payment.amount must be an integer minor-unit string');
  }
  const amount = BigInt(payment.amount);
  if (m.perPayment !== undefined && amount > BigInt(m.perPayment)) {
    return mandate.refuse('scope_exceeded', `payment amount ${payment.amount} exceeds per-payment bound ${m.perPayment}`);
  }
  if (amount > BigInt(m.cap)) {
    return mandate.refuse('scope_exceeded', `payment amount ${payment.amount} exceeds mandate cap ${m.cap}`);
  }

  // 7. expiry, verifier's clock only
  if (typeof clockNowIso !== 'string') {
    return mandate.refuse('internal_error', 'verifier clock not supplied');
  }
  if (clockNowIso >= m.notAfter) {
    return mandate.refuse('expired', `verifier clock ${clockNowIso} is at or after mandate.notAfter ${m.notAfter}`);
  }

  // Best-effort pre-settlement binding sanity check when binding info was
  // actually presented (§7/§13: this is NOT the enforced guarantee -- only a
  // decode-and-compare against the SETTLED artifact is. See lib/settle.cjs).
  // Totality (§6): total absence of {scheme,bindingSlot} is a spec-sanctioned
  // omission (#3376's own extractPaymentBinding omits the whole `payment`
  // member when the payload carried none) and is NOT treated as a failure --
  // pre-settlement authority per §6 rules 1-7 doesn't depend on binding info
  // at all; binding enforcement is inherently a settlement-time property.
  // PARTIAL presence (one of the two given, not both) is genuinely malformed
  // input, not an honest omission, and MUST fail closed rather than be
  // silently skipped alongside the full-omission case.
  const hasScheme = payment.scheme !== undefined;
  const hasSlot = payment.bindingSlot !== undefined;
  if (hasScheme !== hasSlot) {
    return mandate.refuse('malformed_input', 'payment carries exactly one of scheme/bindingSlot — both or neither is required, partial binding info is not a valid omission');
  }
  if (hasScheme && hasSlot) {
    if (!binding.PAYMENT_ID_RE.test(payment.paymentId)) {
      return mandate.refuse('invalid_bundle', 'payment.paymentId out of grammar (§6)');
    }
    let slotOk;
    try {
      slotOk = binding.verifySlot(payment.scheme, envVerify.digest, payment.paymentId, payment.bindingSlot);
    } catch (e) {
      return mandate.refuse('invalid_bundle', `binding check threw: ${e.message}`);
    }
    if (!slotOk) {
      return mandate.refuse('invalid_bundle', 'presented binding slot does not match the derived (mandate, paymentId) binding — PRE-SETTLEMENT ONLY, not proof of the settled amount (§7/§13)');
    }
  }

  return { ok: true, digest: envVerify.digest, warning };
}

module.exports = { authorizePayment };
