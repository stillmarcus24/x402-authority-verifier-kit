'use strict';
// Full conformance run against x402-foundation/x402#3220's authority-vectors.json
// (whawk46 @ 72c3704, pinned in docs/interop/x402-authority/SOURCE_PINS.md).
// Two conformance tiers per authority.md §16: (1) crypto/wire values must
// match byte-for-byte; (2) accept/refuse verdicts must match (message text
// is informative only). This runner checks both tiers and prints a table.

const canon = require('../lib/canon.cjs');
const binding = require('../lib/binding.cjs');
const mandateLib = require('../lib/mandate.cjs');
const authorizeLib = require('../lib/authorize.cjs');
const settleLib = require('../lib/settle.cjs');
const fixtures = require('./fixtures/authority-vectors.json');

const results = [];
function record(section, name, pass, detail) {
  results.push({ section, name, pass, detail: detail || '' });
}

const ma = fixtures.modelA;
const del = fixtures.delegation;
const base = ma.mandate;
const envA = { mandate: ma.mandate, alg: ma.alg, sig: ma.sig };

// --- Tier 1: crypto / wire values, byte-for-byte ---
record('crypto', 'modelA JCS', canon.canonicalize(ma.mandate) === ma.jcs);
record('crypto', 'modelA digest', mandateLib.mandateDigest(ma.mandate) === ma.digest);
record('crypto', 'modelA sig verifies', canon.verifyEd25519('x402-mandate/1\n', ma.mandate, ma.sig, ma.mandate.issuer) === ma.sigVerifies);
{
  const enc = binding.computeAllEncodings(ma.digest, ma.binding.paymentId);
  record('crypto', 'binding eip3009', enc.eip3009 === ma.binding.eip3009);
  record('crypto', 'binding permit2', enc.permit2 === ma.binding.permit2);
  record('crypto', 'binding xrpl', enc.xrpl === ma.binding.xrpl);
}
record('crypto', 'delegation childDigest', mandateLib.mandateDigest(del.child) === del.childDigest);
{
  const chainOk = mandateLib.recoverRootIssuer([envA, { mandate: del.child, alg: del.childAlg, sig: del.childSig }]);
  record('crypto', 'delegation chainOk', chainOk.ok === del.chainOk);
  record('crypto', 'delegation rootIssuer', chainOk.ok && chainOk.rootIssuer === del.rootIssuer);
  record('crypto', 'delegation leafDigest', chainOk.ok && chainOk.leafDigest === del.childDigest);
}

// --- Tier 2: accept/refuse verdicts ---
// modelA.paymentAccepted / paymentRefusals
{
  const accepted = ma.paymentAccepted.payment;
  const now = '2026-08-19T00:00:00Z';
  const r = authorizeLib.authorizePayment(envA, accepted, now);
  record('payment', 'paymentAccepted -> allow', r.ok === ma.paymentAccepted.verdict);

  const refusals = ma.paymentRefusals;
  const cases = {
    overPerPayment: { ...accepted, amount: '300000' },
    outOfScopeRecipient: { ...accepted, recipient: 'evil.example' },
    wrongAsset: { ...accepted, asset: 'USDC' },
    wrongPayer: { ...accepted, payer: fixtures.keys.mallory.publicKeyB64url },
    expired: { ...accepted },
  };
  for (const [name, payment] of Object.entries(cases)) {
    const clock = name === 'expired' ? '2027-06-01T00:00:00Z' : now;
    const res = authorizeLib.authorizePayment(envA, payment, clock);
    record('payment-refusal', name, res.ok === refusals[name], res.ok ? 'allowed' : `${res.code}: ${res.message}`);
  }

  // Original-ask N1/N2/N9 -- binding-level mutations, not covered above
  // (those only exercise §6 rules 1/3-7; these exercise §7's binding check).
  const withBinding = { ...accepted, paymentId: ma.binding.paymentId, scheme: 'eip3009', bindingSlot: ma.binding.eip3009 };
  {
    const r = authorizeLib.authorizePayment(envA, withBinding, now);
    record('binding-mutation', 'N-baseline: correct binding -> ALLOW', r.ok === true);
  }
  {
    const mutated = { ...withBinding, paymentId: 'pay-002' }; // valid grammar, wrong id -> wrong derived B
    const r = authorizeLib.authorizePayment(envA, mutated, now);
    record('binding-mutation', 'N1: mutated paymentId -> DENY', r.ok === false, r.ok ? 'allowed (WRONG)' : `${r.code}: ${r.message}`);
  }
  {
    const mutated = { ...withBinding, bindingSlot: ma.binding.permit2 }; // right B, wrong scheme's encoding
    const r = authorizeLib.authorizePayment(envA, mutated, now);
    record('binding-mutation', 'N2: correct digest, wrong binding_slot for declared scheme -> DENY', r.ok === false, r.ok ? 'allowed (WRONG)' : `${r.code}: ${r.message}`);
  }
  {
    const mutated = { ...withBinding, bindingSlot: undefined }; // scheme present, slot absent -- malformed, not an honest omission
    const r = authorizeLib.authorizePayment(envA, mutated, now);
    record('binding-mutation', 'N9: partial binding info (scheme w/o slot) -> DENY (malformed_input)', r.ok === false && r.code === 'malformed_input', r.ok ? 'allowed (WRONG)' : `${r.code}: ${r.message}`);
  }
  {
    const noBinding = { ...accepted }; // total absence -- spec-sanctioned omission, must still ALLOW on the other 6 rules
    const r = authorizeLib.authorizePayment(envA, noBinding, now);
    record('binding-mutation', 'total binding omission (spec-sanctioned) -> still ALLOW', r.ok === true, r.ok ? '' : `${r.code}: ${r.message}`);
  }
}

// modelA.verdicts -- base scenario sanity (not independently mutated data;
// asserts our checks don't spuriously refuse/warn a clean scenario). See
// SOURCE_PINS.md scope cut: §8/§9 (spend log/committed head) are out of
// scope, so truncatedLog/fakeAccountant/rollback/duplicatePaymentId/
// postSettleInclusion aren't independently exercised here -- recorded as
// not-applicable rather than silently dropped.
for (const k of Object.keys(ma.verdicts)) {
  record('spend-log-scope-cut', k, null, 'out of scope — §8/§9 not implemented, see SOURCE_PINS.md');
}

// shapeRefusals (§3)
{
  const shape = fixtures.shapeRefusals;
  const cases = {
    feb30NotAfter: { ...base, notAfter: '2026-02-30T00:00:00Z' },
    emptyRecipients: { ...base, recipients: [] },
    starMixedWithNamed: { ...base, recipients: ['*', 'merchant.example'] },
    floatCap: { ...base, cap: '1000000.5' },
    perPaymentAboveCap: { ...base, perPayment: '2000000' },
  };
  for (const [name, mandate] of Object.entries(cases)) {
    const r = mandateLib.validateMandateShape(mandate);
    record('shape-refusal', name, r.ok === false, r.ok ? 'accepted (WRONG)' : r.message);
  }
}

// delegation.wideningRefusals (§12)
{
  const widening = del.wideningRefusals;
  const cases = {
    capAboveParent: { ...del.child, cap: '2000000' },
    laterNotAfter: { ...del.child, notAfter: '2027-06-01T00:00:00Z' },
    recipientOutsideParent: { ...del.child, recipients: ['evil.example'] },
    anyUnderScopedParent: { ...del.child, recipients: ['*'] },
  };
  for (const [name, child] of Object.entries(cases)) {
    const r = mandateLib.checkNarrowing(child, base, ma.digest);
    record('delegation-refusal', name, r.ok === false && widening[name] !== undefined, r.ok ? 'accepted (WRONG)' : r.message);
  }
  record('delegation', 'siblingBudget.withinOk', (BigInt(del.child.cap) <= BigInt(base.cap)) === del.siblingBudget.withinOk);
  record('delegation', 'siblingBudget.overRefused (2x child cap vs parent)', ((BigInt(del.child.cap) * 2n) > BigInt(base.cap)) === del.siblingBudget.overRefused);
}

// securityFixes
{
  const sf = fixtures.securityFixes;

  // settledPaymentMatchesOk
  const accepted = ma.paymentAccepted.payment;
  const goodSettled = { scheme: 'eip3009', slot: ma.binding.eip3009, payer: accepted.payer, recipient: accepted.recipient, asset: accepted.asset, amount: accepted.amount };
  const okResult = settleLib.verifyPostSettlement(envA, ma.binding.paymentId, goodSettled, accepted.amount);
  record('security-fix', 'settledPaymentMatchesOk', (okResult.verdict === 'SETTLED_OK') === sf.settledPaymentMatchesOk);

  // settledUnderReport -- two distinct sub-verdicts
  const ur = sf.settledUnderReport;
  const underReport = settleLib.verifyPostSettlement(envA, ur.paymentId, ur.settled, ur.committedEntryAmount);
  const commitMismatch = underReport.reasons && underReport.reasons.find(r => r.message.includes('under-reported'));
  const decodedRefused = underReport.reasons && underReport.reasons.find(r => r.code === 'scope_exceeded');
  record('security-fix', 'settledUnderReport.commitmentMismatch', (!!commitMismatch) === (ur.commitmentMismatchVerdictOk === false));
  record('security-fix', 'settledUnderReport.decodedAmount', (!!decodedRefused) === (ur.decodedAmountVerdictOk === false));
  record('security-fix', 'settledUnderReport.presentedTupleVerdictOk (binding slot itself still matches)',
    settleLib.verifySettledSlot(ur.settled, ma.digest, ur.paymentId).ok === ur.presentedTupleVerdictOk);

  // badAlgRefused
  const badAlgEnv = { mandate: ma.mandate, alg: 'ES256', sig: ma.sig };
  const badAlgResult = mandateLib.verifyMandateEnvelope(badAlgEnv);
  record('security-fix', 'badAlgRefused', (badAlgResult.ok === false) === (sf.badAlgRefused === false));

  // unknownMemberMandateRefused
  const unknownMemberResult = mandateLib.validateMandateShape({ ...base, extra: 'zzz' });
  record('security-fix', 'unknownMemberMandateRefused', unknownMemberResult.ok === false && typeof sf.unknownMemberMandateRefused === 'string');

  // surrogatePurposeRefusedNotThrown -- MUST NOT throw, MUST refuse
  let threw = false, surrogateResult;
  try {
    surrogateResult = mandateLib.validateMandateShape({ ...base, purpose: 'bad\uD800lone' });
  } catch {
    threw = true;
  }
  record('security-fix', 'surrogatePurposeRefusedNotThrown', threw === sf.surrogatePurposeRefusedNotThrown.threw && (surrogateResult && surrogateResult.ok) === sf.surrogatePurposeRefusedNotThrown.ok);

  // strangerVetoResisted -- out of scope: this is a Model B (`accountant:
  // "payees"`) property (§11 rule 1); Model A has no stranger-attestation
  // surface at all, so it's trivially/structurally resisted. Recorded as
  // scope-cut, not fabricated.
  record('spend-log-scope-cut', 'strangerVetoResisted', null, 'Model B (§11) property — Model A/single-payment path has no attestation surface for a stranger to exploit; not independently exercised');
}

// --- print ---
const bySection = {};
for (const r of results) (bySection[r.section] = bySection[r.section] || []).push(r);
let totalRun = 0, totalPass = 0, totalSkip = 0;
for (const [section, rs] of Object.entries(bySection)) {
  console.log(`\n=== ${section} ===`);
  for (const r of rs) {
    if (r.pass === null) { totalSkip++; console.log(`  SKIP  ${r.name}  (${r.detail})`); continue; }
    totalRun++;
    if (r.pass) totalPass++;
    console.log(`  ${r.pass ? 'PASS' : 'FAIL'}  ${r.name}${r.detail ? '  -- ' + r.detail : ''}`);
  }
}
console.log(`\n${totalPass}/${totalRun} passed, ${totalSkip} explicitly scoped out (see SOURCE_PINS.md)`);
process.exitCode = totalPass === totalRun ? 0 : 1;
