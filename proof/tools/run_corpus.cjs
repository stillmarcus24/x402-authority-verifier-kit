#!/usr/bin/env node
'use strict';
// Phase 4/5 runner. A vector PASSES only when:
//   (a) implementation A (Node)   agrees with the expectation, AND
//   (b) implementation B (Python) agrees with the expectation, AND
//   (c) A and B agree with each other on every compared field.
// Anything else is a FAIL and is printed. Failures are never hidden and the
// expectation is never edited to match an implementation.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const nodeImpl = require('../impl-node/assurance.cjs');

const ROOT = path.join(__dirname, '..', '..');
const CORPUS = JSON.parse(fs.readFileSync(path.join(ROOT, 'proof/corpus/adversarial.json'), 'utf8'));

// ---- run every op through both implementations, one Python spawn total ----
const allOps = [];
for (const v of CORPUS.vectors) {
  for (const o of v.ops) allOps.push({ ...o, id: `${v.id}::${o.id}` });
}

const nodeOut = nodeImpl.runOps(allOps);
const tmp = path.join(require('os').tmpdir(), 'stillos-corpus-ops.json');
fs.writeFileSync(tmp, JSON.stringify({ ops: allOps }));
const pyRaw = execFileSync('python3', [path.join(ROOT, 'proof/impl-py/assurance.py'), tmp], {
  encoding: 'utf8', maxBuffer: 256 * 1024 * 1024,
});
const pyOut = JSON.parse(pyRaw).results;

const N = new Map(nodeOut.map(r => [r.id, r.result]));
const P = new Map(pyOut.map(r => [r.id, r.result]));

// ---- fields both implementations must agree on ----------------------------
// `preimage`, `canonical`, `jcs`, `digest*`, verdicts and reason codes are all
// compared. Free-text `message`/`note` fields are not produced by either
// implementation, so nothing prose-shaped is being compared here.
const COMPARE_KEYS = [
  'ok', 'valid', 'error', 'code', 'verdict', 'canonical', 'sha256', 'preimage',
  'field_count', 'computed_hash', 'hash_ok', 'sig_ok', 'comparison_hex',
  'comparison_decimal', 'top5bits', 'masking_is_noop', 'full_equals_stored',
  'full_hex', 'digest_lo', 'digest_hi', 'digest_lo_hex', 'digest_hi_hex',
  'digest_D_decimal', 'hex', 'felt_decimal', 'felt_hex', 'byte_length',
  'provable', 'refusals', 'K', 'F', 'pure_leaf_batch', 'root_domain_tag',
  'jcs', 'digest_hex', 'digest', 'eip3009', 'permit2', 'xrpl',
];

function differ(a, b) {
  if (a === undefined && b === undefined) return null;
  if (a === undefined || b === undefined) return { a, b };
  const out = [];
  for (const k of COMPARE_KEYS) {
    const av = JSON.stringify(a[k]), bv = JSON.stringify(b[k]);
    if (av !== bv) out.push({ key: k, node: a[k], python: b[k] });
  }
  return out.length ? out : null;
}

// ---- expectation evaluator ------------------------------------------------
// Every expectation key is handled EXPLICITLY. An unrecognised key makes the
// vector ERROR rather than silently pass -- a test harness that ignores what
// it does not understand is the failure mode this whole exercise exists to
// avoid.
function evaluate(v, side) {
  const get = (opId) => (side === 'node' ? N : P).get(`${v.id}::${opId}`) || {};
  const ids = v.ops.map(o => o.id);
  const only = get(ids[0]);
  const problems = [];
  const digestOf = (r) => r.sha256 || r.digest_hex || r.comparison_hex || r.value ||
    (r.eip3009 ? r.eip3009 : undefined) || r.hex;

  for (const [key, want] of Object.entries(v.expect)) {
    switch (key) {
      case 'ok': case 'valid': case 'error': case 'code': case 'verdict':
      case 'hash_ok': case 'sig_ok': case 'field_count': case 'top5bits':
      case 'masking_is_noop': case 'provable': case 'pure_leaf_batch':
      case 'canonical':
        if (JSON.stringify(only[key]) !== JSON.stringify(want)) {
          problems.push(`${key}: want ${JSON.stringify(want)} got ${JSON.stringify(only[key])}`);
        }
        break;
      case 'a_equals_b':
      case 'bare_equals_pref': {
        const [x, y] = [get(ids[0]), get(ids[1])];
        if ((digestOf(x) === digestOf(y)) !== want) problems.push(`${key}: want ${want}`);
        break;
      }
      case 'nfc_equals_nfd': case 'num_equals_str': {
        const [x, y] = [get(ids[0]), get(ids[1])];
        if ((x.canonical === y.canonical) !== want) problems.push(`${key}: want ${want}`);
        break;
      }
      case 'a_differs_from_b': case 'a_digest_differs_from_b': {
        const [x, y] = [get(ids[0]), get(ids[1])];
        if ((JSON.stringify(x) !== JSON.stringify(y)) !== want) problems.push(`${key}: want ${want}`);
        break;
      }
      case 'b_refused_or_differs': {
        const [x, y] = [get(ids[0]), get(ids[1])];
        const okv = y.ok === false || JSON.stringify(x) !== JSON.stringify(y);
        if (okv !== want) problems.push(`${key}: want ${want}`);
        break;
      }
      case 'roundtrip_equals_input': {
        const enc = get('enc'), dec = get('dec');
        const inputHex = v.ops[0].args.hex;
        if ((dec.hex === inputHex) !== want) problems.push(`${key}: got ${dec.hex}`);
        if (enc.digest_lo === undefined) problems.push('limbs missing');
        break;
      }
      case 'refusals_include':
        if (!Array.isArray(only.refusals) || !only.refusals.includes(want)) {
          problems.push(`refusals ${JSON.stringify(only.refusals)} missing ${want}`);
        }
        break;
      case 'pre_verdict':
        if (get('pre').verdict !== want) problems.push(`pre_verdict: want ${want} got ${get('pre').verdict}`);
        break;
      case 'post_verdict':
        if (get('post').verdict !== want) problems.push(`post_verdict: want ${want} got ${get('post').verdict}`);
        break;
      case 'ok_len':
        if (get('ok').byte_length !== want) problems.push(`ok_len: got ${get('ok').byte_length}`);
        break;
      case 'over_error':
        if (get('over').error !== want) problems.push(`over_error: got ${get('over').error}`);
        break;
      case 'code_unspecified_divergence':
        // Handled by the differential comparator below: these keys are
        // genuinely unspecified upstream, so they are RECORDED as a divergence
        // instead of being forced into agreement. The verdict is still asserted.
        break;
      case 'node_equals_python': {
        // checked globally by differ(); asserted here so the vector states it
        const d = differ(N.get(`${v.id}::${ids[0]}`), P.get(`${v.id}::${ids[0]}`));
        if ((d === null) !== want) problems.push('node_equals_python violated');
        break;
      }
      case 'jcs_has_payTo_before_payer': {
        const j = only.jcs || '';
        if ((j.indexOf('"payTo"') < j.indexOf('"payer"') && j.indexOf('"payTo"') >= 0) !== want) {
          problems.push('payTo/payer ordering');
        }
        break;
      }
      case 'comparison_hex_has_no_leading_zero': {
        const h = (only.comparison_hex || '').replace(/^0x/, '');
        if ((h[0] !== '0') !== want) problems.push(`leading zero in ${only.comparison_hex}`);
        break;
      }
      case 'canonical_first_key_is_astral': {
        const c = only.canonical || '';
        if (c.startsWith('{"\u{1F600}"') !== want) problems.push(`key order: ${c}`);
        break;
      }
      case 'jcs_sha256_differs_from_receipt_hash': {
        const fixed = get('fixed'), j = get('jcs');
        if ((j.sha256 !== fixed.computed_hash) !== want) problems.push('JCS digest unexpectedly equal');
        break;
      }
      default:
        problems.push(`UNHANDLED_EXPECTATION_KEY:${key}`);
    }
  }
  return problems;
}

// ---- report ---------------------------------------------------------------
const rows = [];
let pass = 0, fail = 0;
for (const v of CORPUS.vectors) {
  const nProb = evaluate(v, 'node');
  const pProb = evaluate(v, 'python');
  const waived = v.expect.code_unspecified_divergence || [];
  let diffs = v.ops.map(o => ({ op: o.id, d: differ(N.get(`${v.id}::${o.id}`), P.get(`${v.id}::${o.id}`)) }))
    .filter(x => x.d !== null);
  let documented = [];
  if (waived.length) {
    documented = diffs.flatMap(x => (Array.isArray(x.d) ? x.d : []).filter(e => waived.includes(e.key)));
    diffs = diffs.map(x => ({ op: x.op, d: Array.isArray(x.d) ? x.d.filter(e => !waived.includes(e.key)) : x.d }))
      .filter(x => x.d !== null && (!Array.isArray(x.d) || x.d.length > 0));
  }
  const ok = nProb.length === 0 && pProb.length === 0 && diffs.length === 0;
  if (ok) pass++; else fail++;
  rows.push({
    id: v.id, attacks: v.attacks, status: ok ? 'PASS' : 'FAIL',
    node_problems: nProb, python_problems: pProb, differential: diffs,
    documented_unspecified_divergence: documented,
    node_result: Object.fromEntries(v.ops.map(o => [o.id, N.get(`${v.id}::${o.id}`)])),
    python_result: Object.fromEntries(v.ops.map(o => [o.id, P.get(`${v.id}::${o.id}`)])),
  });
  if (!ok) {
    console.log(`FAIL ${v.id} -- ${v.attacks}`);
    for (const p of nProb) console.log(`   node:   ${p}`);
    for (const p of pProb) console.log(`   python: ${p}`);
    for (const d of diffs) console.log(`   DIFFERENTIAL ${d.op}: ${JSON.stringify(d.d)}`);
  }
}

fs.writeFileSync(path.join(ROOT, 'proof/results/adversarial-results.json'),
  JSON.stringify({
    schema: 'stillos-assurance-corpus-results/1',
    vector_count: CORPUS.vectors.length, passed: pass, failed: fail,
    rule: 'A vector passes only when BOTH implementations agree with the expectation AND with each other.',
    rows,
  }, null, 2) + '\n');

const divergent = rows.filter(r => r.documented_unspecified_divergence && r.documented_unspecified_divergence.length);
for (const d of divergent) {
  console.log(`DOCUMENTED DIVERGENCE ${d.id}: ${JSON.stringify(d.documented_unspecified_divergence)} -- upstream specifies no value; recorded, not forced.`);
}
console.log(`\nadversarial corpus: ${pass}/${CORPUS.vectors.length} passed, ${fail} failed, ${divergent.length} documented unspecified divergence(s)`);
process.exitCode = fail === 0 ? 0 : 1;
