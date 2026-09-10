#!/usr/bin/env node
'use strict';
// Phase 1 -- pin reality. Re-reads every upstream source LIVE and writes
// proof/SOURCE_PINS.json. Never reuses a previous pin without checking drift:
// if a head SHA moved since the last written pin, that is recorded in
// `drift_detected` rather than silently overwritten.
//
// Requires the `gh` CLI (authenticated, read-only) and network access. This is
// the ONE part of the proof that needs the network; ./prove.sh verifies against
// the committed pin file and never calls out.

const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const OUT = path.join(__dirname, '..', 'SOURCE_PINS.json');

function gh(route, jq) {
  const args = ['api', route];
  if (jq) args.push('--jq', jq);
  return execFileSync('gh', args, { encoding: 'utf8', timeout: 45000 }).trim();
}

function ghJson(route) { return JSON.parse(gh(route)); }

function pr(repo, num) {
  const p = ghJson(`/repos/${repo}/pulls/${num}`);
  return {
    kind: 'pull_request',
    url: p.html_url,
    number: p.number,
    title: p.title,
    author: p.user.login,
    state: p.state,
    merged: p.merged,
    head_sha: p.head.sha,
    base_sha: p.base.sha,
    updated_at: p.updated_at,
  };
}

function issue(repo, num) {
  const i = ghJson(`/repos/${repo}/issues/${num}`);
  return {
    kind: 'issue',
    url: i.html_url,
    number: i.number,
    title: i.title,
    author: i.user.login,
    state: i.state,
    comments: i.comments,
    updated_at: i.updated_at,
  };
}

function fileAtHead(repo, filePath) {
  const commits = ghJson(`/repos/${repo}/commits?path=${encodeURIComponent(filePath)}&per_page=1`);
  const head = ghJson(`/repos/${repo}/commits/HEAD`);
  return {
    kind: 'file',
    repo,
    path: filePath,
    repo_head_sha: head.sha,
    repo_head_date: head.commit.author.date,
    file_last_commit_sha: commits[0].sha,
    file_last_commit_date: commits[0].commit.author.date,
    file_last_commit_subject: commits[0].commit.message.split('\n')[0],
  };
}

function localGit(dir) {
  const sha = execFileSync('git', ['-C', dir, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
  let dirty = '';
  try {
    dirty = execFileSync('git', ['-C', dir, 'status', '--porcelain'], { encoding: 'utf8' }).trim();
  } catch (_) { /* ignore */ }
  return { head_sha: sha, clean: dirty.length === 0 };
}

function main() {
  const asOf = process.env.PIN_AS_OF || new Date().toISOString();
  let previous = null;
  try { previous = JSON.parse(fs.readFileSync(OUT, 'utf8')); } catch (_) { /* first run */ }

  const sources = {
    'x402#3220': pr('x402-foundation/x402', 3220),
    'x402#3376': pr('x402-foundation/x402', 3376),
    'x402#3389': issue('x402-foundation/x402', 3389),
    'vauban/stark-receipt-profile': fileAtHead('vauban-org/x402-starknet', 'docs/stark-receipt-profile-v0.1.md'),
  };

  // Drift check against whatever was pinned last time.
  const drift = [];
  if (previous && previous.sources) {
    for (const [k, v] of Object.entries(sources)) {
      const old = previous.sources[k];
      if (!old) { drift.push({ source: k, change: 'newly_added' }); continue; }
      const keys = ['head_sha', 'file_last_commit_sha', 'state', 'merged', 'updated_at', 'comments'];
      for (const key of keys) {
        if (key in v && key in old && v[key] !== old[key]) {
          drift.push({ source: k, field: key, was: old[key], now: v[key] });
        }
      }
    }
  }

  const out = {
    schema: 'stillos-proof-source-pins/1',
    pinned_at: asOf,
    previous_pinned_at: previous ? previous.pinned_at : null,
    note: 'Every result in PROOF.md is against exactly these revisions. Regenerate with `node proof/tools/pin_sources.cjs` and re-run ./prove.sh before citing a result.',
    sources,
    local_repos: {
      'stillmarcus24/x402-authority-verifier-kit': localGit(path.join(__dirname, '..', '..')),
    },
    drift_detected: drift,
    endorsement_disclaimer:
      'Both x402 PRs are third-party, open and unmerged. The Vauban profile is a third-party draft. ' +
      'Nothing in this file or repository constitutes review, acceptance or endorsement by whawk46, saneGuy, ' +
      'seritalien, goun7, Vauban Pay, Tamga, Apodix, Bolyra, Coinbase or the x402-foundation maintainers.',
  };

  fs.writeFileSync(OUT, JSON.stringify(out, null, 2) + '\n');
  console.log(`wrote ${path.relative(process.cwd(), OUT)}`);
  if (drift.length) {
    console.log(`DRIFT DETECTED (${drift.length}):`);
    for (const d of drift) console.log('  ' + JSON.stringify(d));
  } else if (previous) {
    console.log('no drift vs previous pin');
  }
}

main();
