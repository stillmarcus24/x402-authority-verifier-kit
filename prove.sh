#!/bin/sh
# One command, no network, no dependencies. Exits 0 only if every check passes.
#
#   1. The frozen adversarial corpus regenerates BYTE-IDENTICALLY from its
#      builder. A corpus that drifts when rebuilt is not evidence of anything.
#   2. Both independent implementations (Node A, Python B) run every corpus
#      vector and must agree with the expectation AND with each other.
#   3. The upstream conformance run reproduces x402#3220's own published
#      vectors at the pinned commit.
#
# Source revisions every result is against: proof/SOURCE_PINS.json.
# What the results mean, and what they do not: proof/PROOF.md.
set -e
cd "$(dirname "$0")"

command -v node    >/dev/null 2>&1 || { echo "prove: node not found (>=18 required)"; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "prove: python3 not found (>=3.8 required, stdlib only)"; exit 2; }

echo "node    $(node --version)"
echo "python3 $(python3 --version 2>&1)"
echo

# ---- 1. corpus determinism ------------------------------------------------
echo "[1/3] corpus determinism"
CORPUS=proof/corpus/adversarial.json
SAVED=$(mktemp)
cp "$CORPUS" "$SAVED"
node proof/tools/build_corpus.cjs >/dev/null
if cmp -s "$SAVED" "$CORPUS"; then
  echo "      corpus regenerates byte-identical"
  rm -f "$SAVED"
else
  cp "$SAVED" "$CORPUS"          # leave the tree as we found it
  rm -f "$SAVED"
  echo "      FAIL: corpus is not reproducible from its builder"
  exit 1
fi
echo

# ---- 2. differential corpus (two independent implementations) -------------
echo "[2/3] adversarial corpus, Node vs Python"
node proof/tools/run_corpus.cjs
echo

# ---- 3. upstream conformance ----------------------------------------------
echo "[3/3] upstream conformance against x402#3220 vectors"
node vectors/run_conformance.cjs
echo
echo "PROVED. See proof/PROOF.md for scope, defects found, and the limits of this result."
