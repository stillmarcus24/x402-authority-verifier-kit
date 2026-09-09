# StillOS x402-authority verifier — signing key

Public key material only, pinned as a static file so a receipt can be
verified without a live call to StillOS. Every receipt this verifier issues
is signed by the key below; a fresh clone of this repo generates its own
separate, local signing identity on first run (see `lib/receipt.cjs`) — that
local identity is unrelated to the one documented here, which is the key
StillOS's own operated instance signs under.

| File | Fingerprint | Algorithm | Status | Effective |
|---|---|---|---|---|
| `stillos-x402-authority-ed25519-v1.pub` | `7356b1ad89d0ad46` | Ed25519 | active | 2026-09-08 → present |

## Fingerprint

`fingerprint = SHA256(public_key_pem_bytes).slice(0, 16)` — first 16 hex
characters (8 bytes) of the SHA-256 digest of the exact PEM text in the file
above, including header/footer lines and the trailing newline.

## Rotation policy

Unrotated since creation. On rotation, a new `stillos-x402-authority-ed25519-vN.pub`
file is added, the retiring key's file is kept (required to verify receipts
signed before rotation), and this table gets a new row in the same commit.
