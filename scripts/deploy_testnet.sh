#!/usr/bin/env bash
#
# Deploy the Hypertron shielded pool to Stellar testnet and wire the components.
#
# Prereqs:
#   - stellar CLI (https://developers.stellar.org/docs/tools/cli)
#   - an identity funded via friendbot:  stellar keys generate hypertron --network testnet && \
#       stellar keys fund hypertron --network testnet
#   - verifying keys produced by the ceremony (see docs/ceremony.md):
#       deposit.vk.json, unshield.vk.json, transfer.vk.json
#
# This is intentionally explicit rather than clever: each step prints the id it
# produced so a reviewer can follow the wiring on-chain.
set -euo pipefail

NETWORK="${NETWORK:-testnet}"
SOURCE="${SOURCE:-hypertron}"          # stellar keys identity name
TOKEN="${TOKEN:?set TOKEN to the SAC/token contract id for the pool asset}"

WASM_DIR="target/wasm32v1-none/release"

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
deploy() { # deploy <wasm-name>
  stellar contract deploy \
    --wasm "$WASM_DIR/$1.wasm" \
    --source "$SOURCE" --network "$NETWORK"
}
invoke() { # invoke <contract-id> <fn> [args...]
  stellar contract invoke --id "$1" --source "$SOURCE" --network "$NETWORK" -- "${@:2}"
}

log "Building contracts (release, wasm32v1-none)"
cargo build --release --target wasm32v1-none

log "Deploying commitment"
COMMITMENT=$(deploy hypertron_commitment); echo "commitment = $COMMITMENT"
log "Deploying nullifier"
NULLIFIER=$(deploy hypertron_nullifier);   echo "nullifier  = $NULLIFIER"
log "Deploying verifier"
VERIFIER=$(deploy hypertron_verifier);     echo "verifier   = $VERIFIER"
log "Deploying transfer (pool)"
POOL=$(deploy hypertron_transfer);         echo "pool       = $POOL"

ADMIN=$(stellar keys address "$SOURCE")

log "Initializing components (authority = pool, admin = $ADMIN)"
invoke "$COMMITMENT" initialize --authority "$POOL"
invoke "$NULLIFIER"  initialize --authority "$POOL"
invoke "$VERIFIER"   initialize --admin "$ADMIN"

log "Registering verifying keys (see docs/ceremony.md for how to produce them)"
# Encoding the arkworks VK JSON into the on-chain VerifyingKey struct is
# environment-specific; register_vk expects the uncompressed-point layout the
# prover's groth16::vk_json emits. Register deposit=1, unshield=2, transfer=3.
echo "  -> register deposit.vk.json  under id 1"
echo "  -> register unshield.vk.json under id 2"
echo "  -> register transfer.vk.json under id 3"
echo "  (use your VK-encoding helper / stellar contract invoke $VERIFIER register_vk ...)"

log "Initializing the pool"
invoke "$POOL" initialize --config "{
  \"token\": \"$TOKEN\",
  \"commitment\": \"$COMMITMENT\",
  \"nullifier\": \"$NULLIFIER\",
  \"verifier\": \"$VERIFIER\",
  \"deposit_vk_id\": 1,
  \"unshield_vk_id\": 2,
  \"transfer_vk_id\": 3,
  \"compliance\": null
}"

log "Done. Pool = $POOL"
cat <<EOF

Next:
  - Optionally deploy hypertron_compliance and set config.compliance to it.
  - Fund users, then use the hypertron-prove CLI to build deposit/unshield/
    transfer proofs and submit them (unshield/transfer are relayer-submittable).
EOF
