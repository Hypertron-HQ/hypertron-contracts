#!/usr/bin/env bash
#
# Deploy the Hypertron shielded pool to Stellar testnet and wire the components.
#
# Prereqs:
#   - stellar CLI (https://developers.stellar.org/docs/tools/cli)
#   - an identity funded via friendbot:  stellar keys generate hypertron --network testnet && \
#       stellar keys fund hypertron --network testnet
#   - verifying keys (see docs/CEREMONY.md), or GENERATE_KEYS=1 to produce them:
#       deposit.vk.json, unshield.vk.json, transfer.vk.json
#
# This is intentionally explicit rather than clever: each step prints the id it
# produced so a reviewer can follow the wiring on-chain.
set -euo pipefail

# DEV_SETUP used to generate keys from a fixed seed whose toxic waste was
# publicly recoverable. Fail loudly rather than silently doing something else.
if [ -n "${DEV_SETUP:-}" ]; then
  cat >&2 <<'EOF'
error: DEV_SETUP has been removed. It generated keys from a fixed seed (default
       1), so anyone could reconstruct the toxic waste and forge proofs.

  Use GENERATE_KEYS=1 to run a single-coordinator setup from OS entropy.
  The deliberately-forgeable path, for local circuit work only, is:
      HYPERTRON_INSECURE_DEV_SETUP=1 cargo run -p hypertron-prover -- \
        setup --circuit deposit --insecure-dev-seed 1 ...
EOF
  exit 1
fi

NETWORK="${NETWORK:-testnet}"
SOURCE="${SOURCE:-hypertron}"          # stellar keys identity name
TOKEN="${TOKEN:?set TOKEN to the SAC/token contract id for the pool asset}"

# Directory holding the verifying keys (see docs/CEREMONY.md):
#   $VK_DIR/deposit.vk.json  $VK_DIR/unshield.vk.json  $VK_DIR/transfer.vk.json
#   $VK_DIR/transfer-2.vk.json  $VK_DIR/transfer-4.vk.json
VK_DIR="${VK_DIR:-vk}"
# GENERATE_KEYS=1 runs a single-coordinator setup from OS entropy for all five
# circuits (deposit, unshield, transfer, transfer-2, transfer-4). That is stronger
# than a fixed seed (nothing is reproducible from the repo) but it is NOT a
# multi-party ceremony: whoever runs it could retain the toxic waste. Mainnet
# still requires the ceremony in docs/CEREMONY.md.
GENERATE_KEYS="${GENERATE_KEYS:-0}"
# Reuse an already-deployed verifier (register VK 4/5 only; 1-in keys stay).
# Testnet: VERIFIER=CCHSL7YSPSCT62DBUSCG4CKBJ2I4U4JSBR4RE3YIEGNSEUYXYY7BDIEP
VERIFIER="${VERIFIER:-}"
REUSE_VERIFIER="$VERIFIER"
# COMPLIANCE=1 also deploys hypertron_compliance and wires it into the pool.
COMPLIANCE="${COMPLIANCE:-0}"
# Compliance mode: true => denylist (allow unless listed), false => allowlist.
COMPLIANCE_DEFAULT_ALLOW="${COMPLIANCE_DEFAULT_ALLOW:-true}"

if [ -n "${CARGO_TARGET_DIR:-}" ]; then
  WASM_DIR="$CARGO_TARGET_DIR/wasm32v1-none/release"
else
  WASM_DIR="target/wasm32v1-none/release"
fi

log() { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
deploy() { # deploy <wasm-name>
  stellar contract deploy \
    --wasm "$WASM_DIR/$1.wasm" \
    --source "$SOURCE" --network "$NETWORK"
}
invoke() { # invoke <contract-id> <fn> [args...]
  stellar contract invoke --id "$1" --source "$SOURCE" --network "$NETWORK" -- "${@:2}"
}
prove() { # prove <args...> — run the off-chain prover/VK CLI, stdout only
  cargo run -q -p hypertron-prover -- "$@"
}
register_vk() { # register_vk <verifier-id> <vk-id> <vk-json-file>
  local arg
  arg=$(prove register-vk-args --vk "$3" --vk-id "$2" --compact)
  invoke "$1" register_vk --vk_id "$2" --vk "$arg"
}

log "Building contracts (release, wasm32v1-none)"
cargo build --release --target wasm32v1-none

CIRCUITS=(deposit unshield transfer "transfer-2" "transfer-4")

if [ "$GENERATE_KEYS" = "1" ]; then
  log "GENERATE_KEYS=1: single-coordinator setup from OS entropy into $VK_DIR"
  mkdir -p "$VK_DIR"
  for c in "${CIRCUITS[@]}"; do
    prove setup --circuit "$c" \
      --pk-out "$VK_DIR/$c.pk.bin" --vk-out "$VK_DIR/$c.vk.json" >/dev/null
    echo "  generated $VK_DIR/$c.vk.json"
  done
fi

for c in "${CIRCUITS[@]}"; do
  if [ ! -f "$VK_DIR/$c.vk.json" ]; then
    echo "error: missing $VK_DIR/$c.vk.json (see docs/CEREMONY.md, or set GENERATE_KEYS=1)" >&2
    exit 1
  fi
  # A key produced from a reproducible seed carries this marker. Refuse to
  # deploy one by accident.
  if grep -q '"insecure_dev_seed"' "$VK_DIR/$c.vk.json"; then
    echo "error: $VK_DIR/$c.vk.json was generated from a public development seed;" >&2
    echo "       its proofs are forgeable. Regenerate with GENERATE_KEYS=1." >&2
    exit 1
  fi
done

log "Artifact hashes (record these in deployments/*.json)"
for c in "${CIRCUITS[@]}"; do
  for f in "$VK_DIR/$c.vk.json" "$VK_DIR/$c.pk.bin"; do
    [ -f "$f" ] && shasum -a 256 "$f"
  done
done

log "Deploying commitment"
COMMITMENT=$(deploy hypertron_commitment); echo "commitment = $COMMITMENT"
log "Deploying nullifier"
NULLIFIER=$(deploy hypertron_nullifier);   echo "nullifier  = $NULLIFIER"
if [ -n "$VERIFIER" ]; then
  log "Reusing verifier $VERIFIER"
else
  log "Deploying verifier"
  VERIFIER=$(deploy hypertron_verifier);   echo "verifier   = $VERIFIER"
fi
log "Deploying transfer (pool)"
POOL=$(deploy hypertron_transfer);         echo "pool       = $POOL"

ADMIN=$(stellar keys address "$SOURCE")

log "Initializing components (authority = pool, admin = $ADMIN)"
invoke "$COMMITMENT" initialize --authority "$POOL"
invoke "$NULLIFIER"  initialize --authority "$POOL"
if [ -z "$REUSE_VERIFIER" ]; then
  invoke "$VERIFIER" initialize --admin "$ADMIN"
fi

if [ -z "$REUSE_VERIFIER" ]; then
  log "Registering verifying keys (deposit=1, unshield=2, transfer=3, transfer-2=4, transfer-4=5)"
  register_vk "$VERIFIER" 1 "$VK_DIR/deposit.vk.json"
  register_vk "$VERIFIER" 2 "$VK_DIR/unshield.vk.json"
  register_vk "$VERIFIER" 3 "$VK_DIR/transfer.vk.json"
  register_vk "$VERIFIER" 4 "$VK_DIR/transfer-2.vk.json"
  register_vk "$VERIFIER" 5 "$VK_DIR/transfer-4.vk.json"
else
  log "Registering verifying keys (transfer-2=4, transfer-4=5) on existing verifier"
  register_vk "$VERIFIER" 4 "$VK_DIR/transfer-2.vk.json"
  register_vk "$VERIFIER" 5 "$VK_DIR/transfer-4.vk.json"
fi

COMPLIANCE_ARG="null"
if [ "$COMPLIANCE" = "1" ]; then
  log "Deploying compliance (admin = $ADMIN)"
  COMPLIANCE_ID=$(deploy hypertron_compliance); echo "compliance = $COMPLIANCE_ID"
  invoke "$COMPLIANCE_ID" initialize --admin "$ADMIN" --default_allow "$COMPLIANCE_DEFAULT_ALLOW"
  COMPLIANCE_ARG="\"$COMPLIANCE_ID\""
fi

log "Initializing the pool"
invoke "$POOL" initialize --config "{
  \"token\": \"$TOKEN\",
  \"commitment\": \"$COMMITMENT\",
  \"nullifier\": \"$NULLIFIER\",
  \"verifier\": \"$VERIFIER\",
  \"deposit_vk_id\": 1,
  \"unshield_vk_id\": 2,
  \"transfer_vk_id\": 3,
  \"transfer_2in_vk_id\": 4,
  \"transfer_4in_vk_id\": 5,
  \"compliance\": $COMPLIANCE_ARG
}"

log "Done. Pool = $POOL"
cat <<EOF

Next:
  - Fund users, then use the hypertron-prove CLI (or the @hypertron/prover WASM
    package) to build deposit/unshield/transfer proofs and submit them
    (unshield/transfer are relayer-submittable).
EOF
