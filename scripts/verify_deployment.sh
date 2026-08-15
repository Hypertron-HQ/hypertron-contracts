#!/usr/bin/env bash
#
# Check a Hypertron deployment against its published manifest.
#
# Two independent things are checked, and both must pass:
#
#   1. Integrity — the local verifying/proving keys hash to the values recorded
#      in the manifest, so the published files are the ones described.
#
#   2. Correspondence — a freshly generated proof from each local proving key is
#      accepted by the deployed verifier. A Groth16 pairing check cannot pass
#      against an unrelated verifying key, so this establishes that the key
#      registered on-chain really is the one in this directory. It does not rely
#      on trusting the manifest, the deploy script, or whoever ran them.
#
# Usage:
#   ./scripts/verify_deployment.sh                       # testnet, vk/
#   VK_DIR=... MANIFEST=... NETWORK=... ./scripts/verify_deployment.sh
#
# Requires: stellar CLI, jq, and a funded --source identity for simulation.
set -euo pipefail

NETWORK="${NETWORK:-testnet}"
SOURCE="${SOURCE:-hypertron}"
VK_DIR="${VK_DIR:-vk}"
MANIFEST="${MANIFEST:-deployments/$NETWORK.json}"

for bin in stellar jq; do
  command -v "$bin" >/dev/null || { echo "error: $bin is required" >&2; exit 1; }
done
[ -f "$MANIFEST" ] || { echo "error: no manifest at $MANIFEST" >&2; exit 1; }

VERIFIER=$(jq -r '.contracts.verifier' "$MANIFEST")
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass() { printf '  \033[32mok\033[0m   %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILED=1; }
FAILED=0

echo
echo "verifier $VERIFIER on $NETWORK"
echo "manifest $MANIFEST"

echo
echo "1. artifact integrity"
for c in deposit unshield transfer; do
  for kind in vk pk; do
    case $kind in
      vk) file="$VK_DIR/$c.vk.json"; field=vk_sha256 ;;
      pk) file="$VK_DIR/$c.pk.bin";  field=pk_sha256 ;;
    esac
    want=$(jq -r ".artifacts.$c.$field" "$MANIFEST")
    if [ ! -f "$file" ]; then
      fail "$file is missing"
    elif [ "$(shasum -a 256 "$file" | cut -d' ' -f1)" = "$want" ]; then
      pass "$file"
    else
      fail "$file does not match $field in the manifest"
    fi
  done
  # A key built from a reproducible seed is forgeable and self-identifies.
  if [ -f "$VK_DIR/$c.vk.json" ] && jq -e 'has("insecure_dev_seed")' "$VK_DIR/$c.vk.json" >/dev/null; then
    fail "$c.vk.json came from a public development seed — proofs are forgeable"
  fi
done

echo
echo "2. on-chain keys accept proofs from these proving keys"
for c in deposit unshield transfer; do
  vk_id=$(jq -r ".artifacts.$c.vk_id" "$MANIFEST")
  if ! cargo run -q --release -p hypertron-prover -- self-test \
        --circuit "$c" --pk "$VK_DIR/$c.pk.bin" --out "$TMP/$c.json" >/dev/null 2>&1; then
    fail "$c: could not build a self-test proof"
    continue
  fi
  proof=$(jq -r '.proof' "$TMP/$c.json" | sed 's/^0x//')
  publics=$(jq -c '[.public_inputs[] | sub("^0x"; "")]' "$TMP/$c.json")
  result=$(stellar contract invoke --id "$VERIFIER" --source "$SOURCE" \
    --network "$NETWORK" --send=no -- verify \
    --vk_id "$vk_id" --proof "$proof" --public_inputs "$publics" 2>/dev/null | tail -1)
  if [ "$result" = "true" ]; then
    pass "$c (vk_id=$vk_id) accepted on-chain"
  else
    fail "$c (vk_id=$vk_id) rejected on-chain — the registered key is not this key"
  fi
done

echo
if [ "$FAILED" -eq 0 ]; then
  echo "All checks passed."
  echo
  jq -r '"Setup: " + .setup.kind + " — " + .setup.trust_assumption' "$MANIFEST"
else
  echo "One or more checks FAILED." >&2
  exit 1
fi
