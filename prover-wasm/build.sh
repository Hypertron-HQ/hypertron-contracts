#!/usr/bin/env bash
#
# Build the @hypertron/prover npm package for both the browser (Next.js UI) and
# Node.js (backend relayer/indexer). Produces a single publishable directory at
# prover-wasm/pkg with per-target subfolders:
#
#   pkg/
#     web/    <- ESM, `await init()` before use (browser / bundlers)
#     node/   <- CommonJS, loads synchronously (Node.js)
#     package.json  <- unified @hypertron/prover manifest (conditional exports)
#     README.md
#
# Requires: wasm-pack (cargo install wasm-pack) and the wasm32-unknown-unknown
# target (rustup target add wasm32-unknown-unknown).
set -euo pipefail
cd "$(dirname "$0")"

OUT="pkg"
NAME="hypertron_prover"

rm -rf "$OUT"

echo "==> building web target (ESM)"
wasm-pack build --release --target web    --out-dir "$OUT/web"  --out-name "$NAME"

echo "==> building nodejs target (CommonJS)"
wasm-pack build --release --target nodejs --out-dir "$OUT/node" --out-name "$NAME"

# wasm-pack writes a `.gitignore` containing `*` into each out-dir. npm pack
# respects those files and would publish an empty package (README + package.json
# only). Strip them so web/ and node/ actually ship.
rm -f "$OUT/web/.gitignore" "$OUT/node/.gitignore"

# The per-target package.json files that wasm-pack writes into web/ and node/
# are kept on purpose: Node uses each subfolder's own manifest to pick the
# correct module format (ESM vs CJS). Our unified manifest sits on top.
cp package.json "$OUT/package.json"
cp README.md "$OUT/README.md"

echo "==> done. Publishable package at prover-wasm/$OUT"
echo "    npm pack ./prover-wasm/$OUT   # or: (cd prover-wasm/$OUT && npm publish --access public)"
