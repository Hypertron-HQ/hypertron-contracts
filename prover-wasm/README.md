# @hypertron/prover

Client-side WebAssembly prover for the [Hypertron](../README.md) shielded pool.
It runs the exact same circuits and byte layout as the on-chain verifier, so a
browser wallet (or a Node backend) can build deposit / unshield / transfer
proofs and viewing-key note ciphertexts locally — secrets never leave the
device.

This package is compiled from the `hypertron-prover` Rust crate via
`wasm-bindgen` and wraps [`prover/src`](../prover/src). It ships both an ESM
(browser) and a CommonJS (Node) build.

## Build

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
./build.sh          # from this directory; output lands in ./pkg
```

Publish (once versioned):

```bash
cd pkg && npm publish --access public
```

## What it does NOT bundle

Proving keys are large (megabytes) and circuit-specific, so they are **not**
embedded. Fetch the `pk.bin` produced by the trusted-setup ceremony (see
[`docs/CEREMONY.md`](../docs/CEREMONY.md)) and pass its bytes to each proof
function. Only the small verifying keys live on-chain (registered via
`register_vk`).

## API

All amounts/values are decimal **strings** (JS numbers lose precision past
2^53). Field elements accept decimal or `0x`-hex. Every proof function returns a
JSON **string** whose fields line up 1:1 with the contract call arguments.

| function | needs pk | returns (parsed JSON) |
| --- | --- | --- |
| `owner_pk(spend_sk)` | no | `"0x…"` public owner key |
| `commitment(owner_pk, k, v)` | no | `"0x…"` note commitment |
| `nullifier(spend_sk, k)` | no | `"0x…"` nullifier |
| `merkle_root(leaves_json)` | no | `"0x…"` depth-20 root |
| `keygen(seed?)` | no | `{ view_secret, view_pub }` |
| `encrypt_note_blob(view_pub, owner_pk, k, v)` | no | `"0x…"` blob |
| `decrypt_note_blob(view_secret, blob)` | no | `{ owner_pk, n, k, v }` |
| `deposit_proof(pk, params)` | yes | `{ commitment, proof, public_inputs }` |
| `unshield_proof(pk, params)` | yes | `{ root, nullifier, change_cm, proof, public_inputs }` |
| `transfer_proof(pk, params)` | yes | `{ root, nullifier, out_cm1, out_cm2, proof, public_inputs, recipient_blob?, change_blob? }` |
| `transfer_2_proof(pk, params)` | yes | `{ root, nullifiers, out_cm1, out_cm2, proof, public_inputs, recipient_blob?, change_blob? }` |
| `transfer_4_proof(pk, params)` | yes | `{ root, nullifiers, out_cm1, out_cm2, proof, public_inputs, recipient_blob?, change_blob? }` |

`params` is a JSON string. `spend_sk` is required only for spending proofs and
is never included in encrypted note blobs:

- **deposit**: `{ owner_pk, k, amount }`
- **unshield**: `{ spend_sk, k, v, index, leaves: ["0x…"], recipient_field, amount, change_k, depth? }`
- **transfer**: `{ spend_sk, k, v, index, leaves, out1_owner_pk, out1_k, out1_v, out2_owner_pk, out2_k, out2_v, recipient_view?, self_view?, depth? }`
- **transfer-2 / transfer-4**: `{ spend_sk, inputs: [{ k, v, index }, …], leaves, out1_owner_pk, out1_k, out1_v, out2_owner_pk, out2_k, out2_v, recipient_view?, self_view?, depth? }` (`inputs` length 2 or 4)

Proof randomness is drawn from the platform CSPRNG and is not configurable. The
proof functions previously accepted a `seed`; a fixed seed makes a Groth16 proof
a deterministic function of its witness, which makes repeat proofs of the same
statement byte-identical and lets a guessed witness be confirmed by
recomputation. A `seed` field is now ignored if passed.

Legacy aliases `n`, `out1_n`, and `out2_n` are accepted for compatibility, but
new integrations should use the explicit owner-key names.

`recipient_view` encrypts out1 (the recipient's note) into `recipient_blob`;
`self_view` encrypts out2 (the payer's change note) into `change_blob`, so the
payer can rediscover their change after a browser wipe. Both blobs are emitted
on-chain by the transfer contract, so pass both keys for any real transfer.
They are **not** bound by the transfer proof: a submitter can alter or drop
them without invalidating the proof. Scanners must verify that decrypted notes
open to the published commitments.

`recipient_field` is `sha256(xdr(recipient_address))` (32-byte hex) — the same
value the transfer contract derives on-chain via `Address::to_xdr`, which
serializes the full **ScVal**, not the bare `ScAddress`. From JS that is
`hash(Address.fromString(a).toScVal().toXDR("raw"))`; hashing `toScAddress()`
omits the 4-byte discriminant and the proof will fail to verify. `leaves` is the ordered list of
inserted note commitments (from the indexer) used to rebuild the Merkle path.

## Usage — browser (ESM)

```js
import init, { unshield_proof } from "@hypertron/prover";

await init(); // loads the .wasm; call once

const pk = new Uint8Array(await (await fetch("/keys/unshield.pk.bin")).arrayBuffer());

const out = JSON.parse(unshield_proof(pk, JSON.stringify({
  spend_sk, k, v: "1000",
  index,
  leaves,               // string[] of 0x commitments from the indexer
  recipient_field,      // sha256(xdr(address)) hex
  amount: "700",
  change_k,             // change remains owned by Poseidon(spend_sk, 0)
})));

// out.proof / out.root / out.nullifier / out.change_cm / out.public_inputs
// feed straight into the transfer contract's `unshield` invoke via the Stellar SDK.
```

## Usage — Node (CommonJS)

```js
const { readFileSync } = require("node:fs");
const prover = require("@hypertron/prover"); // no init() needed for the node build

const pk = readFileSync("./keys/transfer.pk.bin");
const out = JSON.parse(prover.transfer_proof(pk, JSON.stringify({
  spend_sk, k, v: "1000",
  index, leaves,
  out1_owner_pk, out1_k, out1_v: "600",
  out2_owner_pk, out2_k, out2_v: "400",
  recipient_view, // optional: also returns out.recipient_blob to emit on-chain
  self_view,      // optional: encrypted payer change for recovery
})));
```

A relayer would take `out.proof` + the public fields and submit the
`unshield` / `transfer` invocation, paying the fee — the note owner never signs.
