# Trusted Setup & Ceremony

Hypertron uses Groth16 (BLS12-381), which requires a **per-circuit trusted
setup**. There are three circuits, each with its own proving key (PK) and
verifying key (VK):

| Circuit    | Public inputs                                   | VK id (convention) |
|------------|-------------------------------------------------|--------------------|
| `deposit`  | `[cm, amount]`                                   | 1 |
| `unshield` | `[root, nullifier, recipient, amount, change_cm]`| 2 |
| `transfer` | `[root, nullifier, out_cm1, out_cm2]`            | 3 |

The security property: if **at least one** setup participant is honest and
destroys their secret ("toxic waste"), no one can forge proofs. A single
coordinator satisfies this **only if you trust that coordinator**. Mainnet TVL
requires a multi-party ceremony (below).

## Phase now — documented single-coordinator setup (dev / testnet)

This is the current, deliberately-simple path. It is reproducible and auditable,
but its soundness rests on one machine. **Do not guard real TVL with it.**

```bash
# One PK/VK per circuit. Use an independent, well-sourced seed per circuit and
# record it; the VK is what you publish + register on-chain.
cargo run -p hypertron-prover --release -- \
  setup --circuit deposit  --seed "$SEED_DEPOSIT"  --pk-out deposit.pk  --vk-out deposit.vk.json
cargo run -p hypertron-prover --release -- \
  setup --circuit unshield --seed "$SEED_UNSHIELD" --pk-out unshield.pk --vk-out unshield.vk.json
cargo run -p hypertron-prover --release -- \
  setup --circuit transfer --seed "$SEED_TRANSFER" --pk-out transfer.pk --vk-out transfer.vk.json
```

Then register each VK on-chain against the deployed verifier under the id above
(`register_vk`). See `scripts/deploy_testnet.sh` for the end-to-end flow.

Coordinator checklist:
1. Run on an **air-gapped** machine; generate seeds from a hardware RNG.
2. Publish the exact toolchain (`rustc` version, crate lockfile) so anyone can
   reproduce the VK from the circuit.
3. After extracting PKs/VKs, **destroy the seeds and the machine's memory/disk**.
4. Publish a transcript: circuit commit hash, seeds' destruction attestation,
   resulting VK hashes.

## Phase next — multi-party ceremony (before mainnet / real TVL)

Groth16 needs both a universal **Powers of Tau** phase and a **circuit-specific
Phase 2** contribution round.

1. **Powers of Tau (Phase 1):** reuse a large, well-known public ceremony (e.g.
   Perpetual Powers of Tau) sized for the circuit's constraint count.
2. **Phase 2 (per circuit):** many independent contributors each add randomness
   to the PK/VK; each publishes a contribution hash. Only one honest deleter is
   required for soundness.
3. Publish the full transcript and let third parties verify the final VK.

Tooling: `snarkjs` / `arkworks-phase2` interoperate with the arkworks 0.4 keys
this repo produces. The prover's `groth16::{pk_from_bytes, vk_json}` round-trip
is the integration seam — swap the `setup` step for ceremony output, keep
`prove`/`verify` unchanged.

## Upgrade path away from a trusted setup

If per-circuit ceremonies become operationally painful, migrate to a **universal
/ updatable** setup (PLONK/UltraHonk). The on-chain verifier is a pluggable seam
(`hypertron_transfer::VerifierApi`): a new backend contract implementing
`verify(vk_id, proof, public_inputs)` can replace Groth16 without touching the
pool, commitment tree, or nullifier registry. Circuits would be re-expressed in
the new proving system but the note format and public-input contracts stay.

## Rotation

VKs are addressed by id and stored in the verifier's persistent storage. To
rotate (new ceremony, fixed circuit): register the new VK under a **new id**,
point the pool's `*_vk_id` at it via a config upgrade, and retire the old id.
Never silently overwrite an in-use id while proofs are in flight.
