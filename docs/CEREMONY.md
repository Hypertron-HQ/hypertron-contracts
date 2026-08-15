# Trusted Setup

Hypertron uses Groth16, which requires circuit-specific setup. Deposit,
unshield, and transfer each have a distinct proving key and verification key.

The current testnet keys come from a single-coordinator setup. Reaching a
production deployment means completing every step below.

```mermaid
flowchart LR
    A["Freeze circuits, parameters,<br/>public-input order"] --> B["Multi-party ceremony<br/>per circuit"]
    B --> C["Publish transcript<br/>and artifact hashes"]
    C --> D["Independent<br/>transcript verification"]
    D --> E["Fresh deploy,<br/>register ceremony VKs"]
    E --> F["External audit and<br/>end-to-end tests"]
    F --> G["Retire the single-coordinator<br/>deployment"]
```

## Current setup

The CLI `setup` command draws its randomness from the OS CSPRNG
(`rand_core::OsRng`). Nothing is seeded from a constant, and no seed material is
written to disk — arkworks consumes the randomness in-stream, so there is no
toxic-waste artifact to store or destroy.

```bash
cargo run -p hypertron-prover -- setup \
  --circuit deposit \
  --pk-out vk/deposit.pk.bin \
  --vk-out vk/deposit.vk.json
```

`scripts/deploy_testnet.sh` runs this for all three circuits when
`GENERATE_KEYS=1`, and prints the artifact hashes to record in the deployment
manifest.

**What this does and does not buy.** The keys are not reproducible from the
repository, so an arbitrary reader cannot forge proofs. But a single coordinator
ran the setup, and that process observed the toxic waste in memory. The
coordinator could have captured it. Trust in the current deployment is trust in
one operator, which is precisely the assumption the ceremony below removes. Do
not describe this as a ceremony.

Mitigations that make the single-coordinator claim as strong as it can be: run
on a freshly booted machine with swap disabled, offline, and reboot afterward.
None of this is externally verifiable, which is the point.

### History

Before 2026-08-15 the CLI took a `--seed u64` defaulting to `1`, and the testnet
deployment was generated from it. That made the toxic waste recoverable by
anyone who read the repository, so proofs were forgeable by anyone. Those keys
have been retired and the on-chain verifying keys rotated.

The `u64` seed has been removed from the setup API rather than merely
re-defaulted, because 64 bits is not a cryptographic secret regardless of how
well it is sourced: an attacker recovers it by deriving one scalar per candidate
and comparing against the published `alpha_g1`. Reproducible randomness is still
available for tests through `groth16::insecure_dev_rng`, and from the CLI via
`--insecure-dev-seed`, which refuses to run unless `HYPERTRON_INSECURE_DEV_SETUP=1`
is set and stamps `insecure_dev_seed` into the emitted `vk.json` so a forgeable
key stays self-identifying. Both the deploy script and
`scripts/verify_deployment.sh` refuse to accept a key carrying that marker.

## Production requirement

Before mainnet, Hypertron must run an independently reviewed multi-party
ceremony for the final circuit set. The ceremony must ensure that the final
toxic waste is unknown as long as at least one participant contributes honestly
and destroys their secret.

The repository currently provides single-coordinator setup tooling, not a
complete MPC coordinator. Do not describe the production ceremony as shipped.

### Known obstacle: Phase 1 on BLS12-381

The curve is not a free choice. [CAPS.md](CAPS.md) records BLS12-381 as a hard
dependency: a pairing check is not feasible in pure contract WASM within
Soroban's resource limits, so the CAP-0059 host functions are required, and the
Poseidon note format is tied to that scalar field. This rules out reusing
Ethereum's perpetual powers-of-tau and the mature BN254 tooling around it.

That leaves two paths, and choosing between them is an open decision that should
be costed before committing to a mainnet timeline:

1. **Reuse an existing BLS12-381 Phase-1 transcript** (the Zcash Sapling powers
   of tau, or Filecoin's extension of it). The obstacle is tooling: those
   transcripts and the Phase-2 implementations around them are bellman-based,
   while these circuits are arkworks. Converting a Phase-2 output into an
   `ark_groth16::ProvingKey` is real work with no off-the-shelf path. Confirm
   the transcript degree covers the final constraint counts before relying on
   this.
2. **A universal / updatable setup**, as noted in the ecosystem comparison in
   `docs/privacy-framework.md`. This removes the per-circuit Phase 2 entirely,
   at the cost of a different proof system and a new on-chain verifier.

Publishing an honest assessment of this trade-off is worth more to reviewers
than an optimistic ceremony schedule.

## Freeze before ceremony

Freeze all of the following first:

- Circuit source and dependency lockfile.
- Merkle depth and Poseidon parameters.
- Public-input order and serialization.
- Value bit width.
- Transfer arities and VK-ID allocation.
- Reproducible build environment and artifact format.

The planned 2-input and 4-input transfer circuits must land before the ceremony.
Any constraint change after setup requires new proving and verification keys,
new registrations, and potentially a new audit.

## Ceremony deliverables

A production ceremony should publish:

1. Tagged source commit and dependency lockfile.
2. Reproducible circuit identifiers or constraint-system hashes.
3. Coordinator implementation and operating instructions.
4. Participant list and contribution order.
5. Signed contribution receipts and transcript.
6. Hashes and sizes of every proving and verification key.
7. Independent transcript verification results.
8. Attestation that contribution secrets were destroyed.
9. Exact mapping from circuit/version to on-chain VK ID.
10. Fresh deployment manifest containing registered key hashes and contract IDs.

Proving keys may be publicly distributed after a sound ceremony. Security
depends on destruction of contribution secrets, not secrecy of the final
proving key.

## Deployment procedure

After transcript verification:

1. Place ceremony outputs in a clean `VK_DIR`.
2. Build contract WASM from the tagged source.
3. Run the deployment script with `GENERATE_KEYS=0` (the default), so it uses
   the ceremony output rather than generating anything.
4. Register each ceremony verification key under its documented ID.
5. Initialize a fresh pool pointing to the fresh verifier.
6. Record artifact hashes and contract IDs in the deployment manifest, then run
   `./scripts/verify_deployment.sh` and publish the output.
7. Run end-to-end deposit, transfer, double-spend rejection, and unshield tests.
8. Retire the single-coordinator deployment in user interfaces.

Example shape:

```bash
VK_DIR=/path/to/verified-ceremony-output \
TOKEN=<asset-contract-id> \
./scripts/deploy_testnet.sh
```

Production deployment additionally requires the audit and operational controls
listed in [SECURITY.md](SECURITY.md).
