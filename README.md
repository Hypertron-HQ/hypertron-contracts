# Hypertron Privacy Protocol

Shielded payments on Stellar / Soroban: convert transparent XLM or USDC into
**private notes**, move value without revealing sender, receiver, or amount, and
exit back to a normal address when needed. Auditors can verify history with a
**viewing key** (read-only).

```
Wallet (USDC / XLM) ──shield──► Notes (private) ──transfer──► Notes
                                      │
                                      └──unshield──► Any wallet (public exit)
```

## What's in this repo

| Crate | Role |
|---|---|
| `contracts/commitment` | Poseidon Merkle tree of note commitments |
| `contracts/nullifier` | Double-spend registry |
| `contracts/verifier` | On-chain Groth16 verifier (BLS12-381) |
| `contracts/transfer` | Shielded pool: `deposit` / `unshield` / `transfer` |
| `contracts/compliance` | Optional exit allow/deny policy |
| `prover` | Circuits, viewing-key crypto, `hypertron-prove` CLI |
| `prover-wasm` | Browser + Node WASM package (`@hypertron/prover`) |
| `examples/merchant-settlement` | Thin reference consumer of the public API |

Notes are **value-committed**: `cm = Poseidon(Poseidon(n, k), v)`. Three circuits
enforce deposit binding, unshield conservation (`v = amount + change`), and
private transfer balance (`v_in = v1 + v2`) with 64-bit range checks.

## Privacy model (honest)

| Hidden | Not hidden |
|---|---|
| Sender address (via relayer) | That a tx happened / its hash |
| Receiver address (private transfer) | Shield / unshield amount & exit address |
| Amount (in-pool transfers) | Timing (no batching yet) |
| Deposit ↔ spend linkage | — |

Viewing keys decrypt note payloads off-chain for compliance. They cannot spend.

## Live testnet

Current deployment (native XLM SAC). Source of truth:
[`deployments/testnet.json`](deployments/testnet.json).

| Role | Contract ID |
|---|---|
| **Pool** | `CCXVZOJB67J7ZBQG2UTZCFJ3ZSAMDLSBB62B7KLZNNLO4WQDD3KX6BYP` |
| Commitment | `CATYUTIG5MYWEGOOIKG5FU6XLO3YBO5NRGVSW4QQSOYSPRVGCOW3QWSJ` |
| Nullifier | `CCEAQ5CYOITD6D7JQ5POGOJAJJV2OAYFDVSAOQVAMBW56HW5K2ZT5WAW` |
| Verifier | `CCHSL7YSPSCT62DBUSCG4CKBJ2I4U4JSBR4RE3YIEGNSEUYXYY7BDIEP` |
| Token (XLM SAC) | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` |

VK ids: deposit=`1`, unshield=`2`, transfer=`3`.

This deploy reuses the existing dev-only verifying keys. Fine for integration;
not for real TVL. Proving keys live under `vk/*.pk.bin` locally (gitignored).

[Pool on Stellar Lab →](https://lab.stellar.org/r/testnet/contract/CCXVZOJB67J7ZBQG2UTZCFJ3ZSAMDLSBB62B7KLZNNLO4WQDD3KX6BYP)

## Quick start

**Prereqs:** Rust toolchain, `wasm32v1-none` target, [Stellar CLI](https://developers.stellar.org/docs/tools/cli) (for deploy).

```bash
# Build contracts (WASM)
cargo build --release --target wasm32v1-none

# Run tests (contracts + prover; e2e Groth16 tests take ~1–2 min)
cargo test --workspace
cargo test -p hypertron-prover

# Prover CLI
cargo run -p hypertron-prover -- --help
cargo run -p hypertron-prover -- setup --circuit deposit --pk-out deposit.pk --vk-out deposit.vk.json
cargo run -p hypertron-prover -- keygen

# WASM npm package (browser + Node)
cd prover-wasm && ./build.sh
```

### Deploy (testnet)

```bash
stellar keys generate hypertron --network testnet   # skip if identity exists
stellar keys fund hypertron --network testnet

# Native XLM SAC on testnet (or set TOKEN to another SAC)
DEV_SETUP=1 TOKEN=CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC \
  ./scripts/deploy_testnet.sh
```

Then update [`deployments/testnet.json`](deployments/testnet.json) with the printed IDs.

## Flows

1. **Shield (`deposit`)** — pull tokens in; prove the commitment opens to `amount`.
2. **Transfer (`transfer`)** — spend one note → two notes; no public address or amount. Relayer-submittable.
3. **Unshield (`unshield`)** — pay a public recipient; keep change in the pool. Relayer-submittable.

One pool per asset (e.g. separate XLM and USDC pools). Apps can show a unified shielded balance.

## Docs

| Doc | Contents |
|---|---|
| [docs/app-integration.md](docs/app-integration.md) | Build a wallet on these contracts; explorer example |
| [docs/smart-contracts.md](docs/smart-contracts.md) | Contract architecture & APIs |
| [docs/privacy-framework.md](docs/privacy-framework.md) | Leakage model |
| [docs/ceremony.md](docs/ceremony.md) | Trusted setup (dev → MPC) |
| [docs/operations.md](docs/operations.md) | TTL, monitoring, incidents |
| [docs/faq-and-roasts.md](docs/faq-and-roasts.md) | FAQ / roast answers |
| [docs/PRD.md](docs/PRD.md) | Product requirements |
| [docs/stellar-caps-seps.md](docs/stellar-caps-seps.md) | Relevant Stellar CAPs / SEPs |
| [prover-wasm/README.md](prover-wasm/README.md) | `@hypertron/prover` JS usage |

## Status

- Protocol contracts + prover: **built and tested** (incl. real-proof e2e lifecycle).
- Testnet pool: **deployed** — see [`deployments/testnet.json`](deployments/testnet.json).
- WASM client prover: **built** (`prover-wasm` → `@hypertron/prover`).
- Indexer / relayer / note scanner: **not in this repo** — see [app-integration.md](docs/app-integration.md).
- Mainnet: needs a **multi-party ceremony** and an **external audit** before real TVL.

## License

Apache-2.0
