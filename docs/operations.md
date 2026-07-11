# Operations Runbook

How to run, monitor, and recover the Hypertron shielded pool. Pairs with
[ceremony.md](ceremony.md) (trusted setup) and `scripts/deploy_testnet.sh`.

## Contracts & authorities

| Contract | Authority | Persistent state |
|---|---|---|
| `hypertron-commitment` | pool (transfer) | tree state, leaves, root history |
| `hypertron-nullifier`  | pool (transfer) | spent nullifiers |
| `hypertron-verifier`   | admin           | verifying keys by id |
| `hypertron-transfer`   | — (config)      | config (token, component ids, vk ids, compliance) |
| `hypertron-compliance` | admin           | allow/deny list (optional) |

## TTL / storage rent

All persistent entries are extended on write:

- commitment: leaves, root-history entries, instance — bumped on every `insert`.
- nullifier: each spent nullifier + instance — bumped on `mark_spent`
  (aggressively: a forgotten nullifier would permit a double-spend).
- verifier: each VK + instance — bumped on `register_vk`.
- transfer: instance — bumped on every deposit/unshield/transfer.

Thresholds: `~30 day` threshold, `~180 day` bump (`518_400` / `3_110_400`
ledgers). **Monitor** the oldest root-history and nullifier entries; if the pool
goes quiet, submit a keep-alive tx (any state-touching call) or call
`extend_ttl` via the SDK before the threshold.

## Monitoring (invariants to alert on)

- **Pool solvency:** `token.balance(pool)` must equal `Σ deposits − Σ unshield
  amounts`. Private transfers never change it. Alert on any drift.
- **Nullifier growth vs. failed verifies:** a spike in failed verifies may signal
  a bad VK registration or a client/circuit mismatch.
- **Root history depth:** proofs are accepted against the last 32 roots; if
  clients lag, they must re-fetch a recent root.
- **Unexpected `RecipientNotAllowed`:** compliance policy churn.

## VK rotation

1. Produce a new VK via a ceremony (see ceremony.md) for the SAME circuit.
2. `verifier.register_vk(new_id, vk)`.
3. Upgrade the pool config so `deposit_vk_id`/`unshield_vk_id`/`transfer_vk_id`
   points at `new_id`.
4. Keep the old id registered until all in-flight proofs drain, then retire it.
   Never overwrite an in-use id.

## Pause / upgrade policy

- The pool has no built-in pause switch in v0.1. To halt, rotate the pool config
  verifier to a contract that returns `false` (rejects all proofs) — deposits and
  exits stall safely; no funds move. Restore by pointing back at the real verifier.
- Contract upgrades: use Soroban upgradeability (SEP-0049) with a timelock; keep
  the commitment tree and nullifier registry immutable across upgrades so history
  and double-spend protection survive.

## Incident response

1. **Suspected soundness bug (value minting):** rotate verifier config to the
   reject-all contract immediately (freezes exits/transfers). Deposits are
   value-bound so they cannot mint; the risk is on the spend side.
2. **Leaked toxic waste (setup compromise):** same freeze, then run a fresh
   ceremony and rotate all three VKs.
3. **Leaked viewing key:** only disclosure is affected (read-only). Rotate the
   recipient's viewing key for future notes; past notes for that key are exposed
   to the holder of the leaked key.
4. **Compliance false-positive:** update the policy list; no crypto change needed.

## Pre-mainnet checklist

- [ ] Multi-party ceremony for all three circuits (ceremony.md).
- [ ] External audit of circuits + contracts.
- [ ] Reproducible WASM builds (SEP-0055/0058) published with VK hashes.
- [ ] Anonymity-set size monitoring (privacy is weak with few notes).
- [ ] Relayer/fee market live (otherwise sender leaks via gas payer).
- [ ] Solvency + nullifier monitoring wired to alerts.
