# Architecture

Hypertron separates the shielded pool into small Soroban contracts and keeps
witness generation in a shared native/browser prover. This document describes
the deployed testnet architecture.

## Components

```mermaid
flowchart TD
    Client["Client prover / scanner"]
    Pool["contracts/transfer<br/>token custody and composition"]
    Tree["contracts/commitment<br/>depth-20 Poseidon Merkle tree"]
    Null["contracts/nullifier<br/>spent-nullifier set"]
    Ver["contracts/verifier<br/>Groth16 over BLS12-381"]
    Pol["contracts/compliance<br/>optional exit policy"]
    Indexer["Indexer<br/>separate repository"]

    Client -->|"proof, commitments, ciphertext blobs"| Pool
    Pool --> Tree
    Pool --> Null
    Pool --> Ver
    Pool -.->|"unshield only"| Pol
    Tree -->|"commitment events"| Indexer
    Indexer -->|"ordered leaves"| Client
```

| Component | Responsibility |
|---|---|
| `contracts/commitment` | Depth-20 Poseidon Merkle tree and recent-root history |
| `contracts/nullifier` | Persistent set of spent nullifiers |
| `contracts/verifier` | Admin-registered Groth16 verification keys and CAP-0059 pairing verification |
| `contracts/transfer` | Token custody and atomic deposit, transfer, and unshield composition |
| `contracts/compliance` | Optional allowlist/denylist check at transparent exit |
| `prover` | Circuits, setup/proof CLI, Merkle paths, note math, viewing encryption |
| `prover-wasm` | Browser/Node bindings for the same prover code |
| `examples/merchant-settlement` | Thin reference consumer using the pool's public client ABI |

The separate Hypertron indexer records commitment events and serves the ordered
leaf list required for witness construction. It is not a proof verifier and
cannot authorize a spend.

## Authority model

- The transfer pool is the only authority allowed to insert commitments.
- The transfer pool is the only authority allowed to mark nullifiers spent.
- The verifier admin may register or replace verification keys by ID.
- The optional compliance admin controls its allowlist or denylist.
- A depositor authorizes token transfer into the pool.
- Private transfer and unshield are permissionless to submit; correctness and
  authorization come from the proof.

Verifier-key administration is a security-sensitive deployment role: the admin
can replace registered keys. A production governance and upgrade policy is not
yet defined. Contract initializers are first-call setters and must be completed
immediately after deploy to avoid first-caller takeover.

## Flow: deposit

```mermaid
sequenceDiagram
    participant C as Client
    participant P as contracts/transfer
    participant V as contracts/verifier
    participant T as Token contract
    participant M as contracts/commitment

    C->>C: pick owner_pk, k, amount and prove cm opens to amount
    C->>P: deposit with proof, cm, amount and depositor auth
    P->>V: verify VK 1 over [cm, amount]
    V-->>P: accepted
    P->>T: move amount into pool escrow
    P->>M: insert cm
    P-->>C: emit Deposited with leaf index and amount
```

Deposits are transparent entries: source and amount are public.

## Flow: private transfer

```mermaid
sequenceDiagram
    participant R as Recipient
    participant S as Sender browser
    participant I as Indexer
    participant X as Submitter or relayer
    participant P as contracts/transfer

    R->>S: publish owner_pk and viewing public key
    I->>S: ordered leaves
    S->>S: build input Merkle path and prove 1-in/2-out with VK 3
    S->>S: encrypt owner_pk, k, v per output to its viewing key
    S->>X: proof, root, nullifier, both commitments, both blobs
    X->>P: transfer
    P->>P: check recent root, check nullifier unused, verify proof
    P->>P: mark nullifier spent and insert both output commitments
    P-->>R: emit PrivateTransfer with leaf indices and blobs
    R->>R: trial-decrypt and keep only blobs opening to a published commitment
```

No recipient address or amount is a public proof input. A production relayer is
still required to avoid exposing the sender through transaction submission.
Because blobs are not proof-bound, scanners must treat commitment match as the
source of truth and ignore decryptable blobs that do not open to the published
leaf.

## Flow: unshield

```mermaid
sequenceDiagram
    participant C as Client
    participant X as Submitter or relayer
    participant P as contracts/transfer
    participant Pol as contracts/compliance
    participant R as Public recipient

    C->>C: build Merkle path and prove membership, nullifier, conservation with VK 2
    C->>X: proof, root, nullifier, recipient, amount, change commitment
    X->>P: unshield
    P->>P: derive recipient field from the actual payout address
    P->>Pol: is_allowed for the exit recipient
    Pol-->>P: allowed
    P->>P: verify proof, spend nullifier, insert change commitment
    P->>R: pay amount
```

The exit recipient and amount are public. There is no on-chain encrypted change
blob for unshield; wallets must retain change note material themselves.

`PrivacyAttested` records the caller's claim flags after rejecting only
`timing=true`. Do not treat it as proof that receiver or amount were hidden.

## Indexer and data availability

The chain is authoritative for roots and spent nullifiers. The indexer provides
historical ordered leaves because RPC event retention is not a permanent data
availability layer.

Current limitation: the frontend consumes indexer leaves to build proofs but
does not yet independently recompute the full root and compare it with the
on-chain root before proving. Adding that check is the next trust-minimization
milestone. It would let clients reject incomplete or reordered leaf responses.

## Atomicity and state ordering

Soroban contract errors do not automatically make unsafe ordering acceptable.
The pool performs root, nullifier, compliance, and proof validation before
state mutation or token movement. On success it marks nullifiers, inserts new
commitments, and transfers tokens as one invocation.

## Storage lifetime

Contracts extend TTL for instance state, roots, leaves, verification keys, and
nullifiers. Nullifier retention is safety-critical: forgetting a spent
nullifier could permit a double-spend. Production operations must monitor and
extend contract state before archival thresholds.

## Repository boundaries

This repository is the cryptographic and contract core. It does not contain:

- Merchant accounts, payment-link APIs, or dashboard UI.
- The production indexer repository.
- A deployed relayer.
- Fiat anchor integration.
- Accounting exports or invoice-bound disclosure proofs.

Those application services consume this protocol; they are not part of its
trusted cryptographic core.
