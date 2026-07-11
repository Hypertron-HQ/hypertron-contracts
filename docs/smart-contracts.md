# Hypertron Smart Contracts — What to Build

The concrete smart-contract plan for the Hypertron Privacy Protocol. This maps the three-layer framework (see `privacy-framework.md`) onto actual Soroban contracts, in build order.

- **Language:** Rust / Soroban
- **Curve default:** BN254 (CAP-0074/0080), BLS12-381 (CAP-0059) as alternate
- **Hashing:** native Poseidon2 (CAP-0075)
- **Principle:** small, composable contracts — each does one job and is auditable on its own.

---

## 1. The build map

```text
PHASE 1 (funded core — build these 4 + 1 example)

  hypertron-commitment ─┐
  hypertron-nullifier  ─┼─► hypertron-transfer ─► examples/merchant-settlement
  hypertron-verifier   ─┘

PHASE 2 (later)

  hypertron-auth
  hypertron-disclosure
  hypertron-policy
```

**Phase 1 = 4 protocol contracts + 1 reference app. Do not start with 8.**

---

## 2. Phase 1 contracts

### 2.1 `hypertron-commitment` — Note & Merkle engine

**Job:** store note commitments in a Merkle tree so a spender can later prove "my note is in the pool" without revealing which one.

- Insert a commitment leaf (Poseidon hash of note secret + amount + owner data).
- Maintain the Merkle root as notes are added.
- Expose the current root and membership paths for off-chain proof building.
- Commitment/hash function behind a trait so it is swappable.

```rust
pub trait CommitmentTree {
    fn insert(env: &Env, leaf: BytesN<32>) -> u32;   // returns leaf index
    fn root(env: &Env) -> BytesN<32>;
    fn contains_root(env: &Env, root: BytesN<32>) -> bool; // recent-root check
}
```

**Storage:** leaves, current root, a small ring buffer of recent roots (so in-flight proofs stay valid).
**Events:** `commitment_added { index, leaf, root }`.

### 2.2 `hypertron-nullifier` — Double-spend registry

**Job:** make sure each note can be spent only once, without linking the spend back to the deposit.

- Record a nullifier when a note is spent.
- Reject any nullifier already seen.

```rust
pub trait NullifierRegistry {
    fn is_spent(env: &Env, nullifier: BytesN<32>) -> bool;
    fn mark_spent(env: &Env, nullifier: BytesN<32>); // panics if already spent
}
```

**Storage:** persistent set of spent nullifiers.
**Events:** `nullifier_spent { nullifier }`.

### 2.3 `hypertron-verifier` — On-chain proof verifier

**Job:** verify a zero-knowledge proof on-chain. This is the credibility centerpiece — no stub, no off-chain trust.

- Verify a Groth16 proof using BN254 host functions (CAP-0074/0080).
- Verification keys stored on-chain and referenced by id (upgradeable, versioned).
- Proof backend behind a trait so a second backend (e.g. UltraHonk / BLS12-381) can be added later.

```rust
pub trait ProofVerifier {
    fn register_vk(env: &Env, vk_id: u32, vk: Bytes);
    fn verify(
        env: &Env,
        vk_id: u32,
        proof: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> bool; // true only if the proof is valid on-chain
}
```

**Storage:** `vk_id -> verification key`.
**Events:** `proof_verified { vk_id }`, `vk_registered { vk_id }`.

### 2.4 `hypertron-transfer` — Confidential transfer (the composition)

**Job:** the value-committed shielded pool, built from the three contracts above.

Notes are **value-committed**: `cm = Poseidon(Poseidon(n,k), v)`. This binds a
value `v` into every commitment so the pool can enforce conservation in zero
knowledge (see §2.7). Three flows, each backed by its own verifying key:

- **deposit (shield):** pull tokens in and insert a commitment — but only after a
  proof that the commitment opens to exactly `amount` (deposit binding), so a
  transparent deposit cannot mint a note worth more than the tokens paid in.
- **unshield (exit):** verify membership + nullifier + value balance
  `v = amount + change`, spend the nullifier, re-insert the change note, pay a
  public recipient, and attest. Optionally gated by a compliance policy (§2.7).
- **transfer (fully private):** spend one note → two output notes. NO public
  recipient address and NO public amount — only the nullifier and two output
  commitments are on-chain, plus opaque encrypted payloads for discovery.

`unshield` and `transfer` require **no auth from the note owner** — they are
relayer-submittable, so the fee payer never links to the sender. Speaks SEP-41
for the underlying asset.

```rust
pub trait ConfidentialTransfer {
    fn deposit(env: &Env, from: Address, amount: i128, commitment: BytesN<32>, deposit_proof: Bytes) -> u32;
    fn unshield(
        env: &Env, proof: Bytes, root: BytesN<32>, nullifier: BytesN<32>,
        recipient: Address, amount: i128, change_commitment: BytesN<32>, claim: PrivacyLevel,
    ) -> PrivacyAttestation;
    fn transfer(
        env: &Env, proof: Bytes, root: BytesN<32>, nullifier: BytesN<32>,
        out_commitment_1: BytesN<32>, out_commitment_2: BytesN<32>, note_1: Bytes, note_2: Bytes,
    );
}
```

Public inputs per circuit: `deposit = [cm, amount]`,
`unshield = [root, nullifier, recipient, amount, change_cm]`,
`transfer = [root, nullifier, out_cm1, out_cm2]`. `unshield` **derives** the
`recipient`/`amount` field elements itself from the real payout args, so a valid
proof is bound to this exact payout — a relayer cannot redirect funds or change
the amount.

**This is where the modules snap together** — it imports the public API of the other three, exactly like an external developer would.

### 2.7 Value conservation, viewing keys, compliance

- **Value conservation + range proofs:** every note value is range-checked to
  64 bits and the balance equations (`v = amount + change`, `v = v1 + v2`) are
  enforced in-circuit, so field wraparound cannot mint value. Deposit binding
  ties the on-chain `amount` to the committed `v`.
- **Stealth / viewing keys:** the `hypertron-prover` `crypto` module implements
  ECIES-style note encryption (X25519 + ChaCha20-Poly1305). A recipient
  publishes a viewing pubkey; senders encrypt `(n,k,v)` to it and the ciphertext
  rides along the `transfer` event. Recipients (or auditors with the viewing
  key) scan and decrypt off-chain — read-only disclosure that cannot spend.
- **Compliance hook (`hypertron-compliance`):** an optional, swappable allow/deny
  list consulted ONLY at the `unshield` exit. Kept out of the ZK core, so it
  never weakens privacy and can be replaced or removed via config.

### 2.5 `examples/merchant-settlement` — Reference consumer

**Job:** prove the protocol is usable and wired to a product. A minimal merchant flow: customer pays, merchant is credited and can settle/withdraw — with amount and payer hidden, correctness verified on-chain.

- Imports `hypertron-transfer` (+ `verifier`) through the **public crate API only** — no internal shortcut.
- Thin TypeScript UI + prover harness on top; all privacy/settlement logic lives in the contracts.

### 2.6 `prover` — Off-chain prover + CLI (`hypertron-prove`)

**Job:** let integrators generate proofs and verifying keys outside the test
suite. This crate is the **canonical, single source** of the circuit and the
Groth16 tooling — `contracts/verifier`'s tests depend on this exact code, so what
you prove with the CLI is what the chain verifies. It is a native `std` crate and
is excluded from the wasm `default-members`.

```text
setup --circuit {deposit|unshield|transfer}  -> pk.bin + vk.json  (register once)
commitment --n --k --v                        -> cm = Poseidon(Poseidon(n,k), v)
nullifier  --n                                -> Poseidon(n, 0)
keygen                                         -> viewing keypair (disclosure)
deposit-proof                                  -> proof, public=[cm, amount]
unshield-proof                                 -> proof, public=[root, nf, recipient, amount, change_cm]
transfer-proof                                 -> proof, public=[root, nf, out_cm1, out_cm2] (+ recipient blob)
encrypt / decrypt                              -> note payload <-> viewing key
```

The proof commands rebuild the Merkle path from the ordered tree leaves, enforce
value balance, and self-verify before emitting. Note: `setup` is a local
deterministic setup for dev/test — production requires the ceremony in
[ceremony.md](ceremony.md).

---

## 3. How a payment flows through the contracts

```text
DEPOSIT (shield)
  user ──deposit(amount, cm, deposit_proof)──► transfer
        ├─► verifier.verify(deposit_proof, [cm, amount])?   (cm opens to amount)
        └─► commitment.insert(cm)

UNSHIELD (exit, relayer-submittable)
  user/relayer ──unshield(proof, root, nullifier, recipient, amount, change_cm)──► transfer
        ├─► compliance.is_allowed(recipient)?      (optional exit policy)
        ├─► commitment.is_known_root(root)?         (note is in the pool)
        ├─► verifier.verify(proof, [root, nullifier, recipient, amount, change_cm])?
        ├─► nullifier.is_spent(nullifier)? → mark_spent
        ├─► commitment.insert(change_cm)            (change stays shielded)
        └─► pay recipient

TRANSFER (fully private, relayer-submittable)
  user/relayer ──transfer(proof, root, nullifier, out_cm1, out_cm2, ct1, ct2)──► transfer
        ├─► verifier.verify(proof, [root, nullifier, out_cm1, out_cm2])?  (v_in = v1 + v2)
        ├─► nullifier.mark_spent(nullifier)
        └─► commitment.insert(out_cm1); insert(out_cm2)   (no address, no amount)
```

---

## 4. Signature feature: Verifiable Privacy Attestations

The differentiator. Turn the leakage model into an on-chain, provable object so "how private is this payment?" has a cryptographic answer instead of a marketing claim.

- Define the leakage dimensions as an on-chain bitmask.
- A transfer may only *claim* a dimension if the proof/mechanism actually backs it.
- On success, emit a `PrivacyAttestation` — a verifiable label of exactly which leaks the payment closed.

```rust
// bit flags for the leakage model
pub struct PrivacyLevel {
    pub sender:      bool,  // identity hidden
    pub receiver:    bool,  // receiver hidden (stealth address)
    pub amount:      bool,  // amount hidden (Pedersen/range proof)
    pub timing:      bool,  // timing hidden (batching/delay)
    pub linkability: bool,  // deposit↔withdraw unlinkable (pool + nullifier)
}

// emitted only after the contract verifies the claim matches the mechanisms used
pub struct PrivacyAttestation {
    pub level: PrivacyLevel,
    pub vk_id: u32,
    pub root:  BytesN<32>,
}
```

Why it matters: it operationalizes the framework, gives auditors/merchants a concrete guarantee, and is a genuine research contribution for the RFC/SEP. It's mostly orchestration on top of the 4 contracts — **no new cryptography.**

---

## 5. Phase 2 contracts (later)

| Contract | Job |
|---|---|
| `hypertron-auth` | Role/permission primitives — who can spend or view a note/account. |
| `hypertron-disclosure` | Selective disclosure / view keys — prove details to an auditor via twisted-ElGamal ciphertexts, without going public. |
| `hypertron-policy` | Pluggable allow/deny-list + policy checks an app can attach without touching the core. |

---

## 6. Cross-cutting engineering notes

- **Constructors (CAP-0058):** initialize each contract cleanly at deploy.
- **State archival / TTL (CAP-0046-12):** extend TTL on the nullifier set and commitment storage so they don't expire.
- **Budget metering (CAP-0046-10):** the binding constraint is on-chain verify cost — benchmark the verifier early against realistic public-input counts.
- **Unified asset events (CAP-0067):** clean indexing of shielded deposits/withdrawals.
- **Upgradeability (SEP-0049) + reproducible builds (SEP-0055/0058):** part of the trust story for a privacy library.

---

## 7. Definition of done (Phase 1)

- [ ] `commitment`, `nullifier`, `verifier` built with meaningful test coverage.
- [ ] `verifier` verifies a real Groth16 proof on-chain (BN254) — not stubbed.
- [ ] `transfer` composes the three; end-to-end confidential deposit → on-chain-verified withdraw on testnet.
- [ ] `merchant-settlement` deployed on testnet, importing only the public API.
- [ ] Privacy Attestation emitted and verifiable on a real transfer.
- [ ] v0.1 published with semver + changelog; docs live.
