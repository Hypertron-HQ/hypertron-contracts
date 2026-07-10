# The Three-Layer Privacy Framework

To build a modular privacy protocol, we must separate *what we protect* from *how we protect it* and *what it costs*. Conflating these leads to monolithic, rigid designs.

This framework breaks payment privacy into three orthogonal layers. It serves as the design spine for the Hypertron Privacy Protocol, explaining exactly why the protocol is split into composable modules rather than a single "privacy" contract.

## Layer 1: Leakage (Security Properties)

This defines **what an adversary can learn**. Leakage is objective and immutable; every payment system has these dimensions, whether they are protected or exposed.

- **Sender Identity:** Who is paying?
- **Receiver Identity:** Who is getting paid?
- **Amount:** How much is moving?
- **Timing:** When did the payment occur?
- **Linkability:** Are these two transactions related?
- **Metadata:** Memos, IP addresses, asset types.

*Goal: Minimize leakage against a specific threat model.*

## Layer 2: Mechanisms (The Tools)

These are the **cryptographic and architectural tools** we use to close the leaks. Each mechanism targets specific leakage dimensions.

- **Relayers:** Decouples the sender's IP/fee-paying account from the transaction.
- **Commitments & Nullifiers:** Breaks on-chain linkability between deposit and withdrawal.
- **ZK Proofs (Groth16/Poseidon):** Hides identity and amount while proving validity.
- **Stealth Addresses:** Hides the receiver on the public ledger.
- **Batching & Delay:** Hides timing by mixing transactions in time.
- **View Keys / Selective Disclosure:** Exposes data only to authorized auditors.

*Goal: Combine tools into a composable protocol.*

## Layer 3: Tradeoffs (The Costs)

Privacy is never free. Every mechanism applied in Layer 2 incurs a cost in Layer 3.

- **Latency / Speed:** Waiting for batches, or generating heavy ZK proofs.
- **Cost (Gas/Compute):** On-chain verification metering, relayer infrastructure.
- **UX:** User friction (e.g., managing local state/notes, waiting for finality).
- **Compliance:** Friction with AML/KYC rules (unless mitigated by view keys/ASPs).
- **Complexity:** Developer burden to integrate.

*Goal: Optimize the balance based on the application's needs.*

---

## The Technique Mapping Matrix

This matrix maps Layer 2 (Mechanisms) against Layer 1 (Leakage blocked) and Layer 3 (Tradeoff incurred).

*Legend: 🟢 Strong protection / Low cost | 🟡 Partial protection / Med cost | 🔴 Little protection / High cost | ⚪ N/A*

| Technique | Sender | Receiver | Amount | Timing | Linkability | Metadata | Cost Impact | Speed Impact |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Relayer** | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 | 🔴 | 🟡 | 🟢 |
| **ZK Pool (Groth16)** | 🟢 | 🟢 | 🔴* | 🔴 | 🟢 | 🔴 | 🔴 | 🟡 |
| **Stealth Addresses** | 🔴 | 🟢 | 🔴 | 🔴 | 🟡 | 🔴 | 🟡 | 🟢 |
| **Batching** | 🔴 | 🔴 | 🔴 | 🟢 | 🟢 | 🔴 | 🟡 | 🔴 |
| **Confidential Tokens** | 🔴 | 🔴 | 🟢 | 🔴 | 🔴 | 🔴 | 🔴 | 🟡 |
| **Selective Disclosure**| ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | ⚪ | 🟡 | 🟢 |

*\* ZK Pools protect amounts only if the pool supports variable denominations; uniform pools leak the fixed amount.*

## Why This Drives the Hypertron Architecture

If a merchant only cares about Sender Identity leakage, forcing them to pay the massive compute cost (Layer 3) of a ZK Pool (Layer 2) is a failure of protocol design. A simple Relayer is sufficient.

If a treasury needs to hide Amount and Linkability, a Relayer is useless; they must pay the compute cost of ZK.

**This is why Hypertron is not a single contract.** It is a modular library where developers import only the mechanisms they need to block their specific leakage, paying only the tradeoffs they are willing to accept.

---

## Where Stellar Confidential Tokens Fit

Stellar shipped a **Confidential Tokens** developer preview (testnet): a wrapper contract that adds private balances and private transfer amounts to any SEP-41 token. A user deposits a normal token, the balance becomes a **Pedersen commitment on the Grumpkin curve**, transfers hide amounts, and the user withdraws back to the underlying token. Proofs are written in Noir and verified on-chain by an UltraHonk verifier using Protocol 25 host functions (BN254 + Poseidon).

The defining property: it is **confidentiality, not anonymity**. Sender and recipient addresses stay fully public on-chain; only amounts and balances are hidden. It also ships compliance features (per-account freeze, designated auditor keys via dual auditor ciphertexts).

### It solves exactly one leakage dimension

Mapped onto Layer 1, Confidential Tokens close **Amount** and leave everything else open:

| Layer | Sender | Receiver | Amount | Timing | Linkability | Metadata | Compliance |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Confidential Token** | 🔴 | 🔴 | 🟢 | 🔴 | 🔴 | 🔴 | 🟢 |
| **Hypertron (pool + relayer + batching)** | 🟢 | 🟢 | 🟡→🟢 | 🟢 | 🟢 | 🟡 | 🟢 |

### Strategic position: complement, not compete

The framework makes the relationship obvious — Confidential Tokens are a single Layer 2 mechanism that closes the **Amount** leak. Hypertron's mechanisms (privacy pool, relayer, batching, stealth addresses) close **Identity, Linkability, and Timing** — the leaks Confidential Tokens deliberately leave open.

This yields a clear interop story rather than a competitive one:

- **Value layer:** a confidential token can supply amount-hiding (amounts already private at the asset level).
- **Privacy layer:** Hypertron adds identity/linkability/timing privacy on top.
- **Together:** amount privacy (asset level) + identity/linkability privacy (protocol level) = a more complete privacy surface than either alone.

### Guardrail for originality

Hypertron treats the Confidential Token as **ecosystem context and a possible interop target**, not as something to wrap or rebuild. The core commitment / nullifier / verifier composition remains original Hypertron engineering. This keeps the "complete privacy" narrative while avoiding any dependency that would make the protocol read as a wrapper around someone else's implementation.

---

## Cryptographic Toolbox

The primitives available for building the protocol, and — critically — whether Soroban can **verify** them on-chain within the resource budget.

### The one principle that decides everything

Proving happens **off-chain** on the user's device (cost = UX, not gas). **Verification** happens **on-chain** and is **metered** (CAP-0046-10 budget). So the question for any primitive is never "is it good crypto" — it is *"can Soroban verify it cheaply enough?"* This single lens sorts the entire toolbox.

### Primitive selection matrix

*Legend: 🟢 recommended / cheap to verify | 🟡 usable with care | 🔴 impractical on-chain today*

| Primitive | What it gives you | Soroban support | Verdict |
| :--- | :--- | :--- | :---: |
| **Poseidon / Poseidon2** | Note commitments, Merkle membership, nullifiers, in-circuit hashing, Fiat-Shamir | Native host fn (CAP-0075) | 🟢 |
| **Pedersen commitments** | Homomorphic **amount** hiding (add/subtract balances without decrypting) | BN254/Grumpkin, BLS12-381 host fns | 🟢 |
| **Groth16 SNARK** | Spend validity + range, **constant, cheap verify** (3 pairings) | BN254 (CAP-0074/0080) or BLS12-381 (CAP-0059) | 🟢 |
| **PLONK / UltraHonk** | Same as Groth16 but **universal setup** (no per-circuit ceremony) | BN254 + Poseidon host fns (ecosystem confidential-token path) | 🟢 |
| **Twisted ElGamal encryption** | Encrypt amounts to recipient/auditor (view keys, auditor ciphertexts) | Curve host fns | 🟢 |
| **ECDH + Stealth addresses** | **Receiver** privacy via one-time addresses | Curve host fns | 🟢 |
| **Merkle trees (Poseidon)** | Membership / anonymity set for the pool | Native hashing (CAP-0075) | 🟢 |
| **Nullifier PRF** | Double-spend prevention without linking to the note | Poseidon-based | 🟢 |
| **BLS signatures (aggregate/threshold)** | Multi-party approval, compact multisig for auth/policy | BLS12-381 (CAP-0059) | 🟡 |
| **KZG polynomial commitments** | Building block for PLONK-style systems | Pairings via BLS12-381 | 🟡 |
| **VRF (verifiable random function)** | Unlinkable one-time address derivation, unbiased randomness | Build on curve host fns | 🟡 |
| **Bulletproofs** | Range proofs with **no trusted setup** | No native verify; hand-rolled MSM, linear cost | 🟡 |
| **STARKs** | No setup, post-quantum | Hashing-heavy verify, no native support | 🔴 |
| **Linkable ring signatures** | Sender anonymity set without a pool | Verify cost scales with ring size | 🔴 |

### Key decisions to lock down

**1. Proof system: Groth16 vs UltraHonk.**

| | Groth16 | UltraHonk (Noir/Barretenberg) |
| :--- | :--- | :--- |
| On-chain verify cost | Cheapest (constant, 3 pairings) | Heavier but supported |
| Trusted setup | **Per-circuit ceremony** (a liability) | Universal/updatable (one ceremony) |
| Ecosystem alignment | RISC Zero verifier exists | Used by Stellar's confidential token |
| Tooling | Circom / snarkjs, arkworks | Noir |

Recommendation: default to **Groth16 on BN254** for the cheapest verify and simplest audit story; keep UltraHonk as an alternate backend behind the `ProofVerifier` trait if avoiding per-circuit setup becomes important.

**2. Range proofs: fold into the SNARK, don't bolt on Bulletproofs.**
A general SNARK proves "amount is in range" *inside* the circuit for free. A standalone Bulletproof only makes sense if you specifically want zero trusted setup for range statements — and even then, UltraHonk (already supported) is a better on-chain fit than a hand-rolled Bulletproof verifier.

**3. Curve: BN254 as the default.**
BN254 (CAP-0074/0080) aligns with Circom/Noir tooling and the ecosystem's Grumpkin/BN254 confidential-token stack. BLS12-381 (CAP-0059) is the alternate — pick it only if a specific proving backend requires it.

### The framing that matters

Hypertron is **not inventing new cryptography**. It composes **standard, Soroban-verifiable primitives** — Poseidon, Pedersen, Groth16/Honk, ECDH, stealth addresses — into a modular privacy layer. That is both more credible to reviewers and less risky than betting the protocol on a primitive (Bulletproofs, STARKs) the chain cannot cheaply verify yet. The originality is in the **composition, module boundaries, and API**, not in the underlying math.
