# Hypertron Privacy Protocol — Product Requirements Document

**A plug-and-play, composable privacy layer for confidential payments on Stellar/Soroban.**

- **Document owner:** Sweta Karar
- **Status:** Draft for team review + SCF Build resubmission
- **Scope of this PRD:** The privacy protocol (a set of composable Soroban smart contracts) **and one** merchant confidential-settlement reference app that consumes it end-to-end on-chain.
- **Explicitly out of scope:** The broader B2B suite (multi-product dashboard, cross-chain treasury, business-ops agents). Removed deliberately in response to prior review feedback.

---

## 1. TL;DR

Today, any Stellar team that wants confidential payments has to build commitment schemes, nullifier tracking, and proof verification themselves. There is no shared, on-chain, plug-and-play privacy layer for Soroban.

Hypertron Privacy Protocol closes that gap. It is a set of small, independently auditable Soroban contracts — commitment tree, nullifier registry, on-chain proof verifier, confidential transfer, authorization, selective disclosure, and compliance hooks — that a developer composes to ship a confidential payment contract **without writing cryptography from scratch and without trusting an off-chain party.**

The centerpiece is a **real on-chain Groth16 verifier** built on Soroban's BLS12-381 host functions (CAP-0059, Protocol 22). This replaces the previous proof-of-concept's stubbed verifier and moves the privacy guarantee from "off-chain and trusted" to "verified on Stellar."

To prove the protocol is real and load-bearing, we ship **one** reference consumer: a merchant confidential-settlement flow that imports the public contracts exactly the way an external integrator would — so the contract is visibly wired to a product, not a disconnected demo.

---

## 2. How this addresses the SCF panel feedback

This PRD is a direct response to the SCF #44 Build Award review. Each objection is mapped to a concrete change below.

| Panel objection | Response in this PRD |
| --- | --- |
| **Scope too broad** — seven product lines for a two-person team in ~4.5 months. | Scope cut to **one** thing: a privacy protocol + one reference consumer. The dashboard, treasury, bridging, and all business-ops agents are removed (Section 4.2). |
| **Doesn't fit Open Track / not the team's own work** — the novel piece reused a third-party reference implementation. | The protocol is **built from scratch as original engineering** — our own contract architecture, module boundaries, storage model, verifier integration, and public API. No third-party reference implementation is used or vendored. Underlying math (Poseidon, Groth16, BLS12-381) is standard cryptography, credited as such, not copied application code. |
| **Privacy contract is a PoC with a stubbed verifier, not connected to the product; live path is off-chain and trusted.** | The **verifier is real and on-chain** (Section 9), using CAP-0059 BLS12-381 host functions. The reference merchant app (Section 11) consumes it through the public API, so the contract is wired to a product. No off-chain trusted verification in the funded deliverable. |
| **Doubts about Stellar command** — ~87% TypeScript / ~1.7% Rust; cited CAP-40 for fee bump when the mechanism is CAP-0015. | The deliverable is **Rust/Soroban-first**; TypeScript is confined to a thin client/reference UI. We correct the record: **fee bump is CAP-0015; CAP-0040 is the ed25519 signed-payload signer** (Appendix A). Deep Soroban work is demonstrated by the on-chain verifier and multi-contract composition. |
| **Ineligible deliverables** — business-ops agents (Sales, Marketing, CRM, ERP) do no Stellar-specific work. | **All removed.** Every deliverable in this PRD is Stellar/Soroban-specific Rust or a Stellar client directly exercising it. |
| **Rework recommendation** — scope to the payments core + merchant confidential-settlement layer, contract wired to product, real design-partner traction, ineligible agents removed. | This PRD **is** that rework: confidential-settlement layer as the core, contract wired to a reference product, a concrete design-partner plan (Section 13), and no ineligible agents. |

---

## 3. Problem & Opportunity

### 3.1 The problem

Soroban has the low-level cryptographic building blocks for privacy (BLS12-381 host functions since Protocol 22, Poseidon libraries), but no composable, plug-and-play privacy **layer**. Every team that wants confidential transfers for payroll, B2B settlement, invoicing, or treasury has to independently solve the same hard problems: commitment schemes, nullifier-based double-spend prevention, on-chain proof verification, and selective disclosure. That is slow, security-risky, and fragments the ecosystem instead of converging on a shared, auditable standard.

### 3.2 The opportunity

Whoever ships the first credible, on-chain, composable privacy layer for Soroban defines the standard other builders depend on. Hypertron becomes the team that maintains the privacy layer, not one app that happens to use privacy tech. Every external integration is both an ecosystem contribution and proof of technical credibility — a natural adoption flywheel.

---

## 4. Goals & Non-Goals

### 4.1 Goals

1. Ship a set of **composable Soroban contracts** for confidential payments, each small enough to audit on its own.
2. Ship a **real on-chain Groth16 verifier** on BLS12-381 (CAP-0059) — no stub, no off-chain trust.
3. Define a **clear composition pattern** so a developer builds a confidential payment contract by importing and combining modules, not by forking application code.
4. Publish the crate(s) to **crates.io** with semantic versioning and a public changelog.
5. Ship **reference documentation**: quickstart, module-by-module API reference, and a security/trust-assumptions page.
6. Ship **one reference consumer** — a merchant confidential-settlement flow — built using only the public API and deployed on testnet, proving the protocol is usable and load-bearing.
7. Achieve **meaningful automated test coverage** on the commitment, nullifier, and verifier modules before tagging v0.1.

### 4.2 Non-Goals (this phase)

- The broader B2B product suite: merchant dashboard, payment links, onboarding UI, cross-chain treasury, CCTP bridging.
- Business-ops agents (Sales, Marketing, CRM, ERP, risk, compliance automation) — removed entirely; ineligible and off-scope.
- A general-purpose zero-knowledge toolkit for arbitrary circuits — scoped specifically to confidential payment/settlement primitives.
- Multi-chain or EVM compatibility.
- A completed third-party security audit — flagged as a required milestone **before** production/mainnet marketing, not claimed as done in this phase.

---

## 5. Target Users

| Persona | Need | What success looks like |
| --- | --- | --- |
| **Soroban dApp developer (external)** | Add confidential transfers to a payments/fintech product without building cryptography in-house. | Imports the crate, follows the quickstart, ships a working confidential transfer with an on-chain verified proof in under a day. |
| **Stellar ecosystem team (treasury / payroll / invoicing)** | Hide amounts and counterparties while still proving correctness on request. | Composes confidential transfer + selective disclosure without understanding the underlying proof system. |
| **Hypertron reference app (internal)** | The same primitives an external developer gets — no internal-only path. | The merchant confidential-settlement flow depends on the public crate, exactly like an external integrator would. |

---

## 6. Vision & Principles

**Vision:** Hypertron Privacy Protocol is the plug-and-play privacy layer for Soroban — a set of composable, auditable Rust contracts that let any Stellar developer add confidential payment logic without writing cryptography from scratch and without trusting an off-chain party.

**Principles:**

1. **On-chain by default.** The privacy guarantee is verified on Stellar, not asserted off-chain. No trusted off-chain verifier in the core path.
2. **Composability over configuration.** Small, focused contracts developers mix and match — not one monolith.
3. **Secure by default.** The safe path is the default path; unsafe behavior requires deliberate opt-in.
4. **Minimal, auditable core.** Every module is small enough to audit on its own.
5. **Standards-first.** Clear interfaces (traits), not just implementations, so the ecosystem can build interoperable implementations against the same contract shape.
6. **Documentation is part of the product.** A layer nobody can integrate without reading the source has failed, regardless of code quality.

---

## 7. What We're Building — The Protocol

Modeled on the pattern of small, composable contracts rather than one large privacy monolith. Each module is scoped to be independently understandable and auditable.

| Module | What it does | Why it's separate |
| --- | --- | --- |
| **Commitment & Note Engine** | Merkle commitment tree + note creation/spending logic. Commitment/hash function behind a trait so it is swappable. | The core cryptographic primitive — smallest possible surface area, easiest to audit in isolation. |
| **Nullifier Registry** | Double-spend prevention: tracks spent notes via nullifier-set storage and lookup. | A single, focused responsibility every confidential transfer depends on. |
| **Proof Verifier** | **Real on-chain Groth16 verifier** on BLS12-381 (CAP-0059), behind a trait so other proving systems can be added later. | Decouples the protocol from a single backend and — critically — makes verification real, not stubbed. |
| **Confidential Transfer Primitive** | The composed "send a hidden amount" logic, built from the three modules above. | The first thing most developers reach for — a ready-made composition. |
| **Authorization** | Role/permission primitives controlling who can spend or view a note or account. | Authorization is a distinct concern from confidentiality, reused across many contract shapes. |
| **Selective Disclosure / View Keys** | Lets a note holder prove transaction details to a specific party (e.g., an auditor) without revealing them publicly. | Makes the protocol usable for real compliance, not just anonymity — modular since not everyone needs it. |
| **Compliance Policy Hooks** | Pluggable allow/deny-list and policy-check interface an application can attach without touching core logic. | Keeps compliance logic out of the trusted cryptographic core. |
| **Testing & Simulation Harness** | Developer-facing utilities to simulate confidential transfers against a local Soroban sandbox. | Lowers the barrier to safe integration; testing tools as a first-class deliverable. |

**Delivery phasing (feasibility-driven, see Section 15):**
- **v0.1 (funded core):** Commitment, Nullifier, Verifier, Confidential Transfer, meta-crate, Testing Harness + one reference consumer + docs.
- **v0.2 (stretch / next phase):** Authorization, Selective Disclosure, Compliance Policy Hooks, external audit, SEP draft.

---

## 8. Architecture & Composition Pattern

The protocol ships as a Cargo workspace of small crates so a developer only pulls in what they need:

```text
hypertron-privacy/
├── hypertron-commitment/   // commitment tree + note engine
├── hypertron-nullifier/    // nullifier registry
├── hypertron-verifier/     // on-chain Groth16 verifier (BLS12-381) + verifier trait
├── hypertron-transfer/     // confidential transfer primitive (composes the above)
├── hypertron-auth/         // spend/view authorization            (v0.2)
├── hypertron-disclosure/   // selective disclosure / view keys     (v0.2)
├── hypertron-policy/       // compliance policy hooks              (v0.2)
├── hypertron-testkit/      // testing & simulation harness
├── hypertron-privacy/      // meta-crate re-exporting the common set
└── examples/
    └── merchant-settlement/ // reference consumer (Section 11)
```

Each module is exposed as a Soroban contract trait a developer's own contract implements or composes against — an "import and extend" pattern adapted to Soroban's contract model (using constructors from CAP-0058 where appropriate).

---

## 9. Centerpiece: The Real On-Chain Verifier

This is the single most important technical deliverable and the direct answer to the "stubbed verifier / off-chain and trusted" objection.

### 9.1 What changes

- **Before (PoC):** `withdraw()` accepted a placeholder/stubbed proof check; the real privacy path ran off-chain and was trusted.
- **After (this PRD):** `hypertron-verifier` verifies a **Groth16 proof on-chain** using Soroban's BLS12-381 host functions introduced in **CAP-0059 (Protocol 22)** — specifically the pairing check exposed via `soroban_sdk::crypto::bls12_381`. A withdrawal only succeeds if the proof verifies on Stellar.

### 9.2 Why this is credible Soroban work

- BLS12-381 operations (G1/G2 arithmetic, `pairing_check`, `hash_to_g1`) are provided as **host functions** so contracts can verify pairing-based proofs within the resource budget. Groth16 verification reduces to a fixed set of curve operations plus one multi-pairing check — a natural fit for these host functions.
- The verifier is structured as a **trait** (`ProofVerifier`) with a concrete Groth16/BLS12-381 implementation, so alternative backends can be added without changing calling contracts.
- Verification keys are treated as versioned, on-chain-registered artifacts, not hardcoded assumptions.

### 9.3 Interface sketch (illustrative, not final)

```rust
pub trait ProofVerifier {
    /// Verify a proof against a registered verification key and public inputs.
    /// Returns true only if the proof is valid on-chain.
    fn verify(
        env: &Env,
        vk_id: VkId,
        proof: Proof,
        public_inputs: Vec<BnScalar>,
    ) -> bool;
}
```

### 9.4 Trust boundary

- **On-chain:** proof verification, nullifier spend, commitment update, payout.
- **Off-chain (client):** witness generation and proof creation (the prover), which is standard for zk systems — the client proves; the chain verifies. No off-chain party is trusted to assert validity.

---

## 10. Developer Experience

Illustrative, not final — the goal is to show the shape of the experience:

```rust
use hypertron_transfer::ConfidentialTransfer;
use hypertron_verifier::Groth16Verifier;

#[contract]
pub struct MyPaymentContract;

#[contractimpl]
impl ConfidentialTransfer for MyPaymentContract {
    // default confidential deposit / withdraw logic,
    // backed by an on-chain Groth16 verifier
}
```

- A developer who wants a plain confidential transfer should be productive by importing one crate and following the quickstart — no cryptography background required.
- A developer who wants custom authorization or a different proof backend overrides just that module without touching the rest.

---

## 11. Reference Consumer: Merchant Confidential Settlement

To prove the protocol is load-bearing (and to wire the contract to a product, per the panel), we ship **one** reference consumer.

- **What it is:** a minimal merchant confidential-settlement flow — a customer pays; the merchant is credited and can settle/withdraw — with the amount and payer counterparty hidden, and correctness verified on-chain.
- **How it depends on the protocol:** it imports `hypertron-transfer` (and `hypertron-verifier`) through the **public crate API**, exactly as an external integrator would. No internal-only shortcut.
- **Why it matters:** the dependency is visible in the codebase and cannot be mistaken for a disconnected demo. This is the concrete resolution of "the contract isn't connected to the product."
- **Client footprint:** a thin TypeScript UI + prover harness. The privacy and settlement logic lives in Rust/Soroban contracts; TypeScript is confined to client interaction.

---

## 12. Distribution & Adoption Strategy

Distribution is the real product risk — the cryptography is tractable; adoption is the open question.

**Channels:**
- Publish to **crates.io** under semantic versioning with a public changelog.
- Publish a **documentation site**: quickstart, module reference, security/trust-assumptions page.
- Ship the merchant confidential-settlement reference built strictly against the public API.
- Draft the module interfaces in a form suitable for a **Stellar Ecosystem Proposal (SEP)**, positioning the protocol as a candidate standard.
- Developer-relations content: build-in-public updates, a technical writeup on the on-chain verifier, and a workshop/talk proposal at a Stellar event.

**Adoption metrics:**

| Metric | What it tells us |
| --- | --- |
| crates.io downloads | Baseline reach. |
| GitHub stars / forks | Ecosystem awareness. |
| External repos importing the crate | Real adoption — the metric that matters most. |
| Reference-app dependency | Confirms the protocol is genuinely load-bearing. |
| Issues / PRs from non-Hypertron contributors | A community forming around the standard. |
| Design-partner LOIs | Traction the panel asked to see (Section 13). |

---

## 13. Design-Partner Traction Plan

The panel asked for real design-partner traction. Concrete plan:

1. Identify 2–3 Stellar ecosystem teams with a genuine confidential-settlement need (payroll, invoicing, B2B settlement).
2. Secure lightweight letters of intent / integration commitments before or during the build.
3. Treat the merchant confidential-settlement reference as the first integration; a design partner's contract is the second.
4. Track integration progress publicly as an adoption signal.

*(Fill in named partners and LOI status here as they are secured.)*

---

## 14. Security & Trust Model

- Publish an explicit **trust-assumptions document**: what runs on-chain vs. off-chain, what the verifier trusts, and confirmation that no module custodies user funds beyond the pool's explicit escrow.
- Target **meaningful test coverage** on every core module before v0.1 is tagged for use outside Hypertron.
- Treat an **external security audit** as a required milestone before the protocol is described as production-ready or promoted for mainnet — not claimed complete in this phase.
- Publish a **versioned security disclosure policy** so integrators know how vulnerabilities are reported and patched.

---

## 15. Milestones & Deliverables

Structured so milestones map cleanly to fundable, verifiable tranches. Feasibility target: a two-person team over ~4.5 months.

| Milestone | Definition of done |
| --- | --- |
| **M1 — On-chain verifier** | `hypertron-verifier` verifies a Groth16 proof on-chain via BLS12-381 host functions; passing tests with real proof/vk fixtures. |
| **M2 — Core primitives** | `hypertron-commitment` and `hypertron-nullifier` extracted as standalone crates with meaningful test coverage. |
| **M3 — Confidential transfer** | `hypertron-transfer` composes the three core modules; end-to-end confidential deposit → on-chain-verified withdraw on testnet. |
| **M4 — Reference consumer** | Merchant confidential-settlement flow deployed on testnet, importing only the public API. |
| **M5 — Publish + docs** | v0.1 on crates.io with semver + changelog; docs site live (quickstart, module reference, trust-assumptions). |
| **M6 (stretch) — Disclosure + policy** | `hypertron-disclosure` and `hypertron-policy` shipped; audit scheduled; SEP draft submitted. |

---

## 16. Roadmap

| Phase | Focus | Exit criteria |
| --- | --- | --- |
| **Phase 0 (done)** | Working confidential-settlement PoC used internally (monolithic pool contract). | One working confidential deposit/withdraw, internal use, stubbed verifier. |
| **Phase 1 (this PRD / funded)** | Real on-chain verifier; extract core primitives into versioned crates; ship one reference consumer wired to the public API; docs. | v0.1 on crates.io; on-chain verified transfer on testnet; reference app depends on it; docs live. |
| **Phase 2** | Authorization, selective disclosure, compliance policy; external audit; SEP draft; developer outreach. | Audit scheduled/complete; SEP submitted; outreach shipped. |
| **Phase 3** | Ecosystem push: support external integrations, add pluggable verifier backends, lightweight governance for the standard. | Multiple external, independently-maintained integrations live. |

---

## 17. Team & Feasibility

- **Team size:** two.
- **Time:** ~4.5 months.
- **Why credible now:** Phase 0 already produced a working confidential-settlement contract (commitment + nullifier + pool logic). Phase 1 is primarily (a) replacing the stub with a real BLS12-381 verifier, (b) refactoring the working monolith into composable crates, and (c) wiring one reference consumer — not inventing from zero. The narrowed scope and reuse of existing working logic make the timeline realistic.

---

## 18. Risks & Open Questions

- **Verifier performance / resource budget.** On-chain pairing checks are metered. Risk: proof verification exceeds budget for realistic circuit sizes. Mitigation: benchmark early against CAP-0059 metering; keep public-input count minimal; validate on testnet in M1.
- **API stability.** Once external developers depend on the crate, breaking changes carry real cost — versioning discipline starts at v0.1.
- **Security stakes rise with adoption.** Bugs in a shared layer are more consequential than in one app — raises the urgency of the audit milestone.
- **Adoption is chicken-and-egg.** Few adopt an unaudited, undocumented layer — so docs and examples get disproportionate early investment.
- **Originality clarity.** Keep a written line between our original composition/API/architecture and the standard cryptographic building blocks (Poseidon, Groth16, BLS12-381) — especially given prior reviewer scrutiny.
- **Scope discipline.** It will be tempting to fold application features back in — the non-goals in Section 4.2 are revisited deliberately, not eroded by default.

---

## Appendix A — Correcting the CAP Record

The prior submission cited **CAP-40** for fee bump / sponsorship. That was incorrect and is corrected here:

- **CAP-0015 — Fee-bump transactions.** Lets an account pay the fee for an existing transaction without re-signing or managing sequence numbers. This is the mechanism the prior proposal described.
- **CAP-0040 — ed25519 signed payload signer.** A signer type for transaction signature disclosure (used in payment channels), *not* fee bump.

## Appendix B — Key Soroban Protocol References

- **CAP-0059 — Host functions for BLS12-381** (Protocol 22, Final). 11 host functions for BLS12-381 field/curve operations, including the pairing check used for Groth16 verification. Exposed via `soroban_sdk::crypto::bls12_381`.
- **CAP-0058 — Constructors for Soroban contracts** (Protocol 22). Constructor support used for clean module initialization.
- **CAP-0015 — Fee-bump transactions.** See Appendix A.
