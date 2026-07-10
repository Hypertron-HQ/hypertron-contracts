# Stellar CAPs & SEPs — Knowledge Base

Reference for the Hypertron Privacy Protocol. One-line summaries of every Core Advancement Proposal (CAP) and the relevant Stellar Ecosystem Proposals (SEPs), plus which ones matter for this project.

- **CAP** = Core Advancement Proposal — changes to the Stellar **protocol/core**.
- **SEP** = Stellar Ecosystem Proposal — standards built **on top of** Stellar.
- "Ver" = protocol version the CAP shipped in.

> Quick correction for our own record: **fee bump = CAP-0015** (Protocol 13). **CAP-0040** is the *ed25519 signed-payload signer*, not fee bump. The prior SCF submission cited this wrong.

---

## 1. CAPs — Final / Accepted / Implemented

| CAP | Ver | One-liner |
|---|---|---|
| 0001 | 10 | `BUMP_SEQUENCE` op to advance an account's sequence number (invalidate pre-signed txs). |
| 0002 | 10 | Move signature verification to the transaction level instead of per-operation. |
| 0003 | 10 | Track trustline liabilities so offers are always asset-backed. |
| 0004 | 10 | Better rounding when crossing offers on the DEX. |
| 0005 | 11 | Surge pricing + fee-bidding for transaction sets. |
| 0006 | 11 | Add `MANAGE_BUY_OFFER` (buy-side DEX offers). |
| 0015 | 13 | **Fee-bump transactions** — one account pays another's fee without re-signing. |
| 0017 | – | Only bump `LastModifiedLedgerSeq` when an entry actually changes. |
| 0018 | 13 | Fine-grained auth: "authorized to maintain liabilities" trustline flag. |
| 0019 | 13 | Make `TransactionEnvelope` a union so new tx types can be added. |
| 0020 | 11 | `INITENTRY` markers to speed up the bucket list. |
| 0021 | 19 | **Generalized tx preconditions** — time/ledger bounds, min-seq-age, extra signers. |
| 0023 | 14 | **Claimable balances** for two-part / async payments. |
| 0024 | 12 | Add `PATH_PAYMENT_STRICT_SEND` to mirror strict-receive. |
| 0025 | 12 | Remove bucket shadowing to simplify the bucket list. |
| 0026 | 12 | Disable the network inflation mechanism. |
| 0027 | 13 | First-class multiplexed (`M...`) accounts. |
| 0028 | 13 | Clear consumed pre-auth signers on failed txs. |
| 0029 | 16 | Allow `ALLOW_TRUST` even when `AUTH_REQUIRED` isn't set. |
| 0030 | 13 | Remove `NO_ISSUER` operation result codes. |
| 0033 | 14/15 | **Sponsored reserves** — one account pays base reserves for another's entries. |
| 0034 | 14 | Preserve tx-set/close-time affinity during consensus nomination. |
| 0035 | 17 | **Asset clawback** — issuers can revoke issued assets. |
| 0038 | 18 | Native AMM / liquidity pools on the DEX. |
| 0040 | 19 | **Ed25519 signed-payload signer** — disclose a signature for a specific payload (payment channels). |
| 0042 | – | Structure transaction sets into multiple parts. |
| 0046 | 20 | Umbrella overview of the Soroban smart-contract platform. |
| 0046-01 | 20 | Wasm smart-contract runtime environment. |
| 0046-02 | 20 | Contract lifecycle (upload/deploy). |
| 0046-03 | 20 | Core smart-contract host functions. |
| 0046-05 | 20 | Contract data / storage model. |
| 0046-06 | 20 | Stellar Asset Contract (SAC) — classic assets in Soroban. |
| 0046-07 | 20 | Metered resource fee model for Soroban. |
| 0046-08 | 20 | Contract events / logging. |
| 0046-09 | 20 | On-chain network-configuration ledger entries. |
| 0046-10 | 20 | CPU/memory budget metering. |
| 0046-11 | 20 | Soroban authorization framework (`require_auth`). |
| 0046-12 | 20 | State archival / TTL interface for contract data. |
| 0051 | 21 | **secp256r1 (P-256) signature verification** host fn (passkeys). |
| 0053 | 21 | Separate TTL-extension host fns for instance vs code. |
| 0054 | 21 | Refined Wasm VM instantiation cost model. |
| 0055 | 21 | Streamlined Soroban module linking. |
| 0056 | 21 | Intra-transaction module caching. |
| 0058 | 22 | **Constructors for Soroban contracts** (run at deploy). |
| 0059 | 22 | **BLS12-381 host functions** (field/curve ops + pairing → Groth16/zk). |
| 0062 | 23 | Soroban live-state prioritization for performance. |
| 0063 | 23 | Parallelism-friendly transaction scheduling. |
| 0065 | 23 | Reusable cross-tx module cache. |
| 0066 | 23 | In-memory read resource type for fees. |
| 0067 | 23 | **Unified asset events** (standardized transfer events). |
| 0068 | 23 | Host fn to get the executable/type behind an address. |
| 0069 | 23 | String↔Bytes conversion host functions. |
| 0070 | 23 | Configurable SCP consensus timing parameters. |
| 0071 | 27 | Authentication delegation + address-bound Soroban credentials. |
| 0071-01 | 27 | Auth delegation for custom (contract) accounts. |
| 0071-02 | 27 | Address-bound Soroban address credentials. |
| 0073 | 26 | Let the SAC create classic G-account balances. |
| 0074 | 25 | **BN254 host functions** (alt curve for zk proofs). |
| 0075 | 25 | **Native Poseidon / Poseidon2 hashing** host functions. |
| 0076 | 24 | Remediate a Protocol-23 state-archival bug. |
| 0077 | 26 | Freeze ledger entries via network config. |
| 0078 | 26 | Host fns for limited TTL extensions. |
| 0079 | 26 | Host fns for muxed-address strkey conversion. |
| 0080 | 26 | **Efficient ZK BN254 host functions** (optimized proving/verification). |
| 0081 | TBD | TTL-ordered eviction of archived entries. |
| 0082 | 26 | **Checked 256-bit integer arithmetic** host functions. |
| 0083 | TBD | Let validators vote to drop a stuck tx set. |
| 0085 | TBD | Externally managed contract executables (Final Comment Period). |

## 2. CAPs — Draft

| CAP | One-liner |
|---|---|
| 0007 | Deterministic account creation at predictable addresses. |
| 0008 | Self-identifying pre-auth transactions. |
| 0009 | Linear / exterior immutable account constraints. |
| 0010 | Dedicated fee-bump account concept. |
| 0011 | Time-relative account freeze. |
| 0012 | Deterministic account IDs via `creatorTxID`. |
| 0014 | Harden tx-set ordering against adversaries. |
| 0022 | Invalid transactions must leave no side effects. |
| 0032 | Trustline pre-authorization. |
| 0037 | Alternative AMM design. |
| 0041 | Concurrent transactions per account. |
| 0043 | ECDSA signers (P-256 and secp256k1). |
| 0044 | SPEEDEX DEX — configuration. |
| 0045 | SPEEDEX DEX — batch pricing. |
| 0057 | Eviction of persistent archived entries. |
| 0060 | Move Soroban VM to a Wasmi register machine (Accepted). |
| 0072 | Let contracts act as signers on Stellar accounts. |
| 0084 | Muxed (multiplexed) contract addresses. |
| 0086 | Host fns for sparse Symbol-keyed map creation/unpacking. |

## 3. CAPs — Rejected

| CAP | One-liner |
|---|---|
| 0013 | Change trustlines to balances. |
| 0016 | Cosigned assets (NopOp / COAUTHORIZED_FLAG). |
| 0031 | Sponsored reserve (superseded by CAP-0033). |
| 0036 | Claimable balance clawback. |
| 0039 | Not-auth-revocable trustlines. |
| 0048 | Smart contract asset interoperability. |
| 0049 | SC asset interoperability with wrapper. |
| 0050 | Smart contract interactions. |
| 0052 | Base64 encoding/decoding host fn. |
| 0061 | SAC extension: memo. |
| 0064 | Memo authorization for Soroban. |

---

## 4. SEPs — Active / Final

| SEP | Title | Status |
|---|---|---|
| 0001 | Stellar Info File (`stellar.toml`) | Active |
| 0002 | Federation Protocol | Final |
| 0004 | Tx Status Endpoint | Final |
| 0005 | Key Derivation Methods for Stellar Accounts | Final |
| 0006 | Deposit and Withdrawal API | Active |
| 0007 | URI Scheme for delegated signing | Final |
| 0008 | Regulated Assets | Final |
| 0009 | Standard KYC Fields | Active |
| 0010 | Stellar Authentication (Web Auth) | Active |
| 0011 | Txrep: human-readable tx representation | Active |
| 0012 | KYC API | Active |
| 0018 | Data Entry Namespaces | Active |
| 0020 | Self-verification of validator nodes | Active |
| 0023 | Muxed Account Strkeys | Active |
| 0024 | Hosted Deposit and Withdrawal | Active |
| 0028 | XDR Base64 Encoding | Final |
| 0029 | Account Memo Requirements | Active |
| 0031 | Cross-Border Payments API | Active |
| 0033 | Identicons for Stellar Accounts | Active |
| 0046 | Contract Meta | Active |
| 0048 | Contract Interface Specification | Active |
| 0053 | Sign and Verify Messages | Final |
| 0054 | Ledger Metadata Storage | Active |

## 5. SEPs — Draft (notable)

| SEP | Title |
|---|---|
| 0039 | Interoperability Recommendations for NFTs (Active) |
| 0040 | Oracle Consumer Interface |
| 0041 | Soroban Token Interface |
| 0045 | Stellar Web Auth for Contract Accounts |
| 0047 | Contract Interface Discovery |
| 0049 | Upgradeable Contracts (OpenZeppelin) |
| 0050 | Non-Fungible Tokens (OpenZeppelin) |
| 0051 | XDR-JSON |
| 0052 | Key Sharing Method for Stellar Keys |
| 0055 | Contract Build Info |
| 0056 | Tokenized Vault Standard |
| 0057 | T-REX (Token for Regulated EXchanges) |
| 0058 | Contract Build Reproducibility for Verification |
| 0059 | External Account API |

---

## 6. What matters for the Hypertron Privacy Protocol

### CAPs — Tier 1 (build directly on these)

| CAP | Why it's core |
|---|---|
| **0075 — Poseidon/Poseidon2** | Native Poseidon hashing for the commitment tree & nullifiers. Lets us drop the `soroban-poseidon` library dependency the current `poolmanager` uses in favor of a host function. |
| **0074 + 0080 — BN254** | BN254 curve + efficient ZK host fns. Likely our real verifier target (see decision note). |
| **0059 — BLS12-381** | Alternate zk curve + pairing check; the official `stellar/soroban-examples/groth16_verifier` uses it. |
| **0082 — checked u256 math** | Overflow-safe field/amount arithmetic in the verifier and note logic. |
| **0058 — constructors** | Clean init for each composable contract. |
| **0046-03/05/10/11/12** | Foundational Soroban we sit on: host fns, storage, metering, auth, state archival/TTL. |

> **Verifier curve decision (must lock down in PRD Section 9):**
> - Circom/snarkjs Groth16 → **BN254** by default → target **CAP-0074/0080**.
> - Soroban example verifier → **BLS12-381** → **CAP-0059** (needs proofs generated with a BLS backend).
> - Our reference stacks (`ZkPay` = Noir, `stellar-private-payments` = Circom) both lean **BN254**.
> - **Recommendation:** default to **BN254 (CAP-0074/0080)**, keep BLS12-381 (CAP-0059) as an alternate backend behind the `ProofVerifier` trait.

### CAPs — Tier 2 (UX, auth, flows for the reference app)

| CAP | Use |
|---|---|
| **0015 — fee bump** | Sponsor fees so private-payment users don't need XLM (and corrects the prior CAP-40 error). |
| **0033 — sponsored reserve** | Sponsor account/trustline reserves for onboarding. |
| **0051 — secp256r1** | Passkey wallet auth in the client. |
| **0021 — preconditions** / **0040 — signed payload** | Time-locked / conditional settlement, disclosure hand-offs, channels. |
| **0067 — unified asset events** | Clean indexing of shielded deposits/withdrawals. |
| **0035 — clawback** | Relevant to the compliance/policy module story. |

### SEPs — Tier 1 (interfaces & trust story)

| SEP | Why |
|---|---|
| **0041 — Soroban Token Interface** | The transfer module must speak the standard token interface. |
| **0048 — Interface Spec** / **0047 — Interface Discovery** / **0046 — Contract Meta** | Publish module traits so others can compose against them (standards-first goal). |
| **0049 — Upgradeable Contracts** | Upgrade pattern for versioned privacy contracts. |
| **0055 — Build Info** + **0058 — Build Reproducibility** | Reproducible, verifiable builds = the trust story for a privacy library. Strong signal for reviewers and integrators. |
| **0053 — Sign & Verify Messages** | Underpins view keys / signed selective disclosure. |

### SEPs — Tier 2 (compliance + app layer)

| SEP | Why |
|---|---|
| **0008 — Regulated Assets** / **0057 — T-REX** | Model for compliance policy hooks. |
| **0009 / 0012 — KYC fields & API** | Selective-disclosure-to-auditor flows. |
| **0056 — Tokenized Vault** | If the pool exposes a vault-like interface. |
| **0010 / 0045 — Web Auth (accounts / contract accounts)** | Auth for the merchant reference app. |
| **0007 — URI scheme** | Payment-request URIs for merchant checkout. |

---

## 7. Sources

- CAP index: https://github.com/stellar/stellar-protocol/tree/master/core
- SEP index: https://github.com/stellar/stellar-protocol/tree/master/ecosystem
- CAP-0059 (BLS12-381): https://github.com/stellar/stellar-protocol/blob/master/core/cap-0059.md
- CAP-0015 (fee bump): https://github.com/stellar/stellar-protocol/blob/master/core/cap-0015.md
- Soroban BLS12-381 SDK: https://docs.rs/soroban-sdk/latest/soroban_sdk/crypto/bls12_381/
- Groth16 verifier example: https://github.com/stellar/soroban-examples/tree/main/groth16_verifier
