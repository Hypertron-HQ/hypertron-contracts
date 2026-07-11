# Building a User-Facing App on Hypertron

Status snapshot and integration guide for building a shielded XLM/USDC wallet on
top of the Hypertron contracts.

## 1. What is built today (in this repo)

| Component | Status | Location |
|---|---|---|
| Commitment tree (Poseidon Merkle) | Built + tested | `contracts/commitment` |
| Nullifier registry | Built + tested | `contracts/nullifier` |
| On-chain Groth16 verifier (BLS12-381) | Built + tested | `contracts/verifier` |
| Shielded pool: deposit / unshield / transfer | Built + tested | `contracts/transfer` |
| Value-committed notes `Poseidon(Poseidon(n,k),v)` | Built | `prover/src/note.rs` |
| 3 circuits (deposit, unshield, transfer) + range/balance | Built | `prover/src/circuit.rs` |
| Viewing keys + ECIES note encryption | Built | `prover/src/crypto.rs` |
| Off-chain prover + CLI (`hypertron-prove`) | Built | `prover/` |
| Compliance hook (optional exit allow/deny) | Built | `contracts/compliance` |
| Testnet deploy script | Built | `scripts/deploy_testnet.sh` |
| Ceremony + operations docs | Built | `docs/ceremony.md`, `docs/operations.md` |
| Tests (incl. real-proof e2e lifecycle) | 40 passing | across crates |

### Not built (app layer — you build these)
- Client-side WASM prover (proofs MUST be built on the user's device).
- Wallet key management (seed -> spend key + viewing key).
- Local note store + event scanner (trial-decrypt to find your notes).
- Indexer (serves ordered leaves + encrypted blobs).
- Relayer service (submits txs, pays fees, so fee-payer != sender).

### Not built (pre-mainnet, external processes)
- Multi-party trusted-setup ceremony (today = single-coordinator dev setup).
- External security audit.

## 2. What is and is NOT hidden

Hidden: **sender address, receiver address, amount, deposit<->spend linkage.**

**NOT hidden (impossible on a public chain):** that a transaction happened, and
its transaction hash. Every Soroban tx is a public ledger entry. Hypertron hides
the *contents and linkage*, not the *existence* of the tx. Hiding existence would
need timing/batching/decoy mechanisms that are not in this codebase.

Revealed only on demand: full note contents to anyone you hand a **viewing key**
(read-only; cannot spend).

## 3. Reference architecture

```
CLIENT (browser/mobile)          RELAYER (you run)        ON-CHAIN (per asset)
- seed -> spend + view keys      - accepts proof+ct       - hypertron-transfer
- local note store               - pays fee, submits      - commitment/nullifier
- WASM prover (local!)           - cannot steal (bound)   - verifier (+compliance)
- encrypt note to recipient ─────► submit transfer ───────► emits PrivateTransfer
        ▲                                                        │
        └──────────── INDEXER (you build): leaves + blobs ◄──────┘
```

One pool per asset (XLM pool, USDC pool). UI shows a unified shielded balance.

## 4. The three flows -> contract calls

**Shield (enter, public, authorized):**
1. Pick `(n,k)`, `v = amount`; compute `cm` and a deposit-binding proof.
2. User wallet signs `deposit(from, amount, cm, deposit_proof)`.

**Transfer (private, relayer-submitted):**
1. Build `out1` (to recipient) + `out2` (change); encrypt `out1` to recipient's
   viewing pubkey.
2. Build `transfer` proof (membership + nullifier + `v_in = v1 + v2`).
3. Relayer submits `transfer(proof, root, nullifier, out_cm1, out_cm2, ct1, ct2)`.

**Unshield (exit, public amount/destination, unlinked):**
1. `unshield(proof, root, nullifier, recipient, amount, change_cm, claim)`.

## 5. Example: what a private transfer looks like end-to-end

Scenario: **Alice pays Bob 40 USDC privately.** Alice holds a shielded note worth
100 USDC. She sends 40 to Bob and keeps 60 as change. A relayer submits it.

### What Alice does (in the app, invisible to the chain)
- Input note: `A = (n=…, k=…, v=100)`, already in the pool at leaf index 12.
- Output notes: `to_bob = (n_b, k_b, v=40)`, `change = (n_c, k_c, v=60)`.
- Encrypts `to_bob` to Bob's viewing pubkey -> ciphertext `ct1`.
- Builds proof: "I own leaf 12, its nullifier is `nf`, and `100 = 40 + 60`."
- Hands `(proof, root, nf, cm_bob, cm_change, ct1, ct2)` to the relayer.

### What a block explorer (e.g. stellar.expert) shows
```
Transaction  a1b2c3…f9  (SUCCESS)
  Ledger:        58,203,114
  Source account: GRELAYER…XYZ         <- the RELAYER, not Alice
  Fee:           0.0012 XLM  (paid by relayer)
  Operation:     invoke_host_function
    Contract:    CDPOOL…USDC           (hypertron-transfer, USDC pool)
    Function:    transfer
    Args:
      proof:            0x8f2a… (384 bytes)
      root:             0x64d5…1e5a
      nullifier:        0x2c7b…2b66
      out_commitment_1: 0x38c5…de1f
      out_commitment_2: 0x0d33…2426
      note_1:           0x0a2d… (ciphertext blob)
      note_2:           0x
  Events:
    PrivateTransfer {
      nullifier:    0x2c7b…2b66
      out_index_1:  13
      out_index_2:  14
      note_1:       0x0a2d…   (encrypted)
      note_2:       0x
    }
```

### What an observer can and cannot infer
| Sees | Cannot see |
|---|---|
| A `transfer` happened on the USDC pool at ledger 58,203,114 | Alice or Bob's identity/address |
| The relayer's account paid the fee | The amount (40) or the change (60) |
| A nullifier was spent + two new commitments created | Which deposit/note was spent (nullifier != address) |
| Opaque 32-byte commitments + a ciphertext blob | Note contents (only viewing-key holders decrypt) |

The relayer being the source account is why **sender address is hidden**. There
is no `recipient` field at all, so **receiver address is hidden**. Values live
only inside commitments/proofs, so **amount is hidden**.

### What Bob does
- His wallet scans `PrivateTransfer` events, trial-decrypts each `note_1`/`note_2`
  with his viewing key, and successfully decrypts `ct1` -> learns `to_bob=(n_b,k_b,40)`.
- Bob now holds a 40-USDC note (leaf 13) he can transfer or unshield.

### What an auditor does (with Alice's viewing key)
- Decrypts the blobs off-chain -> recovers `(n,k,v)`, confirms `40 + 60 = 100`,
  and checks the openings match the on-chain commitments.
- Concludes the tx is legitimate — **without any on-chain decryption and without
  the ability to spend.**

## 6. Comparison: shield / transfer / unshield visibility

| Field on-chain | Shield (deposit) | Private transfer | Unshield (exit) |
|---|---|---|---|
| Source account | user's wallet | relayer | relayer |
| Amount | **public** | hidden | **public** |
| Counterparty address | pool | none | **public recipient** |
| Linkage to deposit | n/a | hidden | hidden |

The public edges are **shield** and **unshield** by design (moving to/from
transparent Stellar). Everything in between is private.

## 7. Client SDK checklist (which prover calls map to each UI action)

The canonical crypto lives in `hypertron_prover` (compile to WASM for the client)
and is mirrored by the `hypertron-prove` CLI. Suggested mapping:

| UI action | Prover call / CLI | On-chain call |
|---|---|---|
| Create wallet | `ViewingKey::from_seed` / `keygen` | — |
| Compute a note commitment | `note::commitment` / `commitment` | — |
| Shield funds | `DepositCircuit` proof / `deposit-proof` | `deposit(from, amount, cm, proof)` |
| Send privately | `TransferCircuit` proof + `encrypt_note` / `transfer-proof` | `transfer(proof, root, nf, cm1, cm2, ct1, ct2)` |
| Cash out | `UnshieldCircuit` proof / `unshield-proof` | `unshield(proof, root, nf, recipient, amount, change_cm, claim)` |
| Receive / scan | `decrypt_note` / `decrypt` | read `PrivateTransfer` events |
| Rebuild Merkle path | `merkle::path` | read ordered leaves from indexer |
| Audit disclosure | share viewing key -> `decrypt_note` | — |

Key rule: **proving happens on the user's device**. A server-side prover would
see note secrets and defeat the privacy model.
