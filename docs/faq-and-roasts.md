# Hypertron — FAQ & Roast Defense

Honest, defensible answers for podcasts, grant reviews, Twitter roasts, and due
diligence. Rule of thumb: **never claim you invented shielded pools, never claim
you're "more advanced" than better-funded teams, and always redirect to
execution and the anonymity set.** Confidence + accuracy beats defensiveness.

---

## Part 1 — Roasts (the spicy ones)

### "You just copied Nethermind's private payments."
Shielded pools aren't Nethermind's invention — they're Zcash's, from 2016.
Nethermind didn't copy Zcash, and I didn't copy Nethermind. We're both building
on a public, well-understood primitive. "Copied" implies a stolen secret; there
is no secret — it's open cryptography. I made my own engineering choices, added
an original feature (Verifiable Privacy Attestations), and now it comes down to
execution. If a serious, well-funded team independently landed on the same
architecture on the same chain, that's validation that I'm building the right
thing.

### "So what's actually different from Nethermind, then?"
Three real things:
1. **Native Stellar primitives** — I use Soroban host functions for BLS12-381
   pairings (CAP-0059) and Poseidon (CAP-0075) instead of shipping a ported
   verifier + hashing library. Built *for* Stellar, not ported onto it: less
   audited surface, cheaper verification.
2. **Verifiable Privacy Attestations** — an on-chain, provable statement of
   exactly which leakage dimensions (sender/receiver/amount/timing/linkability)
   a payment closed. I don't see that in their work.
3. **Single-language Rust/arkworks stack** — one canonical prover crate shared by
   the contract tests and the CLI, so what you prove is exactly what the chain
   verifies.

### "Isn't this just Tornado Cash / a mixer?"
No. A mixer uses fixed denominations and exists mainly to break links. Hypertron
uses **arbitrary amounts** and is built for **payments** — merchant settlement,
private transfers — with **viewing keys** for selective disclosure to auditors.
The compliance story (revealable-on-demand, optional exit policy) is the opposite
of a mixer's "no questions asked" model.

### "You can't even hide the transaction — the tx hash is right there on-chain."
Correct, and I never claimed otherwise. On a public chain you can't hide *that* a
transaction happened — nobody can. What's hidden is the **contents and linkage**:
who sent it, who received it, how much, and which deposit it came from. An
observer sees "a private transfer occurred"; they don't see any of the meaning.

### "It's unaudited and the trusted setup is fake — this isn't real."
Right — it's a testnet-ready proof of concept, and I say so openly. So is
Nethermind's (their repos carry the same "unaudited PoC, ceremony for demo only"
warning). The honest state of the whole category is: the cryptography is proven,
the products aren't hardened yet. My path to production is documented — a real
multi-party ceremony and an external audit — in `docs/ceremony.md` and
`docs/operations.md`.

### "Your circuit is tiny (1-in/2-out). Theirs is 4-in/4-out. You're behind."
It's a deliberate trade-off, not a limitation I missed. A smaller circuit is
faster to prove and far easier to audit — which matters more pre-audit. The cost
is that consolidating many notes takes sequential transfers instead of one
JoinSplit. Scaling to N-in/M-out is a well-understood extension, not a redesign.

### "Nethermind has a live demo and browser proving. You have a CLI."
True today. Both use arkworks Groth16, so proving performance lands in the same
1–3s browser range — the gap is **engineering (WASM prover + web SDK)**, not
cryptography or performance. That's a build task on a known path, and it's next.

### "You're a solo dev vs. a funded infra company. Why would you win?"
In privacy protocols the moat is never the circuit — everyone shares the Zcash
lineage. The moat is the **anonymity set** (users), the **product/vertical**, and
**trust** (audit + compliance relationships). Both projects are PoCs with zero
real users right now. I'm not competing on "who wrote a shielded pool first." I'm
competing on who ships a usable, audited product that people actually use. Roast
me again when we've both shipped and compare user counts.

### "Where's your moat, really?"
Honestly? Not raw crypto. It's (1) being the native-Stellar reference
implementation aiming at a SEP standard, (2) owning a specific vertical — private
merchant settlement with provable attestations — and (3) shipping a real product
first. Standards adoption and network effects are the durable moats.

---

## Part 2 — FAQ (the straight ones)

### What is Hypertron?
A shielded-payments protocol on Stellar/Soroban. Users convert transparent XLM or
USDC into private notes, transfer value without revealing sender/receiver/amount,
and exit to a normal address when they want. Auditors can verify history with a
read-only viewing key.

### What exactly is hidden vs. public?
Hidden: sender address, receiver address, amount, and deposit↔spend linkage.
Public: that a transaction happened (and its hash), plus the amount and address at
the shield (entry) and unshield (exit) edges — by design, since those move
to/from transparent Stellar.

### How does privacy work at a high level?
Notes are value-committed: `cm = Poseidon(Poseidon(n, k), v)`, stored in a Merkle
tree. Spending reveals a nullifier (prevents double-spends) and a zero-knowledge
proof that you own an in-tree note and that values balance — without revealing
which note or how much.

### How do viewing keys / audits work?
Each note sent to someone is emitted as an encrypted blob on-chain (X25519 +
ChaCha20-Poly1305). The recipient — or an auditor holding the viewing key —
decrypts it off-chain to recover the note. Viewing keys are **read-only**: they
reveal history but cannot spend.

### How is the sender's wallet hidden if they pay gas?
A **relayer** submits the `unshield`/`transfer` transaction and pays the fee, so
the fee-paying account never links to the sender. The proof binds the payout, so
the relayer cannot steal or redirect funds.

### Is it compliant, or is it a privacy free-for-all?
Selective disclosure via viewing keys, plus an **optional** exit-time allow/deny
policy that lives *outside* the ZK core (so it never weakens privacy and can be
swapped or removed). Privacy with an auditor escape hatch — not anonymity at all
costs.

### What proving system and curve?
Groth16 over BLS12-381, verified on-chain with Soroban's native pairing host
functions (CAP-0059). Hashing is native Poseidon (CAP-0075). Proofs are built
off-chain by the `hypertron-prover` crate / `hypertron-prove` CLI.

### Why Groth16 and not a universal setup (PLONK/Halo2)?
Groth16 is the cheapest to verify on-chain and best supported by Stellar's host
functions today. The verifier is a pluggable seam, so a universal-setup backend
can replace it later without changing the pool, tree, or nullifier registry.

### What's the trusted setup situation?
Today: a documented single-coordinator/deterministic setup for dev and testnet
(clearly marked not-for-mainnet). Production requires a multi-party ceremony —
the process and upgrade path are in `docs/ceremony.md`.

### What's actually built vs. not?
Built + tested: all contracts (commitment, nullifier, verifier, transfer,
compliance), the prover + CLI, viewing-key encryption, and a real-proof
end-to-end lifecycle test. Not built (app layer): browser WASM prover, wallet key
management, note-scanning indexer, relayer service. Not done (pre-mainnet):
multi-party ceremony and external audit.

### How does an app use this?
See `docs/app-integration.md` — it maps every UI action (shield, send, receive,
cash out, audit) to the exact prover call and contract call, and shows what a
block explorer displays for a private transfer.

### Does it support multiple assets?
Yes — one pool per asset (separate XLM and USDC pools). An app can present a
single unified shielded balance across them.

### Is my money safe? What are the risks?
It's a PoC: unaudited, single-coordinator setup. The honest risks are (1) an
undiscovered circuit/contract bug, (2) trusted-setup compromise before the
ceremony, and (3) weak privacy if the anonymity set is small. All three are
addressed on the roadmap (audit, ceremony, growth) and none should guard real
TVL until then.

### What's the license?
Apache-2.0 — permissive, with an explicit patent grant. Anyone can build on it,
including commercially, as long as they keep attribution.

### What's next?
Browser WASM prover + web SDK, an indexer + relayer, a multi-party ceremony, and
an external audit — then a real merchant-settlement product to grow the anonymity
set.
