# Stellar Protocol Dependencies

Hypertron is built on Soroban host functions and Stellar transaction features.
This document records the ones the deployed code depends on and why each is
required.

## CAP-0059 — BLS12-381 host functions

The on-chain Groth16 verifier uses Soroban's BLS12-381 field, group, MSM, and
pairing operations:

```rust
soroban_sdk::crypto::bls12_381
```

The off-chain prover uses `ark-bls12-381`, so prover and verifier operate over
the same curve and scalar field. Poseidon hashing for note commitments,
nullifiers, owner keys, and Merkle nodes is defined over that same scalar field,
which ties the note format to this curve.

A pairing check is not feasible in pure contract WASM within Soroban's resource
limits, so these host functions are a hard dependency rather than an
optimization.

## CAP-0015 — fee-bump transactions

A fee bump lets one account pay the fee for another account's transaction.

Private transfer and unshield require no note-owner signature — the proof binds
the permitted state transition — so either call can be submitted by a third
party. Combined with a fee bump, that allows a relayer to submit on a user's
behalf without the note owner appearing as the source or fee payer.

This repository does not operate a relayer. Under direct submission the
submitting account is public.

## Contract lifecycle

The contracts expose explicit `initialize` functions rather than constructor
entry points (CAP-0058). Initializers are first-call setters, so a deployment
must be initialized immediately to avoid first-caller takeover.

## Storage and metering

Persistent roots, leaves, nullifiers, verification keys, and policy entries all
require active TTL management. Nullifier retention is safety-critical: losing a
spent nullifier would permit a double-spend.

Proof verification and Poseidon hashing are metered operations and must be
benchmarked against production resource limits before mainnet.

## Poseidon hashing

The commitment contract uses `soroban-poseidon` over BLS12-381 scalar values so
that on-chain hashes match the Arkworks circuit exactly. Hashing runs as
ordinary contract code rather than through a native host function.
