//! Value-committed notes with spend/view separation.
//!
//! A note is the private unit of value in the shielded pool. Its on-chain
//! commitment binds an **owner public key** to an amount:
//!
//! ```text
//! owner_pk = Poseidon(spend_sk, 0)   // public; safe to share / put in blobs
//! cm       = Poseidon(Poseidon(owner_pk, k), v)
//! nf       = Poseidon(spend_sk, k)   // requires spend_sk — NOT recoverable from the blob
//! ```
//!
//! The viewing key only decrypts `(owner_pk, k, v)`. That is enough to verify
//! the commitment and read the amount, but **not** enough to compute the
//! nullifier or authorise a spend. Spending requires `spend_sk`, which never
//! appears in the encrypted note payload.
//!
//! `k` is a per-note blinding factor; `v` is the value. Two Poseidon hashes are
//! used because the on-chain sponge is 2-to-1 (t=3).

use ark_bls12_381::Fr;

use crate::poseidon::poseidon2to1;

/// Maximum note value width. Values are range-checked to `[0, 2^VALUE_BITS)` in
/// every circuit so field arithmetic (balance equations) cannot wrap around and
/// mint value. 64 bits comfortably covers any real SEP-41 token amount.
pub const VALUE_BITS: usize = 64;

/// Domain separator for `owner_pk = Poseidon(spend_sk, OWNER_PK_DOMAIN)`.
pub const OWNER_PK_DOMAIN: u64 = 0;

/// A private note: owner public tag, blinding `k`, and value `v`.
///
/// `owner_pk` is public material (also embedded in viewing-key blobs). It is
/// **not** a spend secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub owner_pk: Fr,
    pub k: Fr,
    pub v: Fr,
}

impl Note {
    pub fn new(owner_pk: Fr, k: Fr, v: Fr) -> Self {
        Note { owner_pk, k, v }
    }

    /// Build a note owned by `spend_sk`.
    pub fn from_spend_key(spend_sk: Fr, k: Fr, v: Fr) -> Self {
        Note::new(owner_pk(spend_sk), k, v)
    }

    /// The note commitment `cm = Poseidon(Poseidon(owner_pk, k), v)`.
    pub fn commitment(&self) -> Fr {
        commitment(self.owner_pk, self.k, self.v)
    }

    /// The nullifier `nf = Poseidon(spend_sk, k)`. Caller must pass the sk that
    /// matches `self.owner_pk`.
    pub fn nullifier(&self, spend_sk: Fr) -> Fr {
        nullifier(spend_sk, self.k)
    }
}

/// `owner_pk = Poseidon(spend_sk, 0)`.
pub fn owner_pk(spend_sk: Fr) -> Fr {
    poseidon2to1(spend_sk, Fr::from(OWNER_PK_DOMAIN))
}

/// Note commitment `cm = Poseidon(Poseidon(owner_pk, k), v)`.
pub fn commitment(owner_pk: Fr, k: Fr, v: Fr) -> Fr {
    let inner = poseidon2to1(owner_pk, k);
    poseidon2to1(inner, v)
}

/// Nullifier `nf = Poseidon(spend_sk, k)`.
pub fn nullifier(spend_sk: Fr, k: Fr) -> Fr {
    poseidon2to1(spend_sk, k)
}
