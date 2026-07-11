//! Value-committed notes.
//!
//! A note is the private unit of value in the shielded pool. Its on-chain
//! commitment binds a secret owner tag to an amount, so the pool can enforce
//! value conservation in zero knowledge:
//!
//! ```text
//! inner = Poseidon(n, k)          // owner/secret commitment (hides who)
//! cm    = Poseidon(inner, v)      // note commitment inserted in the tree
//! nf    = Poseidon(n, 0)          // nullifier (revealed on spend)
//! ```
//!
//! `n` is the spend secret (controls the nullifier), `k` is a blinding factor,
//! and `v` is the value. Two hashes are used because the on-chain Poseidon is a
//! 2-to-1 compression (t=3); nesting gives a 3-input commitment.

use ark_bls12_381::Fr;

use crate::poseidon::poseidon2to1;

/// Maximum note value width. Values are range-checked to `[0, 2^VALUE_BITS)` in
/// every circuit so field arithmetic (balance equations) cannot wrap around and
/// mint value. 64 bits comfortably covers any real SEP-41 token amount.
pub const VALUE_BITS: usize = 64;

/// A private note: owner secret `n`, blinding `k`, and value `v`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    pub n: Fr,
    pub k: Fr,
    pub v: Fr,
}

impl Note {
    pub fn new(n: Fr, k: Fr, v: Fr) -> Self {
        Note { n, k, v }
    }

    /// The note commitment `cm = Poseidon(Poseidon(n, k), v)`.
    pub fn commitment(&self) -> Fr {
        commitment(self.n, self.k, self.v)
    }

    /// The nullifier `nf = Poseidon(n, 0)`.
    pub fn nullifier(&self) -> Fr {
        nullifier(self.n)
    }
}

/// Note commitment `cm = Poseidon(Poseidon(n, k), v)`.
pub fn commitment(n: Fr, k: Fr, v: Fr) -> Fr {
    let inner = poseidon2to1(n, k);
    poseidon2to1(inner, v)
}

/// Nullifier `nf = Poseidon(n, 0)`.
pub fn nullifier(n: Fr) -> Fr {
    poseidon2to1(n, Fr::from(0u64))
}
