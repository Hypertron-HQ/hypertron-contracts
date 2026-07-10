//! Feasibility gate for the ZK membership circuit.
//!
//! The on-chain commitment tree hashes with Soroban's circom-compatible
//! Poseidon (BLS12-381, t=3). For a membership proof to verify, the *in-circuit*
//! hash must be byte-identical. Here we reproduce that Poseidon permutation in
//! arkworks (the same field library used by our prover) and assert it matches
//! the on-chain host output. If this passes, the Merkle circuit can be built on
//! top of this exact permutation.
#![cfg(test)]

use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField};

// Extracted from soroban-poseidon 25.0.0 (BLS12-381, t=3).
include!("poseidon_bls_t3.rs");

const ROUNDS_F: usize = 8;
const ROUNDS_P: usize = 56;

fn hex_to_fr(h: &str) -> Fr {
    let h = h.trim_start_matches("0x");
    let mut raw: ark_std::vec::Vec<u8> = ark_std::vec::Vec::new();
    let mut i = 0;
    if h.len() % 2 == 1 {
        raw.push(u8::from_str_radix(&h[0..1], 16).unwrap());
        i = 1;
    }
    while i < h.len() {
        raw.push(u8::from_str_radix(&h[i..i + 2], 16).unwrap());
        i += 2;
    }
    let mut bytes = [0u8; 32];
    let off = 32 - raw.len();
    bytes[off..].copy_from_slice(&raw);
    Fr::from_be_bytes_mod_order(&bytes)
}

fn pow5(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// MDS matrix as field elements.
pub(crate) fn mds_fr() -> [[Fr; 3]; 3] {
    core::array::from_fn(|i| core::array::from_fn(|j| hex_to_fr(MDS_T3[i][j])))
}

/// Round constants as field elements ((rounds_f + rounds_p) x t).
pub(crate) fn rc_fr() -> [[Fr; 3]; 64] {
    core::array::from_fn(|r| core::array::from_fn(|i| hex_to_fr(RC_T3[r][i])))
}

pub(crate) const N_ROUNDS: usize = ROUNDS_F + ROUNDS_P;
pub(crate) const HALF_F: usize = ROUNDS_F / 2;

/// Standard Poseidon permutation over BLS12-381 Fr, t=3, matching the Soroban
/// host (ARC -> S-box -> MDS each round; partial rounds S-box index 0 only).
pub(crate) fn permute(state: &mut [Fr; 3]) {
    let mds = mds_fr();
    let total = ROUNDS_F + ROUNDS_P;
    let half = ROUNDS_F / 2;

    for round in 0..total {
        // ARC
        for i in 0..3 {
            state[i] += hex_to_fr(RC_T3[round][i]);
        }
        // S-box
        let full = round < half || round >= half + ROUNDS_P;
        if full {
            for i in 0..3 {
                state[i] = pow5(state[i]);
            }
        } else {
            state[0] = pow5(state[0]);
        }
        // MDS
        let mut ns = [Fr::ZERO; 3];
        for i in 0..3 {
            for j in 0..3 {
                ns[i] += mds[i][j] * state[j];
            }
        }
        *state = ns;
    }
}

/// 2-to-1 Poseidon compression matching `poseidon_hash::<3, BlsScalar>([a, b])`.
pub(crate) fn poseidon2to1(a: Fr, b: Fr) -> Fr {
    let mut state = [Fr::ZERO, a, b];
    permute(&mut state);
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::{crypto::bls12_381::Fr as BlsScalar, vec as svec, Env, U256};

    fn soroban_hash(env: &Env, a: u32, b: u32) -> Fr {
        let inputs = svec![env, U256::from_u32(env, a), U256::from_u32(env, b)];
        let out = soroban_poseidon::poseidon_hash::<3, BlsScalar>(env, &inputs);
        let bytes = out.to_be_bytes();
        let len = bytes.len() as usize;
        let mut buf = [0u8; 32];
        bytes.copy_into_slice(&mut buf[(32 - len)..]);
        Fr::from_be_bytes_mod_order(&buf)
    }

    #[test]
    fn arkworks_poseidon_matches_soroban_host() {
        let env = Env::default();
        // Several vectors to be sure it's not a coincidence.
        for (a, b) in [(1u32, 2u32), (0, 0), (7, 999), (123456, 654321)] {
            let expected = soroban_hash(&env, a, b);
            let got = poseidon2to1(Fr::from(a as u64), Fr::from(b as u64));
            assert_eq!(got, expected, "mismatch for inputs ({a}, {b})");
        }
    }
}
