//! Circom-compatible Poseidon over BLS12-381 (t=3, rounds_f=8, rounds_p=56,
//! d=5) — the exact permutation used by Soroban's on-chain host (CAP-0075).
//!
//! This module is the single source of the hash for both:
//!   - the off-chain prover / Merkle tree reconstruction ([`poseidon2to1`]), and
//!   - the in-circuit constraints ([`hash2_var`]).
//!
//! The `hypertron-verifier` crate has a test that asserts [`poseidon2to1`] is
//! byte-identical to `soroban_poseidon::poseidon_hash`, so proofs verify against
//! real on-chain roots.

use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField};
use ark_r1cs_std::{fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::SynthesisError;

include!("poseidon_bls_t3.rs");

const ROUNDS_F: usize = 8;
const ROUNDS_P: usize = 56;

/// Number of Poseidon rounds (full + partial).
pub const N_ROUNDS: usize = ROUNDS_F + ROUNDS_P;
/// Number of full rounds on each side of the partial rounds.
pub const HALF_F: usize = ROUNDS_F / 2;

fn hex_to_fr(h: &str) -> Fr {
    let h = h.trim_start_matches("0x");
    let mut raw: Vec<u8> = Vec::new();
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

/// MDS matrix as field elements.
pub fn mds_fr() -> [[Fr; 3]; 3] {
    core::array::from_fn(|i| core::array::from_fn(|j| hex_to_fr(MDS_T3[i][j])))
}

/// Round constants as field elements (`(rounds_f + rounds_p) x t`).
pub fn rc_fr() -> [[Fr; 3]; 64] {
    core::array::from_fn(|r| core::array::from_fn(|i| hex_to_fr(RC_T3[r][i])))
}

fn pow5(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// Native Poseidon permutation over `Fr`, t=3, matching the Soroban host
/// (ARC -> S-box -> MDS each round; partial rounds apply the S-box to index 0).
pub fn permute(state: &mut [Fr; 3]) {
    let mds = mds_fr();
    let rc = rc_fr();
    for round in 0..N_ROUNDS {
        for i in 0..3 {
            state[i] += rc[round][i];
        }
        let full = round < HALF_F || round >= N_ROUNDS - HALF_F;
        if full {
            for i in 0..3 {
                state[i] = pow5(state[i]);
            }
        } else {
            state[0] = pow5(state[0]);
        }
        let mut ns = [Fr::ZERO; 3];
        for i in 0..3 {
            for j in 0..3 {
                ns[i] += mds[i][j] * state[j];
            }
        }
        *state = ns;
    }
}

/// Native 2-to-1 compression, matching `poseidon_hash::<3, BlsScalar>([a, b])`.
pub fn poseidon2to1(a: Fr, b: Fr) -> Fr {
    let mut state = [Fr::ZERO, a, b];
    permute(&mut state);
    state[0]
}

fn pow5_var(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x * x;
    let x4 = &x2 * &x2;
    Ok(&x4 * x)
}

fn permute_var(
    state: &mut [FpVar<Fr>; 3],
    mds: &[[Fr; 3]; 3],
    rc: &[[Fr; 3]; 64],
) -> Result<(), SynthesisError> {
    for round in 0..N_ROUNDS {
        for i in 0..3 {
            state[i] = &state[i] + FpVar::constant(rc[round][i]);
        }
        let full = round < HALF_F || round >= N_ROUNDS - HALF_F;
        if full {
            for i in 0..3 {
                state[i] = pow5_var(&state[i])?;
            }
        } else {
            state[0] = pow5_var(&state[0])?;
        }
        let mut ns: [FpVar<Fr>; 3] = core::array::from_fn(|_| FpVar::constant(Fr::from(0u64)));
        for i in 0..3 {
            let mut acc = FpVar::constant(Fr::from(0u64));
            for j in 0..3 {
                acc = &acc + &(&state[j] * FpVar::constant(mds[i][j]));
            }
            ns[i] = acc;
        }
        *state = ns;
    }
    Ok(())
}

/// In-circuit 2-to-1 Poseidon compression (same permutation as [`poseidon2to1`]).
pub fn hash2_var(
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    mds: &[[Fr; 3]; 3],
    rc: &[[Fr; 3]; 64],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut state = [FpVar::constant(Fr::from(0u64)), a.clone(), b.clone()];
    permute_var(&mut state, mds, rc)?;
    Ok(state[0].clone())
}
