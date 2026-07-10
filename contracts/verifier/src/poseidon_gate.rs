//! Feasibility gate for the ZK membership circuit.
//!
//! The on-chain commitment tree hashes with Soroban's circom-compatible
//! Poseidon (BLS12-381, t=3). For a membership proof to verify, the *in-circuit*
//! hash (in `hypertron-prover`) must be byte-identical. Here we assert the
//! prover's native Poseidon matches the on-chain host output for several
//! vectors. If this passes, the whole circuit stack rests on the same hash the
//! chain uses.
#![cfg(test)]

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use hypertron_prover::poseidon::poseidon2to1;
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
