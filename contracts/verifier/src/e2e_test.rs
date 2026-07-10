//! End-to-end proof of the on-chain verifier.
//!
//! We generate a *real* Groth16 proof over BLS12-381 with the arkworks prover
//! (an independent implementation), serialize it exactly as the Soroban host
//! expects, and verify it inside the deployed contract using the CAP-0059
//! host pairing functions. This proves the verifier's cryptographic path is
//! correct and interoperable with the standard Groth16 toolchain — not a stub.
#![cfg(test)]

use super::{VerifierContract, VerifierContractClient, VerifyingKey};

use ark_bls12_381::{Bls12_381, Fr as AFr, G1Affine as AG1, G2Affine as AG2};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec as SVec};

/// Toy circuit: prove knowledge of secret factors a, b such that a * b == c,
/// where c is the single public input. Enough to exercise MSM over public
/// inputs plus the full pairing check.
#[derive(Clone)]
struct MulCircuit {
    a: Option<AFr>,
    b: Option<AFr>,
}

impl ConstraintSynthesizer<AFr> for MulCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<AFr>) -> Result<(), SynthesisError> {
        let a_val = self.a;
        let b_val = self.b;
        let a = cs.new_witness_variable(|| a_val.ok_or(SynthesisError::AssignmentMissing))?;
        let b = cs.new_witness_variable(|| b_val.ok_or(SynthesisError::AssignmentMissing))?;
        let c = cs.new_input_variable(|| {
            let a = a_val.ok_or(SynthesisError::AssignmentMissing)?;
            let b = b_val.ok_or(SynthesisError::AssignmentMissing)?;
            Ok(a * b)
        })?;
        cs.enforce_constraint(lc!() + a, lc!() + b, lc!() + c)?;
        Ok(())
    }
}

fn g1_bytes(env: &Env, p: &AG1) -> BytesN<96> {
    let mut v = ark_std::vec::Vec::new();
    p.serialize_uncompressed(&mut v).unwrap();
    let mut buf = [0u8; 96];
    buf.copy_from_slice(&v);
    BytesN::from_array(env, &buf)
}

fn g2_bytes(env: &Env, p: &AG2) -> BytesN<192> {
    let mut v = ark_std::vec::Vec::new();
    p.serialize_uncompressed(&mut v).unwrap();
    let mut buf = [0u8; 192];
    buf.copy_from_slice(&v);
    BytesN::from_array(env, &buf)
}

/// Scalar -> big-endian 32 bytes, matching `Fr::from_bytes` (U256::from_be_bytes).
fn fr_bytes(env: &Env, f: &AFr) -> BytesN<32> {
    let be = f.into_bigint().to_bytes_be();
    let mut buf = [0u8; 32];
    let off = 32 - be.len();
    buf[off..].copy_from_slice(&be);
    BytesN::from_array(env, &buf)
}

fn to_soroban_vk(env: &Env, vk: &ark_groth16::VerifyingKey<Bls12_381>) -> VerifyingKey {
    let mut ic: SVec<BytesN<96>> = SVec::new(env);
    for p in vk.gamma_abc_g1.iter() {
        ic.push_back(g1_bytes(env, p));
    }
    VerifyingKey {
        alpha: g1_bytes(env, &vk.alpha_g1),
        beta: g2_bytes(env, &vk.beta_g2),
        gamma: g2_bytes(env, &vk.gamma_g2),
        delta: g2_bytes(env, &vk.delta_g2),
        ic,
    }
}

fn proof_to_bytes(env: &Env, proof: &ark_groth16::Proof<Bls12_381>) -> Bytes {
    let mut pb = ark_std::vec::Vec::new();
    proof.a.serialize_uncompressed(&mut pb).unwrap(); // G1, 96
    proof.b.serialize_uncompressed(&mut pb).unwrap(); // G2, 192
    proof.c.serialize_uncompressed(&mut pb).unwrap(); // G1, 96
    Bytes::from_slice(env, &pb)
}

fn setup_client(env: &Env) -> VerifierContractClient<'_> {
    let id = env.register(VerifierContract, ());
    let client = VerifierContractClient::new(env, &id);
    client.initialize(&Address::generate(env));
    client
}

#[test]
fn real_groth16_proof_verifies_on_chain() {
    let env = Env::default();
    env.mock_all_auths();
    let client = setup_client(&env);

    let mut rng = StdRng::seed_from_u64(1234);
    let a = AFr::from(3u64);
    let b = AFr::from(11u64);
    let c = a * b; // 33

    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(MulCircuit { a: None, b: None }, &mut rng)
            .unwrap();
    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        MulCircuit {
            a: Some(a),
            b: Some(b),
        },
        &mut rng,
    )
    .unwrap();

    // Sanity: it verifies off-chain with arkworks too.
    assert!(Groth16::<Bls12_381>::verify(&vk, &[c], &proof).unwrap());

    // Now verify the same proof ON-CHAIN.
    client.register_vk(&1, &to_soroban_vk(&env, &vk));
    let proof_bytes = proof_to_bytes(&env, &proof);
    let mut pubs: SVec<BytesN<32>> = SVec::new(&env);
    pubs.push_back(fr_bytes(&env, &c));

    assert!(client.verify(&1, &proof_bytes, &pubs));
}

#[test]
fn wrong_public_input_is_rejected_on_chain() {
    let env = Env::default();
    env.mock_all_auths();
    let client = setup_client(&env);

    let mut rng = StdRng::seed_from_u64(1234);
    let a = AFr::from(3u64);
    let b = AFr::from(11u64);
    let c = a * b;

    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(MulCircuit { a: None, b: None }, &mut rng)
            .unwrap();
    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        MulCircuit {
            a: Some(a),
            b: Some(b),
        },
        &mut rng,
    )
    .unwrap();

    client.register_vk(&1, &to_soroban_vk(&env, &vk));
    let proof_bytes = proof_to_bytes(&env, &proof);

    // Claim c = 34 instead of 33 -> must fail.
    let mut pubs: SVec<BytesN<32>> = SVec::new(&env);
    pubs.push_back(fr_bytes(&env, &(c + AFr::from(1u64))));

    assert!(!client.verify(&1, &proof_bytes, &pubs));
}

#[test]
fn tampered_proof_is_rejected_on_chain() {
    let env = Env::default();
    env.mock_all_auths();
    let client = setup_client(&env);

    let mut rng = StdRng::seed_from_u64(1234);
    let a = AFr::from(7u64);
    let b = AFr::from(6u64);
    let c = a * b;

    let (pk, vk) =
        Groth16::<Bls12_381>::circuit_specific_setup(MulCircuit { a: None, b: None }, &mut rng)
            .unwrap();
    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        MulCircuit {
            a: Some(a),
            b: Some(b),
        },
        &mut rng,
    )
    .unwrap();

    client.register_vk(&1, &to_soroban_vk(&env, &vk));

    // Flip a byte in the proof's A point -> must fail (or trap on a bad point).
    let mut pb = ark_std::vec::Vec::new();
    proof.a.serialize_uncompressed(&mut pb).unwrap();
    proof.b.serialize_uncompressed(&mut pb).unwrap();
    proof.c.serialize_uncompressed(&mut pb).unwrap();
    pb[100] ^= 0x01;
    let tampered = Bytes::from_slice(&env, &pb);

    let mut pubs: SVec<BytesN<32>> = SVec::new(&env);
    pubs.push_back(fr_bytes(&env, &c));

    let res = client.try_verify(&1, &tampered, &pubs);
    // Either verification returns false, or the host rejects the malformed
    // point with an error; both are acceptable rejections.
    match res {
        Ok(Ok(valid)) => assert!(!valid),
        _ => {}
    }
}
