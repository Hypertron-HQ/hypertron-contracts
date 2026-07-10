//! The Hypertron transaction circuit (Phase 1): shielded-pool membership +
//! nullifier derivation, proved in zero knowledge over BLS12-381 and verified
//! on-chain by [`VerifierContract`].
//!
//! Statement proved (public inputs: `[root, nullifier_hash]`):
//!   - I know a note `(n, k)` whose commitment `leaf = Poseidon(n, k)` is a
//!     member of the Merkle tree with the given `root`, AND
//!   - `nullifier_hash = Poseidon(n, 0)` (deterministic per note -> double-spend
//!     protection without linking to the deposit).
//!
//! The in-circuit Poseidon uses the exact parameters of the on-chain host
//! (proved equivalent by `poseidon_gate`), so proofs verify against real
//! on-chain roots.
#![cfg(test)]

use ark_bls12_381::Fr;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar,
    select::CondSelectGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_std::vec::Vec;

use super::poseidon_gate::{mds_fr, rc_fr, HALF_F, N_ROUNDS};

/// Must match the on-chain commitment tree depth.
pub(crate) const DEPTH: usize = 20;

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
        // ARC
        for i in 0..3 {
            state[i] = &state[i] + FpVar::constant(rc[round][i]);
        }
        // S-box (full: all; partial: index 0 only)
        let full = round < HALF_F || round >= N_ROUNDS - HALF_F;
        if full {
            for i in 0..3 {
                state[i] = pow5_var(&state[i])?;
            }
        } else {
            state[0] = pow5_var(&state[0])?;
        }
        // MDS
        let mut ns: [FpVar<Fr>; 3] =
            core::array::from_fn(|_| FpVar::constant(Fr::from(0u64)));
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

fn hash2_var(
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    mds: &[[Fr; 3]; 3],
    rc: &[[Fr; 3]; 64],
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut state = [FpVar::constant(Fr::from(0u64)), a.clone(), b.clone()];
    permute_var(&mut state, mds, rc)?;
    Ok(state[0].clone())
}

pub(crate) struct MembershipCircuit {
    // public inputs
    pub root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    // private witness
    pub n: Option<Fr>,
    pub k: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub path_bits: Vec<Option<bool>>,
}

impl ConstraintSynthesizer<Fr> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mds = mds_fr();
        let rc = rc_fr();

        // Public inputs, allocation order = [root, nullifier_hash].
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_hash = FpVar::new_input(cs.clone(), || {
            self.nullifier_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Note secrets.
        let n = FpVar::new_witness(cs.clone(), || {
            self.n.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let k = FpVar::new_witness(cs.clone(), || {
            self.k.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // leaf = Poseidon(n, k)
        let mut cur = hash2_var(&n, &k, &mds, &rc)?;

        // Walk up the Merkle path to the root.
        for i in 0..DEPTH {
            let sib = FpVar::new_witness(cs.clone(), || {
                self.siblings[i].ok_or(SynthesisError::AssignmentMissing)
            })?;
            let bit = Boolean::new_witness(cs.clone(), || {
                self.path_bits[i].ok_or(SynthesisError::AssignmentMissing)
            })?;
            // bit = 1 => current node is the right child.
            let left = FpVar::conditionally_select(&bit, &sib, &cur)?;
            let right = FpVar::conditionally_select(&bit, &cur, &sib)?;
            cur = hash2_var(&left, &right, &mds, &rc)?;
        }
        cur.enforce_equal(&root)?;

        // nullifier_hash = Poseidon(n, 0)
        let zero = FpVar::constant(Fr::from(0u64));
        let computed = hash2_var(&n, &zero, &mds, &rc)?;
        computed.enforce_equal(&nullifier_hash)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poseidon_gate::poseidon2to1;
    use crate::{VerifierContract, VerifierContractClient, VerifyingKey};

    use ark_bls12_381::Bls12_381;
    use ark_ff::{BigInteger, PrimeField};
    use ark_groth16::Groth16;
    use ark_serialize::CanonicalSerialize;
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    use hypertron_commitment::{CommitmentContract, CommitmentContractClient};
    use soroban_sdk::{
        testutils::Address as _, Address, Bytes, BytesN, Env, Vec as SVec,
    };

    fn fr_to_bytesn(env: &Env, f: &Fr) -> BytesN<32> {
        let be = f.into_bigint().to_bytes_be();
        let mut buf = [0u8; 32];
        buf[(32 - be.len())..].copy_from_slice(&be);
        BytesN::from_array(env, &buf)
    }

    fn bytesn_to_fr(b: &BytesN<32>) -> Fr {
        Fr::from_be_bytes_mod_order(&b.to_array())
    }

    fn g1_bytes(env: &Env, p: &ark_bls12_381::G1Affine) -> BytesN<96> {
        let mut v = ark_std::vec::Vec::new();
        p.serialize_uncompressed(&mut v).unwrap();
        let mut buf = [0u8; 96];
        buf.copy_from_slice(&v);
        BytesN::from_array(env, &buf)
    }
    fn g2_bytes(env: &Env, p: &ark_bls12_381::G2Affine) -> BytesN<192> {
        let mut v = ark_std::vec::Vec::new();
        p.serialize_uncompressed(&mut v).unwrap();
        let mut buf = [0u8; 192];
        buf.copy_from_slice(&v);
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
        proof.a.serialize_uncompressed(&mut pb).unwrap();
        proof.b.serialize_uncompressed(&mut pb).unwrap();
        proof.c.serialize_uncompressed(&mut pb).unwrap();
        Bytes::from_slice(env, &pb)
    }

    #[test]
    fn real_membership_proof_verifies_on_chain() {
        let env = Env::default();
        env.mock_all_auths();

        // ---- 1. Build a note and insert its commitment into the ON-CHAIN tree.
        let n = Fr::from(11111u64);
        let k = Fr::from(22222u64);
        let leaf = poseidon2to1(n, k);

        let commitment_id = env.register(CommitmentContract, ());
        let tree = CommitmentContractClient::new(&env, &commitment_id);
        tree.initialize(&Address::generate(&env));
        tree.insert(&fr_to_bytesn(&env, &leaf)); // leftmost leaf, index 0
        let root_bytes = tree.root();
        let root = bytesn_to_fr(&root_bytes);

        // ---- 2. Reconstruct the (leftmost) Merkle path off-chain.
        let mut siblings: Vec<Option<Fr>> = Vec::new();
        let mut path_bits: Vec<Option<bool>> = Vec::new();
        let mut zero_i = Fr::from(0u64);
        for _ in 0..DEPTH {
            siblings.push(Some(zero_i));
            path_bits.push(Some(false));
            zero_i = poseidon2to1(zero_i, zero_i);
        }

        let nullifier_hash = poseidon2to1(n, Fr::from(0u64));

        // ---- 3. Groth16 setup + prove the membership statement.
        let mut rng = StdRng::seed_from_u64(7);
        let setup_circuit = MembershipCircuit {
            root: None,
            nullifier_hash: None,
            n: None,
            k: None,
            siblings: ark_std::vec![None; DEPTH],
            path_bits: ark_std::vec![None; DEPTH],
        };
        let (pk, vk) =
            Groth16::<Bls12_381>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();

        let witness = MembershipCircuit {
            root: Some(root),
            nullifier_hash: Some(nullifier_hash),
            n: Some(n),
            k: Some(k),
            siblings: siblings.clone(),
            path_bits: path_bits.clone(),
        };
        let proof = Groth16::<Bls12_381>::prove(&pk, witness, &mut rng).unwrap();

        // Sanity: verifies off-chain.
        assert!(Groth16::<Bls12_381>::verify(&vk, &[root, nullifier_hash], &proof).unwrap());

        // ---- 4. Verify the SAME proof ON-CHAIN against the real root.
        let verifier_id = env.register(VerifierContract, ());
        let verifier = VerifierContractClient::new(&env, &verifier_id);
        verifier.initialize(&Address::generate(&env));
        verifier.register_vk(&1, &to_soroban_vk(&env, &vk));

        let mut pubs: SVec<BytesN<32>> = SVec::new(&env);
        pubs.push_back(root_bytes.clone());
        pubs.push_back(fr_to_bytesn(&env, &nullifier_hash));

        assert!(verifier.verify(&1, &proof_to_bytes(&env, &proof), &pubs));

        // A proof presented against a different (wrong) root must fail.
        let mut bad = SVec::new(&env);
        bad.push_back(fr_to_bytesn(&env, &Fr::from(999u64)));
        bad.push_back(fr_to_bytesn(&env, &nullifier_hash));
        assert!(!verifier.verify(&1, &proof_to_bytes(&env, &proof), &bad));
    }
}
