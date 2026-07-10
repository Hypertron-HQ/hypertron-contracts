//! Hypertron Proof Verifier
//!
//! A real on-chain Groth16 verifier built on Soroban's BLS12-381 host
//! functions (CAP-0059). Verification keys are registered on-chain and
//! referenced by id, so backends and circuits can be upgraded without
//! changing calling contracts. The proof is accepted at the contract
//! boundary as raw bytes so alternative backends can interpret them
//! differently — this is the pluggable-verifier seam.
//!
//! Groth16 check: e(A,B) == e(alpha,beta) * e(vk_x,gamma) * e(C,delta),
//! rearranged into a single multi-pairing:
//!   e(-A,B) * e(alpha,beta) * e(vk_x,gamma) * e(C,delta) == 1
//! where vk_x = IC[0] + sum_i public_i * IC[i].
#![no_std]

use soroban_sdk::{
    contract, contractevent, contracterror, contractimpl, contracttype,
    crypto::bls12_381::{Fr, G1Affine, G2Affine},
    Address, Bytes, BytesN, Env, Vec,
};

/// Emitted when a verification key is registered.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VkRegistered {
    #[topic]
    pub vk_id: u32,
}

/// Groth16 proof serialized as 3 curve points: A(G1,96) ‖ B(G2,192) ‖ C(G1,96).
const PROOF_LEN: u32 = 96 + 192 + 96;

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    VkNotFound = 3,
    BadProofLength = 4,
    PublicInputMismatch = 5,
}

/// Groth16 verification key. Points are stored as uncompressed BLS12-381 bytes.
#[contracttype]
#[derive(Clone)]
pub struct VerifyingKey {
    pub alpha: BytesN<96>,       // G1
    pub beta: BytesN<192>,       // G2
    pub gamma: BytesN<192>,      // G2
    pub delta: BytesN<192>,      // G2
    pub ic: Vec<BytesN<96>>,     // G1, length = num_public_inputs + 1
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Admin,
    Vk(u32),
}

#[contract]
pub struct VerifierContract;

#[contractimpl]
impl VerifierContract {
    /// Initialize with an admin who may register verification keys.
    pub fn initialize(env: Env, admin: Address) -> Result<(), Error> {
        if env.storage().instance().has(&Key::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&Key::Admin, &admin);
        Ok(())
    }

    /// Register (or replace) a verification key under `vk_id`. Admin-gated.
    pub fn register_vk(env: Env, vk_id: u32, vk: VerifyingKey) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&Key::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();
        env.storage().persistent().set(&Key::Vk(vk_id), &vk);
        VkRegistered { vk_id }.publish(&env);
        Ok(())
    }

    pub fn has_vk(env: Env, vk_id: u32) -> bool {
        env.storage().persistent().has(&Key::Vk(vk_id))
    }

    /// Verify a Groth16 proof on-chain. Returns true iff the proof is valid.
    pub fn verify(
        env: Env,
        vk_id: u32,
        proof: Bytes,
        public_inputs: Vec<BytesN<32>>,
    ) -> Result<bool, Error> {
        let vk: VerifyingKey = env
            .storage()
            .persistent()
            .get(&Key::Vk(vk_id))
            .ok_or(Error::VkNotFound)?;

        if proof.len() != PROOF_LEN {
            return Err(Error::BadProofLength);
        }
        // IC must have exactly one entry per public input, plus the constant.
        if vk.ic.len() != public_inputs.len() + 1 {
            return Err(Error::PublicInputMismatch);
        }

        let bls = env.crypto().bls12_381();

        // Parse proof points.
        let a = G1Affine::from_bytes(bn96(&env, &proof, 0));
        let b = G2Affine::from_bytes(bn192(&env, &proof, 96));
        let c = G1Affine::from_bytes(bn96(&env, &proof, 288));

        // vk_x = IC[0] + sum_i public_i * IC[i+1]
        let mut vk_x = G1Affine::from_bytes(vk.ic.get(0).unwrap());
        let n = public_inputs.len();
        if n > 0 {
            let mut points: Vec<G1Affine> = Vec::new(&env);
            let mut scalars: Vec<Fr> = Vec::new(&env);
            let mut i = 0;
            while i < n {
                points.push_back(G1Affine::from_bytes(vk.ic.get(i + 1).unwrap()));
                scalars.push_back(Fr::from_bytes(public_inputs.get(i).unwrap()));
                i += 1;
            }
            let acc = bls.g1_msm(points, scalars);
            vk_x = bls.g1_add(&vk_x, &acc);
        }

        // -A via multiplication by (r-1) = -1 in Fr.
        let zero = Fr::from_bytes(BytesN::from_array(&env, &[0u8; 32]));
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one = Fr::from_bytes(BytesN::from_array(&env, &one_bytes));
        let neg_one = bls.fr_sub(&zero, &one);
        let a_neg = bls.g1_mul(&a, &neg_one);

        let mut vp1: Vec<G1Affine> = Vec::new(&env);
        vp1.push_back(a_neg);
        vp1.push_back(G1Affine::from_bytes(vk.alpha.clone()));
        vp1.push_back(vk_x);
        vp1.push_back(c);

        let mut vp2: Vec<G2Affine> = Vec::new(&env);
        vp2.push_back(b);
        vp2.push_back(G2Affine::from_bytes(vk.beta.clone()));
        vp2.push_back(G2Affine::from_bytes(vk.gamma.clone()));
        vp2.push_back(G2Affine::from_bytes(vk.delta.clone()));

        Ok(bls.pairing_check(vp1, vp2))
    }
}

fn bn96(env: &Env, b: &Bytes, off: u32) -> BytesN<96> {
    let mut buf = [0u8; 96];
    b.slice(off..off + 96).copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}

fn bn192(env: &Env, b: &Bytes, off: u32) -> BytesN<192> {
    let mut buf = [0u8; 192];
    b.slice(off..off + 192).copy_into_slice(&mut buf);
    BytesN::from_array(env, &buf)
}

#[cfg(test)]
mod test;

#[cfg(test)]
mod e2e_test;

#[cfg(test)]
mod poseidon_gate;

#[cfg(test)]
mod circuit;
