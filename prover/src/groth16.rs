//! Groth16 setup / prove / serialization for the membership circuit.
//!
//! All group/scalar serialization matches what the on-chain verifier decodes:
//!   - G1 uncompressed = 96 bytes, G2 uncompressed = 192 bytes,
//!   - scalars = 32-byte big-endian,
//!   - proof = A(G1) || B(G2) || C(G1) = 384 bytes,
//!   - verifying key = alpha(G1), beta(G2), gamma(G2), delta(G2), ic(Vec<G1>).

use anyhow::Result;
use ark_bls12_381::{Bls12_381, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{Groth16, Proof, ProvingKey, VerifyingKey};
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};

/// Verifying key in the exact shape the `hypertron-verifier` contract stores,
/// hex-encoded for transport / on-chain registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VkJson {
    pub alpha: String,
    pub beta: String,
    pub gamma: String,
    pub delta: String,
    pub ic: Vec<String>,
}

/// A proof plus the public inputs it was bound to, ready to submit on-chain.
/// The `public_inputs` order matches the corresponding circuit's allocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofJson {
    pub proof: String,
    pub public_inputs: Vec<String>,
}

/// Run a Groth16 setup for any circuit shape.
///
/// NOTE: this is a *local, deterministic* setup for development and testing.
/// A production deployment must run a proper multi-party trusted-setup ceremony
/// and publish the resulting verifying key (see `docs/ceremony.md`).
pub fn setup<C: ConstraintSynthesizer<Fr>>(
    circuit: C,
    seed: u64,
) -> Result<(ProvingKey<Bls12_381>, VerifyingKey<Bls12_381>)> {
    let mut rng = StdRng::seed_from_u64(seed);
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(circuit, &mut rng)?;
    Ok((pk, vk))
}

/// Produce a proof for a fully-assigned witness.
pub fn prove<C: ConstraintSynthesizer<Fr>>(
    pk: &ProvingKey<Bls12_381>,
    circuit: C,
    seed: u64,
) -> Result<Proof<Bls12_381>> {
    let mut rng = StdRng::seed_from_u64(seed);
    Ok(Groth16::<Bls12_381>::prove(pk, circuit, &mut rng)?)
}

/// Off-chain sanity check (same pairing equation the contract runs on-chain).
pub fn verify(vk: &VerifyingKey<Bls12_381>, public_inputs: &[Fr], proof: &Proof<Bls12_381>) -> bool {
    Groth16::<Bls12_381>::verify(vk, public_inputs, proof).unwrap_or(false)
}

fn g1_bytes(p: &G1Affine) -> [u8; 96] {
    let mut v = Vec::new();
    p.serialize_uncompressed(&mut v).expect("g1 serialize");
    let mut buf = [0u8; 96];
    buf.copy_from_slice(&v);
    buf
}

fn g2_bytes(p: &G2Affine) -> [u8; 192] {
    let mut v = Vec::new();
    p.serialize_uncompressed(&mut v).expect("g2 serialize");
    let mut buf = [0u8; 192];
    buf.copy_from_slice(&v);
    buf
}

/// Scalar -> 32-byte big-endian (matches `Fr::from_bytes` / `U256::from_be_bytes`).
pub fn fr_be32(f: &Fr) -> [u8; 32] {
    let be = f.into_bigint().to_bytes_be();
    let mut buf = [0u8; 32];
    buf[(32 - be.len())..].copy_from_slice(&be);
    buf
}

/// Encode a verifying key for on-chain registration.
pub fn vk_json(vk: &VerifyingKey<Bls12_381>) -> VkJson {
    VkJson {
        alpha: hex::encode(g1_bytes(&vk.alpha_g1)),
        beta: hex::encode(g2_bytes(&vk.beta_g2)),
        gamma: hex::encode(g2_bytes(&vk.gamma_g2)),
        delta: hex::encode(g2_bytes(&vk.delta_g2)),
        ic: vk.gamma_abc_g1.iter().map(|p| hex::encode(g1_bytes(p))).collect(),
    }
}

/// Serialize a proof to the 384-byte on-chain layout, hex-encoded.
pub fn proof_hex(proof: &Proof<Bls12_381>) -> String {
    let mut pb = Vec::new();
    proof.a.serialize_uncompressed(&mut pb).expect("proof.a");
    proof.b.serialize_uncompressed(&mut pb).expect("proof.b");
    proof.c.serialize_uncompressed(&mut pb).expect("proof.c");
    hex::encode(pb)
}

/// Proving keys are large; persist them with arkworks' canonical (compressed)
/// encoding so `prove` can reload the exact same key produced by `setup`.
pub fn pk_to_bytes(pk: &ProvingKey<Bls12_381>) -> Result<Vec<u8>> {
    let mut v = Vec::new();
    pk.serialize_compressed(&mut v)?;
    Ok(v)
}

pub fn pk_from_bytes(bytes: &[u8]) -> Result<ProvingKey<Bls12_381>> {
    Ok(ProvingKey::<Bls12_381>::deserialize_compressed(bytes)?)
}

/// Amount (as an unsigned integer) -> field element, matching the on-chain
/// `transfer::amount_field` (big-endian encoding reduced mod the scalar field).
pub fn amount_fr(amount: u128) -> Fr {
    Fr::from(amount)
}
