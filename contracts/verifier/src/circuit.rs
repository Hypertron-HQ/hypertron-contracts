//! On-chain verification of the Hypertron membership circuit.
//!
//! The circuit + prover live in the `hypertron-prover` crate (the same code the
//! `hypertron-prove` CLI ships to integrators). Here we prove that a REAL proof
//! from that crate verifies inside the deployed `VerifierContract`, and drive a
//! full shielded-pool deposit -> prove -> withdraw with no mocks.
#![cfg(test)]

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;

use hypertron_prover::circuit::{MembershipCircuit, DEPTH};
use hypertron_prover::groth16;
use hypertron_prover::merkle;

use crate::{VerifierContract, VerifierContractClient, VerifyingKey};
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec as SVec};

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
    let leaf = merkle::leaf(n, k);

    let commitment_id = env.register(hypertron_commitment::CommitmentContract, ());
    let tree = hypertron_commitment::CommitmentContractClient::new(&env, &commitment_id);
    tree.initialize(&Address::generate(&env));
    tree.insert(&fr_to_bytesn(&env, &leaf)); // leftmost leaf, index 0
    let root_bytes = tree.root();
    let root = bytesn_to_fr(&root_bytes);

    // ---- 2. Reconstruct the path off-chain with the prover's Merkle helper.
    let (root_off, siblings, path_bits) = merkle::path(&[leaf], 0, DEPTH);
    assert_eq!(root_off, root, "off-chain root must equal on-chain root");

    let nullifier_hash = merkle::nullifier(n);
    let recipient_fe = Fr::from(0xC0FFEEu64);
    let amount_fe = Fr::from(50u64);

    // ---- 3. Groth16 setup + prove the membership statement.
    let (pk, vk) = groth16::setup(DEPTH, 7).unwrap();
    let circuit = MembershipCircuit {
        root: Some(root),
        nullifier_hash: Some(nullifier_hash),
        recipient: Some(recipient_fe),
        amount: Some(amount_fe),
        n: Some(n),
        k: Some(k),
        siblings: siblings.into_iter().map(Some).collect(),
        path_bits: path_bits.into_iter().map(Some).collect(),
    };
    let proof = groth16::prove(&pk, circuit, 7).unwrap();

    // Sanity: verifies off-chain.
    assert!(groth16::verify(&vk, &[root, nullifier_hash, recipient_fe, amount_fe], &proof));

    // ---- 4. Verify the SAME proof ON-CHAIN against the real root.
    let verifier_id = env.register(VerifierContract, ());
    let verifier = VerifierContractClient::new(&env, &verifier_id);
    verifier.initialize(&Address::generate(&env));
    verifier.register_vk(&1, &to_soroban_vk(&env, &vk));

    let mut pubs: SVec<BytesN<32>> = SVec::new(&env);
    pubs.push_back(root_bytes.clone());
    pubs.push_back(fr_to_bytesn(&env, &nullifier_hash));
    pubs.push_back(fr_to_bytesn(&env, &recipient_fe));
    pubs.push_back(fr_to_bytesn(&env, &amount_fe));
    assert!(verifier.verify(&1, &proof_to_bytes(&env, &proof), &pubs));

    // A proof presented against a different (wrong) root must fail.
    let mut bad = SVec::new(&env);
    bad.push_back(fr_to_bytesn(&env, &Fr::from(999u64)));
    bad.push_back(fr_to_bytesn(&env, &nullifier_hash));
    bad.push_back(fr_to_bytesn(&env, &recipient_fe));
    bad.push_back(fr_to_bytesn(&env, &amount_fe));
    assert!(!verifier.verify(&1, &proof_to_bytes(&env, &proof), &bad));

    // A proof presented for a DIFFERENT recipient must fail: the relayer-
    // rebinding attack the recipient public input defends against.
    let mut wrong_recipient = SVec::new(&env);
    wrong_recipient.push_back(root_bytes.clone());
    wrong_recipient.push_back(fr_to_bytesn(&env, &nullifier_hash));
    wrong_recipient.push_back(fr_to_bytesn(&env, &Fr::from(0xBADu64)));
    wrong_recipient.push_back(fr_to_bytesn(&env, &amount_fe));
    assert!(!verifier.verify(&1, &proof_to_bytes(&env, &proof), &wrong_recipient));
}

/// End-to-end: a real note is deposited into the shielded pool, a REAL Groth16
/// proof is produced off-chain (via `hypertron-prover`) binding (root, nullifier,
/// recipient, amount), and `transfer.withdraw` verifies it on-chain via the real
/// verifier, spends the nullifier, and pays the recipient. No mocks.
#[test]
fn full_shielded_pool_withdraw_with_real_proof() {
    use hypertron_commitment::{CommitmentContract, CommitmentContractClient};
    use hypertron_nullifier::{NullifierContract, NullifierContractClient};
    use hypertron_transfer::{Config, PrivacyLevel, TransferContract, TransferContractClient};
    use soroban_sdk::{
        token::{Client as TokenClient, StellarAssetClient},
        xdr::ToXdr,
    };

    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();

    // ---- Token + component contracts.
    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let token = sac.address();
    let token_admin = StellarAssetClient::new(&env, &token);

    let commitment_id = env.register(CommitmentContract, ());
    let nullifier_id = env.register(NullifierContract, ());
    let verifier_id = env.register(VerifierContract, ());
    let transfer_id = env.register(TransferContract, ());

    CommitmentContractClient::new(&env, &commitment_id).initialize(&transfer_id);
    NullifierContractClient::new(&env, &nullifier_id).initialize(&transfer_id);

    let pool = TransferContractClient::new(&env, &transfer_id);
    pool.initialize(&Config {
        token: token.clone(),
        commitment: commitment_id.clone(),
        nullifier: nullifier_id.clone(),
        verifier: verifier_id.clone(),
        vk_id: 1,
    });

    // ---- 1. Deposit a real note into the pool (leaf = Poseidon(n, k)).
    let n = Fr::from(424242u64);
    let k = Fr::from(133742u64);
    let leaf = merkle::leaf(n, k);

    let depositor = Address::generate(&env);
    token_admin.mint(&depositor, &1000);
    pool.deposit(&depositor, &100, &fr_to_bytesn(&env, &leaf));

    let root_bytes = CommitmentContractClient::new(&env, &commitment_id).root();
    let root = bytesn_to_fr(&root_bytes);

    // ---- 2. Off-chain: reconstruct the path and derive the public inputs.
    let (_root_off, siblings, path_bits) = merkle::path(&[leaf], 0, DEPTH);
    let nullifier_hash = merkle::nullifier(n);

    let recipient = Address::generate(&env);
    let amount: i128 = 50;
    // Must match `transfer::recipient_field` / `amount_field` exactly.
    let recipient_bytes = env.crypto().sha256(&recipient.clone().to_xdr(&env)).to_bytes();
    let recipient_fe = bytesn_to_fr(&recipient_bytes);
    let amount_fe = groth16::amount_fr(amount as u128);

    // ---- 3. Groth16 setup + prove.
    let (pk, _vk) = groth16::setup(DEPTH, 99).unwrap();
    let proof = groth16::prove(
        &pk,
        MembershipCircuit {
            root: Some(root),
            nullifier_hash: Some(nullifier_hash),
            recipient: Some(recipient_fe),
            amount: Some(amount_fe),
            n: Some(n),
            k: Some(k),
            siblings: siblings.into_iter().map(Some).collect(),
            path_bits: path_bits.into_iter().map(Some).collect(),
        },
        99,
    )
    .unwrap();

    // ---- 4. Register the VK and run the REAL withdrawal.
    let verifier = VerifierContractClient::new(&env, &verifier_id);
    verifier.initialize(&Address::generate(&env));
    verifier.register_vk(&1, &to_soroban_vk(&env, &pk.vk));

    let claim = PrivacyLevel {
        sender: true,
        receiver: false,
        amount: true,
        timing: false,
        linkability: true,
    };
    let att = pool.withdraw(
        &proof_to_bytes(&env, &proof),
        &root_bytes,
        &fr_to_bytesn(&env, &nullifier_hash),
        &recipient,
        &amount,
        &claim,
    );

    assert_eq!(TokenClient::new(&env, &token).balance(&recipient), 50);
    assert_eq!(TokenClient::new(&env, &token).balance(&transfer_id), 50);
    assert!(att.level.sender);
    assert_eq!(att.root, root_bytes);

    // ---- 5. The proof is bound to `amount`: replaying it for a different
    // amount is rejected.
    let n2 = Fr::from(555u64);
    let leaf2 = merkle::leaf(n2, k);
    pool.deposit(&depositor, &100, &fr_to_bytesn(&env, &leaf2));
    let bad = pool.try_withdraw(
        &proof_to_bytes(&env, &proof),
        &CommitmentContractClient::new(&env, &commitment_id).root(),
        &fr_to_bytesn(&env, &merkle::nullifier(n2)),
        &recipient,
        &40, // != bound amount (50) -> proof invalid
        &claim,
    );
    assert!(bad.is_err());
}
