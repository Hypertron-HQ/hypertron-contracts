//! On-chain verification of the Hypertron transaction circuits.
//!
//! The circuits + prover live in the `hypertron-prover` crate (the same code the
//! `hypertron-prove` CLI ships to integrators). Here we prove that REAL proofs
//! from that crate verify inside the deployed `VerifierContract`, and drive a
//! full shielded-pool lifecycle — deposit (value-bound) -> unshield (with change)
//! -> fully-private transfer — end to end with no mocks.
#![cfg(test)]

use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use ark_std::vec;

use hypertron_prover::circuit::{
    DepositCircuit, Transfer2Circuit, Transfer4Circuit, TransferCircuit, TransferInput,
    UnshieldCircuit, DEPTH,
};
use hypertron_prover::note::Note;
use hypertron_prover::{groth16, merkle};

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

/// A real unshield proof verifies on-chain, and every public input is bound:
/// wrong root, wrong recipient, or wrong amount all fail.
#[test]
fn real_unshield_proof_verifies_on_chain() {
    let env = Env::default();
    env.mock_all_auths();
    // Real pairing checks + Poseidon Merkle updates are heavier than the tiny
    // default test budget; use a realistic (unbounded) budget for these tests.
    env.cost_estimate().budget().reset_unlimited();

    // Value-committed note worth 1000, inserted into the on-chain tree.
    let input_spend_sk = Fr::from(11111u64);
    let input = Note::from_spend_key(input_spend_sk, Fr::from(22222u64), Fr::from(1000u64));
    let leaf = input.commitment();

    let commitment_id = env.register(hypertron_commitment::CommitmentContract, ());
    let tree = hypertron_commitment::CommitmentContractClient::new(&env, &commitment_id);
    tree.initialize(&Address::generate(&env));
    tree.insert(&fr_to_bytesn(&env, &leaf));
    let root_bytes = tree.root();
    let root = bytesn_to_fr(&root_bytes);

    let (root_off, siblings, path_bits) = merkle::path(&[leaf], 0, DEPTH);
    assert_eq!(root_off, root, "off-chain root must equal on-chain root");

    let nf = input.nullifier(input_spend_sk);
    let recipient_fe = Fr::from(0xC0FFEEu64);
    let amount = Fr::from(700u64);
    let change = Note::from_spend_key(input_spend_sk, Fr::from(10u64), Fr::from(300u64));
    let change_cm = change.commitment();

    let (pk, vk) =
        groth16::setup(UnshieldCircuit::empty(DEPTH), &mut groth16::insecure_dev_rng(7)).unwrap();
    let circuit = UnshieldCircuit {
        root: Some(root),
        nullifier: Some(nf),
        recipient: Some(recipient_fe),
        amount: Some(amount),
        change_cm: Some(change_cm),
        spend_sk: Some(input_spend_sk),
        k: Some(input.k),
        v: Some(input.v),
        siblings: siblings.into_iter().map(Some).collect(),
        path_bits: path_bits.into_iter().map(Some).collect(),
        k2: Some(change.k),
        vc: Some(change.v),
    };
    let proof = groth16::prove(&pk, circuit, &mut groth16::insecure_dev_rng(7)).unwrap();
    assert!(groth16::verify(&vk, &[root, nf, recipient_fe, amount, change_cm], &proof));

    let verifier_id = env.register(VerifierContract, ());
    let verifier = VerifierContractClient::new(&env, &verifier_id);
    verifier.initialize(&Address::generate(&env));
    verifier.register_vk(&1, &to_soroban_vk(&env, &vk));

    let good = |a, b, c, d, e| {
        let mut p: SVec<BytesN<32>> = SVec::new(&env);
        p.push_back(a);
        p.push_back(b);
        p.push_back(c);
        p.push_back(d);
        p.push_back(e);
        p
    };
    let proof_bytes = proof_to_bytes(&env, &proof);
    let rec = fr_to_bytesn(&env, &recipient_fe);
    let amt = fr_to_bytesn(&env, &amount);
    let ch = fr_to_bytesn(&env, &change_cm);
    let nfb = fr_to_bytesn(&env, &nf);

    assert!(verifier.verify(&1, &proof_bytes, &good(root_bytes.clone(), nfb.clone(), rec.clone(), amt.clone(), ch.clone())));
    // Wrong root.
    assert!(!verifier.verify(&1, &proof_bytes, &good(fr_to_bytesn(&env, &Fr::from(999u64)), nfb.clone(), rec.clone(), amt.clone(), ch.clone())));
    // Wrong recipient (relayer-rebinding defense).
    assert!(!verifier.verify(&1, &proof_bytes, &good(root_bytes.clone(), nfb.clone(), fr_to_bytesn(&env, &Fr::from(0xBADu64)), amt.clone(), ch.clone())));
    // Wrong amount (value-conservation binding).
    assert!(!verifier.verify(&1, &proof_bytes, &good(root_bytes.clone(), nfb, rec, fr_to_bytesn(&env, &Fr::from(800u64)), ch)));
}

/// Full end-to-end lifecycle with REAL proofs and no mocks:
///   1. deposit a value-bound note (deposit circuit),
///   2. unshield part of it to a public recipient, keeping a change note,
///   3. fully-private transfer of a second note into two output notes.
#[test]
fn full_shielded_pool_lifecycle_with_real_proofs() {
    use hypertron_commitment::{CommitmentContract, CommitmentContractClient};
    use hypertron_nullifier::{NullifierContract, NullifierContractClient};
    use hypertron_transfer::{Config, PrivacyLevel, TransferContract, TransferContractClient};
    use soroban_sdk::{
        token::{Client as TokenClient, StellarAssetClient},
        xdr::ToXdr,
    };

    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();
    env.cost_estimate().budget().reset_unlimited();

    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let token = sac.address();
    let token_admin = StellarAssetClient::new(&env, &token);

    let commitment_id = env.register(CommitmentContract, ());
    let nullifier_id = env.register(NullifierContract, ());
    let verifier_id = env.register(VerifierContract, ());
    let transfer_id = env.register(TransferContract, ());

    CommitmentContractClient::new(&env, &commitment_id).initialize(&transfer_id);
    NullifierContractClient::new(&env, &nullifier_id).initialize(&transfer_id);

    // Three circuits, three verifying keys.
    let (deposit_pk, deposit_vk) =
        groth16::setup(DepositCircuit::empty(), &mut groth16::insecure_dev_rng(1)).unwrap();
    let (unshield_pk, unshield_vk) =
        groth16::setup(UnshieldCircuit::empty(DEPTH), &mut groth16::insecure_dev_rng(2)).unwrap();
    let (transfer_pk, transfer_vk) =
        groth16::setup(TransferCircuit::empty(DEPTH), &mut groth16::insecure_dev_rng(3)).unwrap();

    let verifier = VerifierContractClient::new(&env, &verifier_id);
    verifier.initialize(&Address::generate(&env));
    verifier.register_vk(&1, &to_soroban_vk(&env, &deposit_vk));
    verifier.register_vk(&2, &to_soroban_vk(&env, &unshield_vk));
    verifier.register_vk(&3, &to_soroban_vk(&env, &transfer_vk));

    let pool = TransferContractClient::new(&env, &transfer_id);
    pool.initialize(&Config {
        token: token.clone(),
        commitment: commitment_id.clone(),
        nullifier: nullifier_id.clone(),
        verifier: verifier_id.clone(),
        deposit_vk_id: 1,
        unshield_vk_id: 2,
        transfer_vk_id: 3,
        transfer_2in_vk_id: 4,
        transfer_4in_vk_id: 5,
        compliance: None,
    });
    let tree = CommitmentContractClient::new(&env, &commitment_id);

    let depositor = Address::generate(&env);
    token_admin.mint(&depositor, &10_000);

    // ---- 1. Deposit note A worth 100 (value bound by a real deposit proof). --
    let a_spend_sk = Fr::from(424242u64);
    let a = Note::from_spend_key(a_spend_sk, Fr::from(133742u64), Fr::from(100u64));
    let deposit_proof = groth16::prove(
        &deposit_pk,
        DepositCircuit {
            cm: Some(a.commitment()),
            amount: Some(a.v),
            owner_pk: Some(a.owner_pk),
            k: Some(a.k),
        },
        &mut groth16::insecure_dev_rng(11),
    )
    .unwrap();
    pool.deposit(
        &depositor,
        &100,
        &fr_to_bytesn(&env, &a.commitment()),
        &proof_to_bytes(&env, &deposit_proof),
    );
    let mut leaves = vec![a.commitment()]; // mirror of the on-chain tree
    let root_a_bytes = tree.root();
    let root_a = bytesn_to_fr(&root_a_bytes);

    // ---- 2. Unshield 60 to a recipient, 40 stays as a change note. ----------
    let recipient = Address::generate(&env);
    let amount: i128 = 60;
    let recipient_bytes = env.crypto().sha256(&recipient.clone().to_xdr(&env)).to_bytes();
    let recipient_fe = bytesn_to_fr(&recipient_bytes);
    let change = Note::from_spend_key(a_spend_sk, Fr::from(6u64), Fr::from(40u64));

    let (_r, siblings, path_bits) = merkle::path(&leaves, 0, DEPTH);
    let unshield_proof = groth16::prove(
        &unshield_pk,
        UnshieldCircuit {
            root: Some(root_a),
            nullifier: Some(a.nullifier(a_spend_sk)),
            recipient: Some(recipient_fe),
            amount: Some(Fr::from(amount as u64)),
            change_cm: Some(change.commitment()),
            spend_sk: Some(a_spend_sk),
            k: Some(a.k),
            v: Some(a.v),
            siblings: siblings.into_iter().map(Some).collect(),
            path_bits: path_bits.into_iter().map(Some).collect(),
            k2: Some(change.k),
            vc: Some(change.v),
        },
        &mut groth16::insecure_dev_rng(12),
    )
    .unwrap();

    let claim = PrivacyLevel {
        sender: true,
        receiver: false,
        amount: true,
        timing: false,
        linkability: true,
    };
    pool.unshield(
        &proof_to_bytes(&env, &unshield_proof),
        &root_a_bytes,
        &fr_to_bytesn(&env, &a.nullifier(a_spend_sk)),
        &recipient,
        &amount,
        &fr_to_bytesn(&env, &change.commitment()),
        &claim,
    );
    leaves.push(change.commitment()); // change re-inserted at index 1
    assert_eq!(TokenClient::new(&env, &token).balance(&recipient), 60);
    assert_eq!(TokenClient::new(&env, &token).balance(&transfer_id), 40);
    assert_eq!(tree.size(), 2);

    // ---- 3. Deposit note B worth 100, then privately transfer it. -----------
    let b_spend_sk = Fr::from(777u64);
    let b = Note::from_spend_key(b_spend_sk, Fr::from(888u64), Fr::from(100u64));
    let deposit_b = groth16::prove(
        &deposit_pk,
        DepositCircuit {
            cm: Some(b.commitment()),
            amount: Some(b.v),
            owner_pk: Some(b.owner_pk),
            k: Some(b.k),
        },
        &mut groth16::insecure_dev_rng(13),
    )
    .unwrap();
    pool.deposit(&depositor, &100, &fr_to_bytesn(&env, &b.commitment()), &proof_to_bytes(&env, &deposit_b));
    leaves.push(b.commitment()); // index 2
    let root_b_bytes = tree.root();
    let root_b = bytesn_to_fr(&root_b_bytes);

    // B (100) -> out1 (70, to recipient) + out2 (30, change). No public amount.
    let out1 = Note::new(Fr::from(101u64), Fr::from(102u64), Fr::from(70u64));
    let out2 = Note::new(Fr::from(201u64), Fr::from(202u64), Fr::from(30u64));
    let (_rb, sib_b, bits_b) = merkle::path(&leaves, 2, DEPTH);
    let transfer_proof = groth16::prove(
        &transfer_pk,
        TransferCircuit {
            root: Some(root_b),
            nullifier: Some(b.nullifier(b_spend_sk)),
            out_cm1: Some(out1.commitment()),
            out_cm2: Some(out2.commitment()),
            spend_sk: Some(b_spend_sk),
            k: Some(b.k),
            v: Some(b.v),
            siblings: sib_b.into_iter().map(Some).collect(),
            path_bits: bits_b.into_iter().map(Some).collect(),
            owner_pk1: Some(out1.owner_pk),
            k1: Some(out1.k),
            v1: Some(out1.v),
            owner_pk2: Some(out2.owner_pk),
            k2: Some(out2.k),
            v2: Some(out2.v),
        },
        &mut groth16::insecure_dev_rng(14),
    )
    .unwrap();

    let empty = Bytes::new(&env);
    pool.transfer(
        &proof_to_bytes(&env, &transfer_proof),
        &root_b_bytes,
        &fr_to_bytesn(&env, &b.nullifier(b_spend_sk)),
        &fr_to_bytesn(&env, &out1.commitment()),
        &fr_to_bytesn(&env, &out2.commitment()),
        &empty,
        &empty,
    );
    // Leaves so far: A, change, B, out1, out2 = 5. Nothing left the pool in the
    // private transfer, so the balance is still 40 (100 in from B) + 40 change.
    assert_eq!(tree.size(), 5);
    assert_eq!(TokenClient::new(&env, &token).balance(&transfer_id), 140);

    // Value conservation holds: a transfer whose outputs don't sum to the input
    // cannot even be proven, so no on-chain check is needed — but a replayed
    // (double-spent) nullifier is rejected.
    let bad = pool.try_transfer(
        &proof_to_bytes(&env, &transfer_proof),
        &root_b_bytes,
        &fr_to_bytesn(&env, &b.nullifier(b_spend_sk)),
        &fr_to_bytesn(&env, &out1.commitment()),
        &fr_to_bytesn(&env, &out2.commitment()),
        &empty,
        &empty,
    );
    assert!(bad.is_err());
}

fn deposit_note(
    env: &Env,
    pool: &hypertron_transfer::TransferContractClient,
    depositor: &Address,
    deposit_pk: &ark_groth16::ProvingKey<Bls12_381>,
    note: &Note,
    amount: i128,
    rng_seed: u64,
) {
    let deposit_proof = groth16::prove(
        deposit_pk,
        DepositCircuit {
            cm: Some(note.commitment()),
            amount: Some(note.v),
            owner_pk: Some(note.owner_pk),
            k: Some(note.k),
        },
        &mut groth16::insecure_dev_rng(rng_seed),
    )
    .unwrap();
    pool.deposit(
        depositor,
        &amount,
        &fr_to_bytesn(env, &note.commitment()),
        &proof_to_bytes(env, &deposit_proof),
    );
}

fn transfer_n_inputs<const N: usize>(
    spend_sk: Fr,
    notes: &[Note],
    leaves: &[Fr],
    indices: &[usize],
) -> ([TransferInput; N], Fr, [Fr; N]) {
    assert_eq!(notes.len(), N);
    assert_eq!(indices.len(), N);
    let mut nfs = [Fr::from(0u64); N];
    let mut inputs: [TransferInput; N] =
        core::array::from_fn(|_| TransferInput::empty(DEPTH));
    let mut root = Fr::from(0u64);
    for i in 0..N {
        let (r, siblings, path_bits) = merkle::path(leaves, indices[i], DEPTH);
        if i == 0 {
            root = r;
        } else {
            assert_eq!(root, r);
        }
        nfs[i] = notes[i].nullifier(spend_sk);
        inputs[i] = TransferInput {
            k: Some(notes[i].k),
            v: Some(notes[i].v),
            nullifier: Some(nfs[i]),
            siblings: siblings.into_iter().map(Some).collect(),
            path_bits: path_bits.into_iter().map(Some).collect(),
        };
    }
    (inputs, root, nfs)
}

/// 2-in and 4-in private transfers with real Groth16 proofs against the pool.
#[test]
fn multi_input_transfer_with_real_proofs() {
    use hypertron_commitment::{CommitmentContract, CommitmentContractClient};
    use hypertron_nullifier::{NullifierContract, NullifierContractClient};
    use hypertron_transfer::{Config, TransferContract, TransferContractClient};
    use soroban_sdk::token::{Client as TokenClient, StellarAssetClient};

    let env = Env::default();
    env.mock_all_auths_allowing_non_root_auth();
    env.cost_estimate().budget().reset_unlimited();

    let sac = env.register_stellar_asset_contract_v2(Address::generate(&env));
    let token = sac.address();
    let token_admin = StellarAssetClient::new(&env, &token);

    let commitment_id = env.register(CommitmentContract, ());
    let nullifier_id = env.register(NullifierContract, ());
    let verifier_id = env.register(VerifierContract, ());
    let transfer_id = env.register(TransferContract, ());

    CommitmentContractClient::new(&env, &commitment_id).initialize(&transfer_id);
    NullifierContractClient::new(&env, &nullifier_id).initialize(&transfer_id);

    let (deposit_pk, deposit_vk) =
        groth16::setup(DepositCircuit::empty(), &mut groth16::insecure_dev_rng(1)).unwrap();
    let (t2_pk, t2_vk) =
        groth16::setup(Transfer2Circuit::empty(DEPTH), &mut groth16::insecure_dev_rng(4)).unwrap();
    let (t4_pk, t4_vk) =
        groth16::setup(Transfer4Circuit::empty(DEPTH), &mut groth16::insecure_dev_rng(5)).unwrap();

    let verifier = VerifierContractClient::new(&env, &verifier_id);
    verifier.initialize(&Address::generate(&env));
    verifier.register_vk(&1, &to_soroban_vk(&env, &deposit_vk));
    verifier.register_vk(&4, &to_soroban_vk(&env, &t2_vk));
    verifier.register_vk(&5, &to_soroban_vk(&env, &t4_vk));

    let pool = TransferContractClient::new(&env, &transfer_id);
    pool.initialize(&Config {
        token: token.clone(),
        commitment: commitment_id.clone(),
        nullifier: nullifier_id.clone(),
        verifier: verifier_id.clone(),
        deposit_vk_id: 1,
        unshield_vk_id: 2,
        transfer_vk_id: 3,
        transfer_2in_vk_id: 4,
        transfer_4in_vk_id: 5,
        compliance: None,
    });
    let tree = CommitmentContractClient::new(&env, &commitment_id);

    let depositor = Address::generate(&env);
    token_admin.mint(&depositor, &10_000);
    let spend_sk = Fr::from(424242u64);
    let empty = Bytes::new(&env);
    let mut leaves = vec![];

    // ---- 2-in: notes 40 + 60 -> 70 + 30 ------------------------------------
    let n0 = Note::from_spend_key(spend_sk, Fr::from(1u64), Fr::from(40u64));
    let n1 = Note::from_spend_key(spend_sk, Fr::from(2u64), Fr::from(60u64));
    deposit_note(&env, &pool, &depositor, &deposit_pk, &n0, 40, 21);
    leaves.push(n0.commitment());
    deposit_note(&env, &pool, &depositor, &deposit_pk, &n1, 60, 22);
    leaves.push(n1.commitment());

    let out1 = Note::new(Fr::from(101u64), Fr::from(102u64), Fr::from(70u64));
    let out2 = Note::new(Fr::from(201u64), Fr::from(202u64), Fr::from(30u64));
    let (inputs, root, nfs) = transfer_n_inputs::<2>(spend_sk, &[n0, n1], &leaves, &[0, 1]);
    assert_eq!(root, bytesn_to_fr(&tree.root()));
    let proof = groth16::prove(
        &t2_pk,
        Transfer2Circuit {
            root: Some(root),
            out_cm1: Some(out1.commitment()),
            out_cm2: Some(out2.commitment()),
            spend_sk: Some(spend_sk),
            inputs,
            owner_pk1: Some(out1.owner_pk),
            k1: Some(out1.k),
            v1: Some(out1.v),
            owner_pk2: Some(out2.owner_pk),
            k2: Some(out2.k),
            v2: Some(out2.v),
        },
        &mut groth16::insecure_dev_rng(24),
    )
    .unwrap();
    let mut nf_vec: SVec<BytesN<32>> = SVec::new(&env);
    nf_vec.push_back(fr_to_bytesn(&env, &nfs[0]));
    nf_vec.push_back(fr_to_bytesn(&env, &nfs[1]));
    pool.transfer_n(
        &proof_to_bytes(&env, &proof),
        &tree.root(),
        &nf_vec,
        &fr_to_bytesn(&env, &out1.commitment()),
        &fr_to_bytesn(&env, &out2.commitment()),
        &empty,
        &empty,
    );
    leaves.push(out1.commitment());
    leaves.push(out2.commitment());
    assert_eq!(tree.size(), 4);
    assert_eq!(TokenClient::new(&env, &token).balance(&transfer_id), 100);

    // Replay of either 2-in nullifier is rejected.
    assert!(pool
        .try_transfer_n(
            &proof_to_bytes(&env, &proof),
            &tree.root(),
            &nf_vec,
            &fr_to_bytesn(&env, &out1.commitment()),
            &fr_to_bytesn(&env, &out2.commitment()),
            &empty,
            &empty,
        )
        .is_err());

    // ---- 4-in: 10+20+30+40 = 70+30 -----------------------------------------
    let four: [Note; 4] = core::array::from_fn(|i| {
        Note::from_spend_key(
            spend_sk,
            Fr::from(50 + i as u64),
            Fr::from(10 * (i as u64 + 1)),
        )
    });
    let start = leaves.len();
    for (i, note) in four.iter().enumerate() {
        let amt = 10 * (i as i128 + 1);
        deposit_note(&env, &pool, &depositor, &deposit_pk, note, amt, 30 + i as u64);
        leaves.push(note.commitment());
    }
    let out1 = Note::new(Fr::from(301u64), Fr::from(302u64), Fr::from(70u64));
    let out2 = Note::new(Fr::from(401u64), Fr::from(402u64), Fr::from(30u64));
    let idxs = [start, start + 1, start + 2, start + 3];
    let (inputs, root, nfs) = transfer_n_inputs::<4>(spend_sk, &four, &leaves, &idxs);
    assert_eq!(root, bytesn_to_fr(&tree.root()));
    let proof = groth16::prove(
        &t4_pk,
        Transfer4Circuit {
            root: Some(root),
            out_cm1: Some(out1.commitment()),
            out_cm2: Some(out2.commitment()),
            spend_sk: Some(spend_sk),
            inputs,
            owner_pk1: Some(out1.owner_pk),
            k1: Some(out1.k),
            v1: Some(out1.v),
            owner_pk2: Some(out2.owner_pk),
            k2: Some(out2.k),
            v2: Some(out2.v),
        },
        &mut groth16::insecure_dev_rng(34),
    )
    .unwrap();
    let mut nf_vec: SVec<BytesN<32>> = SVec::new(&env);
    for nf in &nfs {
        nf_vec.push_back(fr_to_bytesn(&env, nf));
    }
    pool.transfer_n(
        &proof_to_bytes(&env, &proof),
        &tree.root(),
        &nf_vec,
        &fr_to_bytesn(&env, &out1.commitment()),
        &fr_to_bytesn(&env, &out2.commitment()),
        &empty,
        &empty,
    );
    assert_eq!(tree.size(), 10);
    assert_eq!(TokenClient::new(&env, &token).balance(&transfer_id), 200);
}
