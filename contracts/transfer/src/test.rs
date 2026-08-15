#![cfg(test)]
use super::*;
use hypertron_commitment::{CommitmentContract, CommitmentContractClient};
use hypertron_nullifier::{NullifierContract, NullifierContractClient};
use soroban_sdk::{
    symbol_short,
    testutils::Address as _,
    token::{Client as TokenClient, StellarAssetClient},
    Address, Bytes, BytesN, Env, Vec,
};

// A stand-in verifier so we can unit-test the transfer orchestration without
// real ZK proof fixtures. Returns a configurable result.
#[contract]
pub struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    pub fn set_result(env: Env, ok: bool) {
        env.storage().instance().set(&symbol_short!("ok"), &ok);
    }
    pub fn verify(env: Env, _vk_id: u32, _proof: Bytes, _public_inputs: Vec<BytesN<32>>) -> bool {
        env.storage()
            .instance()
            .get(&symbol_short!("ok"))
            .unwrap_or(true)
    }
}

// A stand-in compliance policy that blocks a single configured address.
#[contract]
pub struct MockCompliance;

#[contractimpl]
impl MockCompliance {
    pub fn block(env: Env, who: Address) {
        env.storage().instance().set(&symbol_short!("blocked"), &who);
    }
    pub fn is_allowed(env: Env, account: Address) -> bool {
        match env.storage().instance().get::<_, Address>(&symbol_short!("blocked")) {
            Some(blocked) => account != blocked,
            None => true,
        }
    }
}

struct Harness {
    env: Env,
    client: TransferContractClient<'static>,
    token: Address,
    token_admin: StellarAssetClient<'static>,
    commitment: CommitmentContractClient<'static>,
    mock_verifier: MockVerifierClient<'static>,
    compliance: MockComplianceClient<'static>,
    pool: Address,
}

fn deploy() -> Harness {
    deploy_inner(true)
}

fn deploy_inner(with_compliance: bool) -> Harness {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token = sac.address();
    let token_admin = StellarAssetClient::new(&env, &token);

    let commitment_id = env.register(CommitmentContract, ());
    let nullifier_id = env.register(NullifierContract, ());
    let verifier_id = env.register(MockVerifier, ());
    let compliance_id = env.register(MockCompliance, ());
    let transfer_id = env.register(TransferContract, ());

    CommitmentContractClient::new(&env, &commitment_id).initialize(&transfer_id);
    NullifierContractClient::new(&env, &nullifier_id).initialize(&transfer_id);

    let client = TransferContractClient::new(&env, &transfer_id);
    client.initialize(&Config {
        token: token.clone(),
        commitment: commitment_id.clone(),
        nullifier: nullifier_id.clone(),
        verifier: verifier_id.clone(),
        deposit_vk_id: 1,
        unshield_vk_id: 2,
        transfer_vk_id: 3,
        transfer_2in_vk_id: 4,
        transfer_4in_vk_id: 5,
        compliance: if with_compliance { Some(compliance_id.clone()) } else { None },
    });

    Harness {
        commitment: CommitmentContractClient::new(&env, &commitment_id),
        mock_verifier: MockVerifierClient::new(&env, &verifier_id),
        compliance: MockComplianceClient::new(&env, &compliance_id),
        client,
        token,
        token_admin,
        pool: transfer_id,
        env,
    }
}

fn leaf(env: &Env, n: u8) -> BytesN<32> {
    let mut a = [0u8; 32];
    a[31] = n;
    BytesN::from_array(env, &a)
}

fn proof(env: &Env) -> Bytes {
    Bytes::from_array(env, &[0u8; 384])
}

fn ok_claim() -> PrivacyLevel {
    PrivacyLevel {
        sender: true,
        receiver: false,
        amount: true,
        timing: false,
        linkability: true,
    }
}

fn deposit(h: &Harness, user: &Address, amount: i128, leaf_n: u8) -> u32 {
    h.client.deposit(user, &amount, &leaf(&h.env, leaf_n), &proof(&h.env))
}

#[test]
fn deposit_pulls_tokens_and_commits() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);

    let idx = deposit(&h, &user, 100, 1);
    assert_eq!(idx, 0);
    assert_eq!(TokenClient::new(&h.env, &h.token).balance(&h.pool), 100);
    assert_eq!(h.commitment.size(), 1);
}

#[test]
fn deposit_rejects_bad_binding_proof() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    h.mock_verifier.set_result(&false); // deposit binding fails

    let res = h.client.try_deposit(&user, &100, &leaf(&h.env, 1), &proof(&h.env));
    assert!(res.is_err());
    // No tokens moved, nothing committed.
    assert_eq!(TokenClient::new(&h.env, &h.token).balance(&h.pool), 0);
    assert_eq!(h.commitment.size(), 0);
}

#[test]
fn unshield_pays_recipient_reinserts_change_and_attests() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    deposit(&h, &user, 100, 1);

    let root = h.commitment.root();
    let recipient = Address::generate(&h.env);
    let change_cm = leaf(&h.env, 7);

    let att = h.client.unshield(
        &proof(&h.env),
        &root,
        &leaf(&h.env, 9), // nullifier
        &recipient,
        &50,
        &change_cm,
        &ok_claim(),
    );

    assert_eq!(TokenClient::new(&h.env, &h.token).balance(&recipient), 50);
    // Change note re-inserted -> tree grew from 1 to 2 leaves.
    assert_eq!(h.commitment.size(), 2);
    assert!(att.level.sender);
    assert!(att.level.linkability);
    assert!(att.level.amount);
    assert!(!att.level.timing);
}

#[test]
fn private_transfer_spends_and_creates_two_notes() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    deposit(&h, &user, 100, 1);

    let root = h.commitment.root();
    let nf = leaf(&h.env, 9);
    let empty = Bytes::new(&h.env);

    h.client.transfer(
        &proof(&h.env),
        &root,
        &nf,
        &leaf(&h.env, 20),
        &leaf(&h.env, 21),
        &empty,
        &empty,
    );

    // Two output commitments inserted (plus the original deposit) = 3 leaves.
    assert_eq!(h.commitment.size(), 3);
    // The input note is spent.
    let res = h.client.try_transfer(
        &proof(&h.env),
        &root,
        &nf,
        &leaf(&h.env, 22),
        &leaf(&h.env, 23),
        &empty,
        &empty,
    );
    assert!(res.is_err());
}

#[test]
fn transfer_n_spends_two_nullifiers() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    deposit(&h, &user, 100, 1);

    let root = h.commitment.root();
    let empty = Bytes::new(&h.env);
    let mut nfs: Vec<BytesN<32>> = Vec::new(&h.env);
    nfs.push_back(leaf(&h.env, 9));
    nfs.push_back(leaf(&h.env, 10));

    h.client.transfer_n(
        &proof(&h.env),
        &root,
        &nfs,
        &leaf(&h.env, 20),
        &leaf(&h.env, 21),
        &empty,
        &empty,
    );
    assert_eq!(h.commitment.size(), 3);

    let res = h.client.try_transfer_n(
        &proof(&h.env),
        &root,
        &nfs,
        &leaf(&h.env, 22),
        &leaf(&h.env, 23),
        &empty,
        &empty,
    );
    assert!(res.is_err());
}

#[test]
fn transfer_n_rejects_duplicates_and_bad_arity() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    deposit(&h, &user, 100, 1);

    let root = h.commitment.root();
    let empty = Bytes::new(&h.env);

    let mut dup: Vec<BytesN<32>> = Vec::new(&h.env);
    dup.push_back(leaf(&h.env, 9));
    dup.push_back(leaf(&h.env, 9));
    assert!(h
        .client
        .try_transfer_n(
            &proof(&h.env),
            &root,
            &dup,
            &leaf(&h.env, 20),
            &leaf(&h.env, 21),
            &empty,
            &empty,
        )
        .is_err());

    let mut one: Vec<BytesN<32>> = Vec::new(&h.env);
    one.push_back(leaf(&h.env, 11));
    assert!(h
        .client
        .try_transfer_n(
            &proof(&h.env),
            &root,
            &one,
            &leaf(&h.env, 20),
            &leaf(&h.env, 21),
            &empty,
            &empty,
        )
        .is_err());
}

#[test]
fn double_spend_is_rejected() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    deposit(&h, &user, 100, 1);

    let root = h.commitment.root();
    let recipient = Address::generate(&h.env);
    let nf = leaf(&h.env, 9);

    h.client
        .unshield(&proof(&h.env), &root, &nf, &recipient, &10, &leaf(&h.env, 7), &ok_claim());

    let res = h.client.try_unshield(
        &proof(&h.env),
        &root,
        &nf,
        &recipient,
        &10,
        &leaf(&h.env, 8),
        &ok_claim(),
    );
    assert!(res.is_err());
}

#[test]
fn unknown_root_is_rejected() {
    let h = deploy();
    let recipient = Address::generate(&h.env);
    let bogus_root = leaf(&h.env, 200);

    let res = h.client.try_unshield(
        &proof(&h.env),
        &bogus_root,
        &leaf(&h.env, 9),
        &recipient,
        &10,
        &leaf(&h.env, 7),
        &ok_claim(),
    );
    assert!(res.is_err());
}

#[test]
fn invalid_proof_is_rejected() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    deposit(&h, &user, 100, 1);
    h.mock_verifier.set_result(&false); // make verification fail

    let root = h.commitment.root();
    let recipient = Address::generate(&h.env);

    let res = h.client.try_unshield(
        &proof(&h.env),
        &root,
        &leaf(&h.env, 9),
        &recipient,
        &10,
        &leaf(&h.env, 7),
        &ok_claim(),
    );
    assert!(res.is_err());
}

#[test]
fn unshield_blocked_by_compliance_policy() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    deposit(&h, &user, 100, 1);

    let root = h.commitment.root();
    let recipient = Address::generate(&h.env);
    h.compliance.block(&recipient); // exit address is denied

    let res = h.client.try_unshield(
        &proof(&h.env),
        &root,
        &leaf(&h.env, 9),
        &recipient,
        &10,
        &leaf(&h.env, 7),
        &ok_claim(),
    );
    assert!(res.is_err());
    // Nothing paid out; funds stay in the pool.
    assert_eq!(TokenClient::new(&h.env, &h.token).balance(&recipient), 0);
    assert_eq!(TokenClient::new(&h.env, &h.token).balance(&h.pool), 100);
}

#[test]
fn timing_claim_is_rejected() {
    let h = deploy();
    let recipient = Address::generate(&h.env);
    let claim = PrivacyLevel {
        sender: true,
        receiver: false,
        amount: false,
        timing: true, // unbacked -> rejected
        linkability: true,
    };
    let res = h.client.try_unshield(
        &proof(&h.env),
        &leaf(&h.env, 1),
        &leaf(&h.env, 9),
        &recipient,
        &10,
        &leaf(&h.env, 7),
        &claim,
    );
    assert!(res.is_err());
}
