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

struct Harness {
    env: Env,
    client: TransferContractClient<'static>,
    token: Address,
    token_admin: StellarAssetClient<'static>,
    commitment: CommitmentContractClient<'static>,
    mock_verifier: MockVerifierClient<'static>,
    pool: Address,
}

fn deploy() -> Harness {
    let env = Env::default();
    env.mock_all_auths();

    let admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token = sac.address();
    let token_admin = StellarAssetClient::new(&env, &token);

    let commitment_id = env.register(CommitmentContract, ());
    let nullifier_id = env.register(NullifierContract, ());
    let verifier_id = env.register(MockVerifier, ());
    let transfer_id = env.register(TransferContract, ());

    CommitmentContractClient::new(&env, &commitment_id).initialize(&transfer_id);
    NullifierContractClient::new(&env, &nullifier_id).initialize(&transfer_id);

    let client = TransferContractClient::new(&env, &transfer_id);
    client.initialize(&Config {
        token: token.clone(),
        commitment: commitment_id.clone(),
        nullifier: nullifier_id.clone(),
        verifier: verifier_id.clone(),
        vk_id: 1,
    });

    Harness {
        commitment: CommitmentContractClient::new(&env, &commitment_id),
        mock_verifier: MockVerifierClient::new(&env, &verifier_id),
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

fn ok_claim() -> PrivacyLevel {
    PrivacyLevel {
        sender: true,
        receiver: false,
        amount: true,
        timing: false,
        linkability: true,
    }
}

#[test]
fn deposit_pulls_tokens_and_commits() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);

    let idx = h.client.deposit(&user, &100, &leaf(&h.env, 1));
    assert_eq!(idx, 0);
    assert_eq!(TokenClient::new(&h.env, &h.token).balance(&h.pool), 100);
    assert_eq!(h.commitment.size(), 1);
}

#[test]
fn full_withdraw_pays_recipient_and_attests() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    h.client.deposit(&user, &100, &leaf(&h.env, 1));

    let root = h.commitment.root();
    let recipient = Address::generate(&h.env);
    let proof = Bytes::from_array(&h.env, &[0u8; 384]);

    let att = h.client.withdraw(
        &proof,
        &root,
        &leaf(&h.env, 9), // nullifier
        &recipient,
        &50,
        &ok_claim(),
    );

    assert_eq!(TokenClient::new(&h.env, &h.token).balance(&recipient), 50);
    assert!(att.level.sender);
    assert!(att.level.linkability);
    assert!(att.level.amount);
    assert!(!att.level.timing);
}

#[test]
fn double_spend_is_rejected() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    h.client.deposit(&user, &100, &leaf(&h.env, 1));

    let root = h.commitment.root();
    let recipient = Address::generate(&h.env);
    let proof = Bytes::from_array(&h.env, &[0u8; 384]);
    let nf = leaf(&h.env, 9);

    h.client
        .withdraw(&proof, &root, &nf, &recipient, &10, &ok_claim());

    let res = h.client.try_withdraw(
        &proof,
        &root,
        &nf,
        &recipient,
        &10,
        &ok_claim(),
    );
    assert!(res.is_err());
}

#[test]
fn unknown_root_is_rejected() {
    let h = deploy();
    let recipient = Address::generate(&h.env);
    let proof = Bytes::from_array(&h.env, &[0u8; 384]);
    let bogus_root = leaf(&h.env, 200);

    let res = h.client.try_withdraw(
        &proof,
        &bogus_root,
        &leaf(&h.env, 9),
        &recipient,
        &10,
        &ok_claim(),
    );
    assert!(res.is_err());
}

#[test]
fn invalid_proof_is_rejected() {
    let h = deploy();
    let user = Address::generate(&h.env);
    h.token_admin.mint(&user, &1000);
    h.client.deposit(&user, &100, &leaf(&h.env, 1));
    h.mock_verifier.set_result(&false); // make verification fail

    let root = h.commitment.root();
    let recipient = Address::generate(&h.env);
    let proof = Bytes::from_array(&h.env, &[0u8; 384]);

    let res = h.client.try_withdraw(
        &proof,
        &root,
        &leaf(&h.env, 9),
        &recipient,
        &10,
        &ok_claim(),
    );
    assert!(res.is_err());
}

#[test]
fn timing_claim_is_rejected() {
    let h = deploy();
    let recipient = Address::generate(&h.env);
    let proof = Bytes::from_array(&h.env, &[0u8; 384]);
    let claim = PrivacyLevel {
        sender: true,
        receiver: false,
        amount: false,
        timing: true, // unbacked -> rejected
        linkability: true,
    };
    let res = h.client.try_withdraw(
        &proof,
        &leaf(&h.env, 1),
        &leaf(&h.env, 9),
        &recipient,
        &10,
        &claim,
    );
    assert!(res.is_err());
}
