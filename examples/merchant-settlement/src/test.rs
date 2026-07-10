#![cfg(test)]
use super::*;
use hypertron_commitment::{CommitmentContract, CommitmentContractClient};
use hypertron_nullifier::{NullifierContract, NullifierContractClient};
use hypertron_transfer::{Config, TransferContract};
use soroban_sdk::{
    testutils::Address as _,
    token::{Client as TokenClient, StellarAssetClient},
    Address, BytesN, Env,
};

fn leaf(env: &Env, n: u8) -> BytesN<32> {
    let mut a = [0u8; 32];
    a[31] = n;
    BytesN::from_array(env, &a)
}

#[test]
fn merchant_collects_via_public_api() {
    let env = Env::default();
    // The customer's auth is required one level below collect(), so allow
    // authorizations at non-root positions in the invocation tree.
    env.mock_all_auths_allowing_non_root_auth();

    let admin = Address::generate(&env);
    let sac = env.register_stellar_asset_contract_v2(admin.clone());
    let token = sac.address();
    let token_admin = StellarAssetClient::new(&env, &token);

    let commitment_id = env.register(CommitmentContract, ());
    let nullifier_id = env.register(NullifierContract, ());
    let verifier_id = Address::generate(&env); // unused for collect()
    let transfer_id = env.register(TransferContract, ());

    CommitmentContractClient::new(&env, &commitment_id).initialize(&transfer_id);
    NullifierContractClient::new(&env, &nullifier_id).initialize(&transfer_id);

    let pool = hypertron_transfer::TransferContractClient::new(&env, &transfer_id);
    pool.initialize(&Config {
        token: token.clone(),
        commitment: commitment_id.clone(),
        nullifier: nullifier_id.clone(),
        verifier: verifier_id,
        vk_id: 1,
    });

    let merchant = Address::generate(&env);
    let merchant_id = env.register(MerchantSettlement, ());
    let merchant_client = MerchantSettlementClient::new(&env, &merchant_id);
    merchant_client.initialize(&transfer_id, &merchant);

    let customer = Address::generate(&env);
    token_admin.mint(&customer, &1000);

    let idx = merchant_client.collect(&customer, &250, &leaf(&env, 1));
    assert_eq!(idx, 0);
    assert_eq!(TokenClient::new(&env, &token).balance(&transfer_id), 250);
    assert_eq!(CommitmentContractClient::new(&env, &commitment_id).size(), 1);
}
