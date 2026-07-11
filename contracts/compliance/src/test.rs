#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, Env};

fn setup(default_allow: bool) -> (Env, ComplianceContractClient<'static>, Address) {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let id = env.register(ComplianceContract, ());
    let client = ComplianceContractClient::new(&env, &id);
    client.initialize(&admin, &default_allow);
    (env, client, admin)
}

#[test]
fn allowlist_blocks_by_default_and_permits_listed() {
    let (env, client, _admin) = setup(false); // allowlist
    let user = Address::generate(&env);
    assert!(!client.is_allowed(&user));
    client.set_listed(&user, &true);
    assert!(client.is_allowed(&user));
    client.set_listed(&user, &false);
    assert!(!client.is_allowed(&user));
}

#[test]
fn denylist_allows_by_default_and_blocks_listed() {
    let (env, client, _admin) = setup(true); // denylist
    let user = Address::generate(&env);
    assert!(client.is_allowed(&user));
    client.set_listed(&user, &true);
    assert!(!client.is_allowed(&user));
}

#[test]
fn double_initialize_rejected() {
    let (_env, client, admin) = setup(false);
    let res = client.try_initialize(&admin, &false);
    assert!(res.is_err());
}
