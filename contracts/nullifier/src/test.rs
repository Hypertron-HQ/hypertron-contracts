#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

fn nf(env: &Env, n: u8) -> BytesN<32> {
    let mut a = [0u8; 32];
    a[31] = n;
    BytesN::from_array(env, &a)
}

fn setup(env: &Env) -> NullifierContractClient<'_> {
    let id = env.register(NullifierContract, ());
    let client = NullifierContractClient::new(env, &id);
    client.initialize(&Address::generate(env));
    client
}

#[test]
fn unspent_by_default() {
    let env = Env::default();
    let client = setup(&env);
    assert!(!client.is_spent(&nf(&env, 1)));
}

#[test]
fn mark_then_spent() {
    let env = Env::default();
    env.mock_all_auths();
    let client = setup(&env);
    client.mark_spent(&nf(&env, 1));
    assert!(client.is_spent(&nf(&env, 1)));
}

#[test]
#[should_panic]
fn double_spend_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let client = setup(&env);
    client.mark_spent(&nf(&env, 5));
    client.mark_spent(&nf(&env, 5)); // -> Error::AlreadySpent
}

#[test]
#[should_panic]
fn mark_requires_auth() {
    let env = Env::default();
    let client = setup(&env);
    client.mark_spent(&nf(&env, 1));
}
