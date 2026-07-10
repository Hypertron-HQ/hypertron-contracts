#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, BytesN, Env};

fn leaf(env: &Env, n: u8) -> BytesN<32> {
    let mut a = [0u8; 32];
    a[31] = n;
    BytesN::from_array(env, &a)
}

fn setup(env: &Env) -> (CommitmentContractClient, Address) {
    let id = env.register(CommitmentContract, ());
    let client = CommitmentContractClient::new(env, &id);
    let authority = Address::generate(env);
    client.initialize(&authority);
    (client, authority)
}

#[test]
fn initialize_sets_empty_root() {
    let env = Env::default();
    let (client, _authority) = setup(&env);
    // A fresh tree has a deterministic non-zero root and zero size.
    assert_eq!(client.size(), 0);
    let root = client.root();
    assert!(client.is_known_root(&root));
}

#[test]
fn insert_returns_incrementing_indices() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _authority) = setup(&env);

    assert_eq!(client.insert(&leaf(&env, 1)), 0);
    assert_eq!(client.insert(&leaf(&env, 2)), 1);
    assert_eq!(client.insert(&leaf(&env, 3)), 2);
    assert_eq!(client.size(), 3);
}

#[test]
fn insert_changes_root_and_tracks_history() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _authority) = setup(&env);

    let r0 = client.root();
    client.insert(&leaf(&env, 1));
    let r1 = client.root();
    assert_ne!(r0, r1);

    // both the old and new roots remain known (history window).
    assert!(client.is_known_root(&r0));
    assert!(client.is_known_root(&r1));
}

#[test]
#[should_panic]
fn duplicate_leaf_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (client, _authority) = setup(&env);
    client.insert(&leaf(&env, 7));
    client.insert(&leaf(&env, 7)); // duplicate -> Error::DuplicateLeaf
}

#[test]
fn unknown_root_is_rejected() {
    let env = Env::default();
    let (client, _authority) = setup(&env);
    let bogus = leaf(&env, 99);
    assert!(!client.is_known_root(&bogus));
}

#[test]
#[should_panic]
fn insert_requires_authority_auth() {
    // Without mock_all_auths, the authority.require_auth() should fail.
    let env = Env::default();
    let (client, _authority) = setup(&env);
    client.insert(&leaf(&env, 1));
}
