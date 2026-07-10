#![cfg(test)]
use super::*;
use soroban_sdk::{testutils::Address as _, Address, Bytes, BytesN, Env, Vec};

fn dummy_vk(env: &Env, n_pub: u32) -> VerifyingKey {
    let mut ic: Vec<BytesN<96>> = Vec::new(env);
    let mut i = 0;
    while i < n_pub + 1 {
        ic.push_back(BytesN::from_array(env, &[0u8; 96]));
        i += 1;
    }
    VerifyingKey {
        alpha: BytesN::from_array(env, &[0u8; 96]),
        beta: BytesN::from_array(env, &[0u8; 192]),
        gamma: BytesN::from_array(env, &[0u8; 192]),
        delta: BytesN::from_array(env, &[0u8; 192]),
        ic,
    }
}

fn setup(env: &Env) -> VerifierContractClient<'_> {
    let id = env.register(VerifierContract, ());
    let client = VerifierContractClient::new(env, &id);
    client.initialize(&Address::generate(env));
    client
}

#[test]
fn register_and_lookup_vk() {
    let env = Env::default();
    env.mock_all_auths();
    let client = setup(&env);
    assert!(!client.has_vk(&1));
    client.register_vk(&1, &dummy_vk(&env, 2));
    assert!(client.has_vk(&1));
}

#[test]
#[should_panic]
fn verify_unknown_vk_errors() {
    let env = Env::default();
    let client = setup(&env);
    let proof = Bytes::from_array(&env, &[0u8; (96 + 192 + 96)]);
    client.verify(&99, &proof, &Vec::new(&env));
}

#[test]
#[should_panic]
fn verify_bad_proof_length_errors() {
    let env = Env::default();
    env.mock_all_auths();
    let client = setup(&env);
    client.register_vk(&1, &dummy_vk(&env, 0));
    let proof = Bytes::from_array(&env, &[0u8; 10]); // wrong length
    client.verify(&1, &proof, &Vec::new(&env));
}

#[test]
#[should_panic]
fn verify_public_input_mismatch_errors() {
    let env = Env::default();
    env.mock_all_auths();
    let client = setup(&env);
    client.register_vk(&1, &dummy_vk(&env, 2)); // expects 2 public inputs
    let proof = Bytes::from_array(&env, &[0u8; (96 + 192 + 96)]);
    // supply 0 public inputs -> mismatch
    client.verify(&1, &proof, &Vec::new(&env));
}

#[test]
fn register_vk_requires_admin_auth() {
    // With no mock auth, registering should fail (auth required).
    let env = Env::default();
    let id = env.register(VerifierContract, ());
    let client = VerifierContractClient::new(&env, &id);
    client.initialize(&Address::generate(&env));
    let res = client.try_register_vk(&1, &dummy_vk(&env, 0));
    assert!(res.is_err());
}
