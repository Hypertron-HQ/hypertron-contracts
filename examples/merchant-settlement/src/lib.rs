//! Merchant Confidential Settlement — reference consumer.
//!
//! Deliberately thin: it imports the Hypertron transfer contract through its
//! PUBLIC client, exactly as an external integrator would. A customer pays into
//! the shielded pool; the merchant later settles a hidden amount to itself with
//! an on-chain-verified proof. This proves the protocol is wired to a product,
//! not a disconnected demo.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractimpl, contracttype, Address, Bytes, BytesN,
    Env,
};

/// Public interface of the Hypertron shielded pool, called through a generated
/// client so this consumer compiles to its own self-contained wasm.
#[contractclient(name = "PoolClient")]
pub trait PoolApi {
    fn deposit(env: Env, from: Address, amount: i128, commitment: BytesN<32>) -> u32;
    fn withdraw(
        env: Env,
        proof: Bytes,
        root: BytesN<32>,
        nullifier: BytesN<32>,
        recipient: Address,
        amount: i128,
        claim: PrivacyLevel,
    ) -> PrivacyAttestation;
}

/// Mirrors `hypertron_transfer::PrivacyLevel` for ABI-compatible calls.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyLevel {
    pub sender: bool,
    pub receiver: bool,
    pub amount: bool,
    pub timing: bool,
    pub linkability: bool,
}

/// Mirrors `hypertron_transfer::PrivacyAttestation`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyAttestation {
    pub level: PrivacyLevel,
    pub vk_id: u32,
    pub root: BytesN<32>,
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Pool,
    Merchant,
}

#[contract]
pub struct MerchantSettlement;

#[contractimpl]
impl MerchantSettlement {
    /// `pool` is the Hypertron transfer contract; `merchant` receives settlements.
    pub fn initialize(env: Env, pool: Address, merchant: Address) -> Result<(), Error> {
        if env.storage().instance().has(&Key::Pool) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&Key::Pool, &pool);
        env.storage().instance().set(&Key::Merchant, &merchant);
        Ok(())
    }

    /// Customer pays `amount` into the shielded pool with a note commitment.
    pub fn collect(
        env: Env,
        customer: Address,
        amount: i128,
        commitment: BytesN<32>,
    ) -> Result<u32, Error> {
        let pool: Address = env.storage().instance().get(&Key::Pool).ok_or(Error::NotInitialized)?;
        Ok(PoolClient::new(&env, &pool).deposit(&customer, &amount, &commitment))
    }

    /// Merchant settles a hidden amount to itself with an on-chain-verified proof.
    pub fn settle(
        env: Env,
        proof: Bytes,
        root: BytesN<32>,
        nullifier: BytesN<32>,
        amount: i128,
        claim: PrivacyLevel,
    ) -> Result<PrivacyAttestation, Error> {
        let pool: Address = env.storage().instance().get(&Key::Pool).ok_or(Error::NotInitialized)?;
        let merchant: Address =
            env.storage().instance().get(&Key::Merchant).ok_or(Error::NotInitialized)?;
        Ok(PoolClient::new(&env, &pool).withdraw(
            &proof,
            &root,
            &nullifier,
            &merchant,
            &amount,
            &claim,
        ))
    }
}

#[cfg(test)]
mod test;
