//! Hypertron Nullifier Registry
//!
//! Tracks spent notes so a note can be spent at most once, without linking the
//! spend back to the original deposit. A single focused responsibility that
//! every confidential transfer depends on.
#![no_std]

use soroban_sdk::{
    contract, contractevent, contracterror, contractimpl, contracttype, Address, BytesN, Env,
};

/// Emitted when a nullifier is marked spent.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NullifierSpent {
    pub nullifier: BytesN<32>,
}

const TTL_THRESHOLD: u32 = 518_400;
const TTL_BUMP: u32 = 3_110_400;

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    AlreadySpent = 3,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Authority,
    Spent(BytesN<32>),
}

#[contract]
pub struct NullifierContract;

#[contractimpl]
impl NullifierContract {
    /// Initialize with the address permitted to mark nullifiers spent.
    pub fn initialize(env: Env, authority: Address) -> Result<(), Error> {
        if env.storage().instance().has(&Key::Authority) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&Key::Authority, &authority);
        Ok(())
    }

    /// Has this nullifier already been spent?
    pub fn is_spent(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage().persistent().has(&Key::Spent(nullifier))
    }

    /// Mark a nullifier spent. Fails if already spent. Authority-gated.
    pub fn mark_spent(env: Env, nullifier: BytesN<32>) -> Result<(), Error> {
        let authority: Address = env
            .storage()
            .instance()
            .get(&Key::Authority)
            .ok_or(Error::NotInitialized)?;
        authority.require_auth();

        let key = Key::Spent(nullifier.clone());
        if env.storage().persistent().has(&key) {
            return Err(Error::AlreadySpent);
        }
        env.storage().persistent().set(&key, &true);
        env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);

        NullifierSpent { nullifier }.publish(&env);
        Ok(())
    }
}

#[cfg(test)]
mod test;
