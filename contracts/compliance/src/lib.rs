//! Hypertron Compliance Policy (optional)
//!
//! A deliberately minimal, SWAPPABLE allowlist consulted by the shielded pool
//! ONLY at the transparent exit (`unshield` recipient). It is intentionally kept
//! OUT of the ZK core: the circuits never see a policy, so privacy is unaffected
//! and the policy can be upgraded, replaced, or removed without touching the
//! cryptography. A pool wired with `compliance: None` enforces no policy at all.
//!
//! The interface (`is_allowed`) matches `hypertron_transfer::ComplianceApi`, so
//! any contract exposing it — allowlist, denylist, sanctions oracle, per-jur-
//! isdiction router — can be dropped in.
//!
//! Modes:
//!   - `default_allow = true`  : denylist (everyone allowed unless listed).
//!   - `default_allow = false` : allowlist (nobody allowed unless listed).
#![no_std]

use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, Address, Env,
};

const TTL_THRESHOLD: u32 = 518_400;
const TTL_BUMP: u32 = 3_110_400;

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
}

/// Emitted when an account's listing changes.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Listed {
    #[topic]
    pub account: Address,
    pub listed: bool,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Admin,
    DefaultAllow,
    /// In allowlist mode: present => allowed. In denylist mode: present => blocked.
    Listed(Address),
}

#[contract]
pub struct ComplianceContract;

#[contractimpl]
impl ComplianceContract {
    /// `default_allow = false` for an allowlist, `true` for a denylist.
    pub fn initialize(env: Env, admin: Address, default_allow: bool) -> Result<(), Error> {
        if env.storage().instance().has(&Key::Admin) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&Key::Admin, &admin);
        env.storage().instance().set(&Key::DefaultAllow, &default_allow);
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
        Ok(())
    }

    /// Add or remove an account from the list. Admin-gated.
    pub fn set_listed(env: Env, account: Address, listed: bool) -> Result<(), Error> {
        let admin: Address = env
            .storage()
            .instance()
            .get(&Key::Admin)
            .ok_or(Error::NotInitialized)?;
        admin.require_auth();

        let key = Key::Listed(account.clone());
        if listed {
            env.storage().persistent().set(&key, &true);
            env.storage().persistent().extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);
        } else {
            env.storage().persistent().remove(&key);
        }
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_BUMP);
        Listed { account, listed }.publish(&env);
        Ok(())
    }

    /// The policy decision consumed by `hypertron_transfer` at exit.
    pub fn is_allowed(env: Env, account: Address) -> bool {
        let default_allow: bool =
            env.storage().instance().get(&Key::DefaultAllow).unwrap_or(true);
        let is_listed = env.storage().persistent().has(&Key::Listed(account));
        if default_allow {
            // Denylist: allowed unless explicitly listed (blocked).
            !is_listed
        } else {
            // Allowlist: allowed only if explicitly listed.
            is_listed
        }
    }
}

#[cfg(test)]
mod test;
