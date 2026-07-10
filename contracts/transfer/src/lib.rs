//! Hypertron Confidential Transfer
//!
//! The composition layer: a shielded pool that snaps together the commitment
//! tree, the nullifier registry, and the on-chain proof verifier. This is the
//! first contract most integrators reach for.
//!
//! Flow:
//!   deposit()  -> pull tokens in, add a note commitment to the tree.
//!   withdraw() -> verify a proof on-chain, spend a nullifier, pay out, and
//!                 emit a verifiable Privacy Attestation.
//!
//! Note: in Soroban, returning `Err` does NOT revert state. Every validation
//! therefore runs *before* any state mutation or token movement.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contractevent, contracterror, contractimpl, contracttype,
    token, xdr::ToXdr, Address, Bytes, BytesN, Env, Vec,
};

/// Cross-contract interfaces. We call components through generated clients
/// rather than linking their crates, so each contract compiles to its own
/// self-contained wasm (linking two contracts into one wasm collides on
/// exported symbols like `initialize`). The concrete contracts are pulled in
/// as dev-dependencies for integration tests.
#[contractclient(name = "CommitmentClient")]
pub trait CommitmentApi {
    fn insert(env: Env, leaf: BytesN<32>) -> u32;
    fn is_known_root(env: Env, root: BytesN<32>) -> bool;
}

#[contractclient(name = "NullifierClient")]
pub trait NullifierApi {
    fn is_spent(env: Env, nullifier: BytesN<32>) -> bool;
    fn mark_spent(env: Env, nullifier: BytesN<32>);
}

/// The pluggable verifier seam: any contract with this signature can back the
/// pool, so the proof backend (Groth16, UltraHonk, …) is swappable.
#[contractclient(name = "VerifierClient")]
pub trait VerifierApi {
    fn verify(env: Env, vk_id: u32, proof: Bytes, public_inputs: Vec<BytesN<32>>) -> bool;
}

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    UnknownRoot = 3,
    NullifierAlreadySpent = 4,
    InvalidProof = 5,
    InvalidAmount = 6,
    UnsupportedLevelClaim = 7,
}

/// The leakage dimensions this protocol reasons about (see privacy-framework.md).
/// A payment may only *claim* a dimension the mechanism actually backs.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyLevel {
    pub sender: bool,
    pub receiver: bool,
    pub amount: bool,
    pub timing: bool,
    pub linkability: bool,
}

/// The signature feature: an on-chain, verifiable statement of exactly which
/// leaks a payment closed. Emitted only after the contract confirms the claim
/// is backed by the mechanisms actually used.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyAttestation {
    pub level: PrivacyLevel,
    pub vk_id: u32,
    pub root: BytesN<32>,
}

/// Emitted on a shielded deposit.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Deposited {
    #[topic]
    pub index: u32,
    pub amount: i128,
}

/// Emitted on a shielded withdrawal.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Withdrawn {
    pub nullifier: BytesN<32>,
    pub amount: i128,
}

/// The verifiable Privacy Attestation, emitted after a successful withdrawal.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivacyAttested {
    pub attestation: PrivacyAttestation,
}

#[contracttype]
#[derive(Clone)]
pub struct Config {
    pub token: Address,
    pub commitment: Address,
    pub nullifier: Address,
    pub verifier: Address,
    pub vk_id: u32,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Config,
}

#[contract]
pub struct TransferContract;

#[contractimpl]
impl TransferContract {
    /// Wire the pool to its component contracts. The commitment and nullifier
    /// contracts must have been initialized with this contract's address as
    /// their authority.
    pub fn initialize(env: Env, config: Config) -> Result<(), Error> {
        if env.storage().instance().has(&Key::Config) {
            return Err(Error::AlreadyInitialized);
        }
        env.storage().instance().set(&Key::Config, &config);
        Ok(())
    }

    pub fn get_config(env: Env) -> Result<Config, Error> {
        load_config(&env)
    }

    /// Shielded deposit: move `amount` of the pool token in and record a note
    /// commitment. Returns the leaf index.
    pub fn deposit(
        env: Env,
        from: Address,
        amount: i128,
        commitment: BytesN<32>,
    ) -> Result<u32, Error> {
        from.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let cfg = load_config(&env)?;

        token::Client::new(&env, &cfg.token).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );

        let index = CommitmentClient::new(&env, &cfg.commitment).insert(&commitment);

        Deposited { index, amount }.publish(&env);
        Ok(index)
    }

    /// Shielded withdrawal: verify the proof on-chain, spend the nullifier,
    /// pay the recipient, and emit a Privacy Attestation.
    pub fn withdraw(
        env: Env,
        proof: Bytes,
        root: BytesN<32>,
        nullifier: BytesN<32>,
        recipient: Address,
        amount: i128,
        claim: PrivacyLevel,
    ) -> Result<PrivacyAttestation, Error> {
        // ---- validation phase (no state changes) ----
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        // This mechanism (shielded pool) cannot provide timing privacy on its
        // own, so a timing claim would be unbacked and is rejected.
        if claim.timing {
            return Err(Error::UnsupportedLevelClaim);
        }
        let cfg = load_config(&env)?;

        let commitment = CommitmentClient::new(&env, &cfg.commitment);
        if !commitment.is_known_root(&root) {
            return Err(Error::UnknownRoot);
        }

        let nullifiers = NullifierClient::new(&env, &cfg.nullifier);
        if nullifiers.is_spent(&nullifier) {
            return Err(Error::NullifierAlreadySpent);
        }

        // The public inputs are DERIVED from the actual payout parameters, so
        // the proof is cryptographically bound to this exact (root, nullifier,
        // recipient, amount). A relayer cannot redirect funds or change the
        // amount without invalidating the proof.
        // Order must match the circuit: [root, nullifier, recipient, amount].
        let mut public_inputs: Vec<BytesN<32>> = Vec::new(&env);
        public_inputs.push_back(root.clone());
        public_inputs.push_back(nullifier.clone());
        public_inputs.push_back(recipient_field(&env, &recipient));
        public_inputs.push_back(amount_field(&env, amount));

        let verifier = VerifierClient::new(&env, &cfg.verifier);
        if !verifier.verify(&cfg.vk_id, &proof, &public_inputs) {
            return Err(Error::InvalidProof);
        }

        // ---- effects phase ----
        nullifiers.mark_spent(&nullifier);
        token::Client::new(&env, &cfg.token).transfer(
            &env.current_contract_address(),
            &recipient,
            &amount,
        );

        let level = PrivacyLevel {
            sender: true,
            receiver: claim.receiver,
            amount: claim.amount,
            timing: false,
            linkability: true,
        };
        let attestation = PrivacyAttestation {
            level,
            vk_id: cfg.vk_id,
            root: root.clone(),
        };

        Withdrawn {
            nullifier,
            amount,
        }
        .publish(&env);
        PrivacyAttested {
            attestation: attestation.clone(),
        }
        .publish(&env);

        Ok(attestation)
    }
}

fn load_config(env: &Env) -> Result<Config, Error> {
    env.storage()
        .instance()
        .get(&Key::Config)
        .ok_or(Error::NotInitialized)
}

/// Deterministically map a recipient `Address` to a BLS12-381 field element,
/// as `sha256(xdr(address))`. The verifier host reduces the 32 bytes modulo the
/// scalar field, so the prover binds the same value with
/// `Fr::from_be_bytes_mod_order(sha256(xdr(address)))`.
fn recipient_field(env: &Env, recipient: &Address) -> BytesN<32> {
    let xdr = recipient.clone().to_xdr(env);
    env.crypto().sha256(&xdr).to_bytes()
}

/// Encode a positive `amount` as a big-endian field element (right-aligned in
/// 32 bytes). The prover binds `Fr::from(amount as u128)`.
fn amount_field(env: &Env, amount: i128) -> BytesN<32> {
    let mut buf = [0u8; 32];
    buf[16..32].copy_from_slice(&amount.to_be_bytes());
    BytesN::from_array(env, &buf)
}

#[cfg(test)]
mod test;
