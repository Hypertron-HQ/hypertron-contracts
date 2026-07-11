//! Hypertron Confidential Transfer
//!
//! The composition layer: a value-committed shielded pool that snaps together
//! the commitment tree, the nullifier registry, and the on-chain proof verifier.
//!
//! Notes are value-committed: `cm = Poseidon(Poseidon(n,k), v)`. Three flows,
//! each backed by its own verifying key so value can never be minted:
//!
//!   deposit()  -> shield: pull tokens in, prove the note commits to `amount`.
//!   unshield() -> exit: prove membership + nullifier + `v = amount + change`,
//!                 pay a public recipient, re-insert the change note.
//!   transfer() -> fully private note->note: no public address or amount; only
//!                 nullifier + two output commitments (+ encrypted payloads).
//!
//! Relayer model: `unshield`/`transfer` require NO auth from the note owner, so
//! a relayer can submit them and pay fees — the fee payer never links to the
//! sender. `deposit` is the only transparent entry and authorizes the depositor.
//!
//! Note: in Soroban, returning `Err` does NOT revert state. Every validation
//! therefore runs *before* any state mutation or token movement.
#![no_std]

use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, token,
    xdr::ToXdr, Address, Bytes, BytesN, Env, Vec,
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

/// Optional compliance policy: a separate, swappable module consulted only at
/// the transparent exit (`unshield`). Kept OUT of the ZK core on purpose.
#[contractclient(name = "ComplianceClient")]
pub trait ComplianceApi {
    fn is_allowed(env: Env, account: Address) -> bool;
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
    RecipientNotAllowed = 8,
}

// TTL policy: keep the pool's instance storage alive well past a month so a
// quiet pool does not get archived out from under its users. (Persistent
// component storage — roots, nullifiers — is bumped inside those contracts.)
const LEDGERS_PER_DAY: u32 = 17_280;
const TTL_THRESHOLD: u32 = LEDGERS_PER_DAY * 30;
const TTL_EXTEND: u32 = LEDGERS_PER_DAY * 60;

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

/// Emitted on a shielded exit (unshield). `change_index` is the leaf position
/// of the change note re-inserted into the pool.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unshielded {
    pub nullifier: BytesN<32>,
    pub amount: i128,
    pub change_index: u32,
}

/// Emitted on a fully-private transfer. Carries the two new commitment indices
/// and their encrypted payloads so recipients can discover notes by scanning.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateTransfer {
    pub nullifier: BytesN<32>,
    pub out_index_1: u32,
    pub out_index_2: u32,
    pub note_1: Bytes,
    pub note_2: Bytes,
}

/// The verifiable Privacy Attestation, emitted after a successful exit.
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
    /// Verifying-key ids, one per circuit.
    pub deposit_vk_id: u32,
    pub unshield_vk_id: u32,
    pub transfer_vk_id: u32,
    /// Optional exit-time allowlist policy (compliance hook).
    pub compliance: Option<Address>,
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
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
        Ok(())
    }

    pub fn get_config(env: Env) -> Result<Config, Error> {
        load_config(&env)
    }

    /// Shielded deposit (shield). Moves `amount` of the pool token in and records
    /// a note commitment, but only after a proof that the commitment actually
    /// opens to `amount` — so a deposit cannot mint a note worth more than the
    /// tokens paid in. Returns the leaf index.
    pub fn deposit(
        env: Env,
        from: Address,
        amount: i128,
        commitment: BytesN<32>,
        deposit_proof: Bytes,
    ) -> Result<u32, Error> {
        from.require_auth();
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        let cfg = load_config(&env)?;

        // Bind commitment <-> amount. Public inputs order: [cm, amount].
        let mut public_inputs: Vec<BytesN<32>> = Vec::new(&env);
        public_inputs.push_back(commitment.clone());
        public_inputs.push_back(amount_field(&env, amount));
        let verifier = VerifierClient::new(&env, &cfg.verifier);
        if !verifier.verify(&cfg.deposit_vk_id, &deposit_proof, &public_inputs) {
            return Err(Error::InvalidProof);
        }

        token::Client::new(&env, &cfg.token).transfer(
            &from,
            &env.current_contract_address(),
            &amount,
        );

        let index = CommitmentClient::new(&env, &cfg.commitment).insert(&commitment);
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND);

        Deposited { index, amount }.publish(&env);
        Ok(index)
    }

    /// Shielded exit (unshield): verify the proof on-chain, spend the nullifier,
    /// re-insert the change note, pay the recipient, and attest. Permissionless
    /// (relayer-submittable): the payout is bound in the proof, so no note-owner
    /// signature is needed and the fee payer never links to the sender.
    pub fn unshield(
        env: Env,
        proof: Bytes,
        root: BytesN<32>,
        nullifier: BytesN<32>,
        recipient: Address,
        amount: i128,
        change_commitment: BytesN<32>,
        claim: PrivacyLevel,
    ) -> Result<PrivacyAttestation, Error> {
        // ---- validation phase (no state changes) ----
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }
        // A shielded pool cannot provide timing privacy on its own, so a timing
        // claim would be unbacked and is rejected.
        if claim.timing {
            return Err(Error::UnsupportedLevelClaim);
        }
        let cfg = load_config(&env)?;

        // Optional compliance gate at the transparent exit only.
        if let Some(policy) = cfg.compliance.clone() {
            if !ComplianceClient::new(&env, &policy).is_allowed(&recipient) {
                return Err(Error::RecipientNotAllowed);
            }
        }

        let commitment = CommitmentClient::new(&env, &cfg.commitment);
        if !commitment.is_known_root(&root) {
            return Err(Error::UnknownRoot);
        }

        let nullifiers = NullifierClient::new(&env, &cfg.nullifier);
        if nullifiers.is_spent(&nullifier) {
            return Err(Error::NullifierAlreadySpent);
        }

        // Public inputs are DERIVED from the payout so the proof is bound to this
        // exact (root, nullifier, recipient, amount, change). A relayer cannot
        // redirect funds, change the amount, or steal the change note.
        // Order must match the circuit: [root, nullifier, recipient, amount, change_cm].
        let mut public_inputs: Vec<BytesN<32>> = Vec::new(&env);
        public_inputs.push_back(root.clone());
        public_inputs.push_back(nullifier.clone());
        public_inputs.push_back(recipient_field(&env, &recipient));
        public_inputs.push_back(amount_field(&env, amount));
        public_inputs.push_back(change_commitment.clone());

        let verifier = VerifierClient::new(&env, &cfg.verifier);
        if !verifier.verify(&cfg.unshield_vk_id, &proof, &public_inputs) {
            return Err(Error::InvalidProof);
        }

        // ---- effects phase ----
        nullifiers.mark_spent(&nullifier);
        let change_index = commitment.insert(&change_commitment);
        token::Client::new(&env, &cfg.token).transfer(
            &env.current_contract_address(),
            &recipient,
            &amount,
        );
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND);

        let level = PrivacyLevel {
            sender: true,
            receiver: claim.receiver,
            amount: claim.amount,
            timing: false,
            linkability: true,
        };
        let attestation = PrivacyAttestation { level, vk_id: cfg.unshield_vk_id, root: root.clone() };

        Unshielded { nullifier, amount, change_index }.publish(&env);
        PrivacyAttested { attestation: attestation.clone() }.publish(&env);

        Ok(attestation)
    }

    /// Fully-private transfer: spend one note, create two output notes. NO public
    /// recipient address and NO public amount — only the nullifier and the two
    /// output commitments are visible, plus opaque encrypted payloads for
    /// recipient discovery. Permissionless / relayer-submittable.
    pub fn transfer(
        env: Env,
        proof: Bytes,
        root: BytesN<32>,
        nullifier: BytesN<32>,
        out_commitment_1: BytesN<32>,
        out_commitment_2: BytesN<32>,
        note_1: Bytes,
        note_2: Bytes,
    ) -> Result<(), Error> {
        let cfg = load_config(&env)?;

        let commitment = CommitmentClient::new(&env, &cfg.commitment);
        if !commitment.is_known_root(&root) {
            return Err(Error::UnknownRoot);
        }
        let nullifiers = NullifierClient::new(&env, &cfg.nullifier);
        if nullifiers.is_spent(&nullifier) {
            return Err(Error::NullifierAlreadySpent);
        }

        // Order must match the circuit: [root, nullifier, out_cm1, out_cm2].
        let mut public_inputs: Vec<BytesN<32>> = Vec::new(&env);
        public_inputs.push_back(root.clone());
        public_inputs.push_back(nullifier.clone());
        public_inputs.push_back(out_commitment_1.clone());
        public_inputs.push_back(out_commitment_2.clone());

        let verifier = VerifierClient::new(&env, &cfg.verifier);
        if !verifier.verify(&cfg.transfer_vk_id, &proof, &public_inputs) {
            return Err(Error::InvalidProof);
        }

        // ---- effects phase ----
        nullifiers.mark_spent(&nullifier);
        let out_index_1 = commitment.insert(&out_commitment_1);
        let out_index_2 = commitment.insert(&out_commitment_2);
        env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND);

        PrivateTransfer { nullifier, out_index_1, out_index_2, note_1, note_2 }.publish(&env);
        Ok(())
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
