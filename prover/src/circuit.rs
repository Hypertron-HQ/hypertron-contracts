//! The Hypertron transaction circuit: shielded-pool membership + nullifier
//! derivation, with the payout (recipient + amount) bound into the proof.
//!
//! Public inputs (in this exact order, matching `transfer.withdraw`):
//!   `[root, nullifier_hash, recipient, amount]`
//!
//! Statement proved:
//!   - I know a note `(n, k)` whose commitment `leaf = Poseidon(n, k)` is a
//!     member of the Merkle tree with the given `root`, AND
//!   - `nullifier_hash = Poseidon(n, 0)` (deterministic per note -> double-spend
//!     protection without linking to the deposit), AND
//!   - `recipient` and `amount` are bound so a relayer cannot redirect funds or
//!     alter the payout.

use ark_bls12_381::Fr;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar,
    select::CondSelectGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::poseidon::{hash2_var, mds_fr, rc_fr};

/// Merkle tree depth. Must match the on-chain commitment tree.
pub const DEPTH: usize = 20;

/// Witness + public assignment for one shielded withdrawal.
#[derive(Clone)]
pub struct MembershipCircuit {
    // public inputs
    pub root: Option<Fr>,
    pub nullifier_hash: Option<Fr>,
    pub recipient: Option<Fr>,
    pub amount: Option<Fr>,
    // private witness
    pub n: Option<Fr>,
    pub k: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub path_bits: Vec<Option<bool>>,
}

impl MembershipCircuit {
    /// An all-`None` instance of the right shape, for `circuit_specific_setup`.
    pub fn empty(depth: usize) -> Self {
        MembershipCircuit {
            root: None,
            nullifier_hash: None,
            recipient: None,
            amount: None,
            n: None,
            k: None,
            siblings: vec![None; depth],
            path_bits: vec![None; depth],
        }
    }
}

impl ConstraintSynthesizer<Fr> for MembershipCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mds = mds_fr();
        let rc = rc_fr();

        // Public inputs, allocation order = [root, nullifier_hash, recipient, amount].
        let root = FpVar::new_input(cs.clone(), || {
            self.root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let nullifier_hash = FpVar::new_input(cs.clone(), || {
            self.nullifier_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let recipient = FpVar::new_input(cs.clone(), || {
            self.recipient.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let amount = FpVar::new_input(cs.clone(), || {
            self.amount.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Note secrets.
        let n = FpVar::new_witness(cs.clone(), || self.n.ok_or(SynthesisError::AssignmentMissing))?;
        let k = FpVar::new_witness(cs.clone(), || self.k.ok_or(SynthesisError::AssignmentMissing))?;

        // leaf = Poseidon(n, k)
        let mut cur = hash2_var(&n, &k, &mds, &rc)?;

        // Walk up the Merkle path to the root.
        let depth = self.siblings.len();
        for i in 0..depth {
            let sib = FpVar::new_witness(cs.clone(), || {
                self.siblings[i].ok_or(SynthesisError::AssignmentMissing)
            })?;
            let bit = Boolean::new_witness(cs.clone(), || {
                self.path_bits[i].ok_or(SynthesisError::AssignmentMissing)
            })?;
            // bit = 1 => current node is the right child.
            let left = FpVar::conditionally_select(&bit, &sib, &cur)?;
            let right = FpVar::conditionally_select(&bit, &cur, &sib)?;
            cur = hash2_var(&left, &right, &mds, &rc)?;
        }
        cur.enforce_equal(&root)?;

        // nullifier_hash = Poseidon(n, 0)
        let zero = FpVar::constant(Fr::from(0u64));
        let computed = hash2_var(&n, &zero, &mds, &rc)?;
        computed.enforce_equal(&nullifier_hash)?;

        // Bind recipient and amount into the constraint system. The Groth16
        // public-input commitment binds them; we reference them here so their
        // variables are definitely present in the R1CS.
        let _ = &recipient * &recipient;
        let _ = &amount * &amount;

        Ok(())
    }
}
