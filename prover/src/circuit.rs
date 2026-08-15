//! The Hypertron transaction circuits.
//!
//! Value is carried by notes `cm = Poseidon(Poseidon(owner_pk, k), v)` where
//! `owner_pk = Poseidon(spend_sk, 0)` (see [`crate::note`]). Viewing-key blobs
//! carry `(owner_pk, k, v)` only — the nullifier `Poseidon(spend_sk, k)` needs
//! the spend key, so auditors who can decrypt cannot spend.
//!
//! Three circuits cover the lifecycle, each with its own verifying key:
//!
//! - [`DepositCircuit`] (shield): proves a deposited commitment opens to the
//!   public `amount` under some `owner_pk` (no spend key needed to *create*).
//! - [`UnshieldCircuit`] (exit): membership + spend-key nullifier + value
//!   balance `v_in = amount + v_change`.
//! - [`TransferCircuit`] (private 1-in / 2-out): same spend-key nullifier,
//!   `v_in = v_out1 + v_out2`, no public address or amount.
//!
//! Every value is range-checked to [`crate::note::VALUE_BITS`] so the balance
//! equations cannot wrap the field and create value from nothing.

use ark_bls12_381::Fr;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar,
    select::CondSelectGadget, ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::note::{OWNER_PK_DOMAIN, VALUE_BITS};
use crate::poseidon::{hash2_var, mds_fr, rc_fr};

/// Merkle tree depth. Must match the on-chain commitment tree.
pub const DEPTH: usize = 20;

type Mds = [[Fr; 3]; 3];
type Rc = [[Fr; 3]; 64];

fn input(cs: &ConstraintSystemRef<Fr>, v: Option<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_input(cs.clone(), || v.ok_or(SynthesisError::AssignmentMissing))
}

fn witness(cs: &ConstraintSystemRef<Fr>, v: Option<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    FpVar::new_witness(cs.clone(), || v.ok_or(SynthesisError::AssignmentMissing))
}

/// Enforce `0 <= value < 2^bits` via a bounded bit decomposition.
fn range_check(value: &FpVar<Fr>, bits: usize) -> Result<(), SynthesisError> {
    let le = value.to_bits_le()?;
    for b in le.iter().skip(bits) {
        b.enforce_equal(&Boolean::constant(false))?;
    }
    Ok(())
}

/// In-circuit note commitment `cm = Poseidon(Poseidon(owner_pk, k), v)`.
fn note_commit(
    owner_pk: &FpVar<Fr>,
    k: &FpVar<Fr>,
    v: &FpVar<Fr>,
    mds: &Mds,
    rc: &Rc,
) -> Result<FpVar<Fr>, SynthesisError> {
    let inner = hash2_var(owner_pk, k, mds, rc)?;
    hash2_var(&inner, v, mds, rc)
}

/// `owner_pk = Poseidon(spend_sk, 0)`.
fn owner_pk_var(
    spend_sk: &FpVar<Fr>,
    mds: &Mds,
    rc: &Rc,
) -> Result<FpVar<Fr>, SynthesisError> {
    let domain = FpVar::constant(Fr::from(OWNER_PK_DOMAIN));
    hash2_var(spend_sk, &domain, mds, rc)
}

/// In-circuit nullifier `nf = Poseidon(spend_sk, k)`.
fn nullifier_var(
    spend_sk: &FpVar<Fr>,
    k: &FpVar<Fr>,
    mds: &Mds,
    rc: &Rc,
) -> Result<FpVar<Fr>, SynthesisError> {
    hash2_var(spend_sk, k, mds, rc)
}

/// Walk a Merkle authentication path from `leaf` and return the computed root.
fn merkle_root(
    cs: &ConstraintSystemRef<Fr>,
    leaf: FpVar<Fr>,
    siblings: &[Option<Fr>],
    path_bits: &[Option<bool>],
    mds: &Mds,
    rc: &Rc,
) -> Result<FpVar<Fr>, SynthesisError> {
    let mut cur = leaf;
    for i in 0..siblings.len() {
        let sib = witness(cs, siblings[i])?;
        let bit = Boolean::new_witness(cs.clone(), || {
            path_bits[i].ok_or(SynthesisError::AssignmentMissing)
        })?;
        let left = FpVar::conditionally_select(&bit, &sib, &cur)?;
        let right = FpVar::conditionally_select(&bit, &cur, &sib)?;
        cur = hash2_var(&left, &right, mds, rc)?;
    }
    Ok(cur)
}

// ---------------------------------------------------------------------------
// Deposit (shield) — binds a public amount to a note commitment.
// ---------------------------------------------------------------------------

/// Public inputs: `[cm, amount]`.
/// Witnesses: `owner_pk`, `k` (no spend key — anyone may fund a known owner_pk).
#[derive(Clone)]
pub struct DepositCircuit {
    pub cm: Option<Fr>,
    pub amount: Option<Fr>,
    pub owner_pk: Option<Fr>,
    pub k: Option<Fr>,
}

impl DepositCircuit {
    pub fn empty() -> Self {
        DepositCircuit {
            cm: None,
            amount: None,
            owner_pk: None,
            k: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mds = mds_fr();
        let rc = rc_fr();

        let cm = input(&cs, self.cm)?;
        let amount = input(&cs, self.amount)?;
        let owner_pk = witness(&cs, self.owner_pk)?;
        let k = witness(&cs, self.k)?;

        range_check(&amount, VALUE_BITS)?;
        let computed = note_commit(&owner_pk, &k, &amount, &mds, &rc)?;
        computed.enforce_equal(&cm)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Unshield (exit) — membership + nullifier + value balance with a change note.
// ---------------------------------------------------------------------------

/// Public inputs: `[root, nullifier, recipient, amount, change_cm]`.
#[derive(Clone)]
pub struct UnshieldCircuit {
    pub root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub recipient: Option<Fr>,
    pub amount: Option<Fr>,
    pub change_cm: Option<Fr>,
    // input note — spend key required
    pub spend_sk: Option<Fr>,
    pub k: Option<Fr>,
    pub v: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub path_bits: Vec<Option<bool>>,
    // change note (same owner)
    pub k2: Option<Fr>,
    pub vc: Option<Fr>,
}

impl UnshieldCircuit {
    pub fn empty(depth: usize) -> Self {
        UnshieldCircuit {
            root: None,
            nullifier: None,
            recipient: None,
            amount: None,
            change_cm: None,
            spend_sk: None,
            k: None,
            v: None,
            siblings: vec![None; depth],
            path_bits: vec![None; depth],
            k2: None,
            vc: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for UnshieldCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mds = mds_fr();
        let rc = rc_fr();

        let root = input(&cs, self.root)?;
        let nf = input(&cs, self.nullifier)?;
        let recipient = input(&cs, self.recipient)?;
        let amount = input(&cs, self.amount)?;
        let change_cm = input(&cs, self.change_cm)?;

        let spend_sk = witness(&cs, self.spend_sk)?;
        let k = witness(&cs, self.k)?;
        let v = witness(&cs, self.v)?;
        let owner = owner_pk_var(&spend_sk, &mds, &rc)?;
        let cm = note_commit(&owner, &k, &v, &mds, &rc)?;
        let computed_root = merkle_root(&cs, cm, &self.siblings, &self.path_bits, &mds, &rc)?;
        computed_root.enforce_equal(&root)?;
        nullifier_var(&spend_sk, &k, &mds, &rc)?.enforce_equal(&nf)?;

        // Change note stays in the pool, still owned by the same spend key.
        let k2 = witness(&cs, self.k2)?;
        let vc = witness(&cs, self.vc)?;
        note_commit(&owner, &k2, &vc, &mds, &rc)?.enforce_equal(&change_cm)?;

        range_check(&amount, VALUE_BITS)?;
        range_check(&vc, VALUE_BITS)?;
        (&amount + &vc).enforce_equal(&v)?;

        let _ = &recipient * &recipient;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Transfer (private, 1-in / 2-out) — no public address or amount.
// ---------------------------------------------------------------------------

/// Public inputs: `[root, nullifier, out_cm1, out_cm2]`.
#[derive(Clone)]
pub struct TransferCircuit {
    pub root: Option<Fr>,
    pub nullifier: Option<Fr>,
    pub out_cm1: Option<Fr>,
    pub out_cm2: Option<Fr>,
    // input note
    pub spend_sk: Option<Fr>,
    pub k: Option<Fr>,
    pub v: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub path_bits: Vec<Option<bool>>,
    // output notes: owner_pk (recipient / self) + k + v
    pub owner_pk1: Option<Fr>,
    pub k1: Option<Fr>,
    pub v1: Option<Fr>,
    pub owner_pk2: Option<Fr>,
    pub k2: Option<Fr>,
    pub v2: Option<Fr>,
}

impl TransferCircuit {
    pub fn empty(depth: usize) -> Self {
        TransferCircuit {
            root: None,
            nullifier: None,
            out_cm1: None,
            out_cm2: None,
            spend_sk: None,
            k: None,
            v: None,
            siblings: vec![None; depth],
            path_bits: vec![None; depth],
            owner_pk1: None,
            k1: None,
            v1: None,
            owner_pk2: None,
            k2: None,
            v2: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mds = mds_fr();
        let rc = rc_fr();

        let root = input(&cs, self.root)?;
        let nf = input(&cs, self.nullifier)?;
        let out_cm1 = input(&cs, self.out_cm1)?;
        let out_cm2 = input(&cs, self.out_cm2)?;

        let spend_sk = witness(&cs, self.spend_sk)?;
        let k = witness(&cs, self.k)?;
        let v = witness(&cs, self.v)?;
        let owner = owner_pk_var(&spend_sk, &mds, &rc)?;
        let cm = note_commit(&owner, &k, &v, &mds, &rc)?;
        let computed_root = merkle_root(&cs, cm, &self.siblings, &self.path_bits, &mds, &rc)?;
        computed_root.enforce_equal(&root)?;
        nullifier_var(&spend_sk, &k, &mds, &rc)?.enforce_equal(&nf)?;

        let owner_pk1 = witness(&cs, self.owner_pk1)?;
        let k1 = witness(&cs, self.k1)?;
        let v1 = witness(&cs, self.v1)?;
        note_commit(&owner_pk1, &k1, &v1, &mds, &rc)?.enforce_equal(&out_cm1)?;

        let owner_pk2 = witness(&cs, self.owner_pk2)?;
        let k2 = witness(&cs, self.k2)?;
        let v2 = witness(&cs, self.v2)?;
        note_commit(&owner_pk2, &k2, &v2, &mds, &rc)?.enforce_equal(&out_cm2)?;

        range_check(&v1, VALUE_BITS)?;
        range_check(&v2, VALUE_BITS)?;
        (&v1 + &v2).enforce_equal(&v)?;
        Ok(())
    }
}
