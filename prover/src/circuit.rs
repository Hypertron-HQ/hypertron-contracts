//! The Hypertron transaction circuits.
//!
//! Value is carried by notes `cm = Poseidon(Poseidon(n,k), v)` (see [`crate::note`]).
//! Three circuits cover the whole lifecycle, each with its own verifying key:
//!
//! - [`DepositCircuit`] (shield): proves a deposited commitment opens to the
//!   public `amount`, so a transparent deposit cannot mint a note worth more.
//! - [`UnshieldCircuit`] (exit): proves membership + nullifier + value balance
//!   `v_in = amount + v_change`, pays a public recipient, keeps a change note.
//! - [`TransferCircuit`] (private 1-in / 2-out): membership + nullifier +
//!   `v_in = v_out1 + v_out2`, with NO public address or amount — fully private.
//!
//! Every value is range-checked to [`crate::note::VALUE_BITS`] so the balance
//! equations cannot wrap the field and create value from nothing.

use ark_bls12_381::Fr;
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar,
    select::CondSelectGadget, ToBitsGadget,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::note::VALUE_BITS;
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
    // `to_bits_le` returns the canonical (< modulus) little-endian bits and
    // constrains them to equal `value`. Forcing the high bits to zero bounds it.
    let le = value.to_bits_le()?;
    for b in le.iter().skip(bits) {
        b.enforce_equal(&Boolean::constant(false))?;
    }
    Ok(())
}

/// In-circuit note commitment `cm = Poseidon(Poseidon(n, k), v)`.
fn note_commit(
    n: &FpVar<Fr>,
    k: &FpVar<Fr>,
    v: &FpVar<Fr>,
    mds: &Mds,
    rc: &Rc,
) -> Result<FpVar<Fr>, SynthesisError> {
    let inner = hash2_var(n, k, mds, rc)?;
    hash2_var(&inner, v, mds, rc)
}

/// In-circuit nullifier `nf = Poseidon(n, 0)`.
fn nullifier(n: &FpVar<Fr>, mds: &Mds, rc: &Rc) -> Result<FpVar<Fr>, SynthesisError> {
    let zero = FpVar::constant(Fr::from(0u64));
    hash2_var(n, &zero, mds, rc)
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
        // bit = 1 => current node is the right child.
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
#[derive(Clone)]
pub struct DepositCircuit {
    pub cm: Option<Fr>,
    pub amount: Option<Fr>,
    pub n: Option<Fr>,
    pub k: Option<Fr>,
}

impl DepositCircuit {
    pub fn empty() -> Self {
        DepositCircuit { cm: None, amount: None, n: None, k: None }
    }
}

impl ConstraintSynthesizer<Fr> for DepositCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mds = mds_fr();
        let rc = rc_fr();

        let cm = input(&cs, self.cm)?;
        let amount = input(&cs, self.amount)?;
        let n = witness(&cs, self.n)?;
        let k = witness(&cs, self.k)?;

        range_check(&amount, VALUE_BITS)?;
        let computed = note_commit(&n, &k, &amount, &mds, &rc)?;
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
    // input note
    pub n: Option<Fr>,
    pub k: Option<Fr>,
    pub v: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub path_bits: Vec<Option<bool>>,
    // change note
    pub n2: Option<Fr>,
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
            n: None,
            k: None,
            v: None,
            siblings: vec![None; depth],
            path_bits: vec![None; depth],
            n2: None,
            k2: None,
            vc: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for UnshieldCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mds = mds_fr();
        let rc = rc_fr();

        // Public, order = [root, nullifier, recipient, amount, change_cm].
        let root = input(&cs, self.root)?;
        let nf = input(&cs, self.nullifier)?;
        let recipient = input(&cs, self.recipient)?;
        let amount = input(&cs, self.amount)?;
        let change_cm = input(&cs, self.change_cm)?;

        // Input note.
        let n = witness(&cs, self.n)?;
        let k = witness(&cs, self.k)?;
        let v = witness(&cs, self.v)?;
        let cm = note_commit(&n, &k, &v, &mds, &rc)?;
        let computed_root = merkle_root(&cs, cm, &self.siblings, &self.path_bits, &mds, &rc)?;
        computed_root.enforce_equal(&root)?;
        nullifier(&n, &mds, &rc)?.enforce_equal(&nf)?;

        // Change note stays in the pool.
        let n2 = witness(&cs, self.n2)?;
        let k2 = witness(&cs, self.k2)?;
        let vc = witness(&cs, self.vc)?;
        note_commit(&n2, &k2, &vc, &mds, &rc)?.enforce_equal(&change_cm)?;

        // Value conservation: v = amount + change. Range checks stop field wrap.
        range_check(&amount, VALUE_BITS)?;
        range_check(&vc, VALUE_BITS)?;
        (&amount + &vc).enforce_equal(&v)?;

        // Bind recipient into the constraint system (Groth16 public-input binding).
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
    pub n: Option<Fr>,
    pub k: Option<Fr>,
    pub v: Option<Fr>,
    pub siblings: Vec<Option<Fr>>,
    pub path_bits: Vec<Option<bool>>,
    // output notes
    pub n1: Option<Fr>,
    pub k1: Option<Fr>,
    pub v1: Option<Fr>,
    pub n2: Option<Fr>,
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
            n: None,
            k: None,
            v: None,
            siblings: vec![None; depth],
            path_bits: vec![None; depth],
            n1: None,
            k1: None,
            v1: None,
            n2: None,
            k2: None,
            v2: None,
        }
    }
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mds = mds_fr();
        let rc = rc_fr();

        // Public, order = [root, nullifier, out_cm1, out_cm2].
        let root = input(&cs, self.root)?;
        let nf = input(&cs, self.nullifier)?;
        let out_cm1 = input(&cs, self.out_cm1)?;
        let out_cm2 = input(&cs, self.out_cm2)?;

        // Input note.
        let n = witness(&cs, self.n)?;
        let k = witness(&cs, self.k)?;
        let v = witness(&cs, self.v)?;
        let cm = note_commit(&n, &k, &v, &mds, &rc)?;
        let computed_root = merkle_root(&cs, cm, &self.siblings, &self.path_bits, &mds, &rc)?;
        computed_root.enforce_equal(&root)?;
        nullifier(&n, &mds, &rc)?.enforce_equal(&nf)?;

        // Output notes (recipient + change), both stay in the pool.
        let n1 = witness(&cs, self.n1)?;
        let k1 = witness(&cs, self.k1)?;
        let v1 = witness(&cs, self.v1)?;
        note_commit(&n1, &k1, &v1, &mds, &rc)?.enforce_equal(&out_cm1)?;

        let n2 = witness(&cs, self.n2)?;
        let k2 = witness(&cs, self.k2)?;
        let v2 = witness(&cs, self.v2)?;
        note_commit(&n2, &k2, &v2, &mds, &rc)?.enforce_equal(&out_cm2)?;

        // Value conservation with range checks on the outputs.
        range_check(&v1, VALUE_BITS)?;
        range_check(&v2, VALUE_BITS)?;
        (&v1 + &v2).enforce_equal(&v)?;
        Ok(())
    }
}
