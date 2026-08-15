//! Hypertron off-chain prover.
//!
//! This crate is the canonical, non-test home of the shielded-pool circuit and
//! the Groth16 tooling around it. The `hypertron-verifier` contract's tests
//! depend on this same code, so what an integrator proves with the
//! `hypertron-prove` CLI is exactly what the chain verifies.

pub mod circuit;
pub mod crypto;
pub mod groth16;
pub mod merkle;
pub mod note;
pub mod poseidon;

pub use ark_bls12_381::Fr;

use anyhow::{anyhow, Result};
use ark_ff::PrimeField;

/// Parse a field element from either a `0x`-prefixed big-endian hex string
/// (up to 32 bytes) or a decimal integer string.
pub fn parse_fr(s: &str) -> Result<Fr> {
    let s = s.trim();
    if let Some(hexpart) = s.strip_prefix("0x") {
        let bytes = hex::decode(if hexpart.len() % 2 == 1 {
            format!("0{hexpart}")
        } else {
            hexpart.to_string()
        })
        .map_err(|e| anyhow!("bad hex field element: {e}"))?;
        if bytes.len() > 32 {
            return Err(anyhow!("field element longer than 32 bytes"));
        }
        let mut buf = [0u8; 32];
        let off = 32 - bytes.len();
        buf[off..].copy_from_slice(&bytes);
        Ok(Fr::from_be_bytes_mod_order(&buf))
    } else {
        let v: u128 = s
            .parse()
            .map_err(|e| anyhow!("field element must be decimal or 0x-hex: {e}"))?;
        Ok(Fr::from(v))
    }
}

/// Parse a fixed 32-byte value from a `0x`-optional hex string.
pub fn parse_bytes32(s: &str) -> Result<[u8; 32]> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    let bytes = hex::decode(s).map_err(|e| anyhow!("bad hex: {e}"))?;
    if bytes.len() != 32 {
        return Err(anyhow!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut buf = [0u8; 32];
    buf.copy_from_slice(&bytes);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{DepositCircuit, TransferCircuit, UnshieldCircuit, DEPTH};
    use crate::note::{commitment, nullifier, owner_pk, Note};

    #[test]
    fn deposit_binds_value_to_commitment() {
        let spend_sk = Fr::from(7u64);
        let note = Note::from_spend_key(spend_sk, Fr::from(8u64), Fr::from(500u64));
        let cm = note.commitment();
        let (pk, vk) = groth16::setup(DepositCircuit::empty(), 3).unwrap();
        let proof = groth16::prove(
            &pk,
            DepositCircuit {
                cm: Some(cm),
                amount: Some(note.v),
                owner_pk: Some(note.owner_pk),
                k: Some(note.k),
            },
            3,
        )
        .unwrap();
        assert!(groth16::verify(&vk, &[cm, note.v], &proof));
        assert!(!groth16::verify(&vk, &[cm, Fr::from(501u64)], &proof));
    }

    #[test]
    fn unshield_requires_spend_key() {
        let spend_sk = Fr::from(1234u64);
        let note = Note::from_spend_key(spend_sk, Fr::from(5678u64), Fr::from(1000u64));
        let leaf = note.commitment();
        let (root, siblings, path_bits) = merkle::path(&[leaf], 0, DEPTH);
        let nf = nullifier(spend_sk, note.k);
        let recipient = Fr::from(0xABCDu64);
        let amount = Fr::from(700u64);
        let change_k = Fr::from(10u64);
        let change_v = Fr::from(300u64);
        let change_cm = commitment(owner_pk(spend_sk), change_k, change_v);

        let (pk, vk) = groth16::setup(UnshieldCircuit::empty(DEPTH), 3).unwrap();
        let proof = groth16::prove(
            &pk,
            UnshieldCircuit {
                root: Some(root),
                nullifier: Some(nf),
                recipient: Some(recipient),
                amount: Some(amount),
                change_cm: Some(change_cm),
                spend_sk: Some(spend_sk),
                k: Some(note.k),
                v: Some(note.v),
                siblings: siblings.into_iter().map(Some).collect(),
                path_bits: path_bits.into_iter().map(Some).collect(),
                k2: Some(change_k),
                vc: Some(change_v),
            },
            3,
        )
        .unwrap();
        assert!(groth16::verify(&vk, &[root, nf, recipient, amount, change_cm], &proof));
        assert!(!groth16::verify(&vk, &[root, nf, recipient, Fr::from(800u64), change_cm], &proof));
    }

    #[test]
    fn transfer_conserves_value_privately() {
        let spend_sk = Fr::from(3u64);
        let note = Note::from_spend_key(spend_sk, Fr::from(4u64), Fr::from(1000u64));
        let leaf = note.commitment();
        let (root, siblings, path_bits) = merkle::path(&[leaf], 0, DEPTH);
        let nf = nullifier(spend_sk, note.k);
        let recip_pk = owner_pk(Fr::from(99u64));
        let to = Note::new(recip_pk, Fr::from(22u64), Fr::from(600u64));
        let change = Note::from_spend_key(spend_sk, Fr::from(32u64), Fr::from(400u64));

        let (pk, vk) = groth16::setup(TransferCircuit::empty(DEPTH), 3).unwrap();
        let proof = groth16::prove(
            &pk,
            TransferCircuit {
                root: Some(root),
                nullifier: Some(nf),
                out_cm1: Some(to.commitment()),
                out_cm2: Some(change.commitment()),
                spend_sk: Some(spend_sk),
                k: Some(note.k),
                v: Some(note.v),
                siblings: siblings.into_iter().map(Some).collect(),
                path_bits: path_bits.into_iter().map(Some).collect(),
                owner_pk1: Some(to.owner_pk),
                k1: Some(to.k),
                v1: Some(to.v),
                owner_pk2: Some(change.owner_pk),
                k2: Some(change.k),
                v2: Some(change.v),
            },
            3,
        )
        .unwrap();
        assert!(groth16::verify(
            &vk,
            &[root, nf, to.commitment(), change.commitment()],
            &proof
        ));
    }

    #[test]
    fn viewing_material_is_not_sufficient_to_nullify() {
        let spend_sk = Fr::from(42u64);
        let note = Note::from_spend_key(spend_sk, Fr::from(5u64), Fr::from(10u64));
        // An auditor who decrypted the blob has owner_pk, k, v — not spend_sk.
        let guessed = nullifier(note.owner_pk, note.k);
        assert_ne!(guessed, nullifier(spend_sk, note.k));
    }
}
