//! Hypertron off-chain prover.
//!
//! This crate is the canonical, non-test home of the shielded-pool circuit and
//! the Groth16 tooling around it. The `hypertron-verifier` contract's tests
//! depend on this same code, so what an integrator proves with the
//! `hypertron-prove` CLI is exactly what the chain verifies.

pub mod circuit;
pub mod groth16;
pub mod merkle;
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
    use crate::circuit::{MembershipCircuit, DEPTH};

    #[test]
    fn setup_prove_verify_roundtrip() {
        let n = Fr::from(1234u64);
        let k = Fr::from(5678u64);
        let leaf = merkle::leaf(n, k);
        let (root, siblings, path_bits) = merkle::path(&[leaf], 0, DEPTH);
        let nullifier_hash = merkle::nullifier(n);
        let recipient = Fr::from(0xABCDu64);
        let amount = groth16::amount_fr(42);

        let (pk, vk) = groth16::setup(DEPTH, 3).unwrap();
        let proof = groth16::prove(
            &pk,
            MembershipCircuit {
                root: Some(root),
                nullifier_hash: Some(nullifier_hash),
                recipient: Some(recipient),
                amount: Some(amount),
                n: Some(n),
                k: Some(k),
                siblings: siblings.into_iter().map(Some).collect(),
                path_bits: path_bits.into_iter().map(Some).collect(),
            },
            3,
        )
        .unwrap();

        assert!(groth16::verify(&vk, &[root, nullifier_hash, recipient, amount], &proof));
        // Wrong amount must fail: the payout is bound into the proof.
        let wrong = groth16::amount_fr(43);
        assert!(!groth16::verify(&vk, &[root, nullifier_hash, recipient, wrong], &proof));
    }

    #[test]
    fn parse_fr_accepts_hex_and_decimal() {
        assert_eq!(parse_fr("255").unwrap(), parse_fr("0xff").unwrap());
        assert!(parse_bytes32("0x00").is_err());
    }
}
