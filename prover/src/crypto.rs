//! Stealth addresses, encrypted note payloads, and viewing keys.
//!
//! This is the selective-disclosure layer. It never touches the ZK core: the
//! chain only ever sees an opaque ciphertext blob (emitted with each output
//! commitment). Recipients scan those blobs and trial-decrypt with a *viewing
//! key*; auditors can be handed the same viewing key to read history without
//! being able to spend.
//!
//! Scheme (ECIES-style, X25519 + ChaCha20-Poly1305):
//!
//! ```text
//! recipient meta-address = (spend_pub, view_pub)      // published once
//! per note:  eph = random x25519;  s = ECDH(eph, view_pub)
//!            key = SHA-256("hypertron:note:v1" || s)
//!            ct  = ChaCha20Poly1305(key, nonce=0, plaintext = n||k||v)
//!            blob = eph_pub (32) || ct
//! ```
//!
//! The recipient (or an auditor with the view key) recomputes
//! `s = ECDH(view_secret, eph_pub)` and decrypts. Spending still requires the
//! separate spend key, so a viewing key is read-only authority.

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::groth16::fr_be32;
use crate::note::Note;

const KDF_DOMAIN: &[u8] = b"hypertron:note:v1";

/// A viewing key: read-only authority to decrypt notes sent to its public half.
/// Give the secret to an auditor for compliance disclosure; it cannot spend.
#[derive(Clone)]
pub struct ViewingKey {
    secret: StaticSecret,
}

impl ViewingKey {
    /// Generate a fresh random viewing key.
    pub fn generate() -> Self {
        ViewingKey { secret: StaticSecret::random_from_rng(OsRng) }
    }

    /// Deterministically derive a viewing key from 32 bytes of seed material
    /// (e.g. an HD-derived leaf of the user's wallet seed).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        ViewingKey { secret: StaticSecret::from(seed) }
    }

    pub fn public(&self) -> ViewingPubKey {
        ViewingPubKey { point: PublicKey::from(&self.secret) }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }
}

/// The public half of a viewing key — part of a recipient's stealth meta-address.
#[derive(Clone, Copy)]
pub struct ViewingPubKey {
    point: PublicKey,
}

impl ViewingPubKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }

    pub fn from_bytes(b: [u8; 32]) -> Self {
        ViewingPubKey { point: PublicKey::from(b) }
    }
}

fn kdf(shared: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(KDF_DOMAIN);
    h.update(shared);
    h.finalize().into()
}

/// Encrypt a note to a recipient's viewing public key. Returns the on-chain
/// blob `eph_pub (32) || ciphertext` to emit alongside the commitment.
pub fn encrypt_note(recipient: &ViewingPubKey, note: &Note) -> Vec<u8> {
    let mut eph_seed = [0u8; 32];
    OsRng.fill_bytes(&mut eph_seed);
    let eph_secret = StaticSecret::from(eph_seed);
    let eph_pub = PublicKey::from(&eph_secret);

    let shared = eph_secret.diffie_hellman(&recipient.point);
    let key = kdf(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new((&key).into());

    let mut plaintext = Vec::with_capacity(96);
    plaintext.extend_from_slice(&fr_be32(&note.n));
    plaintext.extend_from_slice(&fr_be32(&note.k));
    plaintext.extend_from_slice(&fr_be32(&note.v));

    // A fresh ephemeral key per note means a fixed nonce is safe (key is unique).
    let nonce = Nonce::default();
    let ct = cipher.encrypt(&nonce, plaintext.as_ref()).expect("chacha encrypt");

    let mut blob = Vec::with_capacity(32 + ct.len());
    blob.extend_from_slice(eph_pub.as_bytes());
    blob.extend_from_slice(&ct);
    blob
}

/// Try to decrypt a note blob with a viewing key. Returns the note on success.
/// A failed AEAD tag simply means "not for this key" (used while scanning).
pub fn decrypt_note(vk: &ViewingKey, blob: &[u8]) -> Result<Note> {
    if blob.len() < 32 + 16 {
        return Err(anyhow!("blob too short"));
    }
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&blob[..32]);
    let eph_pub = PublicKey::from(eph);

    let shared = vk.secret.diffie_hellman(&eph_pub);
    let key = kdf(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new((&key).into());

    let nonce = Nonce::default();
    let pt = cipher
        .decrypt(&nonce, &blob[32..])
        .map_err(|_| anyhow!("decryption failed (note not addressed to this viewing key)"))?;
    if pt.len() != 96 {
        return Err(anyhow!("unexpected plaintext length {}", pt.len()));
    }
    Ok(Note {
        n: Fr::from_be_bytes_mod_order(&pt[0..32]),
        k: Fr::from_be_bytes_mod_order(&pt[32..64]),
        v: Fr::from_be_bytes_mod_order(&pt[64..96]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let vk = ViewingKey::generate();
        let note = Note::new(Fr::from(11u64), Fr::from(22u64), Fr::from(1_000u64));
        let blob = encrypt_note(&vk.public(), &note);
        let got = decrypt_note(&vk, &blob).unwrap();
        assert_eq!(got, note);
    }

    #[test]
    fn wrong_viewing_key_fails() {
        let vk = ViewingKey::generate();
        let other = ViewingKey::generate();
        let note = Note::new(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64));
        let blob = encrypt_note(&vk.public(), &note);
        assert!(decrypt_note(&other, &blob).is_err());
    }
}
