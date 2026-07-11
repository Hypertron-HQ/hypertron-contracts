//! WebAssembly bindings for the Hypertron off-chain prover.
//!
//! Same circuits and byte layout as the `hypertron-prove` CLI, exposed as
//! JS-callable functions so a browser wallet (or a Node backend) can build
//! deposit/unshield/transfer proofs and note ciphertexts entirely client-side.
//!
//! Design:
//!   - Proving keys are large, so they are NOT embedded. Pass the `pk` bytes
//!     (fetched by the caller) into each proof function.
//!   - Every proof function returns a JSON string whose fields line up 1:1 with
//!     the on-chain contract arguments, so the caller can feed them straight
//!     into a Stellar SDK `invoke`:
//!       deposit  -> { commitment, proof, public_inputs }
//!       unshield -> { root, nullifier, change_cm, proof, public_inputs }
//!       transfer -> { root, nullifier, out_cm1, out_cm2, proof,
//!                     public_inputs, recipient_blob? }
//!   - Amounts/values are passed as decimal strings (JS numbers are unsafe past
//!     2^53); field elements accept decimal or `0x` hex.

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use hypertron_prover::circuit::{DepositCircuit, TransferCircuit, UnshieldCircuit, DEPTH};
use hypertron_prover::crypto::{decrypt_note, encrypt_note, ViewingKey, ViewingPubKey};
use hypertron_prover::note::Note;
use hypertron_prover::{groth16, merkle, note, parse_bytes32, parse_fr};

/// Install a panic hook that surfaces Rust panics in the JS console. Safe to
/// call more than once; call it once at startup.
#[wasm_bindgen(start)]
pub fn start() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

fn err<E: core::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

fn fr(s: &str) -> Result<Fr, JsError> {
    parse_fr(s).map_err(err)
}

fn u128s(s: &str) -> Result<u128, JsError> {
    s.trim().parse::<u128>().map_err(err)
}

fn hex0x(bytes: [u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// A fresh 64-bit seed for Groth16 proof randomness (r, s blinders), drawn from
/// the platform CSPRNG. Deterministic seeds may be passed in via `seed` instead.
fn random_seed() -> u64 {
    let mut b = [0u8; 8];
    getrandom::getrandom(&mut b).expect("getrandom");
    u64::from_le_bytes(b)
}

fn leaves_to_fr(leaves: &[String]) -> Result<Vec<Fr>, JsError> {
    leaves
        .iter()
        .map(|l| {
            let b = parse_bytes32(l).map_err(err)?;
            Ok(Fr::from_be_bytes_mod_order(&b))
        })
        .collect()
}

fn publics_hex(publics: &[Fr]) -> Vec<String> {
    publics.iter().map(|f| hex0x(groth16::fr_be32(f))).collect()
}

// -------------------------------------------------------------------------
// Note math (no proving key needed).
// -------------------------------------------------------------------------

/// Note commitment `cm = Poseidon(Poseidon(n, k), v)` as `0x`-hex.
#[wasm_bindgen]
pub fn commitment(n: &str, k: &str, v: &str) -> Result<String, JsError> {
    let cm = note::commitment(fr(n)?, fr(k)?, Fr::from(u128s(v)?));
    Ok(hex0x(groth16::fr_be32(&cm)))
}

/// Nullifier `nf = Poseidon(n, 0)` as `0x`-hex.
#[wasm_bindgen]
pub fn nullifier(n: &str) -> Result<String, JsError> {
    Ok(hex0x(groth16::fr_be32(&note::nullifier(fr(n)?))))
}

// -------------------------------------------------------------------------
// Viewing keys / selective disclosure.
// -------------------------------------------------------------------------

/// Generate a viewing keypair. Pass a 32-byte hex `seed` for deterministic
/// derivation, or omit it for a random key. Returns `{ view_secret, view_pub }`.
#[wasm_bindgen]
pub fn keygen(seed: Option<String>) -> Result<String, JsError> {
    let vk = match seed {
        Some(s) => ViewingKey::from_seed(parse_bytes32(&s).map_err(err)?),
        None => ViewingKey::generate(),
    };
    Ok(serde_json::json!({
        "view_secret": format!("0x{}", hex::encode(vk.secret_bytes())),
        "view_pub": format!("0x{}", hex::encode(vk.public().to_bytes())),
    })
    .to_string())
}

/// Encrypt a note to a recipient's viewing pubkey. Returns the on-chain blob
/// (`eph_pub || ciphertext`) as `0x`-hex.
#[wasm_bindgen]
pub fn encrypt_note_blob(recipient_view: &str, n: &str, k: &str, v: &str) -> Result<String, JsError> {
    let recip = ViewingPubKey::from_bytes(parse_bytes32(recipient_view).map_err(err)?);
    let note = Note::new(fr(n)?, fr(k)?, Fr::from(u128s(v)?));
    Ok(format!("0x{}", hex::encode(encrypt_note(&recip, &note))))
}

/// Decrypt / scan a note blob with a viewing secret. Returns `{ n, k, v }`, or
/// throws if the blob is not addressed to this key. Used by recipients (note
/// discovery) and auditors (compliance disclosure).
#[wasm_bindgen]
pub fn decrypt_note_blob(view_secret: &str, blob: &str) -> Result<String, JsError> {
    let vk = ViewingKey::from_seed(parse_bytes32(view_secret).map_err(err)?);
    let blob = hex::decode(blob.trim().strip_prefix("0x").unwrap_or(blob.trim())).map_err(err)?;
    let note = decrypt_note(&vk, &blob).map_err(err)?;
    Ok(serde_json::json!({
        "n": format!("0x{}", hex::encode(groth16::fr_be32(&note.n))),
        "k": format!("0x{}", hex::encode(groth16::fr_be32(&note.k))),
        "v": format!("{}", note.v),
    })
    .to_string())
}

// -------------------------------------------------------------------------
// Proofs.
// -------------------------------------------------------------------------

#[derive(Deserialize)]
struct DepositParams {
    n: String,
    k: String,
    amount: String,
    seed: Option<u64>,
}

/// Prove a shield deposit binds `amount` to a commitment.
/// Public inputs order: `[cm, amount]`.
#[wasm_bindgen]
pub fn deposit_proof(pk: &[u8], params_json: &str) -> Result<String, JsError> {
    let p: DepositParams = serde_json::from_str(params_json).map_err(err)?;
    let pk = groth16::pk_from_bytes(pk).map_err(err)?;
    let (n, k) = (fr(&p.n)?, fr(&p.k)?);
    let amount_fe = Fr::from(u128s(&p.amount)?);
    let cm = note::commitment(n, k, amount_fe);
    let circuit = DepositCircuit { cm: Some(cm), amount: Some(amount_fe), n: Some(n), k: Some(k) };
    let proof = groth16::prove(&pk, circuit, p.seed.unwrap_or_else(random_seed)).map_err(err)?;
    let publics = [cm, amount_fe];
    if !groth16::verify(&pk.vk, &publics, &proof) {
        return Err(JsError::new("internal error: proof failed to verify"));
    }
    Ok(serde_json::json!({
        "commitment": hex0x(groth16::fr_be32(&cm)),
        "proof": format!("0x{}", groth16::proof_hex(&proof)),
        "public_inputs": publics_hex(&publics),
    })
    .to_string())
}

#[derive(Deserialize)]
struct UnshieldParams {
    n: String,
    k: String,
    v: String,
    index: usize,
    leaves: Vec<String>,
    recipient_field: String,
    amount: String,
    change_n: String,
    change_k: String,
    depth: Option<usize>,
    seed: Option<u64>,
}

/// Prove an unshield (exit to a public recipient, keep a change note).
/// Public inputs order: `[root, nullifier, recipient, amount, change_cm]`.
#[wasm_bindgen]
pub fn unshield_proof(pk: &[u8], params_json: &str) -> Result<String, JsError> {
    let p: UnshieldParams = serde_json::from_str(params_json).map_err(err)?;
    let pk = groth16::pk_from_bytes(pk).map_err(err)?;
    let depth = p.depth.unwrap_or(DEPTH);
    let (n, k) = (fr(&p.n)?, fr(&p.k)?);
    let v = u128s(&p.v)?;
    let amount = u128s(&p.amount)?;
    if amount > v {
        return Err(JsError::new("amount exceeds note value"));
    }

    let note_in = Note::new(n, k, Fr::from(v));
    let leaf_frs = leaves_to_fr(&p.leaves)?;
    if p.index >= leaf_frs.len() || leaf_frs[p.index] != note_in.commitment() {
        return Err(JsError::new("leaf at index does not match this note"));
    }
    let (root, siblings, path_bits) = merkle::path(&leaf_frs, p.index, depth);
    let nf = note_in.nullifier();
    let recipient_fe = Fr::from_be_bytes_mod_order(&parse_bytes32(&p.recipient_field).map_err(err)?);
    let amount_fe = Fr::from(amount);
    let change = Note::new(fr(&p.change_n)?, fr(&p.change_k)?, Fr::from(v - amount));
    let change_cm = change.commitment();

    let circuit = UnshieldCircuit {
        root: Some(root),
        nullifier: Some(nf),
        recipient: Some(recipient_fe),
        amount: Some(amount_fe),
        change_cm: Some(change_cm),
        n: Some(n),
        k: Some(k),
        v: Some(note_in.v),
        siblings: siblings.into_iter().map(Some).collect(),
        path_bits: path_bits.into_iter().map(Some).collect(),
        n2: Some(change.n),
        k2: Some(change.k),
        vc: Some(change.v),
    };
    let proof = groth16::prove(&pk, circuit, p.seed.unwrap_or_else(random_seed)).map_err(err)?;
    let publics = [root, nf, recipient_fe, amount_fe, change_cm];
    if !groth16::verify(&pk.vk, &publics, &proof) {
        return Err(JsError::new("internal error: proof failed to verify"));
    }
    Ok(serde_json::json!({
        "root": hex0x(groth16::fr_be32(&root)),
        "nullifier": hex0x(groth16::fr_be32(&nf)),
        "change_cm": hex0x(groth16::fr_be32(&change_cm)),
        "proof": format!("0x{}", groth16::proof_hex(&proof)),
        "public_inputs": publics_hex(&publics),
    })
    .to_string())
}

#[derive(Deserialize)]
struct TransferParams {
    n: String,
    k: String,
    v: String,
    index: usize,
    leaves: Vec<String>,
    out1_n: String,
    out1_k: String,
    out1_v: String,
    out2_n: String,
    out2_k: String,
    out2_v: String,
    /// Optional recipient viewing pubkey (hex) to also emit an encrypted blob.
    recipient_view: Option<String>,
    depth: Option<usize>,
    seed: Option<u64>,
}

/// Prove a fully-private note -> two notes transfer.
/// Public inputs order: `[root, nullifier, out_cm1, out_cm2]`.
#[wasm_bindgen]
pub fn transfer_proof(pk: &[u8], params_json: &str) -> Result<String, JsError> {
    let p: TransferParams = serde_json::from_str(params_json).map_err(err)?;
    let pk = groth16::pk_from_bytes(pk).map_err(err)?;
    let depth = p.depth.unwrap_or(DEPTH);
    let v = u128s(&p.v)?;
    let out1_v = u128s(&p.out1_v)?;
    let out2_v = u128s(&p.out2_v)?;
    if out1_v + out2_v != v {
        return Err(JsError::new("outputs must equal input value"));
    }

    let note_in = Note::new(fr(&p.n)?, fr(&p.k)?, Fr::from(v));
    let leaf_frs = leaves_to_fr(&p.leaves)?;
    if p.index >= leaf_frs.len() || leaf_frs[p.index] != note_in.commitment() {
        return Err(JsError::new("leaf at index does not match this note"));
    }
    let (root, siblings, path_bits) = merkle::path(&leaf_frs, p.index, depth);
    let nf = note_in.nullifier();
    let out1 = Note::new(fr(&p.out1_n)?, fr(&p.out1_k)?, Fr::from(out1_v));
    let out2 = Note::new(fr(&p.out2_n)?, fr(&p.out2_k)?, Fr::from(out2_v));

    let circuit = TransferCircuit {
        root: Some(root),
        nullifier: Some(nf),
        out_cm1: Some(out1.commitment()),
        out_cm2: Some(out2.commitment()),
        n: Some(note_in.n),
        k: Some(note_in.k),
        v: Some(note_in.v),
        siblings: siblings.into_iter().map(Some).collect(),
        path_bits: path_bits.into_iter().map(Some).collect(),
        n1: Some(out1.n),
        k1: Some(out1.k),
        v1: Some(out1.v),
        n2: Some(out2.n),
        k2: Some(out2.k),
        v2: Some(out2.v),
    };
    let proof = groth16::prove(&pk, circuit, p.seed.unwrap_or_else(random_seed)).map_err(err)?;
    let publics = [root, nf, out1.commitment(), out2.commitment()];
    if !groth16::verify(&pk.vk, &publics, &proof) {
        return Err(JsError::new("internal error: proof failed to verify"));
    }

    let mut out = serde_json::json!({
        "root": hex0x(groth16::fr_be32(&root)),
        "nullifier": hex0x(groth16::fr_be32(&nf)),
        "out_cm1": hex0x(groth16::fr_be32(&out1.commitment())),
        "out_cm2": hex0x(groth16::fr_be32(&out2.commitment())),
        "proof": format!("0x{}", groth16::proof_hex(&proof)),
        "public_inputs": publics_hex(&publics),
    });
    if let Some(rv) = p.recipient_view {
        let blob = encrypt_note(&ViewingPubKey::from_bytes(parse_bytes32(&rv).map_err(err)?), &out1);
        out["recipient_blob"] = serde_json::Value::String(format!("0x{}", hex::encode(blob)));
    }
    Ok(out.to_string())
}
