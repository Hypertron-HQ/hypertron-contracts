//! WebAssembly bindings for the Hypertron off-chain prover.
//!
//! Same circuits and byte layout as the `hypertron-prove` CLI, exposed as
//! JS-callable functions so a browser wallet (or a Node backend) can build
//! deposit/unshield/transfer proofs and note ciphertexts entirely client-side.
//!
//! Notes use a spend-key-derived owner:
//!   - `owner_pk = Poseidon(spend_sk, 0)`
//!   - `cm = Poseidon(Poseidon(owner_pk, k), v)`
//!   - `nf = Poseidon(spend_sk, k)`
//! Only `owner_pk || k || v` is encrypted into note blobs; `spend_sk` is never
//! disclosed. Spending proofs receive `spend_sk` and prove ownership in-circuit.
//!
//! Design:
//!   - Proving keys are large, so they are NOT embedded. Pass the `pk` bytes
//!     (fetched by the caller) into each proof function.
//!   - Every proof function returns a JSON string whose fields line up 1:1 with
//!     the on-chain contract arguments, so the caller can feed them straight
//!     into a Stellar SDK `invoke`:
//!       deposit  -> { commitment, proof, public_inputs }
//!       unshield -> { root, nullifier, change_cm, proof, public_inputs }
//!       transfer   -> { root, nullifier, out_cm1, out_cm2, proof,
//!                       public_inputs, recipient_blob?, change_blob? }
//!       transfer_n -> { root, nullifiers, out_cm1, out_cm2, proof,
//!                       public_inputs, recipient_blob?, change_blob? }
//!   - Amounts/values are passed as decimal strings (JS numbers are unsafe past
//!     2^53); field elements accept decimal or `0x` hex.

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use rand_core::OsRng;
use serde::Deserialize;
use wasm_bindgen::prelude::*;

use hypertron_prover::circuit::{
    DepositCircuit, TransferCircuit, TransferInput, TransferNCircuit, UnshieldCircuit, DEPTH,
};
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

/// Derive `owner_pk = Poseidon(spend_sk, 0)` as `0x`-hex.
#[wasm_bindgen]
pub fn owner_pk(spend_sk: &str) -> Result<String, JsError> {
    Ok(hex0x(groth16::fr_be32(&note::owner_pk(fr(spend_sk)?))))
}

/// Note commitment `cm = Poseidon(Poseidon(owner_pk, k), v)` as `0x`-hex.
#[wasm_bindgen]
pub fn commitment(owner_pk: &str, k: &str, v: &str) -> Result<String, JsError> {
    let cm = note::commitment(fr(owner_pk)?, fr(k)?, Fr::from(u128s(v)?));
    Ok(hex0x(groth16::fr_be32(&cm)))
}

/// Nullifier `nf = Poseidon(spend_sk, k)` as `0x`-hex.
#[wasm_bindgen]
pub fn nullifier(spend_sk: &str, k: &str) -> Result<String, JsError> {
    Ok(hex0x(groth16::fr_be32(&note::nullifier(
        fr(spend_sk)?,
        fr(k)?,
    ))))
}

/// Merkle root over an ordered JSON array of `0x` leaf commitments (DEPTH=20).
/// Empty array → empty-tree root. Used by hypertron-indexer for root verification.
#[wasm_bindgen]
pub fn merkle_root(leaves_json: &str) -> Result<String, JsError> {
    let leaves: Vec<String> = serde_json::from_str(leaves_json).map_err(err)?;
    let leaf_frs = leaves_to_fr(&leaves)?;
    let root = merkle::root(&leaf_frs, DEPTH);
    Ok(hex0x(groth16::fr_be32(&root)))
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
/// (`eph_pub || ciphertext`) as `0x`-hex. The plaintext is `owner_pk || k || v`;
/// the spend key is never encrypted.
#[wasm_bindgen]
pub fn encrypt_note_blob(
    recipient_view: &str,
    owner_pk: &str,
    k: &str,
    v: &str,
) -> Result<String, JsError> {
    let recip = ViewingPubKey::from_bytes(parse_bytes32(recipient_view).map_err(err)?);
    let note = Note::new(fr(owner_pk)?, fr(k)?, Fr::from(u128s(v)?));
    Ok(format!("0x{}", hex::encode(encrypt_note(&recip, &note))))
}

/// Decrypt / scan a note blob with a viewing secret. Returns
/// `{ owner_pk, n, k, v }`, where `n` is a backward-compatible alias for
/// `owner_pk`, or throws if the blob is not addressed to this key.
#[wasm_bindgen]
pub fn decrypt_note_blob(view_secret: &str, blob: &str) -> Result<String, JsError> {
    let vk = ViewingKey::from_seed(parse_bytes32(view_secret).map_err(err)?);
    let blob = hex::decode(blob.trim().strip_prefix("0x").unwrap_or(blob.trim())).map_err(err)?;
    let note = decrypt_note(&vk, &blob).map_err(err)?;
    let owner_pk = format!("0x{}", hex::encode(groth16::fr_be32(&note.owner_pk)));
    Ok(serde_json::json!({
        "owner_pk": owner_pk,
        "n": owner_pk,
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
    #[serde(alias = "n")]
    owner_pk: String,
    k: String,
    amount: String,
}

/// Prove a shield deposit binds `amount` to a commitment.
/// Public inputs order: `[cm, amount]`.
#[wasm_bindgen]
pub fn deposit_proof(pk: &[u8], params_json: &str) -> Result<String, JsError> {
    let p: DepositParams = serde_json::from_str(params_json).map_err(err)?;
    let pk = groth16::pk_from_bytes(pk).map_err(err)?;
    let (owner_pk, k) = (fr(&p.owner_pk)?, fr(&p.k)?);
    let amount_fe = Fr::from(u128s(&p.amount)?);
    let cm = note::commitment(owner_pk, k, amount_fe);
    let circuit = DepositCircuit {
        cm: Some(cm),
        amount: Some(amount_fe),
        owner_pk: Some(owner_pk),
        k: Some(k),
    };
    let proof = groth16::prove(&pk, circuit, &mut OsRng).map_err(err)?;
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
    spend_sk: String,
    k: String,
    v: String,
    index: usize,
    leaves: Vec<String>,
    recipient_field: String,
    amount: String,
    change_k: String,
    depth: Option<usize>,
}

/// Prove an unshield (exit to a public recipient, keep a change note).
/// Public inputs order: `[root, nullifier, recipient, amount, change_cm]`.
#[wasm_bindgen]
pub fn unshield_proof(pk: &[u8], params_json: &str) -> Result<String, JsError> {
    let p: UnshieldParams = serde_json::from_str(params_json).map_err(err)?;
    let pk = groth16::pk_from_bytes(pk).map_err(err)?;
    let depth = p.depth.unwrap_or(DEPTH);
    let (spend_sk, k) = (fr(&p.spend_sk)?, fr(&p.k)?);
    let v = u128s(&p.v)?;
    let amount = u128s(&p.amount)?;
    if amount > v {
        return Err(JsError::new("amount exceeds note value"));
    }

    let note_in = Note::from_spend_key(spend_sk, k, Fr::from(v));
    let leaf_frs = leaves_to_fr(&p.leaves)?;
    if p.index >= leaf_frs.len() || leaf_frs[p.index] != note_in.commitment() {
        return Err(JsError::new("leaf at index does not match this note"));
    }
    let (root, siblings, path_bits) = merkle::path(&leaf_frs, p.index, depth);
    let nf = note_in.nullifier(spend_sk);
    let recipient_fe =
        Fr::from_be_bytes_mod_order(&parse_bytes32(&p.recipient_field).map_err(err)?);
    let amount_fe = Fr::from(amount);
    let change = Note::new(note_in.owner_pk, fr(&p.change_k)?, Fr::from(v - amount));
    let change_cm = change.commitment();

    let circuit = UnshieldCircuit {
        root: Some(root),
        nullifier: Some(nf),
        recipient: Some(recipient_fe),
        amount: Some(amount_fe),
        change_cm: Some(change_cm),
        spend_sk: Some(spend_sk),
        k: Some(k),
        v: Some(note_in.v),
        siblings: siblings.into_iter().map(Some).collect(),
        path_bits: path_bits.into_iter().map(Some).collect(),
        k2: Some(change.k),
        vc: Some(change.v),
    };
    let proof = groth16::prove(&pk, circuit, &mut OsRng).map_err(err)?;
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
    spend_sk: String,
    k: String,
    v: String,
    index: usize,
    leaves: Vec<String>,
    #[serde(alias = "out1_n")]
    out1_owner_pk: String,
    out1_k: String,
    out1_v: String,
    #[serde(alias = "out2_n")]
    out2_owner_pk: String,
    out2_k: String,
    out2_v: String,
    /// Optional recipient viewing pubkey (hex) to encrypt out1 (recipient's note).
    recipient_view: Option<String>,
    /// Optional self viewing pubkey (hex) to encrypt out2 (payer's change note).
    /// Enables recovery after browser wipe.
    self_view: Option<String>,
    depth: Option<usize>,
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

    let spend_sk = fr(&p.spend_sk)?;
    let note_in = Note::from_spend_key(spend_sk, fr(&p.k)?, Fr::from(v));
    let leaf_frs = leaves_to_fr(&p.leaves)?;
    if p.index >= leaf_frs.len() || leaf_frs[p.index] != note_in.commitment() {
        return Err(JsError::new("leaf at index does not match this note"));
    }
    let (root, siblings, path_bits) = merkle::path(&leaf_frs, p.index, depth);
    let nf = note_in.nullifier(spend_sk);
    let out1 = Note::new(fr(&p.out1_owner_pk)?, fr(&p.out1_k)?, Fr::from(out1_v));
    let out2 = Note::new(fr(&p.out2_owner_pk)?, fr(&p.out2_k)?, Fr::from(out2_v));

    let circuit = TransferCircuit {
        root: Some(root),
        nullifier: Some(nf),
        out_cm1: Some(out1.commitment()),
        out_cm2: Some(out2.commitment()),
        spend_sk: Some(spend_sk),
        k: Some(note_in.k),
        v: Some(note_in.v),
        siblings: siblings.into_iter().map(Some).collect(),
        path_bits: path_bits.into_iter().map(Some).collect(),
        owner_pk1: Some(out1.owner_pk),
        k1: Some(out1.k),
        v1: Some(out1.v),
        owner_pk2: Some(out2.owner_pk),
        k2: Some(out2.k),
        v2: Some(out2.v),
    };
    let proof = groth16::prove(&pk, circuit, &mut OsRng).map_err(err)?;
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
        let blob = encrypt_note(
            &ViewingPubKey::from_bytes(parse_bytes32(&rv).map_err(err)?),
            &out1,
        );
        out["recipient_blob"] = serde_json::Value::String(format!("0x{}", hex::encode(blob)));
    }
    if let Some(sv) = p.self_view {
        let blob = encrypt_note(
            &ViewingPubKey::from_bytes(parse_bytes32(&sv).map_err(err)?),
            &out2,
        );
        out["change_blob"] = serde_json::Value::String(format!("0x{}", hex::encode(blob)));
    }
    Ok(out.to_string())
}

#[derive(Deserialize)]
struct TransferNNote {
    k: String,
    v: String,
    index: usize,
}

#[derive(Deserialize)]
struct TransferNParams {
    spend_sk: String,
    inputs: Vec<TransferNNote>,
    leaves: Vec<String>,
    #[serde(alias = "out1_n")]
    out1_owner_pk: String,
    out1_k: String,
    out1_v: String,
    #[serde(alias = "out2_n")]
    out2_owner_pk: String,
    out2_k: String,
    out2_v: String,
    recipient_view: Option<String>,
    self_view: Option<String>,
    depth: Option<usize>,
}

fn transfer_n_proof<const N: usize>(pk: &[u8], params_json: &str) -> Result<String, JsError> {
    let p: TransferNParams = serde_json::from_str(params_json).map_err(err)?;
    if p.inputs.len() != N {
        return Err(JsError::new(&format!(
            "expected {N} inputs, got {}",
            p.inputs.len()
        )));
    }
    let pk = groth16::pk_from_bytes(pk).map_err(err)?;
    let depth = p.depth.unwrap_or(DEPTH);
    let out1_v = u128s(&p.out1_v)?;
    let out2_v = u128s(&p.out2_v)?;
    let mut in_sum: u128 = 0;
    let mut vs = Vec::with_capacity(N);
    for inp in &p.inputs {
        let v = u128s(&inp.v)?;
        in_sum = in_sum
            .checked_add(v)
            .ok_or_else(|| JsError::new("input value overflow"))?;
        vs.push(v);
    }
    if out1_v + out2_v != in_sum {
        return Err(JsError::new("outputs must equal input value sum"));
    }

    let spend_sk = fr(&p.spend_sk)?;
    let leaf_frs = leaves_to_fr(&p.leaves)?;
    let mut notes = Vec::with_capacity(N);
    for i in 0..N {
        let note = Note::from_spend_key(spend_sk, fr(&p.inputs[i].k)?, Fr::from(vs[i]));
        let idx = p.inputs[i].index;
        if idx >= leaf_frs.len() || leaf_frs[idx] != note.commitment() {
            return Err(JsError::new(&format!(
                "leaf at index {idx} does not match input {i}"
            )));
        }
        notes.push(note);
    }

    let mut inputs_c: [TransferInput; N] =
        core::array::from_fn(|_| TransferInput::empty(depth));
    let mut nfs = Vec::with_capacity(N);
    let mut root_opt: Option<Fr> = None;
    for i in 0..N {
        let (root, siblings, path_bits) = merkle::path(&leaf_frs, p.inputs[i].index, depth);
        match root_opt {
            None => root_opt = Some(root),
            Some(r) if r != root => {
                return Err(JsError::new("inputs do not share a Merkle root"));
            }
            _ => {}
        }
        let nf = notes[i].nullifier(spend_sk);
        nfs.push(nf);
        inputs_c[i] = TransferInput {
            k: Some(notes[i].k),
            v: Some(notes[i].v),
            nullifier: Some(nf),
            siblings: siblings.into_iter().map(Some).collect(),
            path_bits: path_bits.into_iter().map(Some).collect(),
        };
    }
    let root = root_opt.ok_or_else(|| JsError::new("no inputs"))?;
    let out1 = Note::new(fr(&p.out1_owner_pk)?, fr(&p.out1_k)?, Fr::from(out1_v));
    let out2 = Note::new(fr(&p.out2_owner_pk)?, fr(&p.out2_k)?, Fr::from(out2_v));

    let circuit = TransferNCircuit::<N> {
        root: Some(root),
        out_cm1: Some(out1.commitment()),
        out_cm2: Some(out2.commitment()),
        spend_sk: Some(spend_sk),
        inputs: inputs_c,
        owner_pk1: Some(out1.owner_pk),
        k1: Some(out1.k),
        v1: Some(out1.v),
        owner_pk2: Some(out2.owner_pk),
        k2: Some(out2.k),
        v2: Some(out2.v),
    };
    let proof = groth16::prove(&pk, circuit, &mut OsRng).map_err(err)?;
    let mut publics = vec![root];
    publics.extend(nfs.iter().copied());
    publics.push(out1.commitment());
    publics.push(out2.commitment());
    if !groth16::verify(&pk.vk, &publics, &proof) {
        return Err(JsError::new("internal error: proof failed to verify"));
    }

    let mut out = serde_json::json!({
        "root": hex0x(groth16::fr_be32(&root)),
        "nullifiers": nfs.iter().map(|f| hex0x(groth16::fr_be32(f))).collect::<Vec<_>>(),
        "out_cm1": hex0x(groth16::fr_be32(&out1.commitment())),
        "out_cm2": hex0x(groth16::fr_be32(&out2.commitment())),
        "proof": format!("0x{}", groth16::proof_hex(&proof)),
        "public_inputs": publics_hex(&publics),
    });
    if let Some(rv) = p.recipient_view {
        let blob = encrypt_note(
            &ViewingPubKey::from_bytes(parse_bytes32(&rv).map_err(err)?),
            &out1,
        );
        out["recipient_blob"] = serde_json::Value::String(format!("0x{}", hex::encode(blob)));
    }
    if let Some(sv) = p.self_view {
        let blob = encrypt_note(
            &ViewingPubKey::from_bytes(parse_bytes32(&sv).map_err(err)?),
            &out2,
        );
        out["change_blob"] = serde_json::Value::String(format!("0x{}", hex::encode(blob)));
    }
    Ok(out.to_string())
}

/// Prove a 2-in / 2-out private transfer.
/// Public inputs order: `[root, nf_1, nf_2, out_cm1, out_cm2]`.
#[wasm_bindgen]
pub fn transfer_2_proof(pk: &[u8], params_json: &str) -> Result<String, JsError> {
    transfer_n_proof::<2>(pk, params_json)
}

/// Prove a 4-in / 2-out private transfer.
/// Public inputs order: `[root, nf_1, nf_2, nf_3, nf_4, out_cm1, out_cm2]`.
#[wasm_bindgen]
pub fn transfer_4_proof(pk: &[u8], params_json: &str) -> Result<String, JsError> {
    transfer_n_proof::<4>(pk, params_json)
}
