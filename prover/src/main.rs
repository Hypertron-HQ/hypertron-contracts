//! `hypertron-prove` — off-chain prover + selective-disclosure CLI for the
//! Hypertron shielded pool.
//!
//! Circuits (each needs its own verifying key registered on-chain once):
//!   - `deposit`   : bind a public shield amount to a note commitment
//!   - `unshield`  : exit to a public recipient, keeping a change note
//!   - `transfer`  : fully-private note -> two notes (no public address/amount)
//!
//! Typical flows:
//!   hypertron-prove setup --circuit unshield        -> pk.bin + vk.json
//!   hypertron-prove commitment --n .. --k .. --v ..  -> leaf to deposit
//!   hypertron-prove deposit-proof ...                -> proof for `deposit`
//!   hypertron-prove unshield-proof ...               -> proof for `unshield`
//!   hypertron-prove transfer-proof ...               -> proof + recipient blob
//!   hypertron-prove keygen                           -> viewing keypair
//!   hypertron-prove decrypt --view-secret .. --blob ..  -> scan/audit a note

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use ark_ff::PrimeField;
use clap::{Parser, Subcommand, ValueEnum};

use hypertron_prover::circuit::{DepositCircuit, TransferCircuit, UnshieldCircuit};
use hypertron_prover::crypto::{decrypt_note, encrypt_note, ViewingKey, ViewingPubKey};
use hypertron_prover::note::Note;
use hypertron_prover::{groth16, merkle, note, parse_bytes32, parse_fr, Fr};

#[derive(Parser)]
#[command(
    name = "hypertron-prove",
    about = "Off-chain Groth16 prover + viewing-key tooling for the Hypertron shielded pool",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Clone, Copy, ValueEnum)]
enum Circuit {
    Deposit,
    Unshield,
    Transfer,
}

#[derive(Subcommand)]
enum Cmd {
    /// Groth16 setup for one circuit: writes a proving key and a vk JSON.
    ///
    /// LOCAL, deterministic setup for dev/test. Production requires the
    /// coordinator/MPC ceremony described in `docs/ceremony.md`.
    Setup {
        #[arg(long, value_enum)]
        circuit: Circuit,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value = "pk.bin")]
        pk_out: PathBuf,
        #[arg(long, default_value = "vk.json")]
        vk_out: PathBuf,
    },
    /// Compute a note commitment `cm = Poseidon(Poseidon(n,k), v)`.
    Commitment {
        #[arg(long)]
        n: String,
        #[arg(long)]
        k: String,
        #[arg(long)]
        v: u128,
    },
    /// Compute `nullifier = Poseidon(n, 0)`.
    Nullifier {
        #[arg(long)]
        n: String,
    },
    /// Generate a viewing keypair (read-only disclosure authority).
    Keygen {
        /// Optional 32-byte hex seed for deterministic derivation.
        #[arg(long)]
        seed: Option<String>,
    },
    /// Prove a shield deposit binds `amount` to a commitment. Public: [cm, amount].
    DepositProof {
        #[arg(long)]
        pk: PathBuf,
        #[arg(long)]
        n: String,
        #[arg(long)]
        k: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value = "deposit-proof.json")]
        out: PathBuf,
    },
    /// Prove an unshield. Public: [root, nullifier, recipient, amount, change_cm].
    UnshieldProof {
        #[arg(long)]
        pk: PathBuf,
        #[arg(long)]
        n: String,
        #[arg(long)]
        k: String,
        /// Value of the note being spent.
        #[arg(long)]
        v: u128,
        #[arg(long)]
        index: usize,
        #[arg(long)]
        leaves: PathBuf,
        /// Recipient field element = sha256(xdr(address)), 32-byte hex.
        #[arg(long)]
        recipient_field: String,
        /// Amount leaving the pool (must be <= v).
        #[arg(long)]
        amount: u128,
        /// Change note secrets (receives v - amount, kept in the pool).
        #[arg(long)]
        change_n: String,
        #[arg(long)]
        change_k: String,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value = "unshield-proof.json")]
        out: PathBuf,
    },
    /// Prove a fully-private transfer. Public: [root, nullifier, out_cm1, out_cm2].
    TransferProof {
        #[arg(long)]
        pk: PathBuf,
        #[arg(long)]
        n: String,
        #[arg(long)]
        k: String,
        #[arg(long)]
        v: u128,
        #[arg(long)]
        index: usize,
        #[arg(long)]
        leaves: PathBuf,
        /// Output note 1 (to the recipient).
        #[arg(long)]
        out1_n: String,
        #[arg(long)]
        out1_k: String,
        #[arg(long)]
        out1_v: u128,
        /// Output note 2 (change back to sender).
        #[arg(long)]
        out2_n: String,
        #[arg(long)]
        out2_k: String,
        #[arg(long)]
        out2_v: u128,
        /// Optional recipient viewing pubkey (hex) to also emit an encrypted blob.
        #[arg(long)]
        recipient_view: Option<String>,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value = "transfer-proof.json")]
        out: PathBuf,
    },
    /// Encrypt a note to a recipient's viewing pubkey -> on-chain blob (hex).
    Encrypt {
        #[arg(long)]
        recipient_view: String,
        #[arg(long)]
        n: String,
        #[arg(long)]
        k: String,
        #[arg(long)]
        v: u128,
    },
    /// Decrypt / scan a note blob with a viewing secret (recipient or auditor).
    Decrypt {
        #[arg(long)]
        view_secret: String,
        #[arg(long)]
        blob: String,
    },
}

fn hex0x(bytes: [u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn read_leaves(path: &PathBuf) -> Result<Vec<Fr>> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(|l| parse_bytes32(l).map(|b| Fr::from_be_bytes_mod_order(&b)))
        .collect()
}

fn write_proof(out: &PathBuf, proof_hex: String, publics: &[Fr]) -> Result<()> {
    let proof_json = groth16::ProofJson {
        proof: format!("0x{proof_hex}"),
        public_inputs: publics.iter().map(|f| hex0x(groth16::fr_be32(f))).collect(),
    };
    let text = serde_json::to_string_pretty(&proof_json)?;
    fs::write(out, &text).with_context(|| format!("writing {}", out.display()))?;
    println!("{text}");
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Setup { circuit, depth, seed, pk_out, vk_out } => {
            eprintln!(
                "warning: local deterministic setup (seed={seed}). Production needs the \
                 ceremony in docs/ceremony.md."
            );
            let (pk, vk) = match circuit {
                Circuit::Deposit => groth16::setup(DepositCircuit::empty(), seed)?,
                Circuit::Unshield => groth16::setup(UnshieldCircuit::empty(depth), seed)?,
                Circuit::Transfer => groth16::setup(TransferCircuit::empty(depth), seed)?,
            };
            fs::write(&pk_out, groth16::pk_to_bytes(&pk)?)
                .with_context(|| format!("writing {}", pk_out.display()))?;
            let vk_json = serde_json::to_string_pretty(&groth16::vk_json(&vk))?;
            fs::write(&vk_out, &vk_json).with_context(|| format!("writing {}", vk_out.display()))?;
            println!("proving key   -> {}", pk_out.display());
            println!("verifying key -> {} (register on-chain)", vk_out.display());
            println!("{vk_json}");
        }

        Cmd::Commitment { n, k, v } => {
            let cm = note::commitment(parse_fr(&n)?, parse_fr(&k)?, Fr::from(v));
            println!("{}", hex0x(groth16::fr_be32(&cm)));
        }

        Cmd::Nullifier { n } => {
            let nf = note::nullifier(parse_fr(&n)?);
            println!("{}", hex0x(groth16::fr_be32(&nf)));
        }

        Cmd::Keygen { seed } => {
            let vk = match seed {
                Some(s) => ViewingKey::from_seed(parse_bytes32(&s)?),
                None => ViewingKey::generate(),
            };
            println!("view_secret 0x{}", hex::encode(vk.secret_bytes()));
            println!("view_pub    0x{}", hex::encode(vk.public().to_bytes()));
        }

        Cmd::DepositProof { pk, n, k, amount, seed, out } => {
            let pk = groth16::pk_from_bytes(&fs::read(&pk)?)?;
            let (n, k) = (parse_fr(&n)?, parse_fr(&k)?);
            let amount_fe = Fr::from(amount);
            let cm = note::commitment(n, k, amount_fe);
            let circuit = DepositCircuit { cm: Some(cm), amount: Some(amount_fe), n: Some(n), k: Some(k) };
            let proof = groth16::prove(&pk, circuit, seed)?;
            let publics = [cm, amount_fe];
            if !groth16::verify(&pk.vk, &publics, &proof) {
                return Err(anyhow!("internal error: proof failed to verify"));
            }
            println!("commitment {}", hex0x(groth16::fr_be32(&cm)));
            write_proof(&out, groth16::proof_hex(&proof), &publics)?;
        }

        Cmd::UnshieldProof {
            pk, n, k, v, index, leaves, recipient_field, amount, change_n, change_k, depth, seed, out,
        } => {
            let pk = groth16::pk_from_bytes(&fs::read(&pk)?)?;
            let (n, k) = (parse_fr(&n)?, parse_fr(&k)?);
            if amount > v {
                return Err(anyhow!("amount {amount} exceeds note value {v}"));
            }
            let note_in = Note::new(n, k, Fr::from(v));
            let leaf_frs = read_leaves(&leaves)?;
            if index >= leaf_frs.len() || leaf_frs[index] != note_in.commitment() {
                return Err(anyhow!("leaf at index {index} does not match this note"));
            }
            let (root, siblings, path_bits) = merkle::path(&leaf_frs, index, depth);
            let nf = note_in.nullifier();
            let recipient_fe = Fr::from_be_bytes_mod_order(&parse_bytes32(&recipient_field)?);
            let amount_fe = Fr::from(amount);
            let change = Note::new(parse_fr(&change_n)?, parse_fr(&change_k)?, Fr::from(v - amount));
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
            let proof = groth16::prove(&pk, circuit, seed)?;
            let publics = [root, nf, recipient_fe, amount_fe, change_cm];
            if !groth16::verify(&pk.vk, &publics, &proof) {
                return Err(anyhow!("internal error: proof failed to verify"));
            }
            println!("root       {}", hex0x(groth16::fr_be32(&root)));
            println!("change_cm  {}", hex0x(groth16::fr_be32(&change_cm)));
            write_proof(&out, groth16::proof_hex(&proof), &publics)?;
        }

        Cmd::TransferProof {
            pk, n, k, v, index, leaves, out1_n, out1_k, out1_v, out2_n, out2_k, out2_v,
            recipient_view, depth, seed, out,
        } => {
            let pk = groth16::pk_from_bytes(&fs::read(&pk)?)?;
            let note_in = Note::new(parse_fr(&n)?, parse_fr(&k)?, Fr::from(v));
            if out1_v + out2_v != v {
                return Err(anyhow!("outputs {out1_v}+{out2_v} must equal input {v}"));
            }
            let leaf_frs = read_leaves(&leaves)?;
            if index >= leaf_frs.len() || leaf_frs[index] != note_in.commitment() {
                return Err(anyhow!("leaf at index {index} does not match this note"));
            }
            let (root, siblings, path_bits) = merkle::path(&leaf_frs, index, depth);
            let nf = note_in.nullifier();
            let out1 = Note::new(parse_fr(&out1_n)?, parse_fr(&out1_k)?, Fr::from(out1_v));
            let out2 = Note::new(parse_fr(&out2_n)?, parse_fr(&out2_k)?, Fr::from(out2_v));

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
            let proof = groth16::prove(&pk, circuit, seed)?;
            let publics = [root, nf, out1.commitment(), out2.commitment()];
            if !groth16::verify(&pk.vk, &publics, &proof) {
                return Err(anyhow!("internal error: proof failed to verify"));
            }
            println!("root     {}", hex0x(groth16::fr_be32(&root)));
            println!("out_cm1  {}", hex0x(groth16::fr_be32(&out1.commitment())));
            println!("out_cm2  {}", hex0x(groth16::fr_be32(&out2.commitment())));
            if let Some(rv) = recipient_view {
                let blob = encrypt_note(&ViewingPubKey::from_bytes(parse_bytes32(&rv)?), &out1);
                println!("recipient_blob 0x{}", hex::encode(blob));
            }
            write_proof(&out, groth16::proof_hex(&proof), &publics)?;
        }

        Cmd::Encrypt { recipient_view, n, k, v } => {
            let recip = ViewingPubKey::from_bytes(parse_bytes32(&recipient_view)?);
            let note = Note::new(parse_fr(&n)?, parse_fr(&k)?, Fr::from(v));
            println!("0x{}", hex::encode(encrypt_note(&recip, &note)));
        }

        Cmd::Decrypt { view_secret, blob } => {
            let vk = ViewingKey::from_seed(parse_bytes32(&view_secret)?);
            let blob = hex::decode(blob.trim().strip_prefix("0x").unwrap_or(blob.trim()))?;
            let note = decrypt_note(&vk, &blob)?;
            println!("n 0x{}", hex::encode(groth16::fr_be32(&note.n)));
            println!("k 0x{}", hex::encode(groth16::fr_be32(&note.k)));
            println!("v {}", note.v);
        }
    }
    Ok(())
}
