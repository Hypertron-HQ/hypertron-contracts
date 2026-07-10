//! `hypertron-prove` — off-chain prover CLI for the Hypertron shielded pool.
//!
//! Typical flow for an integrator:
//!   1. `hypertron-prove setup`                → pk.bin + vk.json (register vk.json on-chain once)
//!   2. `hypertron-prove leaf --n .. --k ..`   → the commitment to `deposit`
//!   3. ...deposit on-chain, then collect the ordered list of tree leaves...
//!   4. `hypertron-prove prove ...`            → proof.json for `transfer.withdraw`

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use hypertron_prover::circuit::MembershipCircuit;
use hypertron_prover::groth16;
use hypertron_prover::{merkle, parse_bytes32, parse_fr, Fr};
use ark_ff::PrimeField;

#[derive(Parser)]
#[command(
    name = "hypertron-prove",
    about = "Off-chain Groth16 prover for the Hypertron shielded pool",
    version
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Groth16 setup: writes a proving key and a verifying-key JSON.
    ///
    /// This is a LOCAL, deterministic setup for dev/test. Production requires a
    /// proper multi-party trusted-setup ceremony.
    Setup {
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value = "pk.bin")]
        pk_out: PathBuf,
        #[arg(long, default_value = "vk.json")]
        vk_out: PathBuf,
    },
    /// Compute a note commitment `leaf = Poseidon(n, k)` (the value to deposit).
    Leaf {
        #[arg(long)]
        n: String,
        #[arg(long)]
        k: String,
    },
    /// Compute `nullifier_hash = Poseidon(n, 0)`.
    Nullifier {
        #[arg(long)]
        n: String,
    },
    /// Produce a withdrawal proof bound to (root, nullifier, recipient, amount).
    Prove {
        /// Proving key produced by `setup`.
        #[arg(long)]
        pk: PathBuf,
        /// Note secret `n`.
        #[arg(long)]
        n: String,
        /// Note secret `k`.
        #[arg(long)]
        k: String,
        /// Index of this note's leaf in the tree (insertion order).
        #[arg(long)]
        index: usize,
        /// File with one hex leaf per line, in insertion order (current tree state).
        #[arg(long)]
        leaves: PathBuf,
        /// Recipient field element = sha256(xdr(address)), 32-byte hex.
        #[arg(long)]
        recipient_field: String,
        /// Withdrawal amount (must match the on-chain `amount` argument).
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
        #[arg(long, default_value = "proof.json")]
        out: PathBuf,
    },
}

fn hex0x(bytes: [u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Setup {
            depth,
            seed,
            pk_out,
            vk_out,
        } => {
            eprintln!(
                "warning: local deterministic setup (seed={seed}). Production needs a real \
                 multi-party trusted-setup ceremony."
            );
            let (pk, vk) = groth16::setup(depth, seed)?;
            fs::write(&pk_out, groth16::pk_to_bytes(&pk)?)
                .with_context(|| format!("writing {}", pk_out.display()))?;
            let vk_json = serde_json::to_string_pretty(&groth16::vk_json(&vk))?;
            fs::write(&vk_out, &vk_json).with_context(|| format!("writing {}", vk_out.display()))?;
            println!("proving key  -> {}", pk_out.display());
            println!("verifying key -> {} (register this on-chain)", vk_out.display());
            println!("{vk_json}");
        }

        Cmd::Leaf { n, k } => {
            let leaf = merkle::leaf(parse_fr(&n)?, parse_fr(&k)?);
            println!("{}", hex0x(groth16::fr_be32(&leaf)));
        }

        Cmd::Nullifier { n } => {
            let nf = merkle::nullifier(parse_fr(&n)?);
            println!("{}", hex0x(groth16::fr_be32(&nf)));
        }

        Cmd::Prove {
            pk,
            n,
            k,
            index,
            leaves,
            recipient_field,
            amount,
            depth,
            seed,
            out,
        } => {
            let pk = groth16::pk_from_bytes(
                &fs::read(&pk).with_context(|| format!("reading {}", pk.display()))?,
            )?;
            let n = parse_fr(&n)?;
            let k = parse_fr(&k)?;

            let leaves_text =
                fs::read_to_string(&leaves).with_context(|| format!("reading {}", leaves.display()))?;
            let leaf_frs: Vec<Fr> = leaves_text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(|l| parse_bytes32(l).map(|b| Fr::from_be_bytes_mod_order(&b)))
                .collect::<Result<_>>()?;

            if index >= leaf_frs.len() {
                return Err(anyhow!(
                    "index {index} out of range ({} leaves provided)",
                    leaf_frs.len()
                ));
            }
            let expected_leaf = merkle::leaf(n, k);
            if leaf_frs[index] != expected_leaf {
                return Err(anyhow!(
                    "leaf at index {index} does not match Poseidon(n, k); wrong note or index"
                ));
            }

            let (root, siblings, path_bits) = merkle::path(&leaf_frs, index, depth);
            let nullifier_hash = merkle::nullifier(n);
            let recipient_fe = Fr::from_be_bytes_mod_order(&parse_bytes32(&recipient_field)?);
            let amount_fe = groth16::amount_fr(amount);

            let circuit = MembershipCircuit {
                root: Some(root),
                nullifier_hash: Some(nullifier_hash),
                recipient: Some(recipient_fe),
                amount: Some(amount_fe),
                n: Some(n),
                k: Some(k),
                siblings: siblings.into_iter().map(Some).collect(),
                path_bits: path_bits.into_iter().map(Some).collect(),
            };

            let proof = groth16::prove(&pk, circuit, seed)?;

            // Sanity: it must verify off-chain before we hand it out.
            let publics = [root, nullifier_hash, recipient_fe, amount_fe];
            if !groth16::verify(&pk.vk, &publics, &proof) {
                return Err(anyhow!("internal error: generated proof failed to verify"));
            }

            let proof_json = groth16::ProofJson {
                proof: format!("0x{}", groth16::proof_hex(&proof)),
                public_inputs: publics.iter().map(|f| hex0x(groth16::fr_be32(f))).collect(),
            };
            let text = serde_json::to_string_pretty(&proof_json)?;
            fs::write(&out, &text).with_context(|| format!("writing {}", out.display()))?;
            println!("proof -> {} (root = {})", out.display(), hex0x(groth16::fr_be32(&root)));
            println!("{text}");
        }
    }
    Ok(())
}
