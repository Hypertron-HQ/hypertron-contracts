//! `hypertron-prove` — off-chain prover + selective-disclosure CLI for the
//! Hypertron shielded pool.
//!
//! Circuits (each needs its own verifying key registered on-chain once):
//!   - `deposit`   : bind a public shield amount to a note commitment
//!   - `unshield`  : exit to a public recipient, keeping a change note
//!   - `transfer`  : fully-private 1-in / 2-out (no public address/amount)
//!   - `transfer-2`: fully-private 2-in / 2-out
//!   - `transfer-4`: fully-private 4-in / 2-out
//!
//! Typical flows:
//!   hypertron-prove setup --circuit unshield        -> pk.bin + vk.json
//!   hypertron-prove commitment --owner-pk .. --k .. --v ..  -> leaf to deposit
//!   hypertron-prove deposit-proof ...                -> proof for `deposit`
//!   hypertron-prove unshield-proof ...               -> proof for `unshield`
//!   hypertron-prove transfer-proof ...               -> proof + recipient blob
//!   hypertron-prove keygen                           -> viewing keypair
//!   hypertron-prove decrypt --view-secret .. --blob ..  -> scan/audit a note

use std::fs;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use ark_ff::PrimeField;
use ark_std::rand::{CryptoRng, RngCore};
use clap::{Parser, Subcommand, ValueEnum};
use rand_core::OsRng;

use hypertron_prover::circuit::{
    DepositCircuit, Transfer2Circuit, Transfer4Circuit, TransferCircuit, TransferInput,
    TransferNCircuit, UnshieldCircuit,
};
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
    #[value(name = "transfer-2")]
    Transfer2,
    #[value(name = "transfer-4")]
    Transfer4,
}

#[derive(Subcommand)]
enum Cmd {
    /// Groth16 setup for one circuit: writes a proving key and a vk JSON.
    ///
    /// Draws setup randomness from the OS CSPRNG. This is a single-coordinator
    /// setup, not a multi-party ceremony: whoever runs it could retain the toxic
    /// waste. Production requires the ceremony in `docs/CEREMONY.md`.
    Setup {
        #[arg(long, value_enum)]
        circuit: Circuit,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        /// DEV ONLY. Derive setup randomness from a fixed 64-bit seed, producing
        /// keys whose toxic waste anyone can recover and whose proofs anyone can
        /// forge. Requires HYPERTRON_INSECURE_DEV_SETUP=1.
        #[arg(long)]
        insecure_dev_seed: Option<u64>,
        #[arg(long, default_value = "pk.bin")]
        pk_out: PathBuf,
        #[arg(long, default_value = "vk.json")]
        vk_out: PathBuf,
    },
    /// Build a valid proof over a synthetic witness, for checking a deployment.
    ///
    /// Feed the output to the on-chain verifier: if it returns true, the key
    /// registered under that vk_id really is the one this proving key belongs
    /// to. A Groth16 pairing check cannot pass against an unrelated key, so
    /// this confirms the deployment without trusting any published hash.
    SelfTest {
        #[arg(long, value_enum)]
        circuit: Circuit,
        #[arg(long)]
        pk: PathBuf,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value = "self-test-proof.json")]
        out: PathBuf,
    },
    /// Compute a note commitment `cm = Poseidon(Poseidon(owner_pk, k), v)`.
    Commitment {
        /// Owner public key (`Poseidon(spend_sk, 0)`). Alias: `--n`.
        #[arg(long = "owner-pk", visible_alias = "n")]
        owner_pk: String,
        #[arg(long)]
        k: String,
        #[arg(long)]
        v: u128,
    },
    /// Compute `nullifier = Poseidon(spend_sk, k)`.
    Nullifier {
        #[arg(long)]
        spend_sk: String,
        #[arg(long)]
        k: String,
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
        /// Owner public key for the deposited note. Alias: `--n`.
        #[arg(long = "owner-pk", visible_alias = "n")]
        owner_pk: String,
        #[arg(long)]
        k: String,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value = "deposit-proof.json")]
        out: PathBuf,
    },
    /// Prove an unshield. Public: [root, nullifier, recipient, amount, change_cm].
    UnshieldProof {
        #[arg(long)]
        pk: PathBuf,
        /// Spend secret key for the input note (and change note, same owner).
        #[arg(long)]
        spend_sk: String,
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
        /// Blinding for the change note (same owner as input).
        #[arg(long)]
        change_k: String,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value = "unshield-proof.json")]
        out: PathBuf,
    },
    /// Prove a fully-private transfer. Public: [root, nullifier, out_cm1, out_cm2].
    TransferProof {
        #[arg(long)]
        pk: PathBuf,
        /// Spend secret key for the input note.
        #[arg(long)]
        spend_sk: String,
        #[arg(long)]
        k: String,
        #[arg(long)]
        v: u128,
        #[arg(long)]
        index: usize,
        #[arg(long)]
        leaves: PathBuf,
        /// Output note 1 owner_pk (recipient). Alias: `--out1-n`.
        #[arg(long = "out1-owner-pk", visible_alias = "out1-n")]
        out1_owner_pk: String,
        #[arg(long)]
        out1_k: String,
        #[arg(long)]
        out1_v: u128,
        /// Output note 2 owner_pk (change). Alias: `--out2-n`.
        #[arg(long = "out2-owner-pk", visible_alias = "out2-n")]
        out2_owner_pk: String,
        #[arg(long)]
        out2_k: String,
        #[arg(long)]
        out2_v: u128,
        /// Optional recipient viewing pubkey (hex) to also emit an encrypted blob.
        #[arg(long)]
        recipient_view: Option<String>,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value = "transfer-proof.json")]
        out: PathBuf,
    },
    /// Prove a 2-in / 2-out private transfer. Repeat `--k`/`--v`/`--index` twice.
    Transfer2Proof {
        #[arg(long)]
        pk: PathBuf,
        #[arg(long)]
        spend_sk: String,
        #[arg(long, required = true)]
        k: Vec<String>,
        #[arg(long, required = true)]
        v: Vec<u128>,
        #[arg(long, required = true)]
        index: Vec<usize>,
        #[arg(long)]
        leaves: PathBuf,
        #[arg(long = "out1-owner-pk", visible_alias = "out1-n")]
        out1_owner_pk: String,
        #[arg(long)]
        out1_k: String,
        #[arg(long)]
        out1_v: u128,
        #[arg(long = "out2-owner-pk", visible_alias = "out2-n")]
        out2_owner_pk: String,
        #[arg(long)]
        out2_k: String,
        #[arg(long)]
        out2_v: u128,
        #[arg(long)]
        recipient_view: Option<String>,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value = "transfer-2-proof.json")]
        out: PathBuf,
    },
    /// Prove a 4-in / 2-out private transfer. Repeat `--k`/`--v`/`--index` four times.
    Transfer4Proof {
        #[arg(long)]
        pk: PathBuf,
        #[arg(long)]
        spend_sk: String,
        #[arg(long, required = true)]
        k: Vec<String>,
        #[arg(long, required = true)]
        v: Vec<u128>,
        #[arg(long, required = true)]
        index: Vec<usize>,
        #[arg(long)]
        leaves: PathBuf,
        #[arg(long = "out1-owner-pk", visible_alias = "out1-n")]
        out1_owner_pk: String,
        #[arg(long)]
        out1_k: String,
        #[arg(long)]
        out1_v: u128,
        #[arg(long = "out2-owner-pk", visible_alias = "out2-n")]
        out2_owner_pk: String,
        #[arg(long)]
        out2_k: String,
        #[arg(long)]
        out2_v: u128,
        #[arg(long)]
        recipient_view: Option<String>,
        #[arg(long, default_value_t = 20)]
        depth: usize,
        #[arg(long, default_value = "transfer-4-proof.json")]
        out: PathBuf,
    },
    /// Encrypt a note to a recipient's viewing pubkey -> on-chain blob (hex).
    Encrypt {
        #[arg(long)]
        recipient_view: String,
        /// Owner public key. Alias: `--n`.
        #[arg(long = "owner-pk", visible_alias = "n")]
        owner_pk: String,
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
    /// Convert a `vk.json` (from `setup`) into the on-chain `register_vk` struct
    /// argument and print a ready-to-run `stellar contract invoke` command.
    RegisterVkArgs {
        /// Path to the verifying-key JSON emitted by `setup`.
        #[arg(long)]
        vk: PathBuf,
        /// The id to register this key under (deposit=1, unshield=2, transfer=3,
        /// transfer-2=4, transfer-4=5).
        #[arg(long)]
        vk_id: u32,
        /// Verifier contract id. If set, also prints the full invoke command.
        #[arg(long)]
        verifier: Option<String>,
        /// stellar keys identity used as `--source` in the printed command.
        #[arg(long, default_value = "hypertron")]
        source: String,
        /// Network passed as `--network` in the printed command.
        #[arg(long, default_value = "testnet")]
        network: String,
        /// Print ONLY the single-line struct JSON (for scripting / capture).
        #[arg(long)]
        compact: bool,
    },
}

/// Validate that a hex string decodes to exactly `want_bytes` bytes.
fn check_hex_len(name: &str, hex_str: &str, want_bytes: usize) -> Result<()> {
    let s = hex_str.trim().strip_prefix("0x").unwrap_or_else(|| hex_str.trim());
    hex::decode(s).map_err(|e| anyhow!("{name}: invalid hex: {e}"))?;
    let got = s.len() / 2;
    if s.len() % 2 != 0 || got != want_bytes {
        return Err(anyhow!(
            "{name}: expected {want_bytes} bytes ({} hex chars), got {} chars",
            want_bytes * 2,
            s.len()
        ));
    }
    Ok(())
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

/// Setup dispatch over the circuit enum, generic in the RNG so the caller
/// chooses between OS entropy and an explicit development seed.
fn setup_circuit<R: RngCore + CryptoRng>(
    circuit: Circuit,
    depth: usize,
    rng: &mut R,
) -> Result<groth16::Keys> {
    Ok(match circuit {
        Circuit::Deposit => groth16::setup(DepositCircuit::empty(), rng)?,
        Circuit::Unshield => groth16::setup(UnshieldCircuit::empty(depth), rng)?,
        Circuit::Transfer => groth16::setup(TransferCircuit::empty(depth), rng)?,
        Circuit::Transfer2 => groth16::setup(Transfer2Circuit::empty(depth), rng)?,
        Circuit::Transfer4 => groth16::setup(Transfer4Circuit::empty(depth), rng)?,
    })
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

fn self_test_transfer_n<const N: usize>(
    pk: &ark_groth16::ProvingKey<ark_bls12_381::Bls12_381>,
    spend_sk: Fr,
    depth: usize,
) -> Result<(ark_groth16::Proof<ark_bls12_381::Bls12_381>, Vec<Fr>)> {
    let notes: Vec<Note> = (0..N)
        .map(|i| {
            Note::from_spend_key(
                spend_sk,
                Fr::from(1 + i as u64),
                Fr::from(100u64 * (i as u64 + 1)),
            )
        })
        .collect();
    let leaves: Vec<Fr> = notes.iter().map(|n| n.commitment()).collect();
    let sum_v: u64 = (0..N).map(|i| 100 * (i as u64 + 1)).sum();
    let mut inputs: [TransferInput; N] =
        core::array::from_fn(|_| TransferInput::empty(depth));
    let mut publics = vec![merkle::path(&leaves, 0, depth).0];
    for i in 0..N {
        let (root, siblings, path_bits) = merkle::path(&leaves, i, depth);
        assert_eq!(root, publics[0]);
        let nf = notes[i].nullifier(spend_sk);
        publics.push(nf);
        inputs[i] = TransferInput {
            k: Some(notes[i].k),
            v: Some(notes[i].v),
            nullifier: Some(nf),
            siblings: siblings.into_iter().map(Some).collect(),
            path_bits: path_bits.into_iter().map(Some).collect(),
        };
    }
    let out1 = Note::new(Fr::from(101u64), Fr::from(102u64), Fr::from(sum_v - 7));
    let out2 = Note::new(Fr::from(201u64), Fr::from(202u64), Fr::from(7u64));
    publics.push(out1.commitment());
    publics.push(out2.commitment());
    let circuit = TransferNCircuit::<N> {
        root: Some(publics[0]),
        out_cm1: Some(out1.commitment()),
        out_cm2: Some(out2.commitment()),
        spend_sk: Some(spend_sk),
        inputs,
        owner_pk1: Some(out1.owner_pk),
        k1: Some(out1.k),
        v1: Some(out1.v),
        owner_pk2: Some(out2.owner_pk),
        k2: Some(out2.k),
        v2: Some(out2.v),
    };
    let p = groth16::prove(pk, circuit, &mut OsRng)?;
    Ok((p, publics))
}

fn prove_transfer_n<const N: usize>(
    pk: PathBuf,
    spend_sk: String,
    k: Vec<String>,
    v: Vec<u128>,
    index: Vec<usize>,
    leaves: PathBuf,
    out1_owner_pk: String,
    out1_k: String,
    out1_v: u128,
    out2_owner_pk: String,
    out2_k: String,
    out2_v: u128,
    recipient_view: Option<String>,
    depth: usize,
    out: PathBuf,
) -> Result<()> {
    if k.len() != N || v.len() != N || index.len() != N {
        return Err(anyhow!(
            "expected {N} --k, --v, and --index values, got k={} v={} index={}",
            k.len(),
            v.len(),
            index.len()
        ));
    }
    let in_sum: u128 = v.iter().sum();
    if out1_v + out2_v != in_sum {
        return Err(anyhow!(
            "outputs {out1_v}+{out2_v} must equal input sum {in_sum}"
        ));
    }
    let pk = groth16::pk_from_bytes(&fs::read(&pk)?)?;
    let spend_sk = parse_fr(&spend_sk)?;
    let leaf_frs = read_leaves(&leaves)?;
    let mut notes = Vec::with_capacity(N);
    for i in 0..N {
        notes.push(Note::from_spend_key(
            spend_sk,
            parse_fr(&k[i])?,
            Fr::from(v[i]),
        ));
        if index[i] >= leaf_frs.len() || leaf_frs[index[i]] != notes[i].commitment() {
            return Err(anyhow!(
                "leaf at index {} does not match input {}",
                index[i],
                i
            ));
        }
    }
    let mut inputs: [TransferInput; N] =
        core::array::from_fn(|_| TransferInput::empty(depth));
    let mut publics = Vec::new();
    let mut nfs = Vec::new();
    for i in 0..N {
        let (root, siblings, path_bits) = merkle::path(&leaf_frs, index[i], depth);
        if i == 0 {
            publics.push(root);
        } else if publics[0] != root {
            return Err(anyhow!("inputs do not share a Merkle root"));
        }
        let nf = notes[i].nullifier(spend_sk);
        nfs.push(nf);
        inputs[i] = TransferInput {
            k: Some(notes[i].k),
            v: Some(notes[i].v),
            nullifier: Some(nf),
            siblings: siblings.into_iter().map(Some).collect(),
            path_bits: path_bits.into_iter().map(Some).collect(),
        };
    }
    let out1 = Note::new(parse_fr(&out1_owner_pk)?, parse_fr(&out1_k)?, Fr::from(out1_v));
    let out2 = Note::new(parse_fr(&out2_owner_pk)?, parse_fr(&out2_k)?, Fr::from(out2_v));
    publics.extend(nfs.iter().copied());
    publics.push(out1.commitment());
    publics.push(out2.commitment());
    let circuit = TransferNCircuit::<N> {
        root: Some(publics[0]),
        out_cm1: Some(out1.commitment()),
        out_cm2: Some(out2.commitment()),
        spend_sk: Some(spend_sk),
        inputs,
        owner_pk1: Some(out1.owner_pk),
        k1: Some(out1.k),
        v1: Some(out1.v),
        owner_pk2: Some(out2.owner_pk),
        k2: Some(out2.k),
        v2: Some(out2.v),
    };
    let proof = groth16::prove(&pk, circuit, &mut OsRng)?;
    if !groth16::verify(&pk.vk, &publics, &proof) {
        return Err(anyhow!("internal error: proof failed to verify"));
    }
    println!("root     {}", hex0x(groth16::fr_be32(&publics[0])));
    for (i, nf) in nfs.iter().enumerate() {
        println!("nf_{}     {}", i + 1, hex0x(groth16::fr_be32(nf)));
    }
    println!("out_cm1  {}", hex0x(groth16::fr_be32(&out1.commitment())));
    println!("out_cm2  {}", hex0x(groth16::fr_be32(&out2.commitment())));
    if let Some(rv) = recipient_view {
        let blob = encrypt_note(&ViewingPubKey::from_bytes(parse_bytes32(&rv)?), &out1);
        println!("recipient_blob 0x{}", hex::encode(blob));
    }
    write_proof(&out, groth16::proof_hex(&proof), &publics)?;
    Ok(())
}

fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Setup { circuit, depth, insecure_dev_seed, pk_out, vk_out } => {
            let (pk, vk) = match insecure_dev_seed {
                Some(seed) => {
                    if std::env::var("HYPERTRON_INSECURE_DEV_SETUP").as_deref() != Ok("1") {
                        return Err(anyhow!(
                            "--insecure-dev-seed produces keys whose toxic waste anyone can \
                             recover; set HYPERTRON_INSECURE_DEV_SETUP=1 to confirm"
                        ));
                    }
                    eprintln!(
                        "WARNING: insecure development setup (seed={seed}). The toxic waste is \
                         publicly recoverable and proofs under these keys are forgeable. Never \
                         use them to secure value."
                    );
                    setup_circuit(circuit, depth, &mut groth16::insecure_dev_rng(seed))?
                }
                None => {
                    eprintln!(
                        "note: single-coordinator setup from OS entropy. This is not a \
                         multi-party ceremony — whoever runs it could retain the toxic waste. \
                         See docs/CEREMONY.md."
                    );
                    setup_circuit(circuit, depth, &mut OsRng)?
                }
            };
            fs::write(&pk_out, groth16::pk_to_bytes(&pk)?)
                .with_context(|| format!("writing {}", pk_out.display()))?;
            let mut vk_json_value = groth16::vk_json(&vk);
            vk_json_value.insecure_dev_seed = insecure_dev_seed;
            let vk_json = serde_json::to_string_pretty(&vk_json_value)?;
            fs::write(&vk_out, &vk_json).with_context(|| format!("writing {}", vk_out.display()))?;
            println!("proving key   -> {}", pk_out.display());
            println!("verifying key -> {} (register on-chain)", vk_out.display());
            println!("{vk_json}");
        }

        Cmd::SelfTest { circuit, pk, depth, out } => {
            let pk = groth16::pk_from_bytes(&fs::read(&pk)?)?;
            // Any self-consistent witness proves the point; these values are
            // arbitrary and correspond to no real note.
            let spend_sk = Fr::from(20260815u64);
            let input = Note::from_spend_key(spend_sk, Fr::from(1u64), Fr::from(1000u64));
            let (root, siblings, path_bits) = merkle::path(&[input.commitment()], 0, depth);
            let nf = input.nullifier(spend_sk);

            let (proof, publics) = match circuit {
                Circuit::Deposit => {
                    let c = DepositCircuit {
                        cm: Some(input.commitment()),
                        amount: Some(input.v),
                        owner_pk: Some(input.owner_pk),
                        k: Some(input.k),
                    };
                    let p = groth16::prove(&pk, c, &mut OsRng)?;
                    (p, vec![input.commitment(), input.v])
                }
                Circuit::Unshield => {
                    let recipient = Fr::from(0xC0FFEEu64);
                    let amount = Fr::from(700u64);
                    let change = Note::from_spend_key(spend_sk, Fr::from(2u64), Fr::from(300u64));
                    let c = UnshieldCircuit {
                        root: Some(root),
                        nullifier: Some(nf),
                        recipient: Some(recipient),
                        amount: Some(amount),
                        change_cm: Some(change.commitment()),
                        spend_sk: Some(spend_sk),
                        k: Some(input.k),
                        v: Some(input.v),
                        siblings: siblings.into_iter().map(Some).collect(),
                        path_bits: path_bits.into_iter().map(Some).collect(),
                        k2: Some(change.k),
                        vc: Some(change.v),
                    };
                    let p = groth16::prove(&pk, c, &mut OsRng)?;
                    (p, vec![root, nf, recipient, amount, change.commitment()])
                }
                Circuit::Transfer => {
                    let out1 = Note::new(Fr::from(101u64), Fr::from(102u64), Fr::from(600u64));
                    let out2 = Note::new(Fr::from(201u64), Fr::from(202u64), Fr::from(400u64));
                    let c = TransferCircuit {
                        root: Some(root),
                        nullifier: Some(nf),
                        out_cm1: Some(out1.commitment()),
                        out_cm2: Some(out2.commitment()),
                        spend_sk: Some(spend_sk),
                        k: Some(input.k),
                        v: Some(input.v),
                        siblings: siblings.into_iter().map(Some).collect(),
                        path_bits: path_bits.into_iter().map(Some).collect(),
                        owner_pk1: Some(out1.owner_pk),
                        k1: Some(out1.k),
                        v1: Some(out1.v),
                        owner_pk2: Some(out2.owner_pk),
                        k2: Some(out2.k),
                        v2: Some(out2.v),
                    };
                    let p = groth16::prove(&pk, c, &mut OsRng)?;
                    (p, vec![root, nf, out1.commitment(), out2.commitment()])
                }
                Circuit::Transfer2 => self_test_transfer_n::<2>(&pk, spend_sk, depth)?,
                Circuit::Transfer4 => self_test_transfer_n::<4>(&pk, spend_sk, depth)?,
            };

            if !groth16::verify(&pk.vk, &publics, &proof) {
                return Err(anyhow!("internal error: self-test proof failed to verify"));
            }
            write_proof(&out, groth16::proof_hex(&proof), &publics)?;
        }

        Cmd::Commitment { owner_pk, k, v } => {
            let cm = note::commitment(parse_fr(&owner_pk)?, parse_fr(&k)?, Fr::from(v));
            println!("{}", hex0x(groth16::fr_be32(&cm)));
        }

        Cmd::Nullifier { spend_sk, k } => {
            let nf = note::nullifier(parse_fr(&spend_sk)?, parse_fr(&k)?);
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

        Cmd::DepositProof { pk, owner_pk, k, amount, out } => {
            let pk = groth16::pk_from_bytes(&fs::read(&pk)?)?;
            let (owner_pk, k) = (parse_fr(&owner_pk)?, parse_fr(&k)?);
            let amount_fe = Fr::from(amount);
            let cm = note::commitment(owner_pk, k, amount_fe);
            let circuit = DepositCircuit {
                cm: Some(cm),
                amount: Some(amount_fe),
                owner_pk: Some(owner_pk),
                k: Some(k),
            };
            let proof = groth16::prove(&pk, circuit, &mut OsRng)?;
            let publics = [cm, amount_fe];
            if !groth16::verify(&pk.vk, &publics, &proof) {
                return Err(anyhow!("internal error: proof failed to verify"));
            }
            println!("commitment {}", hex0x(groth16::fr_be32(&cm)));
            write_proof(&out, groth16::proof_hex(&proof), &publics)?;
        }

        Cmd::UnshieldProof {
            pk, spend_sk, k, v, index, leaves, recipient_field, amount, change_k, depth, out,
        } => {
            let pk = groth16::pk_from_bytes(&fs::read(&pk)?)?;
            let spend_sk = parse_fr(&spend_sk)?;
            let k = parse_fr(&k)?;
            if amount > v {
                return Err(anyhow!("amount {amount} exceeds note value {v}"));
            }
            let note_in = Note::from_spend_key(spend_sk, k, Fr::from(v));
            let leaf_frs = read_leaves(&leaves)?;
            if index >= leaf_frs.len() || leaf_frs[index] != note_in.commitment() {
                return Err(anyhow!("leaf at index {index} does not match this note"));
            }
            let (root, siblings, path_bits) = merkle::path(&leaf_frs, index, depth);
            let nf = note_in.nullifier(spend_sk);
            let recipient_fe = Fr::from_be_bytes_mod_order(&parse_bytes32(&recipient_field)?);
            let amount_fe = Fr::from(amount);
            let change =
                Note::from_spend_key(spend_sk, parse_fr(&change_k)?, Fr::from(v - amount));
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
            let proof = groth16::prove(&pk, circuit, &mut OsRng)?;
            let publics = [root, nf, recipient_fe, amount_fe, change_cm];
            if !groth16::verify(&pk.vk, &publics, &proof) {
                return Err(anyhow!("internal error: proof failed to verify"));
            }
            println!("root       {}", hex0x(groth16::fr_be32(&root)));
            println!("change_cm  {}", hex0x(groth16::fr_be32(&change_cm)));
            write_proof(&out, groth16::proof_hex(&proof), &publics)?;
        }

        Cmd::TransferProof {
            pk,
            spend_sk,
            k,
            v,
            index,
            leaves,
            out1_owner_pk,
            out1_k,
            out1_v,
            out2_owner_pk,
            out2_k,
            out2_v,
            recipient_view,
            depth,
            out,
        } => {
            let pk = groth16::pk_from_bytes(&fs::read(&pk)?)?;
            let spend_sk = parse_fr(&spend_sk)?;
            let note_in = Note::from_spend_key(spend_sk, parse_fr(&k)?, Fr::from(v));
            if out1_v + out2_v != v {
                return Err(anyhow!("outputs {out1_v}+{out2_v} must equal input {v}"));
            }
            let leaf_frs = read_leaves(&leaves)?;
            if index >= leaf_frs.len() || leaf_frs[index] != note_in.commitment() {
                return Err(anyhow!("leaf at index {index} does not match this note"));
            }
            let (root, siblings, path_bits) = merkle::path(&leaf_frs, index, depth);
            let nf = note_in.nullifier(spend_sk);
            let out1 = Note::new(parse_fr(&out1_owner_pk)?, parse_fr(&out1_k)?, Fr::from(out1_v));
            let out2 = Note::new(parse_fr(&out2_owner_pk)?, parse_fr(&out2_k)?, Fr::from(out2_v));

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
            let proof = groth16::prove(&pk, circuit, &mut OsRng)?;
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

        Cmd::Transfer2Proof {
            pk,
            spend_sk,
            k,
            v,
            index,
            leaves,
            out1_owner_pk,
            out1_k,
            out1_v,
            out2_owner_pk,
            out2_k,
            out2_v,
            recipient_view,
            depth,
            out,
        } => {
            prove_transfer_n::<2>(
                pk,
                spend_sk,
                k,
                v,
                index,
                leaves,
                out1_owner_pk,
                out1_k,
                out1_v,
                out2_owner_pk,
                out2_k,
                out2_v,
                recipient_view,
                depth,
                out,
            )?;
        }

        Cmd::Transfer4Proof {
            pk,
            spend_sk,
            k,
            v,
            index,
            leaves,
            out1_owner_pk,
            out1_k,
            out1_v,
            out2_owner_pk,
            out2_k,
            out2_v,
            recipient_view,
            depth,
            out,
        } => {
            prove_transfer_n::<4>(
                pk,
                spend_sk,
                k,
                v,
                index,
                leaves,
                out1_owner_pk,
                out1_k,
                out1_v,
                out2_owner_pk,
                out2_k,
                out2_v,
                recipient_view,
                depth,
                out,
            )?;
        }

        Cmd::Encrypt { recipient_view, owner_pk, k, v } => {
            let recip = ViewingPubKey::from_bytes(parse_bytes32(&recipient_view)?);
            let note = Note::new(parse_fr(&owner_pk)?, parse_fr(&k)?, Fr::from(v));
            println!("0x{}", hex::encode(encrypt_note(&recip, &note)));
        }

        Cmd::Decrypt { view_secret, blob } => {
            let vk = ViewingKey::from_seed(parse_bytes32(&view_secret)?);
            let blob = hex::decode(blob.trim().strip_prefix("0x").unwrap_or(blob.trim()))?;
            let note = decrypt_note(&vk, &blob)?;
            println!("owner_pk 0x{}", hex::encode(groth16::fr_be32(&note.owner_pk)));
            println!("k 0x{}", hex::encode(groth16::fr_be32(&note.k)));
            println!("v {}", note.v);
        }

        Cmd::RegisterVkArgs { vk, vk_id, verifier, source, network, compact } => {
            let text = fs::read_to_string(&vk).with_context(|| format!("reading {}", vk.display()))?;
            let vkj: groth16::VkJson = serde_json::from_str(&text)
                .with_context(|| format!("parsing {} as a vk.json", vk.display()))?;

            // On-chain layout: alpha/ic = uncompressed G1 (96 bytes),
            // beta/gamma/delta = uncompressed G2 (192 bytes).
            check_hex_len("alpha", &vkj.alpha, 96)?;
            check_hex_len("beta", &vkj.beta, 192)?;
            check_hex_len("gamma", &vkj.gamma, 192)?;
            check_hex_len("delta", &vkj.delta, 192)?;
            if vkj.ic.is_empty() {
                return Err(anyhow!("vk.ic must have at least one element (constant term)"));
            }
            for (i, p) in vkj.ic.iter().enumerate() {
                check_hex_len(&format!("ic[{i}]"), p, 96)?;
            }

            // The stellar CLI encodes a struct arg as JSON, with `BytesN` fields as
            // hex strings and `Vec` as a JSON array — so the on-chain VerifyingKey
            // struct has the exact same shape as `vk.json`.
            let arg = serde_json::json!({
                "alpha": vkj.alpha,
                "beta": vkj.beta,
                "gamma": vkj.gamma,
                "delta": vkj.delta,
                "ic": vkj.ic,
            });

            if compact {
                // Machine-readable: just the arg, so callers can capture it.
                println!("{}", serde_json::to_string(&arg)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&arg)?);
                if let Some(v) = verifier {
                    let arg_str = serde_json::to_string(&arg)?;
                    println!();
                    println!(
                        "stellar contract invoke --id {v} --source {source} --network {network} -- \\\n  \
                         register_vk --vk_id {vk_id} --vk '{arg_str}'"
                    );
                }
            }
        }
    }
    Ok(())
}
