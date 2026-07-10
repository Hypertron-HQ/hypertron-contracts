//! Off-chain reconstruction of the incremental Merkle tree used by the
//! `hypertron-commitment` contract, so we can build the witness (root + path)
//! for a note we deposited earlier.

use ark_bls12_381::Fr;

use crate::poseidon::poseidon2to1;

/// note commitment `leaf = Poseidon(n, k)`.
pub fn leaf(n: Fr, k: Fr) -> Fr {
    poseidon2to1(n, k)
}

/// `nullifier_hash = Poseidon(n, 0)`.
pub fn nullifier(n: Fr) -> Fr {
    poseidon2to1(n, Fr::from(0u64))
}

/// Root of an empty subtree at each level: `zeros[0] = 0`,
/// `zeros[i+1] = Poseidon(zeros[i], zeros[i])`.
pub fn zeros(depth: usize) -> Vec<Fr> {
    let mut z = Vec::with_capacity(depth + 1);
    z.push(Fr::from(0u64));
    for i in 0..depth {
        let prev = z[i];
        z.push(poseidon2to1(prev, prev));
    }
    z
}

/// Reconstruct the root and the authentication path for the leaf at `index`,
/// given the ordered list of currently-inserted `leaves` (unfilled positions
/// are the empty leaf = 0). Mirrors the on-chain incremental tree exactly.
///
/// Returns `(root, siblings, path_bits)` where `path_bits[i] == true` means the
/// current node is the right child at level `i`.
pub fn path(leaves: &[Fr], index: usize, depth: usize) -> (Fr, Vec<Fr>, Vec<bool>) {
    let z = zeros(depth);
    let mut level: Vec<Fr> = leaves.to_vec();
    let mut idx = index;
    let mut siblings = Vec::with_capacity(depth);
    let mut path_bits = Vec::with_capacity(depth);

    for d in 0..depth {
        let zero = z[d];
        let sib_idx = idx ^ 1;
        let sib = level.get(sib_idx).copied().unwrap_or(zero);
        siblings.push(sib);
        path_bits.push(idx & 1 == 1);

        // Build the next level up, padding the missing right node with `zero`.
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let l = level[i];
            let r = level.get(i + 1).copied().unwrap_or(zero);
            next.push(poseidon2to1(l, r));
            i += 2;
        }
        if next.is_empty() {
            next.push(poseidon2to1(zero, zero));
        }
        level = next;
        idx /= 2;
    }

    (level[0], siblings, path_bits)
}
