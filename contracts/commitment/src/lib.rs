//! Hypertron Commitment & Note Engine
//!
//! An incremental Merkle tree of note commitments. A spender later proves, in
//! zero knowledge, that their note is a member of this tree without revealing
//! which leaf it is.
//!
//! The leaf hashing function is isolated in [`hash_pair`] so it can be swapped
//! for the circuit's hash. This scaffold uses keccak256 (always available in
//! the Soroban host); production swaps in Poseidon2 (CAP-0075) so on-chain
//! hashing matches the ZK circuit.
#![no_std]

use soroban_sdk::{
    contract, contractevent, contracterror, contractimpl, contracttype, Bytes, BytesN, Env, Vec,
};

/// Emitted when a note commitment is inserted into the tree.
#[contractevent]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitInserted {
    #[topic]
    pub index: u32,
    pub leaf: BytesN<32>,
    pub root: BytesN<32>,
}

/// Depth of the Merkle tree. 2^DEPTH available leaves.
const DEPTH: u32 = 20;
/// Number of historical roots retained so in-flight proofs stay valid.
const ROOT_HISTORY: u32 = 32;
/// Persistent storage TTL management (~30 day threshold, ~180 day bump).
const TTL_THRESHOLD: u32 = 518_400;
const TTL_BUMP: u32 = 3_110_400;

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotInitialized = 2,
    TreeFull = 3,
    DuplicateLeaf = 4,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    /// Address permitted to insert leaves (the transfer contract).
    Authority,
    /// Serialized tree state.
    State,
    /// Set membership: has this leaf been inserted?
    Leaf(BytesN<32>),
    /// Root history ring buffer entry.
    Root(u32),
}

#[contracttype]
#[derive(Clone)]
pub struct TreeState {
    pub next_index: u32,
    pub current_root_index: u32,
    /// Right-most filled node on each level (Tornado-style incremental tree).
    pub filled_subtrees: Vec<BytesN<32>>,
    /// Precomputed zero (empty) subtree hash for each level.
    pub zeros: Vec<BytesN<32>>,
    pub root: BytesN<32>,
    pub size: u32,
}

#[contract]
pub struct CommitmentContract;

#[contractimpl]
impl CommitmentContract {
    /// Initialize the tree. `authority` is the only address allowed to insert.
    pub fn initialize(env: Env, authority: soroban_sdk::Address) -> Result<(), Error> {
        if env.storage().instance().has(&Key::Authority) {
            return Err(Error::AlreadyInitialized);
        }

        // Build the zero-subtree hashes bottom-up from a domain-separated base.
        let base = env.crypto().keccak256(&Bytes::from_slice(&env, b"hypertron:empty-leaf"));
        let base: BytesN<32> = base.into();

        let mut zeros = Vec::new(&env);
        let mut filled = Vec::new(&env);
        let mut current = base.clone();
        let mut level = 0;
        while level < DEPTH {
            zeros.push_back(current.clone());
            filled.push_back(current.clone());
            current = hash_pair(&env, &current, &current);
            level += 1;
        }
        // `current` is now the root of a fully-empty tree.
        let root = current;

        let state = TreeState {
            next_index: 0,
            current_root_index: 0,
            filled_subtrees: filled,
            zeros,
            root: root.clone(),
            size: 0,
        };

        env.storage().instance().set(&Key::Authority, &authority);
        env.storage().instance().set(&Key::State, &state);
        env.storage().persistent().set(&Key::Root(0), &root);
        Ok(())
    }

    /// Insert a note commitment leaf. Returns its leaf index.
    /// Only the configured authority may call this.
    pub fn insert(env: Env, leaf: BytesN<32>) -> Result<u32, Error> {
        let authority: soroban_sdk::Address = env
            .storage()
            .instance()
            .get(&Key::Authority)
            .ok_or(Error::NotInitialized)?;
        authority.require_auth();

        if env.storage().persistent().has(&Key::Leaf(leaf.clone())) {
            return Err(Error::DuplicateLeaf);
        }

        let mut state: TreeState = env.storage().instance().get(&Key::State).unwrap();
        if state.next_index >= 2u32.pow(DEPTH) {
            return Err(Error::TreeFull);
        }

        let leaf_index = state.next_index;
        let mut current = leaf.clone();
        let mut index = leaf_index;
        let mut level = 0;
        while level < DEPTH {
            let (left, right) = if index % 2 == 0 {
                state.filled_subtrees.set(level, current.clone());
                (current.clone(), state.zeros.get(level).unwrap())
            } else {
                (state.filled_subtrees.get(level).unwrap(), current.clone())
            };
            current = hash_pair(&env, &left, &right);
            index /= 2;
            level += 1;
        }

        let new_root_index = (state.current_root_index + 1) % ROOT_HISTORY;
        state.current_root_index = new_root_index;
        state.root = current.clone();
        state.next_index = leaf_index + 1;
        state.size += 1;

        env.storage().persistent().set(&Key::Leaf(leaf.clone()), &true);
        env.storage().persistent().set(&Key::Root(new_root_index), &current);
        env.storage().instance().set(&Key::State, &state);

        env.storage()
            .persistent()
            .extend_ttl(&Key::Leaf(leaf.clone()), TTL_THRESHOLD, TTL_BUMP);

        CommitInserted {
            index: leaf_index,
            leaf,
            root: current,
        }
        .publish(&env);

        Ok(leaf_index)
    }

    /// Current Merkle root.
    pub fn root(env: Env) -> BytesN<32> {
        let state: TreeState = env.storage().instance().get(&Key::State).unwrap();
        state.root
    }

    /// Was `root` one of the last `ROOT_HISTORY` roots? Used by the verifier
    /// path to accept proofs built against a slightly stale root.
    pub fn is_known_root(env: Env, root: BytesN<32>) -> bool {
        let mut i = 0;
        while i < ROOT_HISTORY {
            if let Some(r) = env.storage().persistent().get::<Key, BytesN<32>>(&Key::Root(i)) {
                if r == root {
                    return true;
                }
            }
            i += 1;
        }
        false
    }

    /// Total number of leaves inserted.
    pub fn size(env: Env) -> u32 {
        let state: TreeState = env.storage().instance().get(&Key::State).unwrap();
        state.size
    }
}

/// Hash two child nodes into their parent. Swap point for Poseidon2 (CAP-0075).
fn hash_pair(env: &Env, left: &BytesN<32>, right: &BytesN<32>) -> BytesN<32> {
    let mut buf = Bytes::new(env);
    buf.append(&Bytes::from_array(env, &left.to_array()));
    buf.append(&Bytes::from_array(env, &right.to_array()));
    env.crypto().keccak256(&buf).into()
}

#[cfg(test)]
mod test;
