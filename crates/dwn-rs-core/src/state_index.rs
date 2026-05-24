use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::sync::{Arc, OnceLock, RwLock};

use k256::sha2::{Digest, Sha256};

use crate::errors::{lock_error, StoreError};
use crate::stores::{EnboxStateIndex, KeyValues, StateHash};
use crate::Value;

const SMT_DEPTH: usize = 256;

static DEFAULT_HASHES: OnceLock<Vec<StateHash>> = OnceLock::new();

#[derive(Debug, Clone, Default)]
/// In-memory Sparse Merkle Tree `StateIndex` used by reference flows and
/// tests. Process-local; data is lost on restart. Production deployments
/// should pair `MessagesSync` with a durable state index (SQLite, etc.).
pub struct MemoryStateIndex {
    tenants: Arc<RwLock<BTreeMap<String, TenantState>>>,
}

#[derive(Debug, Clone, Default)]
struct TenantState {
    global: BTreeSet<String>,
    protocols: BTreeMap<String, BTreeSet<String>>,
    metadata: BTreeMap<String, Option<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Leaf {
    key_hash: StateHash,
    leaf_hash: StateHash,
    value_cid: String,
}

impl EnboxStateIndex for MemoryStateIndex {
    async fn open(&mut self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn close(&mut self) {}

    fn clear(&self) -> impl Future<Output = Result<(), StoreError>> + Send {
        let tenants = self.tenants.clone();
        async move {
            tenants.write().map_err(lock_error)?.clear();
            Ok(())
        }
    }

    fn insert(
        &self,
        tenant: &str,
        message_cid: &str,
        indexes: KeyValues,
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let tenants = self.tenants.clone();
        let tenant = tenant.to_string();
        let message_cid = message_cid.to_string();
        async move {
            let protocol = protocol_index(&indexes);
            let mut tenants = tenants.write().map_err(lock_error)?;
            let state = tenants.entry(tenant).or_default();

            let previous_protocol = state.metadata.get(&message_cid).cloned().flatten();
            if previous_protocol.as_ref() != protocol.as_ref() {
                if let Some(previous_protocol) = previous_protocol {
                    remove_protocol_cid(state, &previous_protocol, &message_cid);
                }
            }

            state.global.insert(message_cid.clone());
            if let Some(protocol) = protocol.clone() {
                state
                    .protocols
                    .entry(protocol)
                    .or_default()
                    .insert(message_cid.clone());
            }
            state.metadata.insert(message_cid, protocol);
            Ok(())
        }
    }

    fn delete(
        &self,
        tenant: &str,
        message_cids: &[String],
    ) -> impl Future<Output = Result<(), StoreError>> + Send {
        let tenants = self.tenants.clone();
        let tenant = tenant.to_string();
        let message_cids = message_cids.to_vec();
        async move {
            let mut tenants = tenants.write().map_err(lock_error)?;
            let Some(state) = tenants.get_mut(&tenant) else {
                return Ok(());
            };

            for message_cid in message_cids {
                state.global.remove(&message_cid);
                if let Some(Some(protocol)) = state.metadata.remove(&message_cid) {
                    remove_protocol_cid(state, &protocol, &message_cid);
                }
            }
            Ok(())
        }
    }

    fn get_root(&self, tenant: &str) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        let tenants = self.tenants.clone();
        let tenant = tenant.to_string();
        async move {
            let tenants = tenants.read().map_err(lock_error)?;
            let cids = tenants
                .get(&tenant)
                .map(|state| state.global.clone())
                .unwrap_or_default();
            Ok(root_hash(&cids))
        }
    }

    fn get_protocol_root(
        &self,
        tenant: &str,
        protocol: &str,
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        let tenants = self.tenants.clone();
        let tenant = tenant.to_string();
        let protocol = protocol.to_string();
        async move {
            let tenants = tenants.read().map_err(lock_error)?;
            let cids = protocol_cids(&tenants, &tenant, &protocol);
            Ok(root_hash(&cids))
        }
    }

    fn get_subtree_hash(
        &self,
        tenant: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        let tenants = self.tenants.clone();
        let tenant = tenant.to_string();
        let prefix = prefix.to_vec();
        async move {
            let tenants = tenants.read().map_err(lock_error)?;
            let cids = tenants
                .get(&tenant)
                .map(|state| state.global.clone())
                .unwrap_or_default();
            Ok(subtree_hash(&cids, &prefix))
        }
    }

    fn get_protocol_subtree_hash(
        &self,
        tenant: &str,
        protocol: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<StateHash, StoreError>> + Send {
        let tenants = self.tenants.clone();
        let tenant = tenant.to_string();
        let protocol = protocol.to_string();
        let prefix = prefix.to_vec();
        async move {
            let tenants = tenants.read().map_err(lock_error)?;
            let cids = protocol_cids(&tenants, &tenant, &protocol);
            Ok(subtree_hash(&cids, &prefix))
        }
    }

    fn get_leaves(
        &self,
        tenant: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send {
        let tenants = self.tenants.clone();
        let tenant = tenant.to_string();
        let prefix = prefix.to_vec();
        async move {
            let tenants = tenants.read().map_err(lock_error)?;
            let cids = tenants
                .get(&tenant)
                .map(|state| state.global.clone())
                .unwrap_or_default();
            Ok(leaves(&cids, &prefix))
        }
    }

    fn get_protocol_leaves(
        &self,
        tenant: &str,
        protocol: &str,
        prefix: &[bool],
    ) -> impl Future<Output = Result<Vec<String>, StoreError>> + Send {
        let tenants = self.tenants.clone();
        let tenant = tenant.to_string();
        let protocol = protocol.to_string();
        let prefix = prefix.to_vec();
        async move {
            let tenants = tenants.read().map_err(lock_error)?;
            let cids = protocol_cids(&tenants, &tenant, &protocol);
            Ok(leaves(&cids, &prefix))
        }
    }
}

fn remove_protocol_cid(state: &mut TenantState, protocol: &str, message_cid: &str) {
    if let Some(cids) = state.protocols.get_mut(protocol) {
        cids.remove(message_cid);
    }
}

fn protocol_index(indexes: &KeyValues) -> Option<String> {
    match indexes.get("protocol") {
        Some(Value::String(protocol)) => Some(protocol.clone()),
        _ => None,
    }
}

fn protocol_cids(
    tenants: &BTreeMap<String, TenantState>,
    tenant: &str,
    protocol: &str,
) -> BTreeSet<String> {
    tenants
        .get(tenant)
        .and_then(|state| state.protocols.get(protocol))
        .cloned()
        .unwrap_or_default()
}

fn root_hash(cids: &BTreeSet<String>) -> StateHash {
    let leaves = make_leaves(cids);
    node_hash(&leaves, 0)
}

fn subtree_hash(cids: &BTreeSet<String>, prefix: &[bool]) -> StateHash {
    let leaves = make_leaves(cids)
        .into_iter()
        .filter(|leaf| leaf_matches_prefix(&leaf.key_hash, prefix))
        .collect::<Vec<_>>();
    node_hash(&leaves, prefix.len())
}

fn leaves(cids: &BTreeSet<String>, prefix: &[bool]) -> Vec<String> {
    let mut leaves = make_leaves(cids)
        .into_iter()
        .filter(|leaf| leaf_matches_prefix(&leaf.key_hash, prefix))
        .collect::<Vec<_>>();

    leaves.sort_by(|left, right| {
        left.key_hash
            .cmp(&right.key_hash)
            .then(left.value_cid.cmp(&right.value_cid))
    });
    leaves.into_iter().map(|leaf| leaf.value_cid).collect()
}

fn make_leaves(cids: &BTreeSet<String>) -> Vec<Leaf> {
    cids.iter()
        .map(|value_cid| {
            let key_hash = hash_key(value_cid);
            let leaf_hash = hash_leaf(&key_hash, value_cid);
            Leaf {
                key_hash,
                leaf_hash,
                value_cid: value_cid.clone(),
            }
        })
        .collect()
}

fn node_hash(leaves: &[Leaf], depth: usize) -> StateHash {
    if leaves.is_empty() {
        return default_hashes()[depth];
    }
    if leaves.len() == 1 || depth >= SMT_DEPTH {
        return leaves[0].leaf_hash;
    }

    let (left, right): (Vec<_>, Vec<_>) = leaves
        .iter()
        .cloned()
        .partition(|leaf| !get_bit(&leaf.key_hash, depth));
    let left_hash = node_hash(&left, depth + 1);
    let right_hash = node_hash(&right, depth + 1);
    hash_children(&left_hash, &right_hash)
}

fn default_hashes() -> &'static [StateHash] {
    DEFAULT_HASHES
        .get_or_init(|| {
            let mut hashes = vec![[0u8; 32]; SMT_DEPTH + 1];
            for depth in (0..SMT_DEPTH).rev() {
                hashes[depth] = hash_children(&hashes[depth + 1], &hashes[depth + 1]);
            }
            hashes
        })
        .as_slice()
}

fn hash_key(value: &str) -> StateHash {
    let digest = Sha256::digest(value.as_bytes());
    digest.into()
}

fn hash_leaf(key_hash: &StateHash, value_cid: &str) -> StateHash {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(key_hash);
    hasher.update(value_cid.as_bytes());
    hasher.finalize().into()
}

fn hash_children(left: &StateHash, right: &StateHash) -> StateHash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn get_bit(hash: &StateHash, depth: usize) -> bool {
    let byte_index = depth >> 3;
    let bit_index = 7 - (depth & 0x07);
    ((hash[byte_index] >> bit_index) & 1) == 1
}

fn leaf_matches_prefix(key_hash: &StateHash, prefix: &[bool]) -> bool {
    prefix
        .iter()
        .enumerate()
        .all(|(depth, bit)| get_bit(key_hash, depth) == *bit)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_matches_typescript_fixture() {
        assert_eq!(
            hex(&root_hash(&BTreeSet::new())),
            "b178c245c947ea7e21ecede07728941a6ab1b706143c06873baff8ebd6de6308"
        );
    }

    fn hex(hash: &StateHash) -> String {
        hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
