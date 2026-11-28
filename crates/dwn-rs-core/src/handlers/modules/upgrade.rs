//! Same-URI module upgrade compatibility.
//!
//! A module URI names one durable contract. Once records exist, an update under
//! that URI may extend what it allows but must not rebind what stored records
//! already depend on: `uses` aliases, attachment identities, and the imported
//! contracts of every active dependent.
//!
//! The comparison is structural. Old and new graphs are resolved against their
//! own governing snapshots and only the contracts a stored record or a
//! dependent actually binds are compared.

use std::collections::BTreeSet;

use crate::interfaces::messages::modules::{Definition, ModuleDefinitionError};

use crate::interfaces::messages::modules::graph::{
    ResolvedModuleGraph, ResolvedModuleNode, ResolvedModuleNodeKind, ResolvedRoleReference,
};

const INCOMPATIBLE: &str = "ModulesConfigureIncompatibleContractUpdate";

/// Validates a consumer's own immutable aliases and existing attachment
/// bindings against the stored record paths.
pub fn validate_module_upgrade(
    previous: &Definition,
    incoming: &Definition,
    old_graph: &ResolvedModuleGraph,
    new_graph: &ResolvedModuleGraph,
    stored_paths: &BTreeSet<String>,
) -> Result<(), ModuleDefinitionError> {
    validate_uses_aliases(previous, incoming)?;

    for (path, old_node) in &old_graph.nodes_by_declared_path {
        validate_existing_node_binding(incoming, path, old_node, new_graph, stored_paths)?;
    }

    // A temporary removal must not erase the physical binding of retained records.
    for (path, node) in &new_graph.nodes_by_declared_path {
        if node.kind == ResolvedModuleNodeKind::Ref
            && !old_graph.nodes_by_declared_path.contains_key(path)
            && has_stored_records_in_subtree(stored_paths, path)
        {
            return Err(incompatible(
                &incoming.module,
                path,
                "retained record parent binding",
            ));
        }
    }

    Ok(())
}

/// Existing lexical aliases may be removed when unused, but cannot be renamed
/// or retargeted.
fn validate_uses_aliases(
    previous: &Definition,
    incoming: &Definition,
) -> Result<(), ModuleDefinitionError> {
    let empty = Default::default();
    let previous_uses = previous.uses.as_ref().unwrap_or(&empty);
    let incoming_uses = incoming.uses.as_ref().unwrap_or(&empty);
    for (alias, uri) in previous_uses {
        let next_uri = incoming_uses.get(alias);
        let renamed = next_uri.is_none()
            && incoming_uses
                .iter()
                .any(|(next_alias, target)| next_alias != alias && target == uri);
        if next_uri.is_some_and(|next_uri| next_uri != uri) || renamed {
            return Err(module_upgrade_error(
                "ModulesConfigureInvalidUsesUpdate",
                format!(
                    "module '{}' cannot rename or retarget uses alias '{alias}'",
                    incoming.module
                ),
            ));
        }
    }
    Ok(())
}

/// Keeps each surviving node's kind and each retained reference's name and
/// physical parent.
fn validate_existing_node_binding(
    incoming: &Definition,
    path: &str,
    old_node: &ResolvedModuleNode,
    new_graph: &ResolvedModuleGraph,
    stored_paths: &BTreeSet<String>,
) -> Result<(), ModuleDefinitionError> {
    let new_node = new_graph.nodes_by_declared_path.get(path);
    if new_node.is_some_and(|new_node| new_node.kind != old_node.kind) {
        return Err(incompatible(&incoming.module, path, "node kind"));
    }
    if old_node.kind != ResolvedModuleNodeKind::Ref {
        return Ok(());
    }

    let renamed = new_graph.nodes_by_declared_path.values().any(|node| {
        node.kind == ResolvedModuleNodeKind::Ref
            && node.declaring_module_path != path
            && same_record_address(old_node, node)
    });
    if renamed {
        return Err(incompatible(&incoming.module, path, "attachment name"));
    }

    let has_stored_descendants = has_stored_records_in_subtree(stored_paths, path);
    if new_node.is_some() || has_stored_descendants {
        let binds_same_parent = new_node.is_some_and(|new_node| {
            old_node.declared_rule_set.reference == new_node.declared_rule_set.reference
                && same_record_address(old_node, new_node)
                && ancestry(old_node) == ancestry(new_node)
        });
        if !binds_same_parent {
            return Err(incompatible(&incoming.module, path, "attachment parent"));
        }
    }
    Ok(())
}

/// Includes the path itself and every descendant that still has stored records.
fn has_stored_records_in_subtree(stored_paths: &BTreeSet<String>, path: &str) -> bool {
    let prefix = format!("{path}/");
    stored_paths
        .iter()
        .any(|stored| stored == path || stored.starts_with(&prefix))
}

/// Compares only the contracts an unchanged reverse dependent actually
/// imports. Every resolved path must survive with the same attachment identity,
/// ancestry, representation, and lifecycle.
pub fn validate_imported_module_contracts(
    old_graph: &ResolvedModuleGraph,
    new_graph: &ResolvedModuleGraph,
) -> Result<(), ModuleDefinitionError> {
    for (path, old_node) in &old_graph.nodes_by_declared_path {
        let new_node = new_graph
            .nodes_by_declared_path
            .get(path)
            .ok_or_else(|| incompatible(&old_graph.root_module_uri, path, "missing path"))?;

        if old_node.kind == ResolvedModuleNodeKind::Ref
            && attachment_contract(old_graph, old_node) != attachment_contract(new_graph, new_node)
        {
            return Err(incompatible(
                &old_graph.root_module_uri,
                path,
                "attachment identity, ancestry, representation, or lifecycle",
            ));
        }

        validate_imported_action_contracts(&old_graph.root_module_uri, path, old_node, new_node)?;
    }
    Ok(())
}

/// An unchanged consumer must resolve each role and actor rule to the same
/// imported contract.
fn validate_imported_action_contracts(
    module_uri: &str,
    path: &str,
    old_node: &ResolvedModuleNode,
    new_node: &ResolvedModuleNode,
) -> Result<(), ModuleDefinitionError> {
    for (index, previous) in old_node.actions.iter().enumerate() {
        let incoming = new_node.actions.get(index);
        if let Some(role) = &previous.resolved_role {
            let unchanged = incoming
                .and_then(|action| action.resolved_role.as_ref())
                .is_some_and(|role_after| role_contract(role) == role_contract(role_after));
            if !unchanged {
                return Err(incompatible(module_uri, path, "role identity or context"));
            }
        }
        if let Some(actor) = &previous.resolved_actor {
            let unchanged = incoming
                .and_then(|action| action.resolved_actor.as_ref())
                .is_some_and(|actor_after| actor == actor_after);
            if !unchanged {
                return Err(incompatible(module_uri, path, "actor identity or ancestry"));
            }
        }
    }
    Ok(())
}

fn same_record_address(left: &ResolvedModuleNode, right: &ResolvedModuleNode) -> bool {
    left.owning_module_uri == right.owning_module_uri
        && left.owning_module_path == right.owning_module_path
}

fn ancestry(node: &ResolvedModuleNode) -> Vec<(String, String)> {
    node.physical_ancestors
        .iter()
        .map(|step| {
            (
                step.address.owning_module_uri.clone(),
                step.address.owning_module_path.clone(),
            )
        })
        .collect()
}

#[derive(Debug, PartialEq, Eq)]
struct AttachmentContract {
    owner: (String, String),
    ancestors: Vec<(String, String)>,
    role: bool,
    squash: bool,
    schema: Option<String>,
    formats: Option<Vec<String>>,
    encrypted: bool,
}

fn attachment_contract(
    graph: &ResolvedModuleGraph,
    node: &ResolvedModuleNode,
) -> AttachmentContract {
    let module_type = graph
        .definitions_by_uri
        .get(&node.owning_module_uri)
        .and_then(|definition| definition.types.get(&node.type_name));
    let formats = module_type
        .and_then(|module_type| module_type.data_formats.as_ref())
        .map(|formats| {
            let mut formats = formats.clone();
            formats.sort();
            formats.dedup();
            formats
        });
    AttachmentContract {
        owner: (
            node.owning_module_uri.clone(),
            node.owning_module_path.clone(),
        ),
        ancestors: ancestry(node),
        role: node.rule_set.role == Some(true),
        squash: node.rule_set.squash == Some(true),
        schema: module_type.and_then(|module_type| module_type.schema.clone()),
        formats,
        encrypted: module_type.and_then(|module_type| module_type.encryption_required)
            == Some(true),
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RoleContract {
    owner: (String, String),
    ancestors: Vec<(String, String)>,
    parent_depth: usize,
    parent: Option<(String, String)>,
    role: bool,
}

fn role_contract(role: &ResolvedRoleReference) -> RoleContract {
    RoleContract {
        owner: (
            role.owning_module_uri.clone(),
            role.owning_module_path.clone(),
        ),
        ancestors: role
            .physical_ancestors
            .iter()
            .map(|step| {
                (
                    step.address.owning_module_uri.clone(),
                    step.address.owning_module_path.clone(),
                )
            })
            .collect(),
        parent_depth: role.parent_physical_depth,
        parent: role.parent_ancestor.as_ref().map(|parent| {
            (
                parent.owning_module_uri.clone(),
                parent.owning_module_path.clone(),
            )
        }),
        role: role.rule_set.role == Some(true),
    }
}

fn incompatible(consumer: &str, path: &str, contract: &str) -> ModuleDefinitionError {
    module_upgrade_error(
        INCOMPATIBLE,
        format!(
            "module '{consumer}' path '{path}' has an incompatible {contract}; use a new module URI"
        ),
    )
}

fn module_upgrade_error(code: &'static str, message: String) -> ModuleDefinitionError {
    ModuleDefinitionError { code, message }
}
