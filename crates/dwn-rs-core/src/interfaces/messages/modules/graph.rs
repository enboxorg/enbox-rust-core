//! Resolved module dependency graphs.
//!
//! A module definition may compose other modules through `uses` aliases and
//! root `$ref` attachment nodes. Resolution expands every dependency at one
//! governing snapshot into concrete record nodes carrying their physical
//! ancestry, so runtime authorization, limits, and encryption reason about
//! physical depth rather than declared path depth.
//!
//! Resolution is deterministic: every traversal is ordered by module URI and
//! declared path. `$ref` nodes add no physical record level; they re-expose the
//! referenced record at the attachment path.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;

use crate::errors::{DwnError, DwnErrorCode};
use crate::interfaces::messages::modules::{
    parse_cross_module_ref, validate_normalized_module_url, Action, Definition,
    ModuleDefinitionError, RuleSet, Who, MAX_RECORD_NESTING_DEPTH,
};

/// A record or role address in the module that physically owns it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ResolvedModuleAddress {
    pub owning_module_uri: String,
    pub owning_module_path: String,
}

/// One physical ancestor of a resolved record, outermost first.
#[derive(Debug, Clone)]
pub struct ResolvedAncestorStep {
    pub address: ResolvedModuleAddress,
    pub declaring_module_uri: String,
    pub declaring_module_path: String,
    pub type_name: String,
    pub rule_set: RuleSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolvedModuleNodeKind {
    Record,
    Ref,
}

/// A concrete record reached through a declared path in the root module.
#[derive(Debug, Clone)]
pub struct ResolvedModuleNode {
    pub declaring_module_uri: String,
    pub declaring_module_path: String,
    pub owning_module_uri: String,
    pub owning_module_path: String,
    pub kind: ResolvedModuleNodeKind,
    pub type_name: String,
    /// The concrete target's rule set. For a `$ref` node this is the referenced
    /// rule set, never the inert local attachment declaration.
    pub rule_set: RuleSet,
    /// The rule set written at the declared path (the `$ref` declaration for a
    /// reference node).
    pub declared_rule_set: RuleSet,
    pub physical_ancestors: Vec<ResolvedAncestorStep>,
    pub physical_depth: usize,
    pub parent_physical_depth: usize,
    pub expected_parent: Option<ResolvedModuleAddress>,
    pub roles_by_raw_ref: BTreeMap<String, ResolvedRoleReference>,
    pub actions: Vec<ResolvedModuleAction>,
}

/// A role resolved in the lexical namespace of the module that references it.
#[derive(Debug, Clone)]
pub struct ResolvedRoleReference {
    pub owning_module_uri: String,
    pub owning_module_path: String,
    pub raw_role: String,
    pub physical_ancestors: Vec<ResolvedAncestorStep>,
    pub physical_depth: usize,
    pub parent_physical_depth: usize,
    pub parent_ancestor: Option<ResolvedModuleAddress>,
    pub rule_set: RuleSet,
}

/// An `of` actor target resolved to its owning record and physical depth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedActorReference {
    pub owning_module_uri: String,
    pub owning_module_path: String,
    pub who: Who,
    pub raw_of: String,
    pub physical_depth: usize,
}

#[derive(Debug, Clone)]
pub struct ResolvedModuleAction {
    pub rule: Action,
    pub resolved_role: Option<ResolvedRoleReference>,
    pub resolved_actor: Option<ResolvedActorReference>,
}

/// One module's resolved view of its dependency graph.
#[derive(Debug, Clone)]
pub struct ResolvedModuleGraph {
    pub root_module_uri: String,
    pub definitions_by_uri: BTreeMap<String, Definition>,
    pub nodes_by_declared_path: BTreeMap<String, ResolvedModuleNode>,
    nodes_by_address: BTreeMap<(String, String), ResolvedModuleNode>,
}

impl ResolvedModuleGraph {
    /// The concrete record node at a declared path in the root module.
    pub fn record_node(&self, module_path: &str) -> Option<&ResolvedModuleNode> {
        self.nodes_by_declared_path.get(module_path)
    }

    /// Resolves an invoked `moduleRole` in the root module's lexical namespace.
    pub fn resolve_invoked_role(
        &self,
        module_role: &str,
    ) -> Result<ResolvedRoleReference, ModuleDefinitionError> {
        let (module_uri, path) = match parse_cross_module_ref(module_role) {
            Some(parsed) => {
                let module_uri = self
                    .definitions_by_uri
                    .get(&self.root_module_uri)
                    .and_then(|definition| definition.uses.as_ref())
                    .and_then(|uses| uses.get(parsed.alias))
                    .cloned()
                    .ok_or_else(|| {
                        module_graph_error(
                            "ModulesConfigureInvalidRefAlias",
                            format!(
                                "reference '{module_role}' has no alias '{}' in module '{}'",
                                parsed.alias, self.root_module_uri
                            ),
                        )
                    })?;
                (module_uri, parsed.module_path.to_string())
            }
            None => (self.root_module_uri.clone(), module_role.to_string()),
        };
        let node = self
            .nodes_by_address
            .get(&(module_uri.clone(), path.clone()))
            .ok_or_else(|| {
                module_graph_error(
                    "ModulesConfigureInvalidRefModulePath",
                    format!("module '{module_uri}' has no declared record path '{path}'"),
                )
            })?;
        role_reference(&self.definitions_by_uri, node, module_role)
    }
}

fn role_reference(
    definitions: &BTreeMap<String, Definition>,
    node: &ResolvedModuleNode,
    raw_role: &str,
) -> Result<ResolvedRoleReference, ModuleDefinitionError> {
    if node.rule_set.role != Some(true) {
        return Err(module_graph_error(
            "ModulesConfigureRoleDoesNotExistAtGivenPath",
            format!("reference '{raw_role}' does not resolve to a role record"),
        ));
    }
    let encrypted_role_type = definitions
        .get(&node.owning_module_uri)
        .and_then(|definition| definition.types.get(&node.type_name))
        .and_then(|module_type| module_type.encryption_required)
        == Some(true);
    if encrypted_role_type {
        return Err(module_graph_error(
            "ModulesConfigureInvalidEncryptedRoleType",
            format!(
                "role '{raw_role}' resolves to encrypted type '{}'; role records cannot be encrypted",
                node.type_name
            ),
        ));
    }
    Ok(ResolvedRoleReference {
        owning_module_uri: node.owning_module_uri.clone(),
        owning_module_path: node.owning_module_path.clone(),
        raw_role: raw_role.to_string(),
        physical_ancestors: node.physical_ancestors.clone(),
        physical_depth: node.physical_depth,
        parent_physical_depth: node.parent_physical_depth,
        parent_ancestor: node.expected_parent.clone(),
        rule_set: node.rule_set.clone(),
    })
}

/// An error raised while loading definitions or resolving their graph.
#[derive(Debug, thiserror::Error)]
pub enum ModuleGraphLoadError {
    #[error("{0}")]
    Definition(#[from] ModuleDefinitionError),
    #[error("{0}")]
    Store(String),
}

impl ModuleGraphLoadError {
    /// The stable code when the failure is a graph contract violation.
    pub fn code(&self) -> Option<DwnErrorCode> {
        match self {
            Self::Definition(error) => DwnErrorCode::try_from(error.code).ok(),
            Self::Store(_) => None,
        }
    }
}

impl From<ModuleGraphLoadError> for DwnError {
    fn from(error: ModuleGraphLoadError) -> Self {
        match error.code() {
            Some(code) => DwnError::new(code, error.to_string()),
            None => DwnError::new(
                DwnErrorCode::ModuleAuthorizationModuleNotFound,
                error.to_string(),
            ),
        }
    }
}

/// Loads every definition reachable from `root` once, without resolving the
/// graph. Callers bind tenant and governing timestamp into `fetch`.
pub async fn preload_module_definitions<F, Fut>(
    root: Definition,
    mut fetch: F,
) -> Result<BTreeMap<String, Definition>, ModuleGraphLoadError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<Option<Definition>, ModuleGraphLoadError>>,
{
    let mut definitions = BTreeMap::new();
    definitions.insert(root.module.clone(), root);
    let mut pending: Vec<String> = uses_targets(&definitions);
    while let Some(module_uri) = pending.pop() {
        if definitions.contains_key(&module_uri) {
            continue;
        }
        let Some(definition) = fetch(module_uri.clone()).await? else {
            return Err(module_graph_error(
                "ModulesConfigureComposedModuleNotInstalled",
                format!("composed module '{module_uri}' is not installed"),
            )
            .into());
        };
        if definition.module != module_uri {
            return Err(module_graph_error(
                "ModulesConfigureInvalidUsesModuleUrl",
                format!(
                    "lookup for '{module_uri}' returned definition '{}'",
                    definition.module
                ),
            )
            .into());
        }
        pending.extend(
            definition
                .uses
                .iter()
                .flat_map(|uses| uses.values())
                .filter(|uri| !definitions.contains_key(*uri))
                .cloned(),
        );
        definitions.insert(module_uri, definition);
    }
    Ok(definitions)
}

fn uses_targets(definitions: &BTreeMap<String, Definition>) -> Vec<String> {
    let mut targets: Vec<String> = definitions
        .values()
        .flat_map(|definition| definition.uses.iter().flat_map(|uses| uses.values()))
        .cloned()
        .collect();
    targets.sort();
    targets.dedup();
    targets
}

/// Loads and resolves the whole dependency closure at one snapshot.
pub async fn load_module_graph<F, Fut>(
    root: Definition,
    fetch: F,
) -> Result<ResolvedModuleGraph, ModuleGraphLoadError>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<Option<Definition>, ModuleGraphLoadError>>,
{
    let root_module_uri = root.module.clone();
    let definitions = preload_module_definitions(root, fetch).await?;
    let root = definitions
        .get(&root_module_uri)
        .cloned()
        .expect("the loaded closure always contains its root");
    let lookup = |uri: &str| definitions.get(uri).cloned();
    Ok(resolve_module_graph(root, &lookup, true)?)
}

/// Resolves a graph from an already loaded definition closure.
pub fn resolve_module_graph(
    root: Definition,
    lookup: &dyn Fn(&str) -> Option<Definition>,
    require_key_agreement: bool,
) -> Result<ResolvedModuleGraph, ModuleDefinitionError> {
    let resolver = ModuleGraphResolver {
        lookup,
        require_key_agreement,
        definitions: BTreeMap::new(),
        nodes: BTreeMap::new(),
        loading: BTreeSet::new(),
        resolving: BTreeSet::new(),
        ref_targets: BTreeMap::new(),
    };
    resolver.resolve(root)
}

struct ModuleGraphResolver<'a> {
    lookup: &'a dyn Fn(&str) -> Option<Definition>,
    require_key_agreement: bool,
    definitions: BTreeMap<String, Definition>,
    nodes: BTreeMap<(String, String), ResolvedModuleNode>,
    loading: BTreeSet<String>,
    resolving: BTreeSet<(String, String)>,
    ref_targets: BTreeMap<String, BTreeMap<(String, String), String>>,
}

impl ModuleGraphResolver<'_> {
    fn resolve(
        mut self,
        definition: Definition,
    ) -> Result<ResolvedModuleGraph, ModuleDefinitionError> {
        let root_module_uri = definition.module.clone();
        self.load_definition(definition)?;

        let module_uris: Vec<String> = self.definitions.keys().cloned().collect();
        for module_uri in &module_uris {
            let structure = self
                .definitions
                .get(module_uri)
                .map(|definition| definition.structure.clone())
                .unwrap_or_default();
            self.resolve_structure(module_uri, &structure, "")?;
        }

        let keys: Vec<(String, String)> = self.nodes.keys().cloned().collect();
        for key in &keys {
            self.resolve_actions(key)?;
        }

        let mut nodes_by_declared_path = BTreeMap::new();
        for node in self.nodes.values() {
            if node.declaring_module_uri == root_module_uri {
                nodes_by_declared_path.insert(node.declaring_module_path.clone(), node.clone());
            }
        }

        Ok(ResolvedModuleGraph {
            root_module_uri,
            definitions_by_uri: self.definitions,
            nodes_by_declared_path,
            nodes_by_address: self.nodes,
        })
    }

    fn load_definition(&mut self, input: Definition) -> Result<(), ModuleDefinitionError> {
        let module_uri = input.module.clone();
        if self.loading.contains(&module_uri) {
            return Err(module_graph_error(
                "ModulesConfigureInvalidUsesCycle",
                format!("module dependency cycle at '{module_uri}'"),
            ));
        }
        if self.definitions.contains_key(&module_uri) {
            return Ok(());
        }
        validate_normalized_module_url(&module_uri)?;
        self.loading.insert(module_uri.clone());
        self.definitions.insert(module_uri.clone(), input.clone());

        let mut used_uris = BTreeSet::new();
        for (alias, target_uri) in input.uses.iter().flat_map(|uses| uses.iter()) {
            validate_normalized_module_url(target_uri).map_err(|_| {
                module_graph_error(
                    "ModulesConfigureInvalidUsesModuleUrl",
                    format!("invalid 'uses' module URL for alias '{alias}': '{target_uri}'"),
                )
            })?;
            if !used_uris.insert(target_uri.clone()) {
                return Err(module_graph_error(
                    "ModulesConfigureDuplicateUsesModule",
                    format!("module '{module_uri}' declares multiple aliases for '{target_uri}'"),
                ));
            }
            if self.loading.contains(target_uri) {
                return Err(module_graph_error(
                    "ModulesConfigureInvalidUsesCycle",
                    format!("module dependency '{module_uri}' -> '{target_uri}' forms a cycle"),
                ));
            }
            if self.definitions.contains_key(target_uri) {
                continue;
            }
            let target = (self.lookup)(target_uri).ok_or_else(|| {
                module_graph_error(
                    "ModulesConfigureComposedModuleNotInstalled",
                    format!("composed module '{target_uri}' (alias '{alias}') is not installed"),
                )
            })?;
            if target.module != *target_uri {
                return Err(module_graph_error(
                    "ModulesConfigureInvalidUsesModuleUrl",
                    format!(
                        "lookup for '{target_uri}' returned definition '{}'",
                        target.module
                    ),
                ));
            }
            self.load_definition(target)?;
        }
        self.loading.remove(&module_uri);
        Ok(())
    }

    fn resolve_structure(
        &mut self,
        module_uri: &str,
        structure: &BTreeMap<String, RuleSet>,
        parent_path: &str,
    ) -> Result<(), ModuleDefinitionError> {
        let names: Vec<String> = structure
            .keys()
            .filter(|name| !name.starts_with('$'))
            .cloned()
            .collect();
        for name in names {
            let path = child_path(parent_path, &name);
            self.resolve_node(module_uri, &path)?;
            let children = structure
                .get(&name)
                .map(|rule_set| rule_set.rules.clone())
                .unwrap_or_default();
            self.resolve_structure(module_uri, &children, &path)?;
        }
        Ok(())
    }

    fn declared_rule_set(
        &self,
        module_uri: &str,
        path: &str,
    ) -> Result<RuleSet, ModuleDefinitionError> {
        let Some(definition) = self.definitions.get(module_uri) else {
            return Err(module_graph_error(
                "ModulesConfigureComposedModuleNotInstalled",
                format!("module '{module_uri}' is not loaded"),
            ));
        };
        let mut node = &definition.structure;
        let mut rule_set = None;
        for segment in path.split('/') {
            if segment.is_empty() || segment.starts_with('$') {
                break;
            }
            let Some(next) = node.get(segment) else {
                return Err(module_graph_error(
                    "ModulesConfigureInvalidRefModulePath",
                    format!("module '{module_uri}' has no declared record path '{path}'"),
                ));
            };
            rule_set = Some(next.clone());
            node = &next.rules;
        }
        rule_set.ok_or_else(|| {
            module_graph_error(
                "ModulesConfigureInvalidRefModulePath",
                format!("module '{module_uri}' has no declared record path '{path}'"),
            )
        })
    }

    fn resolve_reference(
        &mut self,
        module_uri: &str,
        reference: &str,
    ) -> Result<ResolvedModuleNode, ModuleDefinitionError> {
        let Some(parsed) = parse_cross_module_ref(reference) else {
            return self.resolve_node(module_uri, reference);
        };
        let target_uri = self
            .definitions
            .get(module_uri)
            .and_then(|definition| definition.uses.as_ref())
            .and_then(|uses| uses.get(parsed.alias))
            .cloned()
            .ok_or_else(|| {
                module_graph_error(
                    "ModulesConfigureInvalidRefAlias",
                    format!(
                        "reference '{reference}' has no alias '{}' in module '{module_uri}'",
                        parsed.alias
                    ),
                )
            })?;
        self.resolve_node(&target_uri, parsed.module_path)
    }

    fn resolve_node(
        &mut self,
        module_uri: &str,
        path: &str,
    ) -> Result<ResolvedModuleNode, ModuleDefinitionError> {
        let key = (module_uri.to_string(), path.to_string());
        if let Some(node) = self.nodes.get(&key) {
            return Ok(node.clone());
        }
        if self.resolving.contains(&key) {
            return Err(module_graph_error(
                "ModulesConfigureInvalidUsesCycle",
                format!("cyclic reference at '{module_uri}' path '{path}'"),
            ));
        }
        self.resolving.insert(key.clone());
        let declared = self.declared_rule_set(module_uri, path)?;
        let node = if declared.reference.is_some() {
            self.create_reference_node(module_uri, path, &declared)?
        } else {
            self.create_record_node(module_uri, path, declared)?
        };
        if node.physical_depth > MAX_RECORD_NESTING_DEPTH {
            return Err(module_graph_error(
                "ModulesConfigureMaxDepthExceeded",
                format!(
                    "resolved record '{module_uri}' path '{path}' exceeds {MAX_RECORD_NESTING_DEPTH} physical levels"
                ),
            ));
        }
        self.nodes.insert(key.clone(), node.clone());
        self.resolving.remove(&key);
        Ok(node)
    }

    fn create_reference_node(
        &mut self,
        module_uri: &str,
        path: &str,
        declared: &RuleSet,
    ) -> Result<ResolvedModuleNode, ModuleDefinitionError> {
        if path.contains('/') {
            return Err(module_graph_error(
                "ModulesConfigureInvalidRefNotAtRoot",
                format!("reference at '{module_uri}' path '{path}' is not at the structure root"),
            ));
        }
        let reference = declared.reference.as_deref().unwrap_or_default();
        let target = self.resolve_reference(module_uri, reference)?;
        if target.rule_set.squash == Some(true)
            || target
                .physical_ancestors
                .iter()
                .any(|step| step.rule_set.squash == Some(true))
        {
            return Err(module_graph_error(
                "ModulesConfigureInvalidRefTargetSquash",
                format!(
                    "reference '{reference}' at '{module_uri}' path '{path}' has squashable physical ancestry"
                ),
            ));
        }
        let target_key = (
            target.owning_module_uri.clone(),
            target.owning_module_path.clone(),
        );
        let targets = self.ref_targets.entry(module_uri.to_string()).or_default();
        if let Some(previous_path) = targets.get(&target_key) {
            return Err(module_graph_error(
                "ModulesConfigureDuplicateRefTarget",
                format!(
                    "references '{previous_path}' and '{path}' in '{module_uri}' resolve to the same target"
                ),
            ));
        }
        targets.insert(target_key, path.to_string());

        Ok(ResolvedModuleNode {
            declaring_module_uri: module_uri.to_string(),
            declaring_module_path: path.to_string(),
            owning_module_uri: target.owning_module_uri.clone(),
            owning_module_path: target.owning_module_path.clone(),
            kind: ResolvedModuleNodeKind::Ref,
            type_name: target.type_name.clone(),
            rule_set: target.rule_set.clone(),
            declared_rule_set: declared.clone(),
            physical_ancestors: target.physical_ancestors.clone(),
            physical_depth: target.physical_depth,
            parent_physical_depth: target.parent_physical_depth,
            expected_parent: target.expected_parent.clone(),
            roles_by_raw_ref: BTreeMap::new(),
            actions: Vec::new(),
        })
    }

    fn create_record_node(
        &mut self,
        module_uri: &str,
        path: &str,
        declared: RuleSet,
    ) -> Result<ResolvedModuleNode, ModuleDefinitionError> {
        let type_name = path.rsplit('/').next().unwrap_or_default().to_string();
        let exists = self
            .definitions
            .get(module_uri)
            .is_some_and(|definition| definition.types.contains_key(&type_name));
        if !exists {
            return Err(module_graph_error(
                "ModulesConfigureInvalidRuleSetRecordType",
                format!("record path '{path}' in '{module_uri}' has no local type '{type_name}'"),
            ));
        }
        let parent = match path.rsplit_once('/') {
            Some((parent_path, _)) => Some(self.resolve_node(module_uri, parent_path)?),
            None => None,
        };
        let physical_ancestors = match &parent {
            Some(parent) => {
                let mut ancestors = parent.physical_ancestors.clone();
                ancestors.push(ancestor_step(parent));
                ancestors
            }
            None => Vec::new(),
        };
        let physical_depth = physical_ancestors.len() + 1;
        Ok(ResolvedModuleNode {
            declaring_module_uri: module_uri.to_string(),
            declaring_module_path: path.to_string(),
            owning_module_uri: module_uri.to_string(),
            owning_module_path: path.to_string(),
            kind: ResolvedModuleNodeKind::Record,
            type_name,
            rule_set: declared.clone(),
            declared_rule_set: declared,
            physical_ancestors,
            physical_depth,
            parent_physical_depth: physical_depth - 1,
            expected_parent: parent.as_ref().map(|parent| ResolvedModuleAddress {
                owning_module_uri: parent.owning_module_uri.clone(),
                owning_module_path: parent.owning_module_path.clone(),
            }),
            roles_by_raw_ref: BTreeMap::new(),
            actions: Vec::new(),
        })
    }

    fn resolve_actions(&mut self, key: &(String, String)) -> Result<(), ModuleDefinitionError> {
        let Some(mut node) = self.nodes.get(key).cloned() else {
            return Ok(());
        };
        let mut role_keys = BTreeSet::new();
        let mut actor_keys = BTreeSet::new();
        for rule in node.declared_rule_set.actions.clone() {
            let action = match &rule {
                Action::Role(role_rule) => {
                    let role = self.resolve_role(&node, &role_rule.role)?;
                    if let Some(parent) = &role.parent_ancestor {
                        if !is_self_or_ancestor(&node, parent) {
                            return Err(module_graph_error(
                                "ModulesConfigureInvalidRoleAncestor",
                                format!(
                                    "role '{}' cannot obtain its parent context from '{}' in '{}'",
                                    role_rule.role,
                                    node.declaring_module_path,
                                    node.declaring_module_uri
                                ),
                            ));
                        }
                    }
                    let role_key = (
                        role.owning_module_uri.clone(),
                        role.owning_module_path.clone(),
                    );
                    if !role_keys.insert(role_key) {
                        return Err(module_graph_error(
                            "ModulesConfigureDuplicateRoleInRuleSet",
                            format!(
                                "duplicate canonical role '{}' at '{}'",
                                role_rule.role, node.declaring_module_path
                            ),
                        ));
                    }
                    if self.require_key_agreement
                        && node.kind == ResolvedModuleNodeKind::Record
                        && self.node_type_encrypted(&node)
                        && role_rule
                            .can
                            .contains(&crate::interfaces::messages::modules::Can::Read)
                        && role.rule_set.key_agreement.is_none()
                    {
                        return Err(module_graph_error(
                            "ModulesConfigureInvalidEncryptedRoleMissingKeyAgreement",
                            format!(
                                "encrypted path '{}' references role '{}' without $keyAgreement",
                                node.declaring_module_path, role_rule.role
                            ),
                        ));
                    }
                    let raw_role = role_rule.role.clone();
                    node.roles_by_raw_ref.insert(raw_role, role.clone());
                    ResolvedModuleAction {
                        rule: rule.clone(),
                        resolved_role: Some(role),
                        resolved_actor: None,
                    }
                }
                Action::Who(who_rule) => {
                    let resolved_actor = match &who_rule.of {
                        Some(of) => {
                            let target = self.resolve_reference(&node.declaring_module_uri, of)?;
                            let address = ResolvedModuleAddress {
                                owning_module_uri: target.owning_module_uri.clone(),
                                owning_module_path: target.owning_module_path.clone(),
                            };
                            if !is_self_or_ancestor(&node, &address) {
                                return Err(module_graph_error(
                                    "ModulesConfigureInvalidActionOfNotAnAncestor",
                                    format!(
                                        "actor target '{of}' is not an ancestor of '{}' in '{}'",
                                        node.declaring_module_path, node.declaring_module_uri
                                    ),
                                ));
                            }
                            Some(ResolvedActorReference {
                                owning_module_uri: target.owning_module_uri,
                                owning_module_path: target.owning_module_path,
                                who: who_rule.who.clone(),
                                raw_of: of.clone(),
                                physical_depth: target.physical_depth,
                            })
                        }
                        None => None,
                    };
                    let actor_key = (
                        format!("{:?}", who_rule.who),
                        resolved_actor.as_ref().map(|actor| {
                            format!("{}:{}", actor.owning_module_uri, actor.owning_module_path)
                        }),
                    );
                    if !actor_keys.insert(actor_key) {
                        return Err(module_graph_error(
                            "ModulesConfigureDuplicateActorInRuleSet",
                            format!(
                                "duplicate canonical actor {:?} at '{}'",
                                who_rule.who, node.declaring_module_path
                            ),
                        ));
                    }
                    ResolvedModuleAction {
                        rule: rule.clone(),
                        resolved_role: None,
                        resolved_actor,
                    }
                }
            };
            node.actions.push(action);
        }
        self.nodes.insert(key.clone(), node);
        Ok(())
    }

    fn resolve_role(
        &mut self,
        node: &ResolvedModuleNode,
        raw_role: &str,
    ) -> Result<ResolvedRoleReference, ModuleDefinitionError> {
        let target = self.resolve_reference(&node.declaring_module_uri, raw_role)?;
        role_reference(&self.definitions, &target, raw_role)
    }

    fn node_type_encrypted(&self, node: &ResolvedModuleNode) -> bool {
        self.definitions
            .get(&node.owning_module_uri)
            .and_then(|definition| definition.types.get(&node.type_name))
            .and_then(|module_type| module_type.encryption_required)
            == Some(true)
    }
}

fn ancestor_step(node: &ResolvedModuleNode) -> ResolvedAncestorStep {
    ResolvedAncestorStep {
        address: ResolvedModuleAddress {
            owning_module_uri: node.owning_module_uri.clone(),
            owning_module_path: node.owning_module_path.clone(),
        },
        declaring_module_uri: node.declaring_module_uri.clone(),
        declaring_module_path: node.declaring_module_path.clone(),
        type_name: node.type_name.clone(),
        rule_set: node.rule_set.clone(),
    }
}

fn is_self_or_ancestor(node: &ResolvedModuleNode, address: &ResolvedModuleAddress) -> bool {
    let matches = |owning_module_uri: &str, owning_module_path: &str| {
        owning_module_uri == address.owning_module_uri
            && owning_module_path == address.owning_module_path
    };
    matches(&node.owning_module_uri, &node.owning_module_path)
        || node.physical_ancestors.iter().any(|step| {
            matches(
                &step.address.owning_module_uri,
                &step.address.owning_module_path,
            )
        })
}

fn child_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}/{child}")
    }
}

fn module_graph_error(code: &'static str, message: String) -> ModuleDefinitionError {
    ModuleDefinitionError { code, message }
}

/// The role-audience context shared by role authorization and encrypted-record
/// admission. Root roles use an explicit empty context; nested roles use the
/// ancestor prefix at their resolved physical parent depth.
pub fn role_audience_context_id(
    parent_physical_depth: usize,
    context_id: Option<&str>,
) -> Option<String> {
    if parent_physical_depth == 0 {
        return Some(String::new());
    }
    let segments: Vec<&str> = context_id?.split('/').collect();
    if segments.len() < parent_physical_depth || segments.iter().any(|segment| segment.is_empty()) {
        return None;
    }
    Some(segments[..parent_physical_depth].join("/"))
}

/// The context prefix a nested role record must match. Root roles are
/// tenant-wide and carry no prefix.
pub fn role_context_prefix(
    parent_physical_depth: usize,
    context_id: Option<&str>,
) -> Option<String> {
    match role_audience_context_id(parent_physical_depth, context_id)? {
        context if context.is_empty() => None,
        context => Some(context),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interfaces::messages::modules::{ActionRole, ActionWho, Can, Type};

    const CORE: &str = "https://core.example/notes";
    const EXT_A: &str = "https://ext-a.example/comments";
    const EXT_B: &str = "https://ext-b.example/reactions";

    fn text_type() -> Type {
        Type {
            schema: None,
            data_formats: None,
            encryption_required: None,
        }
    }

    fn snapshot(definitions: Vec<Definition>) -> impl Fn(&str) -> Option<Definition> {
        let definitions: BTreeMap<String, Definition> = definitions
            .into_iter()
            .map(|definition| (definition.module.clone(), definition))
            .collect();
        move |uri: &str| definitions.get(uri).cloned()
    }

    fn resolution_error(root: Definition, definitions: Vec<Definition>) -> ModuleDefinitionError {
        let lookup = snapshot(definitions);
        resolve_module_graph(root, &lookup, true).expect_err("graph must be rejected")
    }

    fn core_definition(squash_note: bool) -> Definition {
        Definition {
            module: CORE.to_string(),
            published: true,
            uses: None,
            key_agreement: None,
            types: BTreeMap::from([
                ("notebook".to_string(), text_type()),
                ("note".to_string(), text_type()),
                ("editor".to_string(), text_type()),
                ("private".to_string(), text_type()),
            ]),
            structure: BTreeMap::from([
                (
                    "private".to_string(),
                    RuleSet {
                        rules: BTreeMap::from([(
                            "editor".to_string(),
                            RuleSet {
                                role: Some(true),
                                ..Default::default()
                            },
                        )]),
                        ..Default::default()
                    },
                ),
                (
                    "notebook".to_string(),
                    RuleSet {
                        rules: BTreeMap::from([(
                            "note".to_string(),
                            RuleSet {
                                squash: squash_note.then_some(true),
                                rules: BTreeMap::from([(
                                    "editor".to_string(),
                                    RuleSet {
                                        role: Some(true),
                                        ..Default::default()
                                    },
                                )]),
                                ..Default::default()
                            },
                        )]),
                        ..Default::default()
                    },
                ),
            ]),
        }
    }

    fn ext_a_definition() -> Definition {
        Definition {
            module: EXT_A.to_string(),
            published: true,
            uses: Some(BTreeMap::from([("core".to_string(), CORE.to_string())])),
            key_agreement: None,
            types: BTreeMap::from([("comment".to_string(), text_type())]),
            structure: BTreeMap::from([(
                "note".to_string(),
                RuleSet {
                    reference: Some("core:notebook/note".to_string()),
                    rules: BTreeMap::from([("comment".to_string(), RuleSet::default())]),
                    ..Default::default()
                },
            )]),
        }
    }

    fn ext_b_definition() -> Definition {
        Definition {
            module: EXT_B.to_string(),
            published: true,
            uses: Some(BTreeMap::from([
                ("core".to_string(), CORE.to_string()),
                ("ext".to_string(), EXT_A.to_string()),
            ])),
            key_agreement: None,
            types: BTreeMap::from([("reaction".to_string(), text_type())]),
            structure: BTreeMap::from([(
                "comment".to_string(),
                RuleSet {
                    reference: Some("ext:note/comment".to_string()),
                    rules: BTreeMap::from([("reaction".to_string(), RuleSet::default())]),
                    ..Default::default()
                },
            )]),
        }
    }

    fn chained_definitions() -> Vec<Definition> {
        vec![
            core_definition(false),
            ext_a_definition(),
            ext_b_definition(),
        ]
    }

    // Covers: DWN-PROTO-005
    #[test]
    fn chained_refs_resolve_physical_ancestry_beyond_declared_depth() {
        let root = ext_b_definition();
        let lookup = snapshot(chained_definitions());
        let graph = resolve_module_graph(root, &lookup, true).unwrap();

        let reaction = graph.record_node("comment/reaction").unwrap();
        assert_eq!(reaction.physical_depth, 4);
        assert_eq!(reaction.parent_physical_depth, 3);
        assert_eq!(
            reaction
                .physical_ancestors
                .iter()
                .map(|step| (
                    step.address.owning_module_uri.as_str(),
                    step.address.owning_module_path.as_str()
                ))
                .collect::<Vec<_>>(),
            vec![
                (CORE, "notebook"),
                (CORE, "notebook/note"),
                (EXT_A, "note/comment"),
            ]
        );
        assert_eq!(
            reaction.expected_parent,
            Some(ResolvedModuleAddress {
                owning_module_uri: EXT_A.to_string(),
                owning_module_path: "note/comment".to_string(),
            })
        );

        // The attachment node re-exposes the referenced record without adding
        // a physical level.
        let attachment = graph.record_node("comment").unwrap();
        assert_eq!(attachment.kind, ResolvedModuleNodeKind::Ref);
        assert_eq!(attachment.owning_module_uri, EXT_A);
        assert_eq!(attachment.physical_depth, 3);
    }

    // Covers: DWN-PROTO-005
    #[test]
    fn invoked_cross_module_role_resolves_to_its_owning_address() {
        let root = ext_b_definition();
        let lookup = snapshot(chained_definitions());
        let graph = resolve_module_graph(root, &lookup, true).unwrap();

        let role = graph
            .resolve_invoked_role("core:notebook/note/editor")
            .unwrap();
        assert_eq!(role.owning_module_uri, CORE);
        assert_eq!(role.owning_module_path, "notebook/note/editor");
        assert_eq!(role.parent_physical_depth, 2);
        assert_eq!(role.physical_depth, 3);
        assert_eq!(
            role_audience_context_id(role.parent_physical_depth, Some("nb/n/c/r")),
            Some("nb/n".to_string())
        );
        assert_eq!(
            role_context_prefix(role.parent_physical_depth, Some("nb/n/c/r")),
            Some("nb/n".to_string())
        );
    }

    // Covers: DWN-PROTO-002
    #[test]
    fn root_role_audience_has_no_context() {
        assert_eq!(role_audience_context_id(0, None), Some(String::new()));
        assert_eq!(role_context_prefix(0, None), None);
        assert_eq!(role_audience_context_id(2, Some("only-one")), None);
        assert_eq!(role_audience_context_id(2, Some("/")), None);
    }

    // Covers: DWN-PROTO-005
    #[test]
    fn duplicate_uses_uri_is_rejected() {
        let mut root = ext_a_definition();
        root.uses = Some(BTreeMap::from([
            ("core".to_string(), CORE.to_string()),
            ("other".to_string(), CORE.to_string()),
        ]));
        let error = resolution_error(root, chained_definitions());
        assert_eq!(error.code, "ModulesConfigureDuplicateUsesModule");
    }

    // Covers: DWN-PROTO-005
    #[test]
    fn dependency_cycle_is_rejected() {
        let mut core = core_definition(false);
        core.uses = Some(BTreeMap::from([("ext".to_string(), EXT_A.to_string())]));
        let lookup = snapshot(vec![core, ext_a_definition()]);
        let root = ext_a_definition();
        let error = resolve_module_graph(root, &lookup, true).unwrap_err();
        assert_eq!(error.code, "ModulesConfigureInvalidUsesCycle");
    }

    // Covers: DWN-PROTO-005
    #[test]
    fn missing_dependency_is_rejected() {
        let error = resolution_error(ext_a_definition(), vec![]);
        assert_eq!(error.code, "ModulesConfigureComposedModuleNotInstalled");
    }

    // Covers: DWN-PROTO-005
    #[test]
    fn duplicate_physical_ref_target_is_rejected() {
        let mut root = ext_b_definition();
        root.structure.insert(
            "mirror".to_string(),
            RuleSet {
                reference: Some("ext:note/comment".to_string()),
                rules: BTreeMap::from([("mirror-reaction".to_string(), RuleSet::default())]),
                ..Default::default()
            },
        );
        root.types
            .insert("mirror-reaction".to_string(), text_type());
        let error = resolution_error(root, chained_definitions());
        assert_eq!(error.code, "ModulesConfigureDuplicateRefTarget");
    }

    // Covers: DWN-PROTO-005
    #[test]
    fn ref_onto_squashable_target_or_ancestor_is_rejected() {
        let mut definitions = chained_definitions();
        definitions[0] = core_definition(true);
        let error = resolution_error(ext_a_definition(), definitions);
        assert_eq!(error.code, "ModulesConfigureInvalidRefTargetSquash");
    }

    // Covers: DWN-PROTO-005
    #[test]
    fn physical_depth_beyond_the_cap_is_rejected() {
        let mut root = ext_a_definition();
        let mut rules = BTreeMap::new();
        let mut current = &mut rules;
        for index in 0..MAX_RECORD_NESTING_DEPTH {
            let child = current
                .entry(format!("level-{index}"))
                .or_insert_with(RuleSet::default);
            current = &mut child.rules;
        }
        for index in 0..MAX_RECORD_NESTING_DEPTH {
            root.types.insert(format!("level-{index}"), text_type());
        }
        root.structure.insert(
            "note".to_string(),
            RuleSet {
                reference: Some("core:notebook/note".to_string()),
                rules,
                ..Default::default()
            },
        );
        let error = resolution_error(root, chained_definitions());
        assert_eq!(error.code, "ModulesConfigureMaxDepthExceeded");
    }

    // Covers: DWN-PROTO-002
    #[test]
    fn non_ancestor_role_parent_is_rejected() {
        let mut root = ext_b_definition();
        root.structure.get_mut("comment").unwrap().rules.insert(
            "reaction".to_string(),
            RuleSet {
                actions: vec![Action::Role(ActionRole {
                    role: "core:private/editor".to_string(),
                    can: vec![Can::Create],
                })],
                ..Default::default()
            },
        );
        let error = resolution_error(root, chained_definitions());
        assert_eq!(error.code, "ModulesConfigureInvalidRoleAncestor");
    }

    // Covers: DWN-PROTO-003
    #[test]
    fn non_ancestor_actor_target_is_rejected() {
        let mut root = ext_b_definition();
        root.structure.get_mut("comment").unwrap().rules.insert(
            "reaction".to_string(),
            RuleSet {
                actions: vec![Action::Who(ActionWho {
                    who: Who::Author,
                    of: Some("core:private".to_string()),
                    can: vec![Can::Create],
                })],
                ..Default::default()
            },
        );
        let error = resolution_error(root, chained_definitions());
        assert_eq!(error.code, "ModulesConfigureInvalidActionOfNotAnAncestor");
    }
}
