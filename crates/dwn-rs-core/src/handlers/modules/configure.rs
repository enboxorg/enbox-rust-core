use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::auth::resolver::DidResolver;
use crate::core_module::CoreModuleRegistry;
use crate::descriptors::records::{records_write_descriptor, write_fields};
use crate::descriptors::ModulesConfigureDescriptor;
use crate::dwn::HandlerContext;
use crate::encryption::is_encryption_control_path;
use crate::filters::Filters;
use crate::handlers::records::common::{filter_map, string_filter};
use crate::handlers::records::{RECORDS_INTERFACE, WRITE_METHOD};
use crate::interfaces::messages::modules::graph::{
    load_module_graph, ModuleGraphLoadError, ResolvedModuleGraph, ResolvedModuleNodeKind,
};
use crate::interfaces::messages::modules::{self as module_types, Definition};
use crate::replies::modules::Configure;
use crate::stores::{LatestStateMutation, LatestStateTransition, ManagedResumableTask};
use crate::tasks::manager::ResumableTask;
use crate::Descriptor;
use crate::{canonical_rfc3339, permissions, Handler, Message, Pagination, Response};
use crate::{MessageSort, SortDirection};

use super::common::*;
use super::upgrade::{validate_imported_module_contracts, validate_module_upgrade};

/// Re-examines stored control records after a configuration is accepted.
///
/// Type-erased deliberately. Repair needs a data store and a task store that
/// configuration handling otherwise has no use for, and threading both through
/// as generic parameters would put them on every construction of this handler —
/// including the many that never repair anything. Erasing them keeps the cost
/// where the capability is used.
/// A repair obligation that has been durably recorded but not yet discharged.
///
/// Opaque here on purpose: configuration handling needs to hand the token back,
/// not to know what a task store made of it.
pub struct EnlistedRepair(pub(crate) ManagedResumableTask<ResumableTask>);

pub trait ControlRepairer: Send + Sync {
    /// Records the obligation to re-examine this module's control records.
    ///
    /// Called *before* the configuration commits. The obligation has to outlive
    /// the crash that could happen immediately after the commit, and a task
    /// registered after the commit cannot: there is a window in which the new
    /// history is durable and nothing remembers it needs answering. Enlisting
    /// first inverts the window into a harmless one — an obligation recorded
    /// for a configuration that never landed resumes, re-asks the question
    /// against the history as it actually stands, finds nothing contradicted
    /// and retires.
    fn enlist<'a>(
        &'a self,
        tenant: &'a str,
        module: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<EnlistedRepair, String>> + Send + 'a>>;

    /// Discharges an enlisted obligation, retiring it only once the scan
    /// completes. A scan that fails leaves the obligation in place for the
    /// recovery pass to pick up.
    fn fulfil<'a>(
        &'a self,
        enlisted: EnlistedRepair,
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>>;
}

#[derive(Clone)]
pub struct ModulesConfigureHandler<MessageStore> {
    message_store: MessageStore,
    did_resolver: Option<Arc<dyn DidResolver>>,
    /// Absent on a node that cannot finish what repair would start. Such a node
    /// still accepts configurations and simply never repairs, rather than
    /// half-removing records it cannot durably see through.
    repairer: Option<Arc<dyn ControlRepairer>>,
}

impl<MessageStore> ModulesConfigureHandler<MessageStore> {
    pub fn new(message_store: MessageStore, did_resolver: Option<Arc<dyn DidResolver>>) -> Self {
        Self {
            message_store,
            did_resolver,
            repairer: None,
        }
    }

    /// Gives this handler the ability to repair control records after a
    /// configuration lands. Without it, configurations are accepted and nothing
    /// is re-examined.
    pub fn with_repairer(mut self, repairer: Arc<dyn ControlRepairer>) -> Self {
        self.repairer = Some(repairer);
        self
    }
}

impl<MessageStore> Handler for ModulesConfigureHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    type Reply = Configure;
    type Descriptor = ModulesConfigureDescriptor;

    fn handle(
        &self,
        ctx: HandlerContext<'_, Self::Descriptor>,
    ) -> impl Future<Output = Response<Self::Reply>> + Send {
        async move {
            let HandlerContext {
                tenant,
                message,
                descriptor,
                ..
            } = ctx;

            let authorization = match permissions::validate_authorization_signature(
                &message,
                self.did_resolver.as_deref(),
                true,
            )
            .await
            {
                Ok(Some(authorization)) => authorization,
                Ok(None) => {
                    return Response::unauthorized(
                        "ModulesConfigureAuthorizationFailed: message failed authorization"
                            .to_string(),
                    )
                }
                Err(permissions::AuthorizationValidationError::BadRequest(detail)) => {
                    return Response::bad_request(detail.to_string())
                }
                Err(permissions::AuthorizationValidationError::Unauthorized(detail)) => {
                    return Response::unauthorized(detail.to_string())
                }
                Err(error) => return Response::bad_request(error.to_string()),
            };

            let author = authorization.author.clone();
            let incoming_cid = match message_cid(&message) {
                Ok(cid) => cid,
                Err(detail) => return Response::bad_request(detail.to_string()),
            };
            let existing_messages = match self
                .message_store
                .query(
                    tenant,
                    module_configure_filters(&descriptor.definition.module, false),
                    Some(MessageSort::Timestamp(SortDirection::Ascending)),
                    None,
                    None,
                )
                .await
            {
                Ok(result) => result.messages,
                Err(err) => return store_error_reply(err.to_string()),
            };
            for existing in &existing_messages {
                match message_cid(existing) {
                    Ok(cid) if cid == incoming_cid => return Response::conflict(),
                    Ok(_) => {}
                    Err(detail) => return Response::bad_request(detail),
                }
            }

            // Covers: DWN-REC-003, DWN-AUTH-006
            // Exact replay is classified before mutable grant and composition state can
            // reinterpret an operation that was already admitted.
            if let Err(detail) = permissions::authorize_modules_configure(
                tenant,
                &message,
                &authorization,
                &self.message_store,
            )
            .await
            {
                return Response::unauthorized(detail.to_string());
            }
            if let Err(err) = module_types::validate_definition(&descriptor.definition) {
                return Response::bad_request(err.to_string());
            }
            // Covers: DWN-PROTO-004, DWN-PROTO-005
            // Every configuration resolves its dependency closure at its own
            // message timestamp, so a historical import never sees a newer
            // provider snapshot.
            let incoming_timestamp = canonical_rfc3339(descriptor.message_timestamp);
            if let Err(detail) = self
                .validate_composition_dependencies(
                    tenant,
                    &descriptor.definition,
                    Some(incoming_timestamp.as_str()),
                )
                .await
            {
                return Response::bad_request(detail);
            }

            // Covers: DWN-PROTO-001, DWN-PROTO-004, DWN-PROTO-005
            // Representation policy is immutable once records exist under a
            // path. The scan runs before the configure commits.
            if let Err(reply) = self
                .validate_encryption_policy_immutable(
                    tenant,
                    &descriptor.definition,
                    &incoming_timestamp,
                    &existing_messages,
                )
                .await
            {
                return reply;
            }

            let (transition, incoming_is_newest, previous_definition) =
                match plan_configure_transition(message, &incoming_cid, &author, existing_messages)
                {
                    Ok(Some(plan)) => plan,
                    Ok(None) => return Response::conflict(),
                    Err(detail) => return Response::bad_request(detail),
                };
            if incoming_is_newest {
                if let Err(detail) = self
                    .validate_active_configuration(
                        tenant,
                        &descriptor.definition,
                        previous_definition.as_ref(),
                    )
                    .await
                {
                    return Response::bad_request(detail);
                }
            }
            // Covers: DWN-PROTO-004
            // The obligation to re-examine records is recorded before the
            // configuration it answers for is committed, so no crash can leave
            // an accepted history with nothing remembering to check it. If the
            // obligation cannot even be recorded, the configuration is refused:
            // nothing is durable yet, so a retry still changes something —
            // which is exactly what makes refusing better than accepting a
            // history this node could never repair against.
            let enlisted = match &self.repairer {
                Some(repairer) => {
                    match repairer.enlist(tenant, &descriptor.definition.module).await {
                        Ok(enlisted) => Some((repairer, enlisted)),
                        Err(detail) => return store_error_reply(detail),
                    }
                }
                None => None,
            };

            if let Err(err) = self
                .message_store
                .commit_latest_state(tenant, transition)
                .await
            {
                return store_error_reply(err.to_string());
            }

            // Only now, with the configuration durably accepted, are records
            // judged against it. Running before the commit would judge them
            // against a configuration that might never land.
            if let Some((repairer, enlisted)) = enlisted {
                if let Err(detail) = repairer.fulfil(enlisted).await {
                    // The configuration is accepted either way: it is durable,
                    // and a repair that could not run leaves records in place
                    // rather than half-removed. Reporting it as a failed
                    // configure would invite a retry that changes nothing —
                    // the obligation is still enlisted, and the recovery pass
                    // is what picks it up.
                    tracing::warn!(%tenant, detail, "control repair did not complete");
                }
            }

            Response::accepted()
        }
    }
}

impl<MessageStore> ModulesConfigureHandler<MessageStore>
where
    MessageStore: crate::stores::MessageStore + Clone + Send + Sync + 'static,
{
    /// Resolves the whole dependency closure at the given governing snapshot.
    async fn validate_composition_dependencies(
        &self,
        tenant: &str,
        definition: &Definition,
        message_timestamp: Option<&str>,
    ) -> Result<(), String> {
        let tenant = tenant.to_string();
        let store = self.message_store.clone();
        let message_timestamp = message_timestamp.map(str::to_string);
        load_module_graph(definition.clone(), move |uri| {
            let tenant = tenant.clone();
            let store = store.clone();
            let message_timestamp = message_timestamp.clone();
            async move {
                match fetch_module_definition(&tenant, &uri, &store, message_timestamp.as_deref())
                    .await
                {
                    Ok(definition) => Ok(Some(definition)),
                    Err(ModuleDefinitionLookupError::NotFound(_)) => Ok(None),
                    Err(error) => Err(ModuleGraphLoadError::Store(error.to_string())),
                }
            }
        })
        .await
        .map(|_| ())
        .map_err(|error| error.to_string())
    }

    /// Resolves a graph against an explicit snapshot, preferring the snapshot
    /// over the active store so old and new heads are compared independently.
    async fn load_graph(
        &self,
        tenant: &str,
        definition: &Definition,
        snapshot: &BTreeMap<String, Definition>,
    ) -> Result<ResolvedModuleGraph, ModuleGraphLoadError> {
        let tenant = tenant.to_string();
        let store = self.message_store.clone();
        let snapshot = snapshot.clone();
        load_module_graph(definition.clone(), move |uri| {
            let tenant = tenant.clone();
            let store = store.clone();
            let snapshot_definition = snapshot.get(&uri).cloned();
            async move {
                if let Some(definition) = snapshot_definition {
                    return Ok(Some(definition));
                }
                match fetch_module_definition(&tenant, &uri, &store, None).await {
                    Ok(definition) => Ok(Some(definition)),
                    Err(ModuleDefinitionLookupError::NotFound(_)) => Ok(None),
                    Err(error) => Err(ModuleGraphLoadError::Store(error.to_string())),
                }
            }
        })
        .await
    }

    /// Active heads validate their dependents; historical imports do not.
    async fn validate_active_configuration(
        &self,
        tenant: &str,
        incoming: &Definition,
        previous: Option<&Definition>,
    ) -> Result<(), String> {
        match previous {
            Some(previous) => {
                self.validate_composition_upgrade_compatibility(tenant, previous, incoming)
                    .await
            }
            // A late first installation must also bind against today's active
            // providers.
            None => {
                self.validate_composition_dependencies(tenant, incoming, None)
                    .await
            }
        }
    }

    /// Compares the active old and new snapshots without substituting
    /// historical configurations into either.
    async fn validate_composition_upgrade_compatibility(
        &self,
        tenant: &str,
        previous: &Definition,
        incoming: &Definition,
    ) -> Result<(), String> {
        let configurations = self
            .message_store
            .query(tenant, latest_configure_filters(), None, None, None)
            .await
            .map(|result| result.messages)
            .map_err(|error| error.to_string())?;
        let mut old_definitions = BTreeMap::new();
        for configuration in &configurations {
            let definition = modules_configure_descriptor(configuration)
                .map_err(|error| error.to_string())?
                .definition
                .clone();
            old_definitions.insert(definition.module.clone(), definition);
        }
        old_definitions.insert(previous.module.clone(), previous.clone());
        let mut new_definitions = old_definitions.clone();
        new_definitions.insert(incoming.module.clone(), incoming.clone());

        let old_graph = self
            .load_graph(tenant, previous, &old_definitions)
            .await
            .map_err(|error| error.to_string())?;
        let new_graph = self
            .load_graph(tenant, incoming, &new_definitions)
            .await
            .map_err(|error| error.to_string())?;

        let removes_attachment = old_graph.nodes_by_declared_path.iter().any(|(path, node)| {
            node.kind == ResolvedModuleNodeKind::Ref
                && !new_graph.nodes_by_declared_path.contains_key(path)
        });
        let introduces_attachment = new_graph.nodes_by_declared_path.iter().any(|(path, node)| {
            node.kind == ResolvedModuleNodeKind::Ref
                && !old_graph.nodes_by_declared_path.contains_key(path)
        });
        let stored_paths = if removes_attachment || introduces_attachment {
            self.stored_module_paths(tenant, &incoming.module).await?
        } else {
            BTreeSet::new()
        };
        validate_module_upgrade(previous, incoming, &old_graph, &new_graph, &stored_paths)
            .map_err(|error| error.to_string())?;

        // A changed module affects every current dependent reachable under
        // either snapshot.
        let affected = affected_modules(&old_definitions, &new_definitions, &incoming.module);
        for uri in dependency_order(&affected, &new_definitions) {
            if uri == incoming.module {
                continue;
            }
            let changed = async {
                let before = self
                    .load_graph(
                        tenant,
                        old_definitions.get(&uri).ok_or_else(|| {
                            ModuleGraphLoadError::Store(format!(
                                "dependent '{uri}' has no active definition"
                            ))
                        })?,
                        &old_definitions,
                    )
                    .await?;
                let after = self
                    .load_graph(
                        tenant,
                        new_definitions.get(&uri).ok_or_else(|| {
                            ModuleGraphLoadError::Store(format!(
                                "dependent '{uri}' has no active definition"
                            ))
                        })?,
                        &new_definitions,
                    )
                    .await?;
                validate_imported_module_contracts(&before, &after)
                    .map_err(ModuleGraphLoadError::Definition)
            }
            .await;
            if let Err(error) = changed {
                return Err(format!(
                    "ModulesConfigureIncompatibleContractUpdate: module '{}' update breaks dependent '{uri}': {error}",
                    incoming.module
                ));
            }
        }
        Ok(())
    }

    async fn stored_module_paths(
        &self,
        tenant: &str,
        module: &str,
    ) -> Result<BTreeSet<String>, String> {
        let filter = filter_map([
            ("interface", string_filter(RECORDS_INTERFACE)),
            ("method", string_filter(WRITE_METHOD)),
            ("module", string_filter(module)),
        ]);
        let messages = self
            .message_store
            .query(tenant, Filters::from(filter), None, None, None)
            .await
            .map(|result| result.messages)
            .map_err(|error| error.to_string())?;
        let mut paths = BTreeSet::new();
        for message in &messages {
            let descriptor =
                records_write_descriptor(message).map_err(|error| error.to_string())?;
            paths.insert(descriptor.module_path.clone());
        }
        Ok(paths)
    }

    #[allow(clippy::result_large_err)]
    async fn validate_encryption_policy_immutable(
        &self,
        tenant: &str,
        incoming: &Definition,
        incoming_timestamp: &str,
        existing: &[Message<Descriptor>],
    ) -> Result<(), Response<Configure>> {
        if existing.is_empty() {
            return Ok(());
        }

        let filter = filter_map([
            ("interface", string_filter(RECORDS_INTERFACE)),
            ("method", string_filter(WRITE_METHOD)),
            ("module", string_filter(&incoming.module)),
        ]);
        let records = self
            .message_store
            .query(tenant, Filters::from(filter), None, None, None)
            .await
            .map(|result| result.messages)
            .map_err(|err| store_error_reply(err.to_string()))?;
        let mut policy_by_path: BTreeMap<String, bool> = BTreeMap::new();
        for record in &records {
            let descriptor = records_write_descriptor(record)
                .map_err(|err| store_error_reply(err.to_string()))?;
            let module_path = descriptor.module_path.clone();
            if is_encryption_control_path(&module_path) {
                continue;
            }
            if incoming.rule_at(&module_path).is_none() {
                continue;
            }
            let required = match policy_by_path.get(&module_path) {
                Some(required) => *required,
                None => {
                    let required = self
                        .effective_incoming_policy(
                            tenant,
                            incoming,
                            &module_path,
                            incoming_timestamp,
                        )
                        .await?;
                    policy_by_path.insert(module_path.clone(), required);
                    required
                }
            };
            let encrypted = write_fields(record)
                .map(|fields| fields.encryption.is_some())
                .map_err(|err| store_error_reply(err.to_string()))?;
            if encrypted == required {
                continue;
            }
            return Err(Response::bad_request(format!(
                "ModulesConfigureEncryptionPolicyImmutable: cannot change encryption policy for module path '{module_path}' after records exist; install the changed definition under a new module URI."
            )));
        }

        Ok(())
    }

    #[allow(clippy::result_large_err)]
    async fn effective_incoming_policy(
        &self,
        tenant: &str,
        incoming: &Definition,
        module_path: &str,
        incoming_timestamp: &str,
    ) -> Result<bool, Response<Configure>> {
        if let Some(parsed) = incoming.ref_position(module_path) {
            let ref_uri = incoming
                .uses
                .as_ref()
                .and_then(|uses| uses.get(parsed.alias))
                .ok_or_else(|| {
                    Response::bad_request(format!(
                        "ModulesConfigureInvalidRefAlias: '$ref' alias '{}' at module path '{module_path}' does not exist in the 'uses' map.",
                        parsed.alias
                    ))
                })?;
            let referenced = fetch_module_definition(
                tenant,
                ref_uri,
                &self.message_store,
                Some(incoming_timestamp),
            )
            .await
            .map_err(|err| match err {
                ModuleDefinitionLookupError::NotFound(uri) => Response::bad_request(format!(
                    "ModuleAuthorizationModuleNotFound: unable to find module definition for {uri}"
                )),
                ModuleDefinitionLookupError::Store(detail) => store_error_reply(detail),
                ModuleDefinitionLookupError::InvalidMessage(detail) => {
                    Response::bad_request(detail)
                }
            })?;
            let type_name = parsed
                .module_path
                .split('/')
                .next_back()
                .unwrap_or_default();
            return Ok(referenced
                .types
                .get(type_name)
                .and_then(|module_type| module_type.encryption_required)
                == Some(true));
        }
        let type_name = module_path.split('/').next_back().unwrap_or_default();
        Ok(incoming
            .types
            .get(type_name)
            .and_then(|module_type| module_type.encryption_required)
            == Some(true))
    }
}

fn plan_configure_transition(
    incoming: Message<Descriptor>,
    incoming_cid: &str,
    incoming_author: &str,
    existing: Vec<Message<Descriptor>>,
) -> Result<Option<(LatestStateTransition, bool, Option<Definition>)>, String> {
    let mut comparable = Vec::with_capacity(existing.len());
    for message in &existing {
        let cid = message_cid(message)?;
        if cid == incoming_cid {
            return Ok(None);
        }
        comparable.push(cid);
    }

    let incoming_is_latest = existing.iter().zip(&comparable).all(|(message, cid)| {
        compare_configure_messages(incoming_cid, &incoming, cid, message) == Ordering::Greater
    });
    let newest_existing =
        existing
            .iter()
            .zip(&comparable)
            .max_by(|(left, left_cid), (right, right_cid)| {
                compare_configure_messages(left_cid, left, right_cid, right)
            });
    let latest_existing_cid = newest_existing.map(|(_, cid)| cid.clone());
    let previous_definition = newest_existing
        .map(|(message, _)| {
            modules_configure_descriptor(message).map(|descriptor| descriptor.definition.clone())
        })
        .transpose()?;

    let descriptor = modules_configure_descriptor(&incoming)?;
    let put = LatestStateMutation {
        indexes: configure_indexes(descriptor, Some(incoming_author), incoming_is_latest),
        message: incoming,
    };
    let retains = existing
        .into_iter()
        .zip(comparable)
        .map(|(message, cid)| {
            let descriptor = modules_configure_descriptor(&message)?;
            let author = extract_author(&message);
            Ok(LatestStateMutation {
                indexes: configure_indexes(
                    descriptor,
                    author.as_deref(),
                    !incoming_is_latest && latest_existing_cid.as_deref() == Some(cid.as_str()),
                ),
                message,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;

    Ok(Some((
        LatestStateTransition {
            put,
            retains,
            deletes: Vec::new(),
        },
        incoming_is_latest,
        previous_definition,
    )))
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum ModuleDefinitionLookupError {
    #[error("ModuleAuthorizationModuleNotFound: unable to find module definition for {0}")]
    NotFound(String),
    #[error("{0}")]
    Store(String),
    #[error("{0}")]
    InvalidMessage(String),
}

pub async fn fetch_module_definition<MessageStore>(
    tenant: &str,
    module_uri: &str,
    message_store: &MessageStore,
    message_timestamp: Option<&str>,
) -> Result<Definition, ModuleDefinitionLookupError>
where
    MessageStore: crate::stores::MessageStore + Sync,
{
    if let Some(definition) = CoreModuleRegistry::with_core_modules().get_definition(module_uri) {
        return Ok(definition);
    }

    let filters = module_definition_lookup_filters(module_uri, message_timestamp);
    let mut result = message_store
        .query(
            tenant,
            filters,
            Some(MessageSort::Timestamp(SortDirection::Descending)),
            Some(Pagination::with_limit(1)),
            None,
        )
        .await
        .map_err(|err| ModuleDefinitionLookupError::Store(err.to_string()))?;

    if result.messages.is_empty() && message_timestamp.is_some() {
        result = message_store
            .query(
                tenant,
                module_definition_history_filters(module_uri),
                Some(MessageSort::Timestamp(SortDirection::Ascending)),
                Some(Pagination::with_limit(1)),
                None,
            )
            .await
            .map_err(|err| ModuleDefinitionLookupError::Store(err.to_string()))?;
    }

    let Some(message) = result.messages.first() else {
        return Err(ModuleDefinitionLookupError::NotFound(
            module_uri.to_string(),
        ));
    };

    modules_configure_descriptor(message)
        .map(|descriptor| descriptor.definition.clone())
        .map_err(ModuleDefinitionLookupError::InvalidMessage)
}

/// Every module depending directly or transitively on `root` under either
/// snapshot.
fn affected_modules(
    old_definitions: &BTreeMap<String, Definition>,
    new_definitions: &BTreeMap<String, Definition>,
    root: &str,
) -> BTreeSet<String> {
    let mut affected = BTreeSet::from([root.to_string()]);
    loop {
        let mut expanded = false;
        for definition in old_definitions.values().chain(new_definitions.values()) {
            if affected.contains(&definition.module) {
                continue;
            }
            let depends = definition
                .uses
                .iter()
                .flat_map(|uses| uses.values())
                .any(|uri| affected.contains(uri));
            if depends {
                affected.insert(definition.module.clone());
                expanded = true;
            }
        }
        if !expanded {
            return affected;
        }
    }
}

/// Dependencies before their consumers, each level lexicographical.
fn dependency_order(
    affected: &BTreeSet<String>,
    definitions: &BTreeMap<String, Definition>,
) -> Vec<String> {
    fn visit(
        uri: &str,
        affected: &BTreeSet<String>,
        definitions: &BTreeMap<String, Definition>,
        visited: &mut BTreeSet<String>,
        order: &mut Vec<String>,
    ) {
        if !visited.insert(uri.to_string()) {
            return;
        }
        if let Some(definition) = definitions.get(uri) {
            let mut dependencies: Vec<&String> = definition
                .uses
                .iter()
                .flat_map(|uses| uses.values())
                .filter(|uri| affected.contains(*uri))
                .collect();
            dependencies.sort();
            dependencies.dedup();
            for dependency in dependencies {
                visit(dependency, affected, definitions, visited, order);
            }
        }
        order.push(uri.to_string());
    }

    let mut visited = BTreeSet::new();
    let mut order = Vec::new();
    for uri in affected {
        visit(uri, affected, definitions, &mut visited, &mut order);
    }
    order
}
