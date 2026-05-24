use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Number;
use serde_with::skip_serializing_none;
use ssi_jwk::JWK;
use thiserror::Error;
use url::Url;

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Type {
    pub schema: Option<String>,
    #[serde(rename = "dataFormats")]
    pub data_formats: Option<Vec<String>>,
    #[serde(rename = "encryptionRequired")]
    pub encryption_required: Option<bool>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Default, Clone)]
pub struct Definition {
    pub protocol: String,
    pub published: bool,
    pub uses: Option<BTreeMap<String, String>>,
    pub types: BTreeMap<String, Type>,
    pub structure: BTreeMap<String, RuleSet>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Who {
    #[serde(rename = "anyone")]
    Anyone,
    #[serde(rename = "author")]
    Author,
    #[serde(rename = "recipient")]
    Recipient,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Clone)]
pub enum Can {
    #[serde(rename = "co-delete")]
    CoDelete,
    #[serde(rename = "co-prune")]
    CoPrune,
    #[serde(rename = "co-update")]
    CoUpdate,
    #[serde(rename = "create")]
    Create,
    #[serde(rename = "delete")]
    Delete,
    #[serde(rename = "prune")]
    Prune,
    #[serde(rename = "read")]
    Read,
    #[serde(rename = "update")]
    Update,
    #[serde(rename = "subscribe")]
    Subscribe,
    #[serde(rename = "query")]
    Query,
    #[serde(rename = "squash")]
    Squash,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[skip_serializing_none]
pub struct ActionWho {
    pub who: Who,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub of: Option<String>,
    pub can: Vec<Can>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ActionRole {
    pub role: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub can: Vec<Can>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[skip_serializing_none]
#[serde(untagged)]
pub enum Action {
    Who(ActionWho),
    Role(ActionRole),
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[skip_serializing_none]
pub struct PathEncryption {
    #[serde(rename = "rootKeyId")]
    pub root_key_id: String,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: JWK,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[skip_serializing_none]
pub struct Size {
    pub min: Option<u64>,
    pub max: Option<u64>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Default, Debug, PartialEq, Clone)]
pub struct RuleSet {
    #[serde(rename = "$encryption")]
    pub encryption: Option<PathEncryption>,
    #[serde(rename = "$actions", default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<Action>,
    #[serde(rename = "$role")]
    pub role: Option<bool>,
    #[serde(rename = "$ref")]
    pub reference: Option<String>,
    #[serde(rename = "$size")]
    pub size: Option<Size>,
    #[serde(rename = "$tags")]
    pub tags: Option<Tags>,
    #[serde(rename = "$recordLimit")]
    pub record_limit: Option<RecordLimit>,
    #[serde(rename = "$immutable")]
    pub immutable: Option<bool>,
    #[serde(rename = "$delivery")]
    pub delivery: Option<String>,
    #[serde(rename = "$squash")]
    pub squash: Option<bool>,
    #[serde(flatten, skip_serializing_if = "BTreeMap::is_empty")]
    pub rules: BTreeMap<String, RuleSet>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct RecordLimit {
    pub max: u64,
    pub strategy: String,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Tags {
    #[serde(
        rename = "$requiredTags",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub required_tags: Vec<String>,
    #[serde(rename = "$allowUndefinedTags")]
    pub allow_undefined_tags: Option<bool>,
    #[serde(flatten)]
    pub tags: BTreeMap<String, ProvidedTags>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum TagType {
    #[serde(rename = "string")]
    String,
    #[serde(rename = "number")]
    Number,
    #[serde(rename = "integer")]
    Integer,
    #[serde(rename = "boolean")]
    Boolean,
    #[serde(rename = "array")]
    Array,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub enum ItemType {
    #[serde(rename = "string")]
    String,
    #[serde(rename = "number")]
    Number,
    #[serde(rename = "integer")]
    Integer,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum TagValue {
    String(String),
    Number(Number),
    Boolean(bool),
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct ProvidedTags {
    #[serde(rename = "type")]
    pub tag_type: TagType,
    pub items: Option<TagItems>,
    pub contains: Option<TagContains>,
    #[serde(rename = "enum", default, skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<TagValue>,
    #[serde(rename = "maxLength")]
    pub max_length: Option<usize>,
    #[serde(rename = "minLength")]
    pub min_length: Option<usize>,
    pub minimum: Option<usize>,
    pub maximum: Option<usize>,
    #[serde(rename = "exclusiveMinimum")]
    pub exclusive_minimum: Option<usize>,
    #[serde(rename = "exclusiveMaximum")]
    pub exclusive_maximum: Option<usize>,
    #[serde(rename = "minItems")]
    pub min_items: Option<usize>,
    #[serde(rename = "maxItems")]
    pub max_items: Option<usize>,
    #[serde(rename = "uniqueItems")]
    pub unique_items: Option<bool>,
    #[serde(rename = "minContains")]
    pub min_contains: Option<usize>,
    #[serde(rename = "maxContains")]
    pub max_contains: Option<usize>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TagItems {
    #[serde(rename = "type")]
    pub tag_type: ItemType,
    #[serde(rename = "enum", default, skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<TagValue>,
    pub minimum: Option<usize>,
    pub maximum: Option<usize>,
    #[serde(rename = "exclusiveMinimum")]
    pub exclusive_minimum: Option<usize>,
    #[serde(rename = "exclusiveMaximum")]
    pub exclusive_maximum: Option<usize>,
    #[serde(rename = "minLength")]
    pub min_length: Option<usize>,
    #[serde(rename = "maxLength")]
    pub max_length: Option<usize>,
}

#[skip_serializing_none]
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct TagContains {
    #[serde(rename = "type")]
    pub tag_type: ItemType,
    #[serde(rename = "enum", default, skip_serializing_if = "Vec::is_empty")]
    pub enum_values: Vec<TagValue>,
    pub minimum: Option<usize>,
    pub maximum: Option<usize>,
    #[serde(rename = "exclusiveMinimum")]
    pub exclusive_minimum: Option<usize>,
    #[serde(rename = "exclusiveMaximum")]
    pub exclusive_maximum: Option<usize>,
    #[serde(rename = "minLength")]
    pub min_length: Option<usize>,
    #[serde(rename = "maxLength")]
    pub max_length: Option<usize>,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error("{code}: {message}")]
pub struct ProtocolDefinitionError {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossProtocolRef<'a> {
    pub alias: &'a str,
    pub protocol_path: &'a str,
}

pub fn validate_definition(definition: &Definition) -> Result<(), ProtocolDefinitionError> {
    validate_normalized_protocol_url(&definition.protocol)?;

    for (type_name, protocol_type) in &definition.types {
        if let Some(schema) = &protocol_type.schema {
            validate_normalized_schema_url(schema).map_err(|_| {
                protocol_error(
                    "UrlSchemaNotNormalized",
                    format!("Schema URI {schema} for type {type_name} must be normalized."),
                )
            })?;
        }
    }

    if let Some(uses) = &definition.uses {
        validate_uses(uses, &definition.protocol)?;
    }

    validate_structure(definition)
}

pub fn get_rule_set_at_path<'a>(
    protocol_path: &str,
    structure: &'a BTreeMap<String, RuleSet>,
) -> Option<&'a RuleSet> {
    let mut current = structure;
    let mut rule_set = None;
    for segment in protocol_path
        .split('/')
        .filter(|segment| !segment.is_empty())
    {
        let next = current.get(segment)?;
        rule_set = Some(next);
        current = &next.rules;
    }
    rule_set
}

pub fn parse_cross_protocol_ref(value: &str) -> Option<CrossProtocolRef<'_>> {
    let (alias, protocol_path) = value.split_once(':')?;
    if alias.is_empty() || protocol_path.is_empty() || protocol_path.contains(':') {
        return None;
    }
    Some(CrossProtocolRef {
        alias,
        protocol_path,
    })
}

fn validate_uses(
    uses: &BTreeMap<String, String>,
    own_protocol_uri: &str,
) -> Result<(), ProtocolDefinitionError> {
    for (alias, protocol_uri) in uses {
        if !is_valid_uses_alias(alias) {
            return Err(protocol_error(
                "ProtocolsConfigureInvalidUsesAlias",
                format!("invalid 'uses' alias '{alias}'"),
            ));
        }

        validate_normalized_protocol_url(protocol_uri).map_err(|_| {
            protocol_error(
                "ProtocolsConfigureInvalidUsesProtocolUrl",
                format!(
                    "invalid 'uses' protocol URL for alias '{alias}': '{protocol_uri}' is not a valid normalized protocol URL."
                ),
            )
        })?;

        if protocol_uri == own_protocol_uri {
            return Err(protocol_error(
                "ProtocolsConfigureInvalidUsesSelfReference",
                format!(
                    "'uses' alias '{alias}' references the protocol's own URI '{own_protocol_uri}'."
                ),
            ));
        }
    }
    Ok(())
}

fn validate_structure(definition: &Definition) -> Result<(), ProtocolDefinitionError> {
    let record_types = definition.types.keys().cloned().collect::<Vec<_>>();
    let mut roles = Vec::new();
    fetch_role_paths("", &definition.structure, &mut roles)?;

    validate_rule_map(
        "",
        &definition.structure,
        &record_types,
        &roles,
        definition.uses.as_ref(),
        &definition.types,
    )
}

fn fetch_role_paths(
    protocol_path: &str,
    rules: &BTreeMap<String, RuleSet>,
    roles: &mut Vec<String>,
) -> Result<(), ProtocolDefinitionError> {
    if !protocol_path.is_empty() && protocol_path.split('/').count() > 10 {
        return Err(protocol_error(
            "ProtocolsConfigureRecordNestingDepthExceeded",
            "Record nesting depth exceeded 10 levels.",
        ));
    }

    for (record_type, rule_set) in rules {
        let child_path = child_protocol_path(protocol_path, record_type);
        if rule_set.role == Some(true) {
            roles.push(child_path);
        } else {
            fetch_role_paths(&child_path, &rule_set.rules, roles)?;
        }
    }

    Ok(())
}

fn validate_rule_map(
    protocol_path: &str,
    rules: &BTreeMap<String, RuleSet>,
    record_types: &[String],
    roles: &[String],
    uses: Option<&BTreeMap<String, String>>,
    types: &BTreeMap<String, Type>,
) -> Result<(), ProtocolDefinitionError> {
    for (record_type, rule_set) in rules {
        if rule_set.reference.is_none()
            && !record_types
                .iter()
                .any(|candidate| candidate == record_type)
        {
            return Err(protocol_error(
                "ProtocolsConfigureInvalidRuleSetRecordType",
                format!(
                    "Rule set {record_type} is not declared as an allowed type in the protocol definition."
                ),
            ));
        }

        let child_path = child_protocol_path(protocol_path, record_type);
        validate_rule_set(&child_path, rule_set, roles, uses, types)?;
        validate_rule_map(
            &child_path,
            &rule_set.rules,
            record_types,
            roles,
            uses,
            types,
        )?;
    }

    Ok(())
}

fn validate_rule_set(
    protocol_path: &str,
    rule_set: &RuleSet,
    roles: &[String],
    uses: Option<&BTreeMap<String, String>>,
    types: &BTreeMap<String, Type>,
) -> Result<(), ProtocolDefinitionError> {
    if rule_set.reference.is_some() {
        if protocol_path.contains('/') {
            return Err(protocol_error(
                "ProtocolsConfigureInvalidRefNotAtRoot",
                format!(
                    "'$ref' at protocol path '{protocol_path}' is not allowed: '$ref' nodes are only supported at the root level of the structure."
                ),
            ));
        }
        validate_ref_node(protocol_path, rule_set, uses)?;
    }

    if let Some(size) = &rule_set.size {
        let min = size.min.unwrap_or(0);
        if let Some(max) = size.max {
            if max < min {
                return Err(protocol_error(
                    "ProtocolsConfigureInvalidSize",
                    format!(
                        "Invalid size range found: max limit {max} less than min limit {min} at protocol path '{protocol_path}'"
                    ),
                ));
            }
        }
    }

    if let Some(record_limit) = &rule_set.record_limit {
        if record_limit.max < 1
            || !matches!(record_limit.strategy.as_str(), "reject" | "purgeOldest")
        {
            return Err(protocol_error(
                "ProtocolsConfigureInvalidRecordLimit",
                format!(
                    "Invalid $recordLimit at protocol path '{protocol_path}': max must be >= 1 and strategy must be reject or purgeOldest."
                ),
            ));
        }
    }

    validate_actions(protocol_path, &rule_set.actions, roles, uses)?;

    if let Some(type_name) = protocol_path.split('/').next_back() {
        if types
            .get(type_name)
            .and_then(|protocol_type| protocol_type.encryption_required)
            == Some(true)
        {
            // TypeScript only warns when encrypted records are readable by anyone.
        }
    }

    Ok(())
}

fn validate_ref_node(
    protocol_path: &str,
    rule_set: &RuleSet,
    uses: Option<&BTreeMap<String, String>>,
) -> Result<(), ProtocolDefinitionError> {
    let reference = rule_set.reference.as_deref().unwrap_or_default();
    let parsed = parse_cross_protocol_ref(reference).ok_or_else(|| {
        protocol_error(
            "ProtocolsConfigureInvalidRefAlias",
            format!(
                "'$ref' value '{reference}' at protocol path '{protocol_path}' must be in 'alias:typePath' format."
            ),
        )
    })?;

    if uses.and_then(|uses| uses.get(parsed.alias)).is_none() {
        return Err(protocol_error(
            "ProtocolsConfigureInvalidRefAlias",
            format!(
                "'$ref' alias '{}' at protocol path '{}' does not exist in the 'uses' map.",
                parsed.alias, protocol_path
            ),
        ));
    }

    if !rule_set.actions.is_empty()
        || rule_set.role.is_some()
        || rule_set.size.is_some()
        || rule_set.tags.is_some()
        || rule_set.encryption.is_some()
        || rule_set.record_limit.is_some()
        || rule_set.immutable.is_some()
        || rule_set.delivery.is_some()
        || rule_set.squash.is_some()
    {
        return Err(protocol_error(
            "ProtocolsConfigureInvalidRefNodeHasDirectives",
            format!("'$ref' node at protocol path '{protocol_path}' must not have directives."),
        ));
    }

    Ok(())
}

fn validate_actions(
    protocol_path: &str,
    actions: &[Action],
    roles: &[String],
    uses: Option<&BTreeMap<String, String>>,
) -> Result<(), ProtocolDefinitionError> {
    let mut seen_roles = Vec::<String>::new();
    let mut seen_actors = Vec::<(Who, Option<String>)>::new();

    for action in actions {
        match action {
            Action::Role(action) => {
                if parse_cross_protocol_ref(&action.role).is_some() {
                    validate_cross_protocol_alias(
                        &action.role,
                        uses,
                        protocol_path,
                        "role",
                        "ProtocolsConfigureInvalidCrossProtocolRole",
                    )?;
                } else if !roles.iter().any(|role| role == &action.role) {
                    return Err(protocol_error(
                        "ProtocolsConfigureRoleDoesNotExistAtGivenPath",
                        format!(
                            "Role '{}' for rule set {} does not exist.",
                            action.role, protocol_path
                        ),
                    ));
                }

                if seen_roles.iter().any(|role| role == &action.role) {
                    return Err(protocol_error(
                        "ProtocolsConfigureDuplicateRoleInRuleSet",
                        format!(
                            "More than one action rule per role {} not allowed within a rule set.",
                            action.role
                        ),
                    ));
                }
                seen_roles.push(action.role.clone());
                validate_action_can(protocol_path, &action.can)?;
            }
            Action::Who(action) => {
                if action.who == Who::Anyone && action.of.is_some() {
                    return Err(protocol_error(
                        "ProtocolsConfigureInvalidActionOfNotAllowed",
                        format!("'of' is not allowed at rule set protocol path ({protocol_path})"),
                    ));
                }

                if action.who == Who::Recipient && action.of.is_none() {
                    let allowed = [Can::CoUpdate, Can::CoDelete, Can::CoPrune];
                    if action.can.iter().any(|can| !allowed.contains(can)) {
                        return Err(protocol_error(
                            "ProtocolsConfigureInvalidRecipientOfAction",
                            "Rules for `recipient` without `of` property must have can containing only co-update, co-delete, and co-prune.",
                        ));
                    }
                }

                if action.who == Who::Author && action.of.is_none() {
                    return Err(protocol_error(
                        "ProtocolsConfigureInvalidActionMissingOf",
                        "'of' is required when 'author' is specified as 'who'",
                    ));
                }

                if let Some(of) = &action.of {
                    if parse_cross_protocol_ref(of).is_some() {
                        validate_cross_protocol_alias(
                            of,
                            uses,
                            protocol_path,
                            "of",
                            "ProtocolsConfigureInvalidCrossProtocolOf",
                        )?;
                    } else if !protocol_path.is_empty()
                        && protocol_path != of
                        && !protocol_path.starts_with(&format!("{of}/"))
                    {
                        return Err(protocol_error(
                            "ProtocolsConfigureInvalidActionOfNotAnAncestor",
                            format!(
                                "'of' value '{of}' is not an ancestor of protocol path '{protocol_path}'."
                            ),
                        ));
                    }
                }

                if seen_actors
                    .iter()
                    .any(|(who, of)| who == &action.who && of == &action.of)
                {
                    return Err(protocol_error(
                        "ProtocolsConfigureDuplicateActorInRuleSet",
                        format!(
                            "More than one action rule per actor {:?} of {:?} not allowed within a rule set.",
                            action.who, action.of
                        ),
                    ));
                }
                seen_actors.push((action.who.clone(), action.of.clone()));
                validate_action_can(protocol_path, &action.can)?;
            }
        }
    }

    Ok(())
}

fn validate_action_can(protocol_path: &str, can: &[Can]) -> Result<(), ProtocolDefinitionError> {
    let has_create = can.contains(&Can::Create);
    for (action, code) in [
        (
            Can::Update,
            "ProtocolsConfigureInvalidActionUpdateWithoutCreate",
        ),
        (
            Can::Delete,
            "ProtocolsConfigureInvalidActionDeleteWithoutCreate",
        ),
        (
            Can::Prune,
            "ProtocolsConfigureInvalidActionPruneWithoutCreate",
        ),
    ] {
        if can.contains(&action) && !has_create {
            return Err(protocol_error(
                code,
                format!("Action rule at protocol path '{protocol_path}' contains {action:?} but missing create."),
            ));
        }
    }
    Ok(())
}

fn validate_cross_protocol_alias(
    value: &str,
    uses: Option<&BTreeMap<String, String>>,
    protocol_path: &str,
    field_name: &str,
    code: &'static str,
) -> Result<(), ProtocolDefinitionError> {
    let parsed = parse_cross_protocol_ref(value).ok_or_else(|| {
        protocol_error(
            code,
            format!(
                "cross-protocol '{field_name}' reference '{value}' at protocol path '{protocol_path}' could not be parsed."
            ),
        )
    })?;

    if uses.and_then(|uses| uses.get(parsed.alias)).is_none() {
        return Err(protocol_error(
            code,
            format!(
                "cross-protocol '{field_name}' alias '{}' in '{}' at protocol path '{}' does not exist in the 'uses' map.",
                parsed.alias, value, protocol_path
            ),
        ));
    }
    Ok(())
}

fn validate_normalized_protocol_url(value: &str) -> Result<(), ProtocolDefinitionError> {
    let normalized = normalize_protocol_url(value).map_err(|_| {
        protocol_error(
            "UrlProtocolNotNormalized",
            format!("Protocol URI {value} must be normalized."),
        )
    })?;
    if value != normalized {
        return Err(protocol_error(
            "UrlProtocolNotNormalized",
            format!("Protocol URI {value} must be normalized."),
        ));
    }
    Ok(())
}

fn validate_normalized_schema_url(value: &str) -> Result<(), ProtocolDefinitionError> {
    let normalized = normalize_protocol_url(value).map_err(|_| {
        protocol_error(
            "UrlSchemaNotNormalized",
            format!("Schema URI {value} must be normalized."),
        )
    })?;
    if value != normalized {
        return Err(protocol_error(
            "UrlSchemaNotNormalized",
            format!("Schema URI {value} must be normalized."),
        ));
    }
    Ok(())
}

fn normalize_protocol_url(value: &str) -> Result<String, url::ParseError> {
    let full_url = if has_url_scheme(value) {
        value.to_string()
    } else {
        format!("http://{value}")
    };
    let mut url = Url::parse(&full_url)?;
    url.set_query(None);
    url.set_fragment(None);
    let mut normalized = url.to_string();
    if normalized.ends_with('/') {
        normalized.pop();
    }
    Ok(normalized)
}

fn has_url_scheme(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    !scheme.is_empty()
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        && (!rest.starts_with('/') || rest.starts_with("//"))
}

fn is_valid_uses_alias(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic() && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn child_protocol_path(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}/{child}")
    }
}

fn protocol_error(code: &'static str, message: impl Into<String>) -> ProtocolDefinitionError {
    ProtocolDefinitionError {
        code,
        message: message.into(),
    }
}
