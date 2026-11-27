use std::fmt::Display;

use crate::descriptors::messages::MessagesMethod as DescriptorMessagesMethod;
use crate::descriptors::modules::ModulesMethod as DescriptorModulesMethod;
use crate::descriptors::records::RecordsMethod as DescriptorRecordsMethod;
use crate::descriptors::{Interface, MessageKind};
use crate::descriptors::{CONFIGURE, DELETE, MESSAGES, MODULES, QUERY, READ, RECORDS, WRITE};
use crate::filters::message_filters::Messages as MessagesFilter;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PermissionScope {
    Modules(ModulesScope),
    Messages(MessagesScope),
    Records(RecordsScope),
}

impl PermissionScope {
    pub fn is_unscoped(&self) -> bool {
        matches!(
            self,
            Self::Messages(MessagesScope {
                module: None,
                selector: None,
            })
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModulesScope {
    pub method: ModulesMethod,
    pub module: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModulesMethod {
    Configure,
    Query,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessagesScope {
    pub module: Option<String>,
    pub selector: Option<MessagesSelector>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessagesSelector {
    ContextId(ContextId),
    ModulePath(ModulePath),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordsScope {
    pub method: RecordsMethod,
    pub module: String,
    pub selector: Option<RecordsSelector>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordsMethod {
    Read,
    Write,
    Delete,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecordsSelector {
    ContextId(ContextId),
    ModulePath(ModulePath),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextId(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModulePath(pub String);

impl PermissionScope {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Messages(MessagesScope {
                module: None,
                selector: Some(_),
            }) => Err("Messages permission scope selectors require module"),
            _ => Ok(()),
        }
    }

    pub fn method(&self) -> &'static str {
        match self {
            Self::Modules(ModulesScope {
                method: ModulesMethod::Configure,
                ..
            }) => CONFIGURE,
            Self::Modules(ModulesScope {
                method: ModulesMethod::Query,
                ..
            }) => QUERY,
            Self::Messages(_) => READ,
            Self::Records(RecordsScope {
                method: RecordsMethod::Read,
                ..
            }) => READ,
            Self::Records(RecordsScope {
                method: RecordsMethod::Write,
                ..
            }) => WRITE,
            Self::Records(RecordsScope {
                method: RecordsMethod::Delete,
                ..
            }) => DELETE,
        }
    }

    pub fn interface(&self) -> Interface {
        match self {
            Self::Modules(_) => Interface::Modules,
            Self::Messages(_) => Interface::Messages,
            Self::Records(_) => Interface::Records,
        }
    }

    /// Typed scope→operation capability mapping. Replaces the string
    /// comparison in `perform_base_validation`; decisions are unchanged.
    pub fn covers(&self, kind: &MessageKind) -> bool {
        match (self, kind) {
            (Self::Messages(_), MessageKind::Messages(method)) => {
                matches!(
                    method,
                    DescriptorMessagesMethod::Read
                        | DescriptorMessagesMethod::Query
                        | DescriptorMessagesMethod::Subscribe
                )
            }
            (
                Self::Records(RecordsScope {
                    method: RecordsMethod::Read,
                    ..
                }),
                MessageKind::Records(method),
            ) => {
                matches!(
                    method,
                    DescriptorRecordsMethod::Read
                        | DescriptorRecordsMethod::Query
                        | DescriptorRecordsMethod::Subscribe
                        | DescriptorRecordsMethod::Count
                )
            }
            (
                Self::Records(RecordsScope {
                    method: RecordsMethod::Write,
                    ..
                }),
                MessageKind::Records(DescriptorRecordsMethod::Write),
            ) => true,
            (
                Self::Records(RecordsScope {
                    method: RecordsMethod::Delete,
                    ..
                }),
                MessageKind::Records(DescriptorRecordsMethod::Delete),
            ) => true,
            (
                Self::Modules(ModulesScope {
                    method: ModulesMethod::Configure,
                    ..
                }),
                MessageKind::Modules(DescriptorModulesMethod::Configure),
            ) => true,
            (
                Self::Modules(ModulesScope {
                    method: ModulesMethod::Query,
                    ..
                }),
                MessageKind::Modules(DescriptorModulesMethod::Query),
            ) => true,
            _ => false,
        }
    }

    pub fn module(&self) -> Option<&str> {
        match self {
            Self::Modules(scope) => scope.module.as_deref(),
            Self::Messages(scope) => scope.module.as_deref(),
            Self::Records(scope) => Some(&scope.module),
        }
    }

    pub fn context_id(&self) -> Option<&str> {
        match self {
            Self::Messages(MessagesScope {
                selector: Some(MessagesSelector::ContextId(ContextId(id))),
                ..
            })
            | Self::Records(RecordsScope {
                selector: Some(RecordsSelector::ContextId(ContextId(id))),
                ..
            }) => Some(id),
            _ => None,
        }
    }

    pub fn module_path(&self) -> Option<&str> {
        match self {
            Self::Messages(MessagesScope {
                selector: Some(MessagesSelector::ModulePath(ModulePath(path))),
                ..
            })
            | Self::Records(RecordsScope {
                selector: Some(RecordsSelector::ModulePath(ModulePath(path))),
                ..
            }) => Some(path),
            _ => None,
        }
    }

    pub fn matches_module_target(&self, target: &ModuleScopeTarget<'_>) -> bool {
        let module_match = self.module().is_none() || self.module() == target.module;
        let context_id_match = self.context_id().is_none()
            || matches_subtree(self.context_id().unwrap_or(""), target.context_id);
        let module_path_match = self.module_path().is_none()
            || matches_subtree(self.module_path().unwrap_or(""), target.module_path);

        module_match && context_id_match && module_path_match
    }
}

fn matches_subtree(scope: &str, target: Option<&str>) -> bool {
    target == Some(scope)
        || target
            .is_some_and(|v| v.starts_with(scope) && v.as_bytes().get(scope.len()) == Some(&b'/'))
}

#[derive(Serialize)]
struct SerializedPermissionScope<'a> {
    interface: &'static str,
    method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    module: Option<&'a str>,
    #[serde(rename = "contextId", skip_serializing_if = "Option::is_none")]
    context_id: Option<&'a str>,
    #[serde(rename = "modulePath", skip_serializing_if = "Option::is_none")]
    module_path: Option<&'a str>,
}

impl Serialize for PermissionScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        SerializedPermissionScope {
            interface: self.interface().as_str(),
            method: self.method(),
            module: self.module(),
            context_id: self.context_id(),
            module_path: self.module_path(),
        }
        .serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleScopeTarget<'a> {
    pub module: Option<&'a str>,
    pub context_id: Option<&'a str>,
    pub module_path: Option<&'a str>,
}

impl Display for ModuleScopeTarget<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ModuleScopeTarget {{ module: {:?}, context_id: {:?}, module_path: {:?} }}",
            self.module, self.context_id, self.module_path
        )
    }
}

impl<'a> From<&'a MessagesFilter> for ModuleScopeTarget<'a> {
    fn from(value: &'a MessagesFilter) -> Self {
        Self {
            module: value.module.as_deref(),
            context_id: value.context_id_prefix.as_deref(),
            module_path: value
                .module_path
                .as_deref()
                .or(value.module_path_prefix.as_deref()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedModuleScopeTarget {
    pub module: Option<String>,
    pub context_id: Option<String>,
    pub module_path: Option<String>,
}

impl OwnedModuleScopeTarget {
    pub fn as_ref(&self) -> ModuleScopeTarget<'_> {
        ModuleScopeTarget {
            module: self.module.as_deref(),
            context_id: self.context_id.as_deref(),
            module_path: self.module_path.as_deref(),
        }
    }
}

impl<'de> Deserialize<'de> for PermissionScope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct RawPermissionScope {
            interface: String,
            method: String,
            module: Option<String>,
            #[serde(rename = "contextId")]
            context_id: Option<String>,
            #[serde(rename = "modulePath")]
            module_path: Option<String>,
        }

        let raw = RawPermissionScope::deserialize(deserializer)?;
        let selector_count =
            usize::from(raw.context_id.is_some()) + usize::from(raw.module_path.is_some());
        if selector_count > 1 {
            return Err(serde::de::Error::custom(
                "permission scope cannot contain both contextId and modulePath",
            ));
        }

        match (raw.interface.as_str(), raw.method.as_str()) {
            (MODULES, CONFIGURE) | (MODULES, QUERY) => {
                if raw.context_id.is_some() || raw.module_path.is_some() {
                    return Err(serde::de::Error::custom(
                        "Modules permission scopes cannot contain contextId or modulePath",
                    ));
                }
                let method = if raw.method == CONFIGURE {
                    ModulesMethod::Configure
                } else {
                    ModulesMethod::Query
                };
                Ok(Self::Modules(ModulesScope {
                    method,
                    module: raw.module,
                }))
            }
            (MESSAGES, READ) => {
                let module = raw.module;
                let selector = match (raw.context_id, raw.module_path) {
                    (Some(context_id), None) => {
                        Some(MessagesSelector::ContextId(ContextId(context_id)))
                    }
                    (None, Some(module_path)) => {
                        Some(MessagesSelector::ModulePath(ModulePath(module_path)))
                    }
                    (None, None) => None,
                    (Some(_), Some(_)) => unreachable!("checked above"),
                };
                if selector.is_some() && module.is_none() {
                    return Err(serde::de::Error::custom(
                        "Messages permission scope selectors require module",
                    ));
                }
                Ok(Self::Messages(MessagesScope { module, selector }))
            }
            (RECORDS, READ) | (RECORDS, WRITE) | (RECORDS, DELETE) => {
                let method = match raw.method.as_str() {
                    READ => RecordsMethod::Read,
                    WRITE => RecordsMethod::Write,
                    DELETE => RecordsMethod::Delete,
                    _ => unreachable!("matched above"),
                };
                let module = raw.module.ok_or_else(|| {
                    serde::de::Error::custom("Records permission scopes require module")
                })?;
                let selector = match (raw.context_id, raw.module_path) {
                    (Some(context_id), None) => {
                        Some(RecordsSelector::ContextId(ContextId(context_id)))
                    }
                    (None, Some(module_path)) => {
                        Some(RecordsSelector::ModulePath(ModulePath(module_path)))
                    }
                    (None, None) => None,
                    (Some(_), Some(_)) => unreachable!("checked above"),
                };
                Ok(Self::Records(RecordsScope {
                    method,
                    module,
                    selector,
                }))
            }
            _ => Err(serde::de::Error::custom(format!(
                "unsupported permission scope interface/method pair: {}/{}",
                raw.interface, raw.method
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_value};

    #[test]
    fn serializes_each_legal_scope_shape_with_fixed_discriminants() {
        let module = "https://example.com/notes".to_string();
        let scopes = [
            PermissionScope::Modules(ModulesScope {
                method: ModulesMethod::Configure,
                module: Some(module.clone()),
            }),
            PermissionScope::Messages(MessagesScope {
                module: Some(module.clone()),
                selector: Some(MessagesSelector::ContextId(ContextId("ctx-1".to_string()))),
            }),
            PermissionScope::Records(RecordsScope {
                method: RecordsMethod::Delete,
                module,
                selector: Some(RecordsSelector::ModulePath(ModulePath("note".to_string()))),
            }),
        ];

        let values = scopes.map(|scope| to_value(scope).unwrap());
        assert_eq!(
            values[0],
            serde_json::json!({
                "interface": "Modules",
                "method": "Configure",
                "module": "https://example.com/notes"
            })
        );
        assert_eq!(
            values[1],
            serde_json::json!({
                "interface": "Messages",
                "method": "Read",
                "module": "https://example.com/notes",
                "contextId": "ctx-1"
            })
        );
        assert_eq!(
            values[2],
            serde_json::json!({
                "interface": "Records",
                "method": "Delete",
                "module": "https://example.com/notes",
                "modulePath": "note"
            })
        );
    }

    #[test]
    fn deserializes_and_round_trips_legal_scope_shapes() {
        for json in [
            r#"{"interface":"Modules","method":"Query"}"#,
            r#"{"interface":"Messages","method":"Read","module":"https://example.com/notes","modulePath":"note"}"#,
            r#"{"interface":"Records","method":"Read","module":"https://example.com/notes","contextId":"ctx-1"}"#,
        ] {
            let scope: PermissionScope = from_str(json).unwrap();
            let round_trip: PermissionScope =
                serde_json::from_value(to_value(&scope).unwrap()).unwrap();
            assert_eq!(round_trip, scope);
        }
    }

    #[test]
    fn rejects_illegal_interface_method_pairs_and_selector_shapes() {
        for json in [
            r#"{"interface":"Messages","method":"Query"}"#,
            r#"{"interface":"Messages","method":"Sync"}"#,
            r#"{"interface":"Records","method":"Query","module":"https://example.com/notes"}"#,
            r#"{"interface":"Records","method":"Read"}"#,
            r#"{"interface":"Messages","method":"Read","contextId":"ctx-1"}"#,
            r#"{"interface":"Records","method":"Read","module":"https://example.com/notes","contextId":"ctx-1","modulePath":"note"}"#,
            r#"{"interface":"Modules","method":"Query","contextId":"ctx-1"}"#,
            r#"{"interface":"messages","method":"Read"}"#,
        ] {
            assert!(
                from_str::<PermissionScope>(json).is_err(),
                "expected rejection for {json}"
            );
        }
    }

    #[test]
    fn rejects_unknown_fields_and_invalid_programmatic_message_scope() {
        let unknown_field = r#"{"interface":"Messages","method":"Read","unexpected":true}"#;
        assert!(from_str::<PermissionScope>(unknown_field).is_err());

        let invalid = PermissionScope::Messages(MessagesScope {
            module: None,
            selector: Some(MessagesSelector::ContextId(ContextId("ctx-1".to_string()))),
        });
        assert!(serde_json::to_value(invalid).is_err());
    }

    #[test]
    fn matches_module_target() {
        let notes_scope = PermissionScope::Records(RecordsScope {
            method: RecordsMethod::Read,
            module: "https://example.com/notes".to_string(),
            selector: None,
        });
        let notes_scope_with_context = PermissionScope::Records(RecordsScope {
            method: RecordsMethod::Read,
            module: "https://example.com/notes".to_string(),
            selector: Some(RecordsSelector::ContextId(ContextId("c/1".to_string()))),
        });

        let notes_scope_with_module = PermissionScope::Records(RecordsScope {
            method: RecordsMethod::Read,
            module: "https://example.com/notes".to_string(),
            selector: Some(RecordsSelector::ModulePath(ModulePath("a/b".to_string()))),
        });
        let unscoped_messages_scope = PermissionScope::Messages(MessagesScope {
            module: None,
            selector: None,
        });

        let tt = [
            // Records scope { module: notes }
            (
                &notes_scope,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: None,
                    module_path: None,
                },
                true,
            ),
            (
                &notes_scope,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: Some("ctx-1"),
                    module_path: None,
                },
                true,
            ),
            (
                &notes_scope,
                ModuleScopeTarget {
                    module: Some("https://example.com/chat"),
                    context_id: None,
                    module_path: None,
                },
                false,
            ),
            (
                &notes_scope,
                ModuleScopeTarget {
                    module: None,
                    context_id: None,
                    module_path: None,
                },
                false,
            ),
            // Records scope { module: notes, contextId: c/1 }
            (
                &notes_scope_with_context,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: Some("c/1"),
                    module_path: None,
                },
                true,
            ),
            (
                &notes_scope_with_context,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: Some("c/1/x"),
                    module_path: None,
                },
                true,
            ),
            (
                &notes_scope_with_context,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: Some("c/10"),
                    module_path: None,
                },
                false,
            ),
            (
                &notes_scope_with_context,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: None,
                    module_path: None,
                },
                false,
            ),
            // Records scope { module: notes, modulePath: a/b }
            (
                &notes_scope_with_module,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: None,
                    module_path: Some("a/b"),
                },
                true,
            ),
            (
                &notes_scope_with_module,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: None,
                    module_path: Some("a/b/c"),
                },
                true,
            ),
            (
                &notes_scope_with_module,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: None,
                    module_path: Some("a/x"),
                },
                false,
            ),
            (
                &notes_scope_with_module,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: None,
                    module_path: Some("a/bc"),
                },
                false,
            ),
            (
                &unscoped_messages_scope,
                ModuleScopeTarget {
                    module: Some("https://example.com/notes"),
                    context_id: Some("ctx-1"),
                    module_path: Some("note"),
                },
                true,
            ),
            (
                &unscoped_messages_scope,
                ModuleScopeTarget {
                    module: None,
                    context_id: None,
                    module_path: None,
                },
                true,
            ),
        ];

        for (scope, target, expected) in tt {
            assert_eq!(
                scope.matches_module_target(&target),
                expected,
                "scope: {:?}, target: {:?}",
                scope,
                target
            );
        }
    }
}
