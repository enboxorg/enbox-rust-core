use crate::descriptors::{CONFIGURE, DELETE, MESSAGES, PROTOCOLS, QUERY, READ, RECORDS, WRITE};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PermissionScope {
    Protocols(ProtocolsScope),
    Messages(MessagesScope),
    Records(RecordsScope),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolsScope {
    pub method: ProtocolsMethod,
    pub protocol: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProtocolsMethod {
    Configure,
    Query,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessagesScope {
    pub protocol: Option<String>,
    pub selector: Option<MessagesSelector>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MessagesSelector {
    ContextId(ContextId),
    ProtocolPath(ProtocolPath),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordsScope {
    pub method: RecordsMethod,
    pub protocol: String,
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
    ProtocolPath(ProtocolPath),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContextId(pub String);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtocolPath(pub String);

impl PermissionScope {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self {
            Self::Messages(MessagesScope {
                protocol: None,
                selector: Some(_),
            }) => Err("Messages permission scope selectors require protocol"),
            _ => Ok(()),
        }
    }

    pub fn interface(&self) -> &'static str {
        match self {
            Self::Protocols(_) => PROTOCOLS,
            Self::Messages(_) => MESSAGES,
            Self::Records(_) => RECORDS,
        }
    }

    pub fn method(&self) -> &'static str {
        match self {
            Self::Protocols(ProtocolsScope {
                method: ProtocolsMethod::Configure,
                ..
            }) => CONFIGURE,
            Self::Protocols(ProtocolsScope {
                method: ProtocolsMethod::Query,
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

    pub fn protocol(&self) -> Option<&str> {
        match self {
            Self::Protocols(scope) => scope.protocol.as_deref(),
            Self::Messages(scope) => scope.protocol.as_deref(),
            Self::Records(scope) => Some(&scope.protocol),
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

    pub fn protocol_path(&self) -> Option<&str> {
        match self {
            Self::Messages(MessagesScope {
                selector: Some(MessagesSelector::ProtocolPath(ProtocolPath(path))),
                ..
            })
            | Self::Records(RecordsScope {
                selector: Some(RecordsSelector::ProtocolPath(ProtocolPath(path))),
                ..
            }) => Some(path),
            _ => None,
        }
    }
}

#[derive(Serialize)]
struct SerializedPermissionScope<'a> {
    interface: &'static str,
    method: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<&'a str>,
    #[serde(rename = "contextId", skip_serializing_if = "Option::is_none")]
    context_id: Option<&'a str>,
    #[serde(rename = "protocolPath", skip_serializing_if = "Option::is_none")]
    protocol_path: Option<&'a str>,
}

impl Serialize for PermissionScope {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.validate().map_err(serde::ser::Error::custom)?;
        SerializedPermissionScope {
            interface: self.interface(),
            method: self.method(),
            protocol: self.protocol(),
            context_id: self.context_id(),
            protocol_path: self.protocol_path(),
        }
        .serialize(serializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{from_str, to_value};

    #[test]
    fn serializes_each_legal_scope_shape_with_fixed_discriminants() {
        let protocol = "https://example.com/notes".to_string();
        let scopes = [
            PermissionScope::Protocols(ProtocolsScope {
                method: ProtocolsMethod::Configure,
                protocol: Some(protocol.clone()),
            }),
            PermissionScope::Messages(MessagesScope {
                protocol: Some(protocol.clone()),
                selector: Some(MessagesSelector::ContextId(ContextId("ctx-1".to_string()))),
            }),
            PermissionScope::Records(RecordsScope {
                method: RecordsMethod::Delete,
                protocol,
                selector: Some(RecordsSelector::ProtocolPath(ProtocolPath(
                    "note".to_string(),
                ))),
            }),
        ];

        let values = scopes.map(|scope| to_value(scope).unwrap());
        assert_eq!(
            values[0],
            serde_json::json!({
                "interface": "Protocols",
                "method": "Configure",
                "protocol": "https://example.com/notes"
            })
        );
        assert_eq!(
            values[1],
            serde_json::json!({
                "interface": "Messages",
                "method": "Read",
                "protocol": "https://example.com/notes",
                "contextId": "ctx-1"
            })
        );
        assert_eq!(
            values[2],
            serde_json::json!({
                "interface": "Records",
                "method": "Delete",
                "protocol": "https://example.com/notes",
                "protocolPath": "note"
            })
        );
    }

    #[test]
    fn deserializes_and_round_trips_legal_scope_shapes() {
        for json in [
            r#"{"interface":"Protocols","method":"Query"}"#,
            r#"{"interface":"Messages","method":"Read","protocol":"https://example.com/notes","protocolPath":"note"}"#,
            r#"{"interface":"Records","method":"Read","protocol":"https://example.com/notes","contextId":"ctx-1"}"#,
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
            r#"{"interface":"Records","method":"Query","protocol":"https://example.com/notes"}"#,
            r#"{"interface":"Records","method":"Read"}"#,
            r#"{"interface":"Messages","method":"Read","contextId":"ctx-1"}"#,
            r#"{"interface":"Records","method":"Read","protocol":"https://example.com/notes","contextId":"ctx-1","protocolPath":"note"}"#,
            r#"{"interface":"Protocols","method":"Query","contextId":"ctx-1"}"#,
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
            protocol: None,
            selector: Some(MessagesSelector::ContextId(ContextId("ctx-1".to_string()))),
        });
        assert!(serde_json::to_value(invalid).is_err());
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
            protocol: Option<String>,
            #[serde(rename = "contextId")]
            context_id: Option<String>,
            #[serde(rename = "protocolPath")]
            protocol_path: Option<String>,
        }

        let raw = RawPermissionScope::deserialize(deserializer)?;
        let selector_count =
            usize::from(raw.context_id.is_some()) + usize::from(raw.protocol_path.is_some());
        if selector_count > 1 {
            return Err(serde::de::Error::custom(
                "permission scope cannot contain both contextId and protocolPath",
            ));
        }

        match (raw.interface.as_str(), raw.method.as_str()) {
            (PROTOCOLS, CONFIGURE) | (PROTOCOLS, QUERY) => {
                if raw.context_id.is_some() || raw.protocol_path.is_some() {
                    return Err(serde::de::Error::custom(
                        "Protocols permission scopes cannot contain contextId or protocolPath",
                    ));
                }
                let method = if raw.method == CONFIGURE {
                    ProtocolsMethod::Configure
                } else {
                    ProtocolsMethod::Query
                };
                Ok(Self::Protocols(ProtocolsScope {
                    method,
                    protocol: raw.protocol,
                }))
            }
            (MESSAGES, READ) => {
                let protocol = raw.protocol;
                let selector = match (raw.context_id, raw.protocol_path) {
                    (Some(context_id), None) => {
                        Some(MessagesSelector::ContextId(ContextId(context_id)))
                    }
                    (None, Some(protocol_path)) => {
                        Some(MessagesSelector::ProtocolPath(ProtocolPath(protocol_path)))
                    }
                    (None, None) => None,
                    (Some(_), Some(_)) => unreachable!("checked above"),
                };
                if selector.is_some() && protocol.is_none() {
                    return Err(serde::de::Error::custom(
                        "Messages permission scope selectors require protocol",
                    ));
                }
                Ok(Self::Messages(MessagesScope { protocol, selector }))
            }
            (RECORDS, READ) | (RECORDS, WRITE) | (RECORDS, DELETE) => {
                let method = match raw.method.as_str() {
                    READ => RecordsMethod::Read,
                    WRITE => RecordsMethod::Write,
                    DELETE => RecordsMethod::Delete,
                    _ => unreachable!("matched above"),
                };
                let protocol = raw.protocol.ok_or_else(|| {
                    serde::de::Error::custom("Records permission scopes require protocol")
                })?;
                let selector = match (raw.context_id, raw.protocol_path) {
                    (Some(context_id), None) => {
                        Some(RecordsSelector::ContextId(ContextId(context_id)))
                    }
                    (None, Some(protocol_path)) => {
                        Some(RecordsSelector::ProtocolPath(ProtocolPath(protocol_path)))
                    }
                    (None, None) => None,
                    (Some(_), Some(_)) => unreachable!("checked above"),
                };
                Ok(Self::Records(RecordsScope {
                    method,
                    protocol,
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
