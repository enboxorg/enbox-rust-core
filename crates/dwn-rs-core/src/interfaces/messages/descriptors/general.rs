use serde::{Deserialize, Serialize};

use crate::Fields;

use super::{
    super::descriptors::{
        MessagesQueryDescriptor, MessagesReadDescriptor, MessagesSubscribeDescriptor,
        MessagesSyncDescriptor,
    },
    protocols::Protocols,
    records::Records,
    MessageDescriptor, MessageValidator, ValidationError, MESSAGES, PROTOCOLS, QUERY, READ, RECORDS,
    SUBSCRIBE, SYNC,
};

/// Interfaces represent the different Decentralized Web Node message interface types.
/// See <https://identity.foundation/decentralized-web-node/spec/#interfaces> for more information.
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Descriptor {
    Records(Box<Records>),
    Protocols(Box<Protocols>),
    Messages(Box<Messages>),
}

impl MessageValidator for Descriptor {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Descriptor::Records(_) => Ok(()),
            Descriptor::Protocols(_) => Ok(()),
            Descriptor::Messages(_) => Ok(()),
        }
    }
}

impl MessageDescriptor for Descriptor {
    type Fields = Fields;
    type Parameters = ();

    fn interface(&self) -> &'static str {
        match self {
            Descriptor::Records(_) => RECORDS,
            Descriptor::Protocols(_) => PROTOCOLS,
            Descriptor::Messages(_) => MESSAGES,
        }
    }

    fn method(&self) -> &'static str {
        match self {
            Descriptor::Records(records) => records.method(),
            Descriptor::Protocols(protocols) => protocols.method(),
            Descriptor::Messages(messages) => messages.method(),
        }
    }
}

#[derive(Serialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Messages {
    Read(MessagesReadDescriptor),
    Query(MessagesQueryDescriptor),
    Subscribe(MessagesSubscribeDescriptor),
    Sync(MessagesSyncDescriptor),
}

impl<'de> Deserialize<'de> for Messages {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let interface = value
            .get("interface")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("Messages descriptor missing interface"))?;
        if interface != MESSAGES {
            return Err(serde::de::Error::custom(format!(
                "expected Messages interface, found {interface}"
            )));
        }
        let method = value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("Messages descriptor missing method"))?;

        match method {
            READ => serde_json::from_value(value)
                .map(Messages::Read)
                .map_err(serde::de::Error::custom),
            QUERY => serde_json::from_value(value)
                .map(Messages::Query)
                .map_err(serde::de::Error::custom),
            SUBSCRIBE => serde_json::from_value(value)
                .map(Messages::Subscribe)
                .map_err(serde::de::Error::custom),
            SYNC => serde_json::from_value(value)
                .map(Messages::Sync)
                .map_err(serde::de::Error::custom),
            method => Err(serde::de::Error::custom(format!(
                "unsupported Messages method {method}"
            ))),
        }
    }
}

impl MessageValidator for Messages {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Messages::Read(_) => Ok(()),
            Messages::Query(_) => Ok(()),
            Messages::Subscribe(_) => Ok(()),
            Messages::Sync(_) => Ok(()),
        }
    }
}

impl MessageDescriptor for Messages {
    type Fields = Fields;
    type Parameters = ();

    fn interface(&self) -> &'static str {
        MESSAGES
    }

    fn method(&self) -> &'static str {
        match self {
            Messages::Read(_) => READ,
            Messages::Query(_) => QUERY,
            Messages::Subscribe(_) => SUBSCRIBE,
            Messages::Sync(_) => SYNC,
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::descriptors::ReadDescriptor;
    use crate::{canonical_rfc3339, filters::Records as RecordsFilter};

    #[test]
    fn test_descriptor_serialize() {
        use super::*;

        let now = chrono::Utc::now();
        let desc = Descriptor::Records(Box::new(Records::Read(Box::new(ReadDescriptor {
            message_timestamp: now,
            filter: RecordsFilter::default(),
            permission_grant_id: None,
            date_sort: None,
        }))));
        let serialized = json!(&desc);

        let fmt_now = canonical_rfc3339(now);
        let expected = json!({"interface": RECORDS,"method": READ, "messageTimestamp": fmt_now, "filter": RecordsFilter::default()});

        assert_eq!(serialized, expected);
    }
}
