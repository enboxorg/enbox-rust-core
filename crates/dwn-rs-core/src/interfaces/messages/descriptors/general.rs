use serde::{Deserialize, Serialize};

use crate::Fields;

use super::{
    super::descriptors::{
        ConfigureDescriptor, DeleteDescriptor, MessagesQueryDescriptor, MessagesReadDescriptor,
        MessagesSubscribeDescriptor, ProtocolQueryDescriptor, ReadDescriptor,
        RecordsCountDescriptor, RecordsQueryDescriptor, RecordsWriteDescriptor,
        SubscribeDescriptor,
    },
    MessageDescriptor, MessageValidator, ValidationError, CONFIGURE, COUNT, DELETE, MESSAGES,
    PROTOCOLS, QUERY, READ, RECORDS, SUBSCRIBE, WRITE,
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
pub enum Records {
    Read(Box<ReadDescriptor>),
    Count(Box<RecordsCountDescriptor>),
    Query(Box<RecordsQueryDescriptor>),
    Write(Box<RecordsWriteDescriptor>),
    Delete(Box<DeleteDescriptor>),
    Subscribe(Box<SubscribeDescriptor>),
}

impl<'de> Deserialize<'de> for Records {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let interface = value
            .get("interface")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("Records descriptor missing interface"))?;
        if interface != RECORDS {
            return Err(serde::de::Error::custom(format!(
                "expected Records interface, found {interface}"
            )));
        }
        let method = value
            .get("method")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::custom("Records descriptor missing method"))?;

        match method {
            READ => serde_json::from_value(value)
                .map(Box::new)
                .map(Records::Read)
                .map_err(serde::de::Error::custom),
            COUNT => serde_json::from_value(value)
                .map(Box::new)
                .map(Records::Count)
                .map_err(serde::de::Error::custom),
            QUERY => serde_json::from_value(value)
                .map(Box::new)
                .map(Records::Query)
                .map_err(serde::de::Error::custom),
            WRITE => serde_json::from_value(value)
                .map(Box::new)
                .map(Records::Write)
                .map_err(serde::de::Error::custom),
            DELETE => serde_json::from_value(value)
                .map(Box::new)
                .map(Records::Delete)
                .map_err(serde::de::Error::custom),
            SUBSCRIBE => serde_json::from_value(value)
                .map(Box::new)
                .map(Records::Subscribe)
                .map_err(serde::de::Error::custom),
            method => Err(serde::de::Error::custom(format!(
                "unsupported Records method {method}"
            ))),
        }
    }
}

impl MessageValidator for Records {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Records::Read(_) => Ok(()),
            Records::Count(_) => Ok(()),
            Records::Query(_) => Ok(()),
            Records::Write(_) => Ok(()),
            Records::Delete(_) => Ok(()),
            Records::Subscribe(_) => Ok(()),
        }
    }
}

impl MessageDescriptor for Records {
    type Fields = Fields;
    type Parameters = ();

    fn interface(&self) -> &'static str {
        RECORDS
    }

    fn method(&self) -> &'static str {
        match self {
            Records::Read(_) => READ,
            Records::Count(_) => COUNT,
            Records::Query(_) => QUERY,
            Records::Write(_) => WRITE,
            Records::Delete(_) => DELETE,
            Records::Subscribe(_) => SUBSCRIBE,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Protocols {
    Configure(ConfigureDescriptor),
    Query(ProtocolQueryDescriptor),
}

impl MessageValidator for Protocols {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Protocols::Configure(_) => Ok(()),
            Protocols::Query(_) => Ok(()),
        }
    }
}

impl MessageDescriptor for Protocols {
    type Fields = Fields;
    type Parameters = ();

    fn interface(&self) -> &'static str {
        PROTOCOLS
    }

    fn method(&self) -> &'static str {
        match self {
            Protocols::Configure(_) => CONFIGURE,
            Protocols::Query(_) => QUERY,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
#[serde(untagged)]
pub enum Messages {
    Read(MessagesReadDescriptor),
    Query(MessagesQueryDescriptor),
    Subscribe(MessagesSubscribeDescriptor),
}

impl MessageValidator for Messages {
    fn validate(&self) -> Result<(), ValidationError> {
        match self {
            Messages::Read(_) => Ok(()),
            Messages::Query(_) => Ok(()),
            Messages::Subscribe(_) => Ok(()),
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
        }
    }
}

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::filters::Records as RecordsFilter;

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

        let fmt_now = now.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let expected = json!({"interface": RECORDS,"method": READ, "messageTimestamp": fmt_now, "filter": RecordsFilter::default()});

        assert_eq!(serialized, expected);
    }
}
