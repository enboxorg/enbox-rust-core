use serde::{Deserialize, Serialize};

use crate::Fields;

use super::{
    messages::Messages, protocols::Protocols, records::Records, MessageDescriptor,
    MessageValidator, ValidationError, MESSAGES, PROTOCOLS, RECORDS,
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

#[cfg(test)]
mod test {
    use serde_json::json;

    use crate::descriptors::{ReadDescriptor, READ};
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
