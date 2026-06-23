pub mod descriptors;
pub mod fields;
pub mod protocols;

use std::collections::TryReserveError;

use crate::auth::{jws, Jws};
use crate::cid::generate_cid_from_serialized;
use crate::fields::MessageFields;
use crate::{auth::Authorization, interfaces::messages::descriptors::MessageParameters};
use cid::Cid;
pub use descriptors::Descriptor;
use descriptors::{MessageDescriptor, MessageValidator, RecordsWriteDescriptor, ValidationError};
pub use fields::Fields;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_ipld_dagcbor::EncodeError;
use ssi_jws::JwsSigner;

#[derive(Debug, Clone, PartialEq)]
pub struct Message<D: MessageDescriptor + DeserializeOwned> {
    pub descriptor: D,
    pub fields: D::Fields,
}

impl<D: MessageDescriptor + MessageValidator> Message<D> {
    pub fn new(descriptor: D, fields: D::Fields) -> Result<Self, ValidationError> {
        descriptor.validate()?;

        Ok(Self { descriptor, fields })
    }
}

impl Message<RecordsWriteDescriptor> {
    // attest is used to add an attestation to a message. It can be called multiple
    // times to add multiple attestations. The message must be a RecordsWriteDescriptor.
    pub async fn attest<S: JwsSigner>(&mut self, signers: Vec<S>) -> Result<(), ValidationError> {
        let descriptor_cid = self.descriptor.cid();

        let payload = jws::AttestationPayload { descriptor_cid };

        let signature = jws::Jws::create(payload, Some(signers))
            .await
            .map_err(|e| ValidationError {
                message: e.to_string(),
            })?;

        self.fields.attestation = Some(signature);

        Ok(())
    }

    pub fn unattest<S: JwsSigner>(&mut self) -> Result<(), ValidationError> {
        self.fields.attestation = None;

        Ok(())
    }
}

impl<D> Message<D>
where
    D: MessageDescriptor,
{
    pub fn cid(&self) -> Result<Cid, EncodeError<TryReserveError>> {
        generate_cid_from_serialized(self)
    }
}

impl<D> Message<D>
where
    D: MessageDescriptor + DeserializeOwned,
    D::Parameters: MessageParameters<Descriptor = D, Fields = D::Fields>,
{
    pub async fn create<S: JwsSigner>(
        parameters: D::Parameters,
        signer: Option<S>,
    ) -> Result<Self, ValidationError> {
        let (descriptor, fields) = parameters.build().await?;

        let auth = if let Some(signer) = signer {
            Self::create_authorization(
                &descriptor,
                signer,
                parameters.delegated_grant().clone(),
                parameters.permission_grant_id().clone(),
                parameters.protocol_rule().clone(),
            )
            .await?
        } else {
            Authorization::default()
        };

        // If the fields are None, we create an empty Fields instance.
        let mut fields = fields.unwrap_or_default();
        fields.set_authorization(auth);

        Ok(Self { descriptor, fields })
    }

    async fn create_authorization<S: JwsSigner>(
        descriptor: &D,
        signer: S,
        delegated_grant: Option<Message<RecordsWriteDescriptor>>,
        permission_grant_id: Option<String>,
        protocol_role: Option<String>,
    ) -> Result<Authorization, ValidationError> {
        let delegated_grant_id: Option<Cid> = if let Some(delegated_grant) = delegated_grant.clone()
        {
            Some(delegated_grant.cid().map_err(|err| ValidationError {
                message: err.to_string(),
            })?)
        } else {
            None
        };

        let signature = Self::create_signature(
            descriptor,
            signer,
            delegated_grant_id,
            permission_grant_id,
            protocol_role,
        )
        .await?;

        let mut authorization = Authorization {
            signature,
            ..Default::default()
        };

        if let Some(grant) = delegated_grant {
            authorization.author_delegated_grant = Some(Box::new(grant));
        }

        Ok(authorization)
    }

    async fn create_signature<S: JwsSigner>(
        descriptor: &D,
        signer: S,
        delegated_grant_id: Option<Cid>,
        permission_grant_id: Option<String>,
        protocol_role: Option<String>,
    ) -> Result<Jws, ValidationError> {
        let descriptor_cid = descriptor.cid();

        let payload = jws::Payload {
            descriptor_cid,
            delegated_grant_id,
            permission_grant_id,
            protocol_role,
        };

        let signature = jws::Jws::create(payload, Some(vec![signer]))
            .await
            .map_err(|e| ValidationError {
                message: e.to_string(),
            })?;

        Ok(signature)
    }
}

impl<D> Serialize for Message<D>
where
    D: MessageDescriptor + Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        #[derive(Serialize)]
        struct TempMessage<'a, D: MessageDescriptor> {
            descriptor: &'a D,
            #[serde(flatten)]
            other: &'a D::Fields,
        }

        let temp_message = TempMessage {
            descriptor: &self.descriptor,
            other: &self.fields,
        };

        temp_message.serialize(serializer)
    }
}

// Custom deserializer for the untyped `Message<Descriptor>`. The `Descriptor` union dispatches
// on the `interface`/`method` fields (via the generated `Records`/`Protocols`/`Messages` enums)
// to pick the concrete descriptor when the type is not known at compile time. Concrete
// `Message<D>` deserializers are generated instead by the `#[descriptor]` macro (and, for the
// interface unions, by `#[interface]`), each validating `interface`/`method` against the
// descriptor's `ConcreteDescriptor` consts.
impl<'de> Deserialize<'de> for Message<Descriptor> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct TempMessage {
            descriptor: Descriptor,
            #[serde(flatten)]
            other: Fields,
        }

        let temp_message = TempMessage::deserialize(deserializer)?;

        Ok(Self {
            descriptor: temp_message.descriptor,
            fields: temp_message.other,
        })
    }
}

impl<D> Message<D>
where
    D: MessageDescriptor + DeserializeOwned,
    Message<D>: DeserializeOwned,
{
    /// Deserialize a typed `Message<D>` from a `serde_json::Value`.
    ///
    /// Wraps `serde_json::from_value` in a method on `Message`. Useful when
    /// the JSON value comes from an FFI boundary or a fixture file and the
    /// caller wants the strongly-typed descriptor variant rather than the
    /// untyped [`Descriptor`] union. Use [`Message::deserialize`] (via
    /// `serde_json::from_str`) when reading from a string slice.
    ///
    /// This is type-safe: the descriptor's `#[serde(try_from)]` impl rejects a
    /// value whose `interface`/`method` do not match `D`, so deserializing a
    /// message of the wrong kind into `Message<D>` returns an error rather than
    /// silently producing a mismatched value.
    pub fn from_value(value: serde_json::Value) -> Result<Self, serde_json::Error> {
        serde_json::from_value(value)
    }
}

#[cfg(test)]
mod test {

    use chrono::Utc;
    use descriptors::{ReadDescriptor, Records, RecordsWriteDescriptor};
    use dwn_rs_message_derive::descriptor;
    use fields::MessageFields;
    use serde_json::json;

    use crate::{auth::Authorization, canonical_rfc3339};

    use super::*;

    #[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
    struct TestParameters {}

    impl MessageParameters for TestParameters {
        type Descriptor = TestDescriptor;
        type Fields = TestFields;
    }

    const INTERFACE: &str = "interface";
    const METHOD: &str = "method";
    #[descriptor(interface = INTERFACE, method = METHOD, fields = TestFields, parameters = TestParameters)]
    struct TestDescriptor {
        data: String,
    }

    impl MessageValidator for TestDescriptor {
        fn validate(&self) -> Result<(), ValidationError> {
            if self.data.is_empty() {
                return Err(ValidationError {
                    message: "data".to_string(),
                });
            }
            Ok(())
        }
    }

    #[derive(Serialize, Default, Deserialize, Clone, PartialEq, Debug)]
    struct TestFields {
        field1: String,
        field2: i32,
    }
    impl MessageFields for TestFields {}

    #[test]
    fn test_message_serialize() {
        let desc = TestDescriptor {
            data: "test".to_string(),
        };
        let fields = TestFields {
            field1: "test".to_string(),
            field2: 42,
        };

        let message = Message::new(desc, fields).unwrap();

        let serialized = serde_json::to_string(&message).unwrap();
        let expected = r#"{"descriptor":{"data":"test","interface":"interface","method":"method"},"field1":"test","field2":42}"#;

        assert_eq!(serialized, expected);

        let now = Utc::now();

        let desc = Descriptor::Records(Box::new(Records::Read(Box::new(ReadDescriptor {
            message_timestamp: now,
            filter: crate::filters::Records::default(),
            permission_grant_id: None,
            date_sort: None,
        }))));
        let fields = Fields::Authorization(Authorization {
            ..Default::default()
        });

        let message = Message::new(desc, fields).unwrap();
        let serialized = json!(&message);
        let fmt_now = canonical_rfc3339(now);
        let expected = json!({
                "descriptor": {
                    "messageTimestamp": fmt_now,
                    "filter": crate::filters::Records::default(),
                    "interface":"Records","method":"Read"
                },
                "signature":{}
        });

        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_message_deserialize() {
        let serialized = r#"{"descriptor":{"data":"test","interface":"interface","method":"method"},"field1":"test","field2":42}"#;

        let message: Message<TestDescriptor> = serde_json::from_str(serialized).unwrap();

        let descriptor = TestDescriptor {
            data: "test".to_string(),
        };

        let fields = TestFields {
            field1: "test".to_string(),
            field2: 42,
        };

        let expected = Message::new(descriptor, fields).unwrap();

        assert_eq!(message, expected);
    }

    #[test]
    fn typed_message_from_value_round_trips() {
        let descriptor = TestDescriptor {
            data: "round-trip".to_string(),
        };
        let fields = TestFields {
            field1: "value".to_string(),
            field2: 7,
        };
        let original = Message::new(descriptor, fields).unwrap();

        let value = serde_json::to_value(&original).unwrap();
        let recovered = Message::<TestDescriptor>::from_value(value).unwrap();

        assert_eq!(recovered, original);
    }

    #[test]
    fn typed_from_value_rejects_wrong_method() {
        // Structurally valid for `TestDescriptor`, but `method` does not match — the
        // descriptor's `try_from` (via `#[serde(try_from)]`) must reject it.
        let value = json!({
            "descriptor": {"data": "test", "interface": "interface", "method": "wrong"},
            "field1": "test",
            "field2": 42,
        });

        assert!(Message::<TestDescriptor>::from_value(value).is_err());
    }

    #[test]
    fn typed_from_value_rejects_wrong_interface() {
        let value = json!({
            "descriptor": {"data": "test", "interface": "wrong", "method": "method"},
            "field1": "test",
            "field2": 42,
        });

        assert!(Message::<TestDescriptor>::from_value(value).is_err());
    }

    #[test]
    fn typed_from_value_rejects_mismatched_descriptor_kind() {
        // A real RecordsRead message must not deserialize into a RecordsWrite-typed `Message`.
        let now = Utc::now();
        let read = Message::new(
            Descriptor::Records(Box::new(Records::Read(Box::new(ReadDescriptor {
                message_timestamp: now,
                filter: crate::filters::Records::default(),
                permission_grant_id: None,
                date_sort: None,
            })))),
            Fields::Authorization(Authorization::default()),
        )
        .unwrap();
        let value = serde_json::to_value(&read).unwrap();

        assert!(Message::<RecordsWriteDescriptor>::from_value(value).is_err());
    }
}
