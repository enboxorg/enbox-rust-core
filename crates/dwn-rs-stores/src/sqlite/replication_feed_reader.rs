use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct FeedEntry {
    pub(crate) tenant: String,
    pub(crate) position: i64,
    pub(crate) message_cid: String,
    pub(crate) indexes_json: String,
    #[serde(
        rename = "fingerprint_scopes_json",
        deserialize_with = "deserialize_json_string_to_array"
    )]
    pub(crate) fingerprint_scopes: Vec<String>,
}

fn deserialize_json_string_to_array<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    serde_json::from_str(&s).map_err(serde::de::Error::custom)
}
