use chrono::{DateTime, Utc};
use serde::{Deserialize, Serializer};
use std::str::FromStr;

pub fn serialize_optional_datetime<S>(
    date: &Option<DateTime<Utc>>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match date {
        Some(date) => serialize_datetime(date, serializer),
        None => serializer.serialize_none(),
    }
}

pub fn serialize_datetime<S>(date: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&date.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
}

pub fn serialize_cid<S>(cid: &::cid::Cid, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&cid.to_string())
}

pub mod optional_cid_string {
    use super::*;

    pub fn serialize<S>(cid: &Option<::cid::Cid>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match cid {
            Some(cid) => serializer.serialize_str(&cid.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<::cid::Cid>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer)?
            .map(|cid| ::cid::Cid::from_str(&cid).map_err(serde::de::Error::custom))
            .transpose()
    }
}
