//! `#dwn` service inspection and rewriting for agent DID documents.

use super::{AgentIdentityError, AgentIdentityResult};

use serde_json::{json, Value as JsonValue};
use ssi_dids_core::document::Service;
use ssi_dids_core::Document;
use url::Url;

/// What a DID document advertises for the canonical `#dwn` service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DwnEndpointStatus {
    Ready(Vec<String>),
    ServiceMissing(String),
    ServiceMalformed(String),
}

impl DwnEndpointStatus {
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::Ready(_) => "",
            Self::ServiceMissing(message) | Self::ServiceMalformed(message) => message,
        }
    }
}

/// The ids accepted as the canonical DWN service.
///
/// The `did:dht` wire decoder expands a relative record id such as `dwn` to
/// `<did>#dwn`, so the typed `Document` boundary only carries absolute ids.
/// This matcher accepts every spelling because not every document source is
/// the wire decoder.
fn is_dwn_service_id(id: &str, did_uri: &str) -> bool {
    id == format!("{did_uri}#dwn") || id == "#dwn" || id == "dwn"
}

fn find_dwn_service<'a>(document: &'a Document, did_uri: &str) -> Option<&'a Service> {
    document
        .service
        .iter()
        .find(|service| is_dwn_service_id(service.id.as_str(), did_uri))
}

/// Normalize a non-empty HTTP(S) endpoint list, preserving order and dropping
/// duplicates. Returns `None` when any entry is not a bare HTTP(S) URL.
pub(crate) fn normalize_dwn_endpoints(values: &[String]) -> Option<Vec<String>> {
    if values.is_empty() {
        return None;
    }
    let mut endpoints = Vec::with_capacity(values.len());
    for value in values {
        let url = Url::parse(value).ok()?;
        if !matches!(url.scheme(), "http" | "https")
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return None;
        }
        let normalized = url.to_string();
        let normalized = normalized
            .strip_suffix('/')
            .unwrap_or(&normalized)
            .to_string();
        if !endpoints.contains(&normalized) {
            endpoints.push(normalized);
        }
    }
    Some(endpoints)
}

fn service_endpoint_urls(service: &Service) -> Option<Vec<String>> {
    let value = serde_json::to_value(service).ok()?;
    let values = match value.get("serviceEndpoint")? {
        JsonValue::String(value) => vec![value.clone()],
        JsonValue::Array(values) => values
            .iter()
            .map(|value| value.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()?,
        _ => return None,
    };
    normalize_dwn_endpoints(&values)
}

/// Read and validate the canonical `#dwn` service from a DID document.
pub(crate) fn dwn_endpoint_status(document: &Document, did_uri: &str) -> DwnEndpointStatus {
    let Some(service) = find_dwn_service(document, did_uri) else {
        return DwnEndpointStatus::ServiceMissing(format!(
            "DID '{did_uri}' does not advertise a #dwn service."
        ));
    };
    if serde_json::to_value(&service.type_).ok() != Some(json!("DecentralizedWebNode")) {
        return DwnEndpointStatus::ServiceMalformed(format!(
            "DID '{did_uri}' has a malformed #dwn service."
        ));
    }
    let Some(endpoints) = service_endpoint_urls(service) else {
        return DwnEndpointStatus::ServiceMalformed(format!(
            "DID '{did_uri}' has an invalid #dwn service endpoint."
        ));
    };
    DwnEndpointStatus::Ready(endpoints)
}

/// Clone `document` with only its canonical `#dwn` service endpoint URLs
/// replaced. Any other service is preserved.
pub(crate) fn replace_dwn_service_endpoint_urls(
    document: &Document,
    endpoint_urls: &[String],
) -> AgentIdentityResult<Document> {
    let did_uri = document.id.to_string();
    let endpoints = normalize_dwn_endpoints(endpoint_urls).ok_or_else(|| {
        AgentIdentityError::did(format!(
            "DID '{did_uri}' has an invalid #dwn service endpoint."
        ))
    })?;

    let mut service = find_dwn_service(document, &did_uri)
        .map(serde_json::to_value)
        .transpose()
        .map_err(|error| AgentIdentityError::did(format!("invalid DID service: {error}")))?
        .unwrap_or_else(|| json!({}));
    service["id"] = json!(format!("{did_uri}#dwn"));
    service["type"] = json!("DecentralizedWebNode");
    service["serviceEndpoint"] = json!(endpoints);
    let replacement: Service = serde_json::from_value(service)
        .map_err(|error| AgentIdentityError::did(format!("invalid DID service: {error}")))?;

    let mut updated = document.clone();
    updated
        .service
        .retain(|service| !is_dwn_service_id(service.id.as_str(), &did_uri));
    updated.service.push(replacement);
    Ok(updated)
}

/// Clone `target` and copy the resolved document's `#dwn` service onto it.
///
/// Every other resolved property stays out of the locally controlled document.
pub(crate) fn copy_resolved_dwn_service(target: &Document, source: &Document) -> Document {
    let did_uri = target.id.to_string();
    let mut updated = target.clone();
    updated
        .service
        .retain(|service| !is_dwn_service_id(service.id.as_str(), &did_uri));
    if let Some(service) = find_dwn_service(source, &source.id.to_string()).cloned() {
        updated.service.push(service);
    }
    updated
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:dht:qftx7z968xcpfy1a1diu75pg5meap3gdtg6ezagaw849wdh6oubo";

    fn document(service: JsonValue) -> Document {
        serde_json::from_value(json!({
            "id": DID,
            "service": [service],
        }))
        .unwrap()
    }

    // Covers: DID-DHT-006
    #[test]
    fn accepts_string_endpoints_and_id_variants() {
        for id in [format!("{DID}#dwn"), "#dwn".to_string(), "dwn".to_string()] {
            assert!(is_dwn_service_id(&id, DID), "{id}");
        }
        // Relative service ids are normalized to absolute ones on the wire.
        let document = document(json!({
            "id": format!("{DID}#dwn"),
            "type": "DecentralizedWebNode",
            "serviceEndpoint": "https://dwn.example/",
        }));
        assert_eq!(
            dwn_endpoint_status(&document, DID),
            DwnEndpointStatus::Ready(vec!["https://dwn.example".to_string()])
        );
    }

    // Covers: DID-DHT-006
    #[test]
    fn normalizes_and_deduplicates_endpoints() {
        assert_eq!(
            normalize_dwn_endpoints(&[
                "https://b.example/".to_string(),
                "https://a.example".to_string(),
                "https://b.example".to_string(),
            ]),
            Some(vec![
                "https://b.example".to_string(),
                "https://a.example".to_string()
            ])
        );
        for invalid in [
            vec![],
            vec!["ftp://dwn.example".to_string()],
            vec!["https://dwn.example/?x=1".to_string()],
            vec!["https://dwn.example/#x".to_string()],
            vec!["not a url".to_string()],
        ] {
            assert_eq!(normalize_dwn_endpoints(&invalid), None, "{invalid:?}");
        }
    }

    // Covers: DID-DHT-006
    #[test]
    fn rejects_missing_and_malformed_services() {
        let missing: Document = serde_json::from_value(json!({"id": DID})).unwrap();
        assert!(matches!(
            dwn_endpoint_status(&missing, DID),
            DwnEndpointStatus::ServiceMissing(_)
        ));

        for service in [
            json!({"id": format!("{DID}#dwn"), "type": "Other", "serviceEndpoint": ["https://dwn.example"]}),
            json!({"id": format!("{DID}#dwn"), "type": "DecentralizedWebNode", "serviceEndpoint": []}),
            json!({"id": format!("{DID}#dwn"), "type": "DecentralizedWebNode", "serviceEndpoint": [1]}),
        ] {
            assert!(matches!(
                dwn_endpoint_status(&document(service), DID),
                DwnEndpointStatus::ServiceMalformed(_)
            ));
        }
    }

    // Covers: DID-DHT-006
    #[test]
    fn replacement_rewrites_only_the_dwn_service() {
        let original = serde_json::from_value(json!({
            "id": DID,
            "service": [
                {"id": format!("{DID}#other"), "type": "Other", "serviceEndpoint": ["https://other.example"]},
                {"id": format!("{DID}#dwn"), "type": "DecentralizedWebNode", "serviceEndpoint": ["https://old.example"], "description": "keep me"},
            ],
        }))
        .unwrap();
        let updated = replace_dwn_service_endpoint_urls(
            &original,
            &[
                "https://new.example/".to_string(),
                "https://new.example".to_string(),
            ],
        )
        .unwrap();

        assert_eq!(updated.service.len(), 2);
        assert_eq!(updated.service[0].id.as_str(), format!("{DID}#other"));
        assert_eq!(updated.service[1].id.as_str(), format!("{DID}#dwn"));
        assert_eq!(
            service_endpoint_urls(&updated.service[1]),
            Some(vec!["https://new.example".to_string()])
        );
        assert_eq!(
            updated.service[1].property_set.get("description"),
            Some(&json!("keep me"))
        );
    }

    // Covers: DID-DHT-006
    #[test]
    fn copying_carries_the_resolved_service_only() {
        let target = document(json!({
            "id": format!("{DID}#dwn"),
            "type": "DecentralizedWebNode",
            "serviceEndpoint": ["https://old.example"],
        }));
        let mut source: Document = serde_json::from_value(json!({
            "id": DID,
            "alsoKnownAs": ["did:example:alias"],
            "service": [
                {"id": format!("{DID}#extra"), "type": "Other", "serviceEndpoint": ["https://extra.example"]},
                {"id": format!("{DID}#dwn"), "type": "DecentralizedWebNode", "serviceEndpoint": ["https://resolved.example"]},
            ],
        }))
        .unwrap();
        source.id = target.id.clone();

        let copied = copy_resolved_dwn_service(&target, &source);
        assert!(copied.also_known_as.is_empty());
        assert_eq!(copied.service.len(), 1);
        assert_eq!(
            service_endpoint_urls(&copied.service[0]),
            Some(vec!["https://resolved.example".to_string()])
        );
    }
}
