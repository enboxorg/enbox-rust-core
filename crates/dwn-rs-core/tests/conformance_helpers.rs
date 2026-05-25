//! Shared helpers for conformance fixture parsing in integration tests.

#![allow(dead_code)]

use std::fs;
use std::path::Path;

use serde::de::DeserializeOwned;
use serde_json::Value;

pub fn read_fixture<T: DeserializeOwned>(path: &Path) -> T {
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read fixture {}: {err}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|err| panic!("failed to parse fixture {}: {err}", path.display()))
}

pub fn expect_field<'a>(value: &'a Value, name: &str) -> &'a Value {
    value
        .get(name)
        .unwrap_or_else(|| panic!("fixture field `{name}` is missing from {}", value))
}

pub fn expect_str<'a>(value: &'a Value, name: &str) -> &'a str {
    expect_field(value, name)
        .as_str()
        .unwrap_or_else(|| panic!("fixture field `{name}` must be a string in {}", value))
}
