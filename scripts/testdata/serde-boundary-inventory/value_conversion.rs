//! Fixture: generic Value/map conversion into protected types plus actual
//! decoder call sites (case 7). Scanner must link from_str/from_value calls
//! to the Protected target type and flag Value/map routing.

use serde::Deserialize;
use serde_json::{Map, Value};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protected {
    pub identity: String,
    pub scope: String,
    pub authority: String,
}

pub fn decode_protected_str(text: &str) -> Result<Protected, serde_json::Error> {
    serde_json::from_str::<Protected>(text)
}

pub fn decode_protected_value(value: Value) -> Result<Protected, serde_json::Error> {
    serde_json::from_value::<Protected>(value)
}

pub fn map_into_protected(map: Map<String, Value>) -> Result<Protected, serde_json::Error> {
    serde_json::from_value::<Protected>(Value::Object(map))
}
