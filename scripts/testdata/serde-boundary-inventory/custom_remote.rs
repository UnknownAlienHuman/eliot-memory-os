//! Fixture: remote/with/deserialize_with helpers (case 5).
//! Expect two candidates (RemoteProxy with remote evidence, WithHelper with
//! with + deserialize_with evidence) plus one helper function row.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(remote = "ExternalWireType")]
pub struct RemoteProxy {
    pub identity: String,
    pub scope: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WithHelper {
    #[serde(with = "time::serde::rfc3339")]
    pub created_at: String,
    #[serde(deserialize_with = "parse_identity")]
    pub identity: String,
    pub scope: String,
}

fn parse_identity<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = String::deserialize(deserializer)?;
    Ok(raw)
}
