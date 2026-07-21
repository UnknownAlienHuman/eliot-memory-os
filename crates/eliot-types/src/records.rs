use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct BlobRef {
    pub algorithm: String,
    pub digest_hex: String,
    pub size_bytes: u64,
    pub relative_path: String,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub migration_id: String,
    pub checksum_blake3: String,
    pub applied: bool,
}

#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
pub struct HealthRecord {
    pub component: String,
    pub status: String,
    pub detail: String,
}
