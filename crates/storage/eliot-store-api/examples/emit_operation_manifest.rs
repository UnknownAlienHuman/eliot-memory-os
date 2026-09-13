//! Emits the generated per-operation store manifest set as canonical JSON.
//!
//! The emitted document is the same generated set the crate validates
//! against: entries in canonical declaration order plus the catalogue set
//! digest and its contract/schema/profile bindings.
//!
//! Run with:
//!
//! ```text
//! cargo run -p eliot-store-api --example emit_operation_manifest
//! ```

use std::io::Write as _;

use eliot_store_api::{
    CONTRACT_NAME, CONTRACT_VERSION, OPERATION_CATALOGUE_PROFILE, PAYLOAD_AUTHORITY_VERSION,
    canonical_json_bytes, generated_operation_manifests, operation_manifest_set_digest,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let entries = generated_operation_manifests()?;
    let set_digest = operation_manifest_set_digest(&entries)?;
    let document = serde_json::json!({
        "contract_name": CONTRACT_NAME,
        "contract_version": CONTRACT_VERSION,
        "payload_authority_version": PAYLOAD_AUTHORITY_VERSION,
        "catalogue_profile": OPERATION_CATALOGUE_PROFILE,
        "set_digest": set_digest.as_str(),
        "entries": entries,
    });
    let bytes = canonical_json_bytes(&document)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&bytes)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}
