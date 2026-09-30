//! Owner-published envelope-codec identity of the canonical Context payload.
//!
//! I2.16 `SerializedContextMeasurement` carries
//! `serializer_id_version_and_options` (I2.16:166-168) and refuses to certify a
//! measurement whose serializer, tokenizer, route, tool surface or provider
//! rewrite behaviour changed (I2.16:181). Those three values are therefore not
//! free-form labels on a record: they are the identity of the one codec that
//! produced the exact bytes a measurement digests, and every consumer that
//! content-compares them needs one owner value to compare against.
//!
//! Before this record the Context tree had none. `crates/smart/eliot-context/
//! src/campaign_publication.rs:368-375` states that the Context owner body
//! publishes no serializer identity, and `:381-383` places the serializer,
//! route and model identity with "the route/measurement owner". The measurement
//! owner is the crate that runs the exact measurement operation and owns
//! `SerializedContextMeasurement`, so it is where this publication belongs; it
//! lives in this crate, next to the record that carries it, so the candidate,
//! admission and assembly cells all read the same owner value rather than
//! each accepting a caller's own labels.
//!
//! The codec is `eliot_contracts::canonical_json_bytes`. That is the codec the
//! Context lane actually serializes with and nothing else:
//! `eliot_context_assembly::measurement::final_bytes` produces the exact
//! rendered payload with it, `AdmittedContextSet::canonical_payload_digest`
//! digests the admitted payload with it, and the Context owner's own campaign
//! body digest (`context_recipe_body_digest` / `context_delivery_body_digest`)
//! is re-derived through it. A route that names any other serializer for a
//! Context payload is describing bytes this codec never produced.
//!
//! The options digest is `sha256_hex` over the codec's own declared options, so
//! changing any of them changes the published identity; it is never a constant
//! that repeats the id.

use eliot_contracts::sha256_hex;

use crate::{ContextError, validate_digest, validate_text};

/// Serializer identity of the canonical Context payload codec.
pub const CANONICAL_JSON_SERIALIZER_ID: &str = "eliot-canonical-json";

/// Codec revision of the canonical Context payload codec.
pub const CANONICAL_JSON_SERIALIZER_VERSION: &str = "eliot-canonical-json/v1";

/// Exact options the canonical Context payload codec is invoked with.
///
/// These are the observable options of `eliot_contracts::canonical_json_bytes`
/// itself: value-first serialisation, recursively sorted object keys, compact
/// re-serialisation and UTF-8 bytes. They are the material the published
/// options digest is taken over, so this text is part of the published
/// identity and not a description of it.
pub const CANONICAL_JSON_SERIALIZER_OPTIONS: &[u8] =
    b"eliot_contracts::canonical_json_bytes; serde_json::to_value; object keys sorted recursively; \
      serde_json::to_vec; compact; UTF-8";

/// The three serializer values a Context lane records and its cells compare.
///
/// This is the closed owner record. A value that carries only some of them is
/// not a narrower statement about the same codec: I2.16 names the identity,
/// version and options as one measurement field, and a cell that compares two
/// halves of it has compared nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextSerializerIdentity {
    /// Stable serializer identity.
    pub serializer_id: String,
    /// Serializer revision.
    pub serializer_version: String,
    /// Lowercase SHA-256 digest of the serializer options.
    pub serializer_options_digest: String,
}

impl ContextSerializerIdentity {
    /// Validate the intrinsic shape of the recorded identity.
    ///
    /// This is shape only. It says the record names a serializer; whether it
    /// names *this* codec is decided by comparing it with
    /// [`canonical_json_serializer_identity`], which is the owner value.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(&self.serializer_id, "serializer.serializer_id")?;
        validate_text(&self.serializer_version, "serializer.serializer_version")?;
        validate_digest(
            &self.serializer_options_digest,
            "serializer.serializer_options_digest",
        )
    }
}

/// The owner-published serializer identity of the canonical Context codec.
///
/// The returned value is the only serializer identity a Context lane may carry.
/// It is derived from the codec's declared options rather than assembled from a
/// caller's strings, so it cannot be narrowed to a subset of the compared
/// fields.
#[must_use]
pub fn canonical_json_serializer_identity() -> ContextSerializerIdentity {
    ContextSerializerIdentity {
        serializer_id: CANONICAL_JSON_SERIALIZER_ID.to_owned(),
        serializer_version: CANONICAL_JSON_SERIALIZER_VERSION.to_owned(),
        serializer_options_digest: sha256_hex(CANONICAL_JSON_SERIALIZER_OPTIONS),
    }
}
