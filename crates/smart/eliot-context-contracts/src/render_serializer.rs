//! Owner-issued identity of the codec that renders canonical Context bytes.
//!
//! #1862 BLOCK-2. I2.16 requires the record
//! `SerializedContextMeasurement { envelope_digest,
//! serializer_id_version_and_options, ... }`
//! (`docs/architecture/I02-16-crate-size-and-agent-context-envelope.md:166-179`)
//! and states at `:163` that "Context admission and profile qualification use
//! the exact bytes that the selected route will receive". The three compared
//! values are `SerializedContextMeasurement`'s `serializer_id`,
//! `serializer_version` and `serializer_options_digest`, which this crate
//! defines and fills.
//!
//! The codec those bytes are produced by is the one this crate itself runs:
//! `eliot_contracts::canonical_json_bytes` over the canonical rendered payload
//! under [`CONTEXT_CONTRACT_VERSION`]. Both
//! `ActiveUnderstandingView::canonical_output_digest` and
//! `ActiveUnderstandingView::canonical_output_utf8_bytes` are that single
//! render, and the assembly cell's own byte producer is proved byte-equal to
//! it by `eliot-context-assembly`'s `measurement::canonical_matches`, which
//! recomputes this crate's digest and refuses a mismatch. This record
//! therefore names the codec this crate is the owner of, not a frame codec, a
//! provider codec or any route configuration.
//!
//! I2.16:181 makes a change to the serializer invalidate any qualification, so
//! the record carries three parts and each is derived rather than declared.
//! The three names below are the names the compared records carry; this
//! record's own storage spells them `id`, `version` and `options_digest`
//! because the type already carries the prefix:
//!
//! - `serializer_id` is the owner contract's own name plus this render's
//!   stable codec name;
//! - `serializer_version` is [`CONTEXT_CONTRACT_VERSION`] itself, which is the
//!   very value the render stamps into the payload's `schema_version` member,
//!   so the two cannot disagree;
//! - `serializer_options_digest` is [`canonical_digest`] of the options record
//!   actually in force, so it changes when the codec, the canonicalization
//!   rule, the byte form, the payload member set or the schema revision
//!   changes. `eliot_contracts::canonical_json_bytes` takes no options and no
//!   deployment setting reaches it, so the digest cannot describe an option
//!   the process is not using.
//!
//! The fields are private and this module publishes no other constructor, so
//! the identity cannot be minted, defaulted or substituted by a caller or by
//! a cell. It is issued only by [`canonical_render_serializer`].

use serde::Serialize;

use crate::view::CANONICAL_RENDERED_PAYLOAD_FIELDS;
use crate::{
    CONTEXT_CONTRACT_NAME, CONTEXT_CONTRACT_VERSION, ContextError, canonical_digest,
    validate_digest, validate_text,
};
use eliot_contracts::ContractVersion;

/// The codec `canonical_render_serializer` names, written exactly as the
/// function this crate calls for the payload bytes.
const RENDER_CODEC: &str = "eliot_contracts::canonical_json_bytes";

/// The canonicalization `eliot_contracts::canonical_json_bytes` applies:
/// `serde_json::Value` with object keys sorted lexicographically at every
/// depth.
const RENDER_CANONICALIZATION: &str = "recursive_lexicographic_object_keys";

/// The byte form `eliot_contracts::canonical_json_bytes` emits: a compact
/// `serde_json` vector, no whitespace and no trailing newline.
const RENDER_BYTE_FORM: &str = "serde_json_compact_utf8_vector";

/// Stable name of the payload shape the codec encodes.
const RENDER_PAYLOAD_SCHEMA: &str = "context.canonical_rendered_payload.v1";

/// The codec options this crate's canonical render actually applies.
///
/// Every member is read from the render this crate runs, and the record is
/// digested with that same codec, so the digest cannot drift away from the
/// bytes: a changed member here and a changed member in the payload are the
/// same change.
#[derive(Serialize)]
struct ContextRenderSerializerOptions {
    codec: &'static str,
    canonicalization: &'static str,
    byte_form: &'static str,
    payload_schema: &'static str,
    payload_members: &'static [&'static str],
    payload_schema_version: ContractVersion,
    owner_contract: &'static str,
}

impl ContextRenderSerializerOptions {
    /// The options in force, read from this crate's own render.
    fn in_force() -> Self {
        Self {
            codec: RENDER_CODEC,
            canonicalization: RENDER_CANONICALIZATION,
            byte_form: RENDER_BYTE_FORM,
            payload_schema: RENDER_PAYLOAD_SCHEMA,
            payload_members: &CANONICAL_RENDERED_PAYLOAD_FIELDS,
            payload_schema_version: CONTEXT_CONTRACT_VERSION,
            owner_contract: CONTEXT_CONTRACT_NAME,
        }
    }
}

/// Owner-issued identity of the codec that produces canonical Context bytes.
///
/// This is the `serializer_id_version_and_options` half of the I2.16
/// `SerializedContextMeasurement` record. It is issued by
/// [`canonical_render_serializer`] and carries no public constructor, so the
/// only value that exists is the value the render owner published.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContextRenderSerializer {
    id: String,
    version: String,
    options_digest: String,
}

impl ContextRenderSerializer {
    /// Issue the identity of this crate's canonical rendered payload codec.
    fn issue() -> Result<Self, ContextError> {
        Ok(Self {
            id: format!("{CONTEXT_CONTRACT_NAME}.canonical-rendered-payload"),
            version: CONTEXT_CONTRACT_VERSION.to_string(),
            options_digest: canonical_digest(&ContextRenderSerializerOptions::in_force())?,
        })
    }

    /// Re-prove the ORIGINAL recorded values of this identity.
    ///
    /// The recorded `id` and `version` go through this crate's own text
    /// validator and the recorded `options_digest` through its own digest
    /// validator. No digest is recomputed and compared to itself, and no
    /// external state is read.
    pub fn validate(&self) -> Result<(), ContextError> {
        validate_text(&self.id, "render_serializer.serializer_id")?;
        validate_text(&self.version, "render_serializer.serializer_version")?;
        validate_digest(
            &self.options_digest,
            "render_serializer.serializer_options_digest",
        )
    }

    /// The owner-issued codec identity.
    ///
    /// The accessor keeps the `serializer_` prefix because that is the name the
    /// compared records carry: `SerializedContextMeasurement`,
    /// `ContextExecutionIdentity`, `MeasurementCompositionProfile` and
    /// `AssemblyPolicy` all spell their member `serializer_id`. The prefix
    /// belongs on the type and on those records, so it is not repeated on this
    /// record's own storage.
    #[must_use]
    pub fn serializer_id(&self) -> &str {
        &self.id
    }

    /// The owner-issued codec revision.
    #[must_use]
    pub fn serializer_version(&self) -> &str {
        &self.version
    }

    /// The owner-issued digest of the codec options in force.
    #[must_use]
    pub fn serializer_options_digest(&self) -> &str {
        &self.options_digest
    }

    /// Require that a record's ORIGINAL three values are this owner's.
    ///
    /// Both sides are the values as recorded. Nothing is recomputed to stand
    /// in for the record under test, so a profile, policy or measurement that
    /// names another codec is refused rather than re-described. The three
    /// parameters keep the `serializer_` prefix because they name the compared
    /// records' own members, not this record's storage.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidField`] when this owner record does not
    /// satisfy its own closed contract, and [`ContextError::IdentityConflict`]
    /// when any of the three supplied values is not the one this owner issued.
    pub fn binds(
        &self,
        serializer_id: &str,
        serializer_version: &str,
        serializer_options_digest: &str,
    ) -> Result<(), ContextError> {
        self.validate()?;
        if self.id != serializer_id
            || self.version != serializer_version
            || self.options_digest != serializer_options_digest
        {
            return Err(ContextError::IdentityConflict);
        }
        Ok(())
    }
}

/// Publish the identity of the canonical rendered payload codec.
///
/// The single producer of [`ContextRenderSerializer`]: the render owner
/// states, once, which codec produced the bytes its
/// `SerializedContextMeasurement` records describe.
pub fn canonical_render_serializer() -> Result<ContextRenderSerializer, ContextError> {
    ContextRenderSerializer::issue()
}
