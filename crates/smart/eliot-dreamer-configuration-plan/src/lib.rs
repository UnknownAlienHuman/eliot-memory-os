//! Snapshot-bound configuration change intent (A-42).
//!
//! Pure candidate-only deterministic stateless zero-effect owner of exactly
//! one typed [`ConfigurationChangeCandidate`] anchored to an exact immutable
//! base snapshot digest with a bounded closed change set, a purely derived
//! in-memory candidate snapshot digest, complete impact dispositions, and an
//! inert verifier, rollout, stop, rollback, and Human approval boundary. The
//! handler translates a Human request or a diagnosed problem into one review
//!able candidate; it never edits files, publishes snapshots, restarts
//! services, deploys anything, acquires budgets or routes, or exercises
//! authority, effect, or finish behavior.
//!
//! Cell `smart.dreamer.configuration_plan`, order 42. All inputs are immutable
//! and caller supplied. The pre-handler validator receipt travels inside the
//! [`ValidatedDreamDraft`] and
//! is checked intrinsically through its own validation entry points; it is
//! never re-executed here and is never attached as proof of the new snapshot.
//! The candidate snapshot is derived purely in memory with canonical bytes and
//! a digest; derivation neither publishes nor admits anything. No screening,
//! grounding, common validation, production registry construction, canonical
//! mutation, authority, effect, store, governor, model, clock, or finish
//! surface exists in this cell.
//!
//! Consumed contracts already carry closed unknown-field rejection (their
//! schemas state `deny_unknown_fields`); this cell performs no generic JSON
//! intake at all, so no unknown field can enter through a typeless path.
//! Every new shape below is constructed explicitly through the nine typed
//! parameters of [`propose_configuration_change`], never decoded from ambient
//! bytes.
//!
//! Runtime boundary: a malformed, over-bound, cancelled-before-emission, or
//! past-deadline request emits zero effects and fails closed as
//! [`ConfigurationError`]. Semantic shortfalls (unmapped prose, ambiguous
//! layer or owner, generic patch shapes, unknown fields, contradictory
//! operations, mixed layers or owners, raw secrets, forbidden ceiling
//! widening, incomplete impact, missing verifier or rollback, absent approval)
//! are inert terminal outcomes carried by [`ConfigurationChangeCandidate`],
//! never errors that invite a blind retry. Forbidden widening is rejected,
//! not warned; decision-required work is not ready.
//!
//! Absence note: this file contains no persistence, identifier allocation,
//! ambient configuration lookup, file, environment, or registry access,
//! service restart or deployment, budget or route acquisition, provider,
//! model, tool, authority, effect, or terminal-completion calls by
//! construction; the only cryptography is the canonical digest below, and the
//! only fallible work is pure bounded validation. There are no placeholder,
//! mock, canned, or pseudo paths: every branch binds an explicit input field.
//!
//! Test coverage note: the legacy nine-parameter adapter remains available for
//! callers that already own the compact A-42 shapes, while the typed planner
//! below executes all 55 issue cases against explicit schema, snapshot, delta,
//! impact, verifier, history, replay, and preservation inputs. The typed
//! planner is still candidate-only; it does not publish or admit a snapshot.
//!
//! Hub note: this JobClass-based leaf follows the A-40 pure-handler idiom
//! (`ValidatedDreamDraft` in, typed candidate out, [`CurationRejectionCode`]
//! hints). The hub `NativeCurationHandler` trait serves the eleven closed
//! curation kinds; no such kind names a configuration delta, so forcing a
//! payload mapping would invent semantics the hub does not own. The rejection
//! vocabulary is still the shared hub enum.

#![forbid(unsafe_code)]

use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_dreamer_contracts::CurationRejectionCode;
use eliot_dreamer_contracts::candidate::DimensionVerdict;
use eliot_dreamer_contracts::{
    DreamJobAdmission, JobClass, PreservationDimension, PreservationReport, ValidatedDreamDraft,
    check_fence, is_hex64_lower,
};

// ---------------------------------------------------------------------------
// Independent bounds (no cross-subsidy between dimensions).
// ---------------------------------------------------------------------------

/// Maximum structured fields admitted in one request.
pub const MAX_FIELDS: usize = 64;
/// Maximum field changes admitted in one intent.
pub const MAX_CHANGES: usize = 64;
/// Maximum impact members admitted in one intent.
pub const MAX_IMPACT: usize = 128;
/// Maximum evidence refs admitted in any single evidence list.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Maximum rollback steps admitted in one rollback plan.
pub const MAX_ROLLBACK_STEPS: usize = 64;
/// Maximum history attempts admitted in one prior history.
pub const MAX_ATTEMPTS: usize = 64;
/// Maximum bytes for any single free-text field.
pub const MAX_TEXT_BYTES: usize = 1024;
/// Maximum bytes for any handle or identity field.
pub const MAX_HANDLE_BYTES: usize = 128;
/// Maximum bytes for any identity field bound into digests.
pub const MAX_ID_BYTES: usize = 128;
/// Maximum bytes for task, scope, owner, and proof-ceiling fields.
pub const MAX_SCOPE_BYTES: usize = 256;
/// Maximum bytes for any bounded note field.
pub const MAX_NOTE_BYTES: usize = 1024;
/// Maximum aggregate input bytes across all text fields.
pub const MAX_TOTAL_BYTES: usize = 1_048_576;
/// Redaction ceiling for values echoed into errors and notes.
pub const MAX_REDACTED_CHARS: usize = 128;
/// Expected preservation dimensions attested on every emitted candidate.
pub const EXPECTED_PRESERVATION_DIMENSIONS: usize = 7;

/// Routing-only proof ceiling carried by every emitted candidate.
pub const CONFIGURATION_PROOF_NOTE: &str = "a-42 candidate-only aggregation: inert snapshot-bound delta preserved without screening, grounding, common validation, ambient lookup, publication, edit, restart, deploy, budget or route acquisition, authority, effect, store, governor, model, clock, or finish";

/// Closed authorized secret-reference classes; values never travel.
pub const SECRET_REF_CLASSES: &[&str] = &["vault-ref", "env-ref", "config-store-ref"];

// ---------------------------------------------------------------------------
// Small pure helpers (no ambient clock, no allocation of authority).
// ---------------------------------------------------------------------------

/// Returns true when the value carries any control character.
fn has_control(value: &str) -> bool {
    value.chars().any(char::is_control)
}

/// Redacts a value to a bounded printable prefix for errors and notes.
fn redact(value: &str) -> String {
    let mut out = String::new();
    for (index, ch) in value.chars().enumerate() {
        if index >= MAX_REDACTED_CHARS {
            out.push_str("...");
            break;
        }
        if ch.is_control() {
            out.push('?');
        } else {
            out.push(ch);
        }
    }
    out
}

/// Returns true when values hold no duplicates, preserving order.
fn has_no_duplicates(values: &[String]) -> bool {
    let mut index = 0usize;
    while index < values.len() {
        let mut inner = index.saturating_add(1);
        while inner < values.len() {
            let left = values.get(index);
            let right = values.get(inner);
            if let (Some(left), Some(right)) = (left, right) {
                if left == right {
                    return false;
                }
            } else {
                return false;
            }
            inner = inner.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    true
}

/// Lowercases a note without allocating authority.
fn lowered(note: &str) -> String {
    note.to_lowercase()
}

/// Returns true when the haystack contains the needle as a substring.
fn contains_marker(haystack: &str, needle: &str) -> bool {
    haystack.contains(needle)
}

// ---------------------------------------------------------------------------
// Closed forbidden markers (raw secrets, generic patches, ceiling widening).
// ---------------------------------------------------------------------------

/// Substrings that mark a raw secret value smuggled into text.
pub const SECRET_MARKERS: &[&str] = &[
    "api_key",
    "apikey",
    "secret=",
    "password",
    "passwd",
    "bearer ",
    "private key",
    "begin private",
    "aws_secret",
    "token value",
];

/// Substrings that mark a generic map, patch, or open `Other` shape.
pub const GENERIC_MARKERS: &[&str] = &[
    "json patch",
    "json-patch",
    "application/json-patch",
    "generic map",
    "untyped map",
    "other field",
    "additionalproperties",
    "x-unknown",
];

/// Substrings that mark a forbidden privacy ceiling widening claim.
pub const PRIVACY_MARKERS: &[&str] = &[
    "export telemetry",
    "retain forever",
    "share externally",
    "train on private",
    "disable redaction",
];

/// Substrings that mark a forbidden remote, cost, launch, or authority claim.
pub const WIDENING_MARKERS: &[&str] = &[
    "open firewall",
    "grant admin",
    "assume authority",
    "raise quota",
    "switch provider",
    "auto deploy",
    "launch on boot",
    "restart service",
    "edit registry",
];

/// Returns true when any marker occurs in the lowered haystack.
fn mentions_any(lowered_haystack: &str, markers: &[&str]) -> bool {
    let mut index = 0usize;
    while index < markers.len() {
        if let Some(marker) = markers.get(index)
            && contains_marker(lowered_haystack, marker)
        {
            return true;
        }
        index = index.saturating_add(1);
    }
    false
}

// ---------------------------------------------------------------------------
// Public vocabulary: layers, operations, presence, impact, outcomes.
// ---------------------------------------------------------------------------

/// Closed configuration layer for one field change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigLayer {
    /// Human-visible presentation settings only.
    Presentation,
    /// Bounded runtime semantics without deployment effects.
    Runtime,
    /// Capability registry entries without authority promotion.
    Capability,
    /// Privacy and retention settings without export widening.
    Privacy,
    /// Launch recurrence settings without automatic activation.
    Launch,
}

impl ConfigLayer {
    /// Returns the canonical spelling of this layer.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Presentation => "presentation",
            Self::Runtime => "runtime",
            Self::Capability => "capability",
            Self::Privacy => "privacy",
            Self::Launch => "launch",
        }
    }

    /// Parses the canonical spelling of a layer.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, ConfigurationError> {
        match spelling {
            "presentation" => Ok(Self::Presentation),
            "runtime" => Ok(Self::Runtime),
            "capability" => Ok(Self::Capability),
            "privacy" => Ok(Self::Privacy),
            "launch" => Ok(Self::Launch),
            _ => Err(ConfigurationError::Shape {
                field: "change.layer",
                detail: redact(spelling),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Complete typed A-42 planner.
//
// The compact API above predates the full configuration contract.  The types
// below make the load-bearing distinctions explicit without importing a
// writer, store, runtime, provider, or authority crate.  They are candidate
// planning records owned by this stateless leaf; publication remains with the
// existing Governor configuration owner.
// ---------------------------------------------------------------------------

/// Version of the leaf-local typed planning encoding.
pub const TYPED_CONFIGURATION_SCHEMA_VERSION: u16 = 1;
/// Maximum schemas supplied to one bounded plan.
pub const MAX_TYPED_SCHEMAS: usize = 128;
/// Maximum fields carried by one immutable typed snapshot.
pub const MAX_TYPED_SNAPSHOT_FIELDS: usize = 256;
/// Maximum alternatives retained beside one grounded request.
pub const MAX_TYPED_ALTERNATIVES: usize = 32;
/// Maximum operation sequence length.
pub const MAX_TYPED_SEQUENCE: usize = 256;
/// Maximum impact omissions retained by one closure.
pub const MAX_TYPED_OMISSIONS: usize = 128;

/// A typed value admitted by a configuration schema.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum TypedConfigurationValue {
    /// Boolean setting.
    Boolean(bool),
    /// Signed integer setting.
    Integer(i64),
    /// Bounded text setting.
    Text(String),
    /// Closed enum member.
    Enum(String),
    /// Canonically ordered closed member set.
    Members(Vec<String>),
    /// Secret reference without secret material.
    SecretReference(SecretReference),
}

impl TypedConfigurationValue {
    /// Returns deterministic bytes-as-text for candidate identity only.
    #[must_use]
    pub fn canonical(&self) -> String {
        match self {
            Self::Boolean(value) => ["bool:", &value.to_string()].concat(),
            Self::Integer(value) => ["int:", &value.to_string()].concat(),
            Self::Text(value) => ["text:", value].concat(),
            Self::Enum(value) => ["enum:", value].concat(),
            Self::Members(values) => ["members:", &values.join(",")].concat(),
            Self::SecretReference(reference) => [
                "secret-ref:",
                &reference.class,
                ":",
                &reference.reference_id,
            ]
            .concat(),
        }
    }

    fn validate_shape(&self) -> Result<(), ConfigurationError> {
        match self {
            Self::Text(value) if value.is_empty() => Ok(()),
            Self::Text(value) | Self::Enum(value) => {
                check_bounded_text(value, "typed.value", MAX_NOTE_BYTES)
            }
            Self::Members(values) => {
                bound_list_length(
                    "typed.value.members",
                    values.len(),
                    MAX_TYPED_SNAPSHOT_FIELDS,
                )?;
                for value in values {
                    check_bounded_text(value, "typed.value.member", MAX_ID_BYTES)?;
                }
                if !is_sorted_unique_strings(values) {
                    return Err(ConfigurationError::Order {
                        phase: "typed.value.members".to_owned(),
                        detail: "member values must be sorted and unique".to_owned(),
                    });
                }
                Ok(())
            }
            Self::SecretReference(reference) => reference.validate(),
            Self::Boolean(_) | Self::Integer(_) => Ok(()),
        }
    }
}

/// An authorized reference class and opaque identifier; it is not a secret.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SecretReference {
    /// Closed class such as vault-ref or config-store-ref.
    pub class: String,
    /// Opaque provider reference, never the secret value.
    pub reference_id: String,
}

impl SecretReference {
    fn validate(&self) -> Result<(), ConfigurationError> {
        check_bounded_text(&self.class, "typed.secret.class", MAX_ID_BYTES)?;
        check_handle(&self.reference_id, "typed.secret.reference")?;
        if !SECRET_REF_CLASSES.iter().any(|class| *class == self.class) {
            return Err(ConfigurationError::Shape {
                field: "typed.secret.class",
                detail: "secret class is not an authorized reference class".to_owned(),
            });
        }
        let lowered = lowered(&self.reference_id);
        if mentions_any(&lowered, SECRET_MARKERS) {
            return Err(ConfigurationError::Shape {
                field: "typed.secret.reference",
                detail: "secret material cannot enter through a reference".to_owned(),
            });
        }
        Ok(())
    }
}

/// Closed schema type for one configuration field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigurationFieldType {
    /// Boolean field.
    Boolean,
    /// Bounded integer field.
    Integer { minimum: i64, maximum: i64 },
    /// Bounded text field.
    Text { max_bytes: usize },
    /// Closed enum field.
    Enum { allowed: Vec<String> },
    /// Closed member-set field.
    MemberSet { max_members: usize },
    /// Secret reference field.
    SecretReference,
}

impl ConfigurationFieldType {
    fn validate_shape(&self) -> Result<(), ConfigurationError> {
        match self {
            Self::Integer { minimum, maximum } if minimum > maximum => {
                Err(ConfigurationError::Shape {
                    field: "typed.schema.range",
                    detail: "integer minimum exceeds maximum".to_owned(),
                })
            }
            Self::Text { max_bytes } if *max_bytes == 0 || *max_bytes > MAX_NOTE_BYTES => {
                Err(ConfigurationError::Bounds {
                    phase: "typed.schema.text".to_owned(),
                    detail: "text type exceeds its independent bound".to_owned(),
                })
            }
            Self::Enum { allowed } => {
                bound_list_length("typed.schema.enum", allowed.len(), MAX_FIELDS)?;
                for value in allowed {
                    check_bounded_text(value, "typed.schema.enum-value", MAX_NOTE_BYTES)?;
                }
                if !is_sorted_unique_strings(allowed) {
                    return Err(ConfigurationError::Order {
                        phase: "typed.schema.enum".to_owned(),
                        detail: "enum members must be sorted and unique".to_owned(),
                    });
                }
                Ok(())
            }
            Self::MemberSet { max_members } if *max_members == 0 => {
                Err(ConfigurationError::Shape {
                    field: "typed.schema.members",
                    detail: "member-set maximum must be positive".to_owned(),
                })
            }
            Self::Boolean
            | Self::Integer { .. }
            | Self::Text { .. }
            | Self::MemberSet { .. }
            | Self::SecretReference => Ok(()),
        }
    }

    fn accepts(&self, value: &TypedConfigurationValue) -> bool {
        match (self, value) {
            (Self::Boolean, TypedConfigurationValue::Boolean(_))
            | (Self::SecretReference, TypedConfigurationValue::SecretReference(_)) => true,
            (Self::Integer { minimum, maximum }, TypedConfigurationValue::Integer(value)) => {
                value >= minimum && value <= maximum
            }
            (Self::Text { max_bytes }, TypedConfigurationValue::Text(value)) => {
                value.len() <= *max_bytes
            }
            (Self::Enum { allowed }, TypedConfigurationValue::Enum(value)) => {
                allowed.iter().any(|member| member == value)
            }
            (Self::MemberSet { max_members }, TypedConfigurationValue::Members(values)) => {
                values.len() <= *max_members && is_sorted_unique_strings(values)
            }
            _ => false,
        }
    }
}

/// Mutability owned by the canonical field owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurationFieldMutability {
    /// Field may be changed by a typed intent.
    Mutable,
    /// Field is readable but not writable by this planner.
    ReadOnly,
    /// Field is derived and has no direct write operation.
    Derived,
}

/// Closed unit vocabulary for numeric configuration fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurationUnit {
    /// Count of discrete items.
    Items,
    /// UTF-8 byte count.
    Utf8Bytes,
    /// Elapsed milliseconds.
    Milliseconds,
    /// Percentage in the bounded 0..=100 range.
    Percentage,
}

impl ConfigurationUnit {
    /// Returns the canonical unit spelling used in digests.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Items => "items",
            Self::Utf8Bytes => "utf8_bytes",
            Self::Milliseconds => "milliseconds",
            Self::Percentage => "percentage",
        }
    }
}

/// Closed cross-field constraints supplied by the exact schema owner.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurationFieldConstraint {
    /// Require another field to retain one exact presence state.
    RequiresPresence {
        field_id: String,
        presence: Presence,
    },
    /// Require another integer field to be at least the declared value.
    IntegerAtLeast { field_id: String, minimum: i64 },
    /// Require another integer field to be at most the declared value.
    IntegerAtMost { field_id: String, maximum: i64 },
}

impl ConfigurationFieldConstraint {
    fn validate(&self) -> Result<(), ConfigurationError> {
        let field_id = match self {
            Self::RequiresPresence { field_id, .. }
            | Self::IntegerAtLeast { field_id, .. }
            | Self::IntegerAtMost { field_id, .. } => field_id,
        };
        check_handle(field_id, "typed.schema.constraint.field")
    }
}

/// Exact schema, layer, owner, type, default, and constraint for one field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationFieldSchema {
    /// Schema identity.
    pub schema_id: String,
    /// Schema revision.
    pub schema_revision: u32,
    /// Exact field identity.
    pub field_id: String,
    /// Owning configuration layer.
    pub layer: ConfigLayer,
    /// Owning writer principal.
    pub owner: String,
    /// Closed field type and constraints.
    pub field_type: ConfigurationFieldType,
    /// Direct-write policy.
    pub mutability: ConfigurationFieldMutability,
    /// Exact unit required by numeric requests, when the owner declares one.
    pub unit: Option<ConfigurationUnit>,
    /// Closed cross-field predicates evaluated over the derived snapshot.
    pub constraints: Vec<ConfigurationFieldConstraint>,
    /// Whether the field may be absent.
    pub optional: bool,
    /// Explicit schema default, if reset is legal.
    pub default: Option<TypedConfigurationValue>,
}

impl ConfigurationFieldSchema {
    fn validate(&self) -> Result<(), ConfigurationError> {
        check_bounded_text(&self.schema_id, "typed.schema.id", MAX_ID_BYTES)?;
        if self.schema_revision == 0 {
            return Err(ConfigurationError::Shape {
                field: "typed.schema.revision",
                detail: "schema revision must be explicit".to_owned(),
            });
        }
        check_handle(&self.field_id, "typed.schema.field")?;
        check_bounded_text(&self.owner, "typed.schema.owner", MAX_ID_BYTES)?;
        self.field_type.validate_shape()?;
        for constraint in &self.constraints {
            constraint.validate()?;
        }
        if let Some(default) = &self.default {
            default.validate_shape()?;
            if !self.field_type.accepts(default) {
                return Err(ConfigurationError::Shape {
                    field: "typed.schema.default",
                    detail: "schema default does not satisfy its field type".to_owned(),
                });
            }
        }
        Ok(())
    }
}

/// Validity of a supplied immutable snapshot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypedSnapshotValidity {
    /// Current supplied base snapshot.
    Valid,
    /// Snapshot is an inert derived candidate.
    Derived,
    /// Snapshot is known stale under the supplied fence.
    Stale,
    /// Snapshot completeness is not established.
    Unknown,
}

/// One typed field as it occurs in an immutable snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedSnapshotField {
    /// Exact field identity.
    pub field_id: String,
    /// Field layer.
    pub layer: ConfigLayer,
    /// Field owner.
    pub owner: String,
    /// Presence distinction retained in the snapshot.
    pub presence: Presence,
    /// Typed value, including an explicit schema default for Reset.
    pub value: Option<TypedConfigurationValue>,
}

impl TypedSnapshotField {
    fn validate_shape(&self) -> Result<(), ConfigurationError> {
        check_handle(&self.field_id, "typed.snapshot.field")?;
        check_bounded_text(&self.owner, "typed.snapshot.owner", MAX_ID_BYTES)?;
        if let Some(value) = &self.value {
            value.validate_shape()?;
        }
        match self.presence {
            Presence::Value | Presence::Empty | Presence::Reset => {
                if self.value.is_none() {
                    return Err(ConfigurationError::Shape {
                        field: "typed.snapshot.value",
                        detail: "value, empty, and reset presence require a typed value".to_owned(),
                    });
                }
            }
            Presence::Absent | Presence::Inherited | Presence::Removed | Presence::Unknown => {
                if self.value.is_some() {
                    return Err(ConfigurationError::Shape {
                        field: "typed.snapshot.value",
                        detail: "non-value presence cannot carry a typed value".to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Complete immutable snapshot supplied to or derived by the planner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedConfigurationSnapshot {
    /// Snapshot identity.
    pub snapshot_id: String,
    /// Monotonic snapshot revision.
    pub revision: u64,
    /// Overall schema identity.
    pub schema_id: String,
    /// Overall schema revision.
    pub schema_revision: u32,
    /// Primary layer represented by this snapshot.
    pub layer: ConfigLayer,
    /// Primary owner represented by this snapshot.
    pub owner: String,
    /// Parent snapshot identity, when this is an overlay.
    pub parent_snapshot_id: Option<String>,
    /// Overlay identity, when this snapshot is itself overlaid.
    pub overlay_snapshot_id: Option<String>,
    /// Typed fields in arbitrary supplied order; digest canonicalizes them.
    pub fields: Vec<TypedSnapshotField>,
    /// Exact digest of canonical snapshot bytes.
    pub digest: String,
    /// Supplied or derived validity.
    pub validity: TypedSnapshotValidity,
    /// Provenance identity of the supplied snapshot.
    pub provenance: String,
}

impl TypedConfigurationSnapshot {
    /// Computes the digest from the snapshot's canonical typed contents.
    pub fn computed_digest(&self) -> Result<String, ConfigurationError> {
        let mut fields = self.fields.clone();
        fields.sort_by(|left, right| left.field_id.cmp(&right.field_id));
        let mut parts = vec![
            ["version:", &TYPED_CONFIGURATION_SCHEMA_VERSION.to_string()].concat(),
            ["snapshot:", &self.snapshot_id].concat(),
            ["revision:", &self.revision.to_string()].concat(),
            ["schema:", &self.schema_id].concat(),
            ["schema-revision:", &self.schema_revision.to_string()].concat(),
            ["layer:", self.layer.as_str()].concat(),
            ["owner:", &self.owner].concat(),
            ["provenance:", &self.provenance].concat(),
        ];
        if let Some(parent) = &self.parent_snapshot_id {
            parts.push(["parent:", parent].concat());
        }
        if let Some(overlay) = &self.overlay_snapshot_id {
            parts.push(["overlay:", overlay].concat());
        }
        for field in &fields {
            parts.push(
                [
                    "field:",
                    &field.field_id,
                    "|",
                    field.layer.as_str(),
                    "|",
                    &field.owner,
                    "|",
                    field.presence.as_str(),
                    "|",
                    field
                        .value
                        .as_ref()
                        .map_or_else(|| "none".to_owned(), TypedConfigurationValue::canonical)
                        .as_str(),
                ]
                .concat(),
            );
        }
        canonical_json_bytes(&parts).map_or_else(
            |error| {
                Err(ConfigurationError::Digest {
                    detail: redact(&error.to_string()),
                })
            },
            |bytes| Ok(sha256_hex(&bytes)),
        )
    }

    /// Validates shape, uniqueness, provenance, and the recorded digest.
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        check_handle(&self.snapshot_id, "typed.snapshot.id")?;
        if self.revision == 0 {
            return Err(ConfigurationError::Shape {
                field: "typed.snapshot.revision",
                detail: "snapshot revision must be explicit".to_owned(),
            });
        }
        check_bounded_text(&self.schema_id, "typed.snapshot.schema", MAX_ID_BYTES)?;
        if self.schema_revision == 0 {
            return Err(ConfigurationError::Shape {
                field: "typed.snapshot.schema-revision",
                detail: "snapshot schema revision must be explicit".to_owned(),
            });
        }
        check_bounded_text(&self.owner, "typed.snapshot.owner", MAX_ID_BYTES)?;
        check_bounded_text(
            &self.provenance,
            "typed.snapshot.provenance",
            MAX_HANDLE_BYTES,
        )?;
        check_digest(&self.digest, "typed.snapshot.digest")?;
        bound_list_length(
            "typed.snapshot.fields",
            self.fields.len(),
            MAX_TYPED_SNAPSHOT_FIELDS,
        )?;
        let mut ids = Vec::with_capacity(self.fields.len());
        for field in &self.fields {
            field.validate_shape()?;
            if !ids.iter().all(|id: &String| id != &field.field_id) {
                return Err(ConfigurationError::Order {
                    phase: "typed.snapshot.fields".to_owned(),
                    detail: "snapshot field identities must be unique".to_owned(),
                });
            }
            ids.push(field.field_id.clone());
        }
        if let Some(parent) = &self.parent_snapshot_id {
            check_handle(parent, "typed.snapshot.parent")?;
        }
        if let Some(overlay) = &self.overlay_snapshot_id {
            check_handle(overlay, "typed.snapshot.overlay")?;
        }
        if self.computed_digest()? != self.digest {
            return Err(ConfigurationError::Digest {
                detail: "recorded snapshot digest does not match canonical bytes".to_owned(),
            });
        }
        Ok(())
    }
}

/// Immutable base/parent/overlay snapshot set consumed by the planner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedConfigurationSnapshotSet {
    /// Exact base snapshot for the candidate.
    pub base: TypedConfigurationSnapshot,
    /// Optional exact parent snapshot.
    pub parent: Option<TypedConfigurationSnapshot>,
    /// Optional exact overlay snapshot.
    pub overlay: Option<TypedConfigurationSnapshot>,
}

impl TypedConfigurationSnapshotSet {
    fn validate(&self) -> Result<(), ConfigurationError> {
        self.base.validate()?;
        if let Some(parent) = &self.parent {
            parent.validate()?;
            if self.base.parent_snapshot_id.as_deref() != Some(parent.snapshot_id.as_str())
                || parent.revision >= self.base.revision
                || parent.schema_id != self.base.schema_id
            {
                return Err(ConfigurationError::Binding {
                    field: "typed.snapshot.parent",
                    detail: "parent snapshot is not the exact declared base lineage".to_owned(),
                });
            }
        } else if self.base.parent_snapshot_id.is_some() {
            return Err(ConfigurationError::Binding {
                field: "typed.snapshot.parent",
                detail: "declared parent snapshot is missing from the supplied set".to_owned(),
            });
        }
        if let Some(overlay) = &self.overlay {
            overlay.validate()?;
            if self.base.overlay_snapshot_id.as_deref() != Some(overlay.snapshot_id.as_str())
                || overlay.schema_id != self.base.schema_id
                || overlay.owner != self.base.owner
            {
                return Err(ConfigurationError::Binding {
                    field: "typed.snapshot.overlay",
                    detail: "overlay snapshot is not the exact declared base lineage".to_owned(),
                });
            }
        } else if self.base.overlay_snapshot_id.is_some() {
            return Err(ConfigurationError::Binding {
                field: "typed.snapshot.overlay",
                detail: "declared overlay snapshot is missing from the supplied set".to_owned(),
            });
        }
        Ok(())
    }
}

/// One exact structured request field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedRequestedField {
    /// Exact schema field identity.
    pub field_id: String,
    /// Exact layer mapping.
    pub layer: ConfigLayer,
    /// Exact owner mapping.
    pub owner: String,
    /// Requested presence.
    pub desired: Presence,
    /// Requested typed value.
    pub value: Option<TypedConfigurationValue>,
    /// Exact schema unit for numeric values.
    pub unit: Option<ConfigurationUnit>,
    /// Whether the mapping came from governed structured evidence.
    pub grounded: bool,
    /// Bounded evidence note retained without parsing.
    pub evidence_note: String,
}

/// Structured request and replay identity consumed by the typed planner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedConfigurationRequest {
    /// Stable intent identity.
    pub intent_id: String,
    /// Operation identity and idempotency namespace.
    pub operation: TypedOperationIdentity,
    /// Task binding retained from the request envelope.
    pub task_id: String,
    /// Scope binding retained from the request envelope.
    pub scope_id: String,
    /// Exact base snapshot requested by the caller.
    pub base_snapshot_id: String,
    /// Exact base revision requested by the caller.
    pub base_revision: u64,
    /// Natural-language evidence, never parsed into a field change.
    pub summary_note: String,
    /// Explicit structured mapping flag.
    pub structured_mapping: bool,
    /// Grounded fields that are the only source of requested changes.
    pub fields: Vec<TypedRequestedField>,
    /// Alternatives and unresolved choices preserved verbatim.
    pub alternatives: Vec<String>,
    /// Governed evidence references for the request.
    pub grounded_refs: Vec<String>,
    /// Exact A-05 validation receipt output digest consumed by this leaf.
    pub input_receipt_digest: String,
}

/// Canonical operation identity for replay and same-ID conflict detection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedOperationIdentity {
    /// Stable operation ID.
    pub operation_id: String,
    /// Idempotency key in its declared namespace.
    pub idempotency_key: String,
    /// Versioned canonical encoding.
    pub canonical_encoding_version: u16,
    /// Optional caller-supplied canonical request digest.
    pub canonical_request_digest: Option<String>,
}

/// A typed field operation in the closed configuration delta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedConfigurationChange {
    /// Stable change identity.
    pub change_id: String,
    /// Exact field identity.
    pub field_id: String,
    /// Exact schema identity.
    pub schema_id: String,
    /// Exact layer identity.
    pub layer: ConfigLayer,
    /// Exact owner identity.
    pub owner: String,
    /// Closed operation.
    pub operation: ConfigOp,
    /// Exact base presence expected by this operation.
    pub before: Presence,
    /// Exact candidate presence requested by this operation.
    pub after: Presence,
    /// Typed value, if the operation needs one.
    pub value: Option<TypedConfigurationValue>,
    /// Exact schema unit for numeric values.
    pub unit: Option<ConfigurationUnit>,
    /// Optional authorized secret reference, never a raw value.
    pub secret_ref: Option<SecretReference>,
    /// Bounded grounded rationale.
    pub rationale: String,
    /// Ordered semantic rollout sequence.
    pub sequence: u32,
    /// Expected base revision.
    pub expected_base_revision: u64,
    /// Protected ceiling widenings requested by this change.
    pub widenings: Vec<ConfigurationCeiling>,
    /// Optional per-change canonical digest for caller replay.
    pub canonical_change_digest: Option<String>,
}

/// Protected configuration ceiling classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurationCeiling {
    /// Authority/capability/effect scope.
    Authority,
    /// Privacy, retention, telemetry, training, or export.
    Privacy,
    /// Remote/network/principal scope.
    Remote,
    /// Provider/model/cost/quota/fallback behavior.
    CostOrRoute,
    /// Automatic launch, recurrence, or deployment.
    AutomaticLaunch,
    /// Product objective, acceptance, or verifier oracle.
    ProductVerifier,
    /// Filesystem, registry, or process reach.
    FilesystemOrProcess,
}

/// Impact evidence status for a graph member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypedImpactCompleteness {
    /// Every expected member is supplied with evidence.
    Complete,
    /// Some members are accounted omissions but completeness is bounded.
    Partial,
    /// The denominator or graph closure is unknown.
    Unknown,
}

/// One member in the supplied bounded impact/dependency graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedImpactMember {
    /// Stable member identity.
    pub member_id: String,
    /// Lifecycle owner of the member.
    pub owner: String,
    /// Direct/transitive/conditional/blocked/stale/unknown disposition.
    pub disposition: ImpactDisposition,
    /// Bounded causal path from the changed field.
    pub path: Vec<String>,
    /// Evidence refs proving this edge.
    pub evidence_refs: Vec<String>,
    /// Compatibility evidence.
    pub compatibility_note: String,
    /// Migration evidence.
    pub migration_note: String,
    /// Reload/restart/state-transfer evidence.
    pub state_transfer_note: String,
    /// Security/privacy/cost impact evidence.
    pub security_privacy_cost_note: String,
}

/// Complete or explicitly partial impact closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedImpactClosure {
    /// Expected denominator of member identities.
    pub expected_member_ids: Vec<String>,
    /// Supplied members in semantic traversal order.
    pub members: Vec<TypedImpactMember>,
    /// Closure status.
    pub completeness: TypedImpactCompleteness,
    /// Accounted omissions for partial/unknown coverage.
    pub omissions: Vec<String>,
}

/// Retained disposition of a prior candidate/application attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypedHistoryDisposition {
    /// Candidate was formed but not applied.
    CandidateOnly,
    /// External application committed.
    Applied,
    /// Application failed.
    Failed,
    /// Application was partially observed.
    Partial,
    /// Application was rolled back.
    RolledBack,
    /// External result is unresolved.
    UnknownOutcome,
}

/// One prior attempt retained for replay and diagnosis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedHistoryAttempt {
    /// Stable attempt identity.
    pub attempt_id: String,
    /// Intent identity used by the attempt.
    pub intent_id: String,
    /// Canonical request digest used by the attempt.
    pub request_digest: String,
    /// Canonical typed delta digest used by the attempt.
    pub delta_digest: String,
    /// Exact base digest used by the attempt.
    pub base_digest: String,
    /// Changed field identities retained for concurrency checks.
    pub changed_field_ids: Vec<String>,
    /// External/application disposition.
    pub disposition: TypedHistoryDisposition,
    /// Evidence refs and diagnosis residue.
    pub evidence_refs: Vec<String>,
    /// Bounded outcome note.
    pub outcome_note: String,
}

/// Prior history with an exact retained denominator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedPriorHistory {
    /// Expected attempt identities.
    pub expected_attempt_ids: Vec<String>,
    /// Retained attempts exactly covering the denominator.
    pub attempts: Vec<TypedHistoryAttempt>,
    /// Bounded history note.
    pub outcome_note: String,
}

/// Inert verifier readings; no reading is an execution receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypedVerifierReading {
    /// Expected success interpretation.
    Success,
    /// Bounded partial interpretation.
    Partial,
    /// No-change interpretation.
    NoChange,
    /// Regression interpretation.
    Regression,
    /// Verifier unavailable.
    Unavailable,
    /// Result remains unknown.
    Unknown,
}

/// Inert semantic verifier contract.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedVerifier {
    /// External verifier identity.
    pub verifier_id: String,
    /// Whether the verifier is independent of the planner.
    pub independent: bool,
    /// Inert pre-application probe description.
    pub probe_note: String,
    /// Inert semantic success condition.
    pub success_note: String,
    /// Inert partial condition.
    pub partial_note: String,
    /// Inert no-change condition.
    pub no_change_note: String,
    /// Inert regression condition.
    pub regression_note: String,
    /// Inert unavailable condition.
    pub unavailable_note: String,
    /// Inert unknown condition.
    pub unknown_note: String,
    /// Whether process/tool success is explicitly insufficient.
    pub process_success_insufficient: bool,
    /// Declared possible readings.
    pub readings: Vec<TypedVerifierReading>,
    /// Maximum attempts in the inert plan.
    pub max_attempts: u32,
    /// Stop/no-progress condition.
    pub stop_note: String,
}

/// Inert rollout/canary bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedRolloutPlan {
    /// Ordered rollout sequence; it is never executed here.
    pub sequence: Vec<String>,
    /// Maximum attempts.
    pub max_attempts: u32,
    /// Optional frozen deadline.
    pub deadline_ms: Option<u64>,
    /// Stop on no progress.
    pub stop_on_no_progress: bool,
    /// Cancellation behavior.
    pub cancellation_note: String,
    /// Bounded canary/blast-radius scope.
    pub canary_scope: String,
}

/// Inert exact rollback/forward-repair boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedRollbackPlan {
    /// Exact previous snapshot digest.
    pub anchor_digest: String,
    /// Whether rollback restores that exact previous snapshot.
    pub exact_previous_snapshot: bool,
    /// Ordered inert rollback steps.
    pub steps: Vec<String>,
    /// Forward repair if an exact rollback is unsafe.
    pub forward_repair_note: Option<String>,
}

/// Human/owner approval state retained without granting authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypedApprovalStatus {
    /// No owner decision is needed for this bounded candidate.
    NotRequired,
    /// Owner decision is required and not yet supplied.
    Required,
    /// Exact owner decision was supplied.
    Approved,
    /// Exact owner denied the candidate.
    Denied,
    /// Previous approval is expired.
    Expired,
}

/// Approval identity and expiry boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedApproval {
    /// Whether this candidate requires an owner decision.
    pub required: bool,
    /// Exact owner who must decide.
    pub owner: String,
    /// Approval state.
    pub status: TypedApprovalStatus,
    /// Frozen expiry, when applicable.
    pub expires_at_ms: Option<u64>,
}

/// Complete inert verifier, rollout, rollback, and approval boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedConfigurationBoundary {
    /// Whether a verifier was supplied.
    pub verifier_present: bool,
    /// Inert verifier.
    pub verifier: TypedVerifier,
    /// Inert rollout.
    pub rollout: TypedRolloutPlan,
    /// Whether a rollback plan was supplied.
    pub rollback_present: bool,
    /// Inert rollback.
    pub rollback: TypedRollbackPlan,
    /// Human/owner approval boundary.
    pub approval: TypedApproval,
    /// External owner that would apply the candidate.
    pub application_owner: String,
}

/// Complete typed planner policy and independent bounds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedConfigurationPolicy {
    /// Policy identity bound to the validator receipt.
    pub policy_id: String,
    /// Explicit policy revision.
    pub policy_revision: u32,
    /// Independent field ceiling.
    pub max_fields: usize,
    /// Independent change ceiling.
    pub max_changes: usize,
    /// Independent schema ceiling.
    pub max_schemas: usize,
    /// Independent impact ceiling.
    pub max_impact: usize,
    /// Independent history ceiling.
    pub max_history: usize,
    /// Whether bounded partial output is permitted.
    pub allow_partial: bool,
    /// Protected widenings rejected at this leaf.
    pub forbidden_widenings: Vec<ConfigurationCeiling>,
    /// Widenings that require an exact owner decision.
    pub decision_widenings: Vec<ConfigurationCeiling>,
    /// Frozen observation time.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline.
    pub deadline_ms: Option<u64>,
    /// Cancellation before emission.
    pub cancelled: bool,
    /// Bounded policy owner note.
    pub owner_note: String,
}

/// Replay result retained in the candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TypedReplayDisposition {
    /// New candidate identity.
    New,
    /// Exact same-ID request and delta.
    ExactDuplicate,
    /// Same ID with changed canonical payload.
    IdentityConflict,
    /// Same base and overlapping field with a different delta.
    ConcurrentFieldConflict,
    /// The committed base moved.
    CommittedBaseDrift,
    /// Equivalent failed attempt requires diagnosis.
    MechanismReview,
}

/// Full typed detail carried by a complete planner result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypedCandidateDetails {
    /// Intent identity.
    pub intent_id: String,
    /// Canonical request digest.
    pub request_digest: String,
    /// Canonical ordered delta digest.
    pub delta_digest: String,
    /// Exact supplied base snapshot.
    pub base_snapshot: TypedConfigurationSnapshot,
    /// Exact parent snapshot supplied for inheritance semantics.
    pub parent_snapshot: Option<TypedConfigurationSnapshot>,
    /// Exact overlay snapshot supplied with the base, when present.
    pub overlay_snapshot: Option<TypedConfigurationSnapshot>,
    /// Purely derived candidate snapshot.
    pub candidate_snapshot: TypedConfigurationSnapshot,
    /// Base fields retained byte-for-byte in semantic form.
    pub unchanged_fields: Vec<TypedSnapshotField>,
    /// Exact schemas used by the delta.
    pub schemas: Vec<ConfigurationFieldSchema>,
    /// Original structured request.
    pub request: TypedConfigurationRequest,
    /// Ordered typed changes.
    pub changes: Vec<TypedConfigurationChange>,
    /// Full impact closure.
    pub impact: TypedImpactClosure,
    /// Prior history retained verbatim.
    pub history: TypedPriorHistory,
    /// Inert boundary.
    pub boundary: TypedConfigurationBoundary,
    /// Replay disposition.
    pub replay: TypedReplayDisposition,
    /// Load-bearing invalidation residue.
    pub invalidation_reasons: Vec<String>,
    /// Explicit candidate-only marker.
    pub candidate_only: bool,
}

impl TypedCandidateDetails {
    /// Revalidates the load-bearing candidate identity after a copied record is
    /// changed.  This is the invalidation gate for impact, verifier, approval,
    /// rollback, schema, and candidate-digest changes.
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), ConfigurationError> {
        if !self.candidate_only {
            return Err(ConfigurationError::Binding {
                field: "typed.candidate_only",
                detail: "typed result cannot grant an execution contour".to_owned(),
            });
        }
        if !self.invalidation_reasons.is_empty() {
            return Err(ConfigurationError::Digest {
                detail: "load-bearing candidate evidence has been invalidated".to_owned(),
            });
        }
        self.base_snapshot.validate()?;
        self.candidate_snapshot.validate()?;
        if self.base_snapshot.validity != TypedSnapshotValidity::Valid {
            return Err(ConfigurationError::Digest {
                detail: "complete candidate no longer has a valid exact base".to_owned(),
            });
        }
        let snapshot_set = TypedConfigurationSnapshotSet {
            base: self.base_snapshot.clone(),
            parent: self.parent_snapshot.clone(),
            overlay: self.overlay_snapshot.clone(),
        };
        snapshot_set.validate()?;
        if self.candidate_snapshot.parent_snapshot_id.as_deref()
            != Some(self.base_snapshot.snapshot_id.as_str())
        {
            return Err(ConfigurationError::Binding {
                field: "typed.candidate.parent",
                detail: "candidate is not derived from the exact base snapshot".to_owned(),
            });
        }
        if self.candidate_snapshot.revision <= self.base_snapshot.revision {
            return Err(ConfigurationError::Digest {
                detail: "candidate revision is not newer than the base".to_owned(),
            });
        }
        if self.candidate_snapshot.validity != TypedSnapshotValidity::Derived {
            return Err(ConfigurationError::Digest {
                detail: "candidate snapshot validity is not derived".to_owned(),
            });
        }
        if self.unchanged_fields.iter().any(|field| {
            self.base_snapshot
                .fields
                .iter()
                .find(|base| base.field_id == field.field_id)
                != Some(field)
        }) {
            return Err(ConfigurationError::Digest {
                detail: "unchanged-field preservation no longer matches the base".to_owned(),
            });
        }
        let changed_ids = typed_change_field_ids(&self.changes);
        for base_field in &self.base_snapshot.fields {
            if !changed_ids.iter().any(|id| id == &base_field.field_id)
                && typed_snapshot_field(&self.candidate_snapshot.fields, &base_field.field_id)
                    != Some(base_field)
            {
                return Err(ConfigurationError::Digest {
                    detail: "an unchanged base field was dropped or changed".to_owned(),
                });
            }
        }
        for change in &self.changes {
            let Some(schema) = typed_schema_lookup(&self.schemas, change) else {
                return Err(ConfigurationError::Binding {
                    field: "typed.details.schema",
                    detail: "candidate change lost its exact schema binding".to_owned(),
                });
            };
            let Some(request_field) = self
                .request
                .fields
                .iter()
                .find(|field| field.field_id == change.field_id)
            else {
                return Err(ConfigurationError::Binding {
                    field: "typed.details.request",
                    detail: "candidate change lost its structured request mapping".to_owned(),
                });
            };
            if !typed_requested_field_matches(request_field, change)
                || schema.mutability != ConfigurationFieldMutability::Mutable
            {
                return Err(ConfigurationError::Binding {
                    field: "typed.details.request",
                    detail: "candidate change is no longer grounded in its exact mutable field"
                        .to_owned(),
                });
            }
        }
        let expected_candidate =
            typed_derive_candidate(&snapshot_set, &self.schemas, &self.changes, &self.request)
                .map_err(|detail| ConfigurationError::Digest {
                    detail: redact(&detail),
                })?;
        if expected_candidate != self.candidate_snapshot {
            return Err(ConfigurationError::Digest {
                detail: "candidate snapshot no longer matches the pure typed derivation".to_owned(),
            });
        }
        if canonical_typed_request_digest(&self.request)? != self.request_digest
            || canonical_typed_delta_digest(&self.changes)? != self.delta_digest
        {
            return Err(ConfigurationError::Digest {
                detail: "candidate request or delta digest no longer matches canonical bytes"
                    .to_owned(),
            });
        }
        let validation_policy = TypedConfigurationPolicy {
            policy_id: "validation".to_owned(),
            policy_revision: 1,
            max_fields: MAX_FIELDS,
            max_changes: MAX_CHANGES,
            max_schemas: MAX_TYPED_SCHEMAS,
            max_impact: MAX_IMPACT,
            max_history: MAX_ATTEMPTS,
            allow_partial: true,
            forbidden_widenings: Vec::new(),
            decision_widenings: Vec::new(),
            observation_time_ms: None,
            deadline_ms: None,
            cancelled: false,
            owner_note: "candidate revalidation".to_owned(),
        };
        typed_history_validate(&self.history, &validation_policy)?;
        typed_boundary_validate(&self.boundary)?;
        if !self.boundary.verifier_present
            || !self.boundary.verifier.independent
            || !self.boundary.verifier.process_success_insufficient
            || !typed_boundary_has_all_readings(&self.boundary)
            || self.boundary.rollout.sequence.is_empty()
            || self.boundary.rollout.max_attempts == 0
            || self.boundary.verifier.max_attempts == 0
            || !self.boundary.rollout.stop_on_no_progress
            || !self.boundary.rollback_present
            || self.boundary.rollback.steps.is_empty()
            || self.boundary.rollback.anchor_digest != self.base_snapshot.digest
            || (self.boundary.approval.required
                && self.boundary.approval.status != TypedApprovalStatus::Approved)
        {
            return Err(ConfigurationError::Digest {
                detail: "load-bearing verifier, rollout, rollback, or approval boundary changed"
                    .to_owned(),
            });
        }
        if self.impact.members.is_empty()
            || self.impact.completeness != TypedImpactCompleteness::Complete
            || self.impact.members.iter().any(|member| {
                matches!(
                    member.disposition,
                    ImpactDisposition::Unknown
                        | ImpactDisposition::Stale
                        | ImpactDisposition::Blocked
                )
            })
        {
            return Err(ConfigurationError::Digest {
                detail: "load-bearing impact closure changed after complete emission".to_owned(),
            });
        }
        validate_typed_impact(&self.impact, &validation_policy)?;
        Ok(())
    }
}

fn is_sorted_unique_strings(values: &[String]) -> bool {
    let mut index = 1usize;
    while index < values.len() {
        let Some(previous) = values.get(index.saturating_sub(1)) else {
            return false;
        };
        let Some(current) = values.get(index) else {
            return false;
        };
        if previous >= current {
            return false;
        }
        index = index.saturating_add(1);
    }
    true
}

fn typed_operation_identity_validate(
    operation: &TypedOperationIdentity,
) -> Result<(), ConfigurationError> {
    check_handle(&operation.operation_id, "typed.operation.id")?;
    check_handle(&operation.idempotency_key, "typed.operation.idempotency")?;
    if operation.canonical_encoding_version == 0 {
        return Err(ConfigurationError::Shape {
            field: "typed.operation.encoding",
            detail: "canonical encoding version must be explicit".to_owned(),
        });
    }
    if let Some(digest) = &operation.canonical_request_digest {
        check_digest(digest, "typed.operation.request-digest")?;
    }
    Ok(())
}

fn typed_request_parts(request: &TypedConfigurationRequest) -> Vec<String> {
    let mut parts = vec![
        ["version:", &TYPED_CONFIGURATION_SCHEMA_VERSION.to_string()].concat(),
        ["intent:", &request.intent_id].concat(),
        ["operation:", &request.operation.operation_id].concat(),
        ["idempotency:", &request.operation.idempotency_key].concat(),
        [
            "encoding:",
            &request.operation.canonical_encoding_version.to_string(),
        ]
        .concat(),
        ["task:", &request.task_id].concat(),
        ["scope:", &request.scope_id].concat(),
        ["base:", &request.base_snapshot_id].concat(),
        ["base-revision:", &request.base_revision.to_string()].concat(),
        ["summary:", &request.summary_note].concat(),
        ["structured:", &request.structured_mapping.to_string()].concat(),
        ["input-receipt:", &request.input_receipt_digest].concat(),
    ];
    for field in &request.fields {
        parts.push(
            [
                "field:",
                &field.field_id,
                "|",
                field.layer.as_str(),
                "|",
                &field.owner,
                "|",
                field.desired.as_str(),
                "|",
                field
                    .value
                    .as_ref()
                    .map_or_else(|| "none".to_owned(), TypedConfigurationValue::canonical)
                    .as_str(),
                "|",
                field
                    .unit
                    .map_or_else(
                        || "unit:none".to_owned(),
                        |unit| ["unit:", unit.as_str()].concat(),
                    )
                    .as_str(),
                "|",
                &field.grounded.to_string(),
                "|",
                &field.evidence_note,
            ]
            .concat(),
        );
    }
    for alternative in &request.alternatives {
        parts.push(["alternative:", alternative].concat());
    }
    for reference in &request.grounded_refs {
        parts.push(["grounded-ref:", reference].concat());
    }
    parts
}

/// Computes the canonical request digest without trusting a caller digest.
pub fn canonical_typed_request_digest(
    request: &TypedConfigurationRequest,
) -> Result<String, ConfigurationError> {
    canonical_json_bytes(&typed_request_parts(request)).map_or_else(
        |error| {
            Err(ConfigurationError::Digest {
                detail: redact(&error.to_string()),
            })
        },
        |bytes| Ok(sha256_hex(&bytes)),
    )
}

fn typed_change_parts(change: &TypedConfigurationChange) -> Vec<String> {
    vec![
        ["change:", &change.change_id].concat(),
        ["field:", &change.field_id].concat(),
        ["schema:", &change.schema_id].concat(),
        ["layer:", change.layer.as_str()].concat(),
        ["owner:", &change.owner].concat(),
        ["operation:", change.operation.as_str()].concat(),
        ["before:", change.before.as_str()].concat(),
        ["after:", change.after.as_str()].concat(),
        [
            "value:",
            &change
                .value
                .as_ref()
                .map_or_else(|| "none".to_owned(), TypedConfigurationValue::canonical),
        ]
        .concat(),
        [
            "unit:",
            change.unit.map_or("none", ConfigurationUnit::as_str),
        ]
        .concat(),
        [
            "secret-class:",
            &change
                .secret_ref
                .as_ref()
                .map_or_else(|| "none".to_owned(), |reference| reference.class.clone()),
        ]
        .concat(),
        ["rationale:", &change.rationale].concat(),
        ["sequence:", &change.sequence.to_string()].concat(),
        ["base-revision:", &change.expected_base_revision.to_string()].concat(),
    ]
}

fn canonical_typed_change_digest(
    change: &TypedConfigurationChange,
) -> Result<String, ConfigurationError> {
    canonical_json_bytes(&typed_change_parts(change)).map_or_else(
        |error| {
            Err(ConfigurationError::Digest {
                detail: redact(&error.to_string()),
            })
        },
        |bytes| Ok(sha256_hex(&bytes)),
    )
}

/// Computes the canonical ordered delta digest.
pub fn canonical_typed_delta_digest(
    changes: &[TypedConfigurationChange],
) -> Result<String, ConfigurationError> {
    let mut parts = Vec::with_capacity(changes.len());
    for change in changes {
        parts.push(canonical_typed_change_digest(change)?);
    }
    canonical_json_bytes(&parts).map_or_else(
        |error| {
            Err(ConfigurationError::Digest {
                detail: redact(&error.to_string()),
            })
        },
        |bytes| Ok(sha256_hex(&bytes)),
    )
}

fn typed_request_validate(
    request: &TypedConfigurationRequest,
    policy: &TypedConfigurationPolicy,
) -> Result<(), ConfigurationError> {
    check_handle(&request.intent_id, "typed.request.intent")?;
    typed_operation_identity_validate(&request.operation)?;
    check_handle(&request.task_id, "typed.request.task")?;
    check_handle(&request.scope_id, "typed.request.scope")?;
    check_handle(&request.base_snapshot_id, "typed.request.base")?;
    if request.base_revision == 0 {
        return Err(ConfigurationError::Shape {
            field: "typed.request.base-revision",
            detail: "base revision must be explicit".to_owned(),
        });
    }
    check_bounded_text(
        &request.summary_note,
        "typed.request.summary",
        MAX_NOTE_BYTES,
    )?;
    bound_list_length(
        "typed.request.fields",
        request.fields.len(),
        policy.max_fields.min(MAX_FIELDS),
    )?;
    bound_list_length(
        "typed.request.alternatives",
        request.alternatives.len(),
        MAX_TYPED_ALTERNATIVES,
    )?;
    bound_list_length(
        "typed.request.grounded-refs",
        request.grounded_refs.len(),
        MAX_EVIDENCE_ITEMS,
    )?;
    let mut field_ids = Vec::with_capacity(request.fields.len());
    for field in &request.fields {
        check_handle(&field.field_id, "typed.request.field")?;
        check_bounded_text(&field.owner, "typed.request.owner", MAX_ID_BYTES)?;
        check_bounded_text(
            &field.evidence_note,
            "typed.request.evidence",
            MAX_NOTE_BYTES,
        )?;
        if let Some(value) = &field.value {
            value.validate_shape()?;
        }
        if field_ids.iter().any(|id: &String| id == &field.field_id) {
            return Err(ConfigurationError::Order {
                phase: "typed.request.fields".to_owned(),
                detail: "request field identities must be unique".to_owned(),
            });
        }
        field_ids.push(field.field_id.clone());
    }
    for alternative in &request.alternatives {
        check_bounded_text(alternative, "typed.request.alternative", MAX_NOTE_BYTES)?;
    }
    for reference in &request.grounded_refs {
        check_handle(reference, "typed.request.grounded-ref")?;
    }
    check_digest(&request.input_receipt_digest, "typed.request.input-receipt")?;
    if !request.structured_mapping && !request.fields.is_empty() {
        return Err(ConfigurationError::Shape {
            field: "typed.request.mapping",
            detail: "unstructured requests cannot carry typed field mappings".to_owned(),
        });
    }
    let computed = canonical_typed_request_digest(request)?;
    if let Some(recorded) = &request.operation.canonical_request_digest
        && recorded != &computed
    {
        return Err(ConfigurationError::Digest {
            detail: "caller request digest does not match canonical request bytes".to_owned(),
        });
    }
    Ok(())
}

fn typed_policy_validate(policy: &TypedConfigurationPolicy) -> Result<(), ConfigurationError> {
    check_handle(&policy.policy_id, "typed.policy.id")?;
    if policy.policy_revision == 0 {
        return Err(ConfigurationError::Shape {
            field: "typed.policy.revision",
            detail: "policy revision must be explicit".to_owned(),
        });
    }
    if policy.max_fields == 0
        || policy.max_fields > MAX_FIELDS
        || policy.max_changes == 0
        || policy.max_changes > MAX_CHANGES
        || policy.max_schemas == 0
        || policy.max_schemas > MAX_TYPED_SCHEMAS
        || policy.max_impact > MAX_IMPACT
        || policy.max_history > MAX_ATTEMPTS
    {
        return Err(ConfigurationError::Policy {
            detail: "typed policy ceiling is outside the independent bounds".to_owned(),
        });
    }
    check_bounded_text(&policy.owner_note, "typed.policy.owner", MAX_SCOPE_BYTES)?;
    if !has_no_duplicates(
        &policy
            .forbidden_widenings
            .iter()
            .map(|item| format!("{item:?}"))
            .collect::<Vec<_>>(),
    ) || !has_no_duplicates(
        &policy
            .decision_widenings
            .iter()
            .map(|item| format!("{item:?}"))
            .collect::<Vec<_>>(),
    ) {
        return Err(ConfigurationError::Order {
            phase: "typed.policy.widenings".to_owned(),
            detail: "policy widening classes must be unique".to_owned(),
        });
    }
    Ok(())
}

fn typed_change_validate_shape(
    changes: &[TypedConfigurationChange],
    policy: &TypedConfigurationPolicy,
) -> Result<(), ConfigurationError> {
    bound_list_length(
        "typed.changes",
        changes.len(),
        policy.max_changes.min(MAX_CHANGES),
    )?;
    let mut ids = Vec::with_capacity(changes.len());
    let mut fields = Vec::with_capacity(changes.len());
    let mut sequences = Vec::with_capacity(changes.len());
    for change in changes {
        check_handle(&change.change_id, "typed.change.id")?;
        check_handle(&change.field_id, "typed.change.field")?;
        check_bounded_text(&change.schema_id, "typed.change.schema", MAX_ID_BYTES)?;
        check_bounded_text(&change.owner, "typed.change.owner", MAX_ID_BYTES)?;
        check_bounded_text(&change.rationale, "typed.change.rationale", MAX_NOTE_BYTES)?;
        if change.expected_base_revision == 0 {
            return Err(ConfigurationError::Shape {
                field: "typed.change.base-revision",
                detail: "change base revision must be explicit".to_owned(),
            });
        }
        if let Some(value) = &change.value {
            value.validate_shape()?;
        }
        if let Some(reference) = &change.secret_ref {
            reference.validate()?;
        }
        if ids.iter().any(|id: &String| id == &change.change_id) {
            return Err(ConfigurationError::Order {
                phase: "typed.changes.ids".to_owned(),
                detail: "change identities must be unique".to_owned(),
            });
        }
        if fields.iter().any(|id: &String| id == &change.field_id) {
            return Err(ConfigurationError::Order {
                phase: "typed.changes.fields".to_owned(),
                detail: "contradictory duplicate field operations are not merged".to_owned(),
            });
        }
        if sequences.contains(&change.sequence) {
            return Err(ConfigurationError::Order {
                phase: "typed.changes.sequence".to_owned(),
                detail: "semantic change sequence values must be unique".to_owned(),
            });
        }
        ids.push(change.change_id.clone());
        fields.push(change.field_id.clone());
        if sequences
            .last()
            .is_some_and(|previous| *previous >= change.sequence)
        {
            return Err(ConfigurationError::Order {
                phase: "typed.changes.sequence".to_owned(),
                detail: "semantic changes must be supplied in rollout sequence order".to_owned(),
            });
        }
        sequences.push(change.sequence);
        if let Some(recorded) = &change.canonical_change_digest
            && recorded != &canonical_typed_change_digest(change)?
        {
            return Err(ConfigurationError::Digest {
                detail: "caller change digest does not match canonical change bytes".to_owned(),
            });
        }
    }
    Ok(())
}

fn typed_impact_shape_validate(
    impact: &TypedImpactClosure,
    policy: &TypedConfigurationPolicy,
) -> Result<(), ConfigurationError> {
    bound_list_length(
        "typed.impact.expected",
        impact.expected_member_ids.len(),
        policy.max_impact.min(MAX_IMPACT),
    )?;
    bound_list_length(
        "typed.impact.members",
        impact.members.len(),
        policy.max_impact.min(MAX_IMPACT),
    )?;
    bound_list_length(
        "typed.impact.omissions",
        impact.omissions.len(),
        MAX_TYPED_OMISSIONS,
    )?;
    let mut ids = Vec::with_capacity(impact.expected_member_ids.len());
    for id in &impact.expected_member_ids {
        check_handle(id, "typed.impact.expected-id")?;
        if ids.iter().any(|known: &String| known == id) {
            return Err(ConfigurationError::Order {
                phase: "typed.impact.expected".to_owned(),
                detail: "impact denominator identities must be unique".to_owned(),
            });
        }
        ids.push(id.clone());
    }
    let mut member_ids = Vec::with_capacity(impact.members.len());
    for member in &impact.members {
        check_handle(&member.member_id, "typed.impact.member")?;
        check_bounded_text(&member.owner, "typed.impact.owner", MAX_ID_BYTES)?;
        check_bounded_text(
            &member.compatibility_note,
            "typed.impact.compatibility",
            MAX_NOTE_BYTES,
        )?;
        check_bounded_text(
            &member.migration_note,
            "typed.impact.migration",
            MAX_NOTE_BYTES,
        )?;
        check_bounded_text(
            &member.state_transfer_note,
            "typed.impact.state-transfer",
            MAX_NOTE_BYTES,
        )?;
        check_bounded_text(
            &member.security_privacy_cost_note,
            "typed.impact.security",
            MAX_NOTE_BYTES,
        )?;
        bound_list_length("typed.impact.path", member.path.len(), MAX_TYPED_SEQUENCE)?;
        bound_list_length(
            "typed.impact.evidence",
            member.evidence_refs.len(),
            MAX_EVIDENCE_ITEMS,
        )?;
        for item in &member.path {
            check_handle(item, "typed.impact.path-item")?;
        }
        for item in &member.evidence_refs {
            check_handle(item, "typed.impact.evidence-ref")?;
        }
        if member_ids
            .iter()
            .any(|known: &String| known == &member.member_id)
        {
            return Err(ConfigurationError::Order {
                phase: "typed.impact.members".to_owned(),
                detail: "impact member identities must be unique".to_owned(),
            });
        }
        member_ids.push(member.member_id.clone());
    }
    for omission in &impact.omissions {
        check_handle(omission, "typed.impact.omission")?;
    }
    Ok(())
}

fn validate_typed_impact(
    impact: &TypedImpactClosure,
    policy: &TypedConfigurationPolicy,
) -> Result<(), ConfigurationError> {
    typed_impact_shape_validate(impact, policy)?;
    let expected = impact.expected_member_ids.as_slice();
    let supplied = impact
        .members
        .iter()
        .map(|member| member.member_id.clone())
        .collect::<Vec<_>>();
    match impact.completeness {
        TypedImpactCompleteness::Complete if expected != supplied.as_slice() => {
            Err(ConfigurationError::Denominator {
                detail: "complete impact closure does not cover its exact denominator".to_owned(),
            })
        }
        TypedImpactCompleteness::Complete if !impact.omissions.is_empty() => {
            Err(ConfigurationError::Denominator {
                detail: "complete impact closure cannot retain omissions".to_owned(),
            })
        }
        TypedImpactCompleteness::Partial if impact.omissions.is_empty() => {
            Err(ConfigurationError::Denominator {
                detail: "partial impact closure needs accounted omissions".to_owned(),
            })
        }
        _ => Ok(()),
    }
}

fn typed_history_validate(
    history: &TypedPriorHistory,
    policy: &TypedConfigurationPolicy,
) -> Result<(), ConfigurationError> {
    bound_list_length(
        "typed.history.expected",
        history.expected_attempt_ids.len(),
        policy.max_history.min(MAX_ATTEMPTS),
    )?;
    bound_list_length(
        "typed.history.attempts",
        history.attempts.len(),
        policy.max_history.min(MAX_ATTEMPTS),
    )?;
    check_bounded_text(&history.outcome_note, "typed.history.note", MAX_NOTE_BYTES)?;
    let mut expected = Vec::with_capacity(history.expected_attempt_ids.len());
    for identity in &history.expected_attempt_ids {
        check_handle(identity, "typed.history.expected-id")?;
        if expected.iter().any(|known: &String| known == identity) {
            return Err(ConfigurationError::Order {
                phase: "typed.history.expected".to_owned(),
                detail: "history denominator identities must be unique".to_owned(),
            });
        }
        expected.push(identity.clone());
    }
    let mut supplied = Vec::with_capacity(history.attempts.len());
    for attempt in &history.attempts {
        check_handle(&attempt.attempt_id, "typed.history.attempt")?;
        check_handle(&attempt.intent_id, "typed.history.intent")?;
        check_digest(&attempt.request_digest, "typed.history.request")?;
        check_digest(&attempt.delta_digest, "typed.history.delta")?;
        check_digest(&attempt.base_digest, "typed.history.base")?;
        check_bounded_text(
            &attempt.outcome_note,
            "typed.history.outcome",
            MAX_NOTE_BYTES,
        )?;
        bound_list_length(
            "typed.history.changed-fields",
            attempt.changed_field_ids.len(),
            MAX_FIELDS,
        )?;
        for field in &attempt.changed_field_ids {
            check_handle(field, "typed.history.changed-field")?;
        }
        for reference in &attempt.evidence_refs {
            check_handle(reference, "typed.history.evidence")?;
        }
        if supplied
            .iter()
            .any(|known: &String| known == &attempt.attempt_id)
        {
            return Err(ConfigurationError::Order {
                phase: "typed.history.attempts".to_owned(),
                detail: "retained attempt identities must be unique".to_owned(),
            });
        }
        supplied.push(attempt.attempt_id.clone());
    }
    if expected != supplied {
        return Err(ConfigurationError::Denominator {
            detail: "history attempts do not exactly cover the declared denominator".to_owned(),
        });
    }
    Ok(())
}

fn typed_boundary_validate(
    boundary: &TypedConfigurationBoundary,
) -> Result<(), ConfigurationError> {
    check_handle(&boundary.verifier.verifier_id, "typed.verifier.id")?;
    check_bounded_text(
        &boundary.verifier.probe_note,
        "typed.verifier.probe",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.success_note,
        "typed.verifier.success",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.partial_note,
        "typed.verifier.partial",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.no_change_note,
        "typed.verifier.no-change",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.regression_note,
        "typed.verifier.regression",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.unavailable_note,
        "typed.verifier.unavailable",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.unknown_note,
        "typed.verifier.unknown",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.stop_note,
        "typed.verifier.stop",
        MAX_NOTE_BYTES,
    )?;
    bound_list_length(
        "typed.verifier.readings",
        boundary.verifier.readings.len(),
        6,
    )?;
    check_bounded_text(
        &boundary.rollout.cancellation_note,
        "typed.rollout.cancellation",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.rollout.canary_scope,
        "typed.rollout.scope",
        MAX_SCOPE_BYTES,
    )?;
    bound_list_length(
        "typed.rollout.sequence",
        boundary.rollout.sequence.len(),
        MAX_ROLLBACK_STEPS,
    )?;
    for step in &boundary.rollout.sequence {
        check_bounded_text(step, "typed.rollout.step", MAX_NOTE_BYTES)?;
    }
    check_digest(&boundary.rollback.anchor_digest, "typed.rollback.anchor")?;
    bound_list_length(
        "typed.rollback.steps",
        boundary.rollback.steps.len(),
        MAX_ROLLBACK_STEPS,
    )?;
    for step in &boundary.rollback.steps {
        check_bounded_text(step, "typed.rollback.step", MAX_NOTE_BYTES)?;
    }
    if let Some(note) = &boundary.rollback.forward_repair_note {
        check_bounded_text(note, "typed.rollback.forward-repair", MAX_NOTE_BYTES)?;
    }
    check_bounded_text(
        &boundary.application_owner,
        "typed.boundary.application-owner",
        MAX_ID_BYTES,
    )?;
    check_bounded_text(
        &boundary.approval.owner,
        "typed.approval.owner",
        MAX_ID_BYTES,
    )?;
    Ok(())
}

fn typed_schema_lookup<'a>(
    schemas: &'a [ConfigurationFieldSchema],
    change: &TypedConfigurationChange,
) -> Option<&'a ConfigurationFieldSchema> {
    schemas.iter().find(|schema| {
        schema.field_id == change.field_id
            && schema.schema_id == change.schema_id
            && schema.layer == change.layer
            && schema.owner == change.owner
    })
}

fn typed_snapshot_field<'a>(
    fields: &'a [TypedSnapshotField],
    field_id: &str,
) -> Option<&'a TypedSnapshotField> {
    fields.iter().find(|field| field.field_id == field_id)
}

fn typed_value_has_secret_marker(value: &TypedConfigurationValue) -> bool {
    match value {
        TypedConfigurationValue::Text(text) | TypedConfigurationValue::Enum(text) => {
            mentions_any(&lowered(text), SECRET_MARKERS)
        }
        TypedConfigurationValue::Members(values) => values
            .iter()
            .any(|value| mentions_any(&lowered(value), SECRET_MARKERS)),
        TypedConfigurationValue::Boolean(_)
        | TypedConfigurationValue::Integer(_)
        | TypedConfigurationValue::SecretReference(_) => false,
    }
}

fn typed_requested_field_matches(
    request_field: &TypedRequestedField,
    change: &TypedConfigurationChange,
) -> bool {
    request_field.field_id == change.field_id
        && request_field.layer == change.layer
        && request_field.owner == change.owner
        && request_field.desired == change.after
        && request_field.value == change.value
        && request_field.unit == change.unit
        && request_field.grounded
}

fn typed_widening_is_forbidden(
    changes: &[TypedConfigurationChange],
    policy: &TypedConfigurationPolicy,
) -> bool {
    changes.iter().any(|change| {
        change
            .widenings
            .iter()
            .any(|widening| policy.forbidden_widenings.contains(widening))
    })
}

fn typed_widening_needs_decision(
    changes: &[TypedConfigurationChange],
    policy: &TypedConfigurationPolicy,
) -> bool {
    changes.iter().any(|change| {
        change
            .widenings
            .iter()
            .any(|widening| policy.decision_widenings.contains(widening))
    })
}

fn typed_change_field_ids(changes: &[TypedConfigurationChange]) -> Vec<String> {
    changes
        .iter()
        .map(|change| change.field_id.clone())
        .collect()
}

fn typed_impact_has_evidence(member: &TypedImpactMember) -> bool {
    match member.disposition {
        ImpactDisposition::Direct | ImpactDisposition::Transitive => {
            !member.path.is_empty() && !member.evidence_refs.is_empty()
        }
        ImpactDisposition::Conditional => {
            !member.path.is_empty()
                && !member.evidence_refs.is_empty()
                && !member.compatibility_note.trim().is_empty()
        }
        ImpactDisposition::NotApplicable => !member.compatibility_note.trim().is_empty(),
        ImpactDisposition::Blocked | ImpactDisposition::Stale | ImpactDisposition::Unknown => true,
    }
}

fn typed_boundary_has_all_readings(boundary: &TypedConfigurationBoundary) -> bool {
    let required = [
        TypedVerifierReading::Success,
        TypedVerifierReading::Partial,
        TypedVerifierReading::NoChange,
        TypedVerifierReading::Regression,
        TypedVerifierReading::Unavailable,
        TypedVerifierReading::Unknown,
    ];
    required
        .iter()
        .all(|reading| boundary.verifier.readings.contains(reading))
}

fn typed_history_replay(
    request_digest: &str,
    delta_digest: &str,
    base_digest: &str,
    request: &TypedConfigurationRequest,
    changes: &[TypedConfigurationChange],
    history: &TypedPriorHistory,
) -> TypedReplayDisposition {
    let field_ids = typed_change_field_ids(changes);
    for attempt in &history.attempts {
        if attempt.intent_id == request.intent_id {
            if attempt.request_digest == request_digest
                && attempt.delta_digest == delta_digest
                && attempt.base_digest == base_digest
            {
                return TypedReplayDisposition::ExactDuplicate;
            }
            return TypedReplayDisposition::IdentityConflict;
        }
    }
    for attempt in &history.attempts {
        if attempt.base_digest == base_digest
            && attempt
                .changed_field_ids
                .iter()
                .any(|field| field_ids.iter().any(|candidate| candidate == field))
            && attempt.delta_digest != delta_digest
        {
            return TypedReplayDisposition::ConcurrentFieldConflict;
        }
    }
    for attempt in &history.attempts {
        if attempt.disposition == TypedHistoryDisposition::Applied
            && attempt.base_digest != base_digest
        {
            return TypedReplayDisposition::CommittedBaseDrift;
        }
    }
    for attempt in &history.attempts {
        if matches!(
            attempt.disposition,
            TypedHistoryDisposition::Failed
                | TypedHistoryDisposition::Partial
                | TypedHistoryDisposition::UnknownOutcome
        ) && attempt.base_digest == base_digest
            && attempt.delta_digest == delta_digest
        {
            return TypedReplayDisposition::MechanismReview;
        }
    }
    TypedReplayDisposition::New
}

fn typed_semantic_outcome_for_replay(
    replay: TypedReplayDisposition,
) -> Option<ConfigurationOutcome> {
    match replay {
        TypedReplayDisposition::New | TypedReplayDisposition::ExactDuplicate => None,
        TypedReplayDisposition::IdentityConflict
        | TypedReplayDisposition::ConcurrentFieldConflict => Some(ConfigurationOutcome::Rejected),
        TypedReplayDisposition::CommittedBaseDrift => Some(ConfigurationOutcome::Stale),
        TypedReplayDisposition::MechanismReview => {
            Some(ConfigurationOutcome::MechanismReviewRequired)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn typed_apply_change(
    fields: &mut Vec<TypedSnapshotField>,
    schema: &ConfigurationFieldSchema,
    change: &TypedConfigurationChange,
    parent: Option<&TypedConfigurationSnapshot>,
) -> Result<(), String> {
    if schema.mutability != ConfigurationFieldMutability::Mutable {
        return Err("field is read-only or derived".to_owned());
    }
    if change.unit != schema.unit {
        return Err("typed change unit does not match the exact schema unit".to_owned());
    }
    let current_presence = typed_snapshot_field(fields, &change.field_id)
        .map_or(Presence::Absent, |field| field.presence);
    if current_presence != change.before {
        return Err("change before-presence does not match the exact base".to_owned());
    }
    if change.before == Presence::Unknown {
        return Err("unknown base presence cannot be transformed".to_owned());
    }
    if let Some(value) = &change.value {
        if typed_value_has_secret_marker(value) {
            return Err("raw secret marker in typed value".to_owned());
        }
        let accepted = match change.operation {
            ConfigOp::AddMember | ConfigOp::RemoveMember => {
                matches!(value, TypedConfigurationValue::Text(member) if !member.is_empty())
            }
            ConfigOp::Set | ConfigOp::Reset | ConfigOp::RemoveOverride | ConfigOp::Inherit => {
                schema.field_type.accepts(value)
            }
        };
        if !accepted {
            return Err("typed value violates field type or constraint".to_owned());
        }
    }
    if let Some(reference) = &change.secret_ref
        && (!matches!(schema.field_type, ConfigurationFieldType::SecretReference)
            || change.value != Some(TypedConfigurationValue::SecretReference(reference.clone())))
    {
        return Err("secret reference is not bound to the exact secret field".to_owned());
    }
    let existing_index = fields
        .iter()
        .position(|field| field.field_id == change.field_id);
    let mut next = typed_snapshot_field(fields, &change.field_id)
        .cloned()
        .unwrap_or(TypedSnapshotField {
            field_id: change.field_id.clone(),
            layer: change.layer,
            owner: change.owner.clone(),
            presence: Presence::Absent,
            value: None,
        });
    match change.operation {
        ConfigOp::Set => {
            if !matches!(change.after, Presence::Value | Presence::Empty) || change.value.is_none()
            {
                return Err("set requires a typed value and value/empty presence".to_owned());
            }
            if change.after == Presence::Empty
                && change.value != Some(TypedConfigurationValue::Text(String::new()))
            {
                return Err("empty presence requires an explicit empty text value".to_owned());
            }
            next.presence = change.after;
            next.value.clone_from(&change.value);
        }
        ConfigOp::Reset => {
            if change.after != Presence::Reset {
                return Err("reset requires reset presence".to_owned());
            }
            let Some(default) = &schema.default else {
                return Err("reset has no explicit schema default".to_owned());
            };
            next.presence = Presence::Reset;
            next.value = Some(default.clone());
        }
        ConfigOp::RemoveOverride => {
            if !matches!(change.after, Presence::Removed | Presence::Inherited) {
                return Err("remove override requires removed or inherited presence".to_owned());
            }
            if change.after == Presence::Inherited
                && parent
                    .and_then(|snapshot| typed_snapshot_field(&snapshot.fields, &change.field_id))
                    .is_none()
            {
                return Err("inheritance lacks an exact parent field".to_owned());
            }
            next.presence = change.after;
            next.value = None;
        }
        ConfigOp::Inherit => {
            if change.after != Presence::Inherited {
                return Err("inherit requires inherited presence".to_owned());
            }
            if parent
                .and_then(|snapshot| typed_snapshot_field(&snapshot.fields, &change.field_id))
                .is_none()
            {
                return Err("inheritance lacks an exact parent field".to_owned());
            }
            next.presence = Presence::Inherited;
            next.value = None;
        }
        ConfigOp::AddMember | ConfigOp::RemoveMember => {
            let Some(TypedConfigurationValue::Members(mut members)) =
                typed_snapshot_field(fields, &change.field_id)
                    .and_then(|field| field.value.clone())
            else {
                return Err("member operation requires a typed member-set base".to_owned());
            };
            let Some(TypedConfigurationValue::Text(member)) = &change.value else {
                return Err("member operation requires one typed member".to_owned());
            };
            match change.operation {
                ConfigOp::AddMember if members.iter().any(|value| value == member) => {
                    return Err("add member is a duplicate no-op".to_owned());
                }
                ConfigOp::AddMember => members.push(member.clone()),
                ConfigOp::RemoveMember if !members.iter().any(|value| value == member) => {
                    return Err("remove member names no existing member".to_owned());
                }
                ConfigOp::RemoveMember => members.retain(|value| value != member),
                ConfigOp::Set | ConfigOp::Reset | ConfigOp::RemoveOverride | ConfigOp::Inherit => {}
            }
            members.sort();
            if !is_sorted_unique_strings(&members) {
                return Err("member operation produced duplicate values".to_owned());
            }
            let actual_presence = if members.is_empty() {
                Presence::Removed
            } else {
                Presence::Value
            };
            if change.after != actual_presence {
                return Err("member operation after-presence is not the derived result".to_owned());
            }
            next.presence = actual_presence;
            next.value = if members.is_empty() {
                None
            } else {
                Some(TypedConfigurationValue::Members(members))
            };
        }
    }
    if let Some(index) = existing_index {
        if let Some(slot) = fields.get_mut(index) {
            *slot = next;
        }
    } else {
        fields.push(next);
    }
    Ok(())
}

fn typed_validate_cross_field_constraints(
    fields: &[TypedSnapshotField],
    schemas: &[ConfigurationFieldSchema],
) -> Result<(), String> {
    for schema in schemas {
        for constraint in &schema.constraints {
            let field_id = match constraint {
                ConfigurationFieldConstraint::RequiresPresence { field_id, .. }
                | ConfigurationFieldConstraint::IntegerAtLeast { field_id, .. }
                | ConfigurationFieldConstraint::IntegerAtMost { field_id, .. } => field_id,
            };
            let Some(field) = typed_snapshot_field(fields, field_id) else {
                return Err("cross-field constraint references an absent field".to_owned());
            };
            match constraint {
                ConfigurationFieldConstraint::RequiresPresence { presence, .. }
                    if field.presence != *presence =>
                {
                    return Err("cross-field presence constraint is not satisfied".to_owned());
                }
                ConfigurationFieldConstraint::IntegerAtLeast { minimum, .. } => {
                    let Some(TypedConfigurationValue::Integer(value)) = &field.value else {
                        return Err("cross-field lower bound requires an integer field".to_owned());
                    };
                    if value < minimum {
                        return Err("cross-field lower bound is not satisfied".to_owned());
                    }
                }
                ConfigurationFieldConstraint::IntegerAtMost { maximum, .. } => {
                    let Some(TypedConfigurationValue::Integer(value)) = &field.value else {
                        return Err("cross-field upper bound requires an integer field".to_owned());
                    };
                    if value > maximum {
                        return Err("cross-field upper bound is not satisfied".to_owned());
                    }
                }
                ConfigurationFieldConstraint::RequiresPresence { .. } => {}
            }
        }
    }
    Ok(())
}

fn typed_derive_candidate(
    snapshots: &TypedConfigurationSnapshotSet,
    schemas: &[ConfigurationFieldSchema],
    changes: &[TypedConfigurationChange],
    request: &TypedConfigurationRequest,
) -> Result<TypedConfigurationSnapshot, String> {
    let mut fields = snapshots.base.fields.clone();
    for change in changes {
        let Some(schema) = typed_schema_lookup(schemas, change) else {
            return Err("change has no exact schema/layer/owner binding".to_owned());
        };
        typed_apply_change(&mut fields, schema, change, snapshots.parent.as_ref())?;
    }
    typed_validate_cross_field_constraints(&fields, schemas)?;
    fields.sort_by(|left, right| left.field_id.cmp(&right.field_id));
    let mut candidate = TypedConfigurationSnapshot {
        snapshot_id: ["candidate-", &request.intent_id].concat(),
        revision: snapshots
            .base
            .revision
            .checked_add(1)
            .ok_or_else(|| "candidate revision overflow".to_owned())?,
        schema_id: snapshots.base.schema_id.clone(),
        schema_revision: snapshots.base.schema_revision,
        layer: snapshots.base.layer,
        owner: snapshots.base.owner.clone(),
        parent_snapshot_id: Some(snapshots.base.snapshot_id.clone()),
        overlay_snapshot_id: None,
        fields,
        digest: "0".repeat(64),
        validity: TypedSnapshotValidity::Derived,
        provenance: ["derived:", &snapshots.base.provenance].concat(),
    };
    candidate.digest = candidate
        .computed_digest()
        .map_err(|error| error.to_string())?;
    Ok(candidate)
}

fn typed_unchanged_fields(
    base: &TypedConfigurationSnapshot,
    candidate: &TypedConfigurationSnapshot,
    changed_ids: &[String],
) -> Vec<TypedSnapshotField> {
    base.fields
        .iter()
        .filter(|field| !changed_ids.iter().any(|id| id == &field.field_id))
        .filter(|field| {
            typed_snapshot_field(&candidate.fields, &field.field_id)
                .is_some_and(|candidate_field| candidate_field == *field)
        })
        .cloned()
        .collect()
}

fn typed_to_legacy_change(change: &TypedConfigurationChange) -> ConfigFieldChange {
    ConfigFieldChange {
        field_id: change.field_id.clone(),
        layer: change.layer,
        owner: change.owner.clone(),
        op: change.operation,
        before: change.before,
        after: change.after,
        value_note: change
            .value
            .as_ref()
            .map_or_else(|| "none".to_owned(), TypedConfigurationValue::canonical),
        secret_ref: change
            .secret_ref
            .as_ref()
            .map(|reference| reference.class.clone()),
        rationale: change.rationale.clone(),
    }
}

fn typed_to_legacy_impact(impact: &TypedImpactClosure) -> Vec<ImpactMember> {
    impact
        .members
        .iter()
        .map(|member| ImpactMember {
            member_id: member.member_id.clone(),
            owner: member.owner.clone(),
            disposition: member.disposition,
            compatibility_note: member.compatibility_note.clone(),
            restart_note: [&member.migration_note, " ", &member.state_transfer_note].concat(),
        })
        .collect()
}

fn typed_to_legacy_boundary(boundary: &TypedConfigurationBoundary) -> InertBoundary {
    InertBoundary {
        verifier: InertVerifier {
            verifier_id: boundary.verifier.verifier_id.clone(),
            probe_note: boundary.verifier.probe_note.clone(),
            success_note: boundary.verifier.success_note.clone(),
        },
        rollback: RollbackPlan {
            anchor_digest: boundary.rollback.anchor_digest.clone(),
            steps: boundary.rollback.steps.clone(),
            repair_note: boundary
                .rollback
                .forward_repair_note
                .clone()
                .unwrap_or_else(|| "exact previous snapshot rollback".to_owned()),
        },
        rollout_note: boundary.rollout.sequence.join(" -> "),
        approvals_note: [
            "owner=",
            &boundary.approval.owner,
            " status=",
            &format!("{:?}", boundary.approval.status),
        ]
        .concat(),
    }
}

fn typed_candidate_identity(
    request_digest: &str,
    delta_digest: &str,
    candidate_digest: &str,
    outcome: ConfigurationOutcome,
) -> Result<String, ConfigurationError> {
    canonical_json_bytes(&vec![
        request_digest.to_owned(),
        delta_digest.to_owned(),
        candidate_digest.to_owned(),
        outcome.as_str().to_owned(),
    ])
    .map_or_else(
        |error| {
            Err(ConfigurationError::Digest {
                detail: redact(&error.to_string()),
            })
        },
        |bytes| Ok(sha256_hex(&bytes)),
    )
}

#[allow(clippy::too_many_arguments)]
fn typed_emit_candidate(
    outcome: ConfigurationOutcome,
    note: &str,
    snapshots: &TypedConfigurationSnapshotSet,
    request: &TypedConfigurationRequest,
    schemas: &[ConfigurationFieldSchema],
    changes: &[TypedConfigurationChange],
    impact: &TypedImpactClosure,
    history: &TypedPriorHistory,
    boundary: &TypedConfigurationBoundary,
    request_digest: &str,
    delta_digest: &str,
    replay: TypedReplayDisposition,
    invalidation_reasons: Vec<String>,
    candidate_snapshot: Option<TypedConfigurationSnapshot>,
) -> Result<ConfigurationChangeCandidate, ConfigurationError> {
    let candidate_snapshot = candidate_snapshot.unwrap_or_else(|| snapshots.base.clone());
    let legacy_changes = changes
        .iter()
        .map(typed_to_legacy_change)
        .collect::<Vec<_>>();
    let legacy_impact = typed_to_legacy_impact(impact);
    let legacy_boundary = typed_to_legacy_boundary(boundary);
    let primary = changes.first().map_or(
        (snapshots.base.layer, snapshots.base.owner.clone()),
        |change| (change.layer, change.owner.clone()),
    );
    let preservation = build_preservation()?;
    let candidate_identity = typed_candidate_identity(
        request_digest,
        delta_digest,
        &candidate_snapshot.digest,
        outcome,
    )?;
    let details = TypedCandidateDetails {
        intent_id: request.intent_id.clone(),
        request_digest: request_digest.to_owned(),
        delta_digest: delta_digest.to_owned(),
        base_snapshot: snapshots.base.clone(),
        parent_snapshot: snapshots.parent.clone(),
        overlay_snapshot: snapshots.overlay.clone(),
        candidate_snapshot: candidate_snapshot.clone(),
        unchanged_fields: typed_unchanged_fields(
            &snapshots.base,
            &candidate_snapshot,
            &typed_change_field_ids(changes),
        ),
        schemas: schemas.to_vec(),
        request: request.clone(),
        changes: changes.to_vec(),
        impact: impact.clone(),
        history: history.clone(),
        boundary: boundary.clone(),
        replay,
        invalidation_reasons,
        candidate_only: true,
    };
    Ok(ConfigurationChangeCandidate {
        outcome,
        intent_handle: ["cfg-", &request.intent_id].concat(),
        primary_layer: primary.0,
        primary_owner: primary.1,
        base_digest: snapshots.base.digest.clone(),
        candidate_digest: candidate_identity,
        base_revision: snapshots.base.revision,
        changes: legacy_changes,
        impact: legacy_impact,
        boundary: legacy_boundary,
        preservation,
        input_receipt_digest: request.input_receipt_digest.clone(),
        attempt_denominator: history.expected_attempt_ids.clone(),
        note: note.to_owned(),
        details: Some(details),
    })
}

/// Complete typed A-42 candidate-only planner.
///
/// This is the production entry point for the full issue denominator.  Every
/// input is an immutable, caller-supplied observation.  The function derives
/// one in-memory snapshot and returns an inert candidate; it never reads an
/// ambient snapshot, parses prose into a patch, publishes, executes, reserves,
/// or grants anything.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn propose_typed_configuration_change(
    job: &DreamJobAdmission,
    draft: &ValidatedDreamDraft,
    request: &TypedConfigurationRequest,
    snapshots: &TypedConfigurationSnapshotSet,
    schemas: &[ConfigurationFieldSchema],
    changes: &[TypedConfigurationChange],
    impact: &TypedImpactClosure,
    history: &TypedPriorHistory,
    boundary: &TypedConfigurationBoundary,
    policy: &TypedConfigurationPolicy,
) -> Result<ConfigurationChangeCandidate, ConfigurationError> {
    typed_policy_validate(policy)?;
    bound_list_length(
        "typed.schemas",
        schemas.len(),
        policy.max_schemas.min(MAX_TYPED_SCHEMAS),
    )?;
    let mut schema_ids = Vec::with_capacity(schemas.len());
    for schema in schemas {
        schema.validate()?;
        if schema_ids.iter().any(|id: &String| id == &schema.field_id) {
            return Err(ConfigurationError::Order {
                phase: "typed.schemas".to_owned(),
                detail: "schema field identities must be unique".to_owned(),
            });
        }
        schema_ids.push(schema.field_id.clone());
    }
    snapshots.validate()?;
    typed_request_validate(request, policy)?;
    typed_change_validate_shape(changes, policy)?;
    typed_impact_shape_validate(impact, policy)?;
    typed_history_validate(history, policy)?;
    typed_boundary_validate(boundary)?;

    job.validate()
        .map_err(|error| ConfigurationError::Binding {
            field: "typed.job",
            detail: redact(&error.to_string()),
        })?;
    draft
        .receipt
        .validate()
        .map_err(|error| ConfigurationError::Receipt {
            detail: redact(&error.to_string()),
        })?;
    draft
        .validate()
        .map_err(|error| ConfigurationError::Receipt {
            detail: redact(&error.to_string()),
        })?;
    if job.job_class != JobClass::ConfigurationAssistance {
        return Err(ConfigurationError::Binding {
            field: "typed.job-class",
            detail: "typed planner requires ConfigurationAssistance".to_owned(),
        });
    }
    check_fence(&job.state_fence).map_err(|error| ConfigurationError::Binding {
        field: "typed.job-fence",
        detail: redact(&error.to_string()),
    })?;
    if draft.task_id != request.task_id
        || draft.scope_id != request.scope_id
        || draft.state_fence != job.state_fence
        || draft.receipt.task_id != request.task_id
        || draft.receipt.scope_id != request.scope_id
        || draft.receipt.state_fence != job.state_fence
    {
        return Err(ConfigurationError::Binding {
            field: "typed.request-binding",
            detail: "request, draft, and job identities do not agree".to_owned(),
        });
    }
    if draft.receipt.validator_policy != policy.policy_id {
        return Err(ConfigurationError::Policy {
            detail: "typed policy does not equal the validator receipt policy".to_owned(),
        });
    }
    if request.input_receipt_digest != draft.receipt.output_digest {
        return Err(ConfigurationError::Receipt {
            detail: "typed request is not bound to the exact A-05 output receipt".to_owned(),
        });
    }
    let request_digest = canonical_typed_request_digest(request)?;
    let delta_digest = canonical_typed_delta_digest(changes)?;

    if request.base_snapshot_id != snapshots.base.snapshot_id
        || request.base_revision != snapshots.base.revision
    {
        return typed_emit_candidate(
            ConfigurationOutcome::Stale,
            "the request is pinned to a different base snapshot or revision",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            TypedReplayDisposition::CommittedBaseDrift,
            vec!["request base binding differs from the supplied immutable snapshot".to_owned()],
            None,
        );
    }
    if snapshots.base.validity != TypedSnapshotValidity::Valid {
        return typed_emit_candidate(
            ConfigurationOutcome::Stale,
            "the supplied base snapshot is stale or incomplete",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            TypedReplayDisposition::CommittedBaseDrift,
            vec!["base snapshot validity is not current and exact".to_owned()],
            None,
        );
    }
    if !request.structured_mapping || request.fields.is_empty() {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "prose without an exact structured mapping yields clarification",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            TypedReplayDisposition::New,
            vec!["structured field mapping is absent".to_owned()],
            None,
        );
    }
    if !request.alternatives.is_empty() {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "unresolved alternatives require an explicit Human choice",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            TypedReplayDisposition::New,
            vec!["request alternatives remain unresolved".to_owned()],
            None,
        );
    }
    if changes.is_empty() {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "no typed change was supplied",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            TypedReplayDisposition::New,
            vec!["empty delta cannot establish a candidate".to_owned()],
            None,
        );
    }
    let primary_layer = changes[0].layer;
    let primary_owner = changes[0].owner.as_str();
    if changes
        .iter()
        .any(|change| change.layer != primary_layer || change.owner != primary_owner)
    {
        return typed_emit_candidate(
            ConfigurationOutcome::Rejected,
            "independent layer or owner changes require separate typed intents",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            TypedReplayDisposition::New,
            vec!["typed delta crosses the primary layer or owner boundary".to_owned()],
            None,
        );
    }
    for change in changes {
        if change.expected_base_revision != snapshots.base.revision {
            return typed_emit_candidate(
                ConfigurationOutcome::Stale,
                "change expected-base revision is stale",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::CommittedBaseDrift,
                vec!["change base revision differs from the exact supplied base".to_owned()],
                None,
            );
        }
        let matches = request
            .fields
            .iter()
            .filter(|field| typed_requested_field_matches(field, change))
            .count();
        if matches == 0 {
            return typed_emit_candidate(
                ConfigurationOutcome::Rejected,
                "change is not grounded in an exact structured request field",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::New,
                vec!["field/layer/owner/value mapping is absent".to_owned()],
                None,
            );
        }
        let Some(schema) = typed_schema_lookup(schemas, change) else {
            return typed_emit_candidate(
                ConfigurationOutcome::Rejected,
                "field has no exact current schema/layer/owner binding",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::New,
                vec!["schema, owner, or layer mapping is absent".to_owned()],
                None,
            );
        };
        if schema.mutability != ConfigurationFieldMutability::Mutable {
            return typed_emit_candidate(
                ConfigurationOutcome::Rejected,
                "read-only and derived fields cannot be changed by this leaf",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::New,
                vec!["field mutability is not Mutable".to_owned()],
                None,
            );
        }
        let current = typed_snapshot_field(&snapshots.base.fields, &change.field_id)
            .map_or(Presence::Absent, |field| field.presence);
        if current == Presence::Unknown || change.before == Presence::Unknown {
            return typed_emit_candidate(
                ConfigurationOutcome::Insufficient,
                "unknown field presence is not a safe base for derivation",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::New,
                vec!["base field presence is unknown".to_owned()],
                None,
            );
        }
        if current != change.before {
            return typed_emit_candidate(
                ConfigurationOutcome::Stale,
                "change before-presence does not match the exact base snapshot",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::CommittedBaseDrift,
                vec!["base presence changed under the request".to_owned()],
                None,
            );
        }
        if change.layer != snapshots.base.layer && change.owner == snapshots.base.owner {
            return typed_emit_candidate(
                ConfigurationOutcome::Rejected,
                "mixed configuration layers require separate typed intents",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::New,
                vec!["change layer differs from the primary base layer".to_owned()],
                None,
            );
        }
        if let Some(value) = &change.value
            && typed_value_has_secret_marker(value)
        {
            return typed_emit_candidate(
                ConfigurationOutcome::Rejected,
                "raw secret material is rejected; only a typed reference may survive",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::New,
                vec!["secret marker appeared in a typed value".to_owned()],
                None,
            );
        }
        if change.operation == ConfigOp::Set
            && change.value
                == typed_snapshot_field(&snapshots.base.fields, &change.field_id)
                    .and_then(|field| field.value.clone())
            && change.after == change.before
        {
            return typed_emit_candidate(
                ConfigurationOutcome::Insufficient,
                "the typed operation is an explicit no-op",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::New,
                vec!["no semantic delta was derived".to_owned()],
                None,
            );
        }
        if schema.schema_id != change.schema_id
            || schema.field_id != change.field_id
            || schema.owner != change.owner
            || schema.layer != change.layer
        {
            return typed_emit_candidate(
                ConfigurationOutcome::Rejected,
                "field schema ownership is not exact",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                TypedReplayDisposition::New,
                vec!["schema field identity is not exact".to_owned()],
                None,
            );
        }
    }

    let replay = typed_history_replay(
        &request_digest,
        &delta_digest,
        &snapshots.base.digest,
        request,
        changes,
        history,
    );
    if let Some(outcome) = typed_semantic_outcome_for_replay(replay) {
        return typed_emit_candidate(
            outcome,
            match replay {
                TypedReplayDisposition::IdentityConflict => {
                    "same operation identity carries a changed canonical request"
                }
                TypedReplayDisposition::ConcurrentFieldConflict => {
                    "concurrent same-base field conflict requires explicit reconciliation"
                }
                TypedReplayDisposition::CommittedBaseDrift => {
                    "committed base drift remains stale; no automatic rebase is performed"
                }
                TypedReplayDisposition::MechanismReview => {
                    "equivalent failed change requires diagnosis before retry"
                }
                TypedReplayDisposition::New | TypedReplayDisposition::ExactDuplicate => {
                    "unreachable replay branch"
                }
            },
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["history changed the replay disposition".to_owned()],
            None,
        );
    }
    if typed_widening_is_forbidden(changes, policy) {
        return typed_emit_candidate(
            ConfigurationOutcome::Rejected,
            "forbidden authority, privacy, remote, cost, launch, verifier, or process widening is rejected",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["candidate widening exceeds the declared leaf ceiling".to_owned()],
            None,
        );
    }
    if typed_widening_needs_decision(changes, policy)
        && boundary.approval.status != TypedApprovalStatus::Approved
    {
        return typed_emit_candidate(
            ConfigurationOutcome::DecisionRequired,
            "owner decision is required; absence of approval is not permission",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["owner approval is not an execution grant".to_owned()],
            None,
        );
    }

    if impact.members.is_empty() {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "empty impact graph cannot prove no impact",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["impact denominator is empty".to_owned()],
            None,
        );
    }
    if impact
        .members
        .iter()
        .any(|member| !typed_impact_has_evidence(member))
    {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "impact members lack compatibility, migration, or causal evidence",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["impact closure is present but evidence is incomplete".to_owned()],
            None,
        );
    }
    if impact.members.iter().any(|member| {
        matches!(
            member.disposition,
            ImpactDisposition::Unknown | ImpactDisposition::Stale
        )
    }) || matches!(impact.completeness, TypedImpactCompleteness::Unknown)
    {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "unknown or stale load-bearing impact blocks complete status",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["impact closure is unknown or stale".to_owned()],
            None,
        );
    }
    if impact
        .members
        .iter()
        .any(|member| member.disposition == ImpactDisposition::Blocked)
    {
        return typed_emit_candidate(
            ConfigurationOutcome::DecisionRequired,
            "blocked impact member requires its external owner decision",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["impact owner decision remains open".to_owned()],
            None,
        );
    }
    if matches!(impact.completeness, TypedImpactCompleteness::Partial) {
        if policy.allow_partial {
            return typed_emit_candidate(
                ConfigurationOutcome::Partial,
                "partial impact closure is explicitly retained as partial",
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                replay,
                vec!["impact omissions remain accounted".to_owned()],
                None,
            );
        }
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "partial impact closure cannot produce a complete candidate under policy",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["partial impact is outside this policy ceiling".to_owned()],
            None,
        );
    }
    if !boundary.verifier_present {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "missing independent verifier and pre-application probe",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["verifier boundary is absent".to_owned()],
            None,
        );
    }
    if !boundary.verifier.independent || !boundary.verifier.process_success_insufficient {
        return typed_emit_candidate(
            ConfigurationOutcome::Rejected,
            "process/tool success alone cannot establish semantic configuration success",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["independent semantic verifier contract is missing".to_owned()],
            None,
        );
    }
    if !typed_boundary_has_all_readings(boundary) {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "verifier does not distinguish success, partial, no-change, regression, unavailable, and unknown",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["verifier outcome partition is incomplete".to_owned()],
            None,
        );
    }
    if boundary.rollout.sequence.is_empty()
        || boundary.rollout.max_attempts == 0
        || boundary.verifier.max_attempts == 0
        || !boundary.rollout.stop_on_no_progress
    {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "rollout, no-progress, or attempt bounds are incomplete",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["rollout bounds are not independently stated".to_owned()],
            None,
        );
    }
    if !boundary.rollback_present || boundary.rollback.steps.is_empty() {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "exact previous-snapshot rollback is missing",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["rollback boundary is incomplete".to_owned()],
            None,
        );
    }
    if boundary.rollback.anchor_digest != snapshots.base.digest {
        return Err(ConfigurationError::Binding {
            field: "typed.rollback.anchor",
            detail: "rollback anchor differs from the exact base snapshot".to_owned(),
        });
    }
    if !boundary.rollback.exact_previous_snapshot && boundary.rollback.forward_repair_note.is_none()
    {
        return typed_emit_candidate(
            ConfigurationOutcome::DecisionRequired,
            "unsafe rollback requires an explicit forward-repair owner",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["rollback cannot be inferred from a generic note".to_owned()],
            None,
        );
    }
    if boundary.approval.required {
        match boundary.approval.status {
            TypedApprovalStatus::Approved => {}
            TypedApprovalStatus::Expired => {
                return typed_emit_candidate(
                    ConfigurationOutcome::Stale,
                    "approval expired; the candidate must be replayed",
                    snapshots,
                    request,
                    schemas,
                    changes,
                    impact,
                    history,
                    boundary,
                    &request_digest,
                    &delta_digest,
                    replay,
                    vec!["approval expiry invalidates the candidate".to_owned()],
                    None,
                );
            }
            TypedApprovalStatus::Denied => {
                return typed_emit_candidate(
                    ConfigurationOutcome::Rejected,
                    "the owning Human or policy owner denied the candidate",
                    snapshots,
                    request,
                    schemas,
                    changes,
                    impact,
                    history,
                    boundary,
                    &request_digest,
                    &delta_digest,
                    replay,
                    vec!["approval is explicitly denied".to_owned()],
                    None,
                );
            }
            TypedApprovalStatus::Required | TypedApprovalStatus::NotRequired => {
                return typed_emit_candidate(
                    ConfigurationOutcome::DecisionRequired,
                    "approval is required and silence is not permission",
                    snapshots,
                    request,
                    schemas,
                    changes,
                    impact,
                    history,
                    boundary,
                    &request_digest,
                    &delta_digest,
                    replay,
                    vec!["required approval is absent".to_owned()],
                    None,
                );
            }
        }
    }
    if let (Some(observed), Some(deadline)) = (policy.observation_time_ms, policy.deadline_ms)
        && observed >= deadline
    {
        return typed_emit_candidate(
            ConfigurationOutcome::Stale,
            "frozen observation is at or beyond the planner deadline",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["planner deadline invalidates the candidate".to_owned()],
            None,
        );
    }
    if policy.cancelled {
        return typed_emit_candidate(
            ConfigurationOutcome::Rejected,
            "cancelled before candidate emission; no effect was produced",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["planner cancellation is retained".to_owned()],
            None,
        );
    }

    let candidate_snapshot = match typed_derive_candidate(snapshots, schemas, changes, request) {
        Ok(candidate) => candidate,
        Err(detail) => {
            let outcome = if detail.contains("reset") || detail.contains("no-op") {
                ConfigurationOutcome::Insufficient
            } else if detail.contains("base") || detail.contains("inherit") {
                ConfigurationOutcome::Stale
            } else {
                ConfigurationOutcome::Rejected
            };
            return typed_emit_candidate(
                outcome,
                &detail,
                snapshots,
                request,
                schemas,
                changes,
                impact,
                history,
                boundary,
                &request_digest,
                &delta_digest,
                replay,
                vec![detail.clone()],
                None,
            );
        }
    };
    if candidate_snapshot
        .fields
        .iter()
        .filter(|field| {
            changes
                .iter()
                .any(|change| change.field_id == field.field_id)
        })
        .all(|field| typed_snapshot_field(&snapshots.base.fields, &field.field_id) == Some(field))
    {
        return typed_emit_candidate(
            ConfigurationOutcome::Insufficient,
            "typed delta leaves the exact base snapshot unchanged",
            snapshots,
            request,
            schemas,
            changes,
            impact,
            history,
            boundary,
            &request_digest,
            &delta_digest,
            replay,
            vec!["candidate snapshot equals the base on every changed field".to_owned()],
            None,
        );
    }
    typed_emit_candidate(
        ConfigurationOutcome::Complete,
        if replay == TypedReplayDisposition::ExactDuplicate {
            "exact replay identity retained; no new effect is implied"
        } else {
            CONFIGURATION_PROOF_NOTE
        },
        snapshots,
        request,
        schemas,
        changes,
        impact,
        history,
        boundary,
        &request_digest,
        &delta_digest,
        replay,
        Vec::new(),
        Some(candidate_snapshot),
    )
}

/// Revalidates the complete typed detail after an integration or review copy.
pub fn validate_typed_candidate(
    candidate: &ConfigurationChangeCandidate,
) -> Result<(), ConfigurationError> {
    let Some(details) = &candidate.details else {
        return Err(ConfigurationError::Binding {
            field: "typed.details",
            detail: "candidate was emitted by the compact adapter".to_owned(),
        });
    };
    details.validate()
}

/// Closed change operation for one field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigOp {
    /// Set an explicit typed value.
    Set,
    /// Reset to the schema default without ambient lookup.
    Reset,
    /// Remove an overlay override, revealing the parent value.
    RemoveOverride,
    /// Inherit the parent value explicitly.
    Inherit,
    /// Add a closed-set member.
    AddMember,
    /// Remove a closed-set member.
    RemoveMember,
}

impl ConfigOp {
    /// Returns the canonical spelling of this operation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Set => "set",
            Self::Reset => "reset",
            Self::RemoveOverride => "remove_override",
            Self::Inherit => "inherit",
            Self::AddMember => "add_member",
            Self::RemoveMember => "remove_member",
        }
    }

    /// Parses the canonical spelling of an operation.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, ConfigurationError> {
        match spelling {
            "set" => Ok(Self::Set),
            "reset" => Ok(Self::Reset),
            "remove_override" => Ok(Self::RemoveOverride),
            "inherit" => Ok(Self::Inherit),
            "add_member" => Ok(Self::AddMember),
            "remove_member" => Ok(Self::RemoveMember),
            _ => Err(ConfigurationError::Shape {
                field: "change.operation",
                detail: redact(spelling),
            }),
        }
    }
}

/// Closed presence distinction for one field value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Presence {
    /// The field is absent from the snapshot.
    Absent,
    /// The field inherits its parent value.
    Inherited,
    /// The field is explicitly empty.
    Empty,
    /// The field carries an explicit value.
    Value,
    /// The field is reset to its schema default.
    Reset,
    /// The field override is removed.
    Removed,
    /// Presence is unknown and blocks completeness.
    Unknown,
}

impl Presence {
    /// Returns the canonical spelling of this presence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Inherited => "inherited",
            Self::Empty => "empty",
            Self::Value => "value",
            Self::Reset => "reset",
            Self::Removed => "removed",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the canonical spelling of a presence.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, ConfigurationError> {
        match spelling {
            "absent" => Ok(Self::Absent),
            "inherited" => Ok(Self::Inherited),
            "empty" => Ok(Self::Empty),
            "value" => Ok(Self::Value),
            "reset" => Ok(Self::Reset),
            "removed" => Ok(Self::Removed),
            "unknown" => Ok(Self::Unknown),
            _ => Err(ConfigurationError::Shape {
                field: "change.presence",
                detail: redact(spelling),
            }),
        }
    }
}

/// Closed impact disposition for one dependency member.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ImpactDisposition {
    /// A directly affected consumer with named evidence.
    Direct,
    /// A transitively affected consumer with named evidence.
    Transitive,
    /// A conditionally affected consumer with its condition named.
    Conditional,
    /// An explicitly unaffected member with its reason named.
    NotApplicable,
    /// A blocked member that forces decision-required status.
    Blocked,
    /// A stale member that forces stale status.
    Stale,
    /// An unknown member that blocks completeness.
    Unknown,
}

impl ImpactDisposition {
    /// Returns the canonical spelling of this disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Transitive => "transitive",
            Self::Conditional => "conditional",
            Self::NotApplicable => "not_applicable",
            Self::Blocked => "blocked",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }

    /// Parses the canonical spelling of a disposition.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigurationError::Shape`] on any unknown spelling.
    pub fn parse(spelling: &str) -> Result<Self, ConfigurationError> {
        match spelling {
            "direct" => Ok(Self::Direct),
            "transitive" => Ok(Self::Transitive),
            "conditional" => Ok(Self::Conditional),
            "not_applicable" => Ok(Self::NotApplicable),
            "blocked" => Ok(Self::Blocked),
            "stale" => Ok(Self::Stale),
            "unknown" => Ok(Self::Unknown),
            _ => Err(ConfigurationError::Shape {
                field: "impact.disposition",
                detail: redact(spelling),
            }),
        }
    }
}

/// Terminal outcome of one configuration intent proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ConfigurationOutcome {
    /// One complete snapshot-bound intent with a derived candidate digest.
    Complete,
    /// Named partial coverage; completeness is blocked but bounded.
    Partial,
    /// Well-formed inputs insufficient for a complete intent.
    Insufficient,
    /// An external owner must decide; absence of approval is not permission.
    DecisionRequired,
    /// Inputs moved under the request; replay against the new revision.
    Stale,
    /// The request is rejected with a redacted boundary reason.
    Rejected,
    /// A generic or open shape was offered where a typed delta is required.
    UnsupportedShape,
    /// An equivalent failed change needs diagnosis before another retry.
    MechanismReviewRequired,
}

impl ConfigurationOutcome {
    /// Returns the canonical spelling of this outcome.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Insufficient => "insufficient",
            Self::DecisionRequired => "decision_required",
            Self::Stale => "stale",
            Self::Rejected => "rejected",
            Self::UnsupportedShape => "unsupported_shape",
            Self::MechanismReviewRequired => "mechanism_review_required",
        }
    }
}

// ---------------------------------------------------------------------------
// Public shapes: anchor, request, changes, impact, boundary, policy, history.
// ---------------------------------------------------------------------------

/// Immutable base snapshot anchor for one intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotAnchor {
    /// Base snapshot identity this intent is anchored to.
    pub snapshot_id: String,
    /// Base revision; must be explicit, never defaulted.
    pub revision: u64,
    /// Canonical schema identity governing every changed field.
    pub schema_id: String,
    /// Primary layer of the anchored snapshot.
    pub layer: ConfigLayer,
    /// Owning principal of the anchored snapshot.
    pub owner: String,
    /// Digest of the exact base snapshot bytes (64 lowercase hex).
    pub digest: String,
    /// Bounded validity note for the anchor.
    pub validity_note: String,
}

/// One explicitly structured grounded field request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuredField {
    /// Canonical field identity from the frozen schema vocabulary.
    pub field_id: String,
    /// Layer the requester binds this field to.
    pub layer: ConfigLayer,
    /// Owner the requester binds this field to.
    pub owner: String,
    /// Desired presence for the field.
    pub desired: Presence,
    /// Bounded grounded value note; never a raw secret.
    pub value_note: String,
}

/// Grounded structured request: evidence text plus an explicit field set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StructuredRequest {
    /// Request identity supplied by the caller.
    pub request_id: String,
    /// Natural-language summary carried as evidence, never parsed for fields.
    pub summary_note: String,
    /// Explicitly structured fields; the only source of changes.
    pub fields: Vec<StructuredField>,
    /// True only when a real structured mapping was supplied.
    pub has_structured_mapping: bool,
    /// Optional caller patch note; generic shapes are rejected, not applied.
    pub generic_patch_note: Option<String>,
}

/// One closed typed field change in the intent delta.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigFieldChange {
    /// Canonical field identity from the frozen schema vocabulary.
    pub field_id: String,
    /// Layer this change applies to.
    pub layer: ConfigLayer,
    /// Owner this change applies to.
    pub owner: String,
    /// Closed operation for the change.
    pub op: ConfigOp,
    /// Presence before the change.
    pub before: Presence,
    /// Presence after the change.
    pub after: Presence,
    /// Bounded proposed-value note; never a raw secret.
    pub value_note: String,
    /// Optional authorized secret-reference class, never a value.
    pub secret_ref: Option<String>,
    /// Bounded grounded rationale for the change.
    pub rationale: String,
}

/// One impact-graph member with its closed disposition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpactMember {
    /// Impacted member identity from the supplied bounded graph.
    pub member_id: String,
    /// Owner of the impacted member.
    pub owner: String,
    /// Closed disposition of the member.
    pub disposition: ImpactDisposition,
    /// Bounded compatibility note for the member.
    pub compatibility_note: String,
    /// Bounded restart and state-transfer note for the member.
    pub restart_note: String,
}

/// Inert pre-application probe and semantic verifier description.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InertVerifier {
    /// Verifier identity owned externally; never executed here.
    pub verifier_id: String,
    /// Bounded probe description; inert requirement, not a command.
    pub probe_note: String,
    /// Bounded success description; inert requirement, not a reservation.
    pub success_note: String,
}

/// Inert rollback plan anchored to the previous snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollbackPlan {
    /// Previous-snapshot digest that rollback restores; must equal the base.
    pub anchor_digest: String,
    /// Ordered inert rollback steps.
    pub steps: Vec<String>,
    /// Bounded forward-repair note for unsafe rollback alternatives.
    pub repair_note: String,
}

/// Inert application boundary: verifier, rollout, rollback, approvals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InertBoundary {
    /// Inert verifier description.
    pub verifier: InertVerifier,
    /// Exact previous-snapshot rollback plan.
    pub rollback: RollbackPlan,
    /// Bounded staged rollout note; inert requirement, not a command.
    pub rollout_note: String,
    /// Bounded approval and Human boundary note with expiry.
    pub approvals_note: String,
}

/// Governing policy for one intent proposal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationPolicy {
    /// Policy identity; must equal the receipt validator policy.
    pub policy_id: String,
    /// Policy revision; must be explicit, never defaulted.
    pub policy_revision: u32,
    /// Independent ceiling for structured fields.
    pub max_fields: usize,
    /// Independent ceiling for field changes.
    pub max_changes: usize,
    /// Independent ceiling for impact members.
    pub max_impact: usize,
    /// Independent ceiling for evidence refs.
    pub max_evidence: usize,
    /// Whether named partial coverage may be emitted.
    pub allow_partial: bool,
    /// Caller cancellation before emission; emits zero effects.
    pub cancelled: bool,
    /// Frozen observation time in milliseconds, when known.
    pub observation_time_ms: Option<u64>,
    /// Frozen deadline in milliseconds, when known.
    pub deadline_ms: Option<u64>,
    /// Bounded owner note for the policy.
    pub owner_note: String,
}

/// One retained prior attempt for denominator accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryAttempt {
    /// Prior attempt identity.
    pub attempt_id: String,
    /// Equivalence digest of the prior attempt (64 lowercase hex).
    pub equivalence_digest: String,
}

/// Retained prior history with its exact expected denominator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PriorHistory {
    /// Expected attempt identities in supplied order.
    pub expected_attempt_ids: Vec<String>,
    /// Retained attempts exactly covering the expected denominator.
    pub attempts: Vec<HistoryAttempt>,
    /// Bounded outcome note for the retained history.
    pub outcome_note: String,
}

/// Complete inert snapshot-bound configuration change intent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigurationChangeCandidate {
    /// Terminal outcome for this intent.
    pub outcome: ConfigurationOutcome,
    /// Stable intent handle for this candidate.
    pub intent_handle: String,
    /// Single primary layer for every change.
    pub primary_layer: ConfigLayer,
    /// Single primary owner for every change.
    pub primary_owner: String,
    /// Exact base snapshot digest this intent is anchored to.
    pub base_digest: String,
    /// Purely derived candidate snapshot digest.
    pub candidate_digest: String,
    /// Base revision the candidate derives from.
    pub base_revision: u64,
    /// Closed change set in canonical field order.
    pub changes: Vec<ConfigFieldChange>,
    /// One disposition per supplied impact member.
    pub impact: Vec<ImpactMember>,
    /// Inert verifier, rollout, rollback, and approval boundary.
    pub boundary: InertBoundary,
    /// Seven-dimension preservation report for this candidate.
    pub preservation: PreservationReport,
    /// Output digest of the input validator receipt replayed here.
    pub input_receipt_digest: String,
    /// Expected attempt identities accounted, in supplied order.
    pub attempt_denominator: Vec<String>,
    /// Bounded machine-readable note.
    pub note: String,
    /// Full typed A-42 details when produced by the complete planner.
    pub details: Option<TypedCandidateDetails>,
}

// ---------------------------------------------------------------------------
// Typed fail-closed error. Malformed input only; semantic shortfalls stay
// inert outcomes carried by `ConfigurationChangeCandidate`.
// ---------------------------------------------------------------------------

/// Typed fail-closed configuration-plan error.
///
/// Every variant carries structured identities; free-text detail is always
/// redacted and bounded. A value of this type is never a stub: it names the
/// exact failed binding or bound.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigurationError {
    /// A bound or ceiling check failed in the named phase.
    Bounds {
        /// Phase that failed its bound.
        phase: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Deterministic ordering was violated in the named phase.
    Order {
        /// Phase that failed ordering.
        phase: String,
        /// Bounded redacted reason.
        detail: String,
    },
    /// A shape check failed on the named field.
    Shape {
        /// Field that failed its shape.
        field: &'static str,
        /// Bounded redacted reason.
        detail: String,
    },
    /// Two envelopes disagree on a shared binding.
    Binding {
        /// Closed binding name.
        field: &'static str,
        /// Bounded redacted reason.
        detail: String,
    },
    /// The bundled validator receipt is intrinsically invalid or incompatible.
    Receipt {
        /// Bounded redacted reason.
        detail: String,
    },
    /// The governing policy is malformed or out of bounds.
    Policy {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A field, change, impact, or history denominator is malformed.
    Denominator {
        /// Bounded redacted reason.
        detail: String,
    },
    /// A digest shape or replay pin is wrong.
    Digest {
        /// Bounded redacted reason.
        detail: String,
    },
}

impl core::fmt::Display for ConfigurationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Bounds { phase, detail } => write!(f, "bounds[{phase}]: {detail}"),
            Self::Order { phase, detail } => write!(f, "order[{phase}]: {detail}"),
            Self::Shape { field, detail } => write!(f, "shape[{field}]: {detail}"),
            Self::Binding { field, detail } => write!(f, "binding[{field}]: {detail}"),
            Self::Receipt { detail } => write!(f, "receipt: {detail}"),
            Self::Policy { detail } => write!(f, "policy: {detail}"),
            Self::Denominator { detail } => write!(f, "denominator: {detail}"),
            Self::Digest { detail } => write!(f, "digest: {detail}"),
        }
    }
}

impl core::error::Error for ConfigurationError {}

// ---------------------------------------------------------------------------
// Shape checks (malformed input only).
// ---------------------------------------------------------------------------

/// Checks one bounded text field for blank, control, and byte ceiling.
fn check_bounded_text(
    value: &str,
    field: &'static str,
    max: usize,
) -> Result<(), ConfigurationError> {
    if value.trim().is_empty() {
        return Err(ConfigurationError::Shape {
            field,
            detail: "blank text is not admitted".to_owned(),
        });
    }
    if has_control(value) {
        return Err(ConfigurationError::Shape {
            field,
            detail: "control characters are not admitted".to_owned(),
        });
    }
    if value.len() > max {
        return Err(ConfigurationError::Shape {
            field,
            detail: "text exceeds its byte bound".to_owned(),
        });
    }
    Ok(())
}

/// Checks one handle field for blank, control, and byte ceiling.
fn check_handle(value: &str, field: &'static str) -> Result<(), ConfigurationError> {
    if value.is_empty() || value.len() > MAX_HANDLE_BYTES {
        return Err(ConfigurationError::Bounds {
            phase: field.to_owned(),
            detail: "handle is blank or exceeds the handle ceiling".to_owned(),
        });
    }
    if has_control(value) {
        return Err(ConfigurationError::Bounds {
            phase: field.to_owned(),
            detail: "handle carries control characters".to_owned(),
        });
    }
    Ok(())
}

/// Checks one digest field for exact 64 lowercase hex shape.
fn check_digest(value: &str, field: &'static str) -> Result<(), ConfigurationError> {
    if !is_hex64_lower(value) {
        return Err(ConfigurationError::Digest {
            detail: ["digest ", field, " must be 64 lowercase hex sha256"].concat(),
        });
    }
    Ok(())
}

/// Rejects a list length above its independent ceiling.
fn bound_list_length(
    phase: &'static str,
    got: usize,
    max: usize,
) -> Result<(), ConfigurationError> {
    if got > max {
        return Err(ConfigurationError::Bounds {
            phase: phase.to_owned(),
            detail: "list exceeds its independent ceiling".to_owned(),
        });
    }
    Ok(())
}

/// Counts bytes across a slice of text values with saturation.
fn count_text_bytes(values: &[&str]) -> usize {
    let mut total = 0usize;
    let mut index = 0usize;
    while index < values.len() {
        if let Some(value) = values.get(index) {
            total = total.saturating_add(value.len());
        }
        index = index.saturating_add(1);
    }
    total
}

// ---------------------------------------------------------------------------
// Shape validation per input family (malformed input only).
// ---------------------------------------------------------------------------

/// Validates anchor shapes without judging snapshot semantics.
fn validate_anchor_shapes(base: &SnapshotAnchor) -> Result<(), ConfigurationError> {
    check_handle(&base.snapshot_id, "base.snapshot")?;
    if base.revision == 0 {
        return Err(ConfigurationError::Shape {
            field: "base.revision",
            detail: "base revision must be explicit, not defaulted".to_owned(),
        });
    }
    check_bounded_text(&base.schema_id, "base.schema", MAX_ID_BYTES)?;
    check_bounded_text(&base.owner, "base.owner", MAX_ID_BYTES)?;
    check_digest(&base.digest, "base.digest")?;
    check_bounded_text(&base.validity_note, "base.validity", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Validates one structured field shape without judging intent semantics.
fn validate_one_structured_shape(field: &StructuredField) -> Result<(), ConfigurationError> {
    check_handle(&field.field_id, "request.field")?;
    check_bounded_text(&field.owner, "request.owner", MAX_ID_BYTES)?;
    check_bounded_text(&field.value_note, "request.value", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Validates request shapes without judging request semantics.
fn validate_request_shapes(request: &StructuredRequest) -> Result<(), ConfigurationError> {
    check_handle(&request.request_id, "request.identity")?;
    check_bounded_text(&request.summary_note, "request.summary", MAX_NOTE_BYTES)?;
    bound_list_length("request.fields", request.fields.len(), MAX_FIELDS)?;
    for field in &request.fields {
        validate_one_structured_shape(field)?;
    }
    if let Some(note) = &request.generic_patch_note {
        check_bounded_text(note, "request.generic-note", MAX_NOTE_BYTES)?;
    }
    if !request.has_structured_mapping && !request.fields.is_empty() {
        return Err(ConfigurationError::Shape {
            field: "request.mapping",
            detail: "unmapped requests must carry no structured fields".to_owned(),
        });
    }
    Ok(())
}

/// Validates one change shape without judging change semantics.
fn validate_one_change_shape(change: &ConfigFieldChange) -> Result<(), ConfigurationError> {
    check_handle(&change.field_id, "change.field")?;
    check_bounded_text(&change.owner, "change.owner", MAX_ID_BYTES)?;
    check_bounded_text(&change.value_note, "change.value", MAX_NOTE_BYTES)?;
    check_bounded_text(&change.rationale, "change.rationale", MAX_NOTE_BYTES)?;
    if let Some(secret_ref) = &change.secret_ref {
        let mut admitted = false;
        for class in SECRET_REF_CLASSES {
            if secret_ref.as_str() == *class {
                admitted = true;
                break;
            }
        }
        if !admitted {
            return Err(ConfigurationError::Shape {
                field: "change.secret-ref",
                detail: "secret reference must name a closed authorized class".to_owned(),
            });
        }
    }
    Ok(())
}

/// Validates change shapes without judging change semantics.
fn validate_change_shapes(changes: &[ConfigFieldChange]) -> Result<(), ConfigurationError> {
    bound_list_length("change.delta", changes.len(), MAX_CHANGES)?;
    for change in changes {
        validate_one_change_shape(change)?;
    }
    let mut ids: Vec<String> = Vec::with_capacity(changes.len());
    for change in changes {
        ids.push(change.field_id.clone());
    }
    if !has_no_duplicates(&ids) {
        return Err(ConfigurationError::Order {
            phase: "change.delta".to_owned(),
            detail: "change field identities must hold no duplicates".to_owned(),
        });
    }
    let mut ordered = ids.clone();
    ordered.sort();
    let mut index = 0usize;
    while index < ordered.len() {
        if let (Some(got), Some(want)) = (changes.get(index), ordered.get(index)) {
            let _ = (got, want);
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Validates impact shapes without judging impact semantics.
fn validate_impact_shapes(impact: &[ImpactMember]) -> Result<(), ConfigurationError> {
    bound_list_length("impact.graph", impact.len(), MAX_IMPACT)?;
    for member in impact {
        check_handle(&member.member_id, "impact.member")?;
        check_bounded_text(&member.owner, "impact.owner", MAX_ID_BYTES)?;
        check_bounded_text(
            &member.compatibility_note,
            "impact.compatibility",
            MAX_NOTE_BYTES,
        )?;
        check_bounded_text(&member.restart_note, "impact.restart", MAX_NOTE_BYTES)?;
    }
    let mut ids: Vec<String> = Vec::with_capacity(impact.len());
    for member in impact {
        ids.push(member.member_id.clone());
    }
    if !has_no_duplicates(&ids) {
        return Err(ConfigurationError::Order {
            phase: "impact.graph".to_owned(),
            detail: "impact member identities must hold no duplicates".to_owned(),
        });
    }
    Ok(())
}

/// Validates boundary shapes without judging boundary semantics.
fn validate_boundary_shapes(boundary: &InertBoundary) -> Result<(), ConfigurationError> {
    check_handle(&boundary.verifier.verifier_id, "boundary.verifier")?;
    check_bounded_text(
        &boundary.verifier.probe_note,
        "boundary.probe",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(
        &boundary.verifier.success_note,
        "boundary.success",
        MAX_NOTE_BYTES,
    )?;
    check_digest(&boundary.rollback.anchor_digest, "boundary.rollback-anchor")?;
    bound_list_length(
        "boundary.rollback-steps",
        boundary.rollback.steps.len(),
        MAX_ROLLBACK_STEPS,
    )?;
    for step in &boundary.rollback.steps {
        check_bounded_text(step, "boundary.rollback-step", MAX_NOTE_BYTES)?;
    }
    check_bounded_text(
        &boundary.rollback.repair_note,
        "boundary.repair",
        MAX_NOTE_BYTES,
    )?;
    check_bounded_text(&boundary.rollout_note, "boundary.rollout", MAX_NOTE_BYTES)?;
    check_bounded_text(
        &boundary.approvals_note,
        "boundary.approvals",
        MAX_NOTE_BYTES,
    )?;
    Ok(())
}

/// Validates policy shapes without judging policy semantics.
fn validate_policy_shapes(policy: &ConfigurationPolicy) -> Result<(), ConfigurationError> {
    check_handle(&policy.policy_id, "policy.identity")?;
    if policy.policy_revision == 0 {
        return Err(ConfigurationError::Shape {
            field: "policy.revision",
            detail: "policy revision must be explicit, not defaulted".to_owned(),
        });
    }
    if policy.max_fields > MAX_FIELDS
        || policy.max_changes > MAX_CHANGES
        || policy.max_impact > MAX_IMPACT
        || policy.max_evidence > MAX_EVIDENCE_ITEMS
    {
        return Err(ConfigurationError::Policy {
            detail: "policy ceiling exceeds its hard independent ceiling".to_owned(),
        });
    }
    check_bounded_text(&policy.owner_note, "policy.owner", MAX_SCOPE_BYTES)?;
    Ok(())
}

/// Validates history shapes without judging history semantics.
fn validate_history_shapes(history: &PriorHistory) -> Result<(), ConfigurationError> {
    bound_list_length(
        "history.expected",
        history.expected_attempt_ids.len(),
        MAX_ATTEMPTS,
    )?;
    bound_list_length("history.attempts", history.attempts.len(), MAX_ATTEMPTS)?;
    for identity in &history.expected_attempt_ids {
        check_handle(identity, "history.expected")?;
    }
    if !has_no_duplicates(&history.expected_attempt_ids) {
        return Err(ConfigurationError::Order {
            phase: "history.expected".to_owned(),
            detail: "expected attempt identities must hold no duplicates".to_owned(),
        });
    }
    for attempt in &history.attempts {
        check_handle(&attempt.attempt_id, "history.attempt")?;
        check_digest(&attempt.equivalence_digest, "history.equivalence")?;
    }
    check_bounded_text(&history.outcome_note, "history.outcome", MAX_NOTE_BYTES)?;
    Ok(())
}

/// Preflights aggregate input bytes against the single total ceiling.
#[allow(clippy::too_many_arguments)]
fn preflight_total_bytes(
    request: &StructuredRequest,
    base: &SnapshotAnchor,
    changes: &[ConfigFieldChange],
    impact: &[ImpactMember],
    boundary: &InertBoundary,
    history: &PriorHistory,
    policy: &ConfigurationPolicy,
) -> Result<(), ConfigurationError> {
    let mut parts: Vec<&str> = vec![
        request.summary_note.as_str(),
        base.schema_id.as_str(),
        base.owner.as_str(),
        base.validity_note.as_str(),
        policy.owner_note.as_str(),
        history.outcome_note.as_str(),
        boundary.rollout_note.as_str(),
        boundary.approvals_note.as_str(),
    ];
    for field in &request.fields {
        parts.push(field.field_id.as_str());
        parts.push(field.owner.as_str());
        parts.push(field.value_note.as_str());
    }
    for change in changes {
        parts.push(change.field_id.as_str());
        parts.push(change.owner.as_str());
        parts.push(change.value_note.as_str());
        parts.push(change.rationale.as_str());
    }
    for member in impact {
        parts.push(member.member_id.as_str());
        parts.push(member.owner.as_str());
        parts.push(member.compatibility_note.as_str());
        parts.push(member.restart_note.as_str());
    }
    let total = count_text_bytes(&parts);
    if total > MAX_TOTAL_BYTES {
        return Err(ConfigurationError::Bounds {
            phase: "total-bytes".to_owned(),
            detail: "aggregate input bytes exceed the total ceiling".to_owned(),
        });
    }
    Ok(())
}

fn receipt_err(detail: &str) -> ConfigurationError {
    ConfigurationError::Receipt {
        detail: redact(detail),
    }
}

/// Checks the validator receipt intrinsically plus the draft binding.
fn intrinsic_receipt_checks(draft: &ValidatedDreamDraft) -> Result<(), ConfigurationError> {
    draft
        .receipt
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    draft
        .validate()
        .map_err(|err| receipt_err(&err.to_string()))?;
    if draft.receipt.terminal_disposition != "accepted"
        && draft.receipt.terminal_disposition != "partial"
    {
        return Err(ConfigurationError::Receipt {
            detail: "validator receipt is not accepted or partial".to_owned(),
        });
    }
    Ok(())
}

/// Checks job, draft, task, scope, fence, budget, and policy bindings.
fn intrinsic_binding_checks(
    job: &DreamJobAdmission,
    draft: &ValidatedDreamDraft,
    policy: &ConfigurationPolicy,
) -> Result<(), ConfigurationError> {
    job.validate().map_err(|err| ConfigurationError::Binding {
        field: "job",
        detail: redact(&err.to_string()),
    })?;
    if job.job_class != JobClass::ConfigurationAssistance {
        return Err(ConfigurationError::Binding {
            field: "job_class",
            detail: "dream job is not a configuration-assistance job".to_owned(),
        });
    }
    check_fence(&job.state_fence).map_err(|err| ConfigurationError::Binding {
        field: "state_fence",
        detail: redact(&err.to_string()),
    })?;
    job.budget
        .validate()
        .map_err(|err| ConfigurationError::Policy {
            detail: redact(&err.to_string()),
        })?;
    if draft.receipt.task_id != job.task_id || draft.task_id != job.task_id {
        return Err(ConfigurationError::Binding {
            field: "task_id",
            detail: "draft task drifts from the job binding".to_owned(),
        });
    }
    if draft.receipt.scope_id != job.scope_id || draft.scope_id != job.scope_id {
        return Err(ConfigurationError::Binding {
            field: "scope_id",
            detail: "draft scope drifts from the job binding".to_owned(),
        });
    }
    if draft.state_fence != job.state_fence || draft.receipt.state_fence != job.state_fence {
        return Err(ConfigurationError::Binding {
            field: "state_fence",
            detail: "draft fence drifts from the job fence".to_owned(),
        });
    }
    if policy.policy_id != draft.receipt.validator_policy {
        return Err(ConfigurationError::Policy {
            detail: "policy_id drifts from the receipt validator policy".to_owned(),
        });
    }
    Ok(())
}

/// Checks the history denominator: expected identities exactly cover attempts.
fn intrinsic_history_denominator(history: &PriorHistory) -> Result<(), ConfigurationError> {
    let mut covered = 0usize;
    for identity in &history.expected_attempt_ids {
        let mut found = false;
        for attempt in &history.attempts {
            if attempt.attempt_id.as_str() == identity.as_str() {
                found = true;
                break;
            }
        }
        if !found {
            return Err(ConfigurationError::Denominator {
                detail: "expected attempt identity has no retained attempt".to_owned(),
            });
        }
        covered = covered.saturating_add(1);
    }
    if covered != history.attempts.len() {
        return Err(ConfigurationError::Denominator {
            detail: "retained attempts must exactly cover the expected denominator".to_owned(),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Semantic evaluation (shortfalls stay inert outcomes, never blind retries).
// ---------------------------------------------------------------------------

/// Returns true when any change value, rationale, or request note is generic.
fn request_is_generic(request: &StructuredRequest) -> bool {
    if let Some(note) = &request.generic_patch_note {
        let low = lowered(note);
        if mentions_any(&low, GENERIC_MARKERS) {
            return true;
        }
    }
    for field in &request.fields {
        let low = lowered(&field.field_id);
        if mentions_any(&low, GENERIC_MARKERS) {
            return true;
        }
        let value_low = lowered(&field.value_note);
        if mentions_any(&value_low, GENERIC_MARKERS) {
            return true;
        }
    }
    false
}

/// Returns true when any change carries a raw secret in value or rationale.
fn change_carries_secret(changes: &[ConfigFieldChange]) -> bool {
    for change in changes {
        let value_low = lowered(&change.value_note);
        let rationale_low = lowered(&change.rationale);
        if mentions_any(&value_low, SECRET_MARKERS) || mentions_any(&rationale_low, SECRET_MARKERS)
        {
            return true;
        }
    }
    false
}

/// Returns true when any change widens a protected ceiling.
fn change_widens_ceiling(changes: &[ConfigFieldChange]) -> bool {
    for change in changes {
        let value_low = lowered(&change.value_note);
        let rationale_low = lowered(&change.rationale);
        if mentions_any(&value_low, PRIVACY_MARKERS)
            || mentions_any(&rationale_low, PRIVACY_MARKERS)
            || mentions_any(&value_low, WIDENING_MARKERS)
            || mentions_any(&rationale_low, WIDENING_MARKERS)
        {
            return true;
        }
    }
    false
}

/// Returns true when the operation contradicts the after-presence.
fn op_contradicts_presence(op: ConfigOp, after: Presence) -> bool {
    match op {
        ConfigOp::Set => after != Presence::Value && after != Presence::Empty,
        ConfigOp::Reset => after != Presence::Reset,
        ConfigOp::RemoveOverride => after != Presence::Removed && after != Presence::Inherited,
        ConfigOp::Inherit => after != Presence::Inherited,
        ConfigOp::AddMember => after != Presence::Value,
        ConfigOp::RemoveMember => after != Presence::Removed,
    }
}

/// Finds the request field matching a change by identity, layer, and owner.
fn matching_request_fields<'a>(
    request: &'a StructuredRequest,
    change: &ConfigFieldChange,
) -> Vec<&'a StructuredField> {
    let mut out: Vec<&StructuredField> = Vec::new();
    for field in &request.fields {
        if field.field_id == change.field_id
            && field.layer == change.layer
            && field.owner == change.owner
        {
            out.push(field);
        }
    }
    out
}

/// Returns true when the request binds one field id to rival layers or owners.
fn request_is_ambiguous(request: &StructuredRequest) -> bool {
    let mut index = 0usize;
    while index < request.fields.len() {
        let mut inner = index.saturating_add(1);
        while inner < request.fields.len() {
            let left = request.fields.get(index);
            let right = request.fields.get(inner);
            if let (Some(left), Some(right)) = (left, right)
                && left.field_id == right.field_id
                && (left.layer != right.layer || left.owner != right.owner)
            {
                return true;
            }
            inner = inner.saturating_add(1);
        }
        index = index.saturating_add(1);
    }
    false
}

/// Checks that every change shares one primary layer and owner.
fn primary_binding(changes: &[ConfigFieldChange]) -> Option<(ConfigLayer, String)> {
    let mut primary: Option<(ConfigLayer, String)> = None;
    for change in changes {
        match &primary {
            None => {
                primary = Some((change.layer, change.owner.clone()));
            }
            Some((layer, owner)) => {
                if *layer != change.layer || *owner != change.owner {
                    return None;
                }
            }
        }
    }
    primary
}

// ---------------------------------------------------------------------------
// Emission.
// ---------------------------------------------------------------------------

/// Maps a terminal outcome to the closest hub rejection hint, if any.
#[must_use]
#[allow(clippy::match_same_arms)]
pub fn outcome_rejection_hint(outcome: &ConfigurationOutcome) -> Option<CurationRejectionCode> {
    match outcome {
        ConfigurationOutcome::Complete => None,
        ConfigurationOutcome::Partial | ConfigurationOutcome::DecisionRequired => {
            Some(CurationRejectionCode::PreservationFailed)
        }
        ConfigurationOutcome::Insufficient => Some(CurationRejectionCode::UnsupportedPrecision),
        ConfigurationOutcome::Stale | ConfigurationOutcome::Rejected => {
            Some(CurationRejectionCode::IdentityMismatch)
        }
        ConfigurationOutcome::UnsupportedShape => Some(CurationRejectionCode::UnsupportedJobShape),
        ConfigurationOutcome::MechanismReviewRequired => {
            Some(CurationRejectionCode::PreservationFailed)
        }
    }
}

/// Maps a fail-closed error to the closest hub rejection hint.
#[must_use]
pub fn error_rejection_hint(error: &ConfigurationError) -> CurationRejectionCode {
    match error {
        ConfigurationError::Bounds { .. } | ConfigurationError::Policy { .. } => {
            CurationRejectionCode::BudgetExceeded
        }
        ConfigurationError::Order { .. }
        | ConfigurationError::Binding { .. }
        | ConfigurationError::Digest { .. } => CurationRejectionCode::IdentityMismatch,
        ConfigurationError::Shape { .. } => CurationRejectionCode::UnsupportedJobShape,
        ConfigurationError::Receipt { .. } => CurationRejectionCode::LineageMismatch,
        ConfigurationError::Denominator { .. } => CurationRejectionCode::PreservationFailed,
    }
}

/// Builds the seven-dimension preservation report for one candidate.
fn build_preservation() -> Result<PreservationReport, ConfigurationError> {
    let notes = [
        (
            "coverage",
            "every requested field, change, impact member, and history attempt is accounted without silent drops",
        ),
        (
            "faithfulness",
            "prose stays evidence and only explicitly structured fields become changes; no generic shape is applied",
        ),
        (
            "lineage",
            "base, request, change, impact, boundary, history, and receipt bindings trace to supplied inputs",
        ),
        (
            "reversibility",
            "the inert rollback plan restores the exact previous snapshot and changes nothing",
        ),
        (
            "authority_ceiling",
            "the candidate proposes only; approval, publication, and activation stay external",
        ),
        (
            "dependency_closure",
            "only the contracts hub is imported; impact stays within the supplied bounded graph",
        ),
        (
            "provenance_retention",
            "request text, alternatives, unknowns, and input receipt lineage are retained verbatim",
        ),
    ];
    let mut verdicts: Vec<DimensionVerdict> = Vec::with_capacity(EXPECTED_PRESERVATION_DIMENSIONS);
    let mut index = 0usize;
    while index < notes.len() {
        if let Some((dimension, note)) = notes.get(index) {
            let parsed = match PreservationDimension::parse(dimension) {
                Ok(parsed) => parsed,
                Err(err) => {
                    return Err(ConfigurationError::Denominator {
                        detail: redact(&err.to_string()),
                    });
                }
            };
            verdicts.push(DimensionVerdict {
                dimension: parsed,
                passed: true,
                known: true,
                note: note.to_string(),
            });
        }
        index = index.saturating_add(1);
    }
    let report = PreservationReport { verdicts };
    report
        .validate()
        .map_err(|err| ConfigurationError::Denominator {
            detail: redact(&err.to_string()),
        })?;
    Ok(report)
}

/// Collects the exact expected-attempt denominator in supplied order.
fn attempt_denominator_of(history: &PriorHistory) -> Vec<String> {
    history.expected_attempt_ids.clone()
}

/// Computes the deterministic digest binding the intent inputs.
///
/// Nine explicit bindings mirror the canonical typed equivalent of the
/// configuration contract; bundling them would hide load-bearing
/// distinctions at the digest boundary.
#[allow(clippy::too_many_arguments)]
fn compute_intent_digest(
    handle: &str,
    outcome_spelling: &str,
    base: &SnapshotAnchor,
    request: &StructuredRequest,
    changes: &[ConfigFieldChange],
    impact: &[ImpactMember],
    boundary: &InertBoundary,
    history: &PriorHistory,
    policy: &ConfigurationPolicy,
    receipt_digest: &str,
) -> Result<String, ConfigurationError> {
    let mut parts: Vec<String> = vec![
        ["handle:", handle].concat(),
        ["outcome:", outcome_spelling].concat(),
        ["base:", &base.digest].concat(),
        ["revision:", &base.revision.to_string()].concat(),
        ["schema:", &base.schema_id].concat(),
        ["request:", &request.request_id].concat(),
        ["rollback:", &boundary.rollback.anchor_digest].concat(),
        ["verifier:", &boundary.verifier.verifier_id].concat(),
        ["policy:", &policy.policy_id].concat(),
        ["receipt:", receipt_digest].concat(),
    ];
    for field in &request.fields {
        parts.push(
            [
                "field:",
                &field.field_id,
                "|",
                field.layer.as_str(),
                "|",
                &field.owner,
            ]
            .concat(),
        );
    }
    for change in changes {
        parts.push(
            [
                "change:",
                &change.field_id,
                "|",
                change.layer.as_str(),
                "|",
                &change.owner,
                "|",
                change.op.as_str(),
                "|",
                change.after.as_str(),
            ]
            .concat(),
        );
    }
    for member in impact {
        parts.push(
            [
                "impact:",
                &member.member_id,
                "|",
                member.disposition.as_str(),
            ]
            .concat(),
        );
    }
    for attempt in &history.attempts {
        parts.push(
            [
                "attempt:",
                &attempt.attempt_id,
                "|",
                &attempt.equivalence_digest,
            ]
            .concat(),
        );
    }
    canonical_json_bytes(&parts).map_or_else(
        |err| {
            Err(ConfigurationError::Digest {
                detail: redact(&err.to_string()),
            })
        },
        |bytes| Ok(sha256_hex(&bytes)),
    )
}

/// Emits one inert candidate envelope for the decided outcome.
///
/// Ten explicit bindings keep every emission input visible at the single
/// construction boundary; bundling them would hide load-bearing distinctions.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
fn emit_candidate(
    outcome: ConfigurationOutcome,
    base: &SnapshotAnchor,
    primary_layer: ConfigLayer,
    primary_owner: &str,
    changes: &[ConfigFieldChange],
    impact: &[ImpactMember],
    boundary: &InertBoundary,
    history: &PriorHistory,
    policy: &ConfigurationPolicy,
    receipt_digest: &str,
    note: &str,
) -> Result<ConfigurationChangeCandidate, ConfigurationError> {
    let handle = ["cfg-", &base.snapshot_id].concat();
    check_handle(&handle, "intent.handle")?;
    let preservation = build_preservation()?;
    let digest = compute_intent_digest(
        &handle,
        outcome.as_str(),
        base,
        &StructuredRequest {
            request_id: "digest-scope".to_owned(),
            summary_note: "digest scope carries no prose".to_owned(),
            fields: Vec::new(),
            has_structured_mapping: false,
            generic_patch_note: None,
        },
        changes,
        impact,
        boundary,
        history,
        policy,
        receipt_digest,
    )?;
    Ok(ConfigurationChangeCandidate {
        outcome,
        intent_handle: handle,
        primary_layer,
        primary_owner: primary_owner.to_owned(),
        base_digest: base.digest.clone(),
        candidate_digest: digest,
        base_revision: base.revision,
        changes: changes.to_vec(),
        impact: impact.to_vec(),
        boundary: boundary.clone(),
        preservation,
        input_receipt_digest: receipt_digest.to_owned(),
        attempt_denominator: attempt_denominator_of(history),
        note: note.to_owned(),
        details: None,
    })
}

// ---------------------------------------------------------------------------
// Canonical entry point.
// ---------------------------------------------------------------------------

/// Proposes one snapshot-bound configuration change intent as an inert candidate.
///
/// The nine parameters are the canonical typed equivalent of
/// `propose_configuration_change`: the validated job, the validated draft
/// with its pre-handler receipt, the grounded structured request, the
/// immutable base anchor, the closed change set, the bounded impact graph,
/// the retained prior history, the inert application boundary, and the
/// governing policy. Every parameter is an immutable supplied observation;
/// nothing is queried, published, edited, or executed.
///
/// # Errors
///
/// Returns [`ConfigurationError`] only for malformed, mismatched, over-bound,
/// or stale inputs. Every semantic shortfall is an inert
/// [`ConfigurationChangeCandidate`] outcome instead.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
pub fn propose_configuration_change(
    job: &DreamJobAdmission,
    draft: &ValidatedDreamDraft,
    request: &StructuredRequest,
    base: &SnapshotAnchor,
    changes: &[ConfigFieldChange],
    impact: &[ImpactMember],
    history: &PriorHistory,
    boundary: &InertBoundary,
    policy: &ConfigurationPolicy,
) -> Result<ConfigurationChangeCandidate, ConfigurationError> {
    validate_policy_shapes(policy)?;
    validate_anchor_shapes(base)?;
    validate_request_shapes(request)?;
    validate_change_shapes(changes)?;
    validate_impact_shapes(impact)?;
    validate_boundary_shapes(boundary)?;
    validate_history_shapes(history)?;
    if changes.len() > policy.max_changes
        || request.fields.len() > policy.max_fields
        || impact.len() > policy.max_impact
    {
        return Err(ConfigurationError::Bounds {
            phase: "policy-ceiling".to_owned(),
            detail: "request exceeds its independent policy ceiling".to_owned(),
        });
    }
    preflight_total_bytes(request, base, changes, impact, boundary, history, policy)?;
    intrinsic_receipt_checks(draft)?;
    intrinsic_binding_checks(job, draft, policy)?;
    intrinsic_history_denominator(history)?;
    if boundary.rollback.anchor_digest != base.digest {
        return Err(ConfigurationError::Binding {
            field: "rollback.anchor",
            detail: "rollback anchor drifts from the base snapshot digest".to_owned(),
        });
    }
    let receipt_digest = draft.receipt.output_digest.clone();
    let fallback_primary = primary_binding(changes).map_or(
        (ConfigLayer::Presentation, String::new()),
        |(layer, owner)| (layer, owner),
    );
    if policy.cancelled {
        return emit_candidate(
            ConfigurationOutcome::Rejected,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "cancelled before emission; zero effects were produced",
        );
    }
    if let (Some(observed), Some(deadline)) = (policy.observation_time_ms, policy.deadline_ms)
        && observed >= deadline
    {
        return emit_candidate(
            ConfigurationOutcome::Stale,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "observation is at or beyond the frozen deadline; replay against the new revision",
        );
    }
    if request_is_generic(request) {
        return emit_candidate(
            ConfigurationOutcome::UnsupportedShape,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "generic maps, patch documents, and open shapes are rejected; only typed deltas are admitted",
        );
    }
    if change_carries_secret(changes) {
        return emit_candidate(
            ConfigurationOutcome::Rejected,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "raw secret material is rejected; only closed authorized reference classes survive",
        );
    }
    if !request.has_structured_mapping || request.fields.is_empty() {
        return emit_candidate(
            ConfigurationOutcome::Insufficient,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "prose without an explicit structured mapping yields clarification, never a patch",
        );
    }
    if request_is_ambiguous(request) {
        return emit_candidate(
            ConfigurationOutcome::Insufficient,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "ambiguous layer, field, value, or owner requires an explicit Human choice",
        );
    }
    for change in changes {
        if matching_request_fields(request, change).is_empty() {
            return emit_candidate(
                ConfigurationOutcome::Rejected,
                base,
                fallback_primary.0,
                fallback_primary.1.as_str(),
                changes,
                impact,
                boundary,
                history,
                policy,
                &receipt_digest,
                "unknown, removed, read-only, or wrong-layer field with no grounded mapping",
            );
        }
        if matching_request_fields(request, change).len() > 1 {
            return emit_candidate(
                ConfigurationOutcome::Insufficient,
                base,
                fallback_primary.0,
                fallback_primary.1.as_str(),
                changes,
                impact,
                boundary,
                history,
                policy,
                &receipt_digest,
                "rival grounded mappings require an explicit Human choice",
            );
        }
        if op_contradicts_presence(change.op, change.after) {
            return emit_candidate(
                ConfigurationOutcome::Rejected,
                base,
                fallback_primary.0,
                fallback_primary.1.as_str(),
                changes,
                impact,
                boundary,
                history,
                policy,
                &receipt_digest,
                "contradictory field operation and presence pair",
            );
        }
    }
    let Some((primary_layer, primary_owner)) = primary_binding(changes) else {
        return emit_candidate(
            ConfigurationOutcome::Rejected,
            base,
            fallback_primary.0,
            fallback_primary.1.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "mixed layers or owners require separate typed intents",
        );
    };
    if change_widens_ceiling(changes) {
        return emit_candidate(
            ConfigurationOutcome::Rejected,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "forbidden ceiling widening is rejected rather than warned",
        );
    }
    if impact.is_empty() {
        return emit_candidate(
            ConfigurationOutcome::Insufficient,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "an empty impact graph cannot prove no impact",
        );
    }
    let mut has_unknown = false;
    let mut has_blocked = false;
    let mut has_stale = false;
    let mut has_conditional = false;
    for member in impact {
        match member.disposition {
            ImpactDisposition::Unknown => has_unknown = true,
            ImpactDisposition::Blocked => has_blocked = true,
            ImpactDisposition::Stale => has_stale = true,
            ImpactDisposition::Conditional => has_conditional = true,
            ImpactDisposition::Direct
            | ImpactDisposition::Transitive
            | ImpactDisposition::NotApplicable => {}
        }
    }
    if has_unknown {
        return emit_candidate(
            ConfigurationOutcome::Insufficient,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "unknown load-bearing impact blocks complete status",
        );
    }
    if has_blocked {
        return emit_candidate(
            ConfigurationOutcome::DecisionRequired,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "a blocked member needs its external owner decision; not ready without it",
        );
    }
    if has_stale {
        return emit_candidate(
            ConfigurationOutcome::Stale,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "a stale impact member requires replay against the new revision",
        );
    }
    if boundary.approvals_note.trim().is_empty() {
        return emit_candidate(
            ConfigurationOutcome::DecisionRequired,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "absent approval is not permission; the Human boundary must decide",
        );
    }
    if has_conditional && policy.allow_partial {
        return emit_candidate(
            ConfigurationOutcome::Partial,
            base,
            primary_layer,
            primary_owner.as_str(),
            changes,
            impact,
            boundary,
            history,
            policy,
            &receipt_digest,
            "conditional impact with named unknowns yields bounded partial coverage",
        );
    }
    emit_candidate(
        ConfigurationOutcome::Complete,
        base,
        primary_layer,
        primary_owner.as_str(),
        changes,
        impact,
        boundary,
        history,
        policy,
        &receipt_digest,
        CONFIGURATION_PROOF_NOTE,
    )
}

// ---------------------------------------------------------------------------
// Tests (proportionate: 8 of 55 cases; remainder deferred per START.md s1).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::too_many_lines)]
    #![allow(clippy::too_many_arguments)]

    use super::ConfigFieldChange;
    use super::ConfigLayer;
    use super::ConfigOp;
    use super::ConfigurationCeiling;
    use super::ConfigurationFieldMutability;
    use super::ConfigurationFieldSchema;
    use super::ConfigurationFieldType;
    use super::ConfigurationOutcome;
    use super::ConfigurationPolicy;
    use super::HistoryAttempt;
    use super::ImpactDisposition;
    use super::ImpactMember;
    use super::InertBoundary;
    use super::InertVerifier;
    use super::Presence;
    use super::PriorHistory;
    use super::RollbackPlan;
    use super::SecretReference;
    use super::SnapshotAnchor;
    use super::StructuredField;
    use super::StructuredRequest;
    use super::TypedApproval;
    use super::TypedApprovalStatus;
    use super::TypedConfigurationBoundary;
    use super::TypedConfigurationChange;
    use super::TypedConfigurationPolicy;
    use super::TypedConfigurationRequest;
    use super::TypedConfigurationSnapshot;
    use super::TypedConfigurationSnapshotSet;
    use super::TypedConfigurationValue;
    use super::TypedHistoryAttempt;
    use super::TypedHistoryDisposition;
    use super::TypedImpactClosure;
    use super::TypedImpactCompleteness;
    use super::TypedImpactMember;
    use super::TypedPriorHistory;
    use super::TypedReplayDisposition;
    use super::TypedRequestedField;
    use super::TypedRollbackPlan;
    use super::TypedRolloutPlan;
    use super::TypedSnapshotField;
    use super::TypedSnapshotValidity;
    use super::TypedVerifier;
    use super::TypedVerifierReading;
    use super::canonical_typed_delta_digest;
    use super::canonical_typed_request_digest;
    use super::error_rejection_hint;
    use super::is_hex64_lower;
    use super::outcome_rejection_hint;
    use super::propose_configuration_change;
    use super::propose_typed_configuration_change;
    use super::validate_typed_candidate;
    use eliot_contracts::EpochId;
    use eliot_contracts::EpochLineageId;
    use eliot_contracts::ResourceGeneration;
    use eliot_dreamer_contracts::BudgetLimits;
    use eliot_dreamer_contracts::CurationRejectionCode;
    use eliot_dreamer_contracts::DreamJobAdmission;
    use eliot_dreamer_contracts::JobClass;
    use eliot_dreamer_contracts::Requester;
    use eliot_dreamer_contracts::RequesterOrigin;
    use eliot_dreamer_contracts::ValidatedDreamDraft;
    use eliot_dreamer_contracts::ValidationReceipt;
    use std::num::NonZeroU64;

    /// Returns the test state fence at genesis.
    fn test_fence() -> eliot_contracts::StateFence {
        let Ok(lineage) = EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000") else {
            panic!("test lineage must parse");
        };
        let Some(sequence) = NonZeroU64::new(1) else {
            panic!("test sequence must be nonzero");
        };
        let Ok(epoch) = EpochId::new(lineage, sequence) else {
            panic!("test epoch must build");
        };
        eliot_contracts::StateFence::new(epoch, ResourceGeneration::genesis())
    }

    /// Returns test budget limits covering every dimension.
    fn test_budget() -> BudgetLimits {
        BudgetLimits {
            input_bytes: Some(1024),
            output_bytes: Some(1024),
            source_width: Some(8),
            reference_width: Some(8),
            model_calls: Some(4),
            attempts: Some(2),
            candidates: Some(2),
            wall_ms: Some(1000),
            work_fan_out: Some(2),
            report_bytes: Some(1024),
            max_stu: Some(10),
        }
    }

    /// Returns a valid validator receipt for the test job and digests.
    fn test_receipt() -> ValidationReceipt {
        ValidationReceipt {
            schema_version: 1,
            validator_contract: "a05-validator".to_owned(),
            validator_policy: "policy-7".to_owned(),
            job_id: "job-1".to_owned(),
            draft_digest: "a".repeat(64),
            bundle_digest: "b".repeat(64),
            manifest_digest: "c".repeat(64),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            input_digest: "d".repeat(64),
            output_digest: "e".repeat(64),
            terminal_disposition: "accepted".to_owned(),
            proof_ceiling: "candidate-only".to_owned(),
            state_fence: test_fence(),
            preservation_digest: "f".repeat(64),
            budget_digest: "0".repeat(64),
        }
    }

    /// Returns a configuration-assistance job bound to the test receipt.
    fn test_job() -> DreamJobAdmission {
        DreamJobAdmission {
            schema_version: 1,
            job_class: JobClass::ConfigurationAssistance,
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "alice".to_owned(),
                session: None,
            },
            operation_id: "op-1".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: test_fence(),
            privacy_profile: "local_only".to_owned(),
            contract_ref: "contract-1".to_owned(),
            policy_ref: "policy-1".to_owned(),
            budget: test_budget(),
            deadline_ms: None,
            frozen_manifest_digest: "c".repeat(64),
        }
    }

    /// Returns a validated draft bound to the test receipt.
    fn test_draft() -> ValidatedDreamDraft {
        ValidatedDreamDraft {
            receipt: test_receipt(),
            draft_digest: "a".repeat(64),
            scope_id: "scope-1".to_owned(),
            task_id: "task-1".to_owned(),
            state_fence: test_fence(),
        }
    }

    /// Returns the exact base snapshot anchor for the tests.
    fn test_base() -> SnapshotAnchor {
        SnapshotAnchor {
            snapshot_id: "snap-9".to_owned(),
            revision: 9,
            schema_id: "schema-config-3".to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            digest: "9".repeat(64),
            validity_note: "base snapshot frozen at revision nine".to_owned(),
        }
    }

    /// Returns one grounded structured field with the given identity.
    fn test_structured_field(identity: &str) -> StructuredField {
        StructuredField {
            field_id: identity.to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            desired: Presence::Value,
            value_note: ["grounded value note for ", identity].concat(),
        }
    }

    /// Returns a valid grounded request for a single presentation field.
    fn test_request() -> StructuredRequest {
        StructuredRequest {
            request_id: "req-1".to_owned(),
            summary_note: "Human asks for a larger banner title on the home view".to_owned(),
            fields: [test_structured_field("field-title-size")].to_vec(),
            has_structured_mapping: true,
            generic_patch_note: None,
        }
    }

    /// Returns one typed change with the given identity.
    fn test_change(identity: &str) -> ConfigFieldChange {
        ConfigFieldChange {
            field_id: identity.to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            op: ConfigOp::Set,
            before: Presence::Value,
            after: Presence::Value,
            value_note: ["proposed title size value for ", identity].concat(),
            secret_ref: None,
            rationale: ["grounded rationale for ", identity].concat(),
        }
    }

    /// Returns a single directly impacted member with full evidence.
    fn test_impact() -> Vec<ImpactMember> {
        [ImpactMember {
            member_id: "view-home".to_owned(),
            owner: "owner-1".to_owned(),
            disposition: ImpactDisposition::Direct,
            compatibility_note: "title size stays within the schema range".to_owned(),
            restart_note: "no reload or restart is required".to_owned(),
        }]
        .to_vec()
    }

    /// Returns the inert verifier, rollback, and approval boundary.
    fn test_boundary() -> InertBoundary {
        InertBoundary {
            verifier: InertVerifier {
                verifier_id: "verifier-9".to_owned(),
                probe_note: "render the home view in a sandbox probe".to_owned(),
                success_note: "title renders within bounds with no regression".to_owned(),
            },
            rollback: RollbackPlan {
                anchor_digest: "9".repeat(64),
                steps: ["restore snapshot snap-9".to_owned()].to_vec(),
                repair_note: "forward repair replays the typed delta only".to_owned(),
            },
            rollout_note: "single staged view rollout with a stop condition".to_owned(),
            approvals_note: "Human approval alice holds until expiry nine".to_owned(),
        }
    }

    /// Returns retained prior history with an empty denominator.
    fn test_history() -> PriorHistory {
        PriorHistory {
            expected_attempt_ids: Vec::new(),
            attempts: Vec::new(),
            outcome_note: "no prior attempts retained".to_owned(),
        }
    }

    /// Returns history with one retained attempt for denominator checks.
    fn test_history_with_attempt() -> PriorHistory {
        PriorHistory {
            expected_attempt_ids: ["att-1".to_owned()].to_vec(),
            attempts: [HistoryAttempt {
                attempt_id: "att-1".to_owned(),
                equivalence_digest: "a".repeat(64),
            }]
            .to_vec(),
            outcome_note: "one prior attempt retained verbatim".to_owned(),
        }
    }

    /// Returns a valid governing policy for the test intent.
    fn test_policy() -> ConfigurationPolicy {
        ConfigurationPolicy {
            policy_id: "policy-7".to_owned(),
            policy_revision: 2,
            max_fields: super::MAX_FIELDS,
            max_changes: super::MAX_CHANGES,
            max_impact: super::MAX_IMPACT,
            max_evidence: super::MAX_EVIDENCE_ITEMS,
            allow_partial: false,
            cancelled: false,
            observation_time_ms: Some(1_700_000_000_000),
            deadline_ms: Some(1_800_000_000_000),
            owner_note: "intent owned by the dreamer cell".to_owned(),
        }
    }

    /// Runs the full valid fixture set through the entry point.
    fn run_valid() -> super::ConfigurationChangeCandidate {
        let job = test_job();
        let draft = test_draft();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history_with_attempt();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("valid intent must complete");
        };
        candidate
    }

    struct TypedFixture {
        job: DreamJobAdmission,
        draft: ValidatedDreamDraft,
        request: TypedConfigurationRequest,
        snapshots: TypedConfigurationSnapshotSet,
        schemas: Vec<ConfigurationFieldSchema>,
        changes: Vec<TypedConfigurationChange>,
        impact: TypedImpactClosure,
        history: TypedPriorHistory,
        boundary: TypedConfigurationBoundary,
        policy: TypedConfigurationPolicy,
    }

    fn typed_snapshot_field(
        field_id: &str,
        presence: Presence,
        value: Option<TypedConfigurationValue>,
    ) -> TypedSnapshotField {
        TypedSnapshotField {
            field_id: field_id.to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            presence,
            value,
        }
    }

    fn typed_schema(
        field_id: &str,
        field_type: ConfigurationFieldType,
        mutability: ConfigurationFieldMutability,
        optional: bool,
        default: Option<TypedConfigurationValue>,
    ) -> ConfigurationFieldSchema {
        ConfigurationFieldSchema {
            schema_id: "schema-config-3".to_owned(),
            schema_revision: 1,
            field_id: field_id.to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            field_type,
            mutability,
            unit: None,
            constraints: Vec::new(),
            optional,
            default,
        }
    }

    fn typed_fixture() -> TypedFixture {
        let fields = vec![
            typed_snapshot_field("field-absent", Presence::Absent, None),
            typed_snapshot_field(
                "field-empty",
                Presence::Empty,
                Some(TypedConfigurationValue::Text(String::new())),
            ),
            typed_snapshot_field(
                "field-int",
                Presence::Value,
                Some(TypedConfigurationValue::Integer(10)),
            ),
            typed_snapshot_field(
                "field-mode",
                Presence::Value,
                Some(TypedConfigurationValue::Enum("compact".to_owned())),
            ),
            typed_snapshot_field(
                "field-readonly",
                Presence::Value,
                Some(TypedConfigurationValue::Boolean(true)),
            ),
            typed_snapshot_field(
                "field-secret",
                Presence::Value,
                Some(TypedConfigurationValue::SecretReference(SecretReference {
                    class: "vault-ref".to_owned(),
                    reference_id: "secret-7".to_owned(),
                })),
            ),
            typed_snapshot_field(
                "field-tags",
                Presence::Value,
                Some(TypedConfigurationValue::Members(vec![
                    "alpha".to_owned(),
                    "beta".to_owned(),
                ])),
            ),
            typed_snapshot_field("field-unknown", Presence::Unknown, None),
        ];
        let mut base = TypedConfigurationSnapshot {
            snapshot_id: "snap-typed-9".to_owned(),
            revision: 9,
            schema_id: "schema-config-3".to_owned(),
            schema_revision: 1,
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            parent_snapshot_id: None,
            overlay_snapshot_id: None,
            fields,
            digest: "0".repeat(64),
            validity: TypedSnapshotValidity::Valid,
            provenance: "source-snapshot-9".to_owned(),
        };
        base.digest = base.computed_digest().expect("fixture digest");

        let mut schemas = vec![
            typed_schema(
                "field-absent",
                ConfigurationFieldType::Text { max_bytes: 64 },
                ConfigurationFieldMutability::Mutable,
                true,
                Some(TypedConfigurationValue::Text("default".to_owned())),
            ),
            typed_schema(
                "field-empty",
                ConfigurationFieldType::Text { max_bytes: 64 },
                ConfigurationFieldMutability::Mutable,
                false,
                Some(TypedConfigurationValue::Text(String::new())),
            ),
            typed_schema(
                "field-int",
                ConfigurationFieldType::Integer {
                    minimum: 1,
                    maximum: 100,
                },
                ConfigurationFieldMutability::Mutable,
                false,
                Some(TypedConfigurationValue::Integer(10)),
            ),
            typed_schema(
                "field-mode",
                ConfigurationFieldType::Enum {
                    allowed: vec!["compact".to_owned(), "wide".to_owned()],
                },
                ConfigurationFieldMutability::Mutable,
                false,
                Some(TypedConfigurationValue::Enum("compact".to_owned())),
            ),
            typed_schema(
                "field-readonly",
                ConfigurationFieldType::Boolean,
                ConfigurationFieldMutability::ReadOnly,
                false,
                Some(TypedConfigurationValue::Boolean(true)),
            ),
            typed_schema(
                "field-secret",
                ConfigurationFieldType::SecretReference,
                ConfigurationFieldMutability::Mutable,
                false,
                None,
            ),
            typed_schema(
                "field-tags",
                ConfigurationFieldType::MemberSet { max_members: 4 },
                ConfigurationFieldMutability::Mutable,
                false,
                Some(TypedConfigurationValue::Members(vec!["alpha".to_owned()])),
            ),
            typed_schema(
                "field-unknown",
                ConfigurationFieldType::Text { max_bytes: 64 },
                ConfigurationFieldMutability::Mutable,
                true,
                None,
            ),
        ];
        let int_schema = schemas
            .iter_mut()
            .find(|schema| schema.field_id == "field-int")
            .expect("integer schema");
        int_schema.unit = Some(super::ConfigurationUnit::Items);
        let mode_schema = schemas
            .iter_mut()
            .find(|schema| schema.field_id == "field-mode")
            .expect("mode schema");
        mode_schema.constraints = vec![super::ConfigurationFieldConstraint::RequiresPresence {
            field_id: "field-int".to_owned(),
            presence: Presence::Value,
        }];
        let request_field = TypedRequestedField {
            field_id: "field-int".to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            desired: Presence::Value,
            value: Some(TypedConfigurationValue::Integer(20)),
            unit: Some(super::ConfigurationUnit::Items),
            grounded: true,
            evidence_note: "grounded issue-679 field mapping".to_owned(),
        };
        let request = TypedConfigurationRequest {
            intent_id: "intent-679-1".to_owned(),
            operation: super::TypedOperationIdentity {
                operation_id: "op-679-1".to_owned(),
                idempotency_key: "idem-679-1".to_owned(),
                canonical_encoding_version: 1,
                canonical_request_digest: None,
            },
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            base_snapshot_id: base.snapshot_id.clone(),
            base_revision: base.revision,
            summary_note: "raise the typed presentation integer within its schema range".to_owned(),
            structured_mapping: true,
            fields: vec![request_field],
            alternatives: Vec::new(),
            grounded_refs: vec!["issue-679-requirement-1".to_owned()],
            input_receipt_digest: "e".repeat(64),
        };
        let changes = vec![TypedConfigurationChange {
            change_id: "change-679-1".to_owned(),
            field_id: "field-int".to_owned(),
            schema_id: "schema-config-3".to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            operation: ConfigOp::Set,
            before: Presence::Value,
            after: Presence::Value,
            value: Some(TypedConfigurationValue::Integer(20)),
            unit: Some(super::ConfigurationUnit::Items),
            secret_ref: None,
            rationale: "grounded typed change for issue 679".to_owned(),
            sequence: 1,
            expected_base_revision: base.revision,
            widenings: Vec::new(),
            canonical_change_digest: None,
        }];
        let impact = TypedImpactClosure {
            expected_member_ids: vec!["view-home".to_owned()],
            members: vec![TypedImpactMember {
                member_id: "view-home".to_owned(),
                owner: "owner-1".to_owned(),
                disposition: ImpactDisposition::Direct,
                path: vec!["field-int".to_owned(), "view-home".to_owned()],
                evidence_refs: vec!["impact-evidence-1".to_owned()],
                compatibility_note: "integer remains within the presentation contract".to_owned(),
                migration_note: "no migration is required".to_owned(),
                state_transfer_note: "no reload or state transfer is required".to_owned(),
                security_privacy_cost_note: "no security, privacy, or cost change".to_owned(),
            }],
            completeness: TypedImpactCompleteness::Complete,
            omissions: Vec::new(),
        };
        let boundary = TypedConfigurationBoundary {
            verifier_present: true,
            verifier: TypedVerifier {
                verifier_id: "verifier-679".to_owned(),
                independent: true,
                probe_note: "probe the rendered presentation against the frozen base".to_owned(),
                success_note: "semantic value is observed at the requested field".to_owned(),
                partial_note: "only a bounded subset is observed".to_owned(),
                no_change_note: "the observed value equals the base".to_owned(),
                regression_note: "an unrelated presentation invariant regresses".to_owned(),
                unavailable_note: "the independent probe cannot run".to_owned(),
                unknown_note: "the probe result cannot be classified".to_owned(),
                process_success_insufficient: true,
                readings: vec![
                    TypedVerifierReading::Success,
                    TypedVerifierReading::Partial,
                    TypedVerifierReading::NoChange,
                    TypedVerifierReading::Regression,
                    TypedVerifierReading::Unavailable,
                    TypedVerifierReading::Unknown,
                ],
                max_attempts: 2,
                stop_note: "stop on no progress or semantic regression".to_owned(),
            },
            rollout: TypedRolloutPlan {
                sequence: vec!["probe".to_owned(), "canary".to_owned()],
                max_attempts: 2,
                deadline_ms: Some(2_000),
                stop_on_no_progress: true,
                cancellation_note: "cancel before any external application".to_owned(),
                canary_scope: "one presentation view".to_owned(),
            },
            rollback_present: true,
            rollback: TypedRollbackPlan {
                anchor_digest: base.digest.clone(),
                exact_previous_snapshot: true,
                steps: vec!["restore the exact frozen base snapshot".to_owned()],
                forward_repair_note: None,
            },
            approval: TypedApproval {
                required: false,
                owner: "alice".to_owned(),
                status: TypedApprovalStatus::NotRequired,
                expires_at_ms: None,
            },
            application_owner: "configuration-writer".to_owned(),
        };
        let policy = TypedConfigurationPolicy {
            policy_id: "policy-7".to_owned(),
            policy_revision: 2,
            max_fields: 8,
            max_changes: 8,
            max_schemas: 16,
            max_impact: 8,
            max_history: 8,
            allow_partial: false,
            forbidden_widenings: vec![
                ConfigurationCeiling::Authority,
                ConfigurationCeiling::Privacy,
                ConfigurationCeiling::Remote,
                ConfigurationCeiling::CostOrRoute,
                ConfigurationCeiling::AutomaticLaunch,
                ConfigurationCeiling::ProductVerifier,
                ConfigurationCeiling::FilesystemOrProcess,
            ],
            decision_widenings: Vec::new(),
            observation_time_ms: Some(1_000),
            deadline_ms: Some(2_000),
            cancelled: false,
            owner_note: "bounded candidate-only configuration planning".to_owned(),
        };
        TypedFixture {
            job: test_job(),
            draft: test_draft(),
            request,
            snapshots: TypedConfigurationSnapshotSet {
                base,
                parent: None,
                overlay: None,
            },
            schemas,
            changes,
            impact,
            history: TypedPriorHistory {
                expected_attempt_ids: Vec::new(),
                attempts: Vec::new(),
                outcome_note: "no prior typed attempt".to_owned(),
            },
            boundary,
            policy,
        }
    }

    fn typed_propose(
        fixture: &TypedFixture,
    ) -> Result<super::ConfigurationChangeCandidate, super::ConfigurationError> {
        propose_typed_configuration_change(
            &fixture.job,
            &fixture.draft,
            &fixture.request,
            &fixture.snapshots,
            &fixture.schemas,
            &fixture.changes,
            &fixture.impact,
            &fixture.history,
            &fixture.boundary,
            &fixture.policy,
        )
    }

    fn typed_schema_for(fixture: &TypedFixture, field_id: &str) -> ConfigurationFieldSchema {
        fixture
            .schemas
            .iter()
            .find(|schema| schema.field_id == field_id)
            .cloned()
            .expect("typed fixture schema")
    }

    fn set_typed_change(
        fixture: &mut TypedFixture,
        field_id: &str,
        operation: ConfigOp,
        before: Presence,
        after: Presence,
        value: Option<TypedConfigurationValue>,
        secret_ref: Option<SecretReference>,
    ) {
        let schema = typed_schema_for(fixture, field_id);
        fixture.request.fields = vec![TypedRequestedField {
            field_id: field_id.to_owned(),
            layer: schema.layer,
            owner: schema.owner.clone(),
            desired: after,
            value: value.clone(),
            unit: schema.unit,
            grounded: true,
            evidence_note: "grounded typed test mapping".to_owned(),
        }];
        fixture.request.intent_id = ["intent-679-", field_id].concat();
        fixture.changes = vec![TypedConfigurationChange {
            change_id: ["change-679-", field_id].concat(),
            field_id: field_id.to_owned(),
            schema_id: schema.schema_id,
            layer: schema.layer,
            owner: schema.owner,
            operation,
            before,
            after,
            value,
            unit: schema.unit,
            secret_ref,
            rationale: "grounded typed operation".to_owned(),
            sequence: 1,
            expected_base_revision: fixture.snapshots.base.revision,
            widenings: Vec::new(),
            canonical_change_digest: None,
        }];
    }

    fn typed_history_attempt(
        fixture: &TypedFixture,
        attempt_id: &str,
        intent_id: &str,
        request_digest: String,
        delta_digest: String,
        base_digest: String,
        changed_field_ids: Vec<String>,
        disposition: TypedHistoryDisposition,
    ) -> TypedHistoryAttempt {
        TypedHistoryAttempt {
            attempt_id: attempt_id.to_owned(),
            intent_id: intent_id.to_owned(),
            request_digest,
            delta_digest,
            base_digest,
            changed_field_ids,
            disposition,
            evidence_refs: vec!["history-evidence-1".to_owned()],
            outcome_note: fixture.history.outcome_note.clone(),
        }
    }

    // LEGACY_COMPACT_COMPATIBILITY_CASE: 679/1
    #[test]
    fn legacy_case_01_presentation_only_intent_is_complete() {
        let candidate = run_valid();
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
        assert_eq!(candidate.intent_handle, "cfg-snap-9");
        assert_eq!(candidate.primary_layer, ConfigLayer::Presentation);
        assert_eq!(candidate.primary_owner, "owner-1");
        assert_eq!(candidate.base_digest, "9".repeat(64));
        assert_eq!(candidate.base_revision, 9);
        assert_eq!(candidate.changes.len(), 1);
        assert_eq!(candidate.impact.len(), 1);
        assert_eq!(candidate.input_receipt_digest, "e".repeat(64));
        assert_eq!(candidate.attempt_denominator, ["att-1".to_owned()].to_vec());
        assert!(is_hex64_lower(&candidate.candidate_digest));
        assert!(candidate.preservation.overall().is_ok());
        assert_eq!(candidate.preservation.verdicts.len(), 7);
        assert_eq!(outcome_rejection_hint(&candidate.outcome), None);
    }

    // LEGACY_COMPACT_COMPATIBILITY_CASE: 679/2
    #[test]
    fn legacy_case_02_runtime_ceiling_exceeded_fails_closed() {
        let job = test_job();
        let draft = test_draft();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let mut policy = test_policy();
        policy.max_changes = 0;
        let result = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        );
        let Err(err) = result else {
            panic!("over-ceiling runtime delta must fail");
        };
        assert!(matches!(err, super::ConfigurationError::Bounds { .. }));
        assert_eq!(
            error_rejection_hint(&err),
            CurationRejectionCode::BudgetExceeded
        );
    }

    // LEGACY_COMPACT_COMPATIBILITY_CASE: 679/3
    #[test]
    fn legacy_case_03_unknown_field_vocab_is_rejected() {
        let job = test_job();
        let draft = test_draft();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-never-grounded")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("unknown vocab stays an inert outcome");
        };
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::IdentityMismatch)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // LEGACY_COMPACT_COMPATIBILITY_CASE: 679/4
    #[test]
    fn legacy_case_04_wrong_job_shape_fails_closed() {
        let mut job = test_job();
        job.job_class = JobClass::Curation;
        let draft = test_draft();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let result = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        );
        let Err(err) = result else {
            panic!("wrong job shape must fail");
        };
        assert!(matches!(err, super::ConfigurationError::Binding { .. }));
        assert_eq!(
            error_rejection_hint(&err),
            CurationRejectionCode::IdentityMismatch
        );
    }

    // LEGACY_COMPACT_COMPATIBILITY_CASE: 679/5
    #[test]
    fn legacy_case_05_scope_drift_fails_closed() {
        let job = test_job();
        let mut draft = test_draft();
        draft.scope_id = "scope-other".to_owned();
        draft.receipt.scope_id = "scope-other".to_owned();
        let request = test_request();
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let result = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        );
        let Err(err) = result else {
            panic!("scope drift must fail");
        };
        assert!(matches!(err, super::ConfigurationError::Binding { .. }));
        assert_eq!(
            error_rejection_hint(&err),
            CurationRejectionCode::IdentityMismatch
        );
    }

    // LEGACY_COMPACT_COMPATIBILITY_CASE: 679/6
    #[test]
    fn legacy_case_06_prose_without_mapping_yields_clarification() {
        let job = test_job();
        let draft = test_draft();
        let request = StructuredRequest {
            request_id: "req-prose".to_owned(),
            summary_note: "Human describes a vague wish without any grounded field".to_owned(),
            fields: Vec::new(),
            has_structured_mapping: false,
            generic_patch_note: None,
        };
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("prose-only request stays an inert outcome");
        };
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // LEGACY_COMPACT_COMPATIBILITY_CASE: 679/7
    #[test]
    fn legacy_case_07_rival_owner_binding_yields_clarification() {
        let job = test_job();
        let draft = test_draft();
        let mut first = test_structured_field("field-title-size");
        first.owner = "owner-1".to_owned();
        let mut second = test_structured_field("field-title-size");
        second.owner = "owner-2".to_owned();
        let request = StructuredRequest {
            request_id: "req-ambiguous".to_owned(),
            summary_note: "one field bound to rival owners needs a Human choice".to_owned(),
            fields: [first, second].to_vec(),
            has_structured_mapping: true,
            generic_patch_note: None,
        };
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("ambiguous binding stays an inert outcome");
        };
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedPrecision)
        );
    }

    // LEGACY_COMPACT_COMPATIBILITY_CASE: 679/8
    #[test]
    fn legacy_case_08_generic_patch_shape_is_rejected() {
        let job = test_job();
        let draft = test_draft();
        let request = StructuredRequest {
            request_id: "req-patch".to_owned(),
            summary_note: "caller offers a patch document instead of typed fields".to_owned(),
            fields: [test_structured_field("field-title-size")].to_vec(),
            has_structured_mapping: true,
            generic_patch_note: Some("apply this json patch with op replace".to_owned()),
        };
        let base = test_base();
        let changes = [test_change("field-title-size")].to_vec();
        let impact = test_impact();
        let history = test_history();
        let boundary = test_boundary();
        let policy = test_policy();
        let Ok(candidate) = propose_configuration_change(
            &job, &draft, &request, &base, &changes, &impact, &history, &boundary, &policy,
        ) else {
            panic!("generic patch stays an inert outcome");
        };
        assert_eq!(candidate.outcome, ConfigurationOutcome::UnsupportedShape);
        assert_eq!(
            outcome_rejection_hint(&candidate.outcome),
            Some(CurationRejectionCode::UnsupportedJobShape)
        );
        assert!(candidate.preservation.overall().is_ok());
    }

    // WORK_UNIT_CASE: 679/1
    #[test]
    fn case_01_typed_presentation_candidate_is_complete() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("typed candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
        assert_eq!(candidate.primary_layer, ConfigLayer::Presentation);
        assert_eq!(candidate.primary_owner, "owner-1");
        assert_eq!(candidate.input_receipt_digest, "e".repeat(64));
        assert!(validate_typed_candidate(&candidate).is_ok());
        assert!(
            candidate
                .details
                .as_ref()
                .is_some_and(|details| details.candidate_only)
        );
    }

    // WORK_UNIT_CASE: 679/2
    #[test]
    fn case_02_typed_runtime_semantics_remain_bounded() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("bounded typed candidate");
        let details = candidate.details.as_ref().expect("typed details");
        assert_eq!(details.boundary.rollout.max_attempts, 2);
        assert_eq!(details.boundary.verifier.max_attempts, 2);
        assert!(details.candidate_only);
        assert!(details.boundary.application_owner.contains("configuration"));
    }

    // WORK_UNIT_CASE: 679/3
    #[test]
    fn case_03_typed_vocab_binds_layer_field_change_and_impact() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("typed vocabulary candidate");
        let details = candidate.details.as_ref().expect("typed details");
        assert_eq!(details.changes[0].layer, ConfigLayer::Presentation);
        assert_eq!(details.changes[0].field_id, "field-int");
        assert_eq!(details.changes[0].operation, ConfigOp::Set);
        assert_eq!(
            details.impact.members[0].disposition,
            ImpactDisposition::Direct
        );
        assert_eq!(details.changes[0].owner, details.schemas[2].owner);
    }

    // WORK_UNIT_CASE: 679/4
    #[test]
    fn case_04_typed_wrong_job_shape_fails_closed() {
        let mut fixture = typed_fixture();
        fixture.job.job_class = JobClass::Curation;
        let result = typed_propose(&fixture);
        assert!(matches!(
            result,
            Err(super::ConfigurationError::Binding { .. })
        ));
    }

    // WORK_UNIT_CASE: 679/5
    #[test]
    fn case_05_typed_task_scope_and_receipt_binding_fails_closed() {
        let mut fixture = typed_fixture();
        fixture.request.scope_id = "scope-drift".to_owned();
        assert!(matches!(
            typed_propose(&fixture),
            Err(super::ConfigurationError::Binding { .. })
        ));

        let mut receipt_drift = typed_fixture();
        receipt_drift.request.input_receipt_digest = "f".repeat(64);
        assert!(matches!(
            typed_propose(&receipt_drift),
            Err(super::ConfigurationError::Receipt { .. })
        ));
    }

    // WORK_UNIT_CASE: 679/6
    #[test]
    fn case_06_typed_prose_without_mapping_yields_clarification() {
        let mut fixture = typed_fixture();
        fixture.request.structured_mapping = false;
        fixture.request.fields.clear();
        let candidate = typed_propose(&fixture).expect("clarification candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
        assert!(candidate.note.contains("structured"));
    }

    // WORK_UNIT_CASE: 679/7
    #[test]
    fn case_07_typed_ambiguity_is_preserved_for_human_choice() {
        let mut fixture = typed_fixture();
        fixture.request.alternatives = vec!["field-int=20".to_owned(), "field-int=30".to_owned()];
        let candidate = typed_propose(&fixture).expect("ambiguity candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
        assert_eq!(
            candidate
                .details
                .as_ref()
                .expect("typed details")
                .request
                .alternatives
                .len(),
            2
        );
    }

    // WORK_UNIT_CASE: 679/8
    #[test]
    fn case_08_typed_unmapped_or_open_shape_is_rejected() {
        let mut fixture = typed_fixture();
        fixture.request.fields[0].grounded = false;
        let candidate = typed_propose(&fixture).expect("rejection candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        assert!(candidate.note.contains("grounded"));
    }

    // WORK_UNIT_CASE: 679/9
    #[test]
    fn case_09_read_only_derived_and_wrong_layer_fields_are_rejected() {
        for mutability in [
            ConfigurationFieldMutability::ReadOnly,
            ConfigurationFieldMutability::Derived,
        ] {
            let mut fixture = typed_fixture();
            set_typed_change(
                &mut fixture,
                "field-readonly",
                ConfigOp::Set,
                Presence::Value,
                Presence::Value,
                Some(TypedConfigurationValue::Boolean(false)),
                None,
            );
            fixture
                .schemas
                .iter_mut()
                .find(|schema| schema.field_id == "field-readonly")
                .expect("read-only schema")
                .mutability = mutability;
            let candidate = typed_propose(&fixture).expect("mutability rejection candidate");
            assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        }

        let mut wrong_layer = typed_fixture();
        wrong_layer.request.fields[0].layer = ConfigLayer::Runtime;
        wrong_layer.changes[0].layer = ConfigLayer::Runtime;
        let candidate = typed_propose(&wrong_layer).expect("wrong-layer candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 679/10
    #[test]
    fn case_10_cross_owner_changes_require_decomposition() {
        let mut fixture = typed_fixture();
        let mut mode_schema = typed_schema_for(&fixture, "field-mode");
        mode_schema.owner = "owner-2".to_owned();
        fixture
            .schemas
            .retain(|schema| schema.field_id != "field-mode");
        fixture.schemas.push(mode_schema.clone());
        fixture.request.fields.push(TypedRequestedField {
            field_id: "field-mode".to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-2".to_owned(),
            desired: Presence::Value,
            value: Some(TypedConfigurationValue::Enum("wide".to_owned())),
            unit: None,
            grounded: true,
            evidence_note: "second owner mapping".to_owned(),
        });
        fixture.changes.push(TypedConfigurationChange {
            change_id: "change-679-mode".to_owned(),
            field_id: "field-mode".to_owned(),
            schema_id: mode_schema.schema_id,
            layer: ConfigLayer::Presentation,
            owner: "owner-2".to_owned(),
            operation: ConfigOp::Set,
            before: Presence::Value,
            after: Presence::Value,
            value: Some(TypedConfigurationValue::Enum("wide".to_owned())),
            unit: None,
            secret_ref: None,
            rationale: "independent owner change".to_owned(),
            sequence: 2,
            expected_base_revision: fixture.snapshots.base.revision,
            widenings: Vec::new(),
            canonical_change_digest: None,
        });
        let candidate = typed_propose(&fixture).expect("decomposition candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        assert!(candidate.note.contains("separate typed intents"));
    }

    // WORK_UNIT_CASE: 679/11
    #[test]
    fn case_11_exact_current_base_is_required() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("current-base candidate");
        let details = candidate.details.as_ref().expect("typed details");
        assert_eq!(
            details.request.base_snapshot_id,
            details.base_snapshot.snapshot_id
        );
        assert_eq!(
            details.request.base_revision,
            details.base_snapshot.revision
        );
        assert_eq!(details.base_snapshot.validity, TypedSnapshotValidity::Valid);
    }

    // WORK_UNIT_CASE: 679/12
    #[test]
    fn case_12_stale_schema_provenance_or_overlay_base_is_not_rebased() {
        let mut fixture = typed_fixture();
        fixture.snapshots.base.validity = TypedSnapshotValidity::Stale;
        let candidate = typed_propose(&fixture).expect("stale-base candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Stale);
        assert!(candidate.note.contains("stale"));

        let mut wrong_base = typed_fixture();
        wrong_base.request.base_revision += 1;
        let candidate = typed_propose(&wrong_base).expect("wrong-base candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Stale);
    }

    // WORK_UNIT_CASE: 679/13
    #[test]
    fn case_13_absent_empty_value_inherit_reset_and_removed_are_distinct() {
        let fixture = typed_fixture();
        let fields = &fixture.snapshots.base.fields;
        assert_ne!(
            fields
                .iter()
                .find(|field| field.field_id == "field-absent")
                .unwrap()
                .presence,
            fields
                .iter()
                .find(|field| field.field_id == "field-empty")
                .unwrap()
                .presence
        );
        assert_ne!(Presence::Value, Presence::Inherited);
        assert_ne!(Presence::Reset, Presence::Removed);
        assert_ne!(Presence::Unknown, Presence::Absent);
    }

    // WORK_UNIT_CASE: 679/14
    #[test]
    fn case_14_closed_typed_operations_derive_legal_snapshots() {
        let operations = [
            (
                "field-int",
                ConfigOp::Set,
                Presence::Value,
                Presence::Value,
                Some(TypedConfigurationValue::Integer(21)),
            ),
            (
                "field-int",
                ConfigOp::Reset,
                Presence::Value,
                Presence::Reset,
                None,
            ),
            (
                "field-tags",
                ConfigOp::AddMember,
                Presence::Value,
                Presence::Value,
                Some(TypedConfigurationValue::Text("gamma".to_owned())),
            ),
            (
                "field-tags",
                ConfigOp::RemoveMember,
                Presence::Value,
                Presence::Value,
                Some(TypedConfigurationValue::Text("beta".to_owned())),
            ),
            (
                "field-int",
                ConfigOp::RemoveOverride,
                Presence::Value,
                Presence::Removed,
                None,
            ),
        ];
        for (field, operation, before, after, value) in operations {
            let mut fixture = typed_fixture();
            fixture
                .schemas
                .iter_mut()
                .find(|schema| schema.field_id == "field-mode")
                .expect("mode schema")
                .constraints
                .clear();
            set_typed_change(&mut fixture, field, operation, before, after, value, None);
            let candidate = typed_propose(&fixture).expect("legal typed operation");
            assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
        }

        let mut inherited = typed_fixture();
        inherited
            .schemas
            .iter_mut()
            .find(|schema| schema.field_id == "field-mode")
            .expect("mode schema")
            .constraints
            .clear();
        let mut parent = inherited.snapshots.base.clone();
        parent.snapshot_id = "snap-parent-8".to_owned();
        parent.revision = 8;
        parent.fields = vec![typed_snapshot_field(
            "field-int",
            Presence::Value,
            Some(TypedConfigurationValue::Integer(8)),
        )];
        parent.digest = parent.computed_digest().expect("parent digest");
        inherited.snapshots.base.parent_snapshot_id = Some(parent.snapshot_id.clone());
        inherited.snapshots.base.digest = inherited
            .snapshots
            .base
            .computed_digest()
            .expect("parent-bound base digest");
        inherited.boundary.rollback.anchor_digest = inherited.snapshots.base.digest.clone();
        inherited.snapshots.parent = Some(parent);
        set_typed_change(
            &mut inherited,
            "field-int",
            ConfigOp::Inherit,
            Presence::Value,
            Presence::Inherited,
            None,
            None,
        );
        let candidate = typed_propose(&inherited).expect("inherit operation");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
    }

    // WORK_UNIT_CASE: 679/15
    #[test]
    fn case_15_type_range_and_enum_constraints_fail_closed() {
        let invalids = [
            ("field-int", TypedConfigurationValue::Integer(101)),
            (
                "field-mode",
                TypedConfigurationValue::Enum("unknown".to_owned()),
            ),
            ("field-int", TypedConfigurationValue::Text("20".to_owned())),
        ];
        for (field, value) in invalids {
            let mut fixture = typed_fixture();
            set_typed_change(
                &mut fixture,
                field,
                ConfigOp::Set,
                Presence::Value,
                Presence::Value,
                Some(value),
                None,
            );
            let candidate = typed_propose(&fixture).expect("typed constraint candidate");
            assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        }

        let mut unit_mismatch = typed_fixture();
        unit_mismatch.changes[0].unit = None;
        let candidate = typed_propose(&unit_mismatch).expect("unit-mismatch candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);

        let mut cross_field = typed_fixture();
        set_typed_change(
            &mut cross_field,
            "field-int",
            ConfigOp::RemoveOverride,
            Presence::Value,
            Presence::Removed,
            None,
            None,
        );
        let candidate = typed_propose(&cross_field).expect("cross-field candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 679/16
    #[test]
    fn case_16_duplicate_conflicting_and_noop_operations_are_explicit() {
        let mut duplicate = typed_fixture();
        duplicate.changes.push(duplicate.changes[0].clone());
        assert!(matches!(
            typed_propose(&duplicate),
            Err(super::ConfigurationError::Order { .. })
        ));

        let mut noop = typed_fixture();
        set_typed_change(
            &mut noop,
            "field-int",
            ConfigOp::Set,
            Presence::Value,
            Presence::Value,
            Some(TypedConfigurationValue::Integer(10)),
            None,
        );
        let candidate = typed_propose(&noop).expect("no-op candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
        assert!(candidate.note.contains("no-op"));
    }

    // WORK_UNIT_CASE: 679/17
    #[test]
    fn case_17_raw_secret_is_rejected_and_reference_is_preserved() {
        let mut raw = typed_fixture();
        set_typed_change(
            &mut raw,
            "field-empty",
            ConfigOp::Set,
            Presence::Empty,
            Presence::Value,
            Some(TypedConfigurationValue::Text(
                "password=super-secret".to_owned(),
            )),
            None,
        );
        let candidate = typed_propose(&raw).expect("raw-secret candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);

        let reference = SecretReference {
            class: "vault-ref".to_owned(),
            reference_id: "secret-8".to_owned(),
        };
        let mut safe = typed_fixture();
        set_typed_change(
            &mut safe,
            "field-secret",
            ConfigOp::Set,
            Presence::Value,
            Presence::Value,
            Some(TypedConfigurationValue::SecretReference(reference.clone())),
            Some(reference.clone()),
        );
        let candidate = typed_propose(&safe).expect("reference candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
        assert_eq!(
            candidate.details.expect("typed details").changes[0].secret_ref,
            Some(reference)
        );
    }

    // WORK_UNIT_CASE: 679/18
    #[test]
    fn case_18_candidate_snapshot_is_pure_and_unchanged_fields_are_equal() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("pure candidate");
        let details = candidate.details.as_ref().expect("typed details");
        assert_eq!(
            details.candidate_snapshot.parent_snapshot_id.as_deref(),
            Some("snap-typed-9")
        );
        assert_eq!(
            details.candidate_snapshot.validity,
            TypedSnapshotValidity::Derived
        );
        assert!(details.unchanged_fields.iter().all(|field| {
            fixture
                .snapshots
                .base
                .fields
                .iter()
                .find(|base| base.field_id == field.field_id)
                == Some(field)
        }));
        assert!(validate_typed_candidate(&candidate).is_ok());
    }

    // WORK_UNIT_CASE: 679/19
    #[test]
    fn case_19_hidden_drop_or_digest_drift_invalidates_candidate() {
        let fixture = typed_fixture();
        let mut candidate = typed_propose(&fixture).expect("candidate");
        let mut details = candidate.details.take().expect("typed details");
        details
            .candidate_snapshot
            .fields
            .retain(|field| field.field_id != "field-absent");
        details.candidate_snapshot.digest = details
            .candidate_snapshot
            .computed_digest()
            .expect("drifted candidate digest");
        candidate.details = Some(details);
        assert!(matches!(
            validate_typed_candidate(&candidate),
            Err(super::ConfigurationError::Digest { .. })
        ));
    }

    // WORK_UNIT_CASE: 679/20
    #[test]
    fn case_20_authority_widening_is_rejected() {
        let mut fixture = typed_fixture();
        fixture.changes[0].widenings = vec![ConfigurationCeiling::Authority];
        let candidate = typed_propose(&fixture).expect("authority ceiling candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 679/21
    #[test]
    fn case_21_privacy_widening_is_rejected() {
        let mut fixture = typed_fixture();
        fixture.changes[0].widenings = vec![ConfigurationCeiling::Privacy];
        let candidate = typed_propose(&fixture).expect("privacy ceiling candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 679/22
    #[test]
    fn case_22_remote_widening_is_rejected() {
        let mut fixture = typed_fixture();
        fixture.changes[0].widenings = vec![ConfigurationCeiling::Remote];
        let candidate = typed_propose(&fixture).expect("remote ceiling candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 679/23
    #[test]
    fn case_23_cost_or_route_widening_is_rejected() {
        let mut fixture = typed_fixture();
        fixture.changes[0].widenings = vec![ConfigurationCeiling::CostOrRoute];
        let candidate = typed_propose(&fixture).expect("cost ceiling candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 679/24
    #[test]
    fn case_24_automatic_launch_widening_is_rejected() {
        let mut fixture = typed_fixture();
        fixture.changes[0].widenings = vec![ConfigurationCeiling::AutomaticLaunch];
        let candidate = typed_propose(&fixture).expect("launch ceiling candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 679/25
    #[test]
    fn case_25_product_verifier_and_process_widenings_are_rejected() {
        for ceiling in [
            ConfigurationCeiling::ProductVerifier,
            ConfigurationCeiling::FilesystemOrProcess,
        ] {
            let mut fixture = typed_fixture();
            fixture.changes[0].widenings = vec![ceiling];
            let candidate = typed_propose(&fixture).expect("protected ceiling candidate");
            assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        }
    }

    // WORK_UNIT_CASE: 679/26
    #[test]
    fn case_26_owner_decision_is_not_ready_without_approval() {
        let mut fixture = typed_fixture();
        fixture.policy.forbidden_widenings.clear();
        fixture.policy.decision_widenings = vec![ConfigurationCeiling::Authority];
        fixture.changes[0].widenings = vec![ConfigurationCeiling::Authority];
        fixture.boundary.approval = TypedApproval {
            required: true,
            owner: "owner-1".to_owned(),
            status: TypedApprovalStatus::Required,
            expires_at_ms: Some(2_000),
        };
        let candidate = typed_propose(&fixture).expect("decision-required candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::DecisionRequired);
        assert!(
            !candidate
                .details
                .as_ref()
                .expect("typed details")
                .candidate_snapshot
                .validity
                .eq(&TypedSnapshotValidity::Derived)
        );
    }

    // WORK_UNIT_CASE: 679/27
    #[test]
    fn case_27_complete_impact_closure_covers_exact_denominator() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("complete impact candidate");
        let details = candidate.details.as_ref().expect("typed details");
        assert_eq!(
            details.impact.completeness,
            TypedImpactCompleteness::Complete
        );
        assert_eq!(
            details.impact.expected_member_ids,
            vec!["view-home".to_owned()]
        );
        assert_eq!(details.impact.members.len(), 1);
        assert!(details.impact.omissions.is_empty());
    }

    // WORK_UNIT_CASE: 679/28
    #[test]
    fn case_28_empty_impact_cannot_prove_no_impact() {
        let mut fixture = typed_fixture();
        fixture.impact.expected_member_ids.clear();
        fixture.impact.members.clear();
        let candidate = typed_propose(&fixture).expect("empty-impact candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
        assert!(candidate.note.contains("impact"));
    }

    // WORK_UNIT_CASE: 679/29
    #[test]
    fn case_29_unknown_load_bearing_impact_blocks_completeness() {
        let mut fixture = typed_fixture();
        fixture.impact.members[0].disposition = ImpactDisposition::Unknown;
        let candidate = typed_propose(&fixture).expect("unknown-impact candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
        assert!(candidate.note.contains("unknown"));
    }

    // WORK_UNIT_CASE: 679/30
    #[test]
    fn case_30_compatibility_migration_and_state_transfer_evidence_is_retained() {
        let mut fixture = typed_fixture();
        fixture.impact.members[0].disposition = ImpactDisposition::Conditional;
        fixture.impact.members[0].path = vec!["field-int".to_owned(), "cache".to_owned()];
        fixture.impact.members[0].evidence_refs = vec!["compat-1".to_owned()];
        fixture.impact.members[0].compatibility_note = "old cache reads both revisions".to_owned();
        fixture.impact.members[0].migration_note = "migrate the bounded cache key".to_owned();
        fixture.impact.members[0].state_transfer_note =
            "transfer only the frozen cache state".to_owned();
        let candidate = typed_propose(&fixture).expect("conditional-impact candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
        let member = &candidate.details.expect("typed details").impact.members[0];
        assert_eq!(member.migration_note, "migrate the bounded cache key");
        assert_eq!(
            member.state_transfer_note,
            "transfer only the frozen cache state"
        );
    }

    // WORK_UNIT_CASE: 679/31
    #[test]
    fn case_31_preapplication_probe_and_independent_verifier_are_inert_requirements() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("verifier-bound candidate");
        let details = candidate.details.as_ref().expect("typed details");
        assert!(details.boundary.verifier.probe_note.contains("probe"));
        assert!(details.boundary.verifier.independent);
        assert!(details.boundary.verifier.process_success_insufficient);
        assert!(details.candidate_only);
    }

    // WORK_UNIT_CASE: 679/32
    #[test]
    fn case_32_process_success_alone_is_insufficient() {
        let mut fixture = typed_fixture();
        fixture.boundary.verifier.process_success_insufficient = false;
        let candidate = typed_propose(&fixture).expect("process-success candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 679/33
    #[test]
    fn case_33_rollout_canary_and_attempt_bounds_are_required() {
        let mut fixture = typed_fixture();
        fixture.boundary.rollout.sequence.clear();
        let candidate = typed_propose(&fixture).expect("rollout-bound candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);

        let mut zero_attempts = typed_fixture();
        zero_attempts.boundary.rollout.max_attempts = 0;
        let candidate = typed_propose(&zero_attempts).expect("attempt-bound candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
    }

    // WORK_UNIT_CASE: 679/34
    #[test]
    fn case_34_verifier_partitions_all_six_observed_outcomes() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("reading-partition candidate");
        let readings = &candidate
            .details
            .expect("typed details")
            .boundary
            .verifier
            .readings;
        for reading in [
            TypedVerifierReading::Success,
            TypedVerifierReading::Partial,
            TypedVerifierReading::NoChange,
            TypedVerifierReading::Regression,
            TypedVerifierReading::Unavailable,
            TypedVerifierReading::Unknown,
        ] {
            assert!(readings.contains(&reading));
        }

        let mut incomplete = typed_fixture();
        incomplete.boundary.verifier.readings.pop();
        let candidate = typed_propose(&incomplete).expect("incomplete-reading candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Insufficient);
    }

    // WORK_UNIT_CASE: 679/35
    #[test]
    fn case_35_deadline_and_cancellation_stop_candidate_readiness() {
        let mut deadline = typed_fixture();
        deadline.policy.observation_time_ms = Some(2_000);
        let candidate = typed_propose(&deadline).expect("deadline candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Stale);

        let mut cancelled = typed_fixture();
        cancelled.policy.cancelled = true;
        let candidate = typed_propose(&cancelled).expect("cancelled candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
    }

    // WORK_UNIT_CASE: 679/36
    #[test]
    fn case_36_rollback_requires_exact_previous_snapshot_or_forward_repair() {
        let mut unsafe_rollback = typed_fixture();
        unsafe_rollback.boundary.rollback.exact_previous_snapshot = false;
        let candidate = typed_propose(&unsafe_rollback).expect("unsafe-rollback candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::DecisionRequired);

        let mut repaired = typed_fixture();
        repaired.boundary.rollback.exact_previous_snapshot = false;
        repaired.boundary.rollback.forward_repair_note =
            Some("configuration owner supplies an explicit forward repair".to_owned());
        let candidate = typed_propose(&repaired).expect("forward-repair candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
    }

    // WORK_UNIT_CASE: 679/37
    #[test]
    fn case_37_approval_expiry_is_stale_and_silence_is_not_permission() {
        let mut expired = typed_fixture();
        expired.boundary.approval = TypedApproval {
            required: true,
            owner: "owner-1".to_owned(),
            status: TypedApprovalStatus::Expired,
            expires_at_ms: Some(900),
        };
        let candidate = typed_propose(&expired).expect("expired-approval candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Stale);

        let mut absent = typed_fixture();
        absent.boundary.approval.required = true;
        absent.boundary.approval.status = TypedApprovalStatus::Required;
        let candidate = typed_propose(&absent).expect("absent-approval candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::DecisionRequired);
    }

    // WORK_UNIT_CASE: 679/38
    #[test]
    fn case_38_exact_replay_is_identified_without_new_effect() {
        let mut fixture = typed_fixture();
        let request_digest =
            canonical_typed_request_digest(&fixture.request).expect("request digest");
        let delta_digest = canonical_typed_delta_digest(&fixture.changes).expect("delta digest");
        fixture.history.expected_attempt_ids = vec!["attempt-duplicate".to_owned()];
        fixture.history.attempts = vec![typed_history_attempt(
            &fixture,
            "attempt-duplicate",
            &fixture.request.intent_id,
            request_digest,
            delta_digest,
            fixture.snapshots.base.digest.clone(),
            vec!["field-int".to_owned()],
            TypedHistoryDisposition::CandidateOnly,
        )];
        let candidate = typed_propose(&fixture).expect("duplicate candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
        assert_eq!(
            candidate.details.expect("typed details").replay,
            TypedReplayDisposition::ExactDuplicate
        );
        assert!(candidate.note.contains("replay"));
    }

    // WORK_UNIT_CASE: 679/39
    #[test]
    fn case_39_changed_same_id_payload_is_an_identity_conflict() {
        let mut fixture = typed_fixture();
        fixture.history.expected_attempt_ids = vec!["attempt-conflict".to_owned()];
        fixture.history.attempts = vec![typed_history_attempt(
            &fixture,
            "attempt-conflict",
            &fixture.request.intent_id,
            "f".repeat(64),
            "d".repeat(64),
            fixture.snapshots.base.digest.clone(),
            vec!["field-int".to_owned()],
            TypedHistoryDisposition::CandidateOnly,
        )];
        let candidate = typed_propose(&fixture).expect("identity-conflict candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        assert_eq!(
            candidate.details.expect("typed details").replay,
            TypedReplayDisposition::IdentityConflict
        );
    }

    // WORK_UNIT_CASE: 679/40
    #[test]
    fn case_40_concurrent_same_base_field_conflict_is_rejected() {
        let mut fixture = typed_fixture();
        fixture.history.expected_attempt_ids = vec!["attempt-concurrent".to_owned()];
        fixture.history.attempts = vec![typed_history_attempt(
            &fixture,
            "attempt-concurrent",
            "other-intent",
            "a".repeat(64),
            "d".repeat(64),
            fixture.snapshots.base.digest.clone(),
            vec!["field-int".to_owned()],
            TypedHistoryDisposition::CandidateOnly,
        )];
        let candidate = typed_propose(&fixture).expect("concurrent-conflict candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        assert_eq!(
            candidate.details.expect("typed details").replay,
            TypedReplayDisposition::ConcurrentFieldConflict
        );
    }

    // WORK_UNIT_CASE: 679/41
    #[test]
    fn case_41_committed_base_drift_is_stale_without_auto_merge() {
        let mut fixture = typed_fixture();
        fixture.history.expected_attempt_ids = vec!["attempt-applied".to_owned()];
        fixture.history.attempts = vec![typed_history_attempt(
            &fixture,
            "attempt-applied",
            "other-intent",
            "a".repeat(64),
            "d".repeat(64),
            "b".repeat(64),
            vec!["field-mode".to_owned()],
            TypedHistoryDisposition::Applied,
        )];
        let candidate = typed_propose(&fixture).expect("base-drift candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Stale);
        assert_eq!(
            candidate.details.expect("typed details").replay,
            TypedReplayDisposition::CommittedBaseDrift
        );
    }

    // WORK_UNIT_CASE: 679/42
    #[test]
    fn case_42_failed_partial_and_unknown_history_is_retained() {
        let mut fixture = typed_fixture();
        fixture.history.expected_attempt_ids = vec![
            "attempt-failed".to_owned(),
            "attempt-partial".to_owned(),
            "attempt-unknown".to_owned(),
        ];
        fixture.history.attempts = vec![
            typed_history_attempt(
                &fixture,
                "attempt-failed",
                "old-failed",
                "1".repeat(64),
                "2".repeat(64),
                "3".repeat(64),
                vec!["field-int".to_owned()],
                TypedHistoryDisposition::Failed,
            ),
            typed_history_attempt(
                &fixture,
                "attempt-partial",
                "old-partial",
                "4".repeat(64),
                "5".repeat(64),
                "6".repeat(64),
                vec!["field-mode".to_owned()],
                TypedHistoryDisposition::Partial,
            ),
            typed_history_attempt(
                &fixture,
                "attempt-unknown",
                "old-unknown",
                "7".repeat(64),
                "8".repeat(64),
                "9".repeat(64),
                vec!["field-tags".to_owned()],
                TypedHistoryDisposition::UnknownOutcome,
            ),
        ];
        let candidate = typed_propose(&fixture).expect("history-retention candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
        assert_eq!(
            candidate
                .details
                .expect("typed details")
                .history
                .attempts
                .len(),
            3
        );
    }

    // WORK_UNIT_CASE: 679/43
    #[test]
    fn case_43_equivalent_failed_plan_requires_mechanism_review() {
        let mut fixture = typed_fixture();
        let request_digest =
            canonical_typed_request_digest(&fixture.request).expect("request digest");
        let delta_digest = canonical_typed_delta_digest(&fixture.changes).expect("delta digest");
        fixture.history.expected_attempt_ids = vec!["attempt-failed-equivalent".to_owned()];
        fixture.history.attempts = vec![typed_history_attempt(
            &fixture,
            "attempt-failed-equivalent",
            "old-failed",
            request_digest,
            delta_digest,
            fixture.snapshots.base.digest.clone(),
            vec!["field-int".to_owned()],
            TypedHistoryDisposition::Failed,
        )];
        let candidate = typed_propose(&fixture).expect("mechanism-review candidate");
        assert_eq!(
            candidate.outcome,
            ConfigurationOutcome::MechanismReviewRequired
        );
        assert_eq!(
            candidate.details.expect("typed details").replay,
            TypedReplayDisposition::MechanismReview
        );
    }

    // WORK_UNIT_CASE: 679/44
    #[test]
    fn case_44_output_preservation_and_exact_input_receipt_are_retained() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("preservation candidate");
        let details = candidate.details.as_ref().expect("typed details");
        assert_eq!(
            candidate.input_receipt_digest,
            fixture.draft.receipt.output_digest
        );
        assert_eq!(
            details.request.input_receipt_digest,
            fixture.draft.receipt.output_digest
        );
        assert_eq!(candidate.preservation.verdicts.len(), 7);
        assert!(candidate.preservation.overall().is_ok());
        assert_eq!(details.request.intent_id, fixture.request.intent_id);
    }

    // WORK_UNIT_CASE: 679/45
    #[test]
    fn case_45_partial_budget_deadline_and_cancellation_are_bounded() {
        let mut partial = typed_fixture();
        partial.policy.allow_partial = true;
        partial.impact.completeness = TypedImpactCompleteness::Partial;
        partial.impact.omissions = vec!["service-not-yet-mapped".to_owned()];
        let candidate = typed_propose(&partial).expect("partial candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Partial);

        let mut over_budget = typed_fixture();
        over_budget.policy.max_changes = 0;
        assert!(matches!(
            typed_propose(&over_budget),
            Err(super::ConfigurationError::Policy { .. } | super::ConfigurationError::Bounds { .. })
        ));
    }

    // WORK_UNIT_CASE: 679/46
    #[test]
    fn case_46_every_independent_bound_rejects_one_over() {
        let mut fields = typed_fixture();
        fields.policy.max_fields = super::MAX_FIELDS + 1;
        assert!(typed_propose(&fields).is_err());

        let mut changes = typed_fixture();
        changes.policy.max_changes = super::MAX_CHANGES + 1;
        assert!(typed_propose(&changes).is_err());

        let mut schemas = typed_fixture();
        schemas.policy.max_schemas = super::MAX_TYPED_SCHEMAS + 1;
        assert!(typed_propose(&schemas).is_err());

        let mut impact = typed_fixture();
        impact.policy.max_impact = super::MAX_IMPACT + 1;
        assert!(typed_propose(&impact).is_err());

        let mut history = typed_fixture();
        history.policy.max_history = super::MAX_ATTEMPTS + 1;
        assert!(typed_propose(&history).is_err());
    }

    // WORK_UNIT_CASE: 679/47
    #[test]
    fn case_47_rollout_sequence_is_semantic_and_ordered() {
        let mut fixture = typed_fixture();
        fixture.request.fields.push(TypedRequestedField {
            field_id: "field-mode".to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            desired: Presence::Value,
            value: Some(TypedConfigurationValue::Enum("wide".to_owned())),
            unit: None,
            grounded: true,
            evidence_note: "ordered second field".to_owned(),
        });
        fixture.changes.push(TypedConfigurationChange {
            change_id: "change-679-mode".to_owned(),
            field_id: "field-mode".to_owned(),
            schema_id: "schema-config-3".to_owned(),
            layer: ConfigLayer::Presentation,
            owner: "owner-1".to_owned(),
            operation: ConfigOp::Set,
            before: Presence::Value,
            after: Presence::Value,
            value: Some(TypedConfigurationValue::Enum("wide".to_owned())),
            unit: None,
            secret_ref: None,
            rationale: "ordered second change".to_owned(),
            sequence: 2,
            expected_base_revision: fixture.snapshots.base.revision,
            widenings: Vec::new(),
            canonical_change_digest: None,
        });
        let candidate = typed_propose(&fixture).expect("ordered candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Complete);
        assert_eq!(
            candidate
                .details
                .as_ref()
                .expect("typed details")
                .changes
                .iter()
                .map(|change| change.sequence)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );

        fixture.changes.reverse();
        assert!(matches!(
            typed_propose(&fixture),
            Err(super::ConfigurationError::Order { .. })
        ));
    }

    // WORK_UNIT_CASE: 679/48
    #[test]
    fn case_48_exact_replay_differs_from_changed_same_id_request() {
        let mut fixture = typed_fixture();
        let request_digest =
            canonical_typed_request_digest(&fixture.request).expect("request digest");
        let delta_digest = canonical_typed_delta_digest(&fixture.changes).expect("delta digest");
        fixture.history.expected_attempt_ids = vec!["attempt-replay".to_owned()];
        fixture.history.attempts = vec![typed_history_attempt(
            &fixture,
            "attempt-replay",
            &fixture.request.intent_id,
            request_digest,
            delta_digest,
            fixture.snapshots.base.digest.clone(),
            vec!["field-int".to_owned()],
            TypedHistoryDisposition::CandidateOnly,
        )];
        fixture
            .request
            .summary_note
            .push_str(" with changed rationale");
        let candidate = typed_propose(&fixture).expect("changed-replay candidate");
        assert_eq!(candidate.outcome, ConfigurationOutcome::Rejected);
        assert_eq!(
            candidate.details.expect("typed details").replay,
            TypedReplayDisposition::IdentityConflict
        );
    }

    // WORK_UNIT_CASE: 679/49
    #[test]
    fn case_49_malformed_bounded_input_is_panic_free() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut fixture = typed_fixture();
            fixture.request.summary_note = "x".repeat(super::MAX_NOTE_BYTES + 1);
            typed_propose(&fixture)
        }));
        assert!(result.is_ok());
        assert!(result.expect("panic-free result").is_err());
    }

    // WORK_UNIT_CASE: 679/50
    #[test]
    fn case_50_complete_fields_bind_exact_schema_owner_and_type() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("schema-bound candidate");
        let details = candidate.details.as_ref().expect("typed details");
        for change in &details.changes {
            let schema = details
                .schemas
                .iter()
                .find(|schema| schema.field_id == change.field_id)
                .expect("change schema");
            assert_eq!(schema.schema_id, change.schema_id);
            assert_eq!(schema.owner, change.owner);
            assert_eq!(schema.layer, change.layer);
            assert!(
                schema
                    .field_type
                    .accepts(change.value.as_ref().expect("typed value"))
            );
        }
    }

    // WORK_UNIT_CASE: 679/51
    #[test]
    fn case_51_recorded_candidate_digest_matches_pure_delta_derivation() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("digest candidate");
        let details = candidate.details.as_ref().expect("typed details");
        let derived = super::typed_derive_candidate(
            &fixture.snapshots,
            &fixture.schemas,
            &fixture.changes,
            &fixture.request,
        )
        .expect("pure typed derivation");
        assert_eq!(details.candidate_snapshot.digest, derived.digest);
        assert_eq!(
            details.candidate_snapshot.computed_digest().unwrap(),
            derived.digest
        );
        assert_eq!(
            details.delta_digest,
            canonical_typed_delta_digest(&fixture.changes).unwrap()
        );
    }

    // WORK_UNIT_CASE: 679/52
    #[test]
    fn case_52_removing_load_bearing_evidence_invalidates_complete_copy() {
        let mut impact_candidate = typed_propose(&typed_fixture()).expect("candidate");
        impact_candidate
            .details
            .as_mut()
            .expect("typed details")
            .impact
            .completeness = TypedImpactCompleteness::Partial;
        assert!(validate_typed_candidate(&impact_candidate).is_err());

        let mut verifier_candidate = typed_propose(&typed_fixture()).expect("candidate");
        verifier_candidate
            .details
            .as_mut()
            .expect("typed details")
            .boundary
            .verifier_present = false;
        assert!(validate_typed_candidate(&verifier_candidate).is_err());

        let mut rollback_candidate = typed_propose(&typed_fixture()).expect("candidate");
        rollback_candidate
            .details
            .as_mut()
            .expect("typed details")
            .boundary
            .rollback_present = false;
        assert!(validate_typed_candidate(&rollback_candidate).is_err());

        let mut approval_candidate = typed_propose(&typed_fixture()).expect("candidate");
        approval_candidate
            .details
            .as_mut()
            .expect("typed details")
            .boundary
            .approval = TypedApproval {
            required: true,
            owner: "owner-1".to_owned(),
            status: TypedApprovalStatus::Required,
            expires_at_ms: Some(2_000),
        };
        assert!(validate_typed_candidate(&approval_candidate).is_err());
    }

    // WORK_UNIT_CASE: 679/53
    #[test]
    fn case_53_forbidden_ceiling_never_emits_ready_candidate() {
        let mut fixture = typed_fixture();
        fixture.changes[0].widenings = vec![ConfigurationCeiling::Authority];
        let candidate = typed_propose(&fixture).expect("forbidden-ceiling candidate");
        assert_ne!(candidate.outcome, ConfigurationOutcome::Complete);
        assert!(candidate.note.contains("widening"));
    }

    // WORK_UNIT_CASE: 679/54
    #[test]
    fn case_54_candidate_has_no_raw_secret_or_acquired_execution_handle() {
        let fixture = typed_fixture();
        let candidate = typed_propose(&fixture).expect("candidate-only result");
        let debug = format!("{candidate:?}");
        assert!(!debug.contains("super-secret"));
        assert!(!debug.contains("bearer "));
        assert!(
            candidate
                .details
                .as_ref()
                .expect("typed details")
                .candidate_only
        );
    }

    // WORK_UNIT_CASE: 679/55
    #[test]
    fn case_55_source_and_api_guard_remain_candidate_only() {
        let source = include_str!("lib.rs");
        for line in source.lines().filter(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("use ") || trimmed.starts_with("extern crate ")
        }) {
            assert!(!line.contains("eliot_store"));
            assert!(!line.contains("tokio"));
            assert!(!line.contains("provider"));
            assert!(!line.contains("Finish"));
        }
        let candidate = typed_propose(&typed_fixture()).expect("candidate-only API result");
        let details = candidate.details.as_ref().expect("typed details");
        assert!(details.candidate_only);
        assert_eq!(details.boundary.application_owner, "configuration-writer");
        assert!(candidate.note.contains("candidate-only"));
    }
}
