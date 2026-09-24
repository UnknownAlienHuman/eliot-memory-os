//! Explicit finite compatibility facade over the native cue owners (#833).
//!
//! Current owners remain #804 contracts, #598 normalization (A-11), #622
//! binding candidates (A-12), #624 immutable snapshot (A-13), and #600
//! activation (A-14a); #612/B-RCTX/Host own delivery planning and state.
//! This crate duplicates none of them: local duplicate kinds, contracts,
//! algorithms, and state were deleted, and every retained path delegates
//! to exactly one owner exactly once or refuses with a typed refusal.
//! Historical layouts keep explicit `LegacyEliotCuesV1` identity with
//! closed bounded conversion; insufficient evidence yields typed refusal,
//! never a guessed target, kind, or profile.
//!
//! ## Facade disposition table (exact; every public item has one row)
//!
//! | # | Facade item | Disposition | Owner / replacement |
//! |---|-------------|-------------|---------------------|
//! | 1 | `CueKind` | `ReexportOwner` | `eliot-cue-contracts` vocabulary (type identity preserved) |
//! | 2 | `MatchMode` | `ReexportOwner` | `eliot-cue-contracts` vocabulary (type identity preserved) |
//! | 3 | `LegacyEliotCuesV1Row` | `LegacyDTO` | frozen v1 envelope; decoded by `legacy_adapter`, never aliased into owner decoders |
//! | 4 | `LegacyDeliveryHandoff` | `InertHandoff` | names `B-RCTX/Host` (#612); fabricates no completion |
//! | 5 | `V1RowMigration` | `LegacyDTO` | inert v1 replay identity; byte-identical fields |
//! | 6 | `V1SnapshotMigration` | `LegacyDTO` | inert v1 replay identity; byte-identical fields |
//! | 7 | `FacadeError` | `FacadeSurface` | closed refusal vocabulary below |
//! | 8 | `FACADE_DISPOSITIONS` | `FacadeSurface` | this table, machine-checked by `tests/legacy_facade.rs` |
//! | 9 | `LEGACY_KIND_SPELLINGS` | `FacadeSurface` | frozen 10 `snake_case` spellings from the #706 denominator |
//! | 10 | `preserve_v1_row` | `AdapterEntry` | inert replay constructor |
//! | 11 | `preserve_v1_snapshot` | `AdapterEntry` | inert replay constructor |
//! | 12 | `decode_legacy_kind` | `AdapterEntry` | exact 10 frozen spellings; all else refused |
//! | 13 | `decode_legacy_mode` | `AdapterEntry` | exact 3 spellings; all else refused |
//! | 14 | `adapt_normalize` | `AdapterEntry` | one A-11 call + identity check |
//! | 15 | `adapt_bind` | `AdapterEntry` | one A-12 call + echo check |
//! | 16 | `adapt_rebuild_snapshot` | `AdapterEntry` | one A-13 call + digest check |
//! | 17 | `adapt_activate` | `AdapterEntry` | one A-14a call + result validation |
//! | 18 | `legacy_row_id_v2` | `AdapterEntry` | refuses stored legacy values until fresh owner input |
//! | 19 | `legacy_row_id_v2_from_fresh_observation` | `AdapterEntry` | frozen owner `cue_row_id` projection after fresh normalization |
//! | 20 | `preserve_v1_row_bytes` | `AdapterEntry` | exact v1 row bytes plus replay identity |
//! | 21 | `preserve_v1_snapshot_bytes` | `AdapterEntry` | exact v1 snapshot bytes plus row identities |
//! | 22 | `require_reobservation` | `AdapterEntry` | typed refusal with exact owner/revision pointer |
//! | 23 | `request_legacy_delivery` | `InertHandoff` | validates envelope, names handoff, no completion |
//!
//! Removed duplicates (compile-proof; see `tests/legacy_facade.rs`):
//! local `CueKind`/`MatchMode`/`CueStrength`, all `normalize_value*`
//! copies, `CueKey` constructors/comparison, `CueRecord` construction and
//! lifecycle/invalidation, `CueSnapshot` validation/migration/invalidation,
//! `CueRuntime` evaluation, `FiredCue`/`ActivationHit`/`ActivationTrace`/
//! `FiringResult` result shapes, `ActivationEdge`, `Freshness` checks,
//! `InvalidationCause`, `CueError`, `ObservedCue::normalize/source_value`.
//! Their behavior lives with the owners; owner crates carry their proofs.
//!
//! ## Sequencing (read-only)
//!
//! SHIM-SWEEP-SMART / CUEKIND-OWNER touch adjacent state: #833 (this facade
//! conversion), #835 (transitional `eliot-types` `CueKind` alias removal) +
//! #706 (migration denominator freeze) own alias deletion sequencing, #246
//! owns canonical spelling/keys/identity, #598 owns the A-11 normalizer,
//! #804 owns the A-10 vocabulary. Deletions here execute nothing pending
//! elsewhere; #706 baseline rows stay frozen for #835 reconciliation.

#![forbid(unsafe_code)]

pub mod legacy_adapter;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use eliot_cue_contracts::{CueKind, MatchMode};

/// Frozen legacy v1 kind spellings from the #706 denominator
/// (`crates/eliot-types/tests/data/cue_kind_migration.toml`, `snake_case`
/// wire, `deny_unknown_fields = false`, no aliases). The decoder accepts
/// exactly these ten; everything else is refused, never guessed.
pub const LEGACY_KIND_SPELLINGS: [&str; 10] = [
    "file_path",
    "dir_path",
    "symbol",
    "error_signature",
    "command_pattern",
    "dependency",
    "api_surface",
    "task_class",
    "subsystem",
    "concept",
];

/// One frozen legacy v1 cue envelope.
///
/// Identity is carried by the type name (`LegacyEliotCuesV1*`): the layout
/// keeps the exact v1 fields with no invented version markers, aliases, or
/// defaults. `kind` stays a string so unknown spellings reach the decoder
/// as refusal evidence instead of failing serde first.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacyEliotCuesV1Row {
    /// Scope the legacy row was observed in.
    pub scope: String,
    /// Legacy kind spelling (frozen `snake_case` vocabulary).
    pub kind: String,
    /// Legacy normalized value (retired folding policy; never owner input).
    pub value: String,
    /// Legacy match mode spelling, when recorded.
    pub mode: Option<String>,
    /// Legacy target handle.
    pub target: String,
    /// Legacy source revision.
    pub revision: u64,
}

impl LegacyEliotCuesV1Row {
    /// Validates envelope shape only: non-blank, control-free text.
    /// Vocabulary membership is decided by the decoder, not here.
    pub fn validate(&self) -> Result<(), FacadeError> {
        for (field, value) in [
            ("row.scope", &self.scope),
            ("row.kind", &self.kind),
            ("row.value", &self.value),
            ("row.target", &self.target),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(FacadeError::EnvelopeInvalid { field });
            }
        }
        if let Some(mode) = &self.mode
            && (mode.trim().is_empty() || mode.chars().any(char::is_control))
        {
            return Err(FacadeError::EnvelopeInvalid { field: "row.mode" });
        }
        Ok(())
    }
}

/// Inert legacy delivery handoff.
///
/// Names the exact `#612`/`B-RCTX`/Host handoff for a validated legacy
/// envelope. It carries no completion, receipt, or effect claim: delivery
/// planning and state belong to the owners, never to this facade.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LegacyDeliveryHandoff {
    /// Exact handoff owner.
    pub owner: &'static str,
    /// Owning delivery issue.
    pub issue: u64,
    /// Legacy target the handoff covers.
    pub target: String,
    /// Why this is a handoff and not a completion.
    pub reason: &'static str,
}

/// Replay-only v1 migration for one projection row.
///
/// Carries the preserved legacy identity and its explicit conversion
/// disposition. Never an admission and never a lifecycle, support,
/// applicability, accessibility, or influence claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct V1RowMigration {
    /// Legacy row identity kept byte-identical.
    pub legacy_row_id: String,
    /// Exact v1 row bytes retained for replay. Empty is reserved for the
    /// identity-only compatibility constructor; a byte-closed migration uses
    /// [`preserve_v1_row_bytes`].
    #[serde(default)]
    pub legacy_bytes: Vec<u8>,
    /// Explicit conversion disposition from the owner vocabulary.
    pub disposition: eliot_cue_contracts::ConversionDisposition,
}

/// Replay-only v1 migration for one snapshot.
///
/// Every row keeps its v1 bytes and identity; `ceiling` reports the migration
/// proof ceiling, which is a candidate artifact — not admission, publication,
/// or delivery.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct V1SnapshotMigration {
    /// Legacy snapshot identity, when the v1 envelope supplied one.
    #[serde(default)]
    pub legacy_snapshot_id: String,
    /// Exact v1 snapshot bytes retained for replay. Empty is reserved for
    /// the identity-only compatibility constructor.
    #[serde(default)]
    pub legacy_snapshot_bytes: Vec<u8>,
    /// One entry per preserved legacy row.
    pub rows: Vec<V1RowMigration>,
    /// Migration proof ceiling (candidate artifact only).
    pub ceiling: eliot_cue_contracts::ProofCeiling,
}

/// Refuses an identity-only legacy row migration.
///
/// A replay claim without the original bytes is not a closed migration. Use
/// [`preserve_v1_row_bytes`] with the exact v1 payload instead.
pub fn preserve_v1_row(legacy_row_id: &str) -> Result<V1RowMigration, FacadeError> {
    if legacy_row_id.trim().is_empty() || legacy_row_id.chars().any(char::is_control) {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_row_id",
        });
    }
    Err(FacadeError::MigrationRequired {
        owner: "legacy-v1-replay",
        revision: "raw-bytes-required",
    })
}

/// Preserves the exact v1 row bytes and identity for replay.
pub fn preserve_v1_row_bytes(
    legacy_row_id: &str,
    legacy_bytes: &[u8],
) -> Result<V1RowMigration, FacadeError> {
    if legacy_row_id.trim().is_empty() || legacy_row_id.chars().any(char::is_control) {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_row_id",
        });
    }
    if legacy_bytes.is_empty() {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_bytes",
        });
    }
    Ok(V1RowMigration {
        legacy_row_id: legacy_row_id.to_owned(),
        legacy_bytes: legacy_bytes.to_vec(),
        disposition: eliot_cue_contracts::ConversionDisposition::V1ReplayPreserved {
            legacy_row_id: legacy_row_id.to_owned(),
        },
    })
}

/// Refuses an identity-only legacy snapshot migration.
///
/// A replay claim without the original snapshot bytes is not closed. Use
/// [`preserve_v1_snapshot_bytes`] with the exact v1 payload instead.
pub fn preserve_v1_snapshot(row_ids: &[String]) -> Result<V1SnapshotMigration, FacadeError> {
    if row_ids
        .iter()
        .any(|row_id| row_id.trim().is_empty() || row_id.chars().any(char::is_control))
    {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_row_id",
        });
    }
    Err(FacadeError::MigrationRequired {
        owner: "legacy-v1-replay",
        revision: "raw-bytes-required",
    })
}

/// Preserves a v1 snapshot identity, exact bytes, and every row identity.
pub fn preserve_v1_snapshot_bytes(
    legacy_snapshot_id: &str,
    legacy_snapshot_bytes: &[u8],
    row_ids: &[String],
) -> Result<V1SnapshotMigration, FacadeError> {
    if legacy_snapshot_id.trim().is_empty() || legacy_snapshot_id.chars().any(char::is_control) {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_snapshot_id",
        });
    }
    if legacy_snapshot_bytes.is_empty() {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_snapshot_bytes",
        });
    }
    let mut rows = Vec::with_capacity(row_ids.len());
    for row_id in row_ids {
        if row_id.trim().is_empty() || row_id.chars().any(char::is_control) {
            return Err(FacadeError::EnvelopeInvalid {
                field: "legacy_row_id",
            });
        }
        rows.push(V1RowMigration {
            legacy_row_id: row_id.to_owned(),
            legacy_bytes: Vec::new(),
            disposition: eliot_cue_contracts::ConversionDisposition::V1ReplayPreserved {
                legacy_row_id: row_id.to_owned(),
            },
        });
    }
    Ok(V1SnapshotMigration {
        legacy_snapshot_id: legacy_snapshot_id.to_owned(),
        legacy_snapshot_bytes: legacy_snapshot_bytes.to_vec(),
        rows,
        ceiling: eliot_cue_contracts::ProofCeiling::CandidateArtifact,
    })
}

/// Closed refusal vocabulary for the facade.
///
/// Owner failures pass through untouched (transparent variants); every
/// facade-side refusal names its exact input or owner/revision pointer.
/// Ambiguous legacy material is refused here, never guessed into a
/// target, kind, or profile.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum FacadeError {
    /// A legacy kind spelling outside the frozen ten.
    #[error("unknown legacy cue kind spelling: {input}")]
    UnknownLegacyKind {
        /// Rejected input spelling.
        input: String,
    },
    /// A recognized non-canonical alias (CamelCase, SCREAMING, kebab,
    /// spaced). Aliases never decode: use the frozen `snake_case` spelling.
    #[error("legacy cue kind alias is not decodable, use the frozen snake_case spelling: {input}")]
    LegacyAliasRejected {
        /// Rejected alias spelling.
        input: String,
    },
    /// A legacy match-mode spelling outside exact/prefix/signature.
    #[error("unknown legacy match mode spelling: {input}")]
    UnknownLegacyMode {
        /// Rejected input spelling.
        input: String,
    },
    /// A legacy envelope field failed shape validation.
    #[error("legacy envelope field is blank or carries control characters: {field}")]
    EnvelopeInvalid {
        /// Stable field path, never caller payload.
        field: &'static str,
    },
    /// A decoded legacy kind disagrees with the owner input kind.
    #[error("legacy kind {legacy} disagrees with owner input kind {owner}")]
    KindMismatch {
        /// Decoded legacy kind.
        legacy: String,
        /// Owner input kind.
        owner: String,
    },
    /// Legacy envelope context (scope/value) disagrees with owner input.
    #[error("legacy envelope context disagrees with owner input at {field}")]
    ContextMismatch {
        /// Stable field path, never caller payload.
        field: &'static str,
    },
    /// An owner response does not echo the request identity.
    #[error("owner response identity check failed at {what}")]
    ResponseIdentityMismatch {
        /// Stable check name, never caller payload.
        what: &'static str,
    },
    /// The legacy row needs re-observation under an admitted owner path.
    #[error("legacy row requires re-observation under owner {owner} revision {revision}")]
    MigrationRequired {
        /// Exact target owner.
        owner: &'static str,
        /// Exact target revision.
        revision: &'static str,
    },
    /// A nested A-10 contract rejected the input or result.
    #[error(transparent)]
    Contract(#[from] eliot_cue_contracts::CueContractError),
    /// The A-11 normalizer rejected the input or result.
    #[error(transparent)]
    Normalization(#[from] eliot_cue_normalizer::NormalizationError),
    /// The A-12 binding cell rejected the input or result.
    #[error(transparent)]
    Binding(#[from] eliot_cue_binding::CueBindingError),
    /// The A-14a activation cell rejected the input or result.
    #[error(transparent)]
    Activation(#[from] eliot_cue_activation::ActivationError),
}

/// Every public facade item with its exact disposition.
///
/// `(item, disposition, owner-or-replacement)`; dispositions form a closed
/// set: `ReexportOwner`, `LegacyDTO`, `FacadeSurface`, `AdapterEntry`,
/// `InertHandoff`. `tests/legacy_facade.rs` enforces the exact row count
/// so additions stay deliberate, and the reexport rows resolve by type
/// identity, not prose.
pub const FACADE_DISPOSITIONS: [(&str, &str, &str); 23] = [
    ("CueKind", "ReexportOwner", "eliot-cue-contracts"),
    ("MatchMode", "ReexportOwner", "eliot-cue-contracts"),
    (
        "LegacyEliotCuesV1Row",
        "LegacyDTO",
        "frozen v1 envelope; decoded by legacy_adapter",
    ),
    (
        "LegacyDeliveryHandoff",
        "InertHandoff",
        "B-RCTX/Host (#612); no completion fabricated",
    ),
    (
        "V1RowMigration",
        "LegacyDTO",
        "v1 replay identity and raw-byte slot",
    ),
    (
        "V1SnapshotMigration",
        "LegacyDTO",
        "v1 replay identity and raw-byte slot",
    ),
    ("FacadeError", "FacadeSurface", "closed refusal vocabulary"),
    (
        "FACADE_DISPOSITIONS",
        "FacadeSurface",
        "this table, machine-checked",
    ),
    (
        "LEGACY_KIND_SPELLINGS",
        "FacadeSurface",
        "frozen 10 from the #706 denominator",
    ),
    (
        "preserve_v1_row",
        "AdapterEntry",
        "identity-only compatibility constructor",
    ),
    (
        "preserve_v1_snapshot",
        "AdapterEntry",
        "identity-only compatibility constructor",
    ),
    (
        "preserve_v1_row_bytes",
        "AdapterEntry",
        "exact v1 row bytes and identity",
    ),
    (
        "preserve_v1_snapshot_bytes",
        "AdapterEntry",
        "exact v1 snapshot bytes and row identities",
    ),
    (
        "decode_legacy_kind",
        "AdapterEntry",
        "exact frozen decoding",
    ),
    (
        "decode_legacy_mode",
        "AdapterEntry",
        "exact frozen decoding",
    ),
    ("adapt_normalize", "AdapterEntry", "one A-11 call"),
    ("adapt_bind", "AdapterEntry", "one A-12 call"),
    ("adapt_rebuild_snapshot", "AdapterEntry", "one A-13 call"),
    ("adapt_activate", "AdapterEntry", "one A-14a call"),
    (
        "legacy_row_id_v2",
        "AdapterEntry",
        "refuses stored legacy values",
    ),
    (
        "legacy_row_id_v2_from_fresh_observation",
        "AdapterEntry",
        "frozen owner cue_row_id after fresh normalization",
    ),
    (
        "require_reobservation",
        "AdapterEntry",
        "typed refusal pointer",
    ),
    (
        "request_legacy_delivery",
        "InertHandoff",
        "B-RCTX/Host (#612)",
    ),
];
