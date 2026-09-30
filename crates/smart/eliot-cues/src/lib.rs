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
//! | 7 | `V1PreservedRow` | `LegacyDTO` | exact v1 row bytes and identity input |
//! | 8 | `V1MigrationRejection` | `FacadeSurface` | closed typed conversion-refusal vocabulary |
//! | 9 | `FacadeError` | `FacadeSurface` | closed refusal vocabulary below |
//! | 10 | `FACADE_DISPOSITIONS` | `FacadeSurface` | this table, machine-checked by `tests/legacy_facade.rs` |
//! | 11 | `LEGACY_KIND_SPELLINGS` | `FacadeSurface` | frozen 10 `snake_case` spellings from the #706 denominator |
//! | 12 | `preserve_v1_row` | `AdapterEntry` | refuses identity-only migration |
//! | 13 | `preserve_v1_snapshot` | `AdapterEntry` | refuses identity-only migration |
//! | 14 | `preserve_v1_row_bytes` | `AdapterEntry` | exact v1 row bytes plus replay identity |
//! | 15 | `preserve_v1_snapshot_bytes` | `AdapterEntry` | refuses missing per-row bytes |
//! | 16 | `preserve_v1_snapshot_bytes_with_rows` | `AdapterEntry` | exact snapshot and per-row byte preservation |
//! | 17 | `preserve_v1_snapshot_conversion` | `AdapterEntry` | joins byte-preserved row dispositions |
//! | 18 | `reject_v1_row_conversion` | `AdapterEntry` | typed `V2Rejected` with raw bytes |
//! | 19 | `convert_v1_row` | `AdapterEntry` | fresh-observation-only v1-to-v2 conversion |
//! | 20 | `convert_v1_row_from_fresh_observation` | `AdapterEntry` | fresh owner observation and normalization conversion |
//! | 21 | `decode_legacy_kind` | `AdapterEntry` | exact 10 frozen spellings; all else refused |
//! | 22 | `decode_legacy_mode` | `AdapterEntry` | exact 3 spellings; all else refused |
//! | 23 | `adapt_normalize` | `AdapterEntry` | one A-11 call + identity check |
//! | 24 | `adapt_bind` | `AdapterEntry` | one A-12 call + echo check |
//! | 25 | `adapt_rebuild_snapshot` | `AdapterEntry` | one A-13 call + digest check |
//! | 26 | `adapt_activate` | `AdapterEntry` | one A-14a call + result validation |
//! | 27 | `legacy_row_id_v2` | `AdapterEntry` | refuses stored legacy values until fresh owner input |
//! | 28 | `legacy_row_id_v2_from_fresh_observation` | `AdapterEntry` | frozen owner `cue_row_id` projection after fresh normalization |
//! | 29 | `require_reobservation` | `AdapterEntry` | typed refusal with exact owner/revision pointer |
//! | 30 | `request_legacy_delivery` | `InertHandoff` | validates envelope, names handoff, no completion |
//!
//! `frozen_spellings_round_trip` was a 31st public item with an empty caller
//! set; it was removed in #1143 work item 4 because
//! `tests/legacy_facade.rs` case 26 already proves the same
//! table/decoder agreement over all ten frozen spellings.
//!
//! The legacy-text admissibility rule ("blank after trimming, or carries a
//! control character") was additionally written out at ten call sites across
//! this crate and `legacy_adapter`. #1143 work item 4 collapsed those copies
//! into the single crate-private owner [`is_blank_or_control`], so the rule
//! can no longer drift into disagreeing with itself. Each site keeps its own
//! stable `field` in [`FacadeError::EnvelopeInvalid`], so no refusal path
//! changed. This removed no public item and added none.
//!
//! The `legacy_row_id` refusal built on that rule was still written out five
//! more times, each copy pairing the admissibility check with the same stable
//! `field = "legacy_row_id"`. #1143 work item 4 collapsed those into the single
//! crate-private owner [`validate_legacy_row_id`], which reports that exact
//! field, so every site keeps the field path it already returned; a caller
//! holding a slice of ids reads the same rule through
//! [`validate_legacy_row_ids`]. This removed no public item and added none.
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
    /// Validates envelope shape only: non-blank, control-free text and a
    /// non-zero source revision. Vocabulary membership is decided by the
    /// decoder, not here.
    pub fn validate(&self) -> Result<(), FacadeError> {
        self.validate_shape(true)
    }

    /// Validates the replay envelope while retaining a zero revision as a
    /// semantic conversion refusal. A zero revision is not a usable v1
    /// envelope, but the migration boundary must preserve its bytes and emit a
    /// typed `V2Rejected` disposition instead of losing the supplied identity
    /// behind a structural error.
    pub(crate) fn validate_for_conversion(&self) -> Result<(), FacadeError> {
        self.validate_shape(false)
    }

    fn validate_shape(&self, require_revision: bool) -> Result<(), FacadeError> {
        for (field, value) in [
            ("row.scope", &self.scope),
            ("row.kind", &self.kind),
            ("row.value", &self.value),
            ("row.target", &self.target),
        ] {
            if is_blank_or_control(value) {
                return Err(FacadeError::EnvelopeInvalid { field });
            }
        }
        if let Some(mode) = &self.mode
            && is_blank_or_control(mode)
        {
            return Err(FacadeError::EnvelopeInvalid { field: "row.mode" });
        }
        if require_revision && self.revision == 0 {
            return Err(FacadeError::EnvelopeInvalid {
                field: "row.revision",
            });
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
    /// Exact v1 row bytes retained for replay.
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
    /// Legacy snapshot identity retained for replay.
    pub legacy_snapshot_id: String,
    /// Exact v1 snapshot bytes retained for replay.
    pub legacy_snapshot_bytes: Vec<u8>,
    /// One entry per preserved legacy row.
    pub rows: Vec<V1RowMigration>,
    /// Migration proof ceiling (candidate artifact only).
    pub ceiling: eliot_cue_contracts::ProofCeiling,
}

impl V1RowMigration {
    /// Validates that replay bytes and the disposition retain the same legacy
    /// identity. This never authenticates a v2 identity or grants semantics.
    pub fn validate(&self) -> Result<(), FacadeError> {
        validate_legacy_identity(&self.legacy_row_id)?;
        if self.legacy_bytes.is_empty() {
            return Err(FacadeError::EnvelopeInvalid {
                field: "legacy_bytes",
            });
        }
        let parsed = legacy_adapter::parse_bound_v1_row(&self.legacy_bytes, &self.legacy_row_id)?;
        parsed.validate_for_conversion()?;
        self.disposition.validate().map_err(FacadeError::Contract)?;
        if self.disposition.legacy_row_id() != self.legacy_row_id {
            return Err(FacadeError::ResponseIdentityMismatch {
                what: "migration.legacy_row_id",
            });
        }
        if let eliot_cue_contracts::ConversionDisposition::V2Rejected { reason, .. } =
            &self.disposition
            && V1MigrationRejection::from_reason(reason).is_none()
        {
            return Err(FacadeError::Contract(
                eliot_cue_contracts::CueContractError::Foundation {
                    field: "conversion.reason",
                },
            ));
        }
        Ok(())
    }
}

impl V1SnapshotMigration {
    /// Validates the complete snapshot envelope and every retained row.
    pub fn validate(&self) -> Result<(), FacadeError> {
        validate_legacy_identity(&self.legacy_snapshot_id)?;
        if self.legacy_snapshot_bytes.is_empty() {
            return Err(FacadeError::EnvelopeInvalid {
                field: "legacy_snapshot_bytes",
            });
        }
        if self.ceiling != eliot_cue_contracts::ProofCeiling::CandidateArtifact {
            return Err(FacadeError::EnvelopeInvalid { field: "ceiling" });
        }
        let parsed_ids = legacy_adapter::parse_bound_v1_snapshot(
            &self.legacy_snapshot_bytes,
            &self.legacy_snapshot_id,
        )?;
        let parsed = parsed_ids
            .into_iter()
            .collect::<std::collections::BTreeMap<_, _>>();
        let mut seen = std::collections::BTreeSet::new();
        for row in &self.rows {
            row.validate()?;
            let parsed_row =
                legacy_adapter::parse_bound_v1_row(&row.legacy_bytes, &row.legacy_row_id)?;
            if parsed.get(&row.legacy_row_id) != Some(&parsed_row) {
                return Err(FacadeError::ResponseIdentityMismatch {
                    what: "migration.snapshot.row_payload",
                });
            }
            if !seen.insert(row.legacy_row_id.clone()) {
                return Err(FacadeError::ResponseIdentityMismatch {
                    what: "migration.duplicate_legacy_row_id",
                });
            }
        }
        if parsed.len() != seen.len() || parsed.keys().any(|row_id| !seen.contains(row_id)) {
            return Err(FacadeError::ResponseIdentityMismatch {
                what: "migration.snapshot.row_set",
            });
        }
        Ok(())
    }
}

/// The single owner of the legacy-text admissibility rule.
///
/// "Blank after trimming, or carries a control character" was written out at
/// ten call sites across this crate and `legacy_adapter`. Each copy was a
/// second canonicalization rule that could drift into disagreeing with the
/// others, which is the duplication this issue removes. Every site now reads
/// the rule from here. The `field` each site reports stays a property of that
/// site, so no refusal path changes its stable field path, and this helper
/// never decides membership, a target, a kind or a profile.
pub(crate) fn is_blank_or_control(value: &str) -> bool {
    value.trim().is_empty() || value.chars().any(char::is_control)
}

/// The single owner of the legacy row-id admissibility refusal.
///
/// "Not admissible as legacy text, therefore refuse the row id" was written
/// out at five call sites across this crate and `legacy_adapter`, each copy
/// pairing [`is_blank_or_control`] with the same stable
/// `FacadeError::EnvelopeInvalid { field: "legacy_row_id" }`. Each pair was a
/// second row-id validation rule that could drift into refusing a different
/// input, or into reporting a different field for the same input, and that
/// field is wire-visible. Every site now reads the rule from here and returns
/// the exact field it returned before.
///
/// This stays separate from [`validate_legacy_identity`] on purpose: that
/// owner names its own input as `legacy_identity`, so merging the two would
/// move a field path a caller reads. [`validate_legacy_row_ids`] is the same
/// rule over a slice of ids, and the refusal stays one field for the whole
/// slice because each caller already reported exactly that.
pub(crate) fn validate_legacy_row_id(legacy_row_id: &str) -> Result<(), FacadeError> {
    if is_blank_or_control(legacy_row_id) {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_row_id",
        });
    }
    Ok(())
}

/// The single owner of the legacy row-id admissibility refusal over a slice.
///
/// "At least one id in this set is inadmissible, therefore refuse the set" was
/// written out twice in this crate, once per snapshot entry point. The per-id
/// rule is [`validate_legacy_row_id`]'s, and the reported field stays
/// `legacy_row_id` for every id, which is what both sites already returned.
fn validate_legacy_row_ids(row_ids: &[String]) -> Result<(), FacadeError> {
    for row_id in row_ids {
        validate_legacy_row_id(row_id)?;
    }
    Ok(())
}

fn validate_legacy_identity(value: &str) -> Result<(), FacadeError> {
    if is_blank_or_control(value) {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_identity",
        });
    }
    Ok(())
}

/// One exact legacy row input for a byte-preserving snapshot conversion.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct V1PreservedRow {
    /// Legacy row identity, retained without rewriting.
    pub legacy_row_id: String,
    /// Exact bytes as received from the v1 owner.
    pub legacy_bytes: Vec<u8>,
}

impl V1PreservedRow {
    /// Constructs one immutable legacy row input.
    pub fn new(
        legacy_row_id: impl Into<String>,
        legacy_bytes: impl Into<Vec<u8>>,
    ) -> Result<Self, FacadeError> {
        let value = Self {
            legacy_row_id: legacy_row_id.into(),
            legacy_bytes: legacy_bytes.into(),
        };
        validate_legacy_identity(&value.legacy_row_id)?;
        if value.legacy_bytes.is_empty() {
            return Err(FacadeError::EnvelopeInvalid {
                field: "legacy_bytes",
            });
        }
        legacy_adapter::parse_bound_v1_row(&value.legacy_bytes, &value.legacy_row_id)?;
        Ok(value)
    }
}

/// Closed reasons for refusing a v1-to-v2 identity conversion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum V1MigrationRejection {
    /// No fresh owner observation was supplied.
    MissingFreshObservation,
    /// The supplied observation did not belong to the legacy row.
    FreshObservationMismatch,
    /// The fresh normalized result did not produce the requested key.
    MissingNormalizedKey,
    /// The legacy row is not in the frozen v1 vocabulary.
    UnsupportedLegacyIdentity,
}

impl V1MigrationRejection {
    /// Stable bounded reason emitted in a rejection disposition.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingFreshObservation => "missing_fresh_observation",
            Self::FreshObservationMismatch => "fresh_observation_mismatch",
            Self::MissingNormalizedKey => "missing_normalized_key",
            Self::UnsupportedLegacyIdentity => "unsupported_legacy_identity",
        }
    }

    /// Parses only the closed rejection vocabulary retained by this facade.
    #[must_use]
    pub fn from_reason(value: &str) -> Option<Self> {
        match value {
            "missing_fresh_observation" => Some(Self::MissingFreshObservation),
            "fresh_observation_mismatch" => Some(Self::FreshObservationMismatch),
            "missing_normalized_key" => Some(Self::MissingNormalizedKey),
            "unsupported_legacy_identity" => Some(Self::UnsupportedLegacyIdentity),
            _ => None,
        }
    }
}

/// Refuses an identity-only legacy row migration.
///
/// A replay claim without the original bytes is not a closed migration. Use
/// [`preserve_v1_row_bytes`] with the exact v1 payload instead.
pub fn preserve_v1_row(legacy_row_id: &str) -> Result<V1RowMigration, FacadeError> {
    validate_legacy_row_id(legacy_row_id)?;
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
    validate_legacy_row_id(legacy_row_id)?;
    if legacy_bytes.is_empty() {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_bytes",
        });
    }
    let record = V1RowMigration {
        legacy_row_id: legacy_row_id.to_owned(),
        legacy_bytes: legacy_bytes.to_vec(),
        disposition: eliot_cue_contracts::ConversionDisposition::V1ReplayPreserved {
            legacy_row_id: legacy_row_id.to_owned(),
        },
    };
    record.validate()?;
    Ok(record)
}

/// Refuses an identity-only legacy snapshot migration.
///
/// A replay claim without the original snapshot bytes is not closed. Use
/// [`preserve_v1_snapshot_bytes`] with the exact v1 payload instead.
pub fn preserve_v1_snapshot(row_ids: &[String]) -> Result<V1SnapshotMigration, FacadeError> {
    validate_legacy_row_ids(row_ids)?;
    Err(FacadeError::MigrationRequired {
        owner: "legacy-v1-replay",
        revision: "raw-bytes-required",
    })
}

/// Refuses a snapshot migration that has no exact per-row bytes.
///
/// Snapshot-wide bytes alone cannot prove that each retained row identity is
/// paired with its original row payload. Call
/// [`preserve_v1_snapshot_bytes_with_rows`] with one byte-closed row input for
/// every legacy row.
pub fn preserve_v1_snapshot_bytes(
    legacy_snapshot_id: &str,
    legacy_snapshot_bytes: &[u8],
    row_ids: &[String],
) -> Result<V1SnapshotMigration, FacadeError> {
    validate_legacy_identity(legacy_snapshot_id)?;
    if legacy_snapshot_bytes.is_empty() {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_snapshot_bytes",
        });
    }
    validate_legacy_row_ids(row_ids)?;
    Err(FacadeError::MigrationRequired {
        owner: "legacy-v1-replay",
        revision: "row-bytes-required",
    })
}

/// Preserves exact snapshot bytes and exact bytes for every legacy row.
pub fn preserve_v1_snapshot_bytes_with_rows(
    legacy_snapshot_id: &str,
    legacy_snapshot_bytes: &[u8],
    rows: &[V1PreservedRow],
) -> Result<V1SnapshotMigration, FacadeError> {
    validate_legacy_identity(legacy_snapshot_id)?;
    if legacy_snapshot_bytes.is_empty() {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_snapshot_bytes",
        });
    }
    let mut retained = Vec::with_capacity(rows.len());
    let mut seen = std::collections::BTreeSet::new();
    for row in rows {
        let record = preserve_v1_row_bytes(&row.legacy_row_id, &row.legacy_bytes)?;
        if !seen.insert(record.legacy_row_id.clone()) {
            return Err(FacadeError::ResponseIdentityMismatch {
                what: "migration.duplicate_legacy_row_id",
            });
        }
        retained.push(record);
    }
    let snapshot = V1SnapshotMigration {
        legacy_snapshot_id: legacy_snapshot_id.to_owned(),
        legacy_snapshot_bytes: legacy_snapshot_bytes.to_vec(),
        rows: retained,
        ceiling: eliot_cue_contracts::ProofCeiling::CandidateArtifact,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

/// Joins already-validated row conversion records to one exact snapshot
/// envelope. The rows may be replayed, converted, or explicitly rejected;
/// every row still carries its original bytes and identity.
pub fn preserve_v1_snapshot_conversion(
    legacy_snapshot_id: &str,
    legacy_snapshot_bytes: &[u8],
    rows: &[V1RowMigration],
) -> Result<V1SnapshotMigration, FacadeError> {
    let snapshot = V1SnapshotMigration {
        legacy_snapshot_id: legacy_snapshot_id.to_owned(),
        legacy_snapshot_bytes: legacy_snapshot_bytes.to_vec(),
        rows: rows.to_vec(),
        ceiling: eliot_cue_contracts::ProofCeiling::CandidateArtifact,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

/// The single owner of the v1 row-payload identity binding.
///
/// The retained-bytes/row binding — parse the supplied bytes against the
/// supplied row id and refuse when the parsed row is not byte-equal to the row
/// the caller passed in — was written out twice in this crate, in the same
/// order, once in [`reject_v1_row_conversion`] and once in
/// [`convert_v1_row`](legacy_adapter::convert_v1_row). Two copies of one
/// identity rule are two owners that can drift into accepting different bytes.
/// Both now read this one owner.
///
/// Order is preserved exactly: the payload is bound before the legacy identity
/// is validated, so the first refusal a caller sees is unchanged, and the
/// single stable pointer [`FacadeError::ResponseIdentityMismatch`] with
/// `what = "migration.row_payload"` is the one every caller already receives.
/// The two different field paths that follow the binding
/// (`legacy_identity` vs `legacy_row_id`) deliberately stay at their own call
/// sites, because each names its own input.
pub(crate) fn bind_v1_row_payload(
    legacy_row_id: &str,
    row: &LegacyEliotCuesV1Row,
    legacy_bytes: &[u8],
) -> Result<(), FacadeError> {
    let parsed = legacy_adapter::parse_bound_v1_row(legacy_bytes, legacy_row_id)?;
    if &parsed != row {
        return Err(FacadeError::ResponseIdentityMismatch {
            what: "migration.row_payload",
        });
    }
    Ok(())
}

/// Records a precise v1-to-v2 rejection while retaining the original row
/// bytes and identity. The result is candidate-only and never an admission.
pub fn reject_v1_row_conversion(
    legacy_row_id: &str,
    row: &LegacyEliotCuesV1Row,
    legacy_bytes: &[u8],
    reason: V1MigrationRejection,
) -> Result<V1RowMigration, FacadeError> {
    row.validate_for_conversion()?;
    bind_v1_row_payload(legacy_row_id, row, legacy_bytes)?;
    validate_legacy_identity(legacy_row_id)?;
    if legacy_bytes.is_empty() {
        return Err(FacadeError::EnvelopeInvalid {
            field: "legacy_bytes",
        });
    }
    let record = V1RowMigration {
        legacy_row_id: legacy_row_id.to_owned(),
        legacy_bytes: legacy_bytes.to_vec(),
        disposition: eliot_cue_contracts::ConversionDisposition::V2Rejected {
            legacy_row_id: legacy_row_id.to_owned(),
            reason: reason.as_str().to_owned(),
        },
    };
    record.validate()?;
    Ok(record)
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
    /// Preserved v1 bytes were not a parseable, identity-bound envelope.
    #[error("legacy bytes are not a complete identity-bound v1 envelope: {field}")]
    LegacyBytesInvalid {
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
    /// A legacy index row carries the negative-memory marker, whose blocking
    /// semantics this facade does not own and cannot represent.
    ///
    /// The v1 envelope has no field for the marker, so accepting the row
    /// would discard a blocking rule and present it as an ordinary positive
    /// cue. It is refused instead, and the negative-memory owner
    /// (`eliot-governor`) remains the only place that rule can be resolved.
    #[error("legacy index row carries a negative-memory rule owned by eliot-governor")]
    NegativeMemoryRuleRefused,
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
pub const FACADE_DISPOSITIONS: [(&str, &str, &str); 30] = [
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
    (
        "V1PreservedRow",
        "LegacyDTO",
        "exact v1 row bytes and identity input",
    ),
    (
        "V1MigrationRejection",
        "FacadeSurface",
        "closed typed conversion-refusal vocabulary",
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
        "refuses identity-only migration",
    ),
    (
        "preserve_v1_snapshot",
        "AdapterEntry",
        "refuses identity-only migration",
    ),
    (
        "preserve_v1_row_bytes",
        "AdapterEntry",
        "exact v1 row bytes and identity",
    ),
    (
        "preserve_v1_snapshot_bytes",
        "AdapterEntry",
        "refuses missing per-row bytes",
    ),
    (
        "preserve_v1_snapshot_bytes_with_rows",
        "AdapterEntry",
        "exact snapshot and per-row byte preservation",
    ),
    (
        "preserve_v1_snapshot_conversion",
        "AdapterEntry",
        "joins byte-preserved row dispositions",
    ),
    (
        "reject_v1_row_conversion",
        "AdapterEntry",
        "typed V2Rejected disposition with raw bytes",
    ),
    (
        "convert_v1_row",
        "AdapterEntry",
        "fresh-observation-only v1-to-v2 conversion",
    ),
    (
        "convert_v1_row_from_fresh_observation",
        "AdapterEntry",
        "fresh owner observation and normalization conversion",
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
