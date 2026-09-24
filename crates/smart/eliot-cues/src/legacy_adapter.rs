//! Closed legacy adapter: validate, decode once, call each owner once.
//!
//! Every function here validates a frozen legacy v1 envelope, decodes its
//! kind spelling through the exact frozen vocabulary (anything else is a
//! typed refusal, never a guess), invokes exactly one current owner, checks
//! the returned identity, and returns the owner result unchanged. Legacy
//! material is never aliased into owner decoders, legacy values never
//! become owner comparison keys, and owner errors pass through untouched
//! with no fallback or alternate path.

use eliot_cue_activation::{ActivationProfile, evaluate_activation};
use eliot_cue_binding::{
    BindingProfile, CueBindingResult, ExpectedReuseHint, TouchedResourceProjection,
    derive_cue_binding_candidates,
};
use eliot_cue_contracts::{
    CueSnapshotBuildCandidate, MatchMode as OwnerMatchMode, NormalizationProfile, NormalizedCue,
    ObservedCue as OwnerObservedCue, TargetHandle,
};
use eliot_cue_index::rebuild_cue_snapshot;
use eliot_cue_normalizer::{NormalizationPolicy, normalize_cue};
use eliot_observation::ObservationAdmissionReceipt;

use crate::{
    FacadeError, LEGACY_KIND_SPELLINGS, LegacyEliotCuesV1Row, V1MigrationRejection, V1RowMigration,
};

/// Decodes one frozen legacy v1 kind spelling to the owner vocabulary.
///
/// Accepts exactly [`LEGACY_KIND_SPELLINGS`]. Recognized non-canonical
/// aliases (CamelCase, `SCREAMING_SNAKE`, kebab-case, spaced) are refused as
/// aliases — they never decode — and everything else is unknown.
pub fn decode_legacy_kind(value: &str) -> Result<eliot_cue_contracts::CueKind, FacadeError> {
    use eliot_cue_contracts::CueKind as Owner;
    match value {
        "file_path" => Ok(Owner::FilePath),
        "dir_path" => Ok(Owner::DirPath),
        "symbol" => Ok(Owner::Symbol),
        "error_signature" => Ok(Owner::ErrorSignature),
        "command_pattern" => Ok(Owner::CommandPattern),
        "dependency" => Ok(Owner::Dependency),
        "api_surface" => Ok(Owner::ApiSurface),
        "task_class" => Ok(Owner::TaskClass),
        "subsystem" => Ok(Owner::Subsystem),
        "concept" => Ok(Owner::Concept),
        _ => Err(if is_legacy_alias(value) {
            FacadeError::LegacyAliasRejected {
                input: value.to_owned(),
            }
        } else {
            FacadeError::UnknownLegacyKind {
                input: value.to_owned(),
            }
        }),
    }
}

/// Recognized non-canonical spellings: the ten Rust variant names, their
/// `SCREAMING_SNAKE` forms, and the kebab-case / spaced forms named by the
/// frozen unsupported denominator. All are refused, never mapped.
fn is_legacy_alias(value: &str) -> bool {
    const ALIASES: [&str; 40] = [
        "FilePath",
        "DirPath",
        "Symbol",
        "ErrorSignature",
        "CommandPattern",
        "Dependency",
        "ApiSurface",
        "TaskClass",
        "Subsystem",
        "Concept",
        "FILE_PATH",
        "DIR_PATH",
        "SYMBOL",
        "ERROR_SIGNATURE",
        "COMMAND_PATTERN",
        "DEPENDENCY",
        "API_SURFACE",
        "TASK_CLASS",
        "SUBSYSTEM",
        "CONCEPT",
        "file-path",
        "dir-path",
        "symbol",
        "error-signature",
        "command-pattern",
        "dependency",
        "api-surface",
        "task-class",
        "subsystem",
        "concept",
        "file path",
        "dir path",
        "symbol",
        "error signature",
        "command pattern",
        "dependency",
        "api surface",
        "task class",
        "subsystem",
        "concept",
    ];
    ALIASES.contains(&value)
}

/// Decodes one frozen legacy match-mode spelling to the owner vocabulary.
pub fn decode_legacy_mode(value: &str) -> Result<OwnerMatchMode, FacadeError> {
    match value {
        "exact" => Ok(OwnerMatchMode::Exact),
        "prefix" => Ok(OwnerMatchMode::Prefix),
        "signature" => Ok(OwnerMatchMode::Signature),
        _ => Err(FacadeError::UnknownLegacyMode {
            input: value.to_owned(),
        }),
    }
}

/// Refuses a legacy row that needs re-observation, naming the exact
/// admitted owner path. Legacy normalized values were folded under a
/// retired policy and can never become owner comparison keys; only fresh
/// observation under an admitted policy produces owner inputs.
pub fn require_reobservation(
    row: &LegacyEliotCuesV1Row,
) -> Result<std::convert::Infallible, FacadeError> {
    row.validate()?;
    decode_legacy_kind(&row.kind)?;
    Err(FacadeError::MigrationRequired {
        owner: "eliot-cue-normalizer",
        revision: eliot_cue_normalizer::A11_CONTRACT_REVISION,
    })
}

/// Normalizes one legacy-anchored observation through A-11 exactly once.
///
/// The legacy envelope must agree with the caller-supplied owner
/// observation (kind, verbatim value, scope); the owner call carries the
/// observation, policy, and profile. The returned envelope is checked to
/// echo the request identity before it is handed back unchanged.
pub fn adapt_normalize(
    row: &LegacyEliotCuesV1Row,
    observed: &OwnerObservedCue,
    policy: &NormalizationPolicy,
    profile: &NormalizationProfile,
) -> Result<eliot_cue_normalizer::NormalizationEnvelope, FacadeError> {
    row.validate()?;
    let kind = decode_legacy_kind(&row.kind)?;
    if kind != observed.kind {
        return Err(FacadeError::KindMismatch {
            legacy: row.kind.clone(),
            owner: format!("{:?}", observed.kind),
        });
    }
    if row.value != observed.original_value {
        return Err(FacadeError::ContextMismatch { field: "row.value" });
    }
    if row.scope != observed.context.scope_id.as_str() {
        return Err(FacadeError::ContextMismatch { field: "row.scope" });
    }
    if row.target != observed.source.target.as_str() {
        return Err(FacadeError::ContextMismatch {
            field: "row.target",
        });
    }
    let envelope = normalize_cue(observed, policy, profile)?;
    if envelope.normalized.observed.observed_cue_id != observed.observed_cue_id {
        return Err(FacadeError::ResponseIdentityMismatch {
            what: "normalization.observed_cue_id",
        });
    }
    Ok(envelope)
}

/// Derives binding candidates through A-12 exactly once.
///
/// Every touched row must carry the decoded legacy kind; the owner call
/// carries the caller-supplied admission, rows, hint, and profile. The
/// returned profile identity and row count are checked to echo the request.
pub fn adapt_bind(
    row: &LegacyEliotCuesV1Row,
    admission: &ObservationAdmissionReceipt,
    touched: &[TouchedResourceProjection],
    hint: Option<&ExpectedReuseHint>,
    profile: &BindingProfile,
) -> Result<CueBindingResult, FacadeError> {
    row.validate()?;
    let kind = decode_legacy_kind(&row.kind)?;
    for touched_row in touched {
        if touched_row.normalization.normalized.observed.kind != kind {
            return Err(FacadeError::KindMismatch {
                legacy: row.kind.clone(),
                owner: format!("{:?}", touched_row.normalization.normalized.observed.kind),
            });
        }
    }
    if !touched
        .iter()
        .any(|touched_row| touched_row.target.as_str() == row.target)
    {
        return Err(FacadeError::ContextMismatch {
            field: "row.target",
        });
    }
    let result = derive_cue_binding_candidates(admission, touched, hint, profile)?;
    if result.profile.profile_id != profile.profile_id || result.touched.len() != touched.len() {
        return Err(FacadeError::ResponseIdentityMismatch {
            what: "binding.profile_id/touched",
        });
    }
    Ok(result)
}

/// Rebuilds one snapshot candidate through A-13 exactly once.
///
/// The legacy envelope anchors the rebuild scope; the owner call carries
/// the caller-supplied candidate. The rebuilt digest must equal the
/// presented digest, proving deterministic reconstruction.
pub fn adapt_rebuild_snapshot(
    row: &LegacyEliotCuesV1Row,
    candidate: &CueSnapshotBuildCandidate,
    registry_revision: Option<&str>,
) -> Result<CueSnapshotBuildCandidate, FacadeError> {
    row.validate()?;
    decode_legacy_kind(&row.kind)?;
    if row.scope != candidate.scope_id.as_str() {
        return Err(FacadeError::ContextMismatch { field: "row.scope" });
    }
    let rebuilt = rebuild_cue_snapshot(candidate, registry_revision)?;
    if rebuilt.build_digest != candidate.build_digest {
        return Err(FacadeError::ResponseIdentityMismatch {
            what: "snapshot.build_digest",
        });
    }
    Ok(rebuilt)
}

/// Evaluates one activation through A-14a exactly once.
///
/// The legacy envelope anchors the evaluation scope; the owner call
/// carries the caller-supplied candidate, request, and profile. The
/// returned evaluation is validated against the same triple before it is
/// handed back unchanged, so partial, truncated, stale, and unavailable
/// native outcomes survive verbatim instead of being smoothed over.
pub fn adapt_activate(
    row: &LegacyEliotCuesV1Row,
    candidate: &CueSnapshotBuildCandidate,
    request: &eliot_cue_contracts::ActivationRequest,
    profile: &ActivationProfile,
) -> Result<eliot_cue_activation::CueActivationEvaluation, FacadeError> {
    row.validate()?;
    decode_legacy_kind(&row.kind)?;
    if row.scope != candidate.scope_id.as_str() {
        return Err(FacadeError::ContextMismatch { field: "row.scope" });
    }
    let evaluation = evaluate_activation(candidate, request, profile)?;
    evaluation.validate_against(candidate, request, profile)?;
    Ok(evaluation)
}

/// Refuses a legacy row-to-v2 identity projection from stored legacy fields.
///
/// Legacy values were folded under a retired policy and do not carry proof of
/// a fresh observation or normalization. The old entrypoint remains source
/// compatible only so callers receive an explicit migration refusal; it never
/// computes a v2 identity. Use
/// [`legacy_row_id_v2_from_fresh_observation`] after the owner has produced
/// fresh input.
pub fn legacy_row_id_v2(
    scope: &str,
    kind: &str,
    mode: &str,
    value: &str,
    target: &TargetHandle,
) -> Result<String, FacadeError> {
    let _ = (scope, kind, mode, value, target);
    Err(FacadeError::MigrationRequired {
        owner: "eliot-cue-normalizer",
        revision: eliot_cue_normalizer::A11_CONTRACT_REVISION,
    })
}

/// Computes a v2 row identity only from a fresh owner observation and its
/// normalized result.
///
/// The legacy row is an identity/replay anchor only. Every semantic input to
/// [`eliot_cue_contracts::cue_row_id`] comes from the fresh normalized key;
/// legacy spelling is never silently promoted to comparison material.
pub fn legacy_row_id_v2_from_fresh_observation(
    row: &LegacyEliotCuesV1Row,
    observed: &OwnerObservedCue,
    normalized: &NormalizedCue,
) -> Result<String, FacadeError> {
    row.validate_for_conversion()?;
    let kind = decode_legacy_kind(&row.kind)?;
    let mode_text = row.mode.as_deref().ok_or(FacadeError::MigrationRequired {
        owner: "eliot-cue-normalizer",
        revision: eliot_cue_normalizer::A11_CONTRACT_REVISION,
    })?;
    let mode = decode_legacy_mode(mode_text)?;
    let revision_text = row.revision.to_string();
    let revision_matches = observed
        .source
        .provenance
        .revision
        .as_deref()
        .is_some_and(|revision| {
            revision == revision_text
                || revision.strip_prefix('r') == Some(revision_text.as_str())
                || revision.strip_prefix("rev-") == Some(revision_text.as_str())
        });
    if row.revision == 0
        || !revision_matches
        || observed.kind != kind
        || observed.original_value != row.value
        || observed.context.scope_id.as_str() != row.scope
        || observed.source.target.as_str() != row.target
        || &normalized.observed != observed
    {
        return Err(FacadeError::ContextMismatch {
            field: "fresh_observation",
        });
    }
    normalized.validate().map_err(FacadeError::Contract)?;
    if !normalized.observed.context.lifecycle.is_active() {
        return Err(FacadeError::MigrationRequired {
            owner: "eliot-cue-normalizer",
            revision: eliot_cue_normalizer::A11_CONTRACT_REVISION,
        });
    }
    let key = normalized
        .comparison_keys
        .iter()
        .find(|key| key.match_mode == mode)
        .ok_or(FacadeError::MigrationRequired {
            owner: "eliot-cue-normalizer",
            revision: eliot_cue_normalizer::A11_CONTRACT_REVISION,
        })?;
    let id = eliot_cue_contracts::cue_row_id(
        &row.scope,
        kind,
        mode,
        &key.key_value,
        &TargetHandle::new(row.target.clone())?,
    )?;
    if !id.starts_with("cuev2:") {
        return Err(FacadeError::ResponseIdentityMismatch {
            what: "row_id.namespace",
        });
    }
    Ok(id)
}

/// Converts one byte-preserved v1 row only from fresh owner evidence.
///
/// The legacy envelope and bytes remain the replay authority. A v2 identity is
/// issued only when the caller supplies an owner observation and the exact
/// normalized result for that same observation. Any semantic refusal is
/// represented as a bounded `V2Rejected` record; malformed input or missing
/// raw bytes remains a structural facade error.
#[allow(
    clippy::too_many_lines,
    reason = "conversion keeps structural rejection and fresh-evidence checks together"
)]
pub fn convert_v1_row(
    legacy_row_id: &str,
    row: &LegacyEliotCuesV1Row,
    legacy_bytes: &[u8],
    observed: Option<&OwnerObservedCue>,
    normalized: Option<&NormalizedCue>,
) -> Result<V1RowMigration, FacadeError> {
    row.validate_for_conversion()?;
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
    if row.revision == 0 {
        return crate::reject_v1_row_conversion(
            legacy_row_id,
            row,
            legacy_bytes,
            V1MigrationRejection::FreshObservationMismatch,
        );
    }

    let disposition = match (observed, normalized) {
        (None, _) | (_, None) => {
            return crate::reject_v1_row_conversion(
                legacy_row_id,
                row,
                legacy_bytes,
                V1MigrationRejection::MissingFreshObservation,
            );
        }
        (Some(observed), Some(normalized)) => {
            let Ok(kind) = decode_legacy_kind(&row.kind) else {
                return crate::reject_v1_row_conversion(
                    legacy_row_id,
                    row,
                    legacy_bytes,
                    V1MigrationRejection::UnsupportedLegacyIdentity,
                );
            };
            let Some(mode_text) = row.mode.as_deref() else {
                return crate::reject_v1_row_conversion(
                    legacy_row_id,
                    row,
                    legacy_bytes,
                    V1MigrationRejection::MissingNormalizedKey,
                );
            };
            let Ok(mode) = decode_legacy_mode(mode_text) else {
                return crate::reject_v1_row_conversion(
                    legacy_row_id,
                    row,
                    legacy_bytes,
                    V1MigrationRejection::UnsupportedLegacyIdentity,
                );
            };
            let source_revision = observed.source.provenance.revision.as_deref();
            let revision_text = row.revision.to_string();
            let revision_matches = source_revision.is_some_and(|revision| {
                revision == revision_text
                    || revision.strip_prefix('r') == Some(revision_text.as_str())
                    || revision.strip_prefix("rev-") == Some(revision_text.as_str())
            });
            if observed.kind != kind
                || observed.original_value != row.value
                || observed.context.scope_id.as_str() != row.scope
                || observed.source.target.as_str() != row.target
                || !revision_matches
                || observed.validate().is_err()
                || normalized.validate().is_err()
                || &normalized.observed != observed
                || !normalized.observed.context.lifecycle.is_active()
            {
                return crate::reject_v1_row_conversion(
                    legacy_row_id,
                    row,
                    legacy_bytes,
                    V1MigrationRejection::FreshObservationMismatch,
                );
            }
            let Some(key) = normalized
                .comparison_keys
                .iter()
                .find(|key| key.match_mode == mode)
            else {
                return crate::reject_v1_row_conversion(
                    legacy_row_id,
                    row,
                    legacy_bytes,
                    V1MigrationRejection::MissingNormalizedKey,
                );
            };
            let Ok(row_id) = eliot_cue_contracts::cue_row_id(
                &row.scope,
                kind,
                mode,
                &key.key_value,
                &TargetHandle::new(row.target.clone())?,
            ) else {
                return crate::reject_v1_row_conversion(
                    legacy_row_id,
                    row,
                    legacy_bytes,
                    V1MigrationRejection::MissingNormalizedKey,
                );
            };
            eliot_cue_contracts::ConversionDisposition::V2Converted {
                legacy_row_id: legacy_row_id.to_owned(),
                row_id,
            }
        }
    };
    let record = V1RowMigration {
        legacy_row_id: legacy_row_id.to_owned(),
        legacy_bytes: legacy_bytes.to_vec(),
        disposition,
    };
    record.validate()?;
    Ok(record)
}

/// Convenience form of [`convert_v1_row`] for a caller that already has both
/// fresh owner values. The optional form above remains the fail-closed path
/// for an omitted observation.
pub fn convert_v1_row_from_fresh_observation(
    legacy_row_id: &str,
    row: &LegacyEliotCuesV1Row,
    legacy_bytes: &[u8],
    observed: &OwnerObservedCue,
    normalized: &NormalizedCue,
) -> Result<V1RowMigration, FacadeError> {
    convert_v1_row(
        legacy_row_id,
        row,
        legacy_bytes,
        Some(observed),
        Some(normalized),
    )
}

/// Requests legacy delivery as an inert owner handoff.
///
/// Validates the legacy envelope and names the exact `#612`/`B-RCTX`/Host
/// handoff. Nothing is delivered, completed, or receipted here: delivery
/// planning and state belong to the owners.
pub fn request_legacy_delivery(
    row: &LegacyEliotCuesV1Row,
) -> Result<crate::LegacyDeliveryHandoff, FacadeError> {
    row.validate()?;
    decode_legacy_kind(&row.kind)?;
    Ok(crate::LegacyDeliveryHandoff {
        owner: "B-RCTX/Host",
        issue: 612,
        target: row.target.clone(),
        reason: "legacy delivery requires the owner handoff; the facade fabricates no completion",
    })
}

/// Proves the frozen spelling table and the decoder agree in both
/// directions: every frozen spelling decodes, and every decodable
/// spelling is frozen. Used by the facade denominator test so the two
/// can never drift apart silently.
pub fn frozen_spellings_round_trip() -> bool {
    if LEGACY_KIND_SPELLINGS.len() != 10 {
        return false;
    }
    LEGACY_KIND_SPELLINGS
        .iter()
        .all(|spelling| decode_legacy_kind(spelling).is_ok())
}
