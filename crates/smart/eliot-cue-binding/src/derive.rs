//! Deterministic candidate derivation and explicit cold handling.
use std::collections::{BTreeMap, BTreeSet};
use std::io::{self, Write};

use eliot_change_monitor::{Attribution, ChangeKind};
use eliot_contracts::{canonical_json_bytes, sha256_hex};
use eliot_cue_contracts::{
    BindingCandidateId, BindingDisposition, BindingRole, CueBindingCandidate, CueKind, Digest,
};
use eliot_evidence::{Assertability, EpistemicStatus, EvidenceFreshness};
use eliot_observation::ObservationAdmissionReceipt;
use serde::Serialize;

use crate::{
    BindingProfile, ColdBinding, ColdReason, CueBindingError, CueBindingResult, ExpectedReuseHint,
    MAX_INLINE_CANDIDATES, OmittedBindingIdentity, TouchedResourceProjection, bounds,
};

#[derive(Serialize)]
struct CandidatePreimage<'a> {
    domain: &'static str,
    canonical: &'a eliot_cue_contracts::CanonicalCueIdentity,
    target: &'a str,
    revision: &'a str,
    normalization_input: &'a Digest,
    normalization_result: &'a Digest,
    admission_request: &'a str,
    admission_record: &'a str,
    admission_operation: &'a str,
    change_id: &'a str,
    change_digest: &'a str,
    state_fence: &'a eliot_contracts::StateFence,
    profile: &'a BindingProfile,
    rule_ref: &'a str,
}

#[derive(Serialize)]
struct ResultPreimage<'a> {
    domain: &'static str,
    schema_revision: &'a str,
    admission: &'a ObservationAdmissionReceipt,
    profile: &'a BindingProfile,
    touched: &'a [TouchedResourceProjection],
    candidates: &'a [CueBindingCandidate],
    cold: &'a [ColdBinding],
    omitted: &'a [OmittedBindingIdentity],
    hint: Option<&'a ExpectedReuseHint>,
    input_digest: &'a Digest,
    continuation_digest: &'a Option<Digest>,
    state_fence: &'a eliot_contracts::StateFence,
    outcome: crate::BindingOutcome,
}

#[derive(Serialize)]
struct ContinuationPreimage<'a> {
    domain: &'static str,
    input_digest: &'a Digest,
    omitted: &'a [OmittedBindingIdentity],
}

#[derive(Serialize)]
struct InputPreimage<'a> {
    domain: &'static str,
    admission: &'a ObservationAdmissionReceipt,
    profile: &'a BindingProfile,
    touched: &'a [TouchedResourceProjection],
    hint: Option<&'a ExpectedReuseHint>,
}

struct DerivedCandidate {
    candidate: CueBindingCandidate,
    revision: Option<String>,
}

fn digest<T: Serialize>(value: &T, field: &'static str) -> Result<Digest, CueBindingError> {
    bounded_serialized_len(value, field)?;
    let bytes =
        canonical_json_bytes(value).map_err(|_| CueBindingError::Canonicalization { field })?;
    if bytes.len() > bounds::MAX_OUTPUT_BYTES {
        return Err(CueBindingError::Bound { field });
    }
    Digest::new(sha256_hex(&bytes)).map_err(|_| CueBindingError::Canonicalization { field })
}

struct CountingWriter {
    len: usize,
    limit: usize,
}

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.len = self
            .len
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("serialized input overflow"))?;
        if self.len > self.limit {
            return Err(io::Error::other("serialized input bound"));
        }
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn bounded_serialized_len<T: Serialize>(
    value: &T,
    field: &'static str,
) -> Result<usize, CueBindingError> {
    let mut writer = CountingWriter {
        len: 0,
        limit: bounds::MAX_OUTPUT_BYTES,
    };
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| CueBindingError::Canonicalization { field })?;
    Ok(writer.len)
}

fn cold(row: &TouchedResourceProjection, reason: ColdReason) -> ColdBinding {
    let revision = row
        .change
        .observation
        .after
        .as_ref()
        .map(|r| r.revision.clone());
    ColdBinding {
        target: row.target.clone(),
        revision,
        observed_cue_id: row
            .normalization
            .normalized
            .observed
            .observed_cue_id
            .as_str()
            .to_owned(),
        change_id: row.change.observation.change_id.clone(),
        reason,
    }
}

fn exact_rule(
    profile: &BindingProfile,
    kind: CueKind,
    change: ChangeKind,
) -> Option<&crate::BindingRule> {
    profile.rules.iter().find(|rule| {
        rule.cue_kind == kind && rule.change_kind == change && rule.role == BindingRole::Touched
    })
}

fn validate_rules(profile: &BindingProfile) -> Result<(), CueBindingError> {
    let mut seen = BTreeSet::new();
    for rule in &profile.rules {
        let key = (rule.cue_kind, rule.change_kind, rule.resource_field);
        if !seen.insert(key) {
            return Err(CueBindingError::IdentityConflict {
                field: "profile.rules",
            });
        }
        if !matches!(
            (rule.cue_kind, rule.resource_field),
            (
                CueKind::FilePath | CueKind::DirPath,
                crate::ResourceField::Path
            ) | (CueKind::Symbol, crate::ResourceField::Symbol)
        ) {
            return Err(CueBindingError::UnsupportedKind {
                field: "profile.rule",
            });
        }
    }
    Ok(())
}

fn validate_row_links(
    receipt: &ObservationAdmissionReceipt,
    row: &TouchedResourceProjection,
) -> Result<EvidenceFreshness, ColdReason> {
    let event = receipt
        .record
        .event
        .as_ref()
        .ok_or(ColdReason::MissingEvidence)?;
    let observation = &row.change.observation;
    let after = observation
        .after
        .as_ref()
        .ok_or(ColdReason::MissingEvidence)?;
    if observation.state_fence != receipt.state_fence {
        return Err(ColdReason::IdentityConflict);
    }
    if observation.unknown_origin
        || observation.origin == eliot_change_monitor::ChangeOrigin::Unknown
    {
        return Err(ColdReason::UnknownOrigin);
    }
    if !matches!(
        observation.attribution,
        Attribution::Exact | Attribution::ReceiptLinked
    ) {
        return Err(ColdReason::MissingEvidence);
    }
    let origin = observation
        .origin_ref
        .as_deref()
        .ok_or(ColdReason::MissingEvidence)?;
    if !event.evidence_and_raw_handles.iter().any(|h| h == origin) {
        return Err(ColdReason::MissingEvidence);
    }
    let raw = row
        .normalization
        .normalized
        .observed
        .source
        .provenance
        .raw_handle
        .as_deref()
        .ok_or(ColdReason::MissingEvidence)?;
    if !event.evidence_and_raw_handles.iter().any(|h| h == raw) || raw != origin {
        return Err(ColdReason::IdentityConflict);
    }
    let event_task = event.affected_scope.task_ref.as_deref();
    let cue_task = row
        .normalization
        .normalized
        .observed
        .context
        .task_id
        .as_str();
    if event_task != Some(cue_task) {
        return Err(ColdReason::IdentityConflict);
    }
    if row.normalization.normalized.observed.context.state_fence != receipt.state_fence {
        return Err(ColdReason::IdentityConflict);
    }
    if row.normalization.policy.state_fence != receipt.state_fence {
        return Err(ColdReason::IdentityConflict);
    }
    if row.normalization.normalized.observed.source.target != row.target {
        return Err(ColdReason::IdentityConflict);
    }
    if row.target.as_str() != after.resource_ref {
        return Err(ColdReason::IdentityConflict);
    }
    if row
        .normalization
        .normalized
        .observed
        .source
        .provenance
        .revision
        .as_deref()
        != Some(after.revision.as_str())
    {
        return Err(ColdReason::MissingEvidence);
    }
    if after.content_digest.as_deref()
        != Some(row.normalization.normalized.observed.source.digest.as_str())
    {
        return Err(ColdReason::MissingEvidence);
    }
    if observation
        .digest()
        .map_err(|_| ColdReason::IdentityConflict)?
        != row.change.observation_digest
    {
        return Err(ColdReason::IdentityConflict);
    }
    source_freshness(row)
}

fn source_freshness(row: &TouchedResourceProjection) -> Result<EvidenceFreshness, ColdReason> {
    let context = &row.normalization.normalized.observed.context;
    let evidence = &context.evidence;
    if !row
        .normalization
        .normalized
        .observed
        .context
        .lifecycle
        .is_active()
        || matches!(
            evidence.status,
            EpistemicStatus::Contested
                | EpistemicStatus::Stale
                | EpistemicStatus::Superseded
                | EpistemicStatus::Rejected
        )
        || evidence.assertability == Assertability::AbstainOrFence
        || matches!(
            evidence.freshness,
            EvidenceFreshness::KnownOlderSnapshot
                | EvidenceFreshness::Stale
                | EvidenceFreshness::Unknown
        )
    {
        return Err(ColdReason::MissingEvidence);
    }
    Ok(evidence.freshness)
}

fn preflight(
    admission: &ObservationAdmissionReceipt,
    touched: &[TouchedResourceProjection],
    hint: Option<&ExpectedReuseHint>,
    profile: &BindingProfile,
) -> Result<(usize, Vec<TouchedResourceProjection>), CueBindingError> {
    let mut total = 0;
    bounds::admission_into(admission, &mut total)?;
    bounds::profile_into(profile, &mut total)?;
    validate_rules(profile)?;
    let expected = crate::contracts::profile_digest(profile)
        .map_err(|_| CueBindingError::Canonicalization { field: "profile" })?;
    if expected != profile.profile_digest {
        return Err(CueBindingError::IdentityConflict {
            field: "profile.profile_digest",
        });
    }
    bounds::hint(hint, &mut total)?;
    if touched.len() > bounds::MAX_INPUT_ROWS {
        return Err(CueBindingError::Bound { field: "touched" });
    }
    admission
        .validate()
        .map_err(|_| CueBindingError::Contract { field: "admission" })?;
    if profile.state_fence != admission.state_fence {
        return Err(CueBindingError::IdentityConflict {
            field: "profile.state_fence",
        });
    }
    if let Some(event) = admission.record.event.as_ref()
        && profile.scope_id.as_str() != event.affected_scope.work_scope.as_str()
    {
        return Err(CueBindingError::IdentityConflict {
            field: "profile.scope_id",
        });
    }
    validate_rows(touched, profile, &mut total)?;
    bounded_serialized_len(
        &InputPreimage {
            domain: "eliot.a12.cue-binding.input.v1",
            admission,
            profile,
            touched,
            hint,
        },
        "input",
    )?;
    let mut ordered = touched.to_vec();
    ordered.sort_by(|a, b| {
        a.target
            .as_str()
            .cmp(b.target.as_str())
            .then_with(|| {
                a.change
                    .observation
                    .change_id
                    .cmp(&b.change.observation.change_id)
            })
            .then_with(|| {
                a.normalization
                    .normalized
                    .observed
                    .observed_cue_id
                    .as_str()
                    .cmp(b.normalization.normalized.observed.observed_cue_id.as_str())
            })
    });
    Ok((total, ordered))
}

fn validate_rows(
    touched: &[TouchedResourceProjection],
    profile: &BindingProfile,
    total: &mut usize,
) -> Result<(), CueBindingError> {
    let mut seen = BTreeSet::new();
    let mut change_digests = BTreeMap::new();
    let mut cue_digests = BTreeMap::new();
    for row in touched {
        bounds::row(row, total)?;
        row.change
            .observation
            .validate()
            .map_err(|_| CueBindingError::Contract {
                field: "change.observation",
            })?;
        row.normalization
            .validate()
            .map_err(|_| CueBindingError::Contract {
                field: "normalization",
            })?;
        let p = &row.normalization.policy.profile;
        if p != &profile.expected_normalization_profile
            || row.normalization.policy.scope_id != profile.scope_id
            || row.normalization.policy.state_fence != profile.state_fence
        {
            return Err(CueBindingError::IdentityConflict {
                field: "profile.binding",
            });
        }
        let identity = (
            row.target.as_str().to_owned(),
            row.change.observation.change_id.clone(),
            row.normalization
                .normalized
                .observed
                .observed_cue_id
                .as_str()
                .to_owned(),
        );
        if !seen.insert(identity) {
            return Err(CueBindingError::IdentityConflict {
                field: "touched.projection",
            });
        }
        let change_id = row.change.observation.change_id.as_str();
        if let Some(previous) =
            change_digests.insert(change_id.to_owned(), row.change.observation_digest.clone())
            && previous != row.change.observation_digest
        {
            return Err(CueBindingError::IdentityConflict {
                field: "change.observation_digest",
            });
        }
        let cue_id = row
            .normalization
            .normalized
            .observed
            .observed_cue_id
            .as_str();
        if let Some(previous) =
            cue_digests.insert(cue_id.to_owned(), row.normalization.input_digest.clone())
            && previous != row.normalization.input_digest
        {
            return Err(CueBindingError::IdentityConflict {
                field: "normalization.input_digest",
            });
        }
    }
    Ok(())
}

fn derive_one(
    admission: &ObservationAdmissionReceipt,
    row: &TouchedResourceProjection,
    profile: &BindingProfile,
    task_bound: bool,
) -> Result<Result<CueBindingCandidate, ColdReason>, CueBindingError> {
    let normalized = &row.normalization.normalized;
    let Some(rule) = exact_rule(
        profile,
        normalized.observed.kind,
        row.change.observation.kind,
    ) else {
        return Ok(Err(
            if bounds::cue_kind_supported(normalized.observed.kind) {
                ColdReason::MissingEvidence
            } else {
                ColdReason::UnsupportedKind
            },
        ));
    };
    if !task_bound {
        return Ok(Err(ColdReason::MissingEvidence));
    }
    let freshness = match validate_row_links(admission, row) {
        Ok(value) => value,
        Err(reason) => return Ok(Err(reason)),
    };
    let Some(after) = row.change.observation.after.as_ref() else {
        return Ok(Err(ColdReason::MissingEvidence));
    };
    let Some(expected) = (match rule.resource_field {
        crate::ResourceField::Path => after.path.as_deref(),
        crate::ResourceField::Symbol => after.symbol.as_deref(),
    }) else {
        return Ok(Err(ColdReason::MissingEvidence));
    };
    let Some(canonical) = normalized.canonical.as_ref() else {
        return Ok(Err(ColdReason::MissingEvidence));
    };
    if canonical.canonical_value != expected {
        return Ok(Err(ColdReason::IdentityConflict));
    }
    let change_digest = Digest::new(row.change.observation_digest.clone()).map_err(|_| {
        CueBindingError::Contract {
            field: "change.observation_digest",
        }
    })?;
    let candidate_digest = digest(
        &CandidatePreimage {
            domain: "eliot.a12.cue-binding.candidate.v1",
            canonical,
            target: row.target.as_str(),
            revision: &after.revision,
            normalization_input: &row.normalization.input_digest,
            normalization_result: &row.normalization.result_digest,
            admission_request: &admission.request_digest,
            admission_record: &admission.record_id,
            admission_operation: &admission.operation_id,
            change_id: &row.change.observation.change_id,
            change_digest: change_digest.as_str(),
            state_fence: &admission.state_fence,
            profile,
            rule_ref: &rule.rule_ref,
        },
        "candidate",
    )?;
    let id =
        BindingCandidateId::new(format!("a12:{}", candidate_digest.as_str())).map_err(|_| {
            CueBindingError::Contract {
                field: "candidate.id",
            }
        })?;
    let candidate = CueBindingCandidate::new(
        id,
        canonical.clone(),
        row.target.clone(),
        BindingRole::Touched,
        freshness,
        BindingDisposition::Withheld,
        candidate_digest,
    );
    candidate
        .validate()
        .map_err(|_| CueBindingError::Contract { field: "candidate" })?;
    Ok(Ok(candidate))
}

fn retain_unproved_hint(
    hint: Option<&ExpectedReuseHint>,
    event: Option<&eliot_observation::ObservationEventCore>,
    rows: &[TouchedResourceProjection],
    cold_rows: &mut Vec<ColdBinding>,
) {
    let Some(hint) = hint else { return };
    let target_present = rows.iter().any(|row| row.target == hint.target);
    let proven = target_present
        && event.is_some_and(|value| {
            value
                .evidence_and_raw_handles
                .iter()
                .any(|handle| handle == &hint.evidence_ref)
        });
    if !proven {
        cold_rows.push(ColdBinding {
            target: hint.target.clone(),
            revision: None,
            observed_cue_id: String::new(),
            change_id: String::new(),
            reason: ColdReason::HintUnproved,
        });
    }
}

fn assemble_result(
    admission: &ObservationAdmissionReceipt,
    profile: &BindingProfile,
    ordered_touched: Vec<TouchedResourceProjection>,
    hint: Option<&ExpectedReuseHint>,
    mut cold_rows: Vec<ColdBinding>,
    mut candidates: Vec<DerivedCandidate>,
) -> Result<CueBindingResult, CueBindingError> {
    cold_rows.sort_by(|a, b| {
        a.target
            .as_str()
            .cmp(b.target.as_str())
            .then_with(|| a.change_id.cmp(&b.change_id))
            .then_with(|| a.observed_cue_id.cmp(&b.observed_cue_id))
    });
    candidates.sort_by(|a, b| {
        a.candidate
            .target
            .as_str()
            .cmp(b.candidate.target.as_str())
            .then_with(|| a.candidate.digest.as_str().cmp(b.candidate.digest.as_str()))
    });
    let mut omitted = Vec::new();
    if candidates.len() > MAX_INLINE_CANDIDATES {
        for derived in candidates.drain(MAX_INLINE_CANDIDATES..) {
            omitted.push(OmittedBindingIdentity {
                target: derived.candidate.target,
                revision: derived.revision,
                candidate_digest: Some(derived.candidate.digest),
            });
        }
    }
    let candidates: Vec<CueBindingCandidate> = candidates
        .into_iter()
        .map(|derived| derived.candidate)
        .collect();
    let result_hint = hint.cloned();
    let (continuation_digest, outcome, result_digest) = result_digests(
        admission,
        profile,
        &ordered_touched,
        &candidates,
        &cold_rows,
        &omitted,
        result_hint.as_ref(),
    )?;
    let result = CueBindingResult {
        schema_revision: "1.0.0".to_owned(),
        admission: admission.clone(),
        profile: profile.clone(),
        touched: ordered_touched,
        candidates,
        cold: cold_rows,
        omitted,
        continuation_digest,
        hint: result_hint,
        state_fence: admission.state_fence.clone(),
        outcome,
        result_digest,
    };
    bounded_serialized_len(&result, "result")?;
    Ok(result)
}

fn result_digests(
    admission: &ObservationAdmissionReceipt,
    profile: &BindingProfile,
    touched: &[TouchedResourceProjection],
    candidates: &[CueBindingCandidate],
    cold_rows: &[ColdBinding],
    omitted: &[OmittedBindingIdentity],
    hint: Option<&ExpectedReuseHint>,
) -> Result<(Option<Digest>, crate::BindingOutcome, Digest), CueBindingError> {
    let input_digest = digest(
        &InputPreimage {
            domain: "eliot.a12.cue-binding.input.v1",
            admission,
            profile,
            touched,
            hint,
        },
        "input",
    )?;
    let continuation_digest = if omitted.is_empty() {
        None
    } else {
        Some(digest(
            &ContinuationPreimage {
                domain: "eliot.a12.cue-binding.continuation.v1",
                input_digest: &input_digest,
                omitted,
            },
            "continuation",
        )?)
    };
    let schema_revision = "1.0.0".to_owned();
    let outcome = if !omitted.is_empty() {
        crate::BindingOutcome::PartialOverflow
    } else if candidates.is_empty() {
        crate::BindingOutcome::Cold
    } else {
        crate::BindingOutcome::CandidatesForSuppliedInputs
    };
    let result_digest = digest(
        &ResultPreimage {
            domain: "eliot.a12.cue-binding.result.v1",
            schema_revision: &schema_revision,
            admission,
            profile,
            touched,
            candidates,
            cold: cold_rows,
            omitted,
            hint,
            input_digest: &input_digest,
            continuation_digest: &continuation_digest,
            state_fence: &admission.state_fence,
            outcome,
        },
        "result",
    )?;
    Ok((continuation_digest, outcome, result_digest))
}

/// Derives inert A-10 candidates from a complete admitted observation and a supplied touched denominator.
pub fn derive_cue_binding_candidates(
    admission: &ObservationAdmissionReceipt,
    touched: &[TouchedResourceProjection],
    hint: Option<&ExpectedReuseHint>,
    profile: &BindingProfile,
) -> Result<CueBindingResult, CueBindingError> {
    let (_, ordered_touched) = preflight(admission, touched, hint, profile)?;
    let event = admission.record.event.as_ref();
    let task_bound =
        admission.candidate_disposition == eliot_observation::CandidateDisposition::TaskBound;
    let mut cold_rows = Vec::new();
    let mut candidates = Vec::<DerivedCandidate>::new();
    for row in &ordered_touched {
        match derive_one(admission, row, profile, task_bound)? {
            Ok(candidate) => candidates.push(DerivedCandidate {
                revision: row
                    .change
                    .observation
                    .after
                    .as_ref()
                    .map(|after| after.revision.clone()),
                candidate,
            }),
            Err(reason) => cold_rows.push(cold(row, reason)),
        }
    }
    retain_unproved_hint(hint, event, &ordered_touched, &mut cold_rows);
    assemble_result(
        admission,
        profile,
        ordered_touched,
        hint,
        cold_rows,
        candidates,
    )
}
