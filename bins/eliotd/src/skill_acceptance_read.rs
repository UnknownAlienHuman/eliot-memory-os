//! Canonical procedure-acceptance lookup over committed lifecycle-policy records.
//!
//! The persistent owner of Skill procedure acceptance is the canonical store
//! itself: every governed promotion commits an `ApplyLifecyclePolicy` record
//! carrying the exact six lifecycle parameters (`action`,
//! `base_view_digest`, `candidate_digest`, `candidate_package_digest`,
//! `skill_id`, `verifier_ref`), and the store serves those rows back through
//! the closed `GetCapabilityEvidenceState` read filtered by exact `skill_id`
//! (see `operation_catalogue` and the store adapter read boundary). No
//! candidate bytes, registry projection, or local snapshot can mint one of
//! these rows: rows exist only for canonically committed promotions.
//!
//! The poller dispatch resolves every Hotset intake against these rows
//! before the composition path runs:
//!
//! ```text
//! latest row for the skill, by commit order, binds the presented digest
//!   action in {keep, patch, split, merge, restore} ΓåÆ Accepted
//!   action in {suppress, archive, quarantine}      ΓåÆ Revoked
//! latest row binds another digest, or no row binds the digest
//!                                                  ΓåÆ Unknown (provisional only)
//!   truncated history                              ΓåÆ Unresolvable (refuse)
//! ```
//!
//! Supersession emerges from the same ordering: once a newer row commits for
//! the skill -- accepting or revoking a different package digest -- the older
//! digest no longer holds the current owner position, so it resolves Unknown
//! even when an older row accepted it. An explicit suppress/archive/quarantine
//! row revokes only the digest it binds. Unknown digests never bind material
//! as accepted: absence of a row proves nothing, and a superseded digest
//! proves only that the owner moved on. I7.25 keeps every such intake a
//! reversible candidate until governed promotion commits a row for it.
//!
//! Reads run under `ExactFence` against the caller-observed admitted fence;
//! the response operation, fence, scope, skill, and payload version are
//! re-verified here, mirroring the capability-evidence bridge. Record-level
//! fences are not served by this read: currency also rests on the
//! candidate's owner-issued acceptance receipt matching the admitted fence,
//! enforced at the drive boundary.

use eliot_contracts::StateFence;
use eliot_store_api::{
    EVIDENCE_PACK_MAX_RECORDS, NamedReadOperation, NamedReadRequest, NamedReadResponse,
    ReadConsistency, ScopeId,
};
use thiserror::Error;

/// Scope carrying skill lifecycle-policy authority rows.
///
/// Matches the scope the Governor lifecycle owner stamps on its canonical
/// envelopes: a read under any other scope finds no rows and resolves
/// Unknown, never acceptance.
const LIFECYCLE_SCOPE: &str = "governor";
/// Capability-evidence payload version served by the store adapter.
const CAPABILITY_EVIDENCE_VERSION: u64 = 1;

/// Committed actions confirming the package digest.
const ACCEPT_ACTIONS: [&str; 5] = ["keep", "patch", "split", "merge", "restore"];
/// Committed actions revoking the package digest.
const REVOKE_ACTIONS: [&str; 3] = ["suppress", "archive", "quarantine"];

/// Fail-closed errors for the canonical acceptance lookup.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum AcceptanceReadError {
    /// The skill identity is blank or carries control characters.
    #[error("acceptance lookup skill identity must be non-blank with no control characters")]
    BlankSkill,
    /// The store request is structurally invalid.
    #[error("acceptance lookup read request is invalid: {0}")]
    Request(String),
    /// The store response answers a different operation, fence, scope, or
    /// skill than the planned read.
    #[error("acceptance lookup response does not answer the planned read: {0}")]
    ResponseMismatch(&'static str),
    /// The store payload is not the versioned capability-evidence shape, or
    /// a lifecycle row fails its closed shape.
    #[error("acceptance lookup payload is not the versioned shape: {0}")]
    Payload(&'static str),
    /// The authenticated Kernel route failed before any record resolved.
    #[error("acceptance lookup transport failed: {0}")]
    Transport(String),
}

/// One resolved canonical acceptance decision for a package digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcceptanceRecord {
    /// Skill the rows were selected for.
    pub skill_id: String,
    /// Package source digest the rows bind.
    pub package_digest: String,
    /// Commit order of the deciding row (revision currency).
    pub revision: u64,
    /// Lifecycle action of the deciding row.
    pub action: String,
    /// Verifier bound by the deciding row.
    pub verifier_ref: String,
    /// Candidate digest bound by the deciding row.
    pub candidate_digest: String,
}

/// Canonical acceptance verdict for one presented package digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AcceptanceVerdict {
    /// A committed promotion confirms the digest at the recorded revision.
    Accepted(AcceptanceRecord),
    /// A committed revocation holds the digest at the recorded revision.
    Revoked(AcceptanceRecord),
    /// No committed row binds the digest: provisional policy only, never
    /// acceptance.
    Unknown,
}

/// Plans the closed canonical acceptance read for one skill.
///
/// The request carries the exact `skill_id` + `max_records` selectors the
/// store catalogue declares for `GetCapabilityEvidenceState`, under the
/// lifecycle scope and `ExactFence` fence. It executes through the
/// authenticated Kernel route; the caller enforces the response binding in
/// [`resolve_acceptance`].
pub fn plan_acceptance_read(
    skill_id: &str,
    fence: StateFence,
) -> Result<NamedReadRequest, AcceptanceReadError> {
    if skill_id.trim().is_empty() || skill_id.chars().any(char::is_control) {
        return Err(AcceptanceReadError::BlankSkill);
    }
    let scope = ScopeId::new(LIFECYCLE_SCOPE)
        .map_err(|error| AcceptanceReadError::Request(error.to_string()))?;
    let mut parameters = std::collections::BTreeMap::new();
    parameters.insert(
        "skill_id".to_owned(),
        serde_json::Value::String(skill_id.to_owned()),
    );
    parameters.insert(
        "max_records".to_owned(),
        serde_json::Value::String(EVIDENCE_PACK_MAX_RECORDS.to_string()),
    );
    let request = NamedReadRequest {
        operation: NamedReadOperation::GetCapabilityEvidenceState,
        scope_id: Some(scope),
        consistency: ReadConsistency::ExactFence,
        state_fence: fence,
        parameters,
    };
    request
        .validate()
        .map_err(|error| AcceptanceReadError::Request(error.to_string()))?;
    Ok(request)
}

/// Resolves one presented package digest against the canonical committed
/// lifecycle-policy rows over the authenticated Kernel route.
///
/// Plans the closed read under the caller-observed admitted fence, executes
/// it through the Kernel client, and resolves the verdict. Transport,
/// contract, fence, operation, shape, and truncation failures refuse as
/// errors: the caller settles the pair without installing. Absence of rows
/// resolves Unknown (provisional policy only); only committed rows decide
/// acceptance or revocation.
pub async fn resolve_intake_acceptance(
    kernel: &super::daemon_kernel_client::DaemonKernelClient,
    admitted_fence: &StateFence,
    skill_id: &str,
    package_digest: &str,
) -> Result<AcceptanceVerdict, AcceptanceReadError> {
    let request = plan_acceptance_read(skill_id, admitted_fence.clone())?;
    let response = kernel
        .store_named_async(request.clone())
        .await
        .map_err(|error| AcceptanceReadError::Transport(error.to_string()))?;
    resolve_acceptance(&request, &response, package_digest)
}

/// Latest committed rows for one skill: the overall owner position plus the
/// presented-digest position, each as commit order with its deciding fields.
type LatestSkillRows = (Option<(u64, String)>, Option<(u64, String, String, String)>);

/// Scans served lifecycle-policy rows for one skill and returns the latest
/// committed row overall plus the latest row binding the presented digest.
///
/// Both positions advance by commit order (`capture_index`); served order
/// breaks ties. Every row must carry the exact six lifecycle parameters  -- 
/// a row missing its base view, or naming another skill, fails closed
/// rather than deciding currency on a partial claim.
fn latest_skill_rows(
    records: &[serde_json::Value],
    planned_skill: &str,
    package_digest: &str,
) -> Result<LatestSkillRows, AcceptanceReadError> {
    let mut latest_overall: Option<(u64, String)> = None;
    let mut latest_match: Option<(u64, String, String, String)> = None;
    for record in records {
        if record.get("operation").and_then(serde_json::Value::as_str)
            != Some("ApplyLifecyclePolicy")
        {
            return Err(AcceptanceReadError::Payload("operation"));
        }
        let parameters = record
            .get("parameters")
            .and_then(serde_json::Value::as_object)
            .ok_or(AcceptanceReadError::Payload("parameters"))?;
        let text = |name: &str| {
            parameters
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or(AcceptanceReadError::Payload("parameters"))
        };
        if text("skill_id")? != planned_skill {
            return Err(AcceptanceReadError::Payload("skill"));
        }
        // The committed row carries the exact six lifecycle parameters; a
        // row missing its base view cannot prove the promotion it claims.
        text("base_view_digest")?;
        let row_digest = text("candidate_package_digest")?.to_owned();
        let revision = record
            .get("capture_index")
            .and_then(serde_json::Value::as_u64)
            .ok_or(AcceptanceReadError::Payload("capture_index"))?;
        if latest_overall
            .as_ref()
            .is_none_or(|current| revision > current.0)
        {
            latest_overall = Some((revision, row_digest.clone()));
        }
        if row_digest != package_digest {
            continue;
        }
        let action = text("action")?.to_owned();
        let verifier_ref = text("verifier_ref")?.to_owned();
        let candidate_digest = text("candidate_digest")?.to_owned();
        if latest_match
            .as_ref()
            .is_none_or(|current| revision > current.0)
        {
            latest_match = Some((revision, action, verifier_ref, candidate_digest));
        }
    }
    Ok((latest_overall, latest_match))
}

/// Resolves the canonical acceptance verdict for one package digest.
///
/// Validates operation, fence, scope, skill, and payload-version identity
/// against the planned read, then takes the latest committed row (by commit
/// order) for the skill. Only the digest bound by that latest row can decide
/// Accepted or Revoked: a newer row binding a different package digest
/// supersedes the presented one, resolving Unknown even when an older row
/// accepted it. Absence of any row for the digest resolves Unknown as well  -- 
/// never acceptance. A truncated history cannot prove currency and fails
/// closed: the error refuses the drive rather than installing on a possibly
/// revoked digest.
pub fn resolve_acceptance(
    request: &NamedReadRequest,
    response: &NamedReadResponse,
    package_digest: &str,
) -> Result<AcceptanceVerdict, AcceptanceReadError> {
    if response.operation != NamedReadOperation::GetCapabilityEvidenceState
        || response.operation != request.operation
    {
        return Err(AcceptanceReadError::ResponseMismatch("operation"));
    }
    if response.state_fence != request.state_fence {
        return Err(AcceptanceReadError::ResponseMismatch("fence"));
    }
    response
        .validate()
        .map_err(|_| AcceptanceReadError::ResponseMismatch("shape"))?;
    let payload = &response.payload;
    if payload.get("version").and_then(serde_json::Value::as_u64)
        != Some(CAPABILITY_EVIDENCE_VERSION)
    {
        return Err(AcceptanceReadError::Payload("version"));
    }
    let planned_skill = request
        .parameters
        .get("skill_id")
        .and_then(serde_json::Value::as_str)
        .ok_or(AcceptanceReadError::Payload("skill"))?;
    if payload.get("skill_id").and_then(serde_json::Value::as_str) != Some(planned_skill) {
        return Err(AcceptanceReadError::Payload("skill"));
    }
    let planned_scope = request
        .scope_id
        .clone()
        .ok_or(AcceptanceReadError::Payload("scope"))?;
    let planned_scope_value =
        serde_json::to_value(&planned_scope).map_err(|_| AcceptanceReadError::Payload("scope"))?;
    if payload.get("scope_id") != Some(&planned_scope_value) {
        return Err(AcceptanceReadError::Payload("scope"));
    }
    let provenance = payload
        .get("provenance")
        .ok_or(AcceptanceReadError::Payload("provenance"))?;
    if provenance
        .get("truncated")
        .and_then(serde_json::Value::as_bool)
        != Some(false)
    {
        return Err(AcceptanceReadError::Payload("truncated"));
    }
    let records = payload
        .get("records")
        .and_then(serde_json::Value::as_array)
        .ok_or(AcceptanceReadError::Payload("records"))?;
    let (latest_overall, latest_match) = latest_skill_rows(records, planned_skill, package_digest)?;
    // Currency first: a newer committed row for another digest supersedes the
    // presented one -- the owner moved on, so the older acceptance no longer
    // decides. Absence of any row resolves Unknown the same way.
    match latest_overall {
        Some((_, current_digest)) if current_digest == package_digest => {}
        _ => return Ok(AcceptanceVerdict::Unknown),
    }
    let Some((revision, action, verifier_ref, candidate_digest)) = latest_match else {
        return Ok(AcceptanceVerdict::Unknown);
    };
    let record = AcceptanceRecord {
        skill_id: planned_skill.to_owned(),
        package_digest: package_digest.to_owned(),
        revision,
        action: action.clone(),
        verifier_ref,
        candidate_digest,
    };
    if ACCEPT_ACTIONS.contains(&action.as_str()) {
        Ok(AcceptanceVerdict::Accepted(record))
    } else if REVOKE_ACTIONS.contains(&action.as_str()) {
        Ok(AcceptanceVerdict::Revoked(record))
    } else {
        Err(AcceptanceReadError::Payload("action"))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn fence() -> StateFence {
        use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
        use std::num::NonZeroU64;
        let lineage =
            EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000").expect("test lineage");
        StateFence::new(
            EpochId::new(lineage, NonZeroU64::new(1).expect("nonzero")).expect("valid test epoch"),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn scope() -> ScopeId {
        ScopeId::new(LIFECYCLE_SCOPE).expect("lifecycle scope")
    }

    fn record(index: u64, action: &str, digest: &str) -> serde_json::Value {
        serde_json::json!({
            "capture_index": index,
            "operation": "ApplyLifecyclePolicy",
            "parameters": {
                "action": action,
                "base_view_digest": "a".repeat(64),
                "candidate_digest": "b".repeat(64),
                "candidate_package_digest": digest,
                "skill_id": "skill-demo",
                "verifier_ref": "verifier-1",
            },
        })
    }
    fn response(records: Vec<serde_json::Value>, truncated: bool) -> NamedReadResponse {
        NamedReadResponse {
            operation: NamedReadOperation::GetCapabilityEvidenceState,
            state_fence: fence(),
            revision_heads: Vec::new(),
            payload: serde_json::json!({
                "version": 1,
                "skill_id": "skill-demo",
                "scope_id": serde_json::to_value(scope()).expect("scope value"),
                "records": records,
                "provenance": {
                    "state_fence": serde_json::to_value(fence()).expect("fence value"),
                    "matched_total": records.len(),
                    "returned": records.len(),
                    "max_records": 32,
                    "truncated": truncated,
                },
            }),
        }
    }

    fn planned() -> NamedReadRequest {
        plan_acceptance_read("skill-demo", fence()).expect("planned read")
    }

    #[test]
    fn latest_accepting_row_decides_over_earlier_revocations() {
        let verdict = resolve_acceptance(
            &planned(),
            &response(
                vec![
                    record(1, "suppress", &"d".repeat(64)),
                    record(2, "restore", &"d".repeat(64)),
                ],
                false,
            ),
            &"d".repeat(64),
        )
        .expect("resolves");
        assert!(matches!(
            verdict,
            AcceptanceVerdict::Accepted(ref record) if record.revision == 2
        ));
    }

    #[test]
    fn latest_revoking_row_holds_against_earlier_acceptance() {
        let verdict = resolve_acceptance(
            &planned(),
            &response(
                vec![
                    record(1, "keep", &"d".repeat(64)),
                    record(2, "archive", &"d".repeat(64)),
                ],
                false,
            ),
            &"d".repeat(64),
        )
        .expect("resolves");
        assert!(matches!(
            verdict,
            AcceptanceVerdict::Revoked(ref record) if record.revision == 2
        ));
    }

    #[test]
    fn absent_digest_is_unknown_never_acceptance() {
        let verdict = resolve_acceptance(
            &planned(),
            &response(vec![record(1, "keep", &"e".repeat(64))], false),
            &"d".repeat(64),
        )
        .expect("resolves");
        assert!(matches!(verdict, AcceptanceVerdict::Unknown));
    }

    #[test]
    fn newer_different_digest_supersedes_older_acceptance() {
        // The owner moved on: a newer committed row binds another package
        // digest, so the older digest resolves Unknown even though an older
        // row accepted it. Only the current digest decides.
        let rows = vec![
            record(1, "keep", &"d".repeat(64)),
            record(2, "keep", &"e".repeat(64)),
        ];
        let superseded =
            resolve_acceptance(&planned(), &response(rows.clone(), false), &"d".repeat(64))
                .expect("resolves");
        assert!(matches!(superseded, AcceptanceVerdict::Unknown));
        let current = resolve_acceptance(&planned(), &response(rows, false), &"e".repeat(64))
            .expect("resolves");
        assert!(matches!(
            current,
            AcceptanceVerdict::Accepted(ref record) if record.revision == 2
        ));
    }

    #[test]
    fn superseded_digest_never_revives_past_a_later_revocation() {
        // An older acceptance stays superseded once a newer row commits for
        // another digest -- including a revocation of that newer digest.
        let rows = vec![
            record(1, "keep", &"d".repeat(64)),
            record(2, "suppress", &"e".repeat(64)),
        ];
        let superseded =
            resolve_acceptance(&planned(), &response(rows.clone(), false), &"d".repeat(64))
                .expect("resolves");
        assert!(matches!(superseded, AcceptanceVerdict::Unknown));
        let revoked = resolve_acceptance(&planned(), &response(rows, false), &"e".repeat(64))
            .expect("resolves");
        assert!(matches!(
            revoked,
            AcceptanceVerdict::Revoked(ref record) if record.revision == 2
        ));
    }

    #[test]
    fn row_missing_its_base_view_fails_closed() {
        // Committed rows carry the exact six lifecycle parameters: a row
        // without its base view cannot prove the promotion it claims.
        let mut partial = record(1, "keep", &"d".repeat(64));
        partial["parameters"]
            .as_object_mut()
            .expect("parameters")
            .remove("base_view_digest");
        let refused =
            resolve_acceptance(&planned(), &response(vec![partial], false), &"d".repeat(64));
        assert!(matches!(
            refused,
            Err(AcceptanceReadError::Payload(field)) if field == "parameters"
        ));
    }

    #[test]
    fn truncated_history_fails_closed() {
        let refused = resolve_acceptance(
            &planned(),
            &response(vec![record(1, "keep", &"d".repeat(64))], true),
            &"d".repeat(64),
        );
        assert!(matches!(
            refused,
            Err(AcceptanceReadError::Payload(field)) if field == "truncated"
        ));
    }

    #[test]
    fn foreign_operation_or_action_fails_closed() {
        let mut foreign = record(1, "keep", &"d".repeat(64));
        foreign["operation"] = serde_json::Value::String("UpdateTaskState".to_owned());
        let refused =
            resolve_acceptance(&planned(), &response(vec![foreign], false), &"d".repeat(64));
        assert!(matches!(
            refused,
            Err(AcceptanceReadError::Payload(field)) if field == "operation"
        ));
        let novel = record(1, "transmogrify", &"d".repeat(64));
        let refused =
            resolve_acceptance(&planned(), &response(vec![novel], false), &"d".repeat(64));
        assert!(matches!(
            refused,
            Err(AcceptanceReadError::Payload(field)) if field == "action"
        ));
    }

    #[test]
    fn plan_rejects_blank_skill() {
        assert!(matches!(
            plan_acceptance_read("   ", fence()),
            Err(AcceptanceReadError::BlankSkill)
        ));
    }
}
