use crate::{EngineError, MemoryLifecycleService};
use eliot_store::CanonicalStore;
use eliot_types::{
    CurrentStateRequest, CurrentStateResponse, FetchAtomsL2Request, FetchAtomsL2Response,
    GraphHealthResponse, MemoryRevision, ReadConsistencyMode, RecallL0Request, RecallL0Response,
};
use std::collections::HashSet;
use tokio::time::{Duration, Instant, sleep};

const STALE_READ_TIMEOUT: Duration = Duration::from_secs(5);
const STALE_READ_POLL: Duration = Duration::from_millis(25);

#[derive(Clone, Debug)]
pub struct ReadService {
    store: CanonicalStore,
}

impl ReadService {
    pub const fn new(store: CanonicalStore) -> Self {
        Self { store }
    }

    pub async fn current_state(
        &self,
        request: &CurrentStateRequest,
    ) -> Result<CurrentStateResponse, EngineError> {
        let target = target_revision(request.consistency, request.at_least_revision);
        let started = Instant::now();
        loop {
            let response = self.store.current_state(request).await?;
            if revision_satisfies(response.memory_revision, target) {
                return Ok(response);
            }
            ensure_can_wait(started, target, response.memory_revision)?;
            sleep(STALE_READ_POLL).await;
        }
    }

    pub async fn recall_l0(
        &self,
        request: &RecallL0Request,
    ) -> Result<RecallL0Response, EngineError> {
        let target = target_revision(request.consistency, request.at_least_revision);
        let started = Instant::now();
        loop {
            let response = self.store.recall_l0(request).await?;
            if revision_satisfies(response.at_revision, target) {
                return Ok(MemoryLifecycleService::filter_l0_response(
                    response,
                    request.lifecycle_audit,
                ));
            }
            ensure_can_wait(started, target, response.at_revision)?;
            sleep(STALE_READ_POLL).await;
        }
    }

    pub async fn fetch_atoms_l2(
        &self,
        request: &FetchAtomsL2Request,
    ) -> Result<FetchAtomsL2Response, EngineError> {
        let target = target_revision(request.consistency, request.at_least_revision);
        let started = Instant::now();
        loop {
            let response = self.store.fetch_atoms_l2(request).await?;
            if revision_satisfies(response.at_revision, target) {
                return Ok(response);
            }
            ensure_can_wait(started, target, response.at_revision)?;
            sleep(STALE_READ_POLL).await;
        }
    }
}

pub fn filter_exact_l2_response(response: &mut FetchAtomsL2Response, handles: &[String]) {
    if handles.is_empty() {
        return;
    }
    filter_required_exact_l2_response(response, handles);
}

pub fn filter_required_exact_l2_response(response: &mut FetchAtomsL2Response, handles: &[String]) {
    let handles = handles
        .iter()
        .map(|handle| normalized_public_handle(handle).to_owned())
        .collect::<HashSet<_>>();
    response
        .evidence_atoms
        .retain(|atom| handles.contains(&atom.evidence_id.to_string()));
    response
        .claims
        .retain(|claim| handles.contains(&claim.claim_id.to_string()));
    response
        .verification_runs
        .retain(|run| handles.contains(&run.verification_id.to_string()));
    response.tool_observations.retain(|observation| {
        handles.contains(normalized_public_handle(&observation.observation_id))
    });
    response
        .failure_fingerprints
        .retain(|failure| handles.contains(normalized_public_handle(&failure.fingerprint)));
    response.relations.retain(|relation| {
        handles.contains(normalized_public_handle(&relation.from))
            && handles.contains(normalized_public_handle(&relation.to))
    });
    response.truncation.returned = response.evidence_atoms.len()
        + response.claims.len()
        + response.verification_runs.len()
        + response.tool_observations.len()
        + response.failure_fingerprints.len()
        + response.relations.len();
}

fn normalized_public_handle(value: &str) -> &str {
    const PREFIXES: &[&str] = &[
        "claim:",
        "claim_card:",
        "evidence:",
        "evidence_atom:",
        "verification:",
        "verification_run:",
        "observation:",
        "tool_observation:",
        "failure:",
        "failure_fingerprint:",
    ];
    PREFIXES
        .iter()
        .find_map(|prefix| value.strip_prefix(prefix))
        .unwrap_or(value)
}

fn target_revision(
    consistency: ReadConsistencyMode,
    at_least_revision: Option<MemoryRevision>,
) -> Option<MemoryRevision> {
    match consistency {
        ReadConsistencyMode::Latest => None,
        ReadConsistencyMode::AtLeastRevision => at_least_revision,
    }
}

fn revision_satisfies(actual: MemoryRevision, target: Option<MemoryRevision>) -> bool {
    target.is_none_or(|required| actual >= required)
}

fn ensure_can_wait(
    started: Instant,
    target: Option<MemoryRevision>,
    actual: MemoryRevision,
) -> Result<(), EngineError> {
    if started.elapsed() < STALE_READ_TIMEOUT {
        return Ok(());
    }
    let required = target.map_or(0, MemoryRevision::value);
    Err(EngineError::StaleRead {
        required,
        actual: actual.value(),
    })
}

#[derive(Clone, Debug)]
pub struct GraphHealthService {
    store: CanonicalStore,
}

impl GraphHealthService {
    pub const fn new(store: CanonicalStore) -> Self {
        Self { store }
    }

    pub async fn health(&self) -> Result<GraphHealthResponse, EngineError> {
        Ok(self.store.graph_health().await?)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        filter_exact_l2_response, filter_required_exact_l2_response, normalized_public_handle,
    };
    use eliot_types::{
        ClaimCard, ClaimId, EpistemicStatus, EvidenceAtom, EvidenceId, FetchAtomsL2Response,
        MemoryRevision, ProjectId, RelationSummary, RelationType, TruncationInfo,
    };
    use serde_json::json;

    fn scoped_response() -> (FetchAtomsL2Response, String) {
        let project_id = ProjectId::new_v7();
        let claim_id = ClaimId::new_v7();
        let evidence_id = EvidenceId::new_v7();
        let claim_handle = format!("claim:{claim_id}");
        (
            FetchAtomsL2Response {
                project_id,
                at_revision: MemoryRevision::new(7),
                evidence_atoms: vec![EvidenceAtom {
                    evidence_id,
                    summary: "out of scope".to_owned(),
                    payload: json!({}),
                }],
                claims: vec![ClaimCard {
                    claim_id,
                    statement: "in scope".to_owned(),
                    status: EpistemicStatus::Verified,
                    payload: json!({}),
                }],
                verification_runs: Vec::new(),
                tool_observations: Vec::new(),
                failure_fingerprints: Vec::new(),
                relations: vec![RelationSummary {
                    relation_type: RelationType::Supports,
                    from: claim_handle.clone(),
                    to: format!("evidence:{evidence_id}"),
                }],
                requested_handles: Vec::new(),
                returned_handles: Vec::new(),
                missing_handles: Vec::new(),
                forbidden_handles: Vec::new(),
                continuation: None,
                truncation: TruncationInfo {
                    truncated: false,
                    limit: 50,
                    returned: 3,
                },
            },
            claim_handle,
        )
    }

    #[test]
    fn exact_l2_handles_accept_api_and_surreal_record_prefixes() {
        let id = "2ddae812-5359-43a7-9fe4-f85c2c28bdd4";
        assert_eq!(normalized_public_handle(id), id);
        assert_eq!(normalized_public_handle(&format!("claim:{id}")), id);
        assert_eq!(normalized_public_handle(&format!("claim_card:{id}")), id);
        assert_eq!(
            normalized_public_handle("custom:fingerprint"),
            "custom:fingerprint"
        );
    }

    #[test]
    fn empty_exact_scope_returns_no_l2_nodes_or_relations() {
        let (mut response, _) = scoped_response();
        filter_required_exact_l2_response(&mut response, &[]);
        assert!(response.claims.is_empty());
        assert!(response.evidence_atoms.is_empty());
        assert!(response.relations.is_empty());
        assert_eq!(response.truncation.returned, 0);
    }

    #[test]
    fn optional_empty_scope_preserves_unfiltered_l2_contract() {
        let (mut response, _) = scoped_response();
        filter_exact_l2_response(&mut response, &[]);
        assert_eq!(response.claims.len(), 1);
        assert_eq!(response.evidence_atoms.len(), 1);
        assert_eq!(response.relations.len(), 1);
    }

    #[test]
    fn sealed_relation_requires_both_endpoints_in_exact_scope() {
        let (mut response, _) = scoped_response();
        response.relations = vec![RelationSummary {
            relation_type: RelationType::CoChange,
            from: "file:src/a.rs".to_owned(),
            to: "file:src/b.rs".to_owned(),
        }];
        filter_required_exact_l2_response(&mut response, &["file:src/a.rs".to_owned()]);
        assert!(response.relations.is_empty());

        let (mut response, _) = scoped_response();
        response.relations = vec![RelationSummary {
            relation_type: RelationType::CoChange,
            from: "file:src/a.rs".to_owned(),
            to: "file:src/b.rs".to_owned(),
        }];
        filter_required_exact_l2_response(
            &mut response,
            &["file:src/a.rs".to_owned(), "file:src/b.rs".to_owned()],
        );
        assert_eq!(response.relations.len(), 1);
    }
}
