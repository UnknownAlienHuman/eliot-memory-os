use crate::{MemoryRevision, ProjectId};
use serde::{Deserialize, Serialize};

pub const PROJECT_UNDERSTANDING_SCHEMA_VERSION: &str = "project-understanding-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalHopKind {
    IntentToConcept,
    ConceptToOwner,
    OwnerToSymbol,
    SymbolToStateOrFlow,
    FlowToObservable,
    ObservableToVerifier,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalHopStatus {
    Verified,
    Supported,
    Assumed,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCausalHop {
    pub hop_kind: CausalHopKind,
    pub from: String,
    pub relation: String,
    pub to: String,
    pub evidence_refs: Vec<String>,
    pub status: CausalHopStatus,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingIntent {
    pub exact_user_goal_ref: String,
    pub normalized_goal: String,
    pub desired_state_transition: String,
    pub non_goals: Vec<String>,
    pub acceptance_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingSystem {
    pub project_purpose: String,
    pub subsystem_refs: Vec<String>,
    pub owner_modules: Vec<String>,
    pub entrypoint_refs: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectCausalModel {
    pub hops: Vec<ProjectCausalHop>,
    pub unknown_hops: Vec<CausalHopKind>,
    pub required_probes: Vec<String>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityAcceptanceState {
    pub acceptance_ref: String,
    pub satisfied: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuityGitState {
    pub branch: String,
    pub commit: String,
    pub dirty_state_hash: String,
    pub current_diff_ref: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectContinuityState {
    pub exact_goal: String,
    pub acceptance_state: Vec<ContinuityAcceptanceState>,
    pub completed_items: Vec<String>,
    pub active_plan: Vec<String>,
    pub killed_or_paused_paths: Vec<String>,
    pub current_git: ContinuityGitState,
    pub current_truth_refs: Vec<String>,
    pub used_memory_refs: Vec<String>,
    pub open_unknowns: Vec<String>,
    pub next_action: String,
    pub expected_observable: String,
    pub verifier: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingEvidence {
    pub project_purpose: String,
    pub subsystem_refs: Vec<String>,
    pub owner_modules: Vec<String>,
    pub entrypoint_refs: Vec<String>,
    pub invariant_refs: Vec<String>,
    pub danger_refs: Vec<String>,
    pub artifact_refs: Vec<String>,
    pub flow_evidence_refs: Vec<String>,
    pub non_goals: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectUnderstandingModel {
    pub schema_version: String,
    pub project_id: ProjectId,
    pub task_id: String,
    pub revision_fence: MemoryRevision,
    pub intent: ProjectUnderstandingIntent,
    pub system: ProjectUnderstandingSystem,
    pub causal_model: ProjectCausalModel,
    pub invariants: Vec<String>,
    pub danger_and_negative_memory: Vec<String>,
    pub current_truth_refs: Vec<String>,
    pub historical_or_stale_refs: Vec<String>,
    pub memory_refs_used: Vec<String>,
    pub files_to_inspect: Vec<String>,
    pub files_to_change: Vec<String>,
    pub predicted_changed_paths: Vec<String>,
    pub predicted_failing_verifiers: Vec<String>,
    pub next_allowed_action: String,
    pub expected_observable: String,
    pub verifier_ref: String,
    pub stop_condition: String,
}

impl ProjectUnderstandingModel {
    /// Owner version-selection check applied at this model's real admission owner,
    /// before the decoded model may be consumed as current project proof.
    ///
    /// `deny_unknown_fields` closes the shape but proves nothing about semantic
    /// version selection: a foreign or future layout that happens to deserialize
    /// into the current fields is still not this build's model. This is the step
    /// that makes version selection explicit instead of inferred from the presence
    /// of a `schema_version` string.
    pub fn schema_selection(&self) -> Option<&'static str> {
        project_understanding_schema_selection(&self.schema_version)
    }

    /// Owner admission check for the decoded model.
    ///
    /// Returns the admitted version when the model names the current schema AND its
    /// acceptance/causal evidence cannot be read as satisfied proof it does not
    /// carry. Returns `None` otherwise, which the caller MUST treat as "this model
    /// is not current project understanding".
    ///
    /// I5.16: "Absence of a closure or coverage record means `unknown`, not
    /// unrestricted/complete." An acceptance entry with an empty `acceptance_ref`
    /// names no acceptance criterion, so `satisfied = true` beside it is the absence
    /// of a record read as completeness. Likewise a causal hop claiming `Verified`
    /// or `Supported` while carrying no `evidence_refs` is a coverage claim with no
    /// evidence, which is `unknown`, not proven.
    ///
    /// An ABSENT list is not refused: `ProjectUnderstandingCompiler::compile` derives
    /// `acceptance_refs` from the packet's own acceptance state, which is legitimately
    /// empty when the packet declares no acceptance items, and a causal model with no
    /// hops is a legitimate "no causal knowledge yet" reading. Absence of the list is
    /// already `unknown` under I5.16 and is not read as completeness anywhere; what is
    /// refused is a claim of satisfaction or verification carrying no record at all.
    #[must_use]
    pub fn admission(&self) -> Option<&'static str> {
        let version = self.schema_selection()?;
        let acceptance_named = self
            .intent
            .acceptance_refs
            .iter()
            .chain(std::iter::once(&self.verifier_ref))
            .all(|reference| !reference.trim().is_empty());
        // A hop is proven only when it does NOT claim verification it carries no
        // record for: `Verified`/`Supported` with empty `evidence_refs` is a
        // coverage claim with no evidence and refuses admission. `Assumed`/`Unknown`
        // hops honestly label non-proof, so they pass with or without evidence.
        let coverage_proven = self.causal_model.hops.iter().all(|hop| {
            !matches!(
                hop.status,
                CausalHopStatus::Verified | CausalHopStatus::Supported
            ) || !hop.evidence_refs.is_empty()
        });
        acceptance_named
            .then_some(())
            .filter(|()| coverage_proven)
            .map(|()| version)
    }
}

/// Owner version selection for `ProjectUnderstandingModel`.
///
/// `PROJECT_UNDERSTANDING_SCHEMA_VERSION` is the only schema the engine constructs
/// (`eliot-engine::project_understanding`), and a repository-wide search finds no
/// other `project-understanding-v*` literal. There is no supported legacy revision,
/// so every other version is refused rather than reinterpreted.
#[must_use]
pub fn project_understanding_schema_selection(version: &str) -> Option<&'static str> {
    if version == PROJECT_UNDERSTANDING_SCHEMA_VERSION {
        Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
    } else {
        None
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    const MODEL: &str = r#"{
      "schema_version": "project-understanding-v1",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "revision_fence": 7,
      "intent": {
        "exact_user_goal_ref": "eliot/task/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@7",
        "normalized_goal": "fixture goal",
        "desired_state_transition": "fixture transition",
        "non_goals": [],
        "acceptance_refs": ["accept:fixture-1"]
      },
      "system": {
        "project_purpose": "fixture purpose",
        "subsystem_refs": ["sub:core"],
        "owner_modules": ["mod:core"],
        "entrypoint_refs": ["ep:main"]
      },
      "causal_model": {
        "hops": [
          {
            "hop_kind": "intent_to_concept",
            "from": "intent:task-fixture",
            "relation": "scoped_to",
            "to": "concept:core",
            "evidence_refs": ["artifact:fixture-1"],
            "status": "supported"
          }
        ],
        "unknown_hops": [],
        "required_probes": []
      },
      "invariants": ["inv:fixture-1"],
      "danger_and_negative_memory": [],
      "current_truth_refs": ["claim:fixture-1"],
      "historical_or_stale_refs": [],
      "memory_refs_used": [],
      "files_to_inspect": [],
      "files_to_change": [],
      "predicted_changed_paths": [],
      "predicted_failing_verifiers": [],
      "next_allowed_action": "act-fixture",
      "expected_observable": "obs-fixture",
      "verifier_ref": "verifier:ci-fixture",
      "stop_condition": "stop-fixture"
    }"#;

    const MODEL_ABSENT_LISTS: &str = r#"{
      "schema_version": "project-understanding-v1",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "revision_fence": 7,
      "intent": {
        "exact_user_goal_ref": "eliot/task/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@7",
        "normalized_goal": "fixture goal",
        "desired_state_transition": "fixture transition",
        "non_goals": [],
        "acceptance_refs": []
      },
      "system": {
        "project_purpose": "fixture purpose",
        "subsystem_refs": [],
        "owner_modules": [],
        "entrypoint_refs": []
      },
      "causal_model": {
        "hops": [],
        "unknown_hops": [],
        "required_probes": []
      },
      "invariants": [],
      "danger_and_negative_memory": [],
      "current_truth_refs": [],
      "historical_or_stale_refs": [],
      "memory_refs_used": [],
      "files_to_inspect": [],
      "files_to_change": [],
      "predicted_changed_paths": [],
      "predicted_failing_verifiers": [],
      "next_allowed_action": "act-fixture",
      "expected_observable": "obs-fixture",
      "verifier_ref": "verifier:ci-fixture",
      "stop_condition": "stop-fixture"
    }"#;

    const MODEL_FOREIGN: &str = r#"{
      "schema_version": "project-understanding-v9",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "revision_fence": 7,
      "intent": {
        "exact_user_goal_ref": "eliot/task/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@7",
        "normalized_goal": "fixture goal",
        "desired_state_transition": "fixture transition",
        "non_goals": [],
        "acceptance_refs": ["accept:fixture-1"]
      },
      "system": {
        "project_purpose": "fixture purpose",
        "subsystem_refs": ["sub:core"],
        "owner_modules": ["mod:core"],
        "entrypoint_refs": ["ep:main"]
      },
      "causal_model": {
        "hops": [
          {
            "hop_kind": "intent_to_concept",
            "from": "intent:task-fixture",
            "relation": "scoped_to",
            "to": "concept:core",
            "evidence_refs": ["artifact:fixture-1"],
            "status": "supported"
          }
        ],
        "unknown_hops": [],
        "required_probes": []
      },
      "invariants": ["inv:fixture-1"],
      "danger_and_negative_memory": [],
      "current_truth_refs": ["claim:fixture-1"],
      "historical_or_stale_refs": [],
      "memory_refs_used": [],
      "files_to_inspect": [],
      "files_to_change": [],
      "predicted_changed_paths": [],
      "predicted_failing_verifiers": [],
      "next_allowed_action": "act-fixture",
      "expected_observable": "obs-fixture",
      "verifier_ref": "verifier:ci-fixture",
      "stop_condition": "stop-fixture"
    }"#;

    const MODEL_EMPTY_VERIFIER: &str = r#"{
      "schema_version": "project-understanding-v1",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "revision_fence": 7,
      "intent": {
        "exact_user_goal_ref": "eliot/task/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@7",
        "normalized_goal": "fixture goal",
        "desired_state_transition": "fixture transition",
        "non_goals": [],
        "acceptance_refs": ["accept:fixture-1"]
      },
      "system": {
        "project_purpose": "fixture purpose",
        "subsystem_refs": ["sub:core"],
        "owner_modules": ["mod:core"],
        "entrypoint_refs": ["ep:main"]
      },
      "causal_model": {
        "hops": [
          {
            "hop_kind": "intent_to_concept",
            "from": "intent:task-fixture",
            "relation": "scoped_to",
            "to": "concept:core",
            "evidence_refs": ["artifact:fixture-1"],
            "status": "supported"
          }
        ],
        "unknown_hops": [],
        "required_probes": []
      },
      "invariants": ["inv:fixture-1"],
      "danger_and_negative_memory": [],
      "current_truth_refs": ["claim:fixture-1"],
      "historical_or_stale_refs": [],
      "memory_refs_used": [],
      "files_to_inspect": [],
      "files_to_change": [],
      "predicted_changed_paths": [],
      "predicted_failing_verifiers": [],
      "next_allowed_action": "act-fixture",
      "expected_observable": "obs-fixture",
      "verifier_ref": "",
      "stop_condition": "stop-fixture"
    }"#;

    const MODEL_UNEVIDENCED_VERIFIED: &str = r#"{
      "schema_version": "project-understanding-v1",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "revision_fence": 7,
      "intent": {
        "exact_user_goal_ref": "eliot/task/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@7",
        "normalized_goal": "fixture goal",
        "desired_state_transition": "fixture transition",
        "non_goals": [],
        "acceptance_refs": ["accept:fixture-1"]
      },
      "system": {
        "project_purpose": "fixture purpose",
        "subsystem_refs": ["sub:core"],
        "owner_modules": ["mod:core"],
        "entrypoint_refs": ["ep:main"]
      },
      "causal_model": {
        "hops": [
          {
            "hop_kind": "owner_to_symbol",
            "from": "owner:core",
            "relation": "implemented_by",
            "to": "symbol:main",
            "evidence_refs": [],
            "status": "verified"
          }
        ],
        "unknown_hops": [],
        "required_probes": []
      },
      "invariants": ["inv:fixture-1"],
      "danger_and_negative_memory": [],
      "current_truth_refs": ["claim:fixture-1"],
      "historical_or_stale_refs": [],
      "memory_refs_used": [],
      "files_to_inspect": [],
      "files_to_change": [],
      "predicted_changed_paths": [],
      "predicted_failing_verifiers": [],
      "next_allowed_action": "act-fixture",
      "expected_observable": "obs-fixture",
      "verifier_ref": "verifier:ci-fixture",
      "stop_condition": "stop-fixture"
    }"#;

    // WORK_UNIT_CASE: 935/7
    #[test]
    fn admitted_project_understanding_passes_owner_admission() -> Result<(), serde_json::Error> {
        let model: ProjectUnderstandingModel = serde_json::from_str(MODEL)?;
        assert_eq!(
            model.admission(),
            Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
        );
        // Absent acceptance/causal lists are `unknown`, not false claims: the
        // owner boundary refuses claims of satisfaction without a record, not
        // empty knowledge, so the absent-lists model is still admitted here
        // while no downstream consumer may read it as completeness.
        let absent: ProjectUnderstandingModel = serde_json::from_str(MODEL_ABSENT_LISTS)?;
        assert_eq!(
            absent.admission(),
            Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
        );
        Ok(())
    }

    // WORK_UNIT_CASE: 935/8
    #[test]
    fn unadmitted_project_understanding_fails_owner_admission() -> Result<(), String> {
        for (name, raw) in [
            ("foreign version", MODEL_FOREIGN),
            ("empty verifier ref", MODEL_EMPTY_VERIFIER),
            ("verified hop without evidence", MODEL_UNEVIDENCED_VERIFIED),
        ] {
            // Each refusal fixture still decodes structurally: shape closure is
            // not semantic selection, so admission must fail on the decoded value.
            let model: ProjectUnderstandingModel = serde_json::from_str(raw)
                .map_err(|error| format!("{name} must still decode structurally: {error}"))?;
            if model.admission().is_some() {
                return Err(format!("{name} must not be admitted"));
            }
        }
        let foreign: ProjectUnderstandingModel = serde_json::from_str(MODEL_FOREIGN)
            .map_err(|error| format!("foreign model must still decode: {error}"))?;
        assert_eq!(foreign.schema_selection(), None);
        Ok(())
    }

    // WORK_UNIT_CASE: 935/9
    #[test]
    fn understanding_selection_admits_only_the_current_owner_version() {
        assert_eq!(
            project_understanding_schema_selection(PROJECT_UNDERSTANDING_SCHEMA_VERSION),
            Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
        );
        for foreign in [
            "",
            "v1",
            "project-understanding-v0",
            "project-understanding-v2",
            "PROJECT-UNDERSTANDING-V1",
        ] {
            assert_eq!(
                project_understanding_schema_selection(foreign),
                None,
                "owner selection must refuse {foreign:?}"
            );
        }
    }
}
