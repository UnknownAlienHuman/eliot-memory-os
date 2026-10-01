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
    /// Returns the admitted version when the model names the current schema AND it
    /// cannot be read as a causal/acceptance claim carrying no record at all.
    /// Returns `None` otherwise, which the caller MUST treat as "this model is not
    /// current project understanding".
    ///
    /// I5.16: "Absence of a closure or coverage record means `unknown`, not
    /// unrestricted/complete." Version selection is the owner decision: a foreign or
    /// future layout that happens to deserialize into the current fields is still not
    /// this build's model, so it is refused rather than reinterpreted.
    ///
    /// Refused here, and each refusal is reachable only from bytes this build does not
    /// produce:
    ///
    /// - a declared `schema_version` other than `PROJECT_UNDERSTANDING_SCHEMA_VERSION`;
    /// - an EXPLICITLY EMPTY `intent.acceptance_refs` entry. An empty acceptance
    ///   reference names no acceptance criterion, so any satisfaction claim resting on
    ///   it is the absence of a record read as completeness. `acceptance_state()` in
    ///   `eliot-engine::project_understanding` derives the list from the packet's own
    ///   acceptance items and the task contract, so an entry is present only when a
    ///   criterion was named;
    /// - an EMPTY `causal_model.hops`. `causal_model()` always emits its six hop
    ///   kinds, so a hop-less causal model is not a shape this build produces and
    ///   cannot be admitted as current causal coverage.
    ///
    /// Deliberately NOT refused, because the current compiler emits each of these and
    /// refusing them would reject this build's own current output:
    ///
    /// - an ABSENT `acceptance_refs` list, and an EMPTY `verifier_ref`. Both derive
    ///   from the packet's material frame, which is legitimately empty when the
    ///   compile request carries no `material_frame`
    ///   (`hydrate_material_packet` applies `MaterialPacketFrame::default()`), and
    ///   absence is already `unknown` under I5.16 and is read as completeness nowhere;
    /// - a `Verified`/`Supported` hop with empty `evidence_refs`. `causal_model()`
    ///   gives `OwnerToSymbol` the status `Verified` from the resolved owner and
    ///   entrypoint refs and carries `codecortex_refs` as its evidence, which is empty
    ///   whenever no CodeCortex report is attached. That is the compiler's own
    ///   labelling of a resolved link, not a fabricated coverage claim.
    #[must_use]
    pub fn admission(&self) -> Option<&'static str> {
        let version = self.schema_selection()?;
        let acceptance_named = self
            .intent
            .acceptance_refs
            .iter()
            .all(|reference| !reference.trim().is_empty());
        let causal_coverage_recorded = !self.causal_model.hops.is_empty();
        acceptance_named
            .then_some(())
            .filter(|()| causal_coverage_recorded)
            .map(|()| version)
    }
}

impl ContinuityAcceptanceState {
    /// Owner admission for one decoded acceptance entry.
    ///
    /// `satisfied = true` is a completion claim, and it names the criterion it
    /// completes only through `acceptance_ref`. An EXPLICITLY EMPTY `acceptance_ref`
    /// beside `satisfied = true` is therefore a satisfaction claim carrying no record,
    /// which I5.16 reads as `unknown`, not as completeness, so it is refused rather
    /// than admitted as current proof.
    ///
    /// `satisfied = false` with an empty reference is honest non-claim and is admitted;
    /// a non-empty reference is a named criterion and is admitted either way.
    #[must_use]
    pub fn is_admissible(&self) -> bool {
        !(self.satisfied && self.acceptance_ref.trim().is_empty())
    }
}

impl ProjectContinuityState {
    /// Owner admission for the decoded continuity record.
    ///
    /// Every acceptance entry must be admissible under
    /// [`ContinuityAcceptanceState::is_admissible`], so one empty-reference
    /// satisfaction claim refuses the record as current continuity proof rather than
    /// being counted as a satisfied acceptance item.
    #[must_use]
    pub fn is_admissible(&self) -> bool {
        self.acceptance_state
            .iter()
            .all(ContinuityAcceptanceState::is_admissible)
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

    const MODEL_ABSENT_ACCEPTANCE_REFS: &str = r#"{
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
        "hops": [{
          "hop_kind": "intent_to_concept",
          "from": "intent:task-fixture",
          "relation": "scoped_to",
          "to": "unknown:concept",
          "evidence_refs": [],
          "status": "unknown"
        }],
        "unknown_hops": ["intent_to_concept"],
        "required_probes": ["resolve resolve IntentToConcept"]
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

    const MODEL_EMPTY_CAUSAL_HOP: &str = r#"{
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
        "hops": [],
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

    const MODEL_EMPTY_ACCEPTANCE_REF: &str = r#"{
      "schema_version": "project-understanding-v1",
      "project_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "task_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "revision_fence": 7,
      "intent": {
        "exact_user_goal_ref": "eliot/task/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb@7",
        "normalized_goal": "fixture goal",
        "desired_state_transition": "fixture transition",
        "non_goals": [],
        "acceptance_refs": ["accept:fixture-1", "   "]
      },
      "system": {
        "project_purpose": "fixture purpose",
        "subsystem_refs": ["sub:core"],
        "owner_modules": ["mod:core"],
        "entrypoint_refs": ["ep:main"]
      },
      "causal_model": {
        "hops": [{
          "hop_kind": "intent_to_concept",
          "from": "intent:task-fixture",
          "relation": "scoped_to",
          "to": "concept:core",
          "evidence_refs": ["artifact:fixture-1"],
          "status": "supported"
        }],
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

    const MODEL_NO_MATERIAL_FRAME: &str = r#"{
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
        "project_purpose": "",
        "subsystem_refs": [],
        "owner_modules": [],
        "entrypoint_refs": []
      },
      "causal_model": {
        "hops": [{
          "hop_kind": "owner_to_symbol",
          "from": "unknown:owner",
          "relation": "implemented_by",
          "to": "unknown:symbol",
          "evidence_refs": [],
          "status": "unknown"
        }],
        "unknown_hops": ["owner_to_symbol"],
        "required_probes": ["resolve resolve OwnerToSymbol"]
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
      "verifier_ref": "",
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
        // Absent acceptance lists and an empty `verifier_ref` are `unknown`, not
        // false claims, and the compiler emits exactly these when the compile
        // request carries no material frame, so the owner boundary must admit
        // them rather than reject this build's own current output.
        let absent: ProjectUnderstandingModel = serde_json::from_str(MODEL_ABSENT_ACCEPTANCE_REFS)?;
        assert_eq!(
            absent.admission(),
            Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
        );
        let no_frame: ProjectUnderstandingModel = serde_json::from_str(MODEL_NO_MATERIAL_FRAME)?;
        assert_eq!(
            no_frame.admission(),
            Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
        );
        // A `Verified`/`Supported` hop with empty `evidence_refs` is the
        // compiler's own labelling of a link resolved without a CodeCortex
        // report, so it stays admissible too.
        let unevidenced: ProjectUnderstandingModel =
            serde_json::from_str(MODEL_UNEVIDENCED_VERIFIED)?;
        assert_eq!(
            unevidenced.admission(),
            Some(PROJECT_UNDERSTANDING_SCHEMA_VERSION)
        );
        Ok(())
    }

    // WORK_UNIT_CASE: 935/8
    #[test]
    fn unadmitted_project_understanding_fails_owner_admission() -> Result<(), String> {
        for (name, raw) in [
            ("foreign version", MODEL_FOREIGN),
            ("empty causal coverage", MODEL_EMPTY_CAUSAL_HOP),
            ("empty acceptance ref", MODEL_EMPTY_ACCEPTANCE_REF),
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

    // WORK_UNIT_CASE: 935/8
    #[test]
    fn continuity_acceptance_refuses_satisfied_claim_without_a_named_criterion() {
        let satisfied = ContinuityAcceptanceState {
            acceptance_ref: String::new(),
            satisfied: true,
        };
        assert!(
            !satisfied.is_admissible(),
            "an empty acceptance_ref beside satisfied=true names no criterion"
        );
        assert!(
            !ProjectContinuityState {
                acceptance_state: vec![satisfied],
                ..ProjectContinuityState::default()
            }
            .is_admissible(),
            "one unnamed satisfaction claim refuses the continuity record"
        );
        for admissible in [
            ContinuityAcceptanceState {
                acceptance_ref: "accept:fixture-1".to_owned(),
                satisfied: true,
            },
            ContinuityAcceptanceState {
                acceptance_ref: String::new(),
                satisfied: false,
            },
        ] {
            assert!(
                admissible.is_admissible(),
                "a named criterion, or an honest non-claim, stays admissible"
            );
        }
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
