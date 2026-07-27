use crate::{AgentHostId, ProjectId, SessionId, TaskId};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const UL_CROSS_AGENT_SCHEMA_VERSION: &str = "eliot-ul-cross-agent-suite-v1";
pub const UL_CROSS_AGENT_REPORT_SCHEMA_VERSION: &str = "eliot-ul-cross-agent-report-v1";
pub const UL_CROSS_AGENT_CONFIRMATION_TOKEN: &str = "CONFIRM-8-CLAUDE-ANTIGRAVITY-BLIND-RELAY";
pub const UL_CROSS_AGENT_EXACT_CALLS: usize = 8;
pub const UL_CROSS_AGENT_EXACT_CALLS_U8: u8 = 8;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum UlCrossAgentDirection {
    #[serde(rename = "A")]
    A,
    #[serde(rename = "B")]
    B,
}

impl UlCrossAgentDirection {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::B => "B",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UlCrossAgentRole {
    PrewriteControl,
    Writer,
    Treatment,
    MemoryFreeControl,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UlCrossAgentMemoryMode {
    CurrentMemory,
    CandidateWrite,
    Treatment,
    MemoryFreeControl,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentCase {
    pub ordinal: u8,
    pub case_id: String,
    pub direction: UlCrossAgentDirection,
    pub host: AgentHostId,
    pub role: UlCrossAgentRole,
    pub memory_mode: UlCrossAgentMemoryMode,
    pub file_cue: String,
    pub branch_phrase: String,
    pub expected_first_action: String,
    pub marker_visible_to_provider: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentSuite {
    pub schema_version: String,
    pub harness_version: String,
    pub confirmation_token: String,
    pub hard_provider_call_cap: u8,
    pub cases: Vec<UlCrossAgentCase>,
}

impl UlCrossAgentSuite {
    #[allow(clippy::too_many_lines)]
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != UL_CROSS_AGENT_SCHEMA_VERSION {
            return Err("UL cross-agent suite schema_version is unsupported".to_owned());
        }
        if self.harness_version.trim().is_empty() {
            return Err("UL cross-agent harness_version must not be empty".to_owned());
        }
        if self.confirmation_token != UL_CROSS_AGENT_CONFIRMATION_TOKEN {
            return Err(
                "UL cross-agent confirmation token differs from the fixed token".to_owned(),
            );
        }
        if usize::from(self.hard_provider_call_cap) != UL_CROSS_AGENT_EXACT_CALLS
            || self.cases.len() != UL_CROSS_AGENT_EXACT_CALLS
        {
            return Err(format!(
                "UL cross-agent suite requires exactly {UL_CROSS_AGENT_EXACT_CALLS} calls"
            ));
        }

        let expected = [
            (
                "A0",
                UlCrossAgentDirection::A,
                AgentHostId::Antigravity,
                UlCrossAgentRole::PrewriteControl,
                UlCrossAgentMemoryMode::CurrentMemory,
            ),
            (
                "A1",
                UlCrossAgentDirection::A,
                AgentHostId::Claude,
                UlCrossAgentRole::Writer,
                UlCrossAgentMemoryMode::CandidateWrite,
            ),
            (
                "A2",
                UlCrossAgentDirection::A,
                AgentHostId::Antigravity,
                UlCrossAgentRole::Treatment,
                UlCrossAgentMemoryMode::Treatment,
            ),
            (
                "A3",
                UlCrossAgentDirection::A,
                AgentHostId::Antigravity,
                UlCrossAgentRole::MemoryFreeControl,
                UlCrossAgentMemoryMode::MemoryFreeControl,
            ),
            (
                "B0",
                UlCrossAgentDirection::B,
                AgentHostId::Claude,
                UlCrossAgentRole::PrewriteControl,
                UlCrossAgentMemoryMode::CurrentMemory,
            ),
            (
                "B1",
                UlCrossAgentDirection::B,
                AgentHostId::Antigravity,
                UlCrossAgentRole::Writer,
                UlCrossAgentMemoryMode::CandidateWrite,
            ),
            (
                "B2",
                UlCrossAgentDirection::B,
                AgentHostId::Claude,
                UlCrossAgentRole::Treatment,
                UlCrossAgentMemoryMode::Treatment,
            ),
            (
                "B3",
                UlCrossAgentDirection::B,
                AgentHostId::Claude,
                UlCrossAgentRole::MemoryFreeControl,
                UlCrossAgentMemoryMode::MemoryFreeControl,
            ),
        ];
        for (index, (actual, expected)) in self.cases.iter().zip(expected).enumerate() {
            let ordinal = u8::try_from(index + 1).map_err(|error| error.to_string())?;
            let (case_id, direction, host, role, memory_mode) = expected;
            if actual.ordinal != ordinal
                || actual.case_id != case_id
                || actual.direction != direction
                || actual.host != host
                || actual.role != role
                || actual.memory_mode != memory_mode
            {
                return Err(format!(
                    "UL cross-agent exact plan mismatch at call {ordinal}"
                ));
            }
            let should_see_marker = role == UlCrossAgentRole::Writer;
            if actual.marker_visible_to_provider != should_see_marker {
                return Err(format!(
                    "UL cross-agent marker visibility mismatch at call {ordinal}"
                ));
            }
            if actual.file_cue.trim().is_empty()
                || actual.branch_phrase.trim().is_empty()
                || actual.expected_first_action.trim().is_empty()
            {
                return Err(format!(
                    "UL cross-agent call {ordinal} has incomplete cue semantics"
                ));
            }
        }
        Ok(())
    }

    pub fn plan(
        &self,
        run_id: impl Into<String>,
        project_id: ProjectId,
    ) -> Result<UlCrossAgentPlan, String> {
        self.validate()?;
        let calls = self
            .cases
            .iter()
            .map(|case| UlCrossAgentPlannedCall {
                call_number: case.ordinal,
                case_id: case.case_id.clone(),
                direction: case.direction,
                host: case.host,
                role: case.role,
                memory_mode: case.memory_mode,
                task_id: TaskId::new_v7(),
                session_id: SessionId::new_v7(),
                file_cue: case.file_cue.clone(),
                branch_phrase: case.branch_phrase.clone(),
                expected_first_action: case.expected_first_action.clone(),
                marker_visible_to_provider: case.marker_visible_to_provider,
            })
            .collect();
        let plan = UlCrossAgentPlan {
            schema_version: UL_CROSS_AGENT_SCHEMA_VERSION.to_owned(),
            run_id: run_id.into(),
            project_id,
            hard_provider_call_cap: self.hard_provider_call_cap,
            calls,
        };
        plan.validate()?;
        Ok(plan)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentPlannedCall {
    pub call_number: u8,
    pub case_id: String,
    pub direction: UlCrossAgentDirection,
    pub host: AgentHostId,
    pub role: UlCrossAgentRole,
    pub memory_mode: UlCrossAgentMemoryMode,
    pub task_id: TaskId,
    pub session_id: SessionId,
    pub file_cue: String,
    pub branch_phrase: String,
    pub expected_first_action: String,
    pub marker_visible_to_provider: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentPlan {
    pub schema_version: String,
    pub run_id: String,
    pub project_id: ProjectId,
    pub hard_provider_call_cap: u8,
    pub calls: Vec<UlCrossAgentPlannedCall>,
}

impl UlCrossAgentPlan {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != UL_CROSS_AGENT_SCHEMA_VERSION
            || self.run_id.trim().is_empty()
            || usize::from(self.hard_provider_call_cap) != UL_CROSS_AGENT_EXACT_CALLS
            || self.calls.len() != UL_CROSS_AGENT_EXACT_CALLS
        {
            return Err("UL cross-agent plan envelope is invalid".to_owned());
        }
        let tasks = self
            .calls
            .iter()
            .map(|call| call.task_id)
            .collect::<BTreeSet<_>>();
        let sessions = self
            .calls
            .iter()
            .map(|call| call.session_id)
            .collect::<BTreeSet<_>>();
        if tasks.len() != UL_CROSS_AGENT_EXACT_CALLS || sessions.len() != UL_CROSS_AGENT_EXACT_CALLS
        {
            return Err(
                "UL cross-agent calls require fresh unique task and session identifiers".to_owned(),
            );
        }
        for (index, call) in self.calls.iter().enumerate() {
            if usize::from(call.call_number) != index + 1 {
                return Err("UL cross-agent plan call numbers must be contiguous".to_owned());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentInputDigest {
    pub input_ref: String,
    pub blake3: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentContaminationReceipt {
    pub schema_version: String,
    pub marker_blake3: String,
    pub scanned_inputs: Vec<UlCrossAgentInputDigest>,
    pub contaminated_refs: Vec<String>,
    pub passed: bool,
}

#[must_use]
pub fn scan_ul_cross_agent_reader_inputs<'a>(
    marker: &str,
    inputs: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> UlCrossAgentContaminationReceipt {
    let marker_bytes = marker.as_bytes();
    let mut scanned_inputs = Vec::new();
    let mut contaminated_refs = Vec::new();
    for (input_ref, bytes) in inputs {
        scanned_inputs.push(UlCrossAgentInputDigest {
            input_ref: input_ref.to_owned(),
            blake3: blake3::hash(bytes).to_hex().to_string(),
        });
        if !marker_bytes.is_empty()
            && bytes
                .windows(marker_bytes.len())
                .any(|window| window == marker_bytes)
        {
            contaminated_refs.push(input_ref.to_owned());
        }
    }
    UlCrossAgentContaminationReceipt {
        schema_version: "eliot-ul-cross-agent-contamination-v1".to_owned(),
        marker_blake3: blake3::hash(marker_bytes).to_hex().to_string(),
        passed: contaminated_refs.is_empty(),
        scanned_inputs,
        contaminated_refs,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentReaderOutput {
    pub marker: Option<String>,
    pub memory_handle: Option<String>,
    pub delivery_surface: Option<String>,
    pub applicability: String,
    pub first_action: Option<String>,
    pub influence_receipt: Option<String>,
}

impl UlCrossAgentReaderOutput {
    #[must_use]
    pub fn uses_allowed_delivery_surface(&self) -> bool {
        matches!(
            self.delivery_surface.as_deref(),
            Some("ul_boot" | "ul_fired" | "recall_l0" | "fetch_l2" | "packet")
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentWriterOutput {
    pub candidate_handle: String,
    pub write_receipt: String,
    pub binding_refs: Vec<String>,
    pub candidate_only: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UlCrossAgentInvocationState {
    NeverDispatched,
    Attempting,
    Succeeded,
    Failed,
    UnknownOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UlCrossAgentDispatchDecision {
    DispatchFirstAttempt,
    RetryProvenUndispatched,
    RefuseRedispatch,
}

#[must_use]
pub const fn ul_cross_agent_dispatch_decision(
    state: UlCrossAgentInvocationState,
    proven_undispatched_attempts: u8,
) -> UlCrossAgentDispatchDecision {
    match (state, proven_undispatched_attempts) {
        (UlCrossAgentInvocationState::NeverDispatched, 0) => {
            UlCrossAgentDispatchDecision::DispatchFirstAttempt
        }
        (UlCrossAgentInvocationState::NeverDispatched, 1) => {
            UlCrossAgentDispatchDecision::RetryProvenUndispatched
        }
        _ => UlCrossAgentDispatchDecision::RefuseRedispatch,
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools)]
pub struct UlCrossAgentDirectionEvidence {
    pub direction: UlCrossAgentDirection,
    pub prewrite_control_marker_absent: bool,
    pub writer_canonical_write_succeeded: bool,
    pub writer_memory_has_exact_cue: bool,
    pub treatment_recovered_exact_marker: bool,
    pub treatment_named_exact_handle: bool,
    pub treatment_used_allowed_delivery_surface: bool,
    pub treatment_applicability_exact: bool,
    pub treatment_first_action_exact: bool,
    pub treatment_has_valid_influence_receipt: bool,
    pub memory_free_control_marker_absent: bool,
    pub no_input_contamination: bool,
    pub no_cross_scope_leakage: bool,
    pub truth_revision_changed_only_for_candidate: bool,
    pub candidate_stayed_candidate_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentScoreCheck {
    pub name: String,
    pub passed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentDirectionScore {
    pub direction: UlCrossAgentDirection,
    pub passed: bool,
    pub checks: Vec<UlCrossAgentScoreCheck>,
}

impl UlCrossAgentDirectionEvidence {
    #[must_use]
    pub fn score(&self) -> UlCrossAgentDirectionScore {
        let checks = [
            (
                "prewrite_control_marker_absent",
                self.prewrite_control_marker_absent,
            ),
            (
                "writer_canonical_write_succeeded",
                self.writer_canonical_write_succeeded,
            ),
            (
                "writer_memory_has_exact_cue",
                self.writer_memory_has_exact_cue,
            ),
            (
                "treatment_recovered_exact_marker",
                self.treatment_recovered_exact_marker,
            ),
            (
                "treatment_named_exact_handle",
                self.treatment_named_exact_handle,
            ),
            (
                "treatment_used_allowed_delivery_surface",
                self.treatment_used_allowed_delivery_surface,
            ),
            (
                "treatment_applicability_exact",
                self.treatment_applicability_exact,
            ),
            (
                "treatment_first_action_exact",
                self.treatment_first_action_exact,
            ),
            (
                "treatment_has_valid_influence_receipt",
                self.treatment_has_valid_influence_receipt,
            ),
            (
                "memory_free_control_marker_absent",
                self.memory_free_control_marker_absent,
            ),
            ("no_input_contamination", self.no_input_contamination),
            ("no_cross_scope_leakage", self.no_cross_scope_leakage),
            (
                "truth_revision_changed_only_for_candidate",
                self.truth_revision_changed_only_for_candidate,
            ),
            (
                "candidate_stayed_candidate_only",
                self.candidate_stayed_candidate_only,
            ),
        ]
        .into_iter()
        .map(|(name, passed)| UlCrossAgentScoreCheck {
            name: name.to_owned(),
            passed,
        })
        .collect::<Vec<_>>();
        UlCrossAgentDirectionScore {
            direction: self.direction,
            passed: checks.iter().all(|check| check.passed),
            checks,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UlCrossAgentReport {
    pub schema_version: String,
    pub run_id: String,
    pub project_id: ProjectId,
    pub provider_call_count: u8,
    pub hard_provider_call_cap: u8,
    pub direction_a: UlCrossAgentDirectionScore,
    pub direction_b: UlCrossAgentDirectionScore,
    pub unknown_outcome_calls: Vec<String>,
    pub passed: bool,
}

impl UlCrossAgentReport {
    #[must_use]
    pub fn from_evidence(
        run_id: impl Into<String>,
        project_id: ProjectId,
        provider_call_count: u8,
        direction_a: &UlCrossAgentDirectionEvidence,
        direction_b: &UlCrossAgentDirectionEvidence,
        unknown_outcome_calls: Vec<String>,
    ) -> Self {
        let direction_a = direction_a.score();
        let direction_b = direction_b.score();
        let passed = usize::from(provider_call_count) == UL_CROSS_AGENT_EXACT_CALLS
            && direction_a.passed
            && direction_b.passed
            && unknown_outcome_calls.is_empty();
        Self {
            schema_version: UL_CROSS_AGENT_REPORT_SCHEMA_VERSION.to_owned(),
            run_id: run_id.into(),
            project_id,
            provider_call_count,
            hard_provider_call_cap: UL_CROSS_AGENT_EXACT_CALLS_U8,
            direction_a,
            direction_b,
            unknown_outcome_calls,
            passed,
        }
    }
}
