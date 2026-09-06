//! Provider-neutral dream-job intake contract.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Owns the closed job/requester schema, intrinsic identity and bounds
//! validation, and the authority-separation markers consumed by brief owners.
//! Owns no bundle assembly, grounding, screening, handler, runtime,
//! authority, effect, or finish behavior.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use eliot_contracts::StateFence;

use crate::budget::BudgetLimits;
use crate::error::{ContractViolation, check_fence, check_text, is_hex64_lower};

/// Exact wire `schema_version` admitted by [`DreamJobInput`].
pub const DREAM_JOB_SCHEMA_VERSION: u32 = 1;

/// Canonical kind marker owned by the architecture-brief surface.
pub const ARCHITECTURE_BRIEF_KIND: &str = "architecture_brief";
/// Canonical kind marker owned by the implementation-brief surface.
pub const IMPLEMENTATION_BRIEF_KIND: &str = "implementation_brief";

/// Admitted `privacy_profile` spelling for host-local handling.
pub const PRIVACY_LOCAL_ONLY: &str = "local_only";
/// Admitted `privacy_profile` spelling for governed external handling.
pub const PRIVACY_GOVERNED_EXTERNAL: &str = "governed_external";

/// Closed dream-job class. No open `Other` variant: unknown spellings are
/// rejected at the boundary so a job can never be misrouted silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum JobClass {
    /// Orientation output; self-contained, requires no later output.
    #[serde(rename = "orientation")]
    Orientation,
    /// Memory-curation proposal work.
    #[serde(rename = "curation")]
    Curation,
    /// Clarification exchange work.
    #[serde(rename = "clarification")]
    Clarification,
    /// Research-synthesis work.
    #[serde(rename = "research_synthesis")]
    ResearchSynthesis,
    /// Architecture self-query work.
    #[serde(rename = "architecture_self_query")]
    ArchitectureSelfQuery,
    /// Development-diagnosis work.
    #[serde(rename = "development_diagnosis")]
    DevelopmentDiagnosis,
    /// Maintenance-planning work.
    #[serde(rename = "maintenance")]
    Maintenance,
    /// Orchestration-planning work.
    #[serde(rename = "orchestration_planning")]
    OrchestrationPlanning,
    /// Configuration-assistance work; a first-class class, never an alias.
    #[serde(rename = "configuration_assistance")]
    ConfigurationAssistance,
}

impl JobClass {
    /// Returns the exact wire spelling of this class.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Orientation => "orientation",
            Self::Curation => "curation",
            Self::Clarification => "clarification",
            Self::ResearchSynthesis => "research_synthesis",
            Self::ArchitectureSelfQuery => "architecture_self_query",
            Self::DevelopmentDiagnosis => "development_diagnosis",
            Self::Maintenance => "maintenance",
            Self::OrchestrationPlanning => "orchestration_planning",
            Self::ConfigurationAssistance => "configuration_assistance",
        }
    }
}

/// Parses an exact wire spelling into a [`JobClass`], rejecting anything
/// else (including `"other"`, `"Other"`, and `""`) as fail-closed.
pub fn parse_job_class(value: &str) -> Result<JobClass, ContractViolation> {
    match value {
        "orientation" => Ok(JobClass::Orientation),
        "curation" => Ok(JobClass::Curation),
        "clarification" => Ok(JobClass::Clarification),
        "research_synthesis" => Ok(JobClass::ResearchSynthesis),
        "architecture_self_query" => Ok(JobClass::ArchitectureSelfQuery),
        "development_diagnosis" => Ok(JobClass::DevelopmentDiagnosis),
        "maintenance" => Ok(JobClass::Maintenance),
        "orchestration_planning" => Ok(JobClass::OrchestrationPlanning),
        "configuration_assistance" => Ok(JobClass::ConfigurationAssistance),
        _ => Err(ContractViolation::UnknownVariant {
            field: "job_class",
            value: value.to_owned(),
        }),
    }
}

/// Closed requester origin. Model text can never rewrite this value: it is
/// bound at intake and carried verbatim through the candidate pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum RequesterOrigin {
    /// A human principal.
    #[serde(rename = "human")]
    Human,
    /// An explicitly admitted agent principal.
    #[serde(rename = "admitted_agent")]
    AdmittedAgent,
    /// A schedule-policy principal.
    #[serde(rename = "schedule_policy")]
    SchedulePolicy,
}

impl RequesterOrigin {
    /// Returns the exact wire spelling of this origin.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::AdmittedAgent => "admitted_agent",
            Self::SchedulePolicy => "schedule_policy",
        }
    }
}

/// Parses an exact wire spelling into a [`RequesterOrigin`], rejecting
/// anything else as fail-closed.
pub fn parse_requester_origin(value: &str) -> Result<RequesterOrigin, ContractViolation> {
    match value {
        "human" => Ok(RequesterOrigin::Human),
        "admitted_agent" => Ok(RequesterOrigin::AdmittedAgent),
        "schedule_policy" => Ok(RequesterOrigin::SchedulePolicy),
        _ => Err(ContractViolation::UnknownVariant {
            field: "requester_origin",
            value: value.to_owned(),
        }),
    }
}

/// Authenticated requester binding carried with every dream job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Requester {
    /// Closed origin bound at intake; never rewritten by model text.
    pub origin: RequesterOrigin,
    /// Non-blank principal identity, at most 256 bytes.
    pub principal: String,
    /// Optional caller session binding.
    pub session: Option<String>,
}

impl Requester {
    /// Validates the requester binding without I/O or policy lookup.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.principal, "requester.principal", 256)?;
        if let Some(session) = &self.session {
            check_text(session, "requester.session", 256)?;
        }
        Ok(())
    }
}

/// Canonical closed intake record for one dream job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DreamJobInput {
    /// Wire schema version; must be exactly [`DREAM_JOB_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Closed job class selecting the owning brief/handler surface.
    pub job_class: JobClass,
    /// Authenticated requester binding.
    pub requester: Requester,
    /// Non-blank operation identity, at most 128 bytes.
    pub operation_id: String,
    /// Non-blank idempotency identity, at most 128 bytes.
    pub idempotency_key: String,
    /// Non-blank task binding, at most 256 bytes.
    pub task_id: String,
    /// Non-blank scope binding, at most 256 bytes.
    pub scope_id: String,
    /// Dependency-only state fence captured before external work.
    pub state_fence: StateFence,
    /// Exactly `"local_only"` or `"governed_external"`.
    pub privacy_profile: String,
    /// Non-blank contract reference, at most 512 bytes.
    pub contract_ref: String,
    /// Non-blank policy reference, at most 512 bytes.
    pub policy_ref: String,
    /// Independent per-dimension budget limits.
    pub budget: BudgetLimits,
    /// Optional wall-clock deadline in Unix milliseconds.
    pub deadline_ms: Option<u64>,
    /// Lowercase SHA-256 hex digest of the frozen input manifest.
    pub frozen_manifest_digest: String,
}

impl DreamJobInput {
    /// Validates every intrinsic bound. Protected identity fields must be
    /// explicit: a defaulted `schema_version` or a missing digest is
    /// rejected rather than repaired.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if self.schema_version == 0 {
            return Err(ContractViolation::ImplicitDefault("schema_version"));
        }
        if self.schema_version != DREAM_JOB_SCHEMA_VERSION {
            return Err(ContractViolation::BindingMismatch {
                field: "schema_version",
                reason: std::format!(
                    "expected schema_version {DREAM_JOB_SCHEMA_VERSION}, got {}",
                    self.schema_version
                ),
            });
        }
        self.requester.validate()?;
        check_text(&self.operation_id, "operation_id", 128)?;
        check_text(&self.idempotency_key, "idempotency_key", 128)?;
        check_text(&self.task_id, "task_id", 256)?;
        check_text(&self.scope_id, "scope_id", 256)?;
        check_text(&self.contract_ref, "contract_ref", 512)?;
        check_text(&self.policy_ref, "policy_ref", 512)?;
        let profile = self.privacy_profile.as_str();
        if profile != PRIVACY_LOCAL_ONLY && profile != PRIVACY_GOVERNED_EXTERNAL {
            return Err(ContractViolation::BindingMismatch {
                field: "privacy_profile",
                reason: std::format!(
                    "must be one of {PRIVACY_LOCAL_ONLY:?} or {PRIVACY_GOVERNED_EXTERNAL:?}, got {:?}",
                    self.privacy_profile
                ),
            });
        }
        if self.frozen_manifest_digest.is_empty() {
            return Err(ContractViolation::MissingField("frozen_manifest_digest"));
        }
        if !is_hex64_lower(&self.frozen_manifest_digest) {
            return Err(ContractViolation::BindingMismatch {
                field: "frozen_manifest_digest",
                reason: "must be 64 lowercase hex chars".to_owned(),
            });
        }
        check_fence(&self.state_fence)?;
        self.budget.validate()?;
        Ok(())
    }

    /// Returns the stable canonical identity of this job: the SHA-256 hex of
    /// the canonical JSON bytes of `(job_class, operation_id, scope_id)`.
    /// Never panics; canonicalization of these owned strings is infallible
    /// in practice and falls back to a delimited preimage on error.
    pub fn canonical_id(&self) -> String {
        #[derive(Serialize)]
        struct CanonicalIdParts<'a> {
            job_class: JobClass,
            operation_id: &'a str,
            scope_id: &'a str,
        }
        let parts = CanonicalIdParts {
            job_class: self.job_class,
            operation_id: &self.operation_id,
            scope_id: &self.scope_id,
        };
        if let Ok(bytes) = eliot_contracts::canonical_json_bytes(&parts) {
            eliot_contracts::sha256_hex(&bytes)
        } else {
            let fallback = std::format!(
                "{}|{}|{}",
                self.job_class.as_str(),
                self.operation_id,
                self.scope_id
            );
            eliot_contracts::sha256_hex(fallback.as_bytes())
        }
    }
}

/// Reports whether an orientation job is self-contained: orientation output
/// requires no later output, every other class requires downstream work.
pub fn orientation_is_self_contained(job: &DreamJobInput) -> bool {
    matches!(job.job_class, JobClass::Orientation)
}

/// Marker proving the architecture-brief surface is distinct from the
/// implementation-brief surface. Carries no content and no authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ArchitectureBriefMarker;

impl ArchitectureBriefMarker {
    /// Canonical kind owned by the architecture-brief surface.
    pub const KIND: &'static str = ARCHITECTURE_BRIEF_KIND;
}

/// Marker proving the implementation-brief surface is distinct from the
/// architecture-brief surface. Carries no content and no authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ImplementationBriefMarker;

impl ImplementationBriefMarker {
    /// Canonical kind owned by the implementation-brief surface.
    pub const KIND: &'static str = IMPLEMENTATION_BRIEF_KIND;
}

/// Returns true exactly when the two brief kinds differ, proving the
/// authority separation between brief surfaces.
pub fn brief_kinds_distinct() -> bool {
    ARCHITECTURE_BRIEF_KIND != IMPLEMENTATION_BRIEF_KIND
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration};

    fn sample_job() -> DreamJobInput {
        DreamJobInput {
            schema_version: DREAM_JOB_SCHEMA_VERSION,
            job_class: JobClass::Orientation,
            requester: Requester {
                origin: RequesterOrigin::Human,
                principal: "alice".to_owned(),
                session: None,
            },
            operation_id: "op-1".to_owned(),
            idempotency_key: "idem-1".to_owned(),
            task_id: "task-1".to_owned(),
            scope_id: "scope-1".to_owned(),
            state_fence: StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis()),
            privacy_profile: PRIVACY_LOCAL_ONLY.to_owned(),
            contract_ref: "contract-1".to_owned(),
            policy_ref: "policy-1".to_owned(),
            budget: BudgetLimits {
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
            },
            deadline_ms: None,
            frozen_manifest_digest: "0123456789abcdef".repeat(4),
        }
    }

    // WORK_UNIT_CASE: 578/1
    #[test]
    fn golden_nine_job_classes_with_exact_spellings() {
        let cases: [(JobClass, &str); 9] = [
            (JobClass::Orientation, "orientation"),
            (JobClass::Curation, "curation"),
            (JobClass::Clarification, "clarification"),
            (JobClass::ResearchSynthesis, "research_synthesis"),
            (JobClass::ArchitectureSelfQuery, "architecture_self_query"),
            (JobClass::DevelopmentDiagnosis, "development_diagnosis"),
            (JobClass::Maintenance, "maintenance"),
            (JobClass::OrchestrationPlanning, "orchestration_planning"),
            (
                JobClass::ConfigurationAssistance,
                "configuration_assistance",
            ),
        ];
        assert_eq!(cases.len(), 9);
        for (class, spelling) in cases {
            assert_eq!(class.as_str(), spelling);
            assert_eq!(parse_job_class(spelling).expect("known spelling"), class);
            let wire = serde_json::to_string(&class).expect("serialize class");
            assert_eq!(wire, std::format!("\"{spelling}\""));
            let back: JobClass = serde_json::from_str(&wire).expect("roundtrip class");
            assert_eq!(back, class);
        }
        let decoded: JobClass =
            serde_json::from_str("\"development_diagnosis\"").expect("decode spelling");
        assert_eq!(decoded, JobClass::DevelopmentDiagnosis);
    }

    // WORK_UNIT_CASE: 578/2
    #[test]
    fn configuration_assistance_is_first_class_not_alias() {
        let parsed =
            parse_job_class("configuration_assistance").expect("configuration assistance parses");
        assert_eq!(parsed, JobClass::ConfigurationAssistance);
        assert_eq!(parsed.as_str(), "configuration_assistance");
        let others = [
            JobClass::Orientation,
            JobClass::Curation,
            JobClass::Clarification,
            JobClass::ResearchSynthesis,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::Maintenance,
            JobClass::OrchestrationPlanning,
        ];
        assert_eq!(others.len(), 8);
        for other in others {
            assert_ne!(other, JobClass::ConfigurationAssistance);
            assert_ne!(other.as_str(), JobClass::ConfigurationAssistance.as_str());
            assert_ne!(
                parse_job_class(other.as_str()).expect("other parses"),
                JobClass::ConfigurationAssistance
            );
        }
    }

    // WORK_UNIT_CASE: 578/3
    #[test]
    fn brief_kinds_are_distinct() {
        assert_ne!(ARCHITECTURE_BRIEF_KIND, IMPLEMENTATION_BRIEF_KIND);
        assert_eq!(ARCHITECTURE_BRIEF_KIND, "architecture_brief");
        assert_eq!(IMPLEMENTATION_BRIEF_KIND, "implementation_brief");
        assert!(brief_kinds_distinct());
        assert_ne!(
            ArchitectureBriefMarker::KIND,
            ImplementationBriefMarker::KIND
        );
        assert_eq!(ArchitectureBriefMarker::KIND, ARCHITECTURE_BRIEF_KIND);
        assert_eq!(ImplementationBriefMarker::KIND, IMPLEMENTATION_BRIEF_KIND);
    }

    // WORK_UNIT_CASE: 578/4
    #[test]
    fn orientation_self_contained_while_others_are_not() {
        let mut job = sample_job();
        job.job_class = JobClass::Orientation;
        assert!(orientation_is_self_contained(&job));
        let others = [
            JobClass::Curation,
            JobClass::Clarification,
            JobClass::ResearchSynthesis,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::Maintenance,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ];
        for class in others {
            job.job_class = class;
            let alone = orientation_is_self_contained(&job);
            assert!(!alone, "{class:?} must require downstream work");
        }
    }

    // WORK_UNIT_CASE: 578/5
    #[test]
    fn all_requester_origins_survive_json_roundtrip() {
        let cases = [
            (RequesterOrigin::Human, "human"),
            (RequesterOrigin::AdmittedAgent, "admitted_agent"),
            (RequesterOrigin::SchedulePolicy, "schedule_policy"),
        ];
        for (origin, spelling) in cases {
            assert_eq!(origin.as_str(), spelling);
            let parsed = parse_requester_origin(spelling).expect("known origin");
            assert_eq!(parsed, origin);
            let requester = Requester {
                origin,
                principal: "alice@example".to_owned(),
                session: Some("session-7".to_owned()),
            };
            let wire = serde_json::to_string(&requester).expect("serialize requester");
            assert!(wire.contains(spelling));
            let back: Requester = serde_json::from_str(&wire).expect("roundtrip requester");
            assert_eq!(back.origin, origin);
            assert_eq!(back.principal, "alice@example");
            assert_eq!(back.session.as_deref(), Some("session-7"));
            back.validate().expect("valid requester");
        }
        let sessionless = Requester {
            origin: RequesterOrigin::SchedulePolicy,
            principal: "nightly-policy".to_owned(),
            session: None,
        };
        let wire = serde_json::to_string(&sessionless).expect("serialize sessionless");
        let back: Requester = serde_json::from_str(&wire).expect("roundtrip sessionless");
        assert_eq!(back.session, None);
        assert_eq!(back.principal, "nightly-policy");
    }

    // WORK_UNIT_CASE: 578/6
    #[test]
    fn unknown_job_spelling_missing_field_and_default_version_rejected() {
        for rejected in ["other", "Other", "", "ORIENTATION", "orientation "] {
            let err = parse_job_class(rejected).expect_err("must reject");
            match err {
                ContractViolation::UnknownVariant { field, value } => {
                    assert_eq!(field, "job_class");
                    assert_eq!(value, rejected);
                }
                other => panic!("wrong violation for {rejected:?}: {other:?}"),
            }
        }
        let wire = serde_json::to_string(&sample_job()).expect("serialize job");
        let without_class = wire.replace("\"job_class\":\"orientation\",", "");
        assert_ne!(without_class, wire);
        let err = serde_json::from_str::<DreamJobInput>(&without_class)
            .expect_err("missing job_class must fail");
        let msg = err.to_string();
        assert!(msg.contains("job_class"), "unexpected serde error: {err}");
        let mut defaulted = sample_job();
        defaulted.schema_version = 0;
        let err = defaulted.validate().expect_err("version 0 must fail");
        assert_eq!(err, ContractViolation::ImplicitDefault("schema_version"));
        let mut mismatched = sample_job();
        mismatched.schema_version = 2;
        let err = mismatched.validate().expect_err("version 2 must fail");
        match err {
            ContractViolation::BindingMismatch { field, .. } => {
                assert_eq!(field, "schema_version");
            }
            other => panic!("wrong violation for version 2: {other:?}"),
        }
    }

    // WORK_UNIT_CASE: 578/7
    #[test]
    fn task_scope_and_fence_survive_json_roundtrip() {
        let job = sample_job();
        assert!(job.validate().is_ok());
        let wire = serde_json::to_string(&job).expect("serialize job");
        let back: DreamJobInput = serde_json::from_str(&wire).expect("roundtrip job");
        assert_eq!(back.task_id, "task-1");
        assert_eq!(back.scope_id, "scope-1");
        assert_eq!(back.operation_id, "op-1");
        assert_eq!(back.idempotency_key, "idem-1");
        let back_fence = &back.state_fence;
        let job_fence = &job.state_fence;
        assert_eq!(back_fence.authority_epoch, job_fence.authority_epoch);
        assert_eq!(
            back_fence.resource_generation,
            job_fence.resource_generation
        );
        assert_eq!(back.state_fence.authority_epoch.value(), 1);
        assert_eq!(back.state_fence.resource_generation.value(), 1);
        assert!(back.validate().is_ok());
        assert_eq!(back.canonical_id(), job.canonical_id());
        assert_eq!(back.canonical_id().len(), 64);
        let mut bound_job = sample_job();
        bound_job.operation_id = "o".repeat(128);
        assert!(bound_job.validate().is_ok());
        bound_job.operation_id = "o".repeat(129);
        assert!(bound_job.validate().is_err());
        bound_job.operation_id = "bad\u{0}id".to_owned();
        assert!(bound_job.validate().is_err());
    }

    // WORK_UNIT_CASE: 578/9
    #[test]
    fn unknown_field_and_protected_default_rejected() {
        let wire = serde_json::to_string(&sample_job()).expect("serialize job");
        let with_extra = std::format!(
            "{},\"unexpected_probe_key\":true{}",
            wire.strip_suffix('}').expect("object json"),
            "}"
        );
        let err =
            serde_json::from_str::<DreamJobInput>(&with_extra).expect_err("extra key must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("unknown field"),
            "unexpected serde error: {err}"
        );
        let needle = std::format!("\"schema_version\":{DREAM_JOB_SCHEMA_VERSION}");
        let zeroed = wire.replace(&needle, "\"schema_version\":0");
        assert_ne!(zeroed, wire);
        let decoded: DreamJobInput = serde_json::from_str(&zeroed).expect("decodes");
        let valid = decoded.validate();
        let err = valid.expect_err("zero version must not validate");
        assert_eq!(err, ContractViolation::ImplicitDefault("schema_version"));
        let mut blank_digest = sample_job();
        blank_digest.frozen_manifest_digest.clear();
        let err = blank_digest.validate().expect_err("empty digest must fail");
        let want = ContractViolation::MissingField("frozen_manifest_digest");
        assert_eq!(err, want);
    }
}
