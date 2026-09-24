//! Typed inquiry obligations and the narrow existing-work-graph port.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::StateFence;

use super::inquiry_governance::{
    InquiryGovernanceError, InquiryProtocolProfile, digest, freeze, push_count, push_field, text,
    unique_texts,
};

/// The certificate kind required to satisfy an obligation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptanceCertificateKind {
    KernelCheckedProof,
    ReproducibleBuildAndContractTests,
    ImmutableInputsAndRawMeasurements,
    ExactSourceIdentityAndPassage,
    ProtocolComplianceQcAndRawData,
    AcceptedEvidenceRevisionAndAuthoritySignature,
}

impl AcceptanceCertificateKind {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::KernelCheckedProof => "kernel_checked_proof",
            Self::ReproducibleBuildAndContractTests => "reproducible_build_and_contract_tests",
            Self::ImmutableInputsAndRawMeasurements => "immutable_inputs_and_raw_measurements",
            Self::ExactSourceIdentityAndPassage => "exact_source_identity_and_passage",
            Self::ProtocolComplianceQcAndRawData => "protocol_compliance_qc_and_raw_data",
            Self::AcceptedEvidenceRevisionAndAuthoritySignature => {
                "accepted_evidence_revision_and_authority_signature"
            }
        }
    }
}

/// Obligation lifecycle status from I21.5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InquiryObligationStatus {
    Stub,
    Ready,
    Running,
    Blocked,
    Submitted,
    Verified,
    Rejected,
    Invalidated,
    Cancelled,
}

impl InquiryObligationStatus {
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Stub => "STUB",
            Self::Ready => "READY",
            Self::Running => "RUNNING",
            Self::Blocked => "BLOCKED",
            Self::Submitted => "SUBMITTED",
            Self::Verified => "VERIFIED",
            Self::Rejected => "REJECTED",
            Self::Invalidated => "INVALIDATED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

/// A certificate is the only evidence that can verify an obligation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptanceCertificate {
    pub certificate_id: String,
    pub obligation_id: String,
    pub profile_digest: String,
    pub kind: AcceptanceCertificateKind,
    pub state_fence: StateFence,
    pub issuer: String,
    pub digest: String,
}

impl AcceptanceCertificate {
    pub fn new(
        certificate_id: impl Into<String>,
        obligation_id: impl Into<String>,
        profile_digest: impl Into<String>,
        kind: AcceptanceCertificateKind,
        state_fence: StateFence,
        issuer: impl Into<String>,
    ) -> Result<Self, InquiryGovernanceError> {
        let certificate_id = certificate_id.into();
        let obligation_id = obligation_id.into();
        let profile_digest = profile_digest.into();
        let issuer = issuer.into();
        text(&certificate_id, "certificate.certificate_id")?;
        text(&obligation_id, "certificate.obligation_id")?;
        digest(&profile_digest, "certificate.profile_digest")?;
        text(&issuer, "certificate.issuer")?;
        state_fence
            .validate()
            .map_err(|_| InquiryGovernanceError::InvalidField {
                field: "certificate.state_fence",
            })?;
        let mut p = String::from("inquiry-acceptance-certificate/v1;");
        push_field(&mut p, "certificate_id", &certificate_id);
        push_field(&mut p, "obligation_id", &obligation_id);
        push_field(&mut p, "profile_digest", &profile_digest);
        push_field(&mut p, "kind", kind.wire_name());
        push_field(&mut p, "issuer", &issuer);
        let digest = freeze(&p);
        Ok(Self {
            certificate_id,
            obligation_id,
            profile_digest,
            kind,
            state_fence,
            issuer,
            digest,
        })
    }
}

/// Caller-supplied obligation fields before profile binding/validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryObligationInput {
    pub obligation_id: String,
    pub parent_question: String,
    pub goal: String,
    pub protocol_ref: String,
    pub dependencies: Vec<String>,
    pub assumptions: Vec<String>,
    pub acceptance_certificate_kind: AcceptanceCertificateKind,
    pub information_boundary: String,
    pub responsible_role: String,
    pub verifier: String,
    pub budget_units: u64,
    pub stop_condition: String,
    pub status: InquiryObligationStatus,
    pub certificate: Option<AcceptanceCertificate>,
    pub invalidated_by: Option<String>,
    pub resources_spent: u64,
    pub reusable_artifacts: Vec<String>,
    pub reopen_conditions: Vec<String>,
}

/// A validated obligation bound to one exact profile revision.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryObligation {
    pub obligation_id: String,
    pub parent_question: String,
    pub goal: String,
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub dependencies: Vec<String>,
    pub assumptions: Vec<String>,
    pub acceptance_certificate_kind: AcceptanceCertificateKind,
    pub information_boundary: String,
    pub responsible_role: String,
    pub verifier: String,
    pub budget_units: u64,
    pub stop_condition: String,
    pub status: InquiryObligationStatus,
    pub certificate: Option<AcceptanceCertificate>,
    pub invalidated_by: Option<String>,
    pub resources_spent: u64,
    pub reusable_artifacts: Vec<String>,
    pub reopen_conditions: Vec<String>,
    pub digest: String,
}

impl InquiryObligation {
    #[allow(clippy::too_many_lines)]
    fn from_input(
        mut input: InquiryObligationInput,
        profile: &InquiryProtocolProfile,
    ) -> Result<Self, InquiryGovernanceError> {
        text(&input.obligation_id, "obligation.obligation_id")?;
        text(&input.parent_question, "obligation.parent_question")?;
        text(&input.goal, "obligation.goal")?;
        digest(&input.protocol_ref, "obligation.protocol_ref")?;
        if input.protocol_ref != profile.digest {
            return Err(InquiryGovernanceError::InvalidObligation {
                obligation_id: input.obligation_id,
                reason: "protocol_ref does not bind the profile digest",
            });
        }
        if input.parent_question != profile.question {
            return Err(InquiryGovernanceError::InvalidObligation {
                obligation_id: input.obligation_id,
                reason: "parent_question does not bind the profile question",
            });
        }
        unique_texts(&input.dependencies, "obligation.dependencies")?;
        unique_texts(&input.assumptions, "obligation.assumptions")?;
        text(
            &input.information_boundary,
            "obligation.information_boundary",
        )?;
        text(&input.responsible_role, "obligation.responsible_role")?;
        text(&input.verifier, "obligation.verifier")?;
        if input.budget_units == 0 {
            return Err(InquiryGovernanceError::InvalidObligation {
                obligation_id: input.obligation_id,
                reason: "budget_units must be positive",
            });
        }
        text(&input.stop_condition, "obligation.stop_condition")?;
        unique_texts(&input.reusable_artifacts, "obligation.reusable_artifacts")?;
        unique_texts(&input.reopen_conditions, "obligation.reopen_conditions")?;
        input.dependencies.sort();
        input.assumptions.sort();
        input.reusable_artifacts.sort();
        input.reopen_conditions.sort();
        if input.status == InquiryObligationStatus::Verified {
            let Some(certificate) = &input.certificate else {
                return Err(InquiryGovernanceError::InvalidObligation {
                    obligation_id: input.obligation_id,
                    reason: "VERIFIED requires an acceptance certificate",
                });
            };
            if certificate.obligation_id != input.obligation_id
                || certificate.profile_digest != profile.digest
                || certificate.kind != input.acceptance_certificate_kind
                || certificate.state_fence != profile.state_fence
            {
                return Err(InquiryGovernanceError::InvalidObligation {
                    obligation_id: input.obligation_id,
                    reason: "certificate does not bind obligation/profile/fence",
                });
            }
        }
        if input.status == InquiryObligationStatus::Invalidated {
            let Some(reason) = &input.invalidated_by else {
                return Err(InquiryGovernanceError::InvalidObligation {
                    obligation_id: input.obligation_id,
                    reason: "INVALIDATED requires a cause",
                });
            };
            text(reason, "obligation.invalidated_by")?;
        }
        let mut p = String::from("inquiry-obligation/v1;");
        push_field(&mut p, "obligation_id", &input.obligation_id);
        push_field(&mut p, "parent_question", &input.parent_question);
        push_field(&mut p, "goal", &input.goal);
        push_field(&mut p, "profile_id", &profile.profile_id);
        push_field(&mut p, "profile_revision", &profile.revision.to_string());
        push_field(&mut p, "profile_digest", &profile.digest);
        push_count(&mut p, "dependencies", input.dependencies.len());
        for dependency in &input.dependencies {
            push_field(&mut p, "dependency", dependency);
        }
        push_count(&mut p, "assumptions", input.assumptions.len());
        for assumption in &input.assumptions {
            push_field(&mut p, "assumption", assumption);
        }
        push_field(
            &mut p,
            "certificate_kind",
            input.acceptance_certificate_kind.wire_name(),
        );
        push_field(&mut p, "information_boundary", &input.information_boundary);
        push_field(&mut p, "responsible_role", &input.responsible_role);
        push_field(&mut p, "verifier", &input.verifier);
        push_field(&mut p, "budget_units", &input.budget_units.to_string());
        push_field(&mut p, "stop_condition", &input.stop_condition);
        push_field(&mut p, "status", input.status.wire_name());
        if let Some(certificate) = &input.certificate {
            push_field(&mut p, "certificate_digest", &certificate.digest);
        }
        if let Some(reason) = &input.invalidated_by {
            push_field(&mut p, "invalidated_by", reason);
        }
        push_field(
            &mut p,
            "resources_spent",
            &input.resources_spent.to_string(),
        );
        push_count(&mut p, "reusable_artifacts", input.reusable_artifacts.len());
        for artifact in &input.reusable_artifacts {
            push_field(&mut p, "reusable_artifact", artifact);
        }
        push_count(&mut p, "reopen_conditions", input.reopen_conditions.len());
        for condition in &input.reopen_conditions {
            push_field(&mut p, "reopen_condition", condition);
        }
        let digest = freeze(&p);
        Ok(Self {
            obligation_id: input.obligation_id,
            parent_question: input.parent_question,
            goal: input.goal,
            profile_id: profile.profile_id.clone(),
            profile_revision: profile.revision,
            profile_digest: profile.digest.clone(),
            dependencies: input.dependencies,
            assumptions: input.assumptions,
            acceptance_certificate_kind: input.acceptance_certificate_kind,
            information_boundary: input.information_boundary,
            responsible_role: input.responsible_role,
            verifier: input.verifier,
            budget_units: input.budget_units,
            stop_condition: input.stop_condition,
            status: input.status,
            certificate: input.certificate,
            invalidated_by: input.invalidated_by,
            resources_spent: input.resources_spent,
            reusable_artifacts: input.reusable_artifacts,
            reopen_conditions: input.reopen_conditions,
            digest,
        })
    }

    #[must_use]
    pub fn is_verified_by_certificate(&self) -> bool {
        self.status == InquiryObligationStatus::Verified && self.certificate.is_some()
    }
}

/// Port implemented by the existing `TaskGraphCompiler`. It receives typed
/// obligations and does not expose a second graph owned by Researcher.
pub trait TaskGraphCompiler {
    fn compile(&mut self, obligations: &[InquiryObligation]) -> Result<(), InquiryGovernanceError>;
}

/// Receipt for consumption by the existing work-graph owner.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskGraphCompilationReceipt {
    pub compiler_id: String,
    pub profile_id: String,
    pub profile_revision: u64,
    pub profile_digest: String,
    pub obligation_ids: Vec<String>,
    pub state_fence: StateFence,
    pub candidate_only: bool,
    pub canonical_write_authorized: bool,
    pub digest: String,
}

impl TaskGraphCompilationReceipt {
    pub(crate) fn new(
        compiler_id: String,
        profile: &InquiryProtocolProfile,
        obligations: &[InquiryObligation],
    ) -> Result<Self, InquiryGovernanceError> {
        text(&compiler_id, "compiler.compiler_id")?;
        let mut obligation_ids = obligations
            .iter()
            .map(|item| item.obligation_id.clone())
            .collect::<Vec<_>>();
        obligation_ids.sort();
        let mut p = String::from("task-graph-obligation-compilation/v1;");
        push_field(&mut p, "compiler_id", &compiler_id);
        push_field(&mut p, "profile_id", &profile.profile_id);
        push_field(&mut p, "profile_revision", &profile.revision.to_string());
        push_field(&mut p, "profile_digest", &profile.digest);
        push_count(&mut p, "obligations", obligation_ids.len());
        for id in &obligation_ids {
            push_field(&mut p, "obligation", id);
        }
        let digest = freeze(&p);
        Ok(Self {
            compiler_id,
            profile_id: profile.profile_id.clone(),
            profile_revision: profile.revision,
            profile_digest: profile.digest.clone(),
            obligation_ids,
            state_fence: profile.state_fence.clone(),
            candidate_only: true,
            canonical_write_authorized: false,
            digest,
        })
    }
}

pub(crate) fn compile_obligation_inputs(
    profile: &InquiryProtocolProfile,
    inputs: &[InquiryObligationInput],
) -> Result<Vec<InquiryObligation>, InquiryGovernanceError> {
    if inputs.is_empty() {
        return Err(InquiryGovernanceError::InvalidObligation {
            obligation_id: "<set>".to_owned(),
            reason: "at least one obligation is required",
        });
    }
    let mut obligations = Vec::with_capacity(inputs.len());
    let mut ids = BTreeSet::new();
    for input in inputs {
        let obligation = InquiryObligation::from_input(input.clone(), profile)?;
        if !ids.insert(obligation.obligation_id.clone()) {
            return Err(InquiryGovernanceError::DuplicateIdentity {
                field: "obligation.obligation_id",
            });
        }
        obligations.push(obligation);
    }
    for obligation in &obligations {
        for dependency in &obligation.dependencies {
            if dependency == &obligation.obligation_id || !ids.contains(dependency) {
                return Err(InquiryGovernanceError::InvalidObligation {
                    obligation_id: obligation.obligation_id.clone(),
                    reason: "dependency is missing or self-referential",
                });
            }
        }
    }
    reject_cycles(&obligations)?;
    Ok(obligations)
}

#[allow(clippy::items_after_statements)]
fn reject_cycles(obligations: &[InquiryObligation]) -> Result<(), InquiryGovernanceError> {
    let mut marks = BTreeMap::<String, u8>::new();
    fn visit(
        id: &str,
        obligations: &[InquiryObligation],
        marks: &mut BTreeMap<String, u8>,
    ) -> Result<(), InquiryGovernanceError> {
        match marks.get(id) {
            Some(2) => return Ok(()),
            Some(1) => {
                return Err(InquiryGovernanceError::CircularDependency {
                    obligation_id: id.to_owned(),
                });
            }
            _ => {}
        }
        marks.insert(id.to_owned(), 1);
        let obligation = obligations
            .iter()
            .find(|item| item.obligation_id == id)
            .ok_or_else(|| InquiryGovernanceError::InvalidObligation {
                obligation_id: id.to_owned(),
                reason: "dependency does not resolve",
            })?;
        for dependency in &obligation.dependencies {
            visit(dependency, obligations, marks)?;
        }
        marks.insert(id.to_owned(), 2);
        Ok(())
    }
    for obligation in obligations {
        visit(&obligation.obligation_id, obligations, &mut marks)?;
    }
    Ok(())
}
