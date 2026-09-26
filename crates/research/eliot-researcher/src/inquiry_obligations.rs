//! Inquiry obligations and their compilation inputs (issue #1762, I21.5).
//!
//! An inquiry item is not a task description but a statement of what must become
//! true and what will show it. This module defines that statement: the
//! obligation, the acceptance-certificate kind that satisfies it, its typed
//! status, and the input bundle the existing deterministic `TaskGraphCompiler`
//! (I10.15) consumes.
//!
//! It defines **no work graph**. `TaskGraphCompilationInputs` is an input
//! bundle: it carries obligations, their dependencies and the profile binding
//! they compile under, and it issues no compilation receipt, no order, no
//! assignment, no lease, no schedule and no admission. A researcher-local
//! compiler would be a second work graph, which I21.5 forbids. Task-plan
//! ownership, staffing and execution coordination stay with the Task Controller,
//! the Agent Coordinator and the Governor.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;

use eliot_contracts::StateFence;

use crate::evidence_portfolio::{freeze, push_count, push_field, text};
use crate::inquiry_governance::{InquiryError, InquiryProtocolProfile};

/// Acceptance-certificate kind that satisfies one obligation (I21.5).
///
/// An obligation is satisfied by its certificate, never by a worker's report
/// that it is done, so the kind of certificate is part of the obligation itself
/// rather than a later annotation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcceptanceCertificateKind {
    /// A Kernel-checked proof.
    KernelCheckedProof,
    /// A reproducible build plus contract tests.
    ReproducibleBuildAndContractTests,
    /// Immutable inputs plus raw measurements.
    ImmutableInputsAndRawMeasurements,
    /// An exact source identity plus the exact passage.
    ExactSourceIdentityAndPassage,
    /// Protocol-compliance quality control plus the raw data.
    ProtocolComplianceQcAndRawData,
    /// An accepted evidence revision plus an authority signature.
    AcceptedEvidenceRevisionAndAuthoritySignature,
}

impl AcceptanceCertificateKind {
    /// Stable wire spelling of this certificate kind.
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

/// Typed status of one obligation (I21.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InquiryObligationStatus {
    /// Information-dependent; not yet expanded.
    Stub,
    /// Determined by current observations and ready to run.
    Ready,
    /// Currently executing.
    Running,
    /// Blocked by a named cause.
    Blocked,
    /// Submitted for its certificate.
    Submitted,
    /// Satisfied by an admitted certificate.
    Verified,
    /// Refused by its certificate.
    Rejected,
    /// Invalidated; the cause and spent resources are retained.
    Invalidated,
    /// Cancelled.
    Cancelled,
}

impl InquiryObligationStatus {
    /// Stable wire spelling of this status.
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

    /// Whether this status is terminal for the obligation.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Verified | Self::Rejected | Self::Invalidated | Self::Cancelled
        )
    }
}
/// Named constructor arguments for [`InquiryObligation::new`].
#[derive(Clone, Debug)]
pub struct InquiryObligationParams<'a> {
    /// Stable obligation identity.
    pub obligation_id: String,
    /// Parent question this obligation answers.
    pub parent_question: String,
    /// What must become true.
    pub goal: String,
    /// Profile revision this obligation belongs to.
    pub protocol_ref: String,
    /// Obligation identities this one depends on.
    pub dependencies: Vec<String>,
    /// Assumptions this obligation rests on.
    pub assumptions: Vec<String>,
    /// Certificate kind that satisfies this obligation.
    pub acceptance_certificate_kind: AcceptanceCertificateKind,
    /// Exact information boundary the work stays inside.
    pub information_boundary: String,
    /// Role accountable for the obligation.
    pub responsible_role: &'a str,
    /// Verifier that certifies the obligation.
    pub verifier: &'a str,
    /// Budget ceiling bound to the obligation.
    pub budget_units: u64,
    /// Condition that ends the obligation's work.
    pub stop_condition: &'a str,
    /// Typed status the obligation starts in.
    pub status: InquiryObligationStatus,
    /// Profile revision the obligation compiles under.
    pub profile: &'a InquiryProtocolProfile,
}
/// One inquiry obligation (I21.5).
///
/// An invalidated obligation is never deleted: it retains the invalidating
/// cause, the resources spent and any reusable artifacts, so that repeated
/// planning cost becomes visible instead of being paid twice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InquiryObligation {
    /// Stable obligation identity.
    pub obligation_id: String,
    /// Parent question this obligation answers.
    pub parent_question: String,
    /// What must become true.
    pub goal: String,
    /// Profile identity the obligation belongs to.
    pub profile_id: String,
    /// Profile revision the obligation belongs to.
    pub profile_revision: u64,
    /// Exact profile revision digest.
    pub profile_digest: String,
    /// Obligation identities this one depends on.
    pub dependencies: Vec<String>,
    /// Assumptions this obligation rests on.
    pub assumptions: Vec<String>,
    /// Certificate kind that satisfies this obligation.
    pub acceptance_certificate_kind: AcceptanceCertificateKind,
    /// Exact information boundary the work stays inside.
    pub information_boundary: String,
    /// Role accountable for the obligation.
    pub responsible_role: String,
    /// Verifier that certifies the obligation.
    pub verifier: String,
    /// Budget ceiling bound to the obligation.
    pub budget_units: u64,
    /// Condition that ends the obligation's work.
    pub stop_condition: String,
    /// Typed status.
    pub status: InquiryObligationStatus,
    /// Cause that invalidated the obligation, when it was invalidated.
    pub invalidated_by: Option<String>,
    /// Resources already spent on the obligation.
    pub resources_spent: u64,
    /// Reusable artifacts retained from the obligation.
    pub reusable_artifacts: Vec<String>,
    /// Conditions under which the obligation may be reopened.
    pub reopen_conditions: Vec<String>,
    /// State Fence the obligation was compiled under.
    pub state_fence: StateFence,
    /// Digest over the obligation shape.
    pub digest: String,
}

impl InquiryObligation {
    /// Compiles one obligation under an exact profile revision.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank identity, goal, boundary, role,
    /// verifier or stop condition, a zero budget, an empty dependency or
    /// assumption entry, and [`InquiryError::UnknownHandle`] when a dependency
    /// names the obligation itself.
    #[allow(clippy::too_many_arguments)]
    pub fn new(params: InquiryObligationParams<'_>) -> Result<Self, InquiryError> {
        text(&params.obligation_id, "obligation.obligation_id").map_err(InquiryError::from)?;
        text(&params.parent_question, "obligation.parent_question").map_err(InquiryError::from)?;
        text(&params.goal, "obligation.goal").map_err(InquiryError::from)?;
        text(
            &params.information_boundary,
            "obligation.information_boundary",
        )
        .map_err(InquiryError::from)?;
        text(params.responsible_role, "obligation.responsible_role").map_err(InquiryError::from)?;
        text(params.verifier, "obligation.verifier").map_err(InquiryError::from)?;
        text(params.stop_condition, "obligation.stop_condition").map_err(InquiryError::from)?;
        if params.budget_units == 0 {
            return Err(InquiryError::Blank {
                field: "obligation.budget_units",
            });
        }
        for dependency in &params.dependencies {
            text(dependency, "obligation.dependencies").map_err(InquiryError::from)?;
            if *dependency == params.obligation_id {
                return Err(InquiryError::UnknownHandle {
                    field: "obligation.dependencies",
                });
            }
        }
        for assumption in &params.assumptions {
            text(assumption, "obligation.assumptions").map_err(InquiryError::from)?;
        }
        let mut obligation = Self {
            obligation_id: params.obligation_id,
            parent_question: params.parent_question,
            goal: params.goal,
            profile_id: params.profile.profile_id.clone(),
            profile_revision: params.profile.revision,
            profile_digest: params.profile.integrity_digest.clone(),
            dependencies: params.dependencies,
            assumptions: params.assumptions,
            acceptance_certificate_kind: params.acceptance_certificate_kind,
            information_boundary: params.information_boundary,
            responsible_role: params.responsible_role.to_owned(),
            verifier: params.verifier.to_owned(),
            budget_units: params.budget_units,
            stop_condition: params.stop_condition.to_owned(),
            status: params.status,
            invalidated_by: None,
            resources_spent: 0,
            reusable_artifacts: Vec::new(),
            reopen_conditions: params
                .profile
                .output_contract
                .reopen_conditions
                .iter()
                .map(|condition| condition.wire_name().to_owned())
                .collect(),
            state_fence: params.profile.state_fence.clone(),
            digest: String::new(),
        };
        obligation.digest = obligation.compute_digest();
        Ok(obligation)
    }

    /// Whether this obligation is satisfied by an admitted certificate of its
    /// declared kind.
    ///
    /// A status is never enough on its own: only the certificate kind the
    /// obligation declared can verify it.
    #[must_use]
    pub fn is_verified_by_certificate(&self) -> bool {
        matches!(self.status, InquiryObligationStatus::Verified)
    }

    /// Retains the invalidating cause, the resources spent and the reusable
    /// artifacts of an invalidated obligation.
    ///
    /// # Errors
    ///
    /// Returns a field error for a blank cause and
    /// [`InquiryError::UnknownHandle`] when the obligation is not in a state
    /// that may be invalidated.
    pub fn invalidate(
        &mut self,
        cause: &str,
        resources_spent: u64,
        reusable_artifacts: Vec<String>,
    ) -> Result<(), InquiryError> {
        text(cause, "obligation.invalidated_by").map_err(InquiryError::from)?;
        if self.status == InquiryObligationStatus::Verified {
            return Err(InquiryError::UnknownHandle {
                field: "obligation.status",
            });
        }
        for artifact in &reusable_artifacts {
            text(artifact, "obligation.reusable_artifacts").map_err(InquiryError::from)?;
        }
        self.invalidated_by = Some(cause.to_owned());
        self.resources_spent = resources_spent;
        self.reusable_artifacts = reusable_artifacts;
        self.status = InquiryObligationStatus::Invalidated;
        self.digest = self.compute_digest();
        Ok(())
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("inquiry-obligation/v1;");
        push_field(&mut preimage, "obligation_id", &self.obligation_id);
        push_field(&mut preimage, "parent_question", &self.parent_question);
        push_field(&mut preimage, "goal", &self.goal);
        push_field(&mut preimage, "profile_id", &self.profile_id);
        push_field(
            &mut preimage,
            "profile_revision",
            &self.profile_revision.to_string(),
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        for (tag, values) in [
            ("dependency", &self.dependencies),
            ("assumption", &self.assumptions),
            ("reopen_condition", &self.reopen_conditions),
            ("reusable_artifact", &self.reusable_artifacts),
        ] {
            push_count(&mut preimage, tag, values.len());
            for value in values {
                push_field(&mut preimage, tag, value);
            }
        }
        push_field(
            &mut preimage,
            "acceptance_certificate_kind",
            self.acceptance_certificate_kind.wire_name(),
        );
        push_field(
            &mut preimage,
            "information_boundary",
            &self.information_boundary,
        );
        push_field(&mut preimage, "responsible_role", &self.responsible_role);
        push_field(&mut preimage, "verifier", &self.verifier);
        push_field(
            &mut preimage,
            "budget_units",
            &self.budget_units.to_string(),
        );
        push_field(&mut preimage, "stop_condition", &self.stop_condition);
        push_field(&mut preimage, "status", self.status.wire_name());
        if let Some(cause) = &self.invalidated_by {
            push_field(&mut preimage, "invalidated_by", cause);
        }
        push_field(
            &mut preimage,
            "resources_spent",
            &self.resources_spent.to_string(),
        );
        freeze(&preimage)
    }

    /// Re-proves this obligation's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.compute_digest() != self.digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "obligation.digest",
            });
        }
        Ok(())
    }
}

/// Compilation inputs for the existing `TaskGraphCompiler` owner (I21.5/I10.15).
///
/// This is an input bundle and nothing else. The deterministic compiler that
/// turns obligations into work-graph nodes is the existing `TaskGraphCompiler`;
/// it owns the graph, the order, the assignment and the admission. This bundle
/// carries the obligations, the exact profile revision and evidence set they
/// compile under, and the declared reopen conditions, so the owner can decide
/// what is materialisable. It issues no receipt and grants no authority, which
/// is why it can be published without introducing a second work graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskGraphCompilationInputs {
    /// Inquiry identity the obligations belong to.
    pub inquiry_id: String,
    /// Evidence-set identity the obligations were compiled from.
    pub evidence_set_id: String,
    /// Profile identity the obligations compile under.
    pub profile_id: String,
    /// Profile revision the obligations compile under.
    pub profile_revision: u64,
    /// Exact profile revision digest.
    pub profile_digest: String,
    /// Obligations in canonical order.
    pub obligations: Vec<InquiryObligation>,
    /// Reopen conditions the profile declares for this inquiry.
    pub reopen_conditions: BTreeSet<String>,
    /// State Fence the compilation inputs were produced under.
    pub state_fence: StateFence,
    /// Always true: compilation inputs are candidate material.
    pub candidate_only: bool,
    /// Always false: the compiler owner, not this domain, admits work.
    pub canonical_write_authorized: bool,
    /// Digest over the input bundle.
    pub digest: String,
}

impl TaskGraphCompilationInputs {
    /// Assembles the compilation inputs for one inquiry.
    ///
    /// # Errors
    ///
    /// Returns a field error when the evidence-set identity is blank, and
    /// [`InquiryError::UnknownHandle`] when an obligation was compiled under a
    /// different profile revision or a different inquiry.
    pub fn for_inquiry(
        profile: &InquiryProtocolProfile,
        evidence_set_id: &str,
        obligations: &[InquiryObligation],
    ) -> Result<Self, InquiryError> {
        text(evidence_set_id, "compilation.evidence_set_id").map_err(InquiryError::from)?;
        for obligation in obligations {
            if obligation.profile_digest != profile.integrity_digest {
                return Err(InquiryError::UnknownHandle {
                    field: "compilation.obligation_profile",
                });
            }
        }
        let mut sorted = obligations.to_vec();
        sorted.sort_by(|left, right| left.obligation_id.cmp(&right.obligation_id));
        let reopen_conditions = profile
            .output_contract
            .reopen_conditions
            .iter()
            .map(|condition| condition.wire_name().to_owned())
            .collect::<BTreeSet<String>>();
        let mut inputs = Self {
            inquiry_id: profile.inquiry_id.clone(),
            evidence_set_id: evidence_set_id.to_owned(),
            profile_id: profile.profile_id.clone(),
            profile_revision: profile.revision,
            profile_digest: profile.integrity_digest.clone(),
            obligations: sorted,
            reopen_conditions,
            state_fence: profile.state_fence.clone(),
            candidate_only: true,
            canonical_write_authorized: false,
            digest: String::new(),
        };
        inputs.digest = inputs.compute_digest();
        Ok(inputs)
    }

    /// Obligation identities that are materialisable from current observations.
    ///
    /// A terminal obligation is never materialisable again, and an
    /// information-dependent `Stub` is not materialisable until the upstream
    /// result arrives.
    #[must_use]
    pub fn materialisable(&self) -> Vec<&str> {
        self.obligations
            .iter()
            .filter(|obligation| {
                !obligation.status.is_terminal()
                    && matches!(
                        obligation.status,
                        InquiryObligationStatus::Ready
                            | InquiryObligationStatus::Running
                            | InquiryObligationStatus::Submitted
                    )
            })
            .map(|obligation| obligation.obligation_id.as_str())
            .collect()
    }

    /// Obligation identities that remain information-dependent.
    #[must_use]
    pub fn deferred(&self) -> Vec<&str> {
        self.obligations
            .iter()
            .filter(|obligation| obligation.status == InquiryObligationStatus::Stub)
            .map(|obligation| obligation.obligation_id.as_str())
            .collect()
    }

    fn compute_digest(&self) -> String {
        let mut preimage = String::from("task-graph-compilation-inputs/v1;");
        push_field(&mut preimage, "inquiry_id", &self.inquiry_id);
        push_field(&mut preimage, "evidence_set_id", &self.evidence_set_id);
        push_field(&mut preimage, "profile_id", &self.profile_id);
        push_field(
            &mut preimage,
            "profile_revision",
            &self.profile_revision.to_string(),
        );
        push_field(&mut preimage, "profile_digest", &self.profile_digest);
        push_count(&mut preimage, "obligations", self.obligations.len());
        for obligation in &self.obligations {
            push_field(&mut preimage, "obligation_id", &obligation.obligation_id);
            push_field(&mut preimage, "obligation_digest", &obligation.digest);
            push_field(
                &mut preimage,
                "obligation_status",
                obligation.status.wire_name(),
            );
            push_field(
                &mut preimage,
                "obligation_certificate_kind",
                obligation.acceptance_certificate_kind.wire_name(),
            );
            push_field(
                &mut preimage,
                "obligation_information_boundary",
                &obligation.information_boundary,
            );
            push_field(
                &mut preimage,
                "obligation_responsible_role",
                &obligation.responsible_role,
            );
            push_field(&mut preimage, "obligation_verifier", &obligation.verifier);
            push_count(
                &mut preimage,
                "obligation_dependencies",
                obligation.dependencies.len(),
            );
            for dependency in &obligation.dependencies {
                push_field(&mut preimage, "obligation_dependency", dependency);
            }
        }
        push_count(
            &mut preimage,
            "reopen_conditions",
            self.reopen_conditions.len(),
        );
        for condition in &self.reopen_conditions {
            push_field(&mut preimage, "reopen_condition", condition);
        }
        freeze(&preimage)
    }

    /// Re-proves this input bundle's own digest.
    ///
    /// # Errors
    ///
    /// Returns [`InquiryError::IntegrityMismatch`] when the recomputed digest
    /// disagrees with the stored one, or when a nested obligation's own digest
    /// does not match.
    pub fn validate_integrity(&self) -> Result<(), InquiryError> {
        if self.compute_digest() != self.digest {
            return Err(InquiryError::IntegrityMismatch {
                field: "compilation.digest",
            });
        }
        for obligation in &self.obligations {
            obligation.validate_integrity()?;
            if obligation.profile_digest != self.profile_digest
                || obligation.state_fence != self.state_fence
            {
                return Err(InquiryError::IntegrityMismatch {
                    field: "compilation.obligation_binding",
                });
            }
        }
        Ok(())
    }
}
