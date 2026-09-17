#![forbid(unsafe_code)]

//! Native owner dispatch for admitted Dreamer jobs (issue #702, Slice 7).
//!
//! After the Slice-A/1 admission dispatch admits a job class, this stage
//! resolves the exact native owner for one closed [`JobClass`] with no
//! fallthrough: Curation names the A-31 curation owner
//! (`eliot-dreamer-curation`), Orientation names `eliot-dreamer-orientation`
//! `build_projection`, and every other class names its native owner.
//! Exhaustive with no wildcard arm: extending the closed taxonomy breaks
//! compilation here until the new class is assigned an owning slice.
//!
//! Fail-closed: Curation is Slice-A refused, and the Governor-issued validated
//! draft that no in-binary port supplies yet is absent, so every path refuses
//! — refused classes with [`DreamerError::UnsupportedJobClass`], admitted
//! classes with [`DreamerError::InvalidAdmission`] naming the missing governed
//! draft. No leaf is invoked on any path: the resolver takes only the class,
//! and admitted outcomes run the [`dispatch_admitted_with`] `FnOnce` seam with
//! an awaiting-draft refusal, so there is no handle, port, transport, or draft
//! channel that could reach a leaf.

use eliot_dreamer_contracts::{ContractViolation, JobClass};

use crate::DreamerError;

/// Admitted dispatch outcome: exactly one per Slice-A admitted class.
///
/// Local to this stage to avoid coupling the dispatch table to the Slice-1
/// routing identities: refusal authority stays in Slice-A/1, this enum only
/// names which native owner an admitted job waits on.
#[allow(
    clippy::enum_variant_names,
    reason = "the Admitted postfix mirrors the Slice-1 ClassArm convention so admitted arms read identically at the dispatch site"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DispatchedOutcome {
    /// Orientation waits on `eliot-dreamer-orientation` `build_projection`.
    OrientationAdmitted,
    /// Research synthesis waits on its native research-synthesis owner.
    ResearchSynthesisAdmitted,
    /// Maintenance waits on its native maintenance owner.
    MaintenanceAdmitted,
}

/// Resolves the native owner for one closed job class, fail-closed.
///
/// Each of the nine classes names its exact native owner with no fallthrough.
/// The six Slice-A refused classes return
/// [`DreamerError::UnsupportedJobClass`] carrying their distinct class before
/// any Kernel-facing call. The three admitted classes bind their distinct
/// [`DispatchedOutcome`] and run the once-call owner seam, which refuses with
/// [`DreamerError::InvalidAdmission`] because the Governor-resolved validated
/// draft arrives through a source-owner port in a later slice: dispatching to
/// an unvalidated draft would be self-issued authority. Never invokes leaves
/// on any path.
pub(crate) fn dispatch_admitted_result(
    job_class: JobClass,
) -> Result<DispatchedOutcome, DreamerError> {
    let owner = match job_class {
        // Native owner: eliot-dreamer-curation (A-31). Slice-A refused.
        JobClass::Curation => {
            return Err(DreamerError::UnsupportedJobClass(JobClass::Curation));
        }
        // Native owner: maintenance/clarification owner. Slice-A refused.
        JobClass::Clarification => {
            return Err(DreamerError::UnsupportedJobClass(JobClass::Clarification));
        }
        // Native owner: architecture self-query owner. Slice-A refused.
        JobClass::ArchitectureSelfQuery => {
            return Err(DreamerError::UnsupportedJobClass(
                JobClass::ArchitectureSelfQuery,
            ));
        }
        // Native owner: development-diagnosis owner. Slice-A refused.
        JobClass::DevelopmentDiagnosis => {
            return Err(DreamerError::UnsupportedJobClass(
                JobClass::DevelopmentDiagnosis,
            ));
        }
        // Native owner: orchestration-planning owner. Slice-A refused.
        JobClass::OrchestrationPlanning => {
            return Err(DreamerError::UnsupportedJobClass(
                JobClass::OrchestrationPlanning,
            ));
        }
        // Native owner: configuration-assistance owner. Slice-A refused.
        JobClass::ConfigurationAssistance => {
            return Err(DreamerError::UnsupportedJobClass(
                JobClass::ConfigurationAssistance,
            ));
        }
        // Native owner: eliot-dreamer-orientation build_projection.
        JobClass::Orientation => DispatchedOutcome::OrientationAdmitted,
        // Native owner: research-synthesis owner.
        JobClass::ResearchSynthesis => DispatchedOutcome::ResearchSynthesisAdmitted,
        // Native owner: maintenance owner.
        JobClass::Maintenance => DispatchedOutcome::MaintenanceAdmitted,
    };
    dispatch_admitted_with(owner, |_| {
        Err::<DispatchedOutcome, _>(ContractViolation::MissingField(
            "admitted dispatch requires Governor-resolved validated draft",
        ))
    })
}

/// Runs the admitted native owner exactly once.
///
/// `dispatch_once` is `FnOnce`: the owner entrypoint cannot run twice for one
/// admission through this seam. Production drives the awaiting-draft refusal
/// until the governed slice supplies the validated draft with the real owner
/// handle (A-31 for Curation, `build_projection` for Orientation, and the
/// native owners for the remaining admitted classes); deterministic tests pass
/// a counting wrapper around the owner shape to prove the once-per-admission
/// call shape. The owner value is returned unmodified on success; its typed
/// refusal maps fail-closed.
pub(crate) fn dispatch_admitted_with<T>(
    outcome: DispatchedOutcome,
    dispatch_once: impl FnOnce(DispatchedOutcome) -> Result<T, ContractViolation>,
) -> Result<T, DreamerError> {
    dispatch_once(outcome).map_err(|error| dispatch_denied(&error))
}

/// Maps a native owner refusal to a typed fail-closed refusal.
///
/// Every mapping is [`DreamerError::InvalidAdmission`] (request-rejected code),
/// never the Kernel-admission code: the admission itself was valid, the owner
/// inputs were not. Dynamic payloads (handles, digests, reasons) are dropped
/// in favor of bounded static field names; nothing secret flows.
fn dispatch_denied(error: &ContractViolation) -> DreamerError {
    match error {
        ContractViolation::UnknownVariant { field, .. }
        | ContractViolation::OutOfBounds { field, .. }
        | ContractViolation::BindingMismatch { field, .. }
        | ContractViolation::Malformed { field, .. }
        | ContractViolation::MissingField(field)
        | ContractViolation::ImplicitDefault(field)
        | ContractViolation::CrossStage(field) => DreamerError::InvalidAdmission(field),
        ContractViolation::Budget { dimension, .. } => DreamerError::InvalidAdmission(dimension),
        ContractViolation::KindPayload(_) => {
            DreamerError::InvalidAdmission("kind/payload mismatch")
        }
        ContractViolation::Registry(_) => {
            DreamerError::InvalidAdmission("handler registry conflict")
        }
        ContractViolation::ScreenIneligible(_) => {
            DreamerError::InvalidAdmission("screen ineligible")
        }
        ContractViolation::Preservation(_) => {
            DreamerError::InvalidAdmission("preservation failure")
        }
        ContractViolation::ForbiddenCarry(_) => {
            DreamerError::InvalidAdmission("forbidden candidate carry")
        }
    }
}

#[cfg(test)]
mod slice_7_dispatch_tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::KERNEL_ADMISSION_REQUIRED;

    /// All nine closed classes route to their distinct dispatch decision with
    /// no wildcard arm: each refused class carries its exact class payload,
    /// each admitted class names the missing governed draft. A tenth class
    /// would break compilation instead of misrouting.
    #[test]
    fn all_nine_classes_route_distinctly_fail_closed() {
        for class in [
            JobClass::Curation,
            JobClass::Clarification,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ] {
            let refused = dispatch_admitted_result(class);
            assert!(
                matches!(refused, Err(DreamerError::UnsupportedJobClass(refused_class)) if refused_class == class),
                "class {class:?} must refuse with UnsupportedJobClass({class:?})"
            );
        }
        for class in [
            JobClass::Orientation,
            JobClass::ResearchSynthesis,
            JobClass::Maintenance,
        ] {
            let refused = dispatch_admitted_result(class);
            assert!(
                matches!(
                    refused,
                    Err(DreamerError::InvalidAdmission(
                        "admitted dispatch requires Governor-resolved validated draft"
                    ))
                ),
                "class {class:?} must wait for governed material, got {refused:?}"
            );
        }
        let outcomes = [
            DispatchedOutcome::OrientationAdmitted,
            DispatchedOutcome::ResearchSynthesisAdmitted,
            DispatchedOutcome::MaintenanceAdmitted,
        ];
        assert_ne!(outcomes[0], outcomes[1]);
        assert_ne!(outcomes[0], outcomes[2]);
        assert_ne!(outcomes[1], outcomes[2]);
    }

    /// Each refused class fails closed before any Kernel contact with the
    /// request-rejected code, never the Kernel-admission code. The proof is
    /// structural: the resolver takes only `JobClass` and returns a plain
    /// result, so there is no port, transport, or admission channel it could
    /// call; `submit` runs dispatch before `check_claimed`/`live_view`.
    #[test]
    fn refused_fail_closed_before_kernel() {
        for class in [
            JobClass::Curation,
            JobClass::Clarification,
            JobClass::ArchitectureSelfQuery,
            JobClass::DevelopmentDiagnosis,
            JobClass::OrchestrationPlanning,
            JobClass::ConfigurationAssistance,
        ] {
            let Err(error) = dispatch_admitted_result(class) else {
                panic!("refused class {class:?} must fail");
            };
            assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
            assert_ne!(
                error.code(),
                KERNEL_ADMISSION_REQUIRED,
                "refusal for {class:?} must not borrow the Kernel-admission code"
            );
            assert_eq!(
                format!("{error}"),
                format!("unsupported Dreamer job class: {class:?}")
            );
        }
    }

    /// Admitted classes wait for Governor-resolved material: the refusal names
    /// the missing validated draft instead of invoking a leaf, carries the
    /// request-rejected code, and never the Kernel-admission code.
    #[test]
    fn admitted_wait_for_governed_material() {
        for class in [
            JobClass::Orientation,
            JobClass::ResearchSynthesis,
            JobClass::Maintenance,
        ] {
            let Err(error) = dispatch_admitted_result(class) else {
                panic!("admitted class {class:?} must wait");
            };
            assert!(
                matches!(
                    error,
                    DreamerError::InvalidAdmission(
                        "admitted dispatch requires Governor-resolved validated draft"
                    )
                ),
                "class {class:?} must name the missing draft, got {error:?}"
            );
            assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
            assert_ne!(
                error.code(),
                KERNEL_ADMISSION_REQUIRED,
                "admitted wait for {class:?} must not borrow the Kernel-admission code"
            );
        }
    }

    /// The owner entrypoint runs exactly once per admitted admission: one
    /// counting wrapper per distinct outcome, one call, one typed fail-closed
    /// refusal with the request-rejected code. The wrapper stands in for the
    /// native owner handle (A-31, `build_projection`, and the remaining native
    /// owners), which the governed slice plugs in once validated drafts land.
    #[test]
    fn owner_dispatch_runs_exactly_once_per_admission() {
        for outcome in [
            DispatchedOutcome::OrientationAdmitted,
            DispatchedOutcome::ResearchSynthesisAdmitted,
            DispatchedOutcome::MaintenanceAdmitted,
        ] {
            let calls = AtomicU64::new(0);
            let refused: Result<String, DreamerError> = dispatch_admitted_with(outcome, |seen| {
                calls.fetch_add(1, Ordering::SeqCst);
                assert_eq!(seen, outcome, "owner must observe its distinct outcome");
                Err(ContractViolation::MissingField("governor.validated_draft"))
            });
            assert_eq!(
                calls.load(Ordering::SeqCst),
                1,
                "owner for {outcome:?} must run exactly once per admission"
            );
            let Err(error) = refused else {
                panic!("owner without a validated draft must refuse");
            };
            assert_eq!(error.code(), "DREAMER_REQUEST_REJECTED");
            assert!(
                !matches!(error, DreamerError::KernelAdmissionRequired(_)),
                "owner refusal must not borrow the Kernel-admission code"
            );
        }
    }

    /// A succeeding owner value passes through the seam unmodified, still
    /// exactly once per admission: the seam adds no promotion, thinning, or
    /// rewriting of its own.
    #[test]
    fn owner_value_passes_through_unmodified() {
        let calls = AtomicU64::new(0);
        let outcome = DispatchedOutcome::OrientationAdmitted;
        let passed: Result<String, DreamerError> = dispatch_admitted_with(outcome, |seen| {
            calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(seen, outcome);
            Ok("owner-value".to_owned())
        });
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        let Ok(value) = passed else {
            panic!("owner value must pass through");
        };
        assert_eq!(value, "owner-value");
    }

    /// Every native owner refusal shape maps to the request-rejected code,
    /// never to the Kernel-admission code.
    #[test]
    fn every_owner_refusal_maps_fail_closed() {
        let cases = [
            ContractViolation::MissingField("governor.validated_draft"),
            ContractViolation::ImplicitDefault("schema_version"),
            ContractViolation::CrossStage("validated"),
            ContractViolation::UnknownVariant {
                field: "job_class",
                value: "tenth".to_owned(),
            },
            ContractViolation::OutOfBounds {
                field: "draft.revision",
                min: 1,
                max: 1,
                got: 0,
            },
            ContractViolation::BindingMismatch {
                field: "dispatch.draft",
                reason: "draft differs".to_owned(),
            },
            ContractViolation::Malformed {
                field: "draft.content",
                reason: "blank".to_owned(),
            },
            ContractViolation::Budget {
                dimension: "model_calls",
                reason: "over".to_owned(),
            },
            ContractViolation::KindPayload("kind".to_owned()),
            ContractViolation::Registry("registry".to_owned()),
            ContractViolation::ScreenIneligible("screen".to_owned()),
            ContractViolation::Preservation("preservation".to_owned()),
            ContractViolation::ForbiddenCarry("carry".to_owned()),
        ];
        assert_eq!(cases.len(), 13);
        for error in cases {
            let refused = dispatch_denied(&error);
            assert_eq!(refused.code(), "DREAMER_REQUEST_REJECTED");
            assert!(
                !matches!(refused, DreamerError::KernelAdmissionRequired(_)),
                "owner refusal must not borrow the Kernel-admission code"
            );
        }
    }
}
