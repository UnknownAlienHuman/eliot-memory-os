//! Contract-only security and privacy surfaces for ELIOT C0-12.
//!
//! These records preserve origin, taint, disclosure and influence lineage at
//! every transformation boundary.  This crate does not store data, execute a
//! purge, authorize a route, or issue a completion/release decision.

#![forbid(unsafe_code)]

mod surface_types;
mod validation;

pub use surface_types::*;
pub use validation::{SecurityContractError, validate_selection_pipeline};

/// Stable identity of this contract surface.
pub const CONTRACT_NAME: &str = "eliot.foundation.security-contracts";
/// Current wire revision of this contract surface.
pub const CONTRACT_VERSION: eliot_contracts::ContractVersion =
    eliot_contracts::ContractVersion::new(1, 0, 0);

/// Returns a stable contract identity without assigning any runtime authority.
///
/// # Errors
///
/// Returns an error when the shared contract identity shape cannot be serialized
/// canonically.
pub fn contract_identity() -> Result<eliot_contracts::ContractIdentity, SecurityContractError> {
    #[derive(serde::Serialize)]
    struct Shape {
        surface: &'static str,
        version: eliot_contracts::ContractVersion,
        transformation_rule: &'static str,
    }

    eliot_contracts::contract_identity(
        CONTRACT_NAME,
        CONTRACT_VERSION,
        &Shape {
            surface: "source_assurance_disclosure_influence_erasure_selection",
            version: CONTRACT_VERSION,
            transformation_rule: "origin_bound_and_explicitly_fenced",
        },
    )
    .map_err(SecurityContractError::Foundation)
}

#[cfg(test)]
mod negative_consumer_fixtures {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};

    fn fence() -> StateFence {
        StateFence::new(AuthorityEpoch::genesis(), ResourceGeneration::genesis())
    }

    fn closure(completeness: ClosureCompleteness) -> DisclosureDependencyClosure {
        DisclosureDependencyClosure {
            closure_id: "closure-1".to_owned(),
            subject_ref: "subject-1".to_owned(),
            direct_domain_refs: vec![ObservationDomainRef {
                domain_id: "domain-private".to_owned(),
                kind: ObservationDomainKind::UserPrivate,
                authority_root: "owner-1".to_owned(),
                resource_scope: "scope-1".to_owned(),
                privacy_class: PrivacyClass::Private,
                visibility_and_export_rule: "owner-only".to_owned(),
                model_route_rule: "no-external-model".to_owned(),
                state_fence: fence(),
            }],
            inherited_closure_refs: Vec::new(),
            derivation_or_transformation_refs: Vec::new(),
            completeness,
            declassification_receipt_refs: Vec::new(),
            policy_snapshot_id: "policy-1".to_owned(),
            state_fence: fence(),
            revision: 1,
        }
    }

    #[test]
    fn malformed_and_unknown_fields_fail_closed() {
        let malformed = r#"{"closure_id":42,"subject_ref":"s","direct_domain_refs":[],"inherited_closure_refs":[],"derivation_or_transformation_refs":[],"completeness":"COMPLETE","declassification_receipt_refs":[],"policy_snapshot_id":"p","state_fence":null,"revision":1}"#;
        assert!(serde_json::from_str::<DisclosureDependencyClosure>(malformed).is_err());

        let duplicate = r#"{"closure_id":"c","subject_ref":"s","direct_domain_refs":[],"inherited_closure_refs":[],"derivation_or_transformation_refs":[],"completeness":"COMPLETE","declassification_receipt_refs":[],"policy_snapshot_id":"p","state_fence":{"authority_epoch":0,"resource_generation":0,"authority_digest":"x","resource_digest":"x"},"revision":1,"unexpected":true}"#;
        assert!(serde_json::from_str::<DisclosureDependencyClosure>(duplicate).is_err());
    }

    #[test]
    fn incomplete_closure_cannot_be_exported() {
        assert!(closure(ClosureCompleteness::Partial).validate().is_ok());
        let value = DisclosureDecision {
            subject_and_closure_ref: "closure-1".to_owned(),
            recipient_principal_or_route: "remote-model".to_owned(),
            recipient_capability_set: vec!["model:read".to_owned()],
            covered_domains: vec!["domain-private".to_owned()],
            uncovered_domains: Vec::new(),
            decision: DisclosureDecisionKind::Allow,
            policy_snapshot_and_state_fence: PolicyFence {
                policy_snapshot_id: "policy-1".to_owned(),
                state_fence: fence(),
            },
            receipt_ref: "receipt-1".to_owned(),
            closure_completeness: ClosureCompleteness::Partial,
        };
        assert!(matches!(
            value.validate(),
            Err(SecurityContractError::DisclosureClosureIncomplete)
        ));
    }

    #[test]
    fn taint_cannot_be_laundered_by_summary() {
        let value = TransformationLineage {
            transformation_id: "summary-1".to_owned(),
            input_refs: vec!["observation-1".to_owned()],
            output_ref: "summary-1".to_owned(),
            operation: TransformationKind::ModelSummary,
            input_taint: InstructionTaint::CommandLike,
            output_taint: InstructionTaint::Cleared,
            declassification_receipt_ref: None,
            state_fence: fence(),
        };
        assert!(matches!(
            value.validate(),
            Err(SecurityContractError::TaintLaundering)
        ));
    }

    #[test]
    fn revoked_influence_and_purge_cannot_be_reactivated() {
        let closure = InfluenceDependencyClosure {
            closure_id: "influence-1".to_owned(),
            root_ref: "source-1".to_owned(),
            dependent_refs: vec!["summary-1".to_owned()],
            invalidation_reason: Some(RevocationReason::SourceRevoked),
            current_influence: InfluenceState::Active,
            state_fence: fence(),
            revision: 2,
        };
        assert!(matches!(
            closure.validate(),
            Err(SecurityContractError::RevokedInfluenceActive)
        ));

        let entry = PurgeLedgerEntry {
            purge_id: "purge-1".to_owned(),
            subject_ref: "source-1".to_owned(),
            scope: "scope-1".to_owned(),
            purged_locations: vec![PurgeLocation::CanonicalPayload],
            tombstone_digest: "0000000000000000000000000000000000000000000000000000000000000000"
                .to_owned(),
            state: PurgeState::Purged,
            state_fence: fence(),
            revision: 1,
        };
        assert!(matches!(
            entry.validate_restore(),
            Err(SecurityContractError::PurgeResurrection)
        ));
    }

    #[test]
    fn selection_receipt_rejects_unadmitted_output() {
        let receipt = SelectionIntegrityReceipt {
            selection_id: "selection-1".to_owned(),
            initial_candidate_refs: vec!["a".to_owned()],
            admitted_candidate_refs: vec!["a".to_owned()],
            rejected_candidate_refs: Vec::new(),
            transformation_stages: vec![SelectionStage {
                stage: SelectionStageKind::Summary,
                input_refs: vec!["a".to_owned()],
                output_refs: vec!["b".to_owned()],
                disclosure_closure_ref: "closure-1".to_owned(),
                state_fence: fence(),
            }],
            final_output_refs: vec!["c".to_owned()],
            untrusted_structure_changed_membership: false,
            state_fence: fence(),
            revision: 1,
        };
        assert!(matches!(
            receipt.validate(),
            Err(SecurityContractError::SelectionIntegrityViolation)
        ));
    }
}
