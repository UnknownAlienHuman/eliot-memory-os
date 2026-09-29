//! Admitted research-provider admission binding.
//!
//! A [`ProviderAdmission`] is the immutable bridge manifest this issue requires:
//! exact artifact/config/protocol digests, Module/Capability Registry evidence
//! references, process generation, Authority Epoch, State Fence, privacy/data
//! class, budget/deadline ceilings, route echoes, and the stable operation
//! identity used for cancellation and unknown-outcome reconciliation.
//!
//! The bridge mints nothing. Every value arrives from already-admitted material
//! (the Kernel/Governor grant issuance that produces admissions lives outside
//! this crate, with issues #15/#18); this cell only validates shape and binds
//! one exact [`ResearchQueryRequest`] to one admitted operation before any
//! executor contact. Because the exchange request carries no artifact/config/
//! protocol digest, no Module Registry reference, no process generation, no
//! Authority Epoch and no operation or cancellation identity of its own, the
//! record also re-proves those nine facts by value against the Kernel's own
//! dispatch presentation and its sealed receipt
//! ([`ProviderAdmission::bind_admitted_dispatch`]); carrying them is not the
//! same as being bound to this operation.

use eliot_contracts::{ContractVersion, EpochId, StateFence, fences_match_exact};
use eliot_kernel_service::{ResearchProviderDispatch, ResearchProviderDispatchReceipt};
use eliot_process::{Generation, OperationId};
use eliot_research_exchange_api::{DisclosureClass, ResearchQueryRequest};

use crate::{BridgeIdentity, admitted_disclosure_wire, is_lowercase_sha256};

/// Stable reason carrier for admission construction/binding refusals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRefusal {
    /// A digest field is not a lowercase SHA-256 hex string.
    MalformedDigest,
    /// A text field is blank or carries control characters.
    MalformedText,
    /// The carried epoch disagrees with the carried fence authority epoch.
    EpochFenceConflict,
    /// A budget/deadline ceiling is not a positive bound.
    NonPositiveCeiling,
    /// The request disagrees with the admission on a bound dimension.
    RequestMismatch,
}

impl AdmissionRefusal {
    /// Returns the stable machine-greppable reason string.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MalformedDigest => "admission digest is not a lowercase SHA-256 hex digest",
            Self::MalformedText => "admission text is blank or carries control characters",
            Self::EpochFenceConflict => "admission epoch disagrees with fence authority epoch",
            Self::NonPositiveCeiling => "admission ceiling is not a positive bound",
            Self::RequestMismatch => "request disagrees with the admitted operation binding",
        }
    }
}

/// Immutable admitted manifest for one bounded research-provider operation.
///
/// Field authority notes:
/// - `config_digest` / `protocol_digest` mirror the `ModuleManifest`
///   artifact/config/protocol digest triple next to the bridge executable
///   digest they accompany; they bind exact bytes, never a mutable tag.
/// - `module_id` / `module_generation_id` are Module/Capability Registry
///   evidence *references* (cf. `EliotdLiveSupervisionEvidence`): they
///   correlate the operation with a catalogued generation without granting
///   authority or re-issuing admission.
/// - `inquiry_digest` / `denominator_digest` bind the frozen Researcher
///   inquiry and its exact source-role portfolio / coverage denominator. A
///   coverage or absence claim must name its scope, revision, and the method
///   by which the denominator can be checked independently (A05.07), so an
///   admitted acquisition can never run against an undeclared denominator.
/// - `operation_id` is the stable identity for cancel/reconcile and the only
///   identity the exchange ever keys on; the provider-local job reference
///   stays outcome evidence, never canonical identity.
/// - `cancellation_id` is the cancellation identity for this operation's
///   lifecycle (I7.4: every request carries idempotency identity, deadline and
///   cancellation semantics). It is carried here rather than re-read from the
///   presentation at each use, so a terminal receipt or a control request
///   cannot report or act on a cancellation identity that was never compared
///   against the sealed admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderAdmission {
    bridge: BridgeIdentity,
    config_digest: String,
    protocol_digest: String,
    module_id: String,
    module_generation_id: String,
    process_generation: Generation,
    epoch: EpochId,
    fence: StateFence,
    disclosure: DisclosureClass,
    budget_units: u64,
    deadline_ms: i64,
    protocol_revision: ContractVersion,
    required_schema: String,
    bridge_generation: String,
    operation_id: OperationId,
    cancellation_id: String,
    inquiry_digest: String,
    denominator_digest: String,
    coverage_goal: String,
}

impl ProviderAdmission {
    /// Binds one exact admitted operation. Every digest is shape-checked, the
    /// epoch must equal the fence authority epoch, and ceilings must be
    /// positive. Returns the stable refusal otherwise.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bridge: BridgeIdentity,
        config_digest: impl Into<String>,
        protocol_digest: impl Into<String>,
        module_id: impl Into<String>,
        module_generation_id: impl Into<String>,
        process_generation: Generation,
        epoch: EpochId,
        fence: StateFence,
        disclosure: DisclosureClass,
        budget_units: u64,
        deadline_ms: i64,
        protocol_revision: ContractVersion,
        required_schema: impl Into<String>,
        bridge_generation: impl Into<String>,
        operation_id: OperationId,
        cancellation_id: impl Into<String>,
        inquiry_digest: impl Into<String>,
        denominator_digest: impl Into<String>,
        coverage_goal: impl Into<String>,
    ) -> Result<Self, AdmissionRefusal> {
        let config_digest = config_digest.into();
        let protocol_digest = protocol_digest.into();
        let inquiry_digest = inquiry_digest.into();
        let denominator_digest = denominator_digest.into();
        if !is_lowercase_sha256(&config_digest)
            || !is_lowercase_sha256(&protocol_digest)
            || !is_lowercase_sha256(&inquiry_digest)
            || !is_lowercase_sha256(&denominator_digest)
        {
            return Err(AdmissionRefusal::MalformedDigest);
        }
        let module_id = module_id.into();
        let module_generation_id = module_generation_id.into();
        let required_schema = required_schema.into();
        let bridge_generation = bridge_generation.into();
        let cancellation_id = cancellation_id.into();
        let coverage_goal = coverage_goal.into();
        for value in [
            &module_id,
            &module_generation_id,
            &required_schema,
            &bridge_generation,
            &cancellation_id,
            &coverage_goal,
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(AdmissionRefusal::MalformedText);
            }
        }
        if !epoch.is_same_authority(&fence.authority_epoch) {
            return Err(AdmissionRefusal::EpochFenceConflict);
        }
        if budget_units == 0 || deadline_ms <= 0 {
            return Err(AdmissionRefusal::NonPositiveCeiling);
        }
        Ok(Self {
            bridge,
            config_digest,
            protocol_digest,
            module_id,
            module_generation_id,
            process_generation,
            epoch,
            fence,
            disclosure,
            budget_units,
            deadline_ms,
            protocol_revision,
            required_schema,
            bridge_generation,
            operation_id,
            cancellation_id,
            inquiry_digest,
            denominator_digest,
            coverage_goal,
        })
    }

    /// Returns the admitted bridge identity (exact executable + digest).
    #[must_use]
    pub const fn bridge(&self) -> &BridgeIdentity {
        &self.bridge
    }

    /// Returns the admitted exact config digest.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.config_digest
    }

    /// Returns the admitted exact protocol digest.
    #[must_use]
    pub fn protocol_digest(&self) -> &str {
        &self.protocol_digest
    }

    /// Returns the Module Registry evidence reference.
    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.module_id
    }

    /// Returns the Module generation evidence reference.
    #[must_use]
    pub fn module_generation_id(&self) -> &str {
        &self.module_generation_id
    }

    /// Returns the admitted process generation.
    #[must_use]
    pub const fn process_generation(&self) -> Generation {
        self.process_generation
    }

    /// Returns the admitted Authority Epoch.
    #[must_use]
    pub const fn epoch(&self) -> &EpochId {
        &self.epoch
    }

    /// Returns the admitted State Fence.
    #[must_use]
    pub const fn fence(&self) -> &StateFence {
        &self.fence
    }

    /// Returns the admitted privacy/data class ceiling (exact: no widening).
    #[must_use]
    pub const fn disclosure(&self) -> DisclosureClass {
        self.disclosure
    }

    /// Returns the admitted budget ceiling in provider units.
    #[must_use]
    pub const fn budget_units(&self) -> u64 {
        self.budget_units
    }

    /// Returns the admitted deadline ceiling in milliseconds.
    #[must_use]
    pub const fn deadline_ms(&self) -> i64 {
        self.deadline_ms
    }

    /// Returns the admitted protocol revision.
    #[must_use]
    pub const fn protocol_revision(&self) -> &ContractVersion {
        &self.protocol_revision
    }

    /// Returns the admitted required result schema.
    #[must_use]
    pub fn required_schema(&self) -> &str {
        &self.required_schema
    }

    /// Returns the admitted bridge generation echo.
    #[must_use]
    pub fn bridge_generation(&self) -> &str {
        &self.bridge_generation
    }

    /// Returns the stable operation identity for cancel/reconcile.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Returns the admitted cancellation identity for this operation's
    /// lifecycle.
    #[must_use]
    pub fn cancellation_id(&self) -> &str {
        &self.cancellation_id
    }

    /// Returns the digest of the frozen Researcher inquiry this acquisition
    /// answers.
    #[must_use]
    pub fn inquiry_digest(&self) -> &str {
        &self.inquiry_digest
    }

    /// Returns the digest of the admitted source portfolio / coverage
    /// denominator.
    ///
    /// A coverage or absence claim is only checkable against a declared
    /// denominator (A05-07, I21.6). This is that handle.
    #[must_use]
    pub fn denominator_digest(&self) -> &str {
        &self.denominator_digest
    }

    /// Returns the admitted coverage goal.
    #[must_use]
    pub fn coverage_goal(&self) -> &str {
        &self.coverage_goal
    }

    /// Binds one request to this admitted operation.
    ///
    /// Every bound dimension must agree exactly: fence (exact, both
    /// directions), bridge generation echo, disclosure (no silent privacy
    /// widening), budget/deadline within ceiling, protocol revision, required
    /// schema (route binding), and the coverage goal. Privacy, cost, or route
    /// expansion is a mismatch, never a fallback. Returns the stable refusal
    /// otherwise.
    pub fn validate_request(&self, request: &ResearchQueryRequest) -> Result<(), AdmissionRefusal> {
        if !fences_match_exact(&request.state_fence, &self.fence)
            || request.bridge_generation != self.bridge_generation
            || request.disclosure != self.disclosure
            || request.budget_units == 0
            || request.budget_units > self.budget_units
            || request.deadline_ms <= 0
            || request.deadline_ms > self.deadline_ms
            || request.protocol_revision != self.protocol_revision
            || request.required_schema != self.required_schema
            || request.coverage_goal != self.coverage_goal
        {
            return Err(AdmissionRefusal::RequestMismatch);
        }
        Ok(())
    }

    /// Re-proves that this record is the record of exactly the Kernel-admitted
    /// dispatch this process holds a receipt for.
    ///
    /// [`ProviderAdmission::validate_request`] binds an *exchange request* to
    /// this record, and the request carries no artifact/config/protocol digest,
    /// no Module Registry reference, no process generation, no Authority Epoch
    /// and no operation or cancellation identity of its own — those nine facts
    /// live only here.
    /// A record that merely carries them proves nothing about which operation
    /// was admitted, so this method compares each one **by value** against the
    /// two records that do carry it: the presented
    /// [`ResearchProviderDispatch`] and the sealed
    /// [`ResearchProviderDispatchReceipt`] the Kernel issued for it.
    ///
    /// The owner's own proof is reused rather than restated:
    /// [`ResearchProviderDispatchReceipt::verify_echo`] is the wire owner's
    /// validator, and its single canonical request-digest equality
    /// (`receipt.request_sha256` against a re-computed
    /// `dispatch.canonical_sha256()`) is what makes the presented artifact,
    /// config and protocol digests, the Module/Capability Registry references,
    /// the process generation, the Authority Epoch, the State Fence and the
    /// operation/cancellation identity *the content the live authority actually
    /// admitted* rather than a well-formed shape. Those four digests have no
    /// field-wise owner echo to compare against, so a second digest scheme or a
    /// second identity authority is deliberately not invented here.
    ///
    /// What follows the owner proof is the field-wise comparison, so the record
    /// is self-verifying rather than dependent on a caller's diligence: the
    /// admission's epoch, State Fence, process generation, operation identity and
    /// cancellation identity are compared against the owner's own echoes, and
    /// its artifact,
    /// config/protocol digests, Module Registry references, privacy/data class,
    /// budget/deadline and route terms are compared against the admitted
    /// presentation byte for byte. `coverage_goal` is deliberately absent: it is
    /// a Researcher inquiry term carried by the exchange request, not a dispatch
    /// field, and it is already bound by
    /// [`ProviderAdmission::validate_request`].
    ///
    /// # Errors
    ///
    /// Returns [`AdmissionRefusal::RequestMismatch`] when the receipt does not
    /// echo this dispatch exactly, is not an admitted disposition, or when any
    /// of the nine identity facts above disagrees by value. There is no
    /// fallback value, no partial acceptance, and no second reason code: this
    /// record is either the record of the admitted operation or it is not.
    pub fn bind_admitted_dispatch(
        &self,
        dispatch: &ResearchProviderDispatch,
        receipt: &ResearchProviderDispatchReceipt,
    ) -> Result<(), AdmissionRefusal> {
        receipt
            .verify_echo(dispatch)
            .map_err(|_| AdmissionRefusal::RequestMismatch)?;
        if self.bridge.executable() != dispatch.executable_path.as_str()
            || self.bridge.executable_sha256() != dispatch.executable_sha256.as_str()
            || self.config_digest != dispatch.config_digest
            || self.protocol_digest != dispatch.protocol_digest
            || self.module_id != dispatch.module_id
            || self.module_generation_id != dispatch.module_generation_id
            || self.process_generation.get() != dispatch.process_generation
            || self.process_generation.get() != receipt.admitted_generation
            || !self.epoch.is_same_authority(&dispatch.authority_epoch)
            || !self
                .epoch
                .is_same_authority(&receipt.admitted_authority_epoch)
            || self.fence != dispatch.state_fence
            || self.fence != receipt.admitted_fence
            || self.operation_id.as_str() != dispatch.operation_id.as_str()
            || self.operation_id.as_str() != receipt.operation_id.as_str()
            || self.cancellation_id != dispatch.cancellation_id
            || self.cancellation_id != receipt.cancellation_id
            || admitted_disclosure_wire(self.disclosure) != dispatch.disclosure.as_str()
            || self.budget_units != dispatch.budget_units
            || self.deadline_ms != dispatch.deadline_ms
            || self.protocol_revision != dispatch.protocol_revision
            || self.required_schema != dispatch.required_schema
            || self.bridge_generation != dispatch.bridge_generation
            || self.inquiry_digest != dispatch.inquiry_digest
            || self.denominator_digest != dispatch.denominator_digest
        {
            return Err(AdmissionRefusal::RequestMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use eliot_contracts::ContractVersion;
    use eliot_process::Generation;
    use eliot_research_exchange_api::DisclosureClass;

    use crate::support::{
        DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_SHORT, DIGEST_UPPER, test_admission, test_epoch,
        test_fence, test_identity, test_request,
    };

    use super::*;

    #[test]
    fn admission_accepts_exact_material() {
        let admission = test_admission();
        assert_eq!(admission.bridge(), &test_identity());
        assert_eq!(admission.config_digest(), DIGEST_B);
        assert_eq!(admission.protocol_digest(), DIGEST_C);
        assert_eq!(admission.module_id(), "mod-research-provider");
        assert_eq!(admission.module_generation_id(), "gen-mod-24-a");
        assert_eq!(
            admission.process_generation(),
            Generation::new(3).expect("gen")
        );
        assert!(admission.epoch().is_same_authority(&test_epoch()));
        assert_eq!(admission.fence(), &test_fence());
        assert_eq!(admission.disclosure(), DisclosureClass::ProjectBound);
        assert_eq!(admission.budget_units(), 10);
        assert_eq!(admission.deadline_ms(), 1_800_000_000_000);
        assert_eq!(
            admission.protocol_revision(),
            &ContractVersion::new(1, 0, 0)
        );
        assert_eq!(admission.required_schema(), "research-evidence-bundle/v1");
        assert_eq!(admission.bridge_generation(), "gen-24-slice-a");
        assert_eq!(admission.operation_id().as_str(), "op-24-slice-a");
    }

    #[test]
    fn admission_rejects_malformed_digests() {
        for (config, protocol) in [
            ("", DIGEST_C),
            (DIGEST_SHORT, DIGEST_C),
            (DIGEST_UPPER, DIGEST_C),
            (DIGEST_B, ""),
            (DIGEST_B, DIGEST_SHORT),
            (DIGEST_A, DIGEST_UPPER),
        ] {
            assert!(
                matches!(
                    ProviderAdmission::new(
                        test_identity(),
                        config,
                        protocol,
                        "mod-research-provider",
                        "gen-mod-24-a",
                        Generation::new(3).expect("gen"),
                        test_epoch(),
                        test_fence(),
                        DisclosureClass::ProjectBound,
                        10,
                        1_800_000_000_000,
                        ContractVersion::new(1, 0, 0),
                        "research-evidence-bundle/v1",
                        "gen-24-slice-a",
                        crate::support::test_operation_id(),
                        "cancel-24-slice-a",
                        DIGEST_A,
                        DIGEST_B,
                        crate::support::COVERAGE_GOAL,
                    ),
                    Err(AdmissionRefusal::MalformedDigest)
                ),
                "malformed digest must be rejected: {config:?}/{protocol:?}"
            );
        }
    }

    #[test]
    fn admission_rejects_blank_registry_references() {
        for module in ["", "   "] {
            assert!(
                matches!(
                    ProviderAdmission::new(
                        test_identity(),
                        DIGEST_B,
                        DIGEST_C,
                        module,
                        "gen-mod-24-a",
                        Generation::new(3).expect("gen"),
                        test_epoch(),
                        test_fence(),
                        DisclosureClass::ProjectBound,
                        10,
                        1_800_000_000_000,
                        ContractVersion::new(1, 0, 0),
                        "research-evidence-bundle/v1",
                        "gen-24-slice-a",
                        crate::support::test_operation_id(),
                        "cancel-24-slice-a",
                        DIGEST_A,
                        DIGEST_B,
                        crate::support::COVERAGE_GOAL,
                    ),
                    Err(AdmissionRefusal::MalformedText)
                ),
                "blank registry reference must be rejected: {module:?}"
            );
        }
    }

    #[test]
    fn admission_rejects_epoch_fence_conflict() {
        let other_epoch = {
            use eliot_contracts::EpochLineageId;
            use std::num::NonZeroU64;
            eliot_contracts::EpochId::new(
                EpochLineageId::new("6ba7b810-9dad-11d1-80b4-00c04fd430c8").expect("lineage"),
                NonZeroU64::new(7).expect("sequence"),
            )
            .expect("epoch")
        };
        assert!(
            matches!(
                ProviderAdmission::new(
                    test_identity(),
                    DIGEST_B,
                    DIGEST_C,
                    "mod-research-provider",
                    "gen-mod-24-a",
                    Generation::new(3).expect("gen"),
                    other_epoch,
                    test_fence(),
                    DisclosureClass::ProjectBound,
                    10,
                    1_800_000_000_000,
                    ContractVersion::new(1, 0, 0),
                    "research-evidence-bundle/v1",
                    "gen-24-slice-a",
                    crate::support::test_operation_id(),
                    "cancel-24-slice-a",
                    DIGEST_A,
                    DIGEST_B,
                    crate::support::COVERAGE_GOAL,
                ),
                Err(AdmissionRefusal::EpochFenceConflict)
            ),
            "epoch disagreeing with the fence must be rejected"
        );
    }

    #[test]
    fn admission_rejects_non_positive_ceilings() {
        for (budget, deadline) in [(0, 1_800_000_000_000), (10, 0), (10, -5)] {
            assert!(
                matches!(
                    ProviderAdmission::new(
                        test_identity(),
                        DIGEST_B,
                        DIGEST_C,
                        "mod-research-provider",
                        "gen-mod-24-a",
                        Generation::new(3).expect("gen"),
                        test_epoch(),
                        test_fence(),
                        DisclosureClass::ProjectBound,
                        budget,
                        deadline,
                        ContractVersion::new(1, 0, 0),
                        "research-evidence-bundle/v1",
                        "gen-24-slice-a",
                        crate::support::test_operation_id(),
                        "cancel-24-slice-a",
                        DIGEST_A,
                        DIGEST_B,
                        crate::support::COVERAGE_GOAL,
                    ),
                    Err(AdmissionRefusal::NonPositiveCeiling)
                ),
                "non-positive ceiling must be rejected: {budget}/{deadline}"
            );
        }
    }

    #[test]
    fn matching_request_binds_to_the_admission() {
        assert!(
            test_admission().validate_request(&test_request()).is_ok(),
            "the exact admitted request must bind"
        );
    }

    #[test]
    fn mismatched_requests_are_refused_without_fallback() {
        let admission = test_admission();
        let mut widened = test_request();
        widened.disclosure = DisclosureClass::Public;
        let mut over_budget = test_request();
        over_budget.budget_units = 11;
        let mut over_deadline = test_request();
        over_deadline.deadline_ms = 1_800_000_000_001;
        let mut wrong_generation = test_request();
        wrong_generation.bridge_generation = "gen-foreign".to_owned();
        let mut wrong_schema = test_request();
        wrong_schema.required_schema = "other-schema/v9".to_owned();
        let mut wrong_revision = test_request();
        wrong_revision.protocol_revision = ContractVersion::new(2, 0, 0);
        let mut stale_fence = test_request();
        stale_fence.state_fence = eliot_contracts::StateFence::new(
            test_epoch(),
            eliot_contracts::ResourceGeneration::new(9).expect("resource generation"),
        );
        for (name, request) in [
            ("privacy widening", widened),
            ("budget expansion", over_budget),
            ("deadline expansion", over_deadline),
            ("generation mismatch", wrong_generation),
            ("schema mismatch", wrong_schema),
            ("revision mismatch", wrong_revision),
            ("fence mismatch", stale_fence),
        ] {
            assert!(
                matches!(
                    admission.validate_request(&request),
                    Err(AdmissionRefusal::RequestMismatch)
                ),
                "{name} must be refused without fallback"
            );
        }
    }

    #[test]
    fn refusal_reasons_are_stable() {
        assert_eq!(
            AdmissionRefusal::RequestMismatch.reason(),
            "request disagrees with the admitted operation binding"
        );
    }
}
