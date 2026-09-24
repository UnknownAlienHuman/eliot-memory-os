//! Immutable research-provider bridge admission.
//!
//! A provider is launched only from a closed [`BridgeContract`] that has
//! been resolved against an explicit Module/Capability Registry observation.
//! The bridge does not discover an executable, mint a permit, attach a
//! credential, or infer a route. Those values arrive as evidence from the
//! Kernel/Governor composition boundary and are checked again before a
//! [`eliot_process::ProcessRequest`] is allowed to reach the shared executor.

use eliot_contracts::{ContractVersion, EpochId, StateFence, fences_match_exact};
use eliot_process::{Generation, OperationId};
use eliot_research_exchange_api::{DisclosureClass, ResearchQueryRequest};
use serde::{Deserialize, Serialize};

use crate::{BridgeIdentity, is_lowercase_sha256};

/// Stable refusal categories for manifest/registry/request binding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdmissionRefusal {
    /// A digest field is not a lowercase SHA-256 hex string.
    MalformedDigest,
    /// A text field is blank or carries control characters.
    MalformedText,
    /// A required registry observation was not supplied.
    RegistryEvidenceMissing,
    /// The registry observation does not equal the immutable contract.
    RegistryEvidenceMismatch,
    /// The route, privacy, or data-class binding disagrees.
    RouteMismatch,
    /// The owner/credential binding disagrees.
    CredentialMismatch,
    /// The carried epoch disagrees with the full State Fence.
    EpochFenceConflict,
    /// A budget/deadline/cancellation ceiling is not a positive bound.
    NonPositiveCeiling,
    /// The request disagrees with the admitted operation binding.
    RequestMismatch,
}

impl AdmissionRefusal {
    /// Returns the stable machine-greppable reason string.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::MalformedDigest => "admission digest is not a lowercase SHA-256 hex digest",
            Self::MalformedText => "admission text is blank or carries control characters",
            Self::RegistryEvidenceMissing => "admission has no exact Module Registry evidence",
            Self::RegistryEvidenceMismatch => {
                "admission does not match the exact Module Registry generation evidence"
            }
            Self::RouteMismatch => "admission route/privacy/data binding is not exact",
            Self::CredentialMismatch => "admission owner/credential binding is not exact",
            Self::EpochFenceConflict => "admission epoch disagrees with the full State Fence",
            Self::NonPositiveCeiling => "admission budget/deadline/cancellation bound is invalid",
            Self::RequestMismatch => "request disagrees with the admitted operation binding",
        }
    }
}

/// Principal-bound credential metadata. Secret material is never carried by
/// this record; a Kernel-owned introduction may resolve the opaque reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialBinding {
    /// Stable binding identity.
    pub binding_id: String,
    /// Principal that owns the credential.
    pub owner_principal: String,
    /// Principal allowed to present the request to this route.
    pub acting_principal: String,
    /// Explicit route/operation mode.
    pub mode: String,
    /// Exact data classes admitted for this use.
    pub data_classes: Vec<String>,
    /// Digest of the opaque secret reference, never the secret itself.
    pub secret_ref_sha256: String,
    /// Revocation/rotation evidence handle.
    pub revocation_ref: String,
}

impl CredentialBinding {
    fn validate(&self) -> Result<(), AdmissionRefusal> {
        for value in [
            &self.binding_id,
            &self.owner_principal,
            &self.acting_principal,
            &self.mode,
            &self.revocation_ref,
        ] {
            validate_text(value)?;
        }
        if self.data_classes.is_empty()
            || self
                .data_classes
                .iter()
                .any(|value| validate_text(value).is_err())
        {
            return Err(AdmissionRefusal::MalformedText);
        }
        if !is_lowercase_sha256(&self.secret_ref_sha256) {
            return Err(AdmissionRefusal::MalformedDigest);
        }
        Ok(())
    }
}

/// Exact provider route and disclosure boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRoute {
    /// Stable route identity selected by the registry.
    pub route_id: String,
    /// Provider implementation identity, not an executable path.
    pub provider_id: String,
    /// Route class (offline, service, interactive, and so on).
    pub route_class: String,
    /// Exact privacy/data class admitted for the route.
    pub data_class: String,
    /// Whether this route may consume paid/network budget.
    pub paid_network: bool,
    /// Credential binding selected for this route.
    pub credential_binding: CredentialBinding,
}

impl ProviderRoute {
    fn validate(&self) -> Result<(), AdmissionRefusal> {
        for value in [
            &self.route_id,
            &self.provider_id,
            &self.route_class,
            &self.data_class,
        ] {
            validate_text(value)?;
        }
        self.credential_binding.validate()
    }
}

/// Module/Capability Registry evidence for one immutable provider generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModuleGenerationEvidence {
    /// Module identity.
    pub module_id: String,
    /// Module generation identity.
    pub generation_id: String,
    /// Exact executable artifact digest.
    pub artifact_sha256: String,
    /// Exact configuration digest.
    pub config_sha256: String,
    /// Exact protocol digest.
    pub protocol_sha256: String,
    /// Protocol revision selected by the registry.
    pub protocol_revision: ContractVersion,
    /// Route selected for this module generation.
    pub route: ProviderRoute,
    /// Full State Fence under which the evidence was observed.
    pub state_fence: StateFence,
    /// Registry evidence record is active and usable.
    pub active: bool,
    /// Digest of the complete registry evidence record.
    pub evidence_sha256: String,
}

impl ModuleGenerationEvidence {
    fn validate(&self) -> Result<(), AdmissionRefusal> {
        for value in [&self.module_id, &self.generation_id] {
            validate_text(value)?;
        }
        for digest in [
            &self.artifact_sha256,
            &self.config_sha256,
            &self.protocol_sha256,
            &self.evidence_sha256,
        ] {
            if !is_lowercase_sha256(digest) {
                return Err(AdmissionRefusal::MalformedDigest);
            }
        }
        self.state_fence
            .validate()
            .map_err(|_| AdmissionRefusal::EpochFenceConflict)?;
        self.route.validate()
    }

    fn matches_contract(&self, contract: &BridgeContract) -> bool {
        self.module_id == contract.module_id
            && self.generation_id == contract.module_generation_id
            && self.artifact_sha256 == contract.bridge.executable_sha256()
            && self.config_sha256 == contract.config_digest
            && self.protocol_sha256 == contract.protocol_digest
            && self.protocol_revision == contract.protocol_revision
            && self.state_fence == contract.fence
            && self.route == contract.route
            && self.evidence_sha256 == contract.registry_evidence_sha256
            && self.active
    }
}

/// Closed registry snapshot used to resolve a provider generation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRegistry {
    /// Exact active evidence records. No filesystem/environment discovery is
    /// performed by this type.
    pub records: Vec<ModuleGenerationEvidence>,
}

impl ProviderRegistry {
    /// Creates a closed registry snapshot.
    #[must_use]
    pub const fn new(records: Vec<ModuleGenerationEvidence>) -> Self {
        Self { records }
    }

    /// Resolves one exact active generation record for a contract.
    pub fn resolve(
        &self,
        contract: &BridgeContract,
    ) -> Result<ModuleGenerationEvidence, AdmissionRefusal> {
        contract.validate()?;
        for record in &self.records {
            record.validate()?;
        }
        let mut matches = self
            .records
            .iter()
            .filter(|record| record.matches_contract(contract));
        let resolved = matches
            .next()
            .cloned()
            .ok_or(AdmissionRefusal::RegistryEvidenceMismatch)?;
        if matches.next().is_some() {
            return Err(AdmissionRefusal::RegistryEvidenceMismatch);
        }
        Ok(resolved)
    }
}

/// Stable cancellation identity bound to the admitted operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationBinding {
    /// Stable operation identity used by cancel/reconcile.
    pub operation_id: OperationId,
    /// `RequestIdentity` cancellation id.
    pub cancellation_id: String,
    /// Principal allowed to cancel this exact operation.
    pub owner_principal: String,
    /// Absolute deadline in Unix milliseconds.
    pub deadline_unix_ms: i64,
}

impl CancellationBinding {
    fn validate(&self) -> Result<(), AdmissionRefusal> {
        validate_text(&self.cancellation_id)?;
        validate_text(&self.owner_principal)?;
        if self.deadline_unix_ms <= 0 {
            return Err(AdmissionRefusal::NonPositiveCeiling);
        }
        Ok(())
    }
}

/// Closed immutable manifest for one provider generation and route.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BridgeContract {
    /// Exact executable identity, including digest.
    pub bridge: BridgeIdentity,
    /// Exact config/protocol bytes.
    pub config_digest: String,
    pub protocol_digest: String,
    /// Registry-selected module identity.
    pub module_id: String,
    pub module_generation_id: String,
    /// Registry evidence digest; it is not a blank reference.
    pub registry_evidence_sha256: String,
    /// Process generation carried by the Kernel claim.
    pub process_generation: Generation,
    /// Authority epoch and full State Fence.
    pub epoch: EpochId,
    pub fence: StateFence,
    /// Exact route/privacy/credential binding.
    pub route: ProviderRoute,
    /// Privacy ceiling; no request may widen it.
    pub disclosure: DisclosureClass,
    pub data_class: String,
    /// Budget/deadline ceilings.
    pub budget_units: u64,
    pub deadline_ms: i64,
    pub protocol_revision: ContractVersion,
    pub required_schema: String,
    pub bridge_generation: String,
    /// Stable cancellation identity.
    pub cancellation: CancellationBinding,
}

impl BridgeContract {
    /// Constructs and validates a closed bridge contract.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        bridge: BridgeIdentity,
        config_digest: impl Into<String>,
        protocol_digest: impl Into<String>,
        module_id: impl Into<String>,
        module_generation_id: impl Into<String>,
        registry_evidence_sha256: impl Into<String>,
        process_generation: Generation,
        epoch: EpochId,
        fence: StateFence,
        route: ProviderRoute,
        disclosure: DisclosureClass,
        data_class: impl Into<String>,
        budget_units: u64,
        deadline_ms: i64,
        protocol_revision: ContractVersion,
        required_schema: impl Into<String>,
        bridge_generation: impl Into<String>,
        cancellation: CancellationBinding,
    ) -> Result<Self, AdmissionRefusal> {
        let value = Self {
            bridge,
            config_digest: config_digest.into(),
            protocol_digest: protocol_digest.into(),
            module_id: module_id.into(),
            module_generation_id: module_generation_id.into(),
            registry_evidence_sha256: registry_evidence_sha256.into(),
            process_generation,
            epoch,
            fence,
            route,
            disclosure,
            data_class: data_class.into(),
            budget_units,
            deadline_ms,
            protocol_revision,
            required_schema: required_schema.into(),
            bridge_generation: bridge_generation.into(),
            cancellation,
        };
        value.validate()?;
        Ok(value)
    }

    /// Validates every closed field and cross-binding.
    pub fn validate(&self) -> Result<(), AdmissionRefusal> {
        self.bridge
            .validate()
            .map_err(|_| AdmissionRefusal::MalformedText)?;
        for digest in [
            &self.config_digest,
            &self.protocol_digest,
            &self.registry_evidence_sha256,
        ] {
            if !is_lowercase_sha256(digest) {
                return Err(AdmissionRefusal::MalformedDigest);
            }
        }
        for text in [
            &self.module_id,
            &self.module_generation_id,
            &self.data_class,
            &self.required_schema,
            &self.bridge_generation,
        ] {
            validate_text(text)?;
        }
        if !self.epoch.is_same_authority(&self.fence.authority_epoch) {
            return Err(AdmissionRefusal::EpochFenceConflict);
        }
        self.fence
            .validate()
            .map_err(|_| AdmissionRefusal::EpochFenceConflict)?;
        if self.route.data_class != self.data_class
            || self.route.credential_binding.data_classes != [self.data_class.clone()]
        {
            return Err(AdmissionRefusal::RouteMismatch);
        }
        self.route.validate().map_err(|error| match error {
            AdmissionRefusal::CredentialMismatch => AdmissionRefusal::CredentialMismatch,
            _ => error,
        })?;
        if self.cancellation.deadline_unix_ms != self.deadline_ms
            || self.cancellation.owner_principal != self.route.credential_binding.owner_principal
        {
            return Err(AdmissionRefusal::CredentialMismatch);
        }
        self.cancellation
            .validate()
            .map_err(|_| AdmissionRefusal::NonPositiveCeiling)?;
        if self.budget_units == 0 || self.deadline_ms <= 0 {
            return Err(AdmissionRefusal::NonPositiveCeiling);
        }
        Ok(())
    }

    /// Returns the exact registry evidence digest.
    #[must_use]
    pub fn registry_evidence_sha256(&self) -> &str {
        &self.registry_evidence_sha256
    }

    /// Returns the exact route binding.
    #[must_use]
    pub const fn route(&self) -> &ProviderRoute {
        &self.route
    }

    /// Returns the exact credential binding.
    #[must_use]
    pub const fn credential_binding(&self) -> &CredentialBinding {
        &self.route.credential_binding
    }

    /// Returns the stable cancellation binding.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationBinding {
        &self.cancellation
    }
}

/// Immutable admitted manifest for one bounded research-provider operation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderAdmission {
    contract: BridgeContract,
    operation_id: OperationId,
}

impl ProviderAdmission {
    /// Resolves a contract against a closed Module Registry snapshot and binds
    /// it to one stable operation identity.
    pub fn from_contract(
        contract: BridgeContract,
        operation_id: OperationId,
        registry: &ProviderRegistry,
    ) -> Result<Self, AdmissionRefusal> {
        contract.validate()?;
        let evidence = registry.resolve(&contract).map_err(|error| match error {
            AdmissionRefusal::RegistryEvidenceMismatch => {
                AdmissionRefusal::RegistryEvidenceMismatch
            }
            _ => error,
        })?;
        if evidence.generation_id != contract.module_generation_id
            || evidence.state_fence != contract.fence
        {
            return Err(AdmissionRefusal::RegistryEvidenceMismatch);
        }
        if contract.cancellation.operation_id != operation_id {
            return Err(AdmissionRefusal::RequestMismatch);
        }
        Ok(Self {
            contract,
            operation_id,
        })
    }

    /// Returns the resolved immutable contract.
    #[must_use]
    pub const fn contract(&self) -> &BridgeContract {
        &self.contract
    }

    /// Returns the admitted bridge identity.
    #[must_use]
    pub const fn bridge(&self) -> &BridgeIdentity {
        &self.contract.bridge
    }

    /// Returns the exact config digest.
    #[must_use]
    pub fn config_digest(&self) -> &str {
        &self.contract.config_digest
    }

    /// Returns the exact protocol digest.
    #[must_use]
    pub fn protocol_digest(&self) -> &str {
        &self.contract.protocol_digest
    }

    /// Returns the Module Registry evidence reference.
    #[must_use]
    pub fn module_id(&self) -> &str {
        &self.contract.module_id
    }

    /// Returns the Module generation evidence reference.
    #[must_use]
    pub fn module_generation_id(&self) -> &str {
        &self.contract.module_generation_id
    }

    /// Returns the exact registry evidence digest.
    #[must_use]
    pub fn registry_evidence_sha256(&self) -> &str {
        &self.contract.registry_evidence_sha256
    }

    /// Returns the admitted process generation.
    #[must_use]
    pub const fn process_generation(&self) -> Generation {
        self.contract.process_generation
    }

    /// Returns the admitted Authority Epoch.
    #[must_use]
    pub const fn epoch(&self) -> &EpochId {
        &self.contract.epoch
    }

    /// Returns the admitted full State Fence.
    #[must_use]
    pub const fn fence(&self) -> &StateFence {
        &self.contract.fence
    }

    /// Returns the exact route.
    #[must_use]
    pub const fn route(&self) -> &ProviderRoute {
        &self.contract.route
    }

    /// Returns the privacy ceiling.
    #[must_use]
    pub const fn disclosure(&self) -> DisclosureClass {
        self.contract.disclosure
    }

    /// Returns the exact data class.
    #[must_use]
    pub fn data_class(&self) -> &str {
        &self.contract.data_class
    }

    /// Returns the credential binding.
    #[must_use]
    pub const fn credential_binding(&self) -> &CredentialBinding {
        self.contract.credential_binding()
    }

    /// Returns the budget ceiling.
    #[must_use]
    pub const fn budget_units(&self) -> u64 {
        self.contract.budget_units
    }

    /// Returns the absolute deadline in Unix milliseconds.
    #[must_use]
    pub const fn deadline_ms(&self) -> i64 {
        self.contract.deadline_ms
    }

    /// Returns the protocol revision.
    #[must_use]
    pub const fn protocol_revision(&self) -> &ContractVersion {
        &self.contract.protocol_revision
    }

    /// Returns the required result schema.
    #[must_use]
    pub fn required_schema(&self) -> &str {
        &self.contract.required_schema
    }

    /// Returns the bridge generation echo.
    #[must_use]
    pub fn bridge_generation(&self) -> &str {
        &self.contract.bridge_generation
    }

    /// Returns the stable cancellation identity.
    #[must_use]
    pub const fn cancellation(&self) -> &CancellationBinding {
        self.contract.cancellation()
    }

    /// Returns the stable operation identity for cancel/reconcile.
    #[must_use]
    pub const fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    /// Binds one request to the exact admitted operation.
    pub fn validate_request(&self, request: &ResearchQueryRequest) -> Result<(), AdmissionRefusal> {
        request
            .validate()
            .map_err(|_| AdmissionRefusal::RequestMismatch)?;
        let credential = self.credential_binding();
        if !fences_match_exact(&request.state_fence, &self.contract.fence)
            || request.bridge_generation != self.contract.bridge_generation
            || request.disclosure != self.contract.disclosure
            || request.requester_principal != credential.acting_principal
            || request.budget_units == 0
            || request.budget_units > self.contract.budget_units
            || request.deadline_ms <= 0
            || request.deadline_ms > self.contract.deadline_ms
            || request.protocol_revision != self.contract.protocol_revision
            || request.required_schema != self.contract.required_schema
        {
            return Err(AdmissionRefusal::RequestMismatch);
        }
        Ok(())
    }
}

fn validate_text(value: &str) -> Result<(), AdmissionRefusal> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        Err(AdmissionRefusal::MalformedText)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::num::NonZeroU64;

    use eliot_contracts::{EpochLineageId, ResourceGeneration};
    use eliot_process::Generation;
    use eliot_research_exchange_api::{
        AllowedReferenceManifest, AnchorPrecision, DisclosureClass, SourceClass,
    };

    use super::*;
    use crate::support::{
        DIGEST_A, DIGEST_B, DIGEST_C, DIGEST_UPPER, test_epoch, test_fence, test_identity,
        test_operation_id, test_request,
    };

    fn route() -> ProviderRoute {
        ProviderRoute {
            route_id: "route-research-private".to_owned(),
            provider_id: "provider-research".to_owned(),
            route_class: "service".to_owned(),
            data_class: "project-bound".to_owned(),
            paid_network: true,
            credential_binding: CredentialBinding {
                binding_id: "credential-binding-24".to_owned(),
                owner_principal: "researcher-owner".to_owned(),
                acting_principal: "requester-24-slice-a".to_owned(),
                mode: "explicit_delegation".to_owned(),
                data_classes: vec!["project-bound".to_owned()],
                secret_ref_sha256: DIGEST_A.to_owned(),
                revocation_ref: "revocation-24".to_owned(),
            },
        }
    }

    fn contract() -> BridgeContract {
        BridgeContract::new(
            test_identity(),
            DIGEST_B,
            DIGEST_C,
            "mod-research-provider",
            "gen-mod-24-a",
            DIGEST_A,
            Generation::new(3).expect("generation"),
            test_epoch(),
            test_fence(),
            route(),
            DisclosureClass::ProjectBound,
            "project-bound",
            10,
            1_800_000_000_000,
            ContractVersion::new(1, 0, 0),
            "research-evidence-bundle/v1",
            "gen-24-slice-a",
            CancellationBinding {
                operation_id: test_operation_id(),
                cancellation_id: "cancel-op-24".to_owned(),
                owner_principal: "researcher-owner".to_owned(),
                deadline_unix_ms: 1_800_000_000_000,
            },
        )
        .expect("contract")
    }

    fn evidence() -> ModuleGenerationEvidence {
        let contract = contract();
        ModuleGenerationEvidence {
            module_id: contract.module_id.clone(),
            generation_id: contract.module_generation_id.clone(),
            artifact_sha256: contract.bridge.executable_sha256().to_owned(),
            config_sha256: contract.config_digest.clone(),
            protocol_sha256: contract.protocol_digest.clone(),
            protocol_revision: contract.protocol_revision,
            route: contract.route.clone(),
            state_fence: contract.fence.clone(),
            active: true,
            evidence_sha256: contract.registry_evidence_sha256.clone(),
        }
    }

    #[test]
    fn registry_resolution_is_exact_and_requires_evidence() {
        let contract = contract();
        let registry = ProviderRegistry::new(vec![evidence()]);
        let admission =
            ProviderAdmission::from_contract(contract.clone(), test_operation_id(), &registry)
                .expect("resolved admission");
        assert_eq!(admission.registry_evidence_sha256(), DIGEST_A);
        assert!(
            ProviderRegistry::new(Vec::new())
                .resolve(&contract)
                .is_err()
        );
    }

    #[test]
    fn registry_route_privacy_and_credential_mismatches_fail_closed() {
        let contract = contract();
        let mut registry = ProviderRegistry::new(vec![evidence()]);
        registry.records[0].route.route_id = "route-foreign".to_owned();
        assert_eq!(
            ProviderAdmission::from_contract(contract.clone(), test_operation_id(), &registry)
                .err(),
            Some(AdmissionRefusal::RegistryEvidenceMismatch)
        );
        let mut foreign = contract.clone();
        foreign.route.data_class = "public".to_owned();
        assert_eq!(
            foreign.validate().err(),
            Some(AdmissionRefusal::RouteMismatch)
        );
        let mut credential = contract;
        credential.route.credential_binding.owner_principal = "foreign".to_owned();
        assert_eq!(
            credential.validate().err(),
            Some(AdmissionRefusal::CredentialMismatch)
        );
    }

    #[test]
    fn request_binds_full_fence_owner_budget_deadline_and_schema() {
        let admission = ProviderAdmission::from_contract(
            contract(),
            test_operation_id(),
            &ProviderRegistry::new(vec![evidence()]),
        )
        .expect("admission");
        assert!(admission.validate_request(&test_request()).is_ok());
        let mut request = test_request();
        request.requester_principal = "foreign".to_owned();
        assert_eq!(
            admission.validate_request(&request).err(),
            Some(AdmissionRefusal::RequestMismatch)
        );
        let mut request = test_request();
        request.state_fence = StateFence::new(
            test_epoch(),
            ResourceGeneration::new(9).expect("resource generation"),
        );
        assert_eq!(
            admission.validate_request(&request).err(),
            Some(AdmissionRefusal::RequestMismatch)
        );
    }

    #[test]
    fn all_manifest_digest_and_text_boundaries_are_checked() {
        assert!(contract().bridge.validate().is_ok());
        let mut bad = contract();
        bad.config_digest = DIGEST_UPPER.to_owned();
        assert_eq!(
            bad.validate().err(),
            Some(AdmissionRefusal::MalformedDigest)
        );
        let mut bad = contract();
        bad.module_id = " \n".to_owned();
        assert_eq!(bad.validate().err(), Some(AdmissionRefusal::MalformedText));
        let mut bad = contract();
        bad.epoch = EpochId::new(
            EpochLineageId::new("6ba7b810-9dad-11d1-80b4-00c04fd430c8").expect("lineage"),
            NonZeroU64::new(8).expect("sequence"),
        )
        .expect("epoch");
        assert_eq!(
            bad.validate().err(),
            Some(AdmissionRefusal::EpochFenceConflict)
        );
    }

    #[test]
    fn matching_contract_preserves_exact_route_and_stable_operation() {
        let contract = contract();
        let admission = ProviderAdmission::from_contract(
            contract,
            test_operation_id(),
            &ProviderRegistry::new(vec![evidence()]),
        )
        .expect("admission");
        assert_eq!(admission.route().route_id, "route-research-private");
        assert_eq!(admission.cancellation().cancellation_id, "cancel-op-24");
        assert_eq!(admission.operation_id().as_str(), "op-24-slice-a");
        let _ = AllowedReferenceManifest {
            run_id: "run".to_owned(),
            state_fence: test_fence(),
            source_handles: vec!["source".to_owned()],
            evidence_handles: Vec::new(),
            artifact_handles: Vec::new(),
            allowed_anchor_precision: AnchorPrecision::Section,
            stale_or_revoked_handles: Vec::new(),
            digest: DIGEST_A.to_owned(),
        };
        let _: Option<SourceClass> = None;
    }
}
