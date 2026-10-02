//! I6.5 bridge contract declaration for the agent bridge.
//!
//! The agent bridge translates, isolates and observes between the
//! agent-facing MCP/stdio protocol and the Kernel named-pipe IPC protocol.
//! Task meaning, policy decisions and promotion remain with the Governor and
//! Dreamer owners; this declaration records the exact boundary where the
//! bridge stops and those owners resume.
//!
//! # The declaration is issued, not derived
//!
//! [`agent_bridge_contract`] builds a contract FROM
//! [`AgentBridgeClientDeclaration`], and
//! [`validate_agent_bridge_contract`] validated that derived contract against
//! the same declaration, so every binding check inside it agreed with the input
//! that built it. That is a tautology: it could not refuse a well-formed
//! contract for a different admitted generation, because the digest it compares
//! is recomputed from the very declaration being judged.
//!
//! [`AgentBridgeI65Declaration`] replaces that shape with the one the sibling
//! adapters already use (`OpenCodeBridgeDeclaration` and
//! `ClaudeSidecarBridgeDeclaration`): an owner-issued, versioned,
//! `deny_unknown_fields`, digest-protected record for ONE installed bridge
//! generation, issued by [`issue_agent_bridge_declaration`] and consumed by the
//! gate [`validate_agent_bridge_declaration`].
//!
//! ## Why the gate is load-bearing
//!
//! The two admission arguments of [`validate_agent_bridge_declaration`] are
//! values the issuer's caller did not construct:
//!
//! - `admitted` is the sealed client binding the Kernel front door admitted. It
//!   is compared against the owner-issued `module_generation` (the installed
//!   immutable runtime generation, carrying its registered module contract) and
//!   its module identity. The declaration's own `contract` is re-proved against
//!   it through [`validate_agent_bridge_contract`], so every check the derived
//!   gate performed still runs and none is weakened.
//! - `admitted_fence` is the authority fence the Kernel issued on the
//!   authenticated admission receipt. The record's `state_fence` is compared to
//!   it on the I6.10 exact epoch identity tuple
//!   (`EpochId { lineage_id, sequence }`) plus the resource generation, so a
//!   declaration issued for another authority epoch is refused.
//!
//! `declaration.declaration_sha256` is recomputed over the record's own
//! canonical bytes, so any field edited after issuance is refused rather than
//! repaired, and `declaration.adapter_revision` is the installed artifact
//! identity of this binary rather than a counter invented here.
//!
//! The binding is therefore to the admitted artifact/config/route generation as
//! the Kernel admits it, not to a mutable README or a self-reported version. An
//! unknown required metadata item stays a qualification gap:
//! [`BridgeContract::validate`] refuses an incomplete contract rather than
//! filling it in.

use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, LowercaseSha256,
    ProcessExecutorProfile, SideEffect, StateFence, SuiteRevision, TimeoutsAndCancellation,
    UpstreamProject, UpstreamVersion, canonical_json_bytes, sha256_hex,
};
use eliot_protocol::{
    AGENT_BRIDGE_MODULE_ID, AgentBridgeClientDeclaration,
    ProtocolModuleGeneration as ModuleGeneration,
};
use serde::{Deserialize, Serialize};

/// Recomputes the admitted declaration's content digest as the neutral typed
/// digest the contract carries.
///
/// `AgentBridgeClientDeclaration::validate` already recomputes and compares
/// `declaration_sha256`; this is the same value, retyped. A checked copy never
/// reaches the contract because the digest is recomputed from the admitted
/// declaration on every construction and every validation.
fn admitted_declaration_digest(
    declaration: &AgentBridgeClientDeclaration,
) -> Result<LowercaseSha256, BridgeContractError> {
    let hex = declaration
        .compute_digest()
        .map_err(|_| BridgeContractError::Binding {
            field: "admitted_binding_digest",
            detail: "admitted declaration digest could not be recomputed",
        })?;
    serde_json::from_value(serde_json::Value::String(hex)).map_err(|_| {
        BridgeContractError::Binding {
            field: "admitted_binding_digest",
            detail: "admitted declaration digest is not a canonical SHA-256 value",
        }
    })
}

/// Builds the agent-bridge contract from the admitted declaration.
///
/// The declaration's `ModuleContract` and `ModuleGeneration` supply the exact
/// upstream version and artifact, and the recomputed declaration digest binds
/// the admitted artifact/config/generation; the contract is derived from the
/// admitted generation, never self-reported.
pub fn agent_bridge_contract(
    declaration: &AgentBridgeClientDeclaration,
) -> Result<BridgeContract, BridgeContractError> {
    let module_id = declaration.module_id.as_str();
    let artifact = declaration.module_contract.artifact_id.as_str();
    let version = declaration.module_contract.version.to_string();
    let capabilities = declaration
        .capabilities
        .iter()
        .map(|capability| BridgeCapability {
            capability: capability.clone(),
            protocol_mapping: format!("{capability} -> eliot.agent-bridge.v1"),
        })
        .collect();
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new(module_id)?,
        admitted_binding_digest: Some(admitted_declaration_digest(declaration)?),
        upstream_project_and_license: UpstreamProject {
            name: "ELIOT Kernel".to_owned(),
            license: "ELIOT".to_owned(),
        },
        upstream_version: UpstreamVersion {
            version,
            artifact: artifact.to_owned(),
        },
        eliot_capabilities: capabilities,
        data_classes: vec![
            DataClass::new("agent.activation.request")?,
            DataClass::new("agent.activation.receipt")?,
            DataClass::new("agent.event.envelope")?,
            DataClass::new("agent.host.request")?,
            DataClass::new("agent.host.event")?,
        ],
        credentials_boundary: CredentialsBoundary {
            owner: "kernel.session".to_owned(),
            refs_only: true,
            boundary: "Kernel-issued session and capability token; no raw credential crosses the bridge".to_owned(),
        },
        side_effects: vec![
            SideEffect {
                effect: "agent.bridge.activate".to_owned(),
                authority: "kernel.capability-token".to_owned(),
            },
            SideEffect {
                effect: "agent.event.forward".to_owned(),
                authority: "kernel.event-route".to_owned(),
            },
            SideEffect {
                effect: "agent.host.request".to_owned(),
                authority: "kernel.host-request-route".to_owned(),
            },
        ],
        timeouts_and_cancellation: TimeoutsAndCancellation {
            request_timeout_ms: Some(60_000),
            cancellation: "kernel.request-cancellation".to_owned(),
        },
        health_probe: HealthProbe {
            probe: "activation exchange over admitted transport".to_owned(),
            read_only: false,
        },
        failure_translation: vec![
            FailureTranslation {
                upstream_failure: "transport.send-failed".to_owned(),
                eliot_failure: "provider.unavailable".to_owned(),
                boundary: "no phase reached; re-attach and reconcile before retrying".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "transport.unknown-outcome".to_owned(),
                eliot_failure: "provider.unknown-outcome".to_owned(),
                boundary: "unknown outcome preserved; reconcile, never blind retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "kernel.rejected".to_owned(),
                eliot_failure: "provider.rejected".to_owned(),
                boundary: "typed refusal; no task decision granted".to_owned(),
            },
        ],
        process_executor_profile: ProcessExecutorProfile {
            executor: "P-03 ProcessExecutor".to_owned(),
            contour: "single-take launch binding via host".to_owned(),
            single_take: true,
        },
        independent_contract_suite: SuiteRevision {
            suite: "eliot-agent-bridge".to_owned(),
            revision: "v1".to_owned(),
        },
        fixture_and_golden_corpus: SuiteRevision {
            suite: "eliot-agent-bridge".to_owned(),
            revision: "v1".to_owned(),
        },
        update_method: eliot_contracts::UpdateMethod {
            method: "staged-generation-cutover".to_owned(),
            compatibility: "module-contract-and-generation-equality".to_owned(),
        },
        export_removal_path: ExportRemovalPath {
            export: "bridge-journal-and-receipts".to_owned(),
            removal: "fence-new-calls-drain-revoke-route-remove-artifacts".to_owned(),
        },
        owner_resume: "Governor resumes task meaning and policy decisions; Dreamer resumes cognitive assessment and promotion; the bridge only translates, isolates and observes".to_owned(),
    })
}

/// Validates the agent-bridge contract against the admitted declaration.
///
/// The contract's bridge identity must match the declaration's module id, the
/// upstream version/artifact must match the declaration's module contract and
/// generation, and the contract's admitted binding digest must equal the digest
/// recomputed from the admitted declaration. Any mismatch is a
/// contract-binding failure: a well-formed contract for a different admitted
/// declaration is not a pass.
///
/// This function is only capable of refusing a contract that was PRESENTED. It
/// is tautological when the contract was derived from the same
/// `declaration` argument on the spot, because the digest it compares is
/// recomputed from that declaration either way. [`issue_agent_bridge_declaration`]
/// builds the contract at issuance and
/// [`validate_agent_bridge_declaration`] presents it at the gate, which is what
/// makes these checks load-bearing.
pub fn validate_agent_bridge_contract(
    contract: &BridgeContract,
    declaration: &AgentBridgeClientDeclaration,
) -> Result<(), BridgeContractError> {
    contract.validate().map_err(BridgeContractError::Contract)?;
    if contract.bridge_id.as_str() != declaration.module_id.as_str() {
        return Err(BridgeContractError::Binding {
            field: "bridge_id",
            detail: "contract bridge id does not match the admitted declaration module id",
        });
    }
    if contract.upstream_version.artifact != declaration.module_contract.artifact_id.as_str() {
        return Err(BridgeContractError::Binding {
            field: "upstream_version.artifact",
            detail: "contract artifact does not match the admitted module contract artifact",
        });
    }
    let admitted = admitted_declaration_digest(declaration)?;
    if !contract.binds_admitted_generation(&admitted) {
        return Err(BridgeContractError::Binding {
            field: "admitted_binding_digest",
            detail: "contract does not bind the admitted declaration generation",
        });
    }
    Ok(())
}

/// Stable wire identity of one owner-issued agent-bridge declaration.
pub const AGENT_BRIDGE_DECLARATION_WIRE_ID: &str = "eliot.agent-bridge.bridge-declaration";

/// Current owner-issued declaration wire version.
pub const AGENT_BRIDGE_DECLARATION_WIRE_VERSION: u16 = 1;

/// The owner-issued I6.5 declaration for ONE installed agent-bridge
/// generation.
///
/// This value is configuration issued by the bridge declaration owner, not
/// authority. It carries no task, session, credential, or effect grant; it
/// states which installed generation and authority epoch were admitted, and it
/// carries that generation's complete I6.5 [`BridgeContract`]. Every value in it
/// is owner-issued, so a consumer can compare it against a live admission
/// without deriving it from that admission.
///
/// `adapter_revision` is the installed artifact identity of this binary
/// (`CARGO_PKG_VERSION`), the same installed identity
/// `bridge_contour_declaration` already pins as the contour's adapter and
/// runtime version: this binary IS the bridge artifact, so its crate version is
/// the installed artifact generation rather than a counter invented here. A
/// rebuild that changes it needs a reissued declaration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentBridgeI65Declaration {
    /// Declaration wire identity; must equal
    /// [`AGENT_BRIDGE_DECLARATION_WIRE_ID`].
    pub wire_id: String,
    /// Declaration wire version; must equal
    /// [`AGENT_BRIDGE_DECLARATION_WIRE_VERSION`].
    pub wire_version: u16,
    /// Exact module identity of the installed generation; must equal
    /// [`AGENT_BRIDGE_MODULE_ID`].
    pub adapter_id: String,
    /// Installed bridge artifact generation; must equal this crate's
    /// `CARGO_PKG_VERSION`.
    pub adapter_revision: String,
    /// The installed immutable runtime generation, carrying its registered
    /// module contract and admitted generation fence.
    pub module_generation: ModuleGeneration,
    /// The authority `StateFence` (I6.10 epoch identity) the generation was
    /// admitted under.
    pub state_fence: StateFence,
    /// The complete I6.5 declaration for this admitted generation.
    pub contract: BridgeContract,
    /// Lowercase SHA-256 over every declaration field except this field.
    pub declaration_sha256: String,
}

impl AgentBridgeI65Declaration {
    /// Returns the deterministic bytes covered by `declaration_sha256`.
    pub fn canonical_unsigned_bytes(&self) -> Result<Vec<u8>, BridgeContractError> {
        let mut unsigned = self.clone();
        unsigned.declaration_sha256.clear();
        canonical_json_bytes(&unsigned).map_err(|_| BridgeContractError::InvalidDeclaration {
            field: "declaration",
            detail: "owner-issued declaration is not canonically serializable",
        })
    }

    /// Computes the canonical declaration digest.
    pub fn compute_digest(&self) -> Result<String, BridgeContractError> {
        Ok(sha256_hex(&self.canonical_unsigned_bytes()?))
    }

    /// Populates the owner-recorded canonical digest.
    ///
    /// This is the owner-side step only. It does not relax validation: the
    /// resulting record must still pass [`Self::validate`] before it is
    /// presented, and a record edited after issuance without this step is
    /// refused because its recorded digest no longer matches its bytes.
    pub fn with_computed_digest(mut self) -> Result<Self, BridgeContractError> {
        self.declaration_sha256 = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the owner-issued declaration without admitting anything.
    ///
    /// Re-proves the exact wire shape, the exact module identity and installed
    /// artifact revision, the admitted generation fence, the carried I6.5
    /// contract, and the owner-recorded digest. The cross-checks that need the
    /// live admission - the sealed binding and the Kernel-issued fence - belong
    /// to [`validate_agent_bridge_declaration`], because this method must not
    /// derive them.
    pub fn validate(&self) -> Result<(), BridgeContractError> {
        if self.wire_id != AGENT_BRIDGE_DECLARATION_WIRE_ID
            || self.wire_version != AGENT_BRIDGE_DECLARATION_WIRE_VERSION
        {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "wire_id",
                detail: "unsupported agent-bridge declaration wire shape",
            });
        }
        if self.adapter_id != AGENT_BRIDGE_MODULE_ID {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "adapter_id",
                detail: "declaration does not name the agent-bridge module",
            });
        }
        if self.adapter_revision != env!("CARGO_PKG_VERSION") {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "adapter_revision",
                detail: "declaration was issued for a different installed artifact generation",
            });
        }
        self.state_fence
            .validate()
            .map_err(BridgeContractError::Contract)?;
        self.contract.validate().map_err(BridgeContractError::Contract)?;
        if self.contract.bridge_id.as_str() != self.adapter_id.as_str() {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "contract.bridge_id",
                detail: "carried contract names another bridge than the declaration",
            });
        }
        if self.declaration_sha256 != self.compute_digest()? {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "declaration_sha256",
                detail: "declaration digest mismatch after issuance",
            });
        }
        Ok(())
    }
}

/// Issues the I6.5 declaration for one admitted agent-bridge generation.
///
/// This is the issuer side, called by the declaration owner for one admitted
/// generation from the sealed binding it holds: the record takes that
/// generation's module identity, installed artifact revision, registered
/// runtime generation and admitted generation fence, and carries the complete
/// I6.5 contract built by [`agent_bridge_contract`]. The declaration is stamped
/// with the owner-recorded canonical digest and validated before it is handed
/// to composition, so a consumer never has to accept an unproven copy.
///
/// The issuer deliberately does NOT receive the live Kernel authority fence.
/// That value does not exist yet at issuance, which is what lets
/// [`validate_agent_bridge_declaration`] compare the owner-issued epoch against
/// a fence the issuer's caller could not have constructed.
pub fn issue_agent_bridge_declaration(
    admitted: &AgentBridgeClientDeclaration,
) -> Result<AgentBridgeI65Declaration, BridgeContractError> {
    let issued = AgentBridgeI65Declaration {
        wire_id: AGENT_BRIDGE_DECLARATION_WIRE_ID.to_owned(),
        wire_version: AGENT_BRIDGE_DECLARATION_WIRE_VERSION,
        adapter_id: admitted.module_id.clone(),
        adapter_revision: env!("CARGO_PKG_VERSION").to_owned(),
        module_generation: admitted.module_generation.clone(),
        state_fence: admitted.module_generation.state_fence.clone(),
        contract: agent_bridge_contract(admitted)?,
        declaration_sha256: String::new(),
    }
    .with_computed_digest()?;
    issued.validate()?;
    // The same sealed-binding contract checks the derived gate ran still run
    // here, before the record leaves the issuer.
    validate_agent_bridge_contract(&issued.contract, admitted)?;
    Ok(issued)
}

/// Validates an owner-issued declaration against the live admission it must
/// serve.
///
/// The two admission arguments are the values the declaration is checked
/// against and was never built from, which is what makes this gate capable of
/// refusing:
///
/// - `admitted` is the sealed client binding the Kernel front door admitted.
///   The owner-issued module identity and registered runtime generation must
///   equal it, and the carried contract is re-proved against it through
///   [`validate_agent_bridge_contract`] - including that the contract binds the
///   sealed binding's admitted generation through the declaration owner's own
///   digest.
/// - `admitted_fence` is the authority fence the Kernel issued on the
///   authenticated admission receipt. The declaration's `state_fence` is
///   compared to it on the I6.10 exact epoch identity tuple
///   (`EpochId { lineage_id, sequence }`) plus the resource generation, so a
///   declaration issued under a retired or foreign epoch is refused.
///
/// [`AgentBridgeI65Declaration::validate`] has already re-proved the wire
/// shape, the module identity and installed artifact revision, the carried I6.5
/// contract, and the owner-recorded digest.
pub fn validate_agent_bridge_declaration(
    declaration: &AgentBridgeI65Declaration,
    admitted: &AgentBridgeClientDeclaration,
    admitted_fence: &StateFence,
) -> Result<(), BridgeContractError> {
    declaration.validate()?;
    if declaration.adapter_id != admitted.module_id {
        return Err(BridgeContractError::Binding {
            field: "adapter_id",
            detail: "owner-issued declaration names another admitted module identity",
        });
    }
    if declaration.module_generation != admitted.module_generation {
        return Err(BridgeContractError::Binding {
            field: "module_generation",
            detail: "owner-issued declaration names another admitted runtime generation",
        });
    }
    validate_agent_bridge_contract(&declaration.contract, admitted)?;
    if declaration.state_fence.authority_epoch != admitted_fence.authority_epoch
        || declaration.state_fence.resource_generation != admitted_fence.resource_generation
    {
        return Err(BridgeContractError::Binding {
            field: "state_fence",
            detail: "owner-issued declaration names another authority epoch",
        });
    }
    Ok(())
}

/// Typed failure for agent-bridge contract construction and validation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeContractError {
    /// The neutral contract failed validation.
    #[error("bridge contract invalid: {0}")]
    Contract(#[from] eliot_contracts::ContractError),
    /// The contract does not bind to the admitted declaration.
    #[error("bridge contract binding failed for {field}: {detail}")]
    Binding {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
    /// The owner-issued declaration is not the current proven wire shape.
    #[error("agent bridge declaration invalid for {field}: {detail}")]
    InvalidDeclaration {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{
        ArtifactId, ContractId, ContractVersion, EpochId, EpochLineageId, ResourceGeneration,
    };
    use eliot_protocol::{
        AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID, AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
        ProtocolRange, ProtocolVersion,
    };
    use eliot_runtime_contracts::{HealthVector, ModuleContract, ModuleGenerationState};
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OTHER_LINEAGE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn test_epoch(lineage: &str, sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
        let sequence = NonZeroU64::new(sequence).ok_or("epoch sequence must be nonzero")?;
        Ok(EpochId::new(EpochLineageId::new(lineage)?, sequence)?)
    }

    /// A sealed client binding for one admitted bridge generation.
    fn fixture_declaration(
        epoch_lineage: &str,
        generation: u64,
    ) -> Result<AgentBridgeClientDeclaration, Box<dyn std::error::Error>> {
        let fence = StateFence::new(
            test_epoch(epoch_lineage, 3)?,
            ResourceGeneration::new(generation)?,
        );
        let artifact = ArtifactId::new("a".repeat(64))?;
        let module = ContractId::new(AGENT_BRIDGE_MODULE_ID)?;
        let contract = ModuleContract {
            module_id: module.clone(),
            version: ContractVersion::new(1, 0, 0),
            artifact_id: artifact.clone(),
            protocols: vec!["eliot.agent-bridge.v1".to_owned()],
            capabilities: Vec::new(),
            required_capabilities: vec!["agent.bridge.activate".to_owned()],
            optional_capabilities: Vec::new(),
            advisory_capabilities: Vec::new(),
            state_owner: "eliot-agent-bridge".to_owned(),
            failure_domain: "agent-bridge".to_owned(),
            owner: AGENT_BRIDGE_MODULE_ID.to_owned(),
            hot_replace: false,
            startup_after: vec!["agent.bridge.activate".to_owned()],
            drain_before: vec!["agent.bridge.activate".to_owned()],
            invalidation_triggers: Vec::new(),
            supervision_plan: "one_for_one".to_owned(),
            child_restart: "transient".to_owned(),
            restart_intensity: "3/10m".to_owned(),
            resource_profile: "background-medium".to_owned(),
            privacy_classes: vec!["PUBLIC".to_owned()],
            permissions: Vec::new(),
            health_contract: "health/agent-bridge-v1".to_owned(),
            checkpoint_contract: "checkpoint/bridge-v1".to_owned(),
            compatibility_state: "rebuildable".to_owned(),
            independent_test_profile: "module/agent-bridge".to_owned(),
            contract_fixture_set: "eliot.agent-bridge.v1/agent.bridge.activate".to_owned(),
            affected_test_tags: vec!["agent-bridge".to_owned()],
            architecture: Vec::new(),
            telemetry: "telemetry/agent-bridge-v1".to_owned(),
            removal_boundary: "agent-bridge".to_owned(),
        };
        let generation_record = ModuleGeneration {
            module_id: module,
            generation: ResourceGeneration::new(generation)?,
            artifact_id: artifact,
            state: ModuleGenerationState::Ready,
            health: HealthVector::healthy(),
            state_fence: fence,
        };
        Ok(AgentBridgeClientDeclaration {
            wire_id: AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_ID.to_owned(),
            wire_version: AGENT_BRIDGE_CLIENT_DECLARATION_WIRE_VERSION,
            module_id: AGENT_BRIDGE_MODULE_ID.to_owned(),
            profile_id: "agent-bridge-profile-1".to_owned(),
            protocol_range: ProtocolRange {
                minimum: ProtocolVersion::CURRENT,
                maximum: ProtocolVersion::CURRENT,
            },
            module_contract: contract,
            module_generation: generation_record,
            capabilities: vec!["agent.bridge.activate".to_owned()],
            privacy_classes: vec!["PUBLIC".to_owned()],
            max_frame: 4_194_304,
            expected_kernel_sid: "S-1-5-18".to_owned(),
            expected_kernel_session_id: 0,
            expected_kernel_principal_binding: "kernel:agent-bridge".to_owned(),
            expected_kernel_authority_epoch: test_epoch(TEST_LINEAGE, 8)?,
            expected_kernel_generation: ResourceGeneration::new(2)?,
            expected_kernel_artifact_sha256: "b".repeat(64),
            expected_kernel_config_snapshot_sha256: "c".repeat(64),
            declaration_sha256: String::new(),
        }
        .with_computed_digest()?)
    }

    /// The declaration the owner issues for the fixture admitted generation.
    fn admitted_declaration() -> Result<AgentBridgeI65Declaration, Box<dyn std::error::Error>> {
        issue_agent_bridge_declaration(&fixture_declaration(TEST_LINEAGE, 7)?)
    }

    /// Asserts the owner-issued gate refuses `declaration`, and records the
    /// prior behaviour: the gate this one replaced derived its contract from
    /// the sealed binding it was judging and validated it against that same
    /// binding, so it accepted this exact attempt whatever was presented. The
    /// declaration is the only input that can change that outcome, which is
    /// what makes it load-bearing.
    fn assert_refused(
        declaration: &AgentBridgeI65Declaration,
        admitted: &AgentBridgeClientDeclaration,
        admitted_fence: &StateFence,
    ) -> TestResult {
        assert!(validate_agent_bridge_declaration(declaration, admitted, admitted_fence).is_err());
        let derived = agent_bridge_contract(admitted)?;
        derived.validate()?;
        validate_agent_bridge_contract(&derived, admitted)?;
        Ok(())
    }

    /// The owner-issued declaration gate: every case below is refused only
    /// because the declaration came from outside the attempt it is judged
    /// against. Under the prior derived gate each of them was admitted,
    /// because that gate rebuilt its contract from the attempt it was judging
    /// and therefore always agreed with it.
    #[test]
    fn gate_refuses_owner_declaration_for_another_generation() -> TestResult {
        let admitted = fixture_declaration(TEST_LINEAGE, 7)?;
        let fence = admitted.module_generation.state_fence.clone();

        // A declaration issued for another installed runtime generation.
        let other = fixture_declaration(TEST_LINEAGE, 8)?;
        assert_refused(&issue_agent_bridge_declaration(&other)?, &admitted, &fence)?;

        // A declaration whose generation was admitted under another authority
        // epoch (I6.10).
        let other_epoch = fixture_declaration(OTHER_LINEAGE, 7)?;
        assert_refused(
            &issue_agent_bridge_declaration(&other_epoch)?,
            &admitted,
            &fence,
        )?;

        // The Kernel admits the attempt under another live authority epoch than
        // the sealed binding names.
        let mut foreign_fence = fence.clone();
        foreign_fence.authority_epoch = test_epoch(OTHER_LINEAGE, 11)?;
        assert_refused(&admitted_declaration()?, &admitted, &foreign_fence)?;

        // A contract carrying another sealed binding's admitted-generation
        // digest, with a consistent outer declaration digest.
        let mut declaration = admitted_declaration()?;
        declaration.contract.admitted_binding_digest = Some(admitted_declaration_digest(&other)?);
        assert_refused(&declaration.with_computed_digest()?, &admitted, &fence)?;

        // A record edited after issuance without re-deriving its digest.
        let mut declaration = admitted_declaration()?;
        declaration.module_generation.generation = ResourceGeneration::new(9)?;
        assert_refused(&declaration, &admitted, &fence)?;

        // A record claiming another installed artifact generation.
        let mut declaration = admitted_declaration()?;
        declaration.adapter_revision = "eliot-agent-bridge-0.0.0-other".to_owned();
        assert_refused(&declaration, &admitted, &fence)?;
        Ok(())
    }

    /// The owner-issued declaration for the exact admitted generation is
    /// admitted, and it is the only input shape the gate accepts.
    #[test]
    fn owner_declaration_binds_the_exact_admitted_generation() -> TestResult {
        let admitted = fixture_declaration(TEST_LINEAGE, 7)?;
        let fence = admitted.module_generation.state_fence.clone();
        let declaration = issue_agent_bridge_declaration(&admitted)?;
        assert_eq!(declaration.wire_id, AGENT_BRIDGE_DECLARATION_WIRE_ID);
        assert_eq!(declaration.adapter_id, AGENT_BRIDGE_MODULE_ID);
        assert_eq!(declaration.adapter_revision, env!("CARGO_PKG_VERSION"));
        assert_eq!(declaration.module_generation, admitted.module_generation);
        assert_eq!(declaration.state_fence, fence);
        assert_eq!(declaration.declaration_sha256, declaration.compute_digest()?);
        declaration.validate()?;
        validate_agent_bridge_declaration(&declaration, &admitted, &fence)?;
        Ok(())
    }

    /// Owner-issued declarations are versioned, closed wire records, so an
    /// unknown shape or an unknown field is refused rather than reinterpreted.
    #[test]
    fn owner_declaration_wire_is_closed_and_versioned() -> TestResult {
        let declaration = admitted_declaration()?;
        let bytes = serde_json::to_vec(&declaration)?;
        let decoded: AgentBridgeI65Declaration = serde_json::from_slice(&bytes)?;
        assert_eq!(decoded, declaration);

        let mut stale = serde_json::to_value(&declaration)?;
        stale["wire_version"] = serde_json::json!(u16::MAX);
        let stale: AgentBridgeI65Declaration = serde_json::from_value(stale)?;
        assert!(stale.validate().is_err());

        let mut forbidden = serde_json::to_value(&declaration)?;
        forbidden["effect_authority"] = serde_json::json!("caller-selected");
        assert!(serde_json::from_value::<AgentBridgeI65Declaration>(forbidden).is_err());
        Ok(())
    }
}
