//! I6.5 bridge contract declaration for the Claude sidecar adapter.
//!
//! The Claude adapter translates, isolates and observes between the Claude
//! Agent SDK NDJSON sidecar protocol and the provider-neutral A-01 contracts.
//! Task meaning, policy decisions and promotion remain with the Governor and
//! Dreamer owners; the adapter produces candidate-only results and never
//! acquires task authority.
//!
//! # The declaration is issued, not derived
//!
//! [`ClaudeSidecarBridgeDeclaration`] is the owner-issued, versioned record for
//! ONE installed Claude sidecar generation. It uses the same scheme the agent
//! bridge already uses for its `AgentBridgeClientDeclaration` in
//! `bins/eliot-agent-bridge/src/bridge_contract.rs`: the owner builds the
//! record, the canonical bytes are hashed, and `declaration_sha256` records
//! that hash so [`ClaudeSidecarBridgeDeclaration::validate`] re-proves the
//! owner-recorded value instead of accepting a recomputed substitute. An
//! edited-after-issuance copy is refused at validation, not repaired.
//!
//! [`issue_claude_sidecar_declaration`] is the issuer. It is called by the
//! adapter owner for one admitted generation - the sidecar installation /
//! route-admission owner that knows the route generation it admitted and the
//! authority [`StateFence`] it admitted under - and its output is what
//! composition hands to [`crate::execution::prepare`].
//!
//! ## Why the gate is load-bearing
//!
//! [`validate_claude_sidecar_declaration`] is the consuming gate. It compares
//! the OWNER-ISSUED values against the live admission, and none of them is
//! derived from the values it is checked against:
//!
//! - `declaration.adapter_id` and `declaration.factory_revision` are the
//!   owner's statement of which adapter generation was installed. A
//!   declaration issued for a previous factory revision is refused.
//! - `declaration.route` is the route generation the owner admitted.
//!   [`crate::execution::prepare`] compares it to the route of the admitted
//!   attempt. A declaration issued for a different route generation is refused
//!   - the route digest the declaration carries (its
//!   `contract.admitted_binding_digest`, recomputed here with the route owner's
//!   own [`route_fingerprint_digest_for`]) is then a digest over the wrong
//!   generation.
//! - `declaration.state_fence` is the I6.10 authority epoch identity of the
//!   generation the owner admitted. It is compared to the live current fence. A
//!   declaration issued under a retired or foreign epoch is refused.
//! - `declaration.declaration_sha256` is recomputed over the declaration's own
//!   canonical bytes. Any field edited after issuance is refused.
//!
//! None of these can be implied by checks that already ran on the admit path:
//! before this record existed, [`crate::execution::prepare`] DERIVED the
//! declaration from `(&input.descriptor, &input.admitted.route)` and validated
//! it against that same pair, so every binding check inside it was a
//! tautology and deleting it changed no outcome. Now the declaration arrives
//! from outside, and deleting the gate admits a sidecar generation that the
//! owner never admitted for this attempt.
//!
//! `prepare` still runs its own admitted-path checks; this gate is additive and
//! removes nothing. The declaration binds the admitted artifact/config/route
//! generation rather than a mutable README or a self-reported version, and an
//! unknown required metadata item stays a qualification gap:
//! [`BridgeContract::validate`] refuses an incomplete contract rather than
//! filling it in.

use eliot_agent_api::{RouteFingerprint, StateFence, route_fingerprint_digest_for};
use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, LowercaseSha256,
    ProcessExecutorProfile, SideEffect, SuiteRevision, TimeoutsAndCancellation, UpstreamProject,
    UpstreamVersion, canonical_json_bytes, sha256_hex,
};
use serde::{Deserialize, Serialize};

use crate::execution::CLAUDE_SIDECAR_FACTORY_REVISION;
use crate::{
    CLAUDE_SIDECAR_ADAPTER_ID, CLAUDE_SIDECAR_HOST_FAMILY, CLAUDE_SIDECAR_PROTOCOL_VERSION,
    CLAUDE_SIDECAR_TRANSPORT,
};

/// Stable wire identity of one owner-issued Claude sidecar bridge declaration.
pub const CLAUDE_SIDECAR_DECLARATION_WIRE_ID: &str = "eliot.agent-claude.sidecar-declaration";

/// Current owner-issued declaration wire version.
pub const CLAUDE_SIDECAR_DECLARATION_WIRE_VERSION: u16 = 1;

/// The owner-issued I6.5 declaration for ONE installed Claude sidecar
/// generation.
///
/// This value is configuration issued by the adapter owner, not authority. It
/// carries no task, session, credential, or effect grant; it states which
/// adapter generation, route generation and authority epoch were admitted, and
/// it carries that generation's complete I6.5 [`BridgeContract`]. Every value
/// in it is owner-issued, so a consumer can compare it against a live
/// admission without deriving it from that admission.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaudeSidecarBridgeDeclaration {
    /// Declaration wire identity; must equal
    /// [`CLAUDE_SIDECAR_DECLARATION_WIRE_ID`].
    pub wire_id: String,
    /// Declaration wire version; must equal
    /// [`CLAUDE_SIDECAR_DECLARATION_WIRE_VERSION`].
    pub wire_version: u16,
    /// Exact adapter identity of the installed sidecar generation; must equal
    /// [`CLAUDE_SIDECAR_ADAPTER_ID`].
    pub adapter_id: String,
    /// Factory revision of the installed sidecar generation; must equal
    /// [`CLAUDE_SIDECAR_FACTORY_REVISION`].
    pub factory_revision: u64,
    /// The route generation the owner admitted for this sidecar.
    pub route: RouteFingerprint,
    /// The authority `StateFence` (I6.10 epoch identity) the owner admitted
    /// this generation under.
    pub state_fence: StateFence,
    /// The complete I6.5 declaration for this admitted generation.
    pub contract: BridgeContract,
    /// Lowercase SHA-256 over every declaration field except this field.
    pub declaration_sha256: String,
}

impl ClaudeSidecarBridgeDeclaration {
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
    /// presented, and a record that was edited after issuance without this
    /// step is refused because its recorded digest no longer matches its bytes.
    pub fn with_computed_digest(mut self) -> Result<Self, BridgeContractError> {
        self.declaration_sha256 = self.compute_digest()?;
        Ok(self)
    }

    /// Validates the owner-issued declaration without admitting anything.
    ///
    /// Re-proves the exact wire shape, the exact adapter identity and factory
    /// revision, the route and epoch shapes, the owner-recorded digest, and the
    /// carried I6.5 contract - including that the contract binds this
    /// declaration's own route generation through the route owner's digest.
    pub fn validate(&self) -> Result<(), BridgeContractError> {
        if self.wire_id != CLAUDE_SIDECAR_DECLARATION_WIRE_ID
            || self.wire_version != CLAUDE_SIDECAR_DECLARATION_WIRE_VERSION
        {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "wire_id",
                detail: "unsupported Claude sidecar declaration wire shape",
            });
        }
        if self.adapter_id != CLAUDE_SIDECAR_ADAPTER_ID {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "adapter_id",
                detail: "declaration does not name the Claude sidecar adapter",
            });
        }
        if self.factory_revision != CLAUDE_SIDECAR_FACTORY_REVISION {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "factory_revision",
                detail: "declaration was issued for a different factory revision",
            });
        }
        self.route
            .validate()
            .map_err(|_| BridgeContractError::InvalidDeclaration {
                field: "route",
                detail: "declaration route is not a complete route fingerprint",
            })?;
        self.state_fence
            .validate()
            .map_err(|_| BridgeContractError::InvalidDeclaration {
                field: "state_fence",
                detail: "declaration state fence is not a valid authority fence",
            })?;
        self.contract.validate().map_err(BridgeContractError::Contract)?;
        if self.contract.bridge_id.as_str() != self.adapter_id.as_str() {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "contract.bridge_id",
                detail: "carried contract names another bridge than the declaration",
            });
        }
        let admitted = admitted_route_digest(&self.route)?;
        if !self.contract.binds_admitted_generation(&admitted) {
            return Err(BridgeContractError::Binding {
                field: "contract.admitted_binding_digest",
                detail: "carried contract does not bind this declaration's route generation",
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

/// Issues the I6.5 declaration for one admitted Claude sidecar generation.
///
/// This is the issuer side, called by the adapter owner that installed and
/// admitted the generation: it supplies the route generation it admitted and
/// the authority `StateFence` it admitted under. The declaration is stamped
/// with the owner-recorded canonical digest and validated before it is handed
/// to composition, so a consumer never has to accept an unproven copy.
///
/// Every I6.5 field is fixed by the adapter owner rather than supplied by a
/// caller: the upstream project/license and exact version/artifact, the ELIOT
/// capabilities and their protocol mapping, the data classes, the credentials
/// boundary, the side effects and their gating authority, the
/// timeout/cancellation semantics, the health probe, the failure translations,
/// the process-executor profile, the independent suite and fixture corpus
/// revisions, the update method and its pre-exposure compatibility predicate,
/// and the export/removal path.
pub fn issue_claude_sidecar_declaration(
    route: &RouteFingerprint,
    state_fence: &StateFence,
) -> Result<ClaudeSidecarBridgeDeclaration, BridgeContractError> {
    let issued = ClaudeSidecarBridgeDeclaration {
        wire_id: CLAUDE_SIDECAR_DECLARATION_WIRE_ID.to_owned(),
        wire_version: CLAUDE_SIDECAR_DECLARATION_WIRE_VERSION,
        adapter_id: CLAUDE_SIDECAR_ADAPTER_ID.to_owned(),
        factory_revision: CLAUDE_SIDECAR_FACTORY_REVISION,
        route: route.clone(),
        state_fence: state_fence.clone(),
        contract: claude_adapter_contract(route)?,
        declaration_sha256: String::new(),
    }
    .with_computed_digest()?;
    issued.validate()?;
    Ok(issued)
}

/// Validates an owner-issued declaration against the live admission it must
/// serve.
///
/// The two admission arguments are the values the declaration is checked
/// against and is never built from, which is what makes this gate capable of
/// refusing:
///
/// - `admitted_route` is the route of the admitted attempt. A declaration
///   issued for another route generation is refused, and with it the
///   route-generation digest its contract carries.
/// - `current_fence` is the live authority fence. A declaration issued under
///   another authority epoch is refused.
///
/// [`ClaudeSidecarBridgeDeclaration::validate`] has already re-proved the wire
/// shape, the adapter identity and factory revision, the owner-recorded
/// digest, and the carried I6.5 contract bound to the declaration's own route
/// generation.
pub fn validate_claude_sidecar_declaration(
    declaration: &ClaudeSidecarBridgeDeclaration,
    admitted_route: &RouteFingerprint,
    current_fence: &StateFence,
) -> Result<(), BridgeContractError> {
    declaration.validate()?;
    if &declaration.route != admitted_route {
        return Err(BridgeContractError::Binding {
            field: "route",
            detail: "owner-issued declaration names another admitted route generation",
        });
    }
    if &declaration.state_fence != current_fence {
        return Err(BridgeContractError::Binding {
            field: "state_fence",
            detail: "owner-issued declaration names another authority epoch",
        });
    }
    Ok(())
}

/// Builds the I6.5 contract for one admitted Claude sidecar route generation.
///
/// The admitted route supplies the exact generation identity through the route
/// owner's own digest, so the contract is bound to the generation rather than
/// to a self-reported version; the remaining declared metadata is the adapter
/// owner's fixed declaration.
pub fn claude_adapter_contract(
    route: &RouteFingerprint,
) -> Result<BridgeContract, BridgeContractError> {
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new(CLAUDE_SIDECAR_ADAPTER_ID)?,
        admitted_binding_digest: Some(admitted_route_digest(route)?),
        upstream_project_and_license: UpstreamProject {
            name: "Claude Agent SDK".to_owned(),
            license: "Anthropic".to_owned(),
        },
        upstream_version: UpstreamVersion {
            version: CLAUDE_SIDECAR_PROTOCOL_VERSION.to_owned(),
            artifact: CLAUDE_SIDECAR_ADAPTER_ID.to_owned(),
        },
        eliot_capabilities: vec![
            BridgeCapability {
                capability: "agent.execution".to_owned(),
                protocol_mapping: format!(
                    "{CLAUDE_SIDECAR_HOST_FAMILY}/{CLAUDE_SIDECAR_TRANSPORT} -> A-01 agent-result"
                ),
            },
            BridgeCapability {
                capability: "agent.event.normalization".to_owned(),
                protocol_mapping: "ndjson-stream -> normalized-host-event".to_owned(),
            },
            BridgeCapability {
                capability: "agent.cancellation".to_owned(),
                protocol_mapping: "executor.cancel(operation-id)".to_owned(),
            },
        ],
        data_classes: vec![
            DataClass::new("agent.sidecar.request")?,
            DataClass::new("agent.sidecar.response")?,
            DataClass::new("agent.candidate.result")?,
            DataClass::new("agent.usage.receipt")?,
        ],
        credentials_boundary: CredentialsBoundary {
            owner: "composition.secret-ref".to_owned(),
            refs_only: true,
            boundary: "credential SecretRef reference only; never resolved, logged, or forwarded by this package".to_owned(),
        },
        side_effects: vec![SideEffect {
            effect: "agent.sidecar.launch".to_owned(),
            authority: "P-03 ProcessExecutor".to_owned(),
        }],
        timeouts_and_cancellation: TimeoutsAndCancellation {
            request_timeout_ms: None,
            cancellation: "executor.cancel(operation-id) with cleanup-state".to_owned(),
        },
        health_probe: HealthProbe {
            probe: "executor.inspect(operation-id)".to_owned(),
            read_only: true,
        },
        failure_translation: vec![
            FailureTranslation {
                upstream_failure: "executor.not-found".to_owned(),
                eliot_failure: "adapter.operation-not-found".to_owned(),
                boundary: "typed refusal; no task decision granted".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "executor.unavailable".to_owned(),
                eliot_failure: "adapter.executor-unavailable".to_owned(),
                boundary: "typed refusal; reconcile before retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "executor.unknown-outcome".to_owned(),
                eliot_failure: "adapter.unknown-outcome-requires-reconcile".to_owned(),
                boundary: "unknown outcome preserved; reconcile, never blind retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "sidecar.deadline-exceeded".to_owned(),
                eliot_failure: "adapter.deadline-exceeded".to_owned(),
                boundary: "deadline enforced; cancel and reconcile".to_owned(),
            },
        ],
        process_executor_profile: ProcessExecutorProfile {
            executor: "P-03 ProcessExecutor".to_owned(),
            contour: "single-take launch binding".to_owned(),
            single_take: true,
        },
        independent_contract_suite: SuiteRevision {
            suite: "eliot-agent-claude".to_owned(),
            revision: format!("factory-{CLAUDE_SIDECAR_FACTORY_REVISION}"),
        },
        fixture_and_golden_corpus: SuiteRevision {
            suite: "eliot-agent-claude".to_owned(),
            revision: format!("factory-{CLAUDE_SIDECAR_FACTORY_REVISION}"),
        },
        update_method: eliot_contracts::UpdateMethod {
            method: "staged-generation-cutover".to_owned(),
            compatibility: "adapter-revision-route-and-epoch-equality".to_owned(),
        },
        export_removal_path: ExportRemovalPath {
            export: "candidate-result-and-evidence-refs".to_owned(),
            removal: "fence-new-calls-drain-revoke-route-remove-artifacts".to_owned(),
        },
        owner_resume: "Governor resumes task meaning and policy decisions; Dreamer resumes cognitive assessment and promotion; the adapter only translates, isolates and observes and produces candidate-only results".to_owned(),
    })
}

/// Recomputes the admitted route's owner digest.
///
/// Reuses the route owner's existing identity function
/// ([`route_fingerprint_digest_for`], `sha256_hex(canonical_json_bytes(..))`
/// over the complete [`RouteFingerprint`]) so the value cannot be free text or
/// a self-reported label, and so issuance and validation recompute it the same
/// way.
fn admitted_route_digest(route: &RouteFingerprint) -> Result<LowercaseSha256, BridgeContractError> {
    route_fingerprint_digest_for(route).map_err(|error| BridgeContractError::Route {
        detail: error.to_string(),
    })
}

/// Typed failure for Claude sidecar declaration issuance and validation.
#[derive(Clone, Debug, thiserror::Error, PartialEq, Eq)]
pub enum BridgeContractError {
    /// The neutral contract failed validation.
    #[error("bridge contract invalid: {0}")]
    Contract(#[from] eliot_contracts::ContractError),
    /// The admitted route identity could not be recomputed.
    #[error("admitted route invalid: {detail}")]
    Route {
        /// Bounded detail.
        detail: String,
    },
    /// The owner-issued declaration does not bind to the live admission.
    #[error("bridge contract binding failed for {field}: {detail}")]
    Binding {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
    /// The owner-issued declaration is not the current proven wire shape.
    #[error("claude bridge declaration invalid for {field}: {detail}")]
    InvalidDeclaration {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
}
