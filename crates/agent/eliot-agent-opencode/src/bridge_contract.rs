//! I6.5 bridge contract declaration for the `OpenCode` HTTP/SSE adapter.
//!
//! The `OpenCode` adapter translates, isolates and observes between the
//! `OpenCode` HTTP/SSE protocol and the provider-neutral A-01 contracts. Task
//! meaning, policy decisions and promotion remain with the Governor and
//! Dreamer owners; the adapter never starts a child, owns canonical state, or
//! treats a provider terminal message as task finish.
//!
//! # The declaration is issued, not derived
//!
//! [`OpenCodeBridgeDeclaration`] is the owner-issued, versioned record for ONE
//! installed `OpenCode` adapter generation. It uses the same scheme
//! `ClaudeSidecarBridgeDeclaration` uses for the Claude sidecar and
//! `AgentBridgeClientDeclaration` uses for the agent bridge: the owner builds
//! the record, its canonical bytes are hashed, and `declaration_sha256`
//! records that hash, so [`OpenCodeBridgeDeclaration::validate`] re-proves the
//! owner-recorded value instead of accepting a recomputed substitute. An
//! edited-after-issuance copy is refused at validation, not repaired.
//!
//! [`issue_opencode_declaration`] is the issuer. It is called by the adapter
//! owner for one admitted generation - the owner that knows the route
//! generation it admitted and the authority [`StateFence`] it admitted under -
//! and its output is what composition carries in the bootstrap admission
//! envelope.
//!
//! ## Why the gate is load-bearing
//!
//! Before this record existed, the bootstrap gate derived the contract from
//! `&envelope.binding.route` and re-validated it against that same route, so
//! every binding check inside it was a tautology and deleting the gate changed
//! no outcome. [`validate_opencode_declaration`] is not derived that way. It
//! compares OWNER-ISSUED values against the live admission:
//!
//! - `declaration.adapter_id` and `declaration.adapter_revision` are the
//!   owner's statement of which installed adapter generation this is. A
//!   declaration issued for another artifact generation is refused.
//! - `declaration.route` is the route generation the owner admitted. The gate
//!   compares it to the route of the admitted execution binding. A declaration
//!   issued for another route generation is refused, and the route digest its
//!   contract carries (`contract.admitted_binding_digest`, recomputed here
//!   with the route owner's own [`route_fingerprint_digest_for`]) is then a
//!   digest over the wrong generation.
//! - `declaration.state_fence` is the I6.10 authority epoch identity
//!   (`EpochId { lineage_id, sequence }` carried inside the fence) the
//!   generation was admitted under. It is compared to the live current fence;
//!   a declaration issued under a retired or foreign epoch is refused.
//! - `declaration.declaration_sha256` is recomputed over the declaration's own
//!   canonical bytes. Any field edited after issuance is refused.
//!
//! The declaration binds the admitted artifact/config/route generation rather
//! than a mutable README or a self-reported version, and an unknown required
//! metadata item stays a qualification gap: [`BridgeContract::validate`]
//! refuses an incomplete contract rather than filling it in.

use eliot_agent_api::{RouteFingerprint, StateFence, route_fingerprint_digest_for};
use eliot_contracts::{
    BRIDGE_CONTRACT_REVISION, BridgeCapability, BridgeContract, BridgeId, CredentialsBoundary,
    DataClass, ExportRemovalPath, FailureTranslation, HealthProbe, LowercaseSha256,
    ProcessExecutorProfile, SideEffect, SuiteRevision, TimeoutsAndCancellation, UpstreamProject,
    UpstreamVersion, canonical_json_bytes, sha256_hex,
};
use serde::{Deserialize, Serialize};

use crate::{
    OPENCODE_ADAPTER_ID, OPENCODE_HOST_FAMILY, OPENCODE_PROTOCOL_TRANSPORT,
    OPENCODE_WIRE_LOCATOR_PROTOCOL_REVISION,
};

/// Stable wire identity of one owner-issued `OpenCode` bridge declaration.
pub const OPENCODE_DECLARATION_WIRE_ID: &str = "eliot.agent-opencode.bridge-declaration";

/// Current owner-issued declaration wire version.
pub const OPENCODE_DECLARATION_WIRE_VERSION: u16 = 1;

/// The owner-issued I6.5 declaration for ONE installed `OpenCode` adapter
/// generation.
///
/// This value is configuration issued by the adapter owner, not authority. It
/// carries no task, session, credential, or effect grant; it states which
/// adapter generation, route generation and authority epoch were admitted, and
/// it carries that generation's complete I6.5 [`BridgeContract`]. Every value
/// in it is owner-issued, so a consumer can compare it against a live
/// admission without deriving it from that admission.
///
/// `adapter_revision` is the crate's existing installed-bootstrap artifact
/// identity [`OPENCODE_WIRE_LOCATOR_PROTOCOL_REVISION`]. The `OpenCode`
/// adapter has no adapter-factory owner of its own, so that owner-issued
/// constant - the same value the live wire locator binds - is the artifact
/// generation this declaration names, rather than a counter invented here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeBridgeDeclaration {
    /// Declaration wire identity; must equal
    /// [`OPENCODE_DECLARATION_WIRE_ID`].
    pub wire_id: String,
    /// Declaration wire version; must equal
    /// [`OPENCODE_DECLARATION_WIRE_VERSION`].
    pub wire_version: u16,
    /// Exact adapter identity of the installed generation; must equal
    /// [`OPENCODE_ADAPTER_ID`].
    pub adapter_id: String,
    /// Installed adapter artifact generation; must equal
    /// [`OPENCODE_WIRE_LOCATOR_PROTOCOL_REVISION`].
    pub adapter_revision: String,
    /// The route generation the owner admitted for this adapter.
    pub route: RouteFingerprint,
    /// The authority `StateFence` (I6.10 epoch identity) the owner admitted
    /// this generation under.
    pub state_fence: StateFence,
    /// The complete I6.5 declaration for this admitted generation.
    pub contract: BridgeContract,
    /// Lowercase SHA-256 over every declaration field except this field.
    pub declaration_sha256: String,
}

impl OpenCodeBridgeDeclaration {
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
    /// Re-proves the exact wire shape, the exact adapter identity and artifact
    /// revision, the exact `OpenCode` route family, the route and epoch shapes,
    /// the owner-recorded digest, and the carried I6.5 contract - including
    /// that the contract binds this declaration's own route generation through
    /// the route owner's digest.
    pub fn validate(&self) -> Result<(), BridgeContractError> {
        if self.wire_id != OPENCODE_DECLARATION_WIRE_ID
            || self.wire_version != OPENCODE_DECLARATION_WIRE_VERSION
        {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "wire_id",
                detail: "unsupported OpenCode declaration wire shape",
            });
        }
        if self.adapter_id != OPENCODE_ADAPTER_ID {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "adapter_id",
                detail: "declaration does not name the OpenCode adapter",
            });
        }
        if self.adapter_revision != OPENCODE_WIRE_LOCATOR_PROTOCOL_REVISION {
            return Err(BridgeContractError::InvalidDeclaration {
                field: "adapter_revision",
                detail: "declaration was issued for a different adapter artifact generation",
            });
        }
        if self.route.host_family != OPENCODE_HOST_FAMILY
            || self.route.adapter != OPENCODE_ADAPTER_ID
            || self.route.protocol_transport != OPENCODE_PROTOCOL_TRANSPORT
        {
            return Err(BridgeContractError::Binding {
                field: "route",
                detail: "route is not the exact OpenCode HTTP/SSE route",
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
        self.contract
            .validate()
            .map_err(BridgeContractError::Contract)?;
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

/// Issues the I6.5 declaration for one admitted `OpenCode` adapter generation.
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
pub fn issue_opencode_declaration(
    route: &RouteFingerprint,
    state_fence: &StateFence,
) -> Result<OpenCodeBridgeDeclaration, BridgeContractError> {
    let issued = OpenCodeBridgeDeclaration {
        wire_id: OPENCODE_DECLARATION_WIRE_ID.to_owned(),
        wire_version: OPENCODE_DECLARATION_WIRE_VERSION,
        adapter_id: OPENCODE_ADAPTER_ID.to_owned(),
        adapter_revision: OPENCODE_WIRE_LOCATOR_PROTOCOL_REVISION.to_owned(),
        route: route.clone(),
        state_fence: state_fence.clone(),
        contract: opencode_adapter_contract(route)?,
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
/// - `admitted_route` is the route of the admitted execution binding. A
///   declaration issued for another route generation is refused, and with it
///   the route-generation digest its contract carries.
/// - `current_fence` is the live authority fence. A declaration issued under
///   another authority epoch is refused.
///
/// [`OpenCodeBridgeDeclaration::validate`] has already re-proved the wire
/// shape, the adapter identity and artifact revision, the owner-recorded
/// digest, and the carried I6.5 contract bound to the declaration's own route
/// generation.
pub fn validate_opencode_declaration(
    declaration: &OpenCodeBridgeDeclaration,
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

/// Builds the I6.5 contract for one admitted `OpenCode` route generation.
///
/// The admitted route supplies the exact generation identity through the route
/// owner's own digest, so the contract is bound to the generation rather than
/// to a self-reported version; the remaining declared metadata is the adapter
/// owner's fixed declaration. This is the issuer's own builder: it is not a
/// validator and never decides admission.
pub fn opencode_adapter_contract(
    route: &RouteFingerprint,
) -> Result<BridgeContract, BridgeContractError> {
    Ok(BridgeContract {
        contract_revision: BRIDGE_CONTRACT_REVISION,
        bridge_id: BridgeId::new(OPENCODE_ADAPTER_ID)?,
        admitted_binding_digest: Some(admitted_route_digest(route)?),
        upstream_project_and_license: UpstreamProject {
            name: "OpenCode".to_owned(),
            license: "OpenCode".to_owned(),
        },
        upstream_version: UpstreamVersion {
            version: "http+sse/v1".to_owned(),
            artifact: OPENCODE_ADAPTER_ID.to_owned(),
        },
        eliot_capabilities: vec![
            BridgeCapability {
                capability: "agent.execution".to_owned(),
                protocol_mapping: format!(
                    "{OPENCODE_HOST_FAMILY}/{OPENCODE_PROTOCOL_TRANSPORT} -> A-01 agent-result"
                ),
            },
            BridgeCapability {
                capability: "agent.event.normalization".to_owned(),
                protocol_mapping: "sse-stream -> normalized-host-event".to_owned(),
            },
            BridgeCapability {
                capability: "agent.cancellation".to_owned(),
                protocol_mapping: "executor.cancel(operation-id)".to_owned(),
            },
        ],
        data_classes: vec![
            DataClass::new("agent.opencode.request")?,
            DataClass::new("agent.opencode.response")?,
            DataClass::new("agent.candidate.result")?,
            DataClass::new("agent.usage.receipt")?,
        ],
        credentials_boundary: CredentialsBoundary {
            owner: "composition.secret-ref".to_owned(),
            refs_only: true,
            boundary: "credential reference only; never resolved, logged, or forwarded by this package".to_owned(),
        },
        side_effects: vec![SideEffect {
            effect: "agent.opencode.launch".to_owned(),
            authority: "P-03 ProcessExecutor".to_owned(),
        }],
        timeouts_and_cancellation: TimeoutsAndCancellation {
            request_timeout_ms: None,
            cancellation: "executor.cancel(operation-id)".to_owned(),
        },
        health_probe: HealthProbe {
            probe: "executor.inspect(operation-id)".to_owned(),
            read_only: true,
        },
        failure_translation: vec![
            FailureTranslation {
                upstream_failure: "opencode.route-mismatch".to_owned(),
                eliot_failure: "adapter.route-mismatch".to_owned(),
                boundary: "typed refusal; no task decision granted".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "opencode.run-error".to_owned(),
                eliot_failure: "adapter.run-error".to_owned(),
                boundary: "typed refusal; reconcile before retry".to_owned(),
            },
            FailureTranslation {
                upstream_failure: "opencode.unknown-outcome".to_owned(),
                eliot_failure: "adapter.unknown-outcome".to_owned(),
                boundary: "unknown outcome preserved; reconcile, never blind retry".to_owned(),
            },
        ],
        process_executor_profile: ProcessExecutorProfile {
            executor: "P-03 ProcessExecutor".to_owned(),
            contour: "single-take launch binding".to_owned(),
            single_take: true,
        },
        independent_contract_suite: SuiteRevision {
            suite: "eliot-agent-opencode".to_owned(),
            revision: "v1".to_owned(),
        },
        fixture_and_golden_corpus: SuiteRevision {
            suite: "eliot-agent-opencode".to_owned(),
            revision: "v1".to_owned(),
        },
        update_method: eliot_contracts::UpdateMethod {
            method: "staged-generation-cutover".to_owned(),
            compatibility: "adapter-revision-route-and-epoch-equality".to_owned(),
        },
        export_removal_path: ExportRemovalPath {
            export: "candidate-result-and-evidence-refs".to_owned(),
            removal: "fence-new-calls-drain-revoke-route-remove-artifacts".to_owned(),
        },
        owner_resume: "Governor resumes task meaning and policy decisions; Dreamer resumes cognitive assessment and promotion; the adapter only translates, isolates and observes".to_owned(),
    })
}

/// Recomputes the admitted route's owner digest.
///
/// Reuses the route owner's existing identity function
/// ([`route_fingerprint_digest_for`], `sha256_hex(canonical_json_bytes(..))`
/// over the complete [`RouteFingerprint`]) so the value cannot be free text or
/// a self-reported label, and so the issuer and the consuming gate recompute it
/// the same way.
fn admitted_route_digest(route: &RouteFingerprint) -> Result<LowercaseSha256, BridgeContractError> {
    route_fingerprint_digest_for(route).map_err(|error| BridgeContractError::Route {
        detail: error.to_string(),
    })
}

/// Typed failure for `OpenCode` declaration issuance and validation.
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
    /// The declaration does not bind to the admitted route or epoch.
    #[error("bridge contract binding failed for {field}: {detail}")]
    Binding {
        /// The failing field.
        field: &'static str,
        /// Bounded detail.
        detail: &'static str,
    },
    /// The owner-issued declaration is not the current proven wire shape.
    #[error("opencode bridge declaration invalid for {field}: {detail}")]
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
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration};
    use serde_json::json;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const OTHER_LINEAGE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn fixture_digest(seed: &str) -> Result<LowercaseSha256, Box<dyn std::error::Error>> {
        Ok(serde_json::from_value(json!(sha256_hex(
            format!("opencode-declaration-{seed}").as_bytes()
        )))?)
    }

    fn fixture_route() -> Result<RouteFingerprint, Box<dyn std::error::Error>> {
        Ok(RouteFingerprint {
            host_family: OPENCODE_HOST_FAMILY.to_owned(),
            adapter: OPENCODE_ADAPTER_ID.to_owned(),
            protocol_transport: OPENCODE_PROTOCOL_TRANSPORT.to_owned(),
            runtime_hash: fixture_digest("runtime")?,
            adapter_hash: fixture_digest("adapter")?,
            provider: "opencode-go".to_owned(),
            model: "deepseek-v4-flash".to_owned(),
            auth_billing: "interactive-user".to_owned(),
            serializer_hash: fixture_digest("serializer")?,
            tool_semantics_hash: fixture_digest("tools")?,
            reasoning_mode: "catalogue-default".to_owned(),
            continuation_behavior: "native-resume".to_owned(),
            feature_flags_hash: fixture_digest("features")?,
        })
    }

    fn fixture_epoch(lineage: &str, sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
        let sequence =
            std::num::NonZeroU64::new(sequence).ok_or("epoch sequence must be nonzero")?;
        Ok(EpochId::new(EpochLineageId::new(lineage)?, sequence)?)
    }

    fn fixture_fence(lineage: &str) -> Result<StateFence, Box<dyn std::error::Error>> {
        Ok(StateFence::new(
            fixture_epoch(lineage, 1)?,
            ResourceGeneration::new(1)?,
        ))
    }

    /// The declaration the owner issues for the fixture admitted generation.
    fn admitted_declaration() -> Result<OpenCodeBridgeDeclaration, Box<dyn std::error::Error>> {
        Ok(issue_opencode_declaration(
            &fixture_route()?,
            &fixture_fence(TEST_LINEAGE)?,
        )?)
    }

    /// Asserts the owner-issued gate refuses `declaration`, and records the
    /// prior behaviour: the gate this one replaced derived its contract from
    /// `route` itself, so it accepted this exact attempt whatever declaration
    /// was presented. The declaration is the only input that can change that
    /// outcome, which is what makes it load-bearing.
    fn assert_refused(
        declaration: &OpenCodeBridgeDeclaration,
        route: &RouteFingerprint,
        fence: &StateFence,
    ) -> TestResult {
        assert!(validate_opencode_declaration(declaration, route, fence).is_err());
        let derived = opencode_adapter_contract(route)?;
        derived.validate()?;
        assert!(derived.binds_admitted_generation(&admitted_route_digest(route)?));
        Ok(())
    }

    /// The owner-issued declaration gate: every case below is refused only
    /// because the declaration came from outside.
    ///
    /// Each case is a declaration the owner issued for a DIFFERENT generation
    /// than the attempt was admitted under. Under the prior derived gate every
    /// one of them was admitted, because that gate rebuilt its contract from
    /// the attempt it was judging and therefore always agreed with it.
    #[test]
    fn gate_refuses_owner_declaration_for_another_generation() -> TestResult {
        let route = fixture_route()?;
        let fence = fixture_fence(TEST_LINEAGE)?;

        // A declaration issued for a different route generation.
        let mut foreign_route = route.clone();
        foreign_route.model = "other-generation-model".to_owned();
        let foreign = issue_opencode_declaration(&foreign_route, &fence)?;
        assert_refused(&foreign, &route, &fence)?;

        // A declaration issued under a different authority epoch (I6.10).
        let foreign = issue_opencode_declaration(&route, &fixture_fence(OTHER_LINEAGE)?)?;
        assert_refused(&foreign, &route, &fence)?;

        // A declaration issued for a different adapter artifact generation.
        let mut declaration = admitted_declaration()?;
        declaration.adapter_revision = "eliot-opencode-bootstrap-http-sse-v0".to_owned();
        assert_refused(&declaration, &route, &fence)?;

        // A declaration edited after issuance without re-deriving its digest.
        let mut declaration = admitted_declaration()?;
        declaration.contract.side_effects[0].authority = "caller-selected-authority".to_owned();
        assert_refused(&declaration, &route, &fence)?;

        // A declaration whose declared capabilities were dropped, with a
        // consistent outer digest.
        let mut declaration = admitted_declaration()?;
        declaration.contract.eliot_capabilities.clear();
        let declaration = declaration.with_computed_digest()?;
        assert_refused(&declaration, &route, &fence)?;

        // A declaration whose route digest was swapped for another
        // generation's, with a consistent outer digest.
        let mut declaration = admitted_declaration()?;
        declaration.contract.admitted_binding_digest =
            Some(route_fingerprint_digest_for(&foreign_route)?);
        let declaration = declaration.with_computed_digest()?;
        assert_refused(&declaration, &route, &fence)?;
        Ok(())
    }

    /// The owner-issued declaration for the exact admitted generation is
    /// admitted, and it is the only input shape the gate accepts.
    #[test]
    fn owner_declaration_binds_the_exact_admitted_generation() -> TestResult {
        let route = fixture_route()?;
        let fence = fixture_fence(TEST_LINEAGE)?;
        let declaration = admitted_declaration()?;
        assert_eq!(declaration.wire_id, OPENCODE_DECLARATION_WIRE_ID);
        assert_eq!(declaration.adapter_id, OPENCODE_ADAPTER_ID);
        assert_eq!(
            declaration.adapter_revision,
            OPENCODE_WIRE_LOCATOR_PROTOCOL_REVISION
        );
        assert_eq!(declaration.route, route);
        assert_eq!(declaration.state_fence, fence);
        assert_eq!(
            declaration.declaration_sha256,
            declaration.compute_digest()?
        );
        declaration.validate()?;
        assert!(
            declaration
                .contract
                .binds_admitted_generation(&route_fingerprint_digest_for(&route)?)
        );
        validate_opencode_declaration(&declaration, &route, &fence)?;
        Ok(())
    }

    /// Owner-issued declarations are versioned, closed wire records, so an
    /// unknown shape or an unknown field is refused rather than reinterpreted.
    #[test]
    fn owner_declaration_wire_is_closed_and_versioned() -> TestResult {
        let declaration = admitted_declaration()?;
        let bytes = serde_json::to_vec(&declaration)?;
        let decoded: OpenCodeBridgeDeclaration = serde_json::from_slice(&bytes)?;
        assert_eq!(decoded, declaration);

        let mut stale = serde_json::to_value(&declaration)?;
        stale["wire_version"] = json!(u16::MAX);
        let stale: OpenCodeBridgeDeclaration = serde_json::from_value(stale)?;
        assert!(stale.validate().is_err());

        let mut forbidden = serde_json::to_value(&declaration)?;
        forbidden["effect_authority"] = json!("caller-selected");
        assert!(serde_json::from_value::<OpenCodeBridgeDeclaration>(forbidden).is_err());
        Ok(())
    }
}
