//! Daemon-side Kernel handshake and wire validation.
//!
//! Architecture: A13.2 (Governor/Kernel authenticated IPC boundary), A13.8
//! (process-receipt-gated pre-admission).
//! Implementation: I1.8 (artifact-bound session), I2.16 (generation fencing),
//! I2.23 (typed contract payloads), I1.12 (compatibility and rollback boundary).
//! Kernel remains the sole process, Store, and canonical authority owner.

use eliot_contracts::EpochId;
#[cfg(windows)]
use eliot_contracts::{ArtifactId, ContractId, ContractVersion, ResourceGeneration};
use eliot_governor::{GovernorLaunchConfig, KernelGenerationSnapshot, KernelPortError};
#[cfg(windows)]
use eliot_protocol::{
    ClientHello, Frame, FrameKind, MessageType, ProtocolPayload, ProtocolRange, ProtocolVersion,
    ServerHello,
};
#[cfg(windows)]
use eliot_runtime_contracts::{
    ModuleContract, ModuleGeneration, ModuleGenerationState, compare_published_projection,
};
use serde::Deserialize;
use thiserror::Error;

use super::KernelLaunchBinding;
use crate::{DaemonError, ELIOTD_RECEIPT_PENDING_REJECTION, PROTOCOL_VERSION, SERVICE_NAME};

#[cfg(windows)]
use eliot_kernel_core::{CompatibilityMismatch, MismatchField};

/// The single I1.12 required capability this daemon declares in its
/// `ClientHello` and therefore requires the Kernel's `ServerHello` to admit.
///
/// It is named here, once, because it is now TWO facts rather than one: the
/// value [`client_hello`] requests, and the value
/// [`admit_required_capability`] requires the peer to have granted. While the
/// request and the requirement were the same literal in two roles, the daemon
/// could request a capability and never check that the Kernel admitted it, so a
/// `ServerHello` carrying an empty or unrelated capability set passed this
/// boundary unchanged. Restating the literal at the requirement site would have
/// recreated that drift, so this constant is the one owner of both.
#[cfg(windows)]
const DAEMON_FRONT_DOOR_CAPABILITY: &str = "daemon";

/// The I1.12 fields the Kernel's `ServerHello` does not present to this daemon,
/// so this boundary cannot compare them.
///
/// I1.12 names seven items every process handshake exchanges. What the Kernel
/// actually presents in `ServerHello` on this wire is
/// `selected_protocol`, `authority_epoch`, `allowed_capabilities`,
/// `allowed_effects`, `control_channel`, `heartbeat_ms` and the
/// `config_snapshot` object; `eliot_protocol::ServerHello` is a pinned contract
/// shape and this daemon's own decoder reads `config_snapshot` under
/// `deny_unknown_fields`, so no further I1.12 item can arrive on it. The five
/// items below are therefore NOT verified here, and none of them is filled from
/// this binary's own values: a field the peer never presented, compared against
/// a value this process supplied itself, verifies nothing, and
/// `eliot_kernel_core::admit_handshake` is deliberately not called at this
/// boundary because admitting it would require constructing a
/// `CompatibilityEnvelope` from receiver-owned values for five of its fields.
///
/// Refusing on their absence is also not available: nothing this daemon presents
/// can make the Kernel publish them, so failing closed would refuse every
/// integrated startup rather than verify a peer. Each is recorded at the
/// boundary by [`record_unpresented_handshake_fields`] instead, so an
/// incomplete handshake is visible rather than read as a complete one.
#[cfg(windows)]
const UNPRESENTED_HANDSHAKE_FIELDS: [MismatchField; 5] = [
    MismatchField::ContractSetDigest,
    MismatchField::CanonicalFormatRange,
    MismatchField::ArchitectureDigest,
    MismatchField::NormativeSeal,
    MismatchField::MigrationClass,
];

#[derive(Debug, Error)]
pub(crate) enum KernelClientError {
    #[cfg(not(windows))]
    #[error("Kernel client is unavailable on this target")]
    Unsupported,
    #[error("Kernel client contract: {0}")]
    Contract(String),
    #[error("Kernel client unknown outcome: {0}")]
    Unknown(String),
    #[error("Kernel transport: {0}")]
    Transport(String),
    #[error("Kernel pre-admission transport: {0}")]
    PreAdmissionTransport(String),
    #[error("Kernel has not yet published the exact launched eliotd process receipt")]
    PreAdmissionPending,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum WireOutcome {
    Known {
        value: serde_json::Value,
        recovery: Option<serde_json::Value>,
    },
    Partial {
        reason: String,
        value: serde_json::Value,
    },
    Unknown {
        reason: String,
    },
    Error {
        code: String,
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelSnapshotWire {
    service: String,
    protocol: String,
    generation: u64,
    authority_epoch: EpochId,
    artifact_digest: String,
    protected_snapshot_digest: String,
}

pub(super) fn expected_snapshot(
    launch: &GovernorLaunchConfig,
) -> Result<KernelGenerationSnapshot, crate::DaemonError> {
    let snapshot = KernelGenerationSnapshot {
        service: launch.kernel.service.clone(),
        protocol: launch.kernel.protocol.clone(),
        generation: launch.kernel.generation,
        authority_epoch: launch.kernel.authority_epoch.clone(),
        artifact_digest: launch.kernel.artifact_digest.clone(),
        protected_snapshot_digest: launch.protected_snapshot_digest.clone(),
        principal: launch.kernel.principal.clone(),
    };
    snapshot
        .validate()
        .map_err(|error| crate::DaemonError::Kernel(error.to_string()))?;
    Ok(snapshot)
}

#[cfg(windows)]
impl super::DaemonKernelClient {
    pub(super) async fn snapshot_request(
        &self,
    ) -> Result<KernelGenerationSnapshot, KernelClientError> {
        let value = self
            .transact_async("snapshot", serde_json::json!({}))
            .await?;
        let wire: KernelSnapshotWire = serde_json::from_value(value)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        let snapshot = KernelGenerationSnapshot {
            service: wire.service,
            protocol: wire.protocol,
            generation: ResourceGeneration::new(wire.generation)
                .map_err(|error| KernelClientError::Contract(error.to_string()))?,
            authority_epoch: wire.authority_epoch,
            artifact_digest: wire.artifact_digest,
            protected_snapshot_digest: wire.protected_snapshot_digest,
            principal: self.launch.kernel.principal.clone(),
        };
        snapshot
            .validate()
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        self.launch
            .kernel
            .admits(&snapshot)
            .map_err(|error| KernelClientError::Contract(error.to_string()))?;
        Ok(snapshot)
    }
}

/// The daemon module's published I6.4 contract projection.
///
/// `module_contract.required_capabilities` carries runtime dependency edges onto
/// other hot modules. The `daemon` capability the daemon needs from the Kernel
/// is a handshake-requested capability (carried by `ClientHello.capabilities`),
/// not a runtime module-graph edge, so it is deliberately absent here: the two
/// lists are never conflated.
#[cfg(windows)]
pub(crate) fn declared_module_contract(
    module_id: ContractId,
    artifact_id: ArtifactId,
) -> ModuleContract {
    ModuleContract {
        module_id,
        version: ContractVersion::new(1, 0, 0),
        artifact_id,
        protocols: vec![PROTOCOL_VERSION.to_owned()],
        capabilities: Vec::new(),
        required_capabilities: Vec::new(),
        optional_capabilities: Vec::new(),
        advisory_capabilities: Vec::new(),
        state_owner: SERVICE_NAME.to_owned(),
        failure_domain: "daemon".to_owned(),
        owner: SERVICE_NAME.to_owned(),
        hot_replace: true,
        startup_after: Vec::new(),
        drain_before: Vec::new(),
        invalidation_triggers: Vec::new(),
        supervision_plan: "one_for_one".to_owned(),
        child_restart: "transient".to_owned(),
        restart_intensity: "3/10m".to_owned(),
        resource_profile: "background-medium".to_owned(),
        privacy_classes: vec!["PUBLIC".to_owned()],
        permissions: Vec::new(),
        health_contract: "health/eliotd-v1".to_owned(),
        checkpoint_contract: "checkpoint/daemon-v1".to_owned(),
        compatibility_state: "rebuildable".to_owned(),
        independent_test_profile: "module/eliotd".to_owned(),
        contract_fixture_set: "eliot.daemon.v1/daemon".to_owned(),
        affected_test_tags: vec!["eliotd".to_owned(), "daemon".to_owned()],
        architecture: Vec::new(),
        telemetry: "telemetry/eliotd-v1".to_owned(),
        removal_boundary: "eliotd".to_owned(),
    }
}

/// Admits the daemon's immutable runtime manifest and returns the module
/// contract projection the Kernel handshake must publish.
///
/// The manifest bytes are loaded from the admitted artifact location through the
/// protected path lease and admitted against the accepted build identity; the
/// publisher's declaration is then compared field-by-field with the contract
/// those exact bytes carry, so a substituted or edited manifest is refused
/// rather than published.
///
/// This is the daemon's manifest admission boundary. It is not yet reached from
/// the live startup path because no build/package owner stages the manifest
/// beside the artifact. The release bundler
/// (`scripts/build-eliot-windows-x64-release.ps1`) is that owner and is not
/// this issue's; the wiring is blocked on it.
#[cfg(windows)]
pub fn admitted_daemon_module_contract(
    accepted_artifact_sha256: &str,
) -> Result<ModuleContract, DaemonError> {
    let admitted = crate::daemon_config::admit_daemon_module_manifest(accepted_artifact_sha256)?;
    let contract =
        declared_module_contract(admitted.module_id.clone(), admitted.artifact_id.clone());
    compare_published_projection(&admitted, &contract)
        .map_err(|error| DaemonError::LaunchConfig(error.to_string()))?;
    Ok(contract)
}

#[cfg(windows)]
pub(super) fn client_hello(
    binding: &KernelLaunchBinding,
) -> Result<ClientHello, KernelClientError> {
    let module_id = ContractId::new("eliotd")
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let artifact_id = ArtifactId::new(binding.daemon_artifact_sha256.as_str())
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let contract = admitted_daemon_module_contract(binding.daemon_artifact_sha256.as_str())
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let generation = ModuleGeneration {
        module_id,
        generation: binding.module_generation,
        artifact_id,
        state: ModuleGenerationState::Starting,
        health: eliot_runtime_contracts::HealthVector::healthy(),
        state_fence: binding.state_fence.clone(),
    };
    Ok(ClientHello {
        protocol_range: ProtocolRange {
            minimum: ProtocolVersion::CURRENT,
            maximum: ProtocolVersion::CURRENT,
        },
        module_bridge_identity: SERVICE_NAME.to_owned(),
        artifact_hash: generation.artifact_id.clone(),
        module_contract: contract,
        module_generation: generation,
        launch_nonce: binding.launch_nonce.clone(),
        capabilities: vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()],
        privacy_classes: vec!["PUBLIC".to_owned()],
        max_frame: u32::try_from(eliot_protocol::MAX_FRAME_BYTES)
            .map_err(|_| KernelClientError::Contract("maximum frame exceeds u32".to_owned()))?,
        authority_epoch: binding.authority_epoch.clone(),
    })
}

#[cfg(windows)]
pub(crate) fn is_pre_admission_pending_rejection(
    frame: &Frame,
    expected_connection_id: &str,
) -> bool {
    if frame.validate().is_err()
        || frame.connection_id != expected_connection_id
        || frame.kind != FrameKind::Control
        || frame.message_type != MessageType::Fatal
        || frame.request_id.is_some()
        || frame.request_identity.is_some()
    {
        return false;
    }
    let ProtocolPayload::Json(serde_json::Value::Object(payload)) = &frame.payload else {
        return false;
    };
    payload.len() == 1
        && payload
            .get("rejection_reason")
            .and_then(serde_json::Value::as_str)
            == Some(ELIOTD_RECEIPT_PENDING_REJECTION)
}

/// Admits the Kernel peer at the I1.12 process boundary, before this daemon
/// becomes the live process behind its front door.
///
/// This runs inside [`validate_server_hello`], which runs before
/// `DaemonKernelClient::connect_transport` retains the validated session
/// binding, so a refusal here means the daemon never becomes live. Every
/// comparison names its own I1.12 field, because I1.12's verdict is "the
/// mismatching field reported" and a single lumped "snapshot mismatch" string
/// cannot report one.
///
/// # The two operands of each comparison
///
/// The receiver is this daemon; the candidate is the Kernel peer. Each arm
/// below therefore has one operand this process holds and one the peer
/// presented, and the peer can never satisfy an arm by echoing a value this
/// process supplied:
///
/// | I1.12 field | Receiver-held operand | Peer-presented operand |
/// |---|---|---|
/// | protocol range | `ProtocolVersion::CURRENT`, compiled into `eliotd` | `hello.selected_protocol`, chosen by the Kernel from its own `ServerHandshakePolicy.protocol_range` |
/// | Authority Epoch | `launch.kernel.authority_epoch`, from the Host-approved launch descriptor | `hello.authority_epoch` and `snapshot.authority_epoch`, published by the running Kernel |
/// | required capabilities | [`DAEMON_FRONT_DOOR_CAPABILITY`], this daemon's own requirement | `hello.allowed_capabilities`, the intersection the Kernel admitted |
///
/// The other half of I1.12's `module generation and Authority Epoch` item, the
/// module generation, is already refused by the snapshot comparison in
/// [`validate_server_hello`] — `snapshot.generation` against
/// `launch.kernel.generation`, one operand from the running Kernel and one from
/// the Host-approved descriptor — and is left there because
/// [`UNPRESENTED_HANDSHAKE_FIELDS`] is not the place for it and the shared
/// [`MismatchField`] vocabulary has no generation label.
///
/// The Authority Epoch arm requires BOTH peer-presented epoch values to match,
/// because `ServerHello` carries the epoch twice (`authority_epoch` and the
/// `config_snapshot` copy) and a Kernel whose two copies disagree is refused
/// rather than decided by whichever copy happens to be read first.
///
/// # What this arm is NOT
///
/// It does not construct a `CompatibilityEnvelope` and it does not call
/// `eliot_kernel_core::admit_handshake`. See
/// [`UNPRESENTED_HANDSHAKE_FIELDS`]: the Kernel's `ServerHello` carries no
/// contract-set digest, canonical-format range, Architecture source digest,
/// `NormativePairIdentity` receipt or migration class, and building those five
/// fields from this binary's own values to satisfy the envelope constructor
/// would make every one of them a self-comparison that changes no outcome. The
/// structured refusal type is still the shared
/// [`CompatibilityMismatch`], so the reason a caller reads is the same value
/// the Kernel, store-bridge and generation gates report, not a second scheme.
#[cfg(windows)]
fn admit_kernel_peer_compatibility(
    launch: &GovernorLaunchConfig,
    hello: &ServerHello,
    snapshot: &KernelSnapshotWire,
) -> Result<(), CompatibilityMismatch> {
    admit_protocol_range(hello)?;
    admit_authority_epoch(launch, hello, snapshot)?;
    admit_required_capability(hello)
}

/// I1.12 `protocol range`: the negotiated protocol the Kernel selected against
/// this daemon's own compiled range.
#[cfg(windows)]
fn admit_protocol_range(hello: &ServerHello) -> Result<(), CompatibilityMismatch> {
    if hello.selected_protocol == ProtocolVersion::CURRENT {
        return Ok(());
    }
    Err(CompatibilityMismatch::new(
        MismatchField::ProtocolRange,
        "the Kernel selected a protocol version outside this daemon's own protocol range",
    ))
}

/// I1.12 `Authority Epoch`.
///
/// I1.12 pairs the module generation with the Authority Epoch as one exchanged
/// item, but only the epoch has a [`MismatchField`] in the shared vocabulary and
/// the module generation therefore stays refused by the snapshot comparison in
/// [`validate_server_hello`] rather than being reported under a field label that
/// means something else. Inventing a generation label here would have created a
/// second refusal vocabulary beside the shared one.
#[cfg(windows)]
fn admit_authority_epoch(
    launch: &GovernorLaunchConfig,
    hello: &ServerHello,
    snapshot: &KernelSnapshotWire,
) -> Result<(), CompatibilityMismatch> {
    let admitted = &launch.kernel.authority_epoch;
    if hello.authority_epoch.is_same_authority(admitted)
        && snapshot.authority_epoch.is_same_authority(admitted)
    {
        return Ok(());
    }
    Err(CompatibilityMismatch::new(
        MismatchField::AuthorityEpoch,
        "the Kernel published an Authority Epoch outside this daemon's admitted epoch lineage",
    ))
}

/// I1.12 `required/optional capabilities`: the Kernel must have granted this
/// daemon the front-door capability this daemon requires.
///
/// Both operands are independent: the requirement is this daemon's own
/// declaration (the same value [`client_hello`] asks for), and the granted set
/// is the intersection the Kernel computed from its own
/// `ServerHandshakePolicy.allowed_capabilities`. A Kernel built or configured
/// without the daemon front-door capability yields an empty or unrelated
/// `allowed_capabilities` and is refused.
///
/// Absence is refused rather than read as agreement. An empty
/// `allowed_capabilities` is not a Kernel that agreed this daemon needs nothing;
/// it is a Kernel that never granted the claim this field exists to record, and
/// admitting it would be admitting "the pipe answered".
#[cfg(windows)]
fn admit_required_capability(hello: &ServerHello) -> Result<(), CompatibilityMismatch> {
    if hello
        .allowed_capabilities
        .iter()
        .any(|capability| capability == DAEMON_FRONT_DOOR_CAPABILITY)
    {
        return Ok(());
    }
    Err(CompatibilityMismatch::new(
        MismatchField::RequiredCapability,
        "the Kernel granted no front-door session carrying the capability this daemon requires",
    ))
}

/// Records, at this boundary, that the Kernel's `ServerHello` presented no
/// value for the I1.12 items in [`UNPRESENTED_HANDSHAKE_FIELDS`].
///
/// One bounded observation per field, carrying only the stable
/// [`MismatchField`] label — never a digest, epoch tuple, path or descriptor
/// material. This is a record of an INCOMPLETE handshake, not a refusal: it is
/// what keeps "the pipe answered" from being read as "the envelope was
/// exchanged".
#[cfg(windows)]
fn record_unpresented_handshake_fields() {
    for field in UNPRESENTED_HANDSHAKE_FIELDS {
        tracing::warn!(
            target: "eliotd::diagnostics",
            "eliotd.kernel_handshake.compatibility_field_unpresented:{field}"
        );
    }
}

/// Renders one structured I1.12 refusal as the daemon's existing typed Kernel
/// contract failure.
///
/// [`CompatibilityMismatch`]'s `Display` already renders both the stable field
/// label and the bounded reason, so no second rendering scheme is introduced and
/// the field name survives into the caller-visible error text.
#[cfg(windows)]
fn compatibility_refusal(mismatch: &CompatibilityMismatch) -> KernelClientError {
    KernelClientError::Contract(mismatch.to_string())
}

#[cfg(windows)]
pub(crate) fn validate_server_hello(
    launch: &GovernorLaunchConfig,
    binding: &KernelLaunchBinding,
    hello: &ServerHello,
) -> Result<(), KernelClientError> {
    hello
        .validate()
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    let snapshot: KernelSnapshotWire = serde_json::from_value(hello.config_snapshot.clone())
        .map_err(|error| KernelClientError::Contract(error.to_string()))?;
    // I1.12 (#1968): the Kernel peer is admitted against the I1.12 fields it
    // actually presents, BEFORE the validated session binding is retained, so an
    // incompatible Kernel generation never becomes the peer this live daemon
    // runs against. The I1.12 items the `ServerHello` wire shape cannot carry
    // are recorded as unpresented rather than filled from this binary.
    admit_kernel_peer_compatibility(launch, hello, &snapshot)
        .map_err(|mismatch| compatibility_refusal(&mismatch))?;
    record_unpresented_handshake_fields();
    if hello.session_principal_binding
        != format!(
            "sid={};session={}",
            binding.expected_kernel_sid, binding.expected_kernel_session_id
        )
    {
        return Err(KernelClientError::Contract(
            "Kernel ServerHello principal binding mismatch".to_owned(),
        ));
    }
    if snapshot.service != launch.kernel.service
        || snapshot.protocol != launch.kernel.protocol
        || snapshot.generation != launch.kernel.generation.value()
        || snapshot.artifact_digest != launch.kernel.artifact_digest
        || snapshot.protected_snapshot_digest != launch.protected_snapshot_digest
        || snapshot.protected_snapshot_digest != launch.kernel.protected_snapshot_digest
    {
        return Err(KernelClientError::Contract(
            "Kernel ServerHello generation snapshot mismatch".to_owned(),
        ));
    }
    Ok(())
}

/// Acceptance proof for the I1.12 Kernel-peer admission at this boundary
/// (issue #1968).
///
/// One admitted case plus one refusal per comparison, and every refusal asserts
/// the exact [`MismatchField`] rather than only that an error occurred, because
/// I1.12's verdict is "the mismatching field reported". The refusal operands
/// are deliberately NOT copies of the receiver-held values: each substitutes a
/// value the receiver does not hold, so the proof fails if a comparison ever
/// degenerates into this daemon checking its own constant against itself.
#[cfg(all(test, windows))]
mod kernel_peer_compatibility_tests {
    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_governor::GovernorLaunchConfig;
    use eliot_kernel_core::MismatchField;
    use std::num::NonZeroU64;

    use super::{
        DAEMON_FRONT_DOOR_CAPABILITY, KernelSnapshotWire, UNPRESENTED_HANDSHAKE_FIELDS,
        admit_kernel_peer_compatibility,
    };

    const ADMITTED_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const FOREIGN_LINEAGE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

    /// Returns the structured refusal, or a test failure naming the case.
    fn refused_by(
        launch: &GovernorLaunchConfig,
        hello: &eliot_protocol::ServerHello,
        snapshot: &KernelSnapshotWire,
        case: &str,
    ) -> Result<MismatchField, Box<dyn std::error::Error>> {
        match admit_kernel_peer_compatibility(launch, hello, snapshot) {
            Ok(()) => Err(format!("{case} was admitted but must be refused").into()),
            Err(refusal) => Ok(refusal.field()),
        }
    }

    fn epoch(lineage: &str, sequence: u64) -> Result<EpochId, Box<dyn std::error::Error>> {
        Ok(EpochId::new(
            EpochLineageId::new(lineage)?,
            NonZeroU64::new(sequence).ok_or("nonzero authority sequence")?,
        )?)
    }

    fn launch_config() -> Result<GovernorLaunchConfig, Box<dyn std::error::Error>> {
        Ok(GovernorLaunchConfig {
            instance_id: "test-instance".to_owned(),
            kernel: eliot_governor::KernelGenerationExpectation {
                service: "eliot-kernel".to_owned(),
                protocol: "eliot.kernel.v1".to_owned(),
                artifact_digest: "a".repeat(64),
                protected_snapshot_digest: "b".repeat(64),
                principal: "local-service".to_owned(),
                generation: eliot_contracts::ResourceGeneration::new(1)?,
                authority_epoch: epoch(ADMITTED_LINEAGE, 1)?,
            },
            protected_snapshot_digest: "b".repeat(64),
        })
    }

    fn admitted_snapshot(
        launch: &GovernorLaunchConfig,
    ) -> Result<KernelSnapshotWire, Box<dyn std::error::Error>> {
        Ok(serde_json::from_value(serde_json::json!({
            "service": launch.kernel.service,
            "protocol": launch.kernel.protocol,
            "generation": launch.kernel.generation.value(),
            "authority_epoch": launch.kernel.authority_epoch,
            "artifact_digest": launch.kernel.artifact_digest,
            "protected_snapshot_digest": launch.protected_snapshot_digest,
        }))?)
    }

    fn admitted_hello(
        launch: &GovernorLaunchConfig,
        granted: Vec<String>,
    ) -> eliot_protocol::ServerHello {
        eliot_protocol::ServerHello {
            selected_protocol: eliot_protocol::ProtocolVersion::CURRENT,
            session_principal_binding: "sid=S-1-5-19;session=0".to_owned(),
            allowed_capabilities: granted,
            allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
            config_snapshot: serde_json::json!({
                "service": launch.kernel.service,
                "protocol": launch.kernel.protocol,
                "generation": launch.kernel.generation.value(),
                "authority_epoch": launch.kernel.authority_epoch,
                "artifact_digest": launch.kernel.artifact_digest,
                "protected_snapshot_digest": launch.protected_snapshot_digest,
            }),
            heartbeat_ms: 1_000,
            control_channel: "eliot-kernel".to_owned(),
            rejection_reason: None,
            authority_epoch: launch.kernel.authority_epoch.clone(),
        }
    }

    #[test]
    fn admitted_kernel_peer_carries_the_required_capability_and_admitted_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()]);
        admit_kernel_peer_compatibility(&launch, &hello, &snapshot)?;
        Ok(())
    }

    #[test]
    fn kernel_peer_outside_the_protocol_range_names_the_protocol_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let snapshot = admitted_snapshot(&launch)?;
        let mut hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()]);
        hello.selected_protocol = eliot_protocol::ProtocolVersion { major: 9, minor: 9 };
        assert_eq!(
            refused_by(&launch, &hello, &snapshot, "a foreign protocol version")?,
            MismatchField::ProtocolRange,
            "the refusal must name the I1.12 protocol range field"
        );
        Ok(())
    }

    #[test]
    fn kernel_peer_outside_the_epoch_lineage_names_the_epoch_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let mut snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()]);
        // The snapshot copy of the epoch is substituted, so the arm that fires is
        // proved to read the peer-presented copy rather than the
        // `ServerHello.authority_epoch` this daemon also compares.
        snapshot.authority_epoch = epoch(FOREIGN_LINEAGE, 7)?;
        assert_eq!(
            refused_by(&launch, &hello, &snapshot, "a foreign epoch lineage")?,
            MismatchField::AuthorityEpoch,
            "the refusal must name the I1.12 Authority Epoch field"
        );
        Ok(())
    }

    #[test]
    fn kernel_peer_granting_no_capability_names_the_capability_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let snapshot = admitted_snapshot(&launch)?;
        // An EMPTY granted set is the absence case: it must be refused, never
        // read as a Kernel that agreed this daemon requires nothing.
        let absent = admitted_hello(&launch, Vec::new());
        assert_eq!(
            refused_by(&launch, &absent, &snapshot, "an absent granted capability")?,
            MismatchField::RequiredCapability,
            "the refusal must name the I1.12 required-capability field"
        );

        let unrelated = admitted_hello(&launch, vec!["some-other-capability".to_owned()]);
        assert_eq!(
            refused_by(&launch, &unrelated, &snapshot, "an unrelated capability")?,
            MismatchField::RequiredCapability
        );
        Ok(())
    }

    #[test]
    fn the_envelope_items_this_wire_cannot_present_are_named_not_filled()
    -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            UNPRESENTED_HANDSHAKE_FIELDS,
            [
                MismatchField::ContractSetDigest,
                MismatchField::CanonicalFormatRange,
                MismatchField::ArchitectureDigest,
                MismatchField::NormativeSeal,
                MismatchField::MigrationClass,
            ],
            "the unpresented set is the measured `ServerHello` gap, not a preference"
        );
        // A Kernel peer that presented none of those five is still admitted on
        // the fields it does present; the gap is recorded, never defaulted into
        // agreement and never backfilled from this binary.
        let launch = launch_config()?;
        let snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()]);
        admit_kernel_peer_compatibility(&launch, &hello, &snapshot)?;
        Ok(())
    }
}

pub(crate) fn operation_payload(
    operation: &str,
    payload: serde_json::Value,
) -> Result<serde_json::Value, KernelClientError> {
    let serde_json::Value::Object(mut object) = payload else {
        return Err(KernelClientError::Contract(
            "Kernel application payload must be an object".to_owned(),
        ));
    };
    object.insert(
        "operation".to_owned(),
        serde_json::Value::String(operation.to_owned()),
    );
    Ok(serde_json::Value::Object(object))
}

pub(crate) fn kernel_port_error(error: KernelClientError) -> KernelPortError {
    match error {
        KernelClientError::Contract(error) => KernelPortError::Contract(error),
        KernelClientError::Unknown(error) => KernelPortError::Unknown(error),
        KernelClientError::Transport(error) => KernelPortError::NotAdmitted(error),
        KernelClientError::PreAdmissionTransport(error) => KernelPortError::NotAdmitted(error),
        KernelClientError::PreAdmissionPending => KernelPortError::NotAdmitted(
            "Kernel has not published the exact launched process receipt".to_owned(),
        ),
        #[cfg(not(windows))]
        KernelClientError::Unsupported => {
            KernelPortError::NotAdmitted("Windows Kernel transport is required".to_owned())
        }
    }
}
