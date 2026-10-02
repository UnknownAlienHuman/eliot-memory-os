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

/// The I1.12 envelope's OWNER crate surface, reached through its module path
/// rather than the root re-exports.
///
/// The typed admission of the five envelope items below lives there and is
/// called, never restated here. The path is the module path rather than the root
/// re-export because this issue's write set does not include the owner's
/// `lib.rs`, and the module is `pub`; the same path is already used elsewhere in
/// this binary (`kernel_context_read_client.rs`).
#[cfg(windows)]
use eliot_kernel_core::module::compatibility_handshake as owner;
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

/// The I1.12 `state migration class` THIS DAEMON declares, and therefore the
/// receiver-held operand its boundary compares a Kernel peer against.
///
/// I1.12 names the field and defines no vocabulary for it, so the owner crate
/// deliberately owns and exports no derived value and every boundary supplies
/// its own declaration; read `eliot_kernel_core::StateMigrationClass`. This
/// declaration is `NoMigration` because this daemon's own published module
/// contract declares it `compatibility_state: "rebuildable"`
/// ([`declared_module_contract`]): the process holds no durable state a
/// handshake could require migrating, and it is the same class the Kernel's own
/// process boundary declares (`bins/eliot-kernel/src/compatibility_gate.rs`).
///
/// It is a DECLARATION, not a derived truth, and the comparison it feeds is
/// therefore only as strong as the agreement between two declarations. That
/// limit is the owner crate's, stated there and not restated as a stronger
/// guarantee here.
#[cfg(windows)]
const DAEMON_STATE_MIGRATION_CLASS: owner::StateMigrationClass =
    owner::StateMigrationClass::NoMigration;

/// The receiver-held half of the five I1.12 comparisons this boundary makes.
///
/// Every value here is compiled into `eliotd` or derived from what `eliotd`
/// compiles in. None of them can be influenced by what the peer presents, which
/// is what makes the five comparisons at
/// [`admit_kernel_peer_compatibility`] bindings rather than echoes.
#[cfg(windows)]
struct DaemonCompatibilityReceiver {
    contract_set_digest: String,
    canonical_format_range: owner::VersionRange,
}

/// Derives this daemon's own receiver-held envelope values.
///
/// The two derivable ones are read from their owners in `eliot_kernel_core`
/// rather than restated here, so this binary holds no private spelling of any
/// value a producer in another binary also presents. The Architecture source
/// digest and the migration class need no derivation: the first is a compiled
/// constant and the second is this binary's declaration.
#[cfg(windows)]
fn daemon_compatibility_receiver() -> Result<DaemonCompatibilityReceiver, KernelClientError> {
    let identities = [
        eliot_kernel_core::contract_identity().map_err(contract_identity_failure)?,
        eliot_kernel_service::contract_identity().map_err(contract_identity_failure)?,
        eliot_protocol::protocol_contract_identity().map_err(contract_identity_failure)?,
        eliot_runtime_contracts::contract_identity().map_err(contract_identity_failure)?,
    ];
    Ok(DaemonCompatibilityReceiver {
        contract_set_digest: eliot_kernel_core::contract_set_digest(&identities)
            .map_err(contract_identity_failure)?,
        canonical_format_range: eliot_kernel_core::handshake_canonical_format_range()
            .map_err(contract_identity_failure)?,
    })
}

/// Renders a failed receiver-side contract-identity derivation as this
/// boundary's existing typed failure.
///
/// One refusal shape for all four identity owners, because they fail for the
/// same reason and report the same class of problem; the reasons themselves are
/// each owner crate's own `Display`.
#[cfg(windows)]
fn contract_identity_failure(error: impl std::fmt::Display) -> KernelClientError {
    KernelClientError::Contract(format!(
        "this daemon could not derive its own I1.12 envelope identity: {error}"
    ))
}

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

/// The Kernel's `ServerHello.config_snapshot` as this boundary decodes it.
///
/// The first six fields are the generation snapshot this daemon already compared
/// against the Host-approved launch descriptor. The last five are the remaining
/// I1.12 envelope items, which the Kernel-side producer publishes into this same
/// free-form object under the names I1.12 uses for them.
///
/// They are held as `Option<serde_json::Value>` rather than as their owner types
/// for ONE reason: a value that is absent and a value that cannot be decoded must
/// both be refusals that NAME the mismatching field through
/// [`MismatchField`], and a whole-struct serde failure names neither. Each is
/// therefore decoded from this raw value by the owner's own type inside its own
/// comparison, so the typed refusal survives every shape of disagreement.
///
/// `deny_unknown_fields` is unchanged: a snapshot carrying a key this boundary
/// does not read is still refused rather than partially believed.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct KernelSnapshotWire {
    service: String,
    protocol: String,
    generation: u64,
    authority_epoch: EpochId,
    artifact_digest: String,
    protected_snapshot_digest: String,
    contract_set_digest: Option<serde_json::Value>,
    canonical_format_range: Option<serde_json::Value>,
    architecture_source_digest: Option<serde_json::Value>,
    normative_pair_receipt: Option<serde_json::Value>,
    state_migration_class: Option<serde_json::Value>,
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
/// the Host-approved descriptor — and is left there because the shared
/// [`MismatchField`] vocabulary has no generation label. Inventing one here would
/// have created a second refusal vocabulary beside the shared one.
///
/// The Authority Epoch arm requires BOTH peer-presented epoch values to match,
/// because `ServerHello` carries the epoch twice (`authority_epoch` and the
/// `config_snapshot` copy) and a Kernel whose two copies disagree is refused
/// rather than decided by whichever copy happens to be read first.
///
/// # The remaining five, and why they are admitted here rather than skipped
///
/// The five other I1.12 items reach this boundary inside the free-form
/// `config_snapshot` object, and each is compared against a value THIS PROCESS
/// compiled in, never against a value it read from the peer in the same
/// expression and never by re-hashing the peer's own value and comparing it with
/// itself:
///
/// | I1.12 field | Receiver-held operand | Peer-presented operand | Owner helper |
/// |---|---|---|---|
/// | contract-set digest | `daemon_compatibility_receiver`, which derives it with `eliot_kernel_core::contract_set_digest` over the SAME four public contract identities the Kernel's own production caller uses (`bins/eliot-kernel/src/frame_dispatch.rs::runtime_contract_set_digest`) | `config_snapshot.contract_set_digest` | `owner::admit_contract_set_digest` |
/// | canonical format range | `eliot_kernel_core::handshake_canonical_format_range()` | `config_snapshot.canonical_format_range`, decoded by the owner's `VersionRange` | `owner::admit_canonical_format_range` |
/// | Architecture source digest | `eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST`, compiled into `eliotd` | `config_snapshot.architecture_source_digest` | `owner::admit_architecture_source_digest` |
/// | sealed `NormativePairIdentity` receipt | the same compiled Architecture source digest | `config_snapshot.normative_pair_receipt`, decoded by the owner's `NormativePairReceipt` | `owner::admit_normative_pair_receipt` |
/// | state migration class | [`DAEMON_STATE_MIGRATION_CLASS`], this binary's own declaration | `config_snapshot.state_migration_class`, decoded by the owner's `StateMigrationClass` | `owner::admit_migration_class` |
///
/// Each of those five helpers is the owner's SINGLE comparison of its field, and
/// the owner's own `admit_handshake` calls the same five, so this boundary and
/// the Kernel's own gate cannot disagree about what "compatible" means. This
/// boundary does NOT construct a `CompatibilityEnvelope` and does NOT call
/// `admit_handshake`: four of the envelope's fields are not presented as an
/// envelope here (the generation and the epoch are compared against the
/// Host-approved launch descriptor, and the capability set is the Kernel's
/// granted intersection), so building one would make those four arms
/// self-comparisons. The comparisons themselves are the owner's, and the
/// structured refusal type is still the shared [`CompatibilityMismatch`], so the
/// reason a caller reads is the same value the Kernel, store-bridge and
/// generation gates report, not a second scheme.
///
/// # Absence is a refusal, not a default
///
/// A Kernel that presents none of those five has NOT exchanged the envelope, so
/// each absent item is refused under its own [`MismatchField`]. That is the
/// fail-closed reading I1.12's acceptance demands, and it is safe here because
/// the Kernel-side producer of these keys lands in this same delivery.
#[cfg(windows)]
fn admit_kernel_peer_compatibility(
    launch: &GovernorLaunchConfig,
    hello: &ServerHello,
    snapshot: &KernelSnapshotWire,
    receiver: &DaemonCompatibilityReceiver,
) -> Result<(), CompatibilityMismatch> {
    admit_protocol_range(hello)?;
    admit_authority_epoch(launch, hello, snapshot)?;
    admit_required_capability(hello)?;
    admit_peer_contract_set_digest(snapshot, receiver)?;
    admit_peer_canonical_format_range(snapshot, receiver)?;
    admit_peer_architecture_source_digest(snapshot)?;
    admit_peer_normative_pair_receipt(snapshot)?;
    admit_peer_state_migration_class(snapshot)
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

/// I1.12 `contract-set digest`, verified against the digest THIS BUILD produces
/// over the same four public contract identities.
///
/// The argument list is the one the existing production caller uses, read from
/// `bins/eliot-kernel/src/frame_dispatch.rs::runtime_contract_set_digest`:
/// `eliot-kernel-core`, `eliot-kernel-service`, `eliot-protocol` and
/// `eliot-runtime-contracts` in that order. That order, the arity and the
/// hashing belong to `eliot_kernel_core::contract_set_digest`, so this binary
/// holds no private spelling; what this binary supplies is only WHICH public
/// surfaces it compiles in.
#[cfg(windows)]
fn admit_peer_contract_set_digest(
    snapshot: &KernelSnapshotWire,
    receiver: &DaemonCompatibilityReceiver,
) -> Result<(), CompatibilityMismatch> {
    let presented: String = presented_compatibility_field(
        MismatchField::ContractSetDigest,
        "contract_set_digest",
        snapshot.contract_set_digest.as_ref(),
    )?;
    owner::admit_contract_set_digest(&presented, &receiver.contract_set_digest)
}

/// I1.12 `canonical format range`, compared by OVERLAP and not by equality.
///
/// The peer may legitimately present a wider range than this build speaks, so the
/// owner's relation is the right one and is applied by the owner.
#[cfg(windows)]
fn admit_peer_canonical_format_range(
    snapshot: &KernelSnapshotWire,
    receiver: &DaemonCompatibilityReceiver,
) -> Result<(), CompatibilityMismatch> {
    let presented: owner::VersionRange = presented_compatibility_field(
        MismatchField::CanonicalFormatRange,
        "canonical_format_range",
        snapshot.canonical_format_range.as_ref(),
    )?;
    // The negotiated revision is this boundary's to use only to prove the two
    // ranges share one; no daemon state is keyed on it, so it is not carried.
    let _negotiated =
        owner::admit_canonical_format_range(presented, receiver.canonical_format_range)?;
    Ok(())
}

/// I1.12 `Architecture source digest`, against the constant compiled into this
/// daemon.
///
/// This is the comparison that establishes the peer's identity, because the
/// operand is one this process did not take from the peer.
#[cfg(windows)]
fn admit_peer_architecture_source_digest(
    snapshot: &KernelSnapshotWire,
) -> Result<(), CompatibilityMismatch> {
    let presented: String = presented_compatibility_field(
        MismatchField::ArchitectureDigest,
        "architecture_source_digest",
        snapshot.architecture_source_digest.as_ref(),
    )?;
    owner::admit_architecture_source_digest(
        &presented,
        eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
    )
}

/// I1.12 `NormativePairIdentity` receipt, presented as externally sealed.
///
/// Two checks, and the honest statement of which one carries weight:
///
/// - The DIGEST half is the real check. The receipt's
///   `architecture_source_digest()` is compared against THIS daemon's own
///   `CURRENT_ARCHITECTURE_SOURCE_DIGEST`, an operand the peer never supplied,
///   so a receipt minted over a FOREIGN Architecture digest is refused here even
///   when its own seal tag is perfectly correct.
/// - The TAG half is NOT an independent seal. `expected_seal_tag` is unkeyed
///   SHA-256 over published constants, so `NormativePairReceipt::verifies()`
///   compares two peer-supplied values with each other and can only prove the
///   peer agrees with itself. It is still run, because it is the only constraint
///   on the presented tag at all - deleting it would admit a receipt whose tag is
///   arbitrary - and because it is the owner's own check, but it establishes
///   nothing about identity that the digest half has not already established. No
///   external seal issuer exists in this repository; that is the owner crate's
///   own statement in `expected_seal_tag`, not a gap introduced here.
#[cfg(windows)]
fn admit_peer_normative_pair_receipt(
    snapshot: &KernelSnapshotWire,
) -> Result<(), CompatibilityMismatch> {
    let presented: owner::NormativePairReceipt = presented_compatibility_field(
        MismatchField::NormativeSeal,
        "normative_pair_receipt",
        snapshot.normative_pair_receipt.as_ref(),
    )?;
    owner::admit_normative_pair_receipt(
        &presented,
        eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
    )
}

/// I1.12 `state migration class`, against [`DAEMON_STATE_MIGRATION_CLASS`].
///
/// The comparison is exact and lives in the owner, so a Kernel that declares a
/// different class is refused by name. What a class asserts about a durable
/// format is still undefined, because I1.12 names the field and defines no
/// vocabulary - see the owner crate's `StateMigrationClass` documentation.
#[cfg(windows)]
fn admit_peer_state_migration_class(
    snapshot: &KernelSnapshotWire,
) -> Result<(), CompatibilityMismatch> {
    let presented: owner::StateMigrationClass = presented_compatibility_field(
        MismatchField::MigrationClass,
        "state_migration_class",
        snapshot.state_migration_class.as_ref(),
    )?;
    owner::admit_migration_class(presented, DAEMON_STATE_MIGRATION_CLASS)
}

/// Decodes one presented I1.12 item, refusing absence AND unreadability under
/// the SAME [`MismatchField`].
///
/// Both failures are refusals that must name the field, so neither may become a
/// whole-struct serde error that names nothing. The decoding type is the owner's
/// own type for that field, so the accepted shape is the owner's shape.
#[cfg(windows)]
fn presented_compatibility_field<T: serde::de::DeserializeOwned>(
    field: MismatchField,
    key: &'static str,
    presented: Option<&serde_json::Value>,
) -> Result<T, CompatibilityMismatch> {
    let Some(presented) = presented else {
        return Err(CompatibilityMismatch::new(
            field,
            format!("the Kernel's ServerHello presented no {key}"),
        ));
    };
    serde_json::from_value(presented.clone()).map_err(|error| {
        CompatibilityMismatch::new(
            field,
            format!("the Kernel's ServerHello presented an unreadable {key}: {error}"),
        )
    })
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
    // I1.12 (#1968): the Kernel peer is admitted against the WHOLE compatibility
    // envelope BEFORE the validated session binding is retained, so an
    // incompatible Kernel generation never becomes the peer this live daemon
    // runs against. The receiver half of every comparison is derived from this
    // daemon's own compiled identity, never from anything the peer presented.
    admit_kernel_peer_compatibility(launch, hello, &snapshot, &daemon_compatibility_receiver()?)
        .map_err(|mismatch| compatibility_refusal(&mismatch))?;
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
///
/// Every expected value in this module is read from the OWNER crate
/// (`eliot_kernel_core`) rather than typed here. That is what keeps these
/// fixtures meaning what they claim: a proof built from literals would keep
/// passing after the owners moved, and would then be asserting that a stale
/// literal is admitted.
#[cfg(all(test, windows))]
mod kernel_peer_compatibility_tests {
    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_governor::GovernorLaunchConfig;
    use eliot_kernel_core::MismatchField;
    use std::num::NonZeroU64;

    use super::{
        DAEMON_FRONT_DOOR_CAPABILITY, DAEMON_STATE_MIGRATION_CLASS, KernelSnapshotWire,
        admit_kernel_peer_compatibility, daemon_compatibility_receiver, owner,
        presented_compatibility_field,
    };

    const ADMITTED_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";
    const FOREIGN_LINEAGE: &str = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";

    /// The five I1.12 envelope items, each built from its owner exactly as the
    /// Kernel-side producer builds them.
    fn presented_envelope_items()
    -> Result<serde_json::Map<String, serde_json::Value>, Box<dyn std::error::Error>> {
        let identities = [
            eliot_kernel_core::contract_identity()?,
            eliot_kernel_service::contract_identity()?,
            eliot_protocol::protocol_contract_identity()?,
            eliot_runtime_contracts::contract_identity()?,
        ];
        let architecture_source_digest = eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST;
        let receipt = owner::NormativePairReceipt::new(
            architecture_source_digest,
            eliot_kernel_core::expected_seal_tag(architecture_source_digest),
        )?;
        serde_json::json!({
            "contract_set_digest": eliot_kernel_core::contract_set_digest(&identities)?,
            "canonical_format_range": eliot_kernel_core::handshake_canonical_format_range()?,
            "architecture_source_digest": architecture_source_digest,
            "normative_pair_receipt": receipt,
            "state_migration_class": DAEMON_STATE_MIGRATION_CLASS,
        })
        .as_object()
        .cloned()
        .ok_or_else(|| "the five presented items must project to a JSON object".into())
    }

    /// The `config_snapshot` object a Kernel peer publishes on this wire: the
    /// six generation-snapshot keys plus the five I1.12 envelope items.
    fn published_snapshot(
        launch: &GovernorLaunchConfig,
    ) -> Result<serde_json::Map<String, serde_json::Value>, Box<dyn std::error::Error>> {
        let mut object = serde_json::json!({
            "service": launch.kernel.service,
            "protocol": launch.kernel.protocol,
            "generation": launch.kernel.generation.value(),
            "authority_epoch": launch.kernel.authority_epoch,
            "artifact_digest": launch.kernel.artifact_digest,
            "protected_snapshot_digest": launch.protected_snapshot_digest,
        })
        .as_object()
        .cloned()
        .ok_or("the generation snapshot must be a JSON object")?;
        object.extend(presented_envelope_items()?);
        Ok(object)
    }

    fn snapshot_of(
        object: serde_json::Map<String, serde_json::Value>,
    ) -> Result<KernelSnapshotWire, Box<dyn std::error::Error>> {
        Ok(serde_json::from_value(serde_json::Value::Object(object))?)
    }

    fn admitted_snapshot(
        launch: &GovernorLaunchConfig,
    ) -> Result<KernelSnapshotWire, Box<dyn std::error::Error>> {
        snapshot_of(published_snapshot(launch)?)
    }

    fn admitted_hello(
        launch: &GovernorLaunchConfig,
        granted: Vec<String>,
    ) -> Result<eliot_protocol::ServerHello, Box<dyn std::error::Error>> {
        Ok(eliot_protocol::ServerHello {
            selected_protocol: eliot_protocol::ProtocolVersion::CURRENT,
            session_principal_binding: "sid=S-1-5-19;session=0".to_owned(),
            allowed_capabilities: granted,
            allowed_effects: vec!["REVERSIBLE_MUTATION".to_owned()],
            config_snapshot: serde_json::Value::Object(published_snapshot(launch)?),
            heartbeat_ms: 1_000,
            control_channel: "eliot-kernel".to_owned(),
            rejection_reason: None,
            authority_epoch: launch.kernel.authority_epoch.clone(),
        })
    }

    /// Returns the structured refusal, or a test failure naming the case.
    fn refused_by(
        launch: &GovernorLaunchConfig,
        hello: &eliot_protocol::ServerHello,
        snapshot: &KernelSnapshotWire,
        case: &str,
    ) -> Result<MismatchField, Box<dyn std::error::Error>> {
        let receiver = daemon_compatibility_receiver()?;
        match admit_kernel_peer_compatibility(launch, hello, snapshot, &receiver) {
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

    #[test]
    fn admitted_kernel_peer_carries_the_required_capability_and_admitted_epoch()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        admit_kernel_peer_compatibility(
            &launch,
            &hello,
            &snapshot,
            &daemon_compatibility_receiver()?,
        )?;
        Ok(())
    }

    #[test]
    fn kernel_peer_outside_the_protocol_range_names_the_protocol_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let snapshot = admitted_snapshot(&launch)?;
        let mut hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
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
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
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
        let absent = admitted_hello(&launch, Vec::new())?;
        assert_eq!(
            refused_by(&launch, &absent, &snapshot, "an absent granted capability")?,
            MismatchField::RequiredCapability,
            "the refusal must name the I1.12 required-capability field"
        );

        let unrelated = admitted_hello(&launch, vec!["some-other-capability".to_owned()])?;
        assert_eq!(
            refused_by(&launch, &unrelated, &snapshot, "an unrelated capability")?,
            MismatchField::RequiredCapability
        );
        Ok(())
    }

    // ---------------------------------------------------------------------
    // The five envelope items this boundary now verifies (issue #1968, W1).
    // ---------------------------------------------------------------------

    /// POSITIVE case: a peer presenting all five items as their OWNERS produce
    /// them is admitted, and each presented value is proven equal to the
    /// receiver-held owner value this boundary compared it against.
    ///
    /// Asserting the equality as well as the admission is what stops this case
    /// from passing vacuously: if a comparison silently stopped reading the
    /// presented value, the admission would still succeed and only these
    /// assertions would fail.
    #[test]
    fn every_presented_envelope_item_is_admitted_when_it_matches_its_owner()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        let receiver = daemon_compatibility_receiver()?;

        let presented: String = presented_compatibility_field(
            MismatchField::ContractSetDigest,
            "contract_set_digest",
            snapshot.contract_set_digest.as_ref(),
        )?;
        assert_eq!(
            presented, receiver.contract_set_digest,
            "the presented contract-set digest must be the one this build derives"
        );

        let presented: owner::VersionRange = presented_compatibility_field(
            MismatchField::CanonicalFormatRange,
            "canonical_format_range",
            snapshot.canonical_format_range.as_ref(),
        )?;
        assert!(
            owner::admit_canonical_format_range(presented, receiver.canonical_format_range).is_ok(),
            "the presented canonical-format range must overlap this build's own"
        );

        let presented: String = presented_compatibility_field(
            MismatchField::ArchitectureDigest,
            "architecture_source_digest",
            snapshot.architecture_source_digest.as_ref(),
        )?;
        assert_eq!(
            presented,
            eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
            "the presented Architecture source digest must be this build's own constant"
        );

        let presented: owner::NormativePairReceipt = presented_compatibility_field(
            MismatchField::NormativeSeal,
            "normative_pair_receipt",
            snapshot.normative_pair_receipt.as_ref(),
        )?;
        owner::admit_normative_pair_receipt(
            &presented,
            eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
        )?;

        let presented: owner::StateMigrationClass = presented_compatibility_field(
            MismatchField::MigrationClass,
            "state_migration_class",
            snapshot.state_migration_class.as_ref(),
        )?;
        assert_eq!(
            presented, DAEMON_STATE_MIGRATION_CLASS,
            "the presented migration class must be this daemon's own declaration"
        );

        admit_kernel_peer_compatibility(&launch, &hello, &snapshot, &receiver)?;
        Ok(())
    }

    #[test]
    fn a_foreign_contract_set_digest_names_the_contract_set_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let mut snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        snapshot.contract_set_digest = Some(serde_json::Value::String("1".repeat(64)));
        assert_eq!(
            refused_by(&launch, &hello, &snapshot, "a foreign contract-set digest")?,
            MismatchField::ContractSetDigest,
            "the refusal must name the I1.12 contract-set digest field"
        );
        Ok(())
    }

    #[test]
    fn a_disjoint_canonical_format_range_names_the_canonical_format_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let mut snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        // Disjoint by construction: `u32::MAX` is outside any range this build's
        // owner currently produces, whatever that range is.
        snapshot.canonical_format_range = Some(serde_json::to_value(owner::VersionRange::new(
            u32::MAX,
            u32::MAX,
        )?)?);
        assert_eq!(
            refused_by(
                &launch,
                &hello,
                &snapshot,
                "a disjoint canonical format range"
            )?,
            MismatchField::CanonicalFormatRange,
            "the refusal must name the I1.12 canonical format range field"
        );
        Ok(())
    }

    /// The canonical-format arm is an OVERLAP comparison, not equality: a peer
    /// presenting a strictly WIDER range that still shares this build's revision
    /// is compatible and must be admitted. This is the case an equality
    /// comparison would wrongly refuse.
    #[test]
    fn a_wider_overlapping_canonical_format_range_is_admitted()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let mut snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        let receiver = daemon_compatibility_receiver()?;
        let own = receiver.canonical_format_range;
        let wider = owner::VersionRange::new(
            own.min(),
            own.max()
                .checked_add(8)
                .ok_or("room above the owned revision")?,
        )?;
        assert_ne!(wider, own, "the substituted range must be strictly wider");
        snapshot.canonical_format_range = Some(serde_json::to_value(wider)?);
        admit_kernel_peer_compatibility(&launch, &hello, &snapshot, &receiver)?;
        Ok(())
    }

    #[test]
    fn a_foreign_architecture_source_digest_names_the_architecture_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let mut snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        snapshot.architecture_source_digest = Some(serde_json::Value::String("2".repeat(64)));
        assert_eq!(
            refused_by(
                &launch,
                &hello,
                &snapshot,
                "a foreign architecture source digest"
            )?,
            MismatchField::ArchitectureDigest,
            "the refusal must name the I1.12 Architecture source digest field"
        );
        Ok(())
    }

    #[test]
    fn a_receipt_with_a_forged_seal_tag_names_the_normative_seal_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let mut snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        // The DIGEST half is correct, so only the tag half can refuse this. The
        // tag is the owner's own unkeyed recomputation over published
        // constants, and this value is not it.
        let forged = owner::NormativePairReceipt::new(
            eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
            "3".repeat(64),
        )?;
        assert!(
            !forged.verifies(),
            "the substituted tag must fail the owner's own recomputation"
        );
        snapshot.normative_pair_receipt = Some(serde_json::to_value(forged)?);
        assert_eq!(
            refused_by(
                &launch,
                &hello,
                &snapshot,
                "a forged normative-pair seal tag"
            )?,
            MismatchField::NormativeSeal,
            "the refusal must name the I1.12 sealed normative-pair receipt field"
        );
        Ok(())
    }

    /// FORGERY case: a receipt entirely SELF-CONSISTENT over a FOREIGN
    /// Architecture source digest - the foreign digest, and the owner's own
    /// correct tag FOR that digest - is still refused.
    ///
    /// This is the case that proves the DIGEST half, and not the tag half, is
    /// what binds the receipt to this receiver. A boundary that re-hashed the
    /// peer's own digest and compared the result with itself would admit exactly
    /// this message.
    #[test]
    fn a_self_consistent_receipt_over_a_foreign_architecture_digest_is_refused()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let mut snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        let foreign = "4".repeat(64);
        assert_ne!(
            foreign,
            eliot_kernel_core::CURRENT_ARCHITECTURE_SOURCE_DIGEST,
            "the forged digest must be foreign to this build"
        );
        let forged = owner::NormativePairReceipt::new(
            foreign.clone(),
            eliot_kernel_core::expected_seal_tag(&foreign),
        )?;
        assert!(
            forged.verifies(),
            "the forged receipt must be self-consistent, or this proves nothing"
        );
        snapshot.normative_pair_receipt = Some(serde_json::to_value(forged)?);
        assert_eq!(
            refused_by(
                &launch,
                &hello,
                &snapshot,
                "a receipt over a foreign digest"
            )?,
            MismatchField::NormativeSeal,
            "the receiver-held Architecture digest must refuse a foreign receipt"
        );
        Ok(())
    }

    #[test]
    fn a_foreign_state_migration_class_names_the_migration_class_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let mut snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        assert_ne!(
            owner::StateMigrationClass::BreakingRebase,
            DAEMON_STATE_MIGRATION_CLASS,
            "the substituted class must differ from this daemon's own declaration"
        );
        snapshot.state_migration_class = Some(serde_json::to_value(
            owner::StateMigrationClass::BreakingRebase,
        )?);
        assert_eq!(
            refused_by(
                &launch,
                &hello,
                &snapshot,
                "a foreign state migration class"
            )?,
            MismatchField::MigrationClass,
            "the refusal must name the I1.12 state migration class field"
        );
        Ok(())
    }

    /// FAIL-CLOSED case: each of the five items, ABSENT, is a refusal under its
    /// own field label.
    ///
    /// Every other case in this module varies a VALUE. This one removes the KEY,
    /// because that is the shape a Kernel which never exchanged the envelope
    /// presents, and admitting it would be admitting "the pipe answered". The
    /// loop runs once per key so no item can be exempted without it showing.
    #[test]
    fn an_absent_envelope_item_is_refused_and_names_its_own_field()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let published = published_snapshot(&launch)?;
        let admitted = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        let receiver = daemon_compatibility_receiver()?;
        for (key, field) in [
            ("contract_set_digest", MismatchField::ContractSetDigest),
            (
                "canonical_format_range",
                MismatchField::CanonicalFormatRange,
            ),
            (
                "architecture_source_digest",
                MismatchField::ArchitectureDigest,
            ),
            ("normative_pair_receipt", MismatchField::NormativeSeal),
            ("state_migration_class", MismatchField::MigrationClass),
        ] {
            let mut absent = published.clone();
            assert!(
                absent.remove(key).is_some(),
                "{key} must be published in the base fixture for this case to mean anything"
            );
            let snapshot = snapshot_of(absent)?;
            let Err(refusal) =
                admit_kernel_peer_compatibility(&launch, &admitted, &snapshot, &receiver)
            else {
                return Err(format!("an absent {key} was admitted but must be refused").into());
            };
            assert_eq!(refusal.field(), field, "the refusal must name {key}");
        }
        Ok(())
    }

    /// A value that is PRESENT but unreadable is refused under the same field
    /// label as an absent one, so a malformed presentation never becomes an
    /// anonymous wire error that names nothing.
    #[test]
    fn an_unreadable_envelope_item_names_its_own_field() -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let mut snapshot = admitted_snapshot(&launch)?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        snapshot.contract_set_digest = Some(serde_json::json!({ "not": "a digest" }));
        assert_eq!(
            refused_by(
                &launch,
                &hello,
                &snapshot,
                "an unreadable contract-set digest"
            )?,
            MismatchField::ContractSetDigest,
            "an unreadable value must name its field exactly as an absent one does"
        );
        Ok(())
    }

    /// The five keys travel inside the FREE-FORM `config_snapshot` object, so the
    /// pinned `ServerHello` contract shape carries them unchanged. That is what
    /// makes the fail-closed case above a producer obligation rather than a
    /// protocol impossibility.
    #[test]
    fn all_five_keys_survive_the_pinned_server_hello_contract_shape()
    -> Result<(), Box<dyn std::error::Error>> {
        let launch = launch_config()?;
        let hello = admitted_hello(&launch, vec![DAEMON_FRONT_DOOR_CAPABILITY.to_owned()])?;
        for key in [
            "contract_set_digest",
            "canonical_format_range",
            "architecture_source_digest",
            "normative_pair_receipt",
            "state_migration_class",
        ] {
            assert!(
                hello.config_snapshot.get(key).is_some(),
                "{key} must travel inside config_snapshot"
            );
        }
        hello.validate()?;
        let encoded = serde_json::to_value(&hello)?;
        let decoded: eliot_protocol::ServerHello = serde_json::from_value(encoded)?;
        assert_eq!(
            decoded.config_snapshot, hello.config_snapshot,
            "all five keys must survive the pinned `ServerHello` round trip"
        );
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
