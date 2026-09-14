//! Private Governor-backed `ControlBoard` port adapters.
//!
//! The four adapters translate between the provider-neutral
//! [`ControlBoard`](eliot_controlboard::ControlBoard) ports and one immutable
//! [`ControlBoardGovernorSnapshot`](eliot_governor::ControlBoardGovernorSnapshot)
//! taken from the single [`GovernorComposition`](eliot_governor::GovernorComposition)
//! by [`DaemonComposition::controlboard`](super::DaemonComposition::controlboard).
//! They forward authenticated input and translate typed results only:
//!
//! - No policy, admission, or semantic rules live here. Role, privacy, and
//!   capability resolution stays with the session/authority owner, so
//!   [`resolve`](eliot_controlboard::AccessResolverPort::resolve) validates
//!   the request shape and snapshot pins, then admits one owner-issued session
//!   binding ([`AdmittedSessionAccess`]) pinned to the live snapshot
//!   fence/revision instead of inventing rights. A session with no admission
//!   keeps the fail-closed gap (`Unavailable`), so 'source not connected'
//!   stays distinct from an admitted-but-empty view.
//! - The Swarm projection providers (catalogue, preferences) are admitted to
//!   the Governor snapshot port as explicit owner-issued bindings
//!   ([`GovernorSwarmProjection::with_admitted_providers`]). Admission records
//!   which providers the composition trusts; it does not fabricate their
//!   bytes. The Governor snapshot carries no catalogue/preference owner
//!   state, so an admitted-but-unresolvable read still fails closed with a
//!   typed gap (`Unknown`, distinct from the unadmitted `Unavailable`). The
//!   zero-model gate stays intact in `eliot-controlboard`; nothing here
//!   populates live execution.
//! - Operator submission admits one exact-view intent against the live
//!   snapshot fence and returns a candidate-only receipt. Acceptance is
//!   transport acknowledgement, never task completion or a canonical write:
//!   there is no commit path in this module. Boards built from one daemon
//!   composition share one volatile replay handle
//!   ([`SharedOperatorReplay`]); durable operator identity lives in Kernel
//!   ORS through the async Governor operator borrow.
//! - Action digests, ceilings, capabilities, and targets are enforced by
//!   `ControlBoard` before and after the port call; the adapters enforce the
//!   bindings only the live snapshot can check (revision/fence currency and
//!   the owner-issued identity binding) and echo the board-validated ceilings
//!   without widening them.
//!
//! The adapters perform only in-memory reads over the immutable snapshot and
//! never touch I/O, so they cannot block the single-thread async reactor. The
//! current Kernel binding is observed through the composition snapshot, never
//! through a second client.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use eliot_contracts::SessionId;
use eliot_controlboard::{
    AccessBinding, AccessResolverPort, ActionCapability, CanonicalState, CanonicalStatePort,
    CommandDisposition, CommandReceipt, CommandRequest, ControlBoard, OperatorCommandPort,
    PortError, PrivacyClass, ProjectionBinding, ProjectionProvider, ProviderCompleteness,
    ReadRequest, Role, SwarmProjectionEnvelope, SwarmProjectionPort, ViewRevision,
};
use eliot_governor::ControlBoardGovernorSnapshot;

/// Builds one [`ControlBoard`] over a fresh Governor projection snapshot.
///
/// The snapshot is immutable: every port call in the returned board observes
/// the same fence and revision, so a mid-read Governor refresh surfaces as an
/// exact-view mismatch at the next call rather than silent divergence.
///
/// The board shares the caller-retained [`SharedOperatorReplay`] handle, so a
/// newly created board replays an already-admitted operation instead of
/// admitting it twice. `admitted` carries owner-issued session bindings for
/// the access resolver; production passes none (the session owner is
/// deferred), which keeps the unadmitted typed gap.
pub(crate) fn controlboard_over_snapshot(
    snapshot: ControlBoardGovernorSnapshot,
    shared: &SharedOperatorReplay,
    admitted: Vec<AdmittedSessionAccess>,
) -> ControlBoard {
    let snapshot = Arc::new(snapshot);
    // Production passes no sessions, which cannot fail. An invalid test
    // admission degrades to the empty resolver so submission stays fail-closed
    // downstream instead of inventing rights.
    let access = if admitted.is_empty() {
        GovernorAccessResolver::new(Arc::clone(&snapshot))
    } else {
        GovernorAccessResolver::with_admitted_sessions(Arc::clone(&snapshot), admitted)
            .unwrap_or_else(|_| GovernorAccessResolver::new(Arc::clone(&snapshot)))
    };
    ControlBoard::new(
        Some(Box::new(access)),
        Some(Box::new(GovernorCanonicalState::new(Arc::clone(&snapshot)))),
        Some(Box::new(GovernorOperatorCommand::with_shared_replay(
            Arc::clone(&snapshot),
            shared,
        ))),
    )
    .with_swarm_projection(Box::new(GovernorSwarmProjection::new(snapshot)))
}

/// Rejects bindings that are not current at the snapshot fence and revision.
///
/// A refresh between the access resolution and this call fails closed here
/// instead of serving a cross-fence view.
fn access_currency(
    snapshot: &ControlBoardGovernorSnapshot,
    access: &AccessBinding,
) -> Result<(), PortError> {
    if access.access_revision.get() != snapshot.read_revision
        || access.access_fence != snapshot.fence
    {
        return Err(PortError::Denied);
    }
    Ok(())
}

/// Governor-backed access resolver.
///
/// Performs the real request-shape and snapshot-pin checks, then admits one
/// owner-issued session binding per known session (see
/// [`AdmittedSessionAccess`]). The Governor session owner carries no
/// `ControlBoard` role, privacy, or capability facts itself, and this adapter
/// never invents them: access rights come only from the admitted owner-issued
/// facts, pinned here to the live snapshot fence and revision. A session with
/// no admission keeps the fail-closed gap (`Unavailable`, reported by the
/// board as `PlanGap(AccessResolver)`), so 'source not connected' stays
/// distinct from an admitted-but-empty view.
struct GovernorAccessResolver {
    snapshot: Arc<ControlBoardGovernorSnapshot>,
    admitted: BTreeMap<String, AdmittedSessionAccess>,
}

/// Owner-issued session access facts admitted by the Governor snapshot port.
///
/// References and facts only: session identity, principal id, work scope,
/// role, admitted privacy classes, action capabilities, owner provenance refs
/// (binding id, binding digest, receipt ref), and owner-observed timestamps.
/// No credential, secret, token, cookie, or payload bytes ever appear here.
///
/// The timestamps are echoed owner-observed facts (like the ceiling echoing
/// documented at the top of this module); lifetime enforcement stays with the
/// issuing owner and `ControlBoard::seal_for`, which re-checks the echoed
/// bounds on every view.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmittedSessionAccess {
    session_id: String,
    principal_id: String,
    work_scope: String,
    role: Role,
    admitted_privacy: Vec<PrivacyClass>,
    capabilities: Vec<ActionCapability>,
    binding_id: String,
    binding_digest: String,
    receipt_ref: String,
    issued_at_unix_ms: u64,
    observed_at_unix_ms: u64,
    expires_at_unix_ms: u64,
}

// AUD-C02: composition admission seam for the future session owner (User
// Broker role issuance is deferred to #23/#1135). Production wiring stays on
// `new` (empty map) until that owner exists.
#[allow(dead_code)]
impl AdmittedSessionAccess {
    /// Admits one owner-issued session binding after fail-closed validation.
    /// The full owner-issued fact set travels in one validated step so no
    /// partial binding can resolve.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        session_id: impl Into<String>,
        principal_id: impl Into<String>,
        work_scope: impl Into<String>,
        role: Role,
        admitted_privacy: Vec<PrivacyClass>,
        capabilities: Vec<ActionCapability>,
        binding_id: impl Into<String>,
        binding_digest: impl Into<String>,
        receipt_ref: impl Into<String>,
        issued_at_unix_ms: u64,
        observed_at_unix_ms: u64,
        expires_at_unix_ms: u64,
    ) -> Result<Self, PortError> {
        let binding = Self {
            session_id: session_id.into(),
            principal_id: principal_id.into(),
            work_scope: work_scope.into(),
            role,
            admitted_privacy,
            capabilities,
            binding_id: binding_id.into(),
            binding_digest: binding_digest.into(),
            receipt_ref: receipt_ref.into(),
            issued_at_unix_ms,
            observed_at_unix_ms,
            expires_at_unix_ms,
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<Self, PortError> {
        if !valid_binding_text(&self.session_id)
            || !valid_binding_text(&self.principal_id)
            || !valid_binding_text(&self.work_scope)
            || !valid_binding_text(&self.binding_id)
            || !valid_binding_text(&self.receipt_ref)
            || !valid_binding_digest(&self.binding_digest)
            || self.admitted_privacy.is_empty()
        {
            return Err(PortError::Invalid(
                "session access admission binding is malformed".to_owned(),
            ));
        }
        if self.issued_at_unix_ms == 0
            || self.observed_at_unix_ms < self.issued_at_unix_ms
            || self.observed_at_unix_ms >= self.expires_at_unix_ms
        {
            return Err(PortError::Invalid(
                "session access admission lifetime is malformed".to_owned(),
            ));
        }
        let mut privacy = BTreeSet::new();
        for class in &self.admitted_privacy {
            if !privacy.insert(*class as u8) {
                return Err(PortError::Invalid(
                    "session access admission has a duplicate privacy class".to_owned(),
                ));
            }
        }
        let mut capabilities = BTreeSet::new();
        for capability in &self.capabilities {
            if !capabilities.insert(*capability as u8) {
                return Err(PortError::Invalid(
                    "session access admission has a duplicate capability".to_owned(),
                ));
            }
        }
        Ok(self.clone())
    }

    /// Exact-replay rule for one session: identical facts replay, changed
    /// facts under the same session id conflict without mutating the stored
    /// binding.
    fn same_binding(&self, other: &Self) -> bool {
        self.session_id == other.session_id
            && self.principal_id == other.principal_id
            && self.work_scope == other.work_scope
            && self.role == other.role
            && self.admitted_privacy == other.admitted_privacy
            && self.capabilities == other.capabilities
            && self.binding_id == other.binding_id
            && self.binding_digest == other.binding_digest
            && self.receipt_ref == other.receipt_ref
            && self.issued_at_unix_ms == other.issued_at_unix_ms
            && self.observed_at_unix_ms == other.observed_at_unix_ms
            && self.expires_at_unix_ms == other.expires_at_unix_ms
    }
}

impl GovernorAccessResolver {
    fn new(snapshot: Arc<ControlBoardGovernorSnapshot>) -> Self {
        Self {
            snapshot,
            admitted: BTreeMap::new(),
        }
    }

    /// Admits owner-issued session bindings into the Governor snapshot port.
    /// Each binding is validated fail-closed; re-admitting an identical
    /// binding is an idempotent replay, while a changed binding under an
    /// already-admitted session id is an identity conflict that mutates
    /// nothing.
    // AUD-C02: composition admission point for the future session owner;
    // production wiring stays on `new` (empty map) until that owner exists.
    #[allow(dead_code)]
    pub(crate) fn with_admitted_sessions(
        snapshot: Arc<ControlBoardGovernorSnapshot>,
        admitted: Vec<AdmittedSessionAccess>,
    ) -> Result<Self, PortError> {
        let mut sessions = BTreeMap::new();
        for binding in admitted {
            let binding = binding.validate()?;
            match sessions.get(&binding.session_id) {
                None => {
                    sessions.insert(binding.session_id.clone(), binding);
                }
                Some(stored) if stored.same_binding(&binding) => {}
                Some(_) => return Err(PortError::IdentityConflict),
            }
        }
        Ok(Self {
            snapshot,
            admitted: sessions,
        })
    }
}

impl AccessResolverPort for GovernorAccessResolver {
    fn resolve(&mut self, request: &ReadRequest) -> Result<AccessBinding, PortError> {
        SessionId::new(&request.session_id)
            .map_err(|error| PortError::Invalid(format!("controlboard session: {error}")))?;
        if request
            .expected_revision
            .is_some_and(|revision| revision.get() != self.snapshot.read_revision)
            || request
                .expected_fence
                .as_ref()
                .is_some_and(|fence| fence != &self.snapshot.fence)
        {
            return Err(PortError::Denied);
        }
        let admitted = self
            .admitted
            .get(&request.session_id)
            .ok_or(PortError::Unavailable)?;
        let access_revision = ViewRevision::new(self.snapshot.read_revision).map_err(|_| {
            PortError::Invalid("controlboard read revision must be non-zero".to_owned())
        })?;
        Ok(AccessBinding {
            principal_id: admitted.principal_id.clone(),
            work_scope: admitted.work_scope.clone(),
            role: admitted.role,
            admitted_privacy: admitted.admitted_privacy.clone(),
            capabilities: admitted.capabilities.clone(),
            session_id: request.session_id.clone(),
            connection_id: request.connection_id.clone(),
            credential_binding: request.credential_binding.clone(),
            challenge: request.challenge.clone(),
            request_id: request.request_id.clone(),
            generation: request.generation,
            issued_at_unix_ms: admitted.issued_at_unix_ms,
            observed_at_unix_ms: admitted.observed_at_unix_ms,
            expires_at_unix_ms: admitted.expires_at_unix_ms,
            access_revision,
            access_fence: self.snapshot.fence.clone(),
        })
    }
}

/// Governor-backed canonical state reader.
///
/// Serves the refresh-consistent snapshot as a valid empty-items view over
/// real G-11/I-12 bindings. Empty data and a missing provider stay distinct:
/// this path succeeds with zero items while genuinely absent providers fail
/// as typed gaps elsewhere.
struct GovernorCanonicalState {
    snapshot: Arc<ControlBoardGovernorSnapshot>,
}

impl GovernorCanonicalState {
    fn new(snapshot: Arc<ControlBoardGovernorSnapshot>) -> Self {
        Self { snapshot }
    }
}

impl CanonicalStatePort for GovernorCanonicalState {
    fn read(
        &mut self,
        _request: &ReadRequest,
        access: &AccessBinding,
    ) -> Result<CanonicalState, PortError> {
        access_currency(&self.snapshot, access)?;
        let revision = ViewRevision::new(self.snapshot.read_revision).map_err(|_| {
            PortError::Invalid("controlboard read revision must be non-zero".to_owned())
        })?;
        let state = CanonicalState {
            revision,
            fence: self.snapshot.fence.clone(),
            completeness: ProviderCompleteness {
                g11_coordination: ProjectionBinding {
                    provider: ProjectionProvider::G11,
                    work_id: "G-11".to_owned(),
                    binding_id: self.snapshot.g11_coordination.binding_id.clone(),
                    binding_revision: revision,
                    binding_fence: self.snapshot.fence.clone(),
                    binding_digest: self.snapshot.g11_coordination.binding_digest.clone(),
                    receipt_ref: self.snapshot.g11_coordination.receipt_ref.clone(),
                },
                i12_report_projection: ProjectionBinding {
                    provider: ProjectionProvider::I12,
                    work_id: "I-12".to_owned(),
                    binding_id: self.snapshot.i12_report.binding_id.clone(),
                    binding_revision: revision,
                    binding_fence: self.snapshot.fence.clone(),
                    binding_digest: self.snapshot.i12_report.binding_digest.clone(),
                    receipt_ref: self.snapshot.i12_report.receipt_ref.clone(),
                },
            },
            items: Vec::new(),
            reviews: Vec::new(),
            provenance: Vec::new(),
        };
        state
            .validate()
            .map_err(|error| PortError::Invalid(format!("governor controlboard state: {error}")))?;
        Ok(state)
    }
}

/// Process-retained exact-replay handle shared by every board built through
/// [`controlboard_over_snapshot`] from one
/// [`DaemonComposition`](super::DaemonComposition).
///
/// Volatile fast path only, never the durability story: it lets a newly
/// created board replay an admission without a second effecting-port call
/// while the process lives. Durable operator identity lives in Kernel ORS and
/// is reconciled through the async Governor operator borrow
/// (`GovernorComposition::operator_reconciliation`); a restart drops this map
/// and replays resolve through that receipt route instead.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedOperatorReplay {
    inner: Arc<Mutex<HashMap<String, (CommandRequest, CommandReceipt)>>>,
}

impl SharedOperatorReplay {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Counts stored admissions. Test introspection only: proving a replay
    /// across boards added no second admission.
    #[cfg(test)]
    pub(crate) fn admission_count(&self) -> usize {
        self.inner.lock().map_or(0, |map| map.len())
    }
}

/// Governor-backed operator command admission.
///
/// Admits one exact-view intent after verifying the owner-issued identity
/// binding against the live snapshot fence. The receipt is candidate-only:
/// it acknowledges admission, never execution, completion, or a canonical
/// write.
struct GovernorOperatorCommand {
    snapshot: Arc<ControlBoardGovernorSnapshot>,
    // #1187: exact-replay record keyed by operation_id text, shared through
    // [`SharedOperatorReplay`] so every board built from one daemon
    // composition replays the same admission. An identical binding returns
    // the stored receipt without a second admission; a changed binding under
    // the same operation_id surfaces as the controlboard IdentityConflict
    // (via PortError::IdentityConflict, mapped by
    // ControlBoardError::from_port). The stored binding is never overwritten,
    // so a conflict mutates no state. This map is a volatile fast path only:
    // cross-restart durability belongs to Kernel ORS through the async
    // Governor operator borrow, never to this handle.
    replay: SharedOperatorReplay,
}

impl GovernorOperatorCommand {
    /// Per-instance replay handle. Test use only: production boards share
    /// one daemon handle through [`Self::with_shared_replay`].
    #[cfg(test)]
    fn new(snapshot: Arc<ControlBoardGovernorSnapshot>) -> Self {
        Self {
            snapshot,
            replay: SharedOperatorReplay::new(),
        }
    }

    /// Shares one process-retained replay handle across boards built from one
    /// daemon composition. The handle is a volatile fast path only; durable
    /// identity stays in Kernel ORS.
    fn with_shared_replay(
        snapshot: Arc<ControlBoardGovernorSnapshot>,
        shared: &SharedOperatorReplay,
    ) -> Self {
        Self {
            snapshot,
            replay: shared.clone(),
        }
    }
}

/// Compares exactly the receipt-bound fields of two operator commands (#1187
/// R1). `operation_id` is the lookup key and `identity` is the authenticator,
/// so neither is compared here; session, access binding (capability),
/// action/target bytes and digest, revision, fence, and ceilings must all
/// match for an exact replay.
fn same_operator_binding(stored: &CommandRequest, incoming: &CommandRequest) -> bool {
    stored.session_id == incoming.session_id
        && stored.access_digest == incoming.access_digest
        && stored.action == incoming.action
        && stored.action_digest == incoming.action_digest
        && stored.expected_revision == incoming.expected_revision
        && stored.expected_fence == incoming.expected_fence
        && stored.proof_ceiling == incoming.proof_ceiling
        && stored.effect_ceiling == incoming.effect_ceiling
}

impl OperatorCommandPort for GovernorOperatorCommand {
    fn submit(&mut self, command: &CommandRequest) -> Result<CommandReceipt, PortError> {
        let operation_key = command.operation_id.as_str().to_owned();
        // A poisoned replay lock leaves the outcome unknown rather than
        // inventing an admission or a denial.
        let mut replay = self.replay.inner.lock().map_err(|_| PortError::Unknown)?;
        if let Some((bound, receipt)) = replay.get(&operation_key) {
            if same_operator_binding(bound, command) {
                return Ok(receipt.clone());
            }
            return Err(PortError::IdentityConflict);
        }
        if command.expected_revision.get() != self.snapshot.read_revision
            || command.expected_fence != self.snapshot.fence
        {
            return Err(PortError::Denied);
        }
        command.identity.validate().map_err(|error| {
            PortError::Invalid(format!("controlboard command identity: {error}"))
        })?;
        if command.identity.request.state_fence != self.snapshot.fence {
            return Err(PortError::Denied);
        }
        let identity_session = command
            .identity
            .request
            .metadata
            .session_id
            .clone()
            .map(SessionId::into_string)
            .unwrap_or_default();
        if identity_session != command.session_id {
            return Err(PortError::Denied);
        }
        let receipt = CommandReceipt {
            receipt_ref: format!(
                "controlboard-candidate:{}:{}",
                command.operation_id.as_str(),
                command.action_digest
            ),
            session_id: command.session_id.clone(),
            access_digest: command.access_digest.clone(),
            action_digest: command.action_digest.clone(),
            proof_ceiling: command.proof_ceiling,
            effect_ceiling: command.effect_ceiling,
            disposition: CommandDisposition::Accepted,
            observed_revision: command.expected_revision,
            observed_fence: command.expected_fence.clone(),
        };
        replay.insert(operation_key, (command.clone(), receipt.clone()));
        Ok(receipt)
    }
}

/// Governor-backed Swarm projection reader.
///
/// The port admits the catalogue and preference Swarm providers as explicit
/// owner-issued bindings (see [`GovernorSwarmProjection::with_admitted_providers`]).
/// Admission never invents projection bytes: the Governor snapshot carries no
/// catalogue/preference owner state, so a fully admitted read whose bytes are
/// not resolvable from the snapshot fails closed with a typed `Unknown` gap,
/// while a read with a missing provider fails as `Unavailable`. Both stay
/// typed gaps at the board (`UnknownOutcome` vs `PlanGap`); the zero-model
/// profile is preserved because this port populates no execution state either
/// way.
#[derive(Clone, Debug, Eq, PartialEq)]
struct GovernorSwarmProjection {
    snapshot: Arc<ControlBoardGovernorSnapshot>,
    admitted: BTreeMap<SwarmProviderSlot, AdmittedSwarmProvider>,
}

/// One Swarm provider slot the Governor snapshot port can admit. Only the
/// catalogue and preference providers have a Swarm projection contract; any
/// other provider remains a typed gap by construction.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum SwarmProviderSlot {
    Catalogue,
    Preferences,
}

/// Opaque owner-issued binding for one admitted Swarm provider. References
/// only: binding identity, binding digest, and receipt reference as strings.
/// No credential, secret, token, cookie, or payload bytes ever appear here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmittedSwarmProvider {
    slot: SwarmProviderSlot,
    binding_id: String,
    binding_digest: String,
    receipt_ref: String,
}

// RECHECK-265: composition admission seam wired once live catalogue bytes exist.
#[allow(dead_code)]
fn valid_binding_text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

// RECHECK-265: composition admission seam wired once live catalogue bytes exist.
#[allow(dead_code)]
fn valid_binding_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

// RECHECK-265: composition admission seam wired once live catalogue bytes exist.
#[allow(dead_code)]
impl AdmittedSwarmProvider {
    pub(crate) fn new(
        slot: SwarmProviderSlot,
        binding_id: impl Into<String>,
        binding_digest: impl Into<String>,
        receipt_ref: impl Into<String>,
    ) -> Result<Self, PortError> {
        let binding = Self {
            slot,
            binding_id: binding_id.into(),
            binding_digest: binding_digest.into(),
            receipt_ref: receipt_ref.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    fn validate(&self) -> Result<Self, PortError> {
        if !valid_binding_text(&self.binding_id)
            || !valid_binding_text(&self.receipt_ref)
            || !valid_binding_digest(&self.binding_digest)
        {
            return Err(PortError::Invalid(
                "swarm provider admission binding is malformed".to_owned(),
            ));
        }
        Ok(self.clone())
    }

    /// Exact-replay rule for one slot: identical bytes replay, changed bytes
    /// under the same slot conflict without mutating the stored binding.
    fn same_binding(&self, other: &Self) -> bool {
        self.slot == other.slot
            && self.binding_id == other.binding_id
            && self.binding_digest == other.binding_digest
            && self.receipt_ref == other.receipt_ref
    }
}

impl GovernorSwarmProjection {
    fn new(snapshot: Arc<ControlBoardGovernorSnapshot>) -> Self {
        Self {
            snapshot,
            admitted: BTreeMap::new(),
        }
    }

    /// Admits catalogue/preference Swarm providers into the Governor snapshot
    /// port. Each binding is validated fail-closed; re-admitting an identical
    /// binding is an idempotent replay, while a changed binding under an
    /// already-admitted slot is an identity conflict that mutates nothing.
    // RECHECK-265: composition admission point wired once live catalogue bytes exist.
    #[allow(dead_code)]
    pub(crate) fn with_admitted_providers(
        snapshot: Arc<ControlBoardGovernorSnapshot>,
        admitted: Vec<AdmittedSwarmProvider>,
    ) -> Result<Self, PortError> {
        let mut slots = BTreeMap::new();
        for binding in admitted {
            let binding = binding.validate()?;
            match slots.get(&binding.slot) {
                None => {
                    slots.insert(binding.slot, binding);
                }
                Some(stored) if stored.same_binding(&binding) => {}
                Some(_) => return Err(PortError::IdentityConflict),
            }
        }
        Ok(Self {
            snapshot,
            admitted: slots,
        })
    }

    fn admitted(&self, slot: SwarmProviderSlot) -> bool {
        self.admitted.contains_key(&slot)
    }
}

impl SwarmProjectionPort for GovernorSwarmProjection {
    fn read(
        &mut self,
        _request: &ReadRequest,
        access: &AccessBinding,
    ) -> Result<SwarmProjectionEnvelope, PortError> {
        access_currency(&self.snapshot, access)?;
        if !self.admitted(SwarmProviderSlot::Catalogue)
            || !self.admitted(SwarmProviderSlot::Preferences)
        {
            return Err(PortError::Unavailable);
        }
        // Both providers are admitted, but the Governor snapshot carries no
        // catalogue/preference owner bytes to project. Serving invented rows
        // would be a privacy expansion and a fabricated observation, so the
        // admitted-but-unresolvable read stays a typed gap instead.
        Err(PortError::Unknown)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use eliot_contracts::{
        ClockReading, EpochId, EpochLineageId, OperationId, ProductId, RequestId, RequestMetadata,
        ResourceGeneration, SourceId, StateFence,
    };
    use eliot_controlboard::{
        ActionCapability, ControlBoardError, OperatorAction, PrivacyClass, RequiredProvider, Role,
    };
    use eliot_protocol::RequestIdentity;
    use eliot_receipts::RequestBinding;
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn test_epoch(sequence: u64) -> EpochId {
        EpochId::new(
            EpochLineageId::new(TEST_LINEAGE_A).expect("valid test lineage"),
            NonZeroU64::new(sequence).expect("nonzero test sequence"),
        )
        .expect("valid test epoch")
    }

    fn fence() -> StateFence {
        StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(7).expect("generation"),
        )
    }

    fn snapshot() -> ControlBoardGovernorSnapshot {
        ControlBoardGovernorSnapshot {
            fence: fence(),
            read_revision: 7,
            coordination_sequence: 3,
            g11_coordination: eliot_governor::ControlBoardOwnerBinding {
                binding_id: "governor-owner:coordination".to_owned(),
                binding_digest: "c".repeat(64),
                receipt_ref: "a".repeat(64),
            },
            i12_report: eliot_governor::ControlBoardOwnerBinding {
                binding_id: "governor-owner:observation".to_owned(),
                binding_digest: "d".repeat(64),
                receipt_ref: "b".repeat(64),
            },
        }
    }

    fn identity_for(session: &str, fence: &StateFence) -> RequestIdentity {
        RequestIdentity {
            request: RequestBinding {
                metadata: RequestMetadata {
                    request_id: RequestId::new("request-1").expect("request id"),
                    session_id: Some(eliot_contracts::SessionId::new(session).expect("session id")),
                    task_id: None,
                    product_id: ProductId::new("product").expect("product id"),
                    source_id: SourceId::new("source").expect("source id"),
                    state_fence: fence.clone(),
                    clock: ClockReading::default(),
                },
                state_fence: fence.clone(),
            },
            idempotency_key: "idem-1".to_owned(),
            deadline_unix_ms: 1_000,
            cancellation_id: "cancel-1".to_owned(),
        }
    }

    fn request_for(session: &str) -> ReadRequest {
        ReadRequest::new(
            session,
            format!("{session}-connection"),
            format!("{session}-credential"),
            format!("{session}-challenge"),
            format!("{session}-request"),
            1,
        )
        .expect("request")
    }

    fn access_for(session: &str, capabilities: &[ActionCapability]) -> AccessBinding {
        access_at(
            session,
            capabilities,
            ViewRevision::new(7).expect("revision"),
            fence(),
        )
    }

    fn access_at(
        session: &str,
        capabilities: &[ActionCapability],
        revision: ViewRevision,
        fence: StateFence,
    ) -> AccessBinding {
        AccessBinding {
            principal_id: format!("{session}-principal"),
            work_scope: "scope".to_owned(),
            role: Role::HumanRequester,
            admitted_privacy: vec![PrivacyClass::Public],
            capabilities: capabilities.to_vec(),
            session_id: session.to_owned(),
            connection_id: format!("{session}-connection"),
            credential_binding: format!("{session}-credential"),
            challenge: format!("{session}-challenge"),
            request_id: format!("{session}-request"),
            generation: 1,
            issued_at_unix_ms: 1_000,
            observed_at_unix_ms: 1_100,
            expires_at_unix_ms: 2_000,
            access_revision: revision,
            access_fence: fence,
        }
    }

    fn command_for(session: &str, action: OperatorAction) -> CommandRequest {
        let fence = fence();
        CommandRequest::new(
            identity_for(session, &fence),
            OperationId::new("operation-1").expect("operation id"),
            ViewRevision::new(7).expect("revision"),
            fence,
            action,
        )
        .expect("command")
    }

    /// Session-keyed test access resolver. It returns exact bindings per
    /// known session and denies unknown ones; it mints no authority of its
    /// own and exists only to let the adapter tests reach the board logic.
    #[derive(Clone)]
    struct SessionKeyedAccess {
        bindings: BTreeMap<String, AccessBinding>,
    }

    impl AccessResolverPort for SessionKeyedAccess {
        fn resolve(&mut self, request: &ReadRequest) -> Result<AccessBinding, PortError> {
            self.bindings
                .get(&request.session_id)
                .cloned()
                .ok_or(PortError::Denied)
        }
    }

    /// Counting test command port. It records invocations and always
    /// accepts with the board-validated ceilings; assertions on the call
    /// count prove rejected commands never reach an effecting port.
    #[derive(Clone)]
    struct CountingCommand {
        calls: Arc<Mutex<usize>>,
    }

    impl OperatorCommandPort for CountingCommand {
        fn submit(&mut self, command: &CommandRequest) -> Result<CommandReceipt, PortError> {
            *self.calls.lock().expect("call count") += 1;
            Ok(CommandReceipt {
                receipt_ref: "receipt-1".to_owned(),
                session_id: command.session_id.clone(),
                access_digest: command.access_digest.clone(),
                action_digest: command.action_digest.clone(),
                proof_ceiling: command.proof_ceiling,
                effect_ceiling: command.effect_ceiling,
                disposition: CommandDisposition::Accepted,
                observed_revision: command.expected_revision,
                observed_fence: command.expected_fence.clone(),
            })
        }
    }

    fn board_with_counting_command(
        sessions: &[&str],
        capabilities: &[ActionCapability],
        calls: Arc<Mutex<usize>>,
    ) -> ControlBoard {
        let bindings = sessions
            .iter()
            .map(|session| ((*session).to_owned(), access_for(session, capabilities)))
            .collect();
        ControlBoard::new(
            Some(Box::new(SessionKeyedAccess { bindings })),
            Some(Box::new(GovernorCanonicalState::new(Arc::new(snapshot())))),
            Some(Box::new(CountingCommand { calls })),
        )
    }

    #[test]
    fn governor_read_adapter_serves_a_coherent_empty_view() {
        let calls = Arc::new(Mutex::new(0));
        let mut board = board_with_counting_command(&["session-a"], &[], Arc::clone(&calls));
        let view = board.view(&request_for("session-a")).expect("view");
        assert_eq!(view.revision.get(), 7);
        assert_eq!(view.fence, fence());
        assert!(view.items.is_empty());
        assert!(view.reviews.is_empty());
        assert!(view.provenance.is_empty());
        assert_eq!(*calls.lock().expect("call count"), 0);
    }

    #[test]
    fn admitted_start_query_returns_candidate_only_acceptance() {
        let snapshot = Arc::new(snapshot());
        let bindings = BTreeMap::from([(
            "session-a".to_owned(),
            access_for("session-a", &[ActionCapability::StartQuery]),
        )]);
        let mut board = ControlBoard::new(
            Some(Box::new(SessionKeyedAccess { bindings })),
            Some(Box::new(GovernorCanonicalState::new(Arc::clone(&snapshot)))),
            Some(Box::new(GovernorOperatorCommand::new(snapshot))),
        );
        let view = board.view(&request_for("session-a")).expect("view");
        assert!(view.items.is_empty());
        let submitted = command_for(
            "session-a",
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        );
        let receipt = board
            .submit(&request_for("session-a"), submitted.clone())
            .expect("receipt");
        assert_eq!(receipt.disposition, CommandDisposition::Accepted);
        assert_eq!(
            receipt.proof_ceiling,
            eliot_receipts::ProofCeiling::Observation
        );
        assert_eq!(receipt.proof_ceiling, submitted.proof_ceiling);
        assert_eq!(
            receipt.effect_ceiling,
            eliot_controlboard::EffectCeiling::CandidateOnly
        );
        assert_eq!(receipt.effect_ceiling, submitted.effect_ceiling);
        assert_eq!(receipt.observed_revision.get(), 7);
        assert_eq!(receipt.observed_fence, fence());
        let view = board.view(&request_for("session-a")).expect("view");
        assert!(view.items.is_empty());
    }

    #[test]
    fn cross_principal_and_stale_commands_invoke_no_effecting_port() {
        let calls = Arc::new(Mutex::new(0));
        let mut board = board_with_counting_command(
            &["session-a", "session-b"],
            &[ActionCapability::PauseTask, ActionCapability::StartQuery],
            Arc::clone(&calls),
        );
        let foreign = command_for(
            "session-a",
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        );
        assert_eq!(
            board.submit(&request_for("session-b"), foreign),
            Err(ControlBoardError::StaleView)
        );

        let mut replay = request_for("session-a");
        replay.connection_id = "stolen-connection".to_owned();
        assert_eq!(
            board.submit(
                &replay,
                command_for(
                    "session-a",
                    OperatorAction::StartQuery {
                        query_kind: "semantic-search".to_owned(),
                    },
                ),
            ),
            Err(ControlBoardError::Unauthorized)
        );

        let stale_fence = StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(6).expect("generation"),
        );
        let stale = CommandRequest::new(
            identity_for("session-a", &stale_fence),
            OperationId::new("operation-1").expect("operation id"),
            ViewRevision::new(6).expect("revision"),
            stale_fence,
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        )
        .expect("command");
        assert_eq!(
            board.submit(&request_for("session-a"), stale),
            Err(ControlBoardError::StaleView)
        );

        let mut tampered = command_for(
            "session-a",
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        );
        tampered.action_digest = "0".repeat(64);
        assert_eq!(
            board.submit(&request_for("session-a"), tampered),
            Err(ControlBoardError::ActionBindingMismatch)
        );
        assert_eq!(*calls.lock().expect("call count"), 0);
    }

    #[test]
    fn missing_providers_are_typed_gaps_not_empty_views() {
        let mut board =
            controlboard_over_snapshot(snapshot(), &SharedOperatorReplay::new(), Vec::new());
        assert_eq!(
            board.view(&request_for("session-a")),
            Err(ControlBoardError::PlanGap(RequiredProvider::AccessResolver))
        );

        let bindings = BTreeMap::from([("session-a".to_owned(), access_for("session-a", &[]))]);
        let mut board =
            ControlBoard::new(Some(Box::new(SessionKeyedAccess { bindings })), None, None)
                .with_swarm_projection(Box::new(GovernorSwarmProjection::new(
                    Arc::new(snapshot()),
                )));
        assert_eq!(
            board.swarm_view(&request_for("session-a")),
            Err(ControlBoardError::PlanGap(
                RequiredProvider::SwarmProjection
            ))
        );
    }

    #[test]
    fn stale_live_snapshot_denies_commands_before_effects() {
        let mut churned = snapshot();
        churned.read_revision = 8;
        churned.fence = StateFence::new(
            test_epoch(1),
            ResourceGeneration::new(8).expect("generation"),
        );
        let churned = Arc::new(churned);
        let bindings = BTreeMap::from([(
            "session-a".to_owned(),
            access_at(
                "session-a",
                &[ActionCapability::StartQuery],
                ViewRevision::new(8).expect("revision"),
                churned.fence.clone(),
            ),
        )]);
        let mut board = ControlBoard::new(
            Some(Box::new(SessionKeyedAccess { bindings })),
            Some(Box::new(GovernorCanonicalState::new(Arc::clone(&churned)))),
            Some(Box::new(GovernorOperatorCommand::new(Arc::new(snapshot())))),
        );
        let churned_command = {
            let fence = churned.fence.clone();
            CommandRequest::new(
                identity_for("session-a", &fence),
                OperationId::new("operation-1").expect("operation id"),
                ViewRevision::new(8).expect("revision"),
                fence,
                OperatorAction::StartQuery {
                    query_kind: "semantic-search".to_owned(),
                },
            )
            .expect("command")
        };
        assert_eq!(
            board.submit(&request_for("session-a"), churned_command),
            Err(ControlBoardError::Unauthorized)
        );
    }

    /// Counting decorator around the real Governor adapter (#1187 R1). It
    /// delegates every *new* admission and records invocations, so an exact
    /// replay short-circuited by the board store is observable as zero
    /// additional effecting-port calls.
    struct CountingOperator {
        inner: GovernorOperatorCommand,
        calls: Arc<Mutex<usize>>,
    }

    impl OperatorCommandPort for CountingOperator {
        fn submit(&mut self, command: &CommandRequest) -> Result<CommandReceipt, PortError> {
            *self.calls.lock().expect("call count") += 1;
            self.inner.submit(command)
        }
    }

    fn board_with_governor_command(
        snapshot: Arc<ControlBoardGovernorSnapshot>,
        calls: Arc<Mutex<usize>>,
    ) -> ControlBoard {
        let bindings = BTreeMap::from([(
            "session-a".to_owned(),
            access_for("session-a", &[ActionCapability::StartQuery]),
        )]);
        ControlBoard::new(
            Some(Box::new(SessionKeyedAccess { bindings })),
            Some(Box::new(GovernorCanonicalState::new(Arc::clone(&snapshot)))),
            Some(Box::new(CountingOperator {
                inner: GovernorOperatorCommand::new(snapshot),
                calls,
            })),
        )
    }

    fn start_query_for(session: &str) -> CommandRequest {
        command_for(
            session,
            OperatorAction::StartQuery {
                query_kind: "semantic-search".to_owned(),
            },
        )
    }

    #[test]
    fn exact_replay_returns_same_receipt() {
        let snapshot = Arc::new(snapshot());
        let calls = Arc::new(Mutex::new(0));
        let mut board = board_with_governor_command(snapshot, Arc::clone(&calls));
        let submitted = start_query_for("session-a");
        let first = board
            .submit(&request_for("session-a"), submitted.clone())
            .expect("first receipt");
        let second = board
            .submit(&request_for("session-a"), submitted)
            .expect("replay receipt");
        assert_eq!(first, second);
        assert_eq!(first.disposition, CommandDisposition::Accepted);
        assert_eq!(*calls.lock().expect("call count"), 1);
    }

    #[test]
    fn changed_payload_same_operation_is_identity_conflict() {
        let snapshot = Arc::new(snapshot());
        let calls = Arc::new(Mutex::new(0));
        let mut board = board_with_governor_command(snapshot, Arc::clone(&calls));
        let submitted = start_query_for("session-a");
        let first = board
            .submit(&request_for("session-a"), submitted.clone())
            .expect("first receipt");
        assert_eq!(*calls.lock().expect("call count"), 1);
        let changed = command_for(
            "session-a",
            OperatorAction::StartQuery {
                query_kind: "other-query".to_owned(),
            },
        );
        assert_eq!(
            changed.operation_id.as_str(),
            submitted.operation_id.as_str()
        );
        assert_ne!(changed.action_digest, submitted.action_digest);
        assert_eq!(
            board.submit(&request_for("session-a"), changed),
            Err(ControlBoardError::IdentityConflict)
        );
        assert_eq!(
            ControlBoardError::IdentityConflict.to_string(),
            "IDENTITY_CONFLICT"
        );
        assert_eq!(*calls.lock().expect("call count"), 1);
        // The conflict mutates no state: the original binding still replays.
        let replay = board
            .submit(&request_for("session-a"), submitted)
            .expect("replay receipt");
        assert_eq!(replay, first);
        assert_eq!(*calls.lock().expect("call count"), 1);
    }

    fn admitted_binding(slot: SwarmProviderSlot, name: &str) -> AdmittedSwarmProvider {
        AdmittedSwarmProvider::new(
            slot,
            format!("governor-owner:{name}"),
            "c".repeat(64),
            "e".repeat(64),
        )
        .expect("valid admission binding")
    }

    fn admitted_port() -> GovernorSwarmProjection {
        GovernorSwarmProjection::with_admitted_providers(
            Arc::new(snapshot()),
            vec![
                admitted_binding(SwarmProviderSlot::Catalogue, "catalogue"),
                admitted_binding(SwarmProviderSlot::Preferences, "preferences"),
            ],
        )
        .expect("admitted port")
    }

    #[test]
    fn swarm_provider_admission_validates_replays_and_conflicts() {
        assert!(matches!(
            AdmittedSwarmProvider::new(
                SwarmProviderSlot::Catalogue,
                "   ",
                "c".repeat(64),
                "e".repeat(64)
            ),
            Err(PortError::Invalid(_))
        ));
        assert!(matches!(
            AdmittedSwarmProvider::new(
                SwarmProviderSlot::Preferences,
                "governor-owner:preferences",
                "not-a-digest",
                "e".repeat(64)
            ),
            Err(PortError::Invalid(_))
        ));
        assert!(matches!(
            AdmittedSwarmProvider::new(
                SwarmProviderSlot::Catalogue,
                "governor-owner:catalogue",
                "c".repeat(64),
                "receipt\x07ref"
            ),
            Err(PortError::Invalid(_))
        ));

        // Re-admitting identical bindings is an idempotent replay.
        let replay = GovernorSwarmProjection::with_admitted_providers(
            Arc::new(snapshot()),
            vec![
                admitted_binding(SwarmProviderSlot::Catalogue, "catalogue"),
                admitted_binding(SwarmProviderSlot::Preferences, "preferences"),
            ],
        )
        .expect("replay admission");
        assert_eq!(replay.admitted, admitted_port().admitted);

        // A changed binding under an admitted slot conflicts and stores nothing.
        assert_eq!(
            GovernorSwarmProjection::with_admitted_providers(
                Arc::new(snapshot()),
                vec![
                    admitted_binding(SwarmProviderSlot::Catalogue, "catalogue"),
                    AdmittedSwarmProvider::new(
                        SwarmProviderSlot::Catalogue,
                        "governor-owner:catalogue",
                        "d".repeat(64),
                        "e".repeat(64),
                    )
                    .expect("changed binding validates structurally"),
                ],
            ),
            Err(PortError::IdentityConflict)
        );
    }

    #[test]
    fn admitted_swarm_reads_fail_as_typed_gaps_never_panics() {
        let access = access_for("session-a", &[]);
        // No admitted provider: the classic unavailable gap.
        let mut bare = GovernorSwarmProjection::new(Arc::new(snapshot()));
        assert_eq!(
            bare.read(&request_for("session-a"), &access),
            Err(PortError::Unavailable)
        );
        // Partial admission still lacks a required provider.
        let mut partial = GovernorSwarmProjection::with_admitted_providers(
            Arc::new(snapshot()),
            vec![admitted_binding(SwarmProviderSlot::Catalogue, "catalogue")],
        )
        .expect("partial admission");
        assert_eq!(
            partial.read(&request_for("session-a"), &access),
            Err(PortError::Unavailable)
        );
        // Full admission without resolvable Governor bytes is a distinct
        // typed gap, not a silent empty view and not a panic.
        let mut full = admitted_port();
        assert_eq!(
            full.read(&request_for("session-a"), &access),
            Err(PortError::Unknown)
        );
        // Currency still enforced before admission state is even consulted.
        let stale_access = access_at(
            "session-a",
            &[],
            ViewRevision::new(8).expect("revision"),
            fence(),
        );
        assert_eq!(
            full.read(&request_for("session-a"), &stale_access),
            Err(PortError::Denied)
        );

        // Board mapping keeps both gaps typed: unadmitted is a plan gap,
        // admitted-but-unresolvable is an unknown outcome.
        let bindings = BTreeMap::from([("session-a".to_owned(), access_for("session-a", &[]))]);
        let mut gap_board =
            ControlBoard::new(Some(Box::new(SessionKeyedAccess { bindings })), None, None)
                .with_swarm_projection(Box::new(GovernorSwarmProjection::new(
                    Arc::new(snapshot()),
                )));
        assert_eq!(
            gap_board.swarm_view(&request_for("session-a")),
            Err(ControlBoardError::PlanGap(
                RequiredProvider::SwarmProjection
            ))
        );
        let bindings = BTreeMap::from([("session-a".to_owned(), access_for("session-a", &[]))]);
        let mut admitted_board =
            ControlBoard::new(Some(Box::new(SessionKeyedAccess { bindings })), None, None)
                .with_swarm_projection(Box::new(admitted_port()));
        assert_eq!(
            admitted_board.swarm_view(&request_for("session-a")),
            Err(ControlBoardError::UnknownOutcome)
        );
    }

    #[test]
    fn governor_adapter_enforces_replay_idempotency_at_snapshot_binding() {
        let mut port = GovernorOperatorCommand::new(Arc::new(snapshot()));
        let submitted = start_query_for("session-a");
        let first = port.submit(&submitted).expect("first receipt");
        let second = port.submit(&submitted).expect("replay receipt");
        assert_eq!(first, second);
        let changed = command_for(
            "session-a",
            OperatorAction::StartQuery {
                query_kind: "other-query".to_owned(),
            },
        );
        assert_eq!(port.submit(&changed), Err(PortError::IdentityConflict));
        // No state mutation on conflict: the original binding still replays.
        assert_eq!(port.submit(&submitted).expect("replay receipt"), first);
    }

    fn admitted_start_session(session: &str) -> AdmittedSessionAccess {
        AdmittedSessionAccess::new(
            session,
            format!("{session}-principal"),
            "scope",
            Role::HumanRequester,
            vec![PrivacyClass::Public],
            vec![ActionCapability::StartQuery],
            format!("governor-owner:access:{session}"),
            "e".repeat(64),
            format!("governor-owner:receipt:{session}"),
            1_000,
            1_100,
            2_000,
        )
        .expect("valid session admission")
    }

    #[test]
    fn factory_boards_share_replay_without_second_admission() {
        // #1187 AUD-C03 acceptance 1-3 at eliotd level, built only through
        // the real factory path: board A admits, a newly created board B
        // replays the original identity with no second admission, a changed
        // payload conflicts without mutating anything, and a post-refresh
        // snapshot with the same handle still replays.
        let shared = SharedOperatorReplay::new();
        let mut board_a = controlboard_over_snapshot(
            snapshot(),
            &shared,
            vec![admitted_start_session("session-a")],
        );
        let submitted = start_query_for("session-a");
        let first = board_a
            .submit(&request_for("session-a"), submitted.clone())
            .expect("first receipt");
        assert_eq!(first.disposition, CommandDisposition::Accepted);
        assert_eq!(shared.admission_count(), 1);
        drop(board_a);
        // A newly created board over a post-refresh snapshot (same live
        // fence/revision) resolves the original identity.
        let mut board_b = controlboard_over_snapshot(
            snapshot(),
            &shared,
            vec![admitted_start_session("session-a")],
        );
        let replayed = board_b
            .submit(&request_for("session-a"), submitted.clone())
            .expect("replay receipt");
        assert_eq!(replayed, first);
        assert_eq!(
            shared.admission_count(),
            1,
            "replay through a new board must not be a second admission"
        );
        // Changed payload under the same operation id conflicts and stores
        // nothing.
        let changed = command_for(
            "session-a",
            OperatorAction::StartQuery {
                query_kind: "other-query".to_owned(),
            },
        );
        assert_eq!(
            board_b.submit(&request_for("session-a"), changed),
            Err(ControlBoardError::IdentityConflict)
        );
        assert_eq!(shared.admission_count(), 1);
        // The conflict mutated nothing: the original binding still replays.
        let again = board_b
            .submit(&request_for("session-a"), submitted)
            .expect("post-conflict replay");
        assert_eq!(again, first);
        assert_eq!(shared.admission_count(), 1);
    }

    fn admitted_session(session: &str) -> AdmittedSessionAccess {
        AdmittedSessionAccess::new(
            session,
            format!("{session}-principal"),
            "scope",
            Role::HumanRequester,
            vec![PrivacyClass::Public],
            Vec::new(),
            format!("governor-owner:access:{session}"),
            "e".repeat(64),
            format!("governor-owner:receipt:{session}"),
            1_000,
            1_100,
            2_000,
        )
        .expect("valid session admission")
    }

    fn board_with_admitted_session(
        snapshot: Arc<ControlBoardGovernorSnapshot>,
        admitted: AdmittedSessionAccess,
    ) -> ControlBoard {
        ControlBoard::new(
            Some(Box::new(
                GovernorAccessResolver::with_admitted_sessions(
                    Arc::clone(&snapshot),
                    vec![admitted],
                )
                .expect("admitted session"),
            )),
            Some(Box::new(GovernorCanonicalState::new(snapshot))),
            None,
        )
    }

    #[test]
    fn admitted_session_resolves_to_live_pinned_view() {
        let snapshot = Arc::new(snapshot());
        let admitted = admitted_session("session-a");
        // Port-level resolve pins the owner-issued facts to the live pins.
        let mut resolver = GovernorAccessResolver::with_admitted_sessions(
            Arc::clone(&snapshot),
            vec![admitted.clone()],
        )
        .expect("admitted session");
        let binding = resolver
            .resolve(&request_for("session-a"))
            .expect("resolve");
        assert_eq!(binding.session_id, "session-a");
        assert_eq!(binding.connection_id, "session-a-connection");
        assert_eq!(binding.principal_id, "session-a-principal");
        assert_eq!(binding.access_revision.get(), 7);
        assert_eq!(binding.access_fence, fence());
        // The same binding reads the real G-11/I-12 bindings from canonical state.
        let mut reader = GovernorCanonicalState::new(Arc::clone(&snapshot));
        let canonical = reader
            .read(&request_for("session-a"), &binding)
            .expect("canonical");
        assert_eq!(
            canonical.completeness.g11_coordination.binding_id,
            "governor-owner:coordination"
        );
        assert_eq!(
            canonical.completeness.i12_report_projection.binding_id,
            "governor-owner:observation"
        );
        // Board view over the real adapters: Ok empty view on the live pins.
        let mut board = board_with_admitted_session(Arc::clone(&snapshot), admitted);
        let view = board.view(&request_for("session-a")).expect("view");
        assert_eq!(view.revision.get(), 7);
        assert_eq!(view.fence, fence());
        assert!(view.items.is_empty());
        assert!(view.reviews.is_empty());
        assert!(view.provenance.is_empty());
        // Unknown session: source not connected, never an empty view.
        assert_eq!(
            board.view(&request_for("session-b")),
            Err(ControlBoardError::PlanGap(RequiredProvider::AccessResolver))
        );
        // Stale fence pin: denied before admission state is even consulted.
        let stale = request_for("session-a").pinned(
            ViewRevision::new(7).expect("revision"),
            StateFence::new(
                test_epoch(1),
                ResourceGeneration::new(6).expect("generation"),
            ),
        );
        assert_eq!(board.view(&stale), Err(ControlBoardError::Unauthorized));
        // Empty admission map: production behaviour is unchanged (unavailable).
        let mut bare = ControlBoard::new(
            Some(Box::new(GovernorAccessResolver::new(Arc::clone(&snapshot)))),
            Some(Box::new(GovernorCanonicalState::new(snapshot))),
            None,
        );
        assert_eq!(
            bare.view(&request_for("session-a")),
            Err(ControlBoardError::PlanGap(RequiredProvider::AccessResolver))
        );
    }

    #[test]
    fn changed_session_readmission_is_identity_conflict() {
        let snapshot = Arc::new(snapshot());
        let admitted = admitted_session("session-a");
        // Identical re-admission replays: both instances resolve the same binding.
        let mut first = GovernorAccessResolver::with_admitted_sessions(
            Arc::clone(&snapshot),
            vec![admitted.clone()],
        )
        .expect("admit");
        let mut replay = GovernorAccessResolver::with_admitted_sessions(
            Arc::clone(&snapshot),
            vec![admitted.clone()],
        )
        .expect("replay");
        assert_eq!(
            first.resolve(&request_for("session-a")).expect("resolve"),
            replay.resolve(&request_for("session-a")).expect("resolve")
        );
        // Changed facts under the admitted session id conflict and store nothing.
        let mut changed = admitted.clone();
        changed.work_scope = "other-scope".to_owned();
        assert!(matches!(
            GovernorAccessResolver::with_admitted_sessions(
                Arc::clone(&snapshot),
                vec![admitted, changed]
            ),
            Err(PortError::IdentityConflict)
        ));
        // Malformed owner facts (empty privacy admits nothing sealable) are
        // rejected at admission, never resolved.
        assert!(matches!(
            AdmittedSessionAccess::new(
                "session-a",
                "session-a-principal",
                "scope",
                Role::HumanRequester,
                Vec::new(),
                Vec::new(),
                "governor-owner:access:session-a",
                "e".repeat(64),
                "governor-owner:receipt:session-a",
                1_000,
                1_100,
                2_000,
            ),
            Err(PortError::Invalid(_))
        ));
    }
}
