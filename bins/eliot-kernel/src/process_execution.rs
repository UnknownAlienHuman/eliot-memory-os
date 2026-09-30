//! Kernel process-execution admission and execution closure.
//!
//! Traceability: Architecture A2.3, A13.2, ARCH-AUTH-01, ARCH-RES-01;
//! Implementation I1.2, I2.15, I14.6, I14.24, I14.26, I15.3. This ordinary
//! module owns only authenticated process admission,
//! authority/replay/evidence linearization, path proofs, and the bounded
//! executor handoff. It does not own task completion, semantic authority,
//! ambient command execution, or path widening. The module remains below the
//! <10k LOC split invariant.

use std::collections::{BTreeMap, btree_map::Entry};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::activation_lifecycle::{
    DescendantClosureReceipt, DescendantRegistry, RegisteredDescendant,
};
use super::host_request_route::change_monitor;
use super::{KernelComposition, KernelStoreGateway};
use eliot_ipc::Session;
use eliot_kernel_core::{
    AuthoritySnapshotBinding, AuthoritySnapshotBindingWire, DispatchSnapshotCodec,
    KernelAuthorityReplaySnapshot, ProcessDispatchAuthorityController, ProcessExecutionReplayAbort,
    ProcessExecutionReplayBegin, ProcessExecutionReplayRecord, ProcessExecutionReplayState,
    ProcessExecutionReplayStore, ProcessExecutionReplayStoreWithAbort, process_admission_digest,
};
use eliot_kernel_service::{
    HostKernelCandidateBinding, KernelServiceError, ProcessExecutionRequest,
    ProcessExecutionResponse,
};
use eliot_ors::{
    EpochIdentity, EpochLineage, OpaqueLabel, ProcessEvidenceRecord,
    ProcessStartReplayRecord as OrsReplayRecord, ProcessStartReplayState as OrsReplayState,
    ProcessStreamRecoveryBinding, ProcessStreamRecoveryProjection, RecoveryOwner,
    RedbRecoveryStore,
};
use eliot_platform::ClockObservation;
use eliot_platform_windows::{
    ProtectedSecret, RecoverableJobBinding, RecoverableJobObject, RetainedProcessPathLease,
    WindowsPlatform,
};
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchValidationContext, FencingToken, Generation,
    KernelDispatchKey, OperationId, OriginChallenge, OriginChallengeRequest, OriginControlGrant,
    OriginControlOperation, OriginControlPresentation, OriginGrantEffectOutcome, PermitIssuance,
    ProcessEvidence, ProcessEvidenceSink, ProcessExecutionAdmissionRequest, ProcessExecutionError,
    ProcessExecutor, ProcessLaunchAdmission, ProcessLifecycle, ProcessOwnerBinding, ProcessRequest,
    ProcessSessionBinding, ProcessStartReceipt, ProcessStreamEvidence, SessionId,
    SuspendedLaunchEvidence, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::{DispatchValidationPort, WindowsProcessExecutor};
use eliot_store_api::{
    CanonicalValidationSnapshot, RevisionHead, StateFence as StoreStateFence, canonical_json_bytes,
};
use serde::{Deserialize, Serialize};

/// F-LOG-KERNEL-3 (#901): process-execution boundary observations.
///
/// Observation only, via #895's facade: fixed `kernel.process.*` event names
/// plus a bounded stable outcome. Never carries operation identities,
/// digests, paths, command material, receipts, or owner error strings
/// (I15.4, I07.20).
fn observe_process(event: &'static str, outcome: &'static str) {
    use super::kernel_diagnostics::{KERNEL_DIAGNOSTICS_TARGET, bound_field};
    let event_bound = bound_field(event);
    let outcome_bound = bound_field(outcome);
    tracing::info!(
        target: KERNEL_DIAGNOSTICS_TARGET,
        event = event_bound.text(),
        outcome = outcome_bound.text(),
        "process execution observation"
    );
}

/// Maps one process-execution failure to its stable diagnostic code.
///
/// Only the variant is emitted; any `String` payload (executor detail, sink
/// message, contract field/reason) is never logged.
fn process_terminal_code(error: &ProcessExecutionError) -> &'static str {
    match error {
        ProcessExecutionError::Contract(_) => "process_contract",
        ProcessExecutionError::NotFound => "process_not_found",
        ProcessExecutionError::Unavailable(_) => "process_unavailable",
        ProcessExecutionError::EvidenceSink(_) => "process_evidence_sink",
        ProcessExecutionError::UnknownOutcome => "process_unknown_outcome",
    }
}

pub struct ProcessExecutionAuthorityConfig {
    pub authority_id: DispatchAuthorityId,
    pub key: KernelDispatchKey,
    pub snapshot_binding: AuthoritySnapshotBinding,
    pub snapshot_codec: Arc<dyn DispatchSnapshotCodec>,
}

struct OrsProcessReplayStore {
    store: Arc<RedbRecoveryStore>,
}

/// The authenticated process operation whose source effect is being observed.
///
/// This is formed from the admitted request and server-derived owner before a
/// process can start. A source adapter must use it to select the governed
/// attempt and tracked-resource baseline; executable, cwd, and exit status are
/// deliberately absent as source-mutation evidence. The lease is the exact
/// admitted `ActionLeaseRef` (I10.21 associated Session/ActionLease/tool
/// operation/attempt); it is carried for adapter attribution and never
/// re-derived, and the executor handoff invents no lease comparison because it
/// carries no lease value to compare against.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GovernedProcessEffectBinding {
    operation_id: OperationId,
    session_id: SessionId,
    action_lease_ref: ActionLeaseRef,
    state_fence: FencingToken,
    owner: ProcessOwnerBinding,
}

impl GovernedProcessEffectBinding {
    fn from_admission(
        owner: &ProcessOwnerBinding,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> Result<Self, ProcessExecutionError> {
        admission.validate()?;
        let intent = admission.intent();
        if admission.recipient_module_id() != owner.module_id()
            || !admission
                .state_fence()
                .authority_epoch()
                .is_same_authority(owner.authority_epoch())
            || admission.state_fence().generation() != owner.generation()
            || admission.state_fence().generation() != intent.generation()
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        Ok(Self {
            operation_id: intent.operation_id().clone(),
            session_id: intent.session_id().clone(),
            action_lease_ref: admission.action_lease_ref().clone(),
            state_fence: admission.state_fence().clone(),
            owner: owner.clone(),
        })
    }

    pub(crate) fn operation_id(&self) -> &OperationId {
        &self.operation_id
    }

    fn matches_request(&self, owner: &ProcessOwnerBinding, request: &ProcessRequest) -> bool {
        self.owner == *owner
            && self.operation_id == *request.operation_id()
            && self.session_id == *request.session_id()
            && self.state_fence == *request.fence()
            && self.state_fence.generation() == request.generation()
    }
}

/// Complete tracked-source baseline captured before the admitted process effect.
///
/// The Kernel-owned effect port constructs one entry per admission-declared
/// mutation target: two independent opens of the declared path that must
/// agree, resolved under the lease-owned working directory. The tool
/// executable image is not a tracked source and is never read here; it only
/// scopes launch authority through the path lease. A baseline without
/// targets carries no source identity: the operation runs unobserved and no
/// hint is ingested for it, so a monitor gap on a never-declared path can
/// never wedge governed acceptance or fence the tool.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GovernedProcessEffectBaseline {
    binding: GovernedProcessEffectBinding,
    targets: Vec<EffectTargetBaseline>,
    capture_fence: FencingToken,
    effect_digest: String,
}

/// One declared target's pre-effect state: the absolute declared path, its
/// ledger resource identity, the lane-stable locator, and the proven
/// before-state (exact bytes plus digest) two agreeing reads established.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectTargetBaseline {
    path: PathBuf,
    resource: String,
    lane_path: String,
    target_digest: String,
    before_bytes: Vec<u8>,
    before_digest: String,
}

impl GovernedProcessEffectBaseline {
    pub(crate) fn binding(&self) -> &GovernedProcessEffectBinding {
        &self.binding
    }

    pub(crate) fn observed(&self) -> bool {
        !self.targets.is_empty()
    }
}

/// Validated post-effect readback for one admitted process operation.
///
/// The Kernel-owned effect port constructs one entry per baseline target
/// from two further independent opens plus the terminal evidence's own
/// State Fence. A target that cannot be read back is omitted here, unless
/// two agreeing not-found observations prove deletion (I10.21 AUD5), which
/// crosses as deletion evidence; only agreeing real reads otherwise become
/// evidence. A receipt without targets proves nothing and ingests nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GovernedProcessChangeReceipt {
    targets: Vec<EffectTargetReceipt>,
    terminal_fence: FencingToken,
}

/// One declared target's terminal state, joined to its baseline entry by
/// absolute declared path. Only the agreeing terminal reads cross into
/// evidence; ledger identity (resource, lane path, target digest) is read
/// from the baseline entry the path joins to. An after-state of all-`None`
/// is proven deletion (two agreeing not-found reads against the baseline),
/// never a read glitch: it admits an immutable `Absent` observation at
/// ingest instead of an unobserved gap.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EffectTargetReceipt {
    path: PathBuf,
    after_bytes: Option<Vec<u8>>,
    after_first_digest: Option<String>,
    after_reread_digest: Option<String>,
}

impl GovernedProcessChangeReceipt {
    pub(crate) fn observed(&self) -> bool {
        !self.targets.is_empty()
    }
}

/// Typed `ChangeMonitor` ingress failures the effect port reports instead
/// of swallowing (I10.21 AUD4).
///
/// Per-target evidence outcomes still report through the baseline/receipt
/// `observed` flags instead of failing: an unreadable image or a
/// mismatched operation runs unobserved, never fenced. A poisoned ledger
/// is not an evidence outcome: no hint, record, or confirmation below can
/// be admitted or read back, so the observation is refused with a typed
/// error instead of recorded as unobserved. The gateway observes the typed
/// outcome and continues the operation; the poisoned ledger itself keeps
/// governed acceptance blocked, so reporting never fences an unrelated
/// module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum GovernedProcessEffectPortError {
    /// The `ChangeMonitor` ledger lock is poisoned.
    LedgerPoisoned,
}

/// Kernel-owned readback and `ChangeMonitor` ingress for process tools.
///
/// The attached implementor
/// ([`KernelGovernedProcessEffectPort`]) opens each admission-declared
/// mutation target before launch and again at reconcile, hashes the exact
/// bytes itself, and ingests the validated transition bound to the exact
/// governed baseline Kernel retained for the operation. Kernel always
/// supplies that baseline at ingest so the observation keeps its
/// Session/operation/State-Fence attribution; process success is never
/// source evidence, and unreadable or mismatched observations stay
/// unobserved instead of inventing bytes.
pub(crate) trait GovernedProcessEffectPort: Send + Sync {
    fn capture_before(
        &self,
        binding: &GovernedProcessEffectBinding,
        source: &GovernedProcessEffectSource,
    ) -> Result<GovernedProcessEffectBaseline, GovernedProcessEffectPortError>;

    fn read_after(
        &self,
        baseline: &GovernedProcessEffectBaseline,
        terminal_evidence: &ProcessEvidence,
    ) -> Result<GovernedProcessChangeReceipt, GovernedProcessEffectPortError>;

    fn ingest(
        &self,
        baseline: GovernedProcessEffectBaseline,
        receipt: GovernedProcessChangeReceipt,
    ) -> Result<(), GovernedProcessEffectPortError>;
}

/// Lease-owned tracked-source read for one governed process operation.
///
/// Built by the gateway from the admitted intent and the retained path
/// proof: the executable and working directory the
/// `RetainedProcessPathLease` owns (launch-authority scope only, never
/// source evidence), the admission-pinned content digest the intent
/// validator checked, the validated effect digest that receipts this exact
/// attempt, and the declared mutation set: admission-declared (argv) paths
/// resolved under the working directory. Argv is part of the intent's
/// `effect_digest` preimage, so these targets are admission-declared, not
/// inferred; the port observes exactly them instead of the tool image.
pub(crate) struct GovernedProcessEffectSource {
    executable: PathBuf,
    working_directory: PathBuf,
    expected_sha256: String,
    effect_digest: String,
    lease: Arc<RetainedProcessPathLease>,
    declared_targets: Vec<PathBuf>,
}

/// Kernel-owned `ChangeMonitor` readback adapter for governed tool effects
/// (#1824, I10.21 W2/A1/A2).
///
/// Attached at [`ProcessExecutionGateway::new`]. Every digest below comes
/// from a real file open of an admission-declared mutation target: two
/// opens at capture (which must agree, or the target stays out of the
/// baseline) and two opens at readback (which the ledger itself compares,
/// with disagreement refused as `UnstableReadback`). The admission-pinned
/// digest is only the lease authority the capture validates against: any
/// transition between the retained previous digest
/// and two fresh agreeing reads is confirmed through the filesystem/Git
/// observation adapter ([`change_monitor::observe_filesystem_notification`])
/// against actual Git-substrate plus content re-read evidence for the real
/// hinted source, so an external uncorrelated mutation emits an
/// unknown-origin change and blocks governed acceptance until a recorded
/// governed change reconciles it. A transition the adapter cannot confirm
/// keeps the retained digest for the next capture instead of advancing
/// past evidence the ledger never admitted.
/// Per-artifact last-observed
/// digests are retained here under one mutex (atomic publish); the ledger
/// itself stays the only acceptance gate. After a restart the map starts
/// empty and each capture falls back to the ledger-retained tip
/// ([`change_monitor::resource_tip`], rebuilt from the durable sidecar at
/// construction), so a restart never silently establishes a fresh baseline
/// over an unreconciled mutation.
pub(crate) struct KernelGovernedProcessEffectPort {
    last_observed: Mutex<BTreeMap<String, String>>,
}

/// What two opens of one tracked source prove: agreeing present bytes are
/// a stable observation; two agreeing not-found observations prove absence
/// (I10.21 AUD5: the deletion evidence the reconcile path admits as an
/// immutable `Absent` observation). Any other failure — permissions,
/// transient I/O, or disagreeing reads — proves nothing about stability or
/// absence and is `None` from the reader below, never a deletion claim.
enum TrackedSourceRead {
    Present {
        bytes: Vec<u8>,
        first_digest: String,
        reread_digest: String,
    },
    Absent,
}

impl KernelGovernedProcessEffectPort {
    pub(crate) fn new() -> Self {
        let port = Self {
            last_observed: Mutex::new(BTreeMap::new()),
        };
        // I10.21 durability (AUD3): rebuild the ledger from its durable
        // sidecar when this process started fresh, so ledger-retained tips
        // keep detecting external transitions below. A missing sidecar is
        // a clean boot; a corrupt or unreadable sidecar is reported here
        // and stays fail-closed at the finish-acceptance gate, which
        // rehydrates (and refuses) before consulting it.
        if change_monitor::hydrate_ledger_sidecar_if_empty().is_err() {
            observe_process(
                "kernel.process.effect_baseline_unavailable",
                "hydrate_failed",
            );
        }
        port
    }

    /// Opens the tracked path twice and hashes both reads. The digests
    /// must agree: a single read proves nothing about stability, and two
    /// reads that disagree prove the path is changing under observation.
    fn read_tracked_source(path: &Path) -> Option<TrackedSourceRead> {
        let first = match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return None,
        };
        let second = match std::fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(_) => return None,
        };
        match (first, second) {
            (Some(first_bytes), Some(second_bytes)) => {
                let first_digest = super::sha256_hex(&first_bytes);
                let reread_digest = super::sha256_hex(&second_bytes);
                (first_digest == reread_digest).then_some(TrackedSourceRead::Present {
                    bytes: first_bytes,
                    first_digest,
                    reread_digest,
                })
            }
            (None, None) => Some(TrackedSourceRead::Absent),
            (Some(_), None) | (None, Some(_)) => None,
        }
    }

    /// Lane-stable locator for one tracked resource: the content-bound
    /// digest of its stable identity, never a bare constant, so distinct
    /// tracked sources never share one artifact record.
    fn lane_path_for(resource: &str) -> (String, String) {
        let target_digest = super::sha256_hex(resource.as_bytes());
        (
            target_digest.clone(),
            format!("process-target/{target_digest}"),
        )
    }

    /// Confirms one unexplained tracked-source transition through the
    /// filesystem/Git observation adapter
    /// ([`change_monitor::observe_filesystem_notification`]): the retained
    /// previous digest against actual Git-substrate plus content re-read
    /// evidence the adapter collects itself, admitted through the existing
    /// ingest-plus-confirm path. The adapter takes the real hinted source —
    /// the lease-owned file the capture reads just proved moved, named
    /// relative to the lease-owned working directory — never a synthesized
    /// OS event: a source that cannot be named under that root has no valid
    /// hint shape and is refused as
    /// [`change_monitor::ChangeMonitorError::InvalidHint`] without touching
    /// the ledger. Failures stay typed so the caller keeps failing closed
    /// (the retained digest is preserved for the next capture) without
    /// inventing evidence; ledger contention never fences the tool.
    fn observe_external_filesystem_transition(
        workspace_root: &Path,
        hinted_source: &Path,
        resource: &str,
        event_ref: &str,
        before_digest: &str,
    ) -> Result<change_monitor::HintConfirmation, change_monitor::ChangeMonitorError> {
        let relative = hinted_source
            .strip_prefix(workspace_root)
            .map_err(|_| change_monitor::ChangeMonitorError::InvalidHint)?;
        let notification = change_monitor::FilesystemEventNotification {
            event_ref: event_ref.to_owned(),
            resource: resource.to_owned(),
            path: relative.to_string_lossy().replace('\\', "/"),
        };
        change_monitor::observe_filesystem_notification(
            workspace_root,
            &notification,
            Some(before_digest),
        )
    }

    /// Checks one retained previous digest against fresh reads through the
    /// filesystem/Git observation adapter (I10.21 A2): the retained previous
    /// digest against two fresh agreeing reads is evidence no admission
    /// explains by itself, so the transition is external and uncorrelated
    /// until a recorded governed change reconciles it. Sets `observed` when
    /// the adapter admits the transition and returns `false`; returns `true`
    /// when the caller must skip the target (the transition stays
    /// unrecorded and a blocking gap marker pins the retained digest so the
    /// next capture re-detects it instead of advancing past evidence the
    /// ledger never admitted). Ledger contention fences the tool instead.
    fn check_retained_external_transition(
        workspace_root: &Path,
        hinted_source: &Path,
        resource: &str,
        event_ref: &str,
        previous: &str,
        operation: &str,
        observed: &mut bool,
    ) -> Result<bool, GovernedProcessEffectPortError> {
        match Self::observe_external_filesystem_transition(
            workspace_root,
            hinted_source,
            resource,
            event_ref,
            previous,
        ) {
            Ok(confirmation) => {
                *observed = true;
                observe_process(
                    "kernel.process.effect_external_transition",
                    match confirmation {
                        change_monitor::HintConfirmation::VerifiedImmaterial => "immaterial",
                        change_monitor::HintConfirmation::MaterialRecorded {
                            reconciled, ..
                        } => {
                            if reconciled {
                                "reconciled"
                            } else {
                                "material"
                            }
                        }
                    },
                );
                Ok(false)
            }
            Err(error) => {
                let outcome = if error == change_monitor::ChangeMonitorError::UnstableReadback {
                    "unstable"
                } else {
                    "unobserved"
                };
                // I10.21 AUD4: the retained previous digest proves
                // a real transition, but the ledger could not
                // record it. The target leaves the baseline with a
                // blocking gap marker pinned to the retained digest
                // instead of advancing past evidence the ledger
                // never admitted; the next capture re-detects it.
                match change_monitor::note_unresolved_transition(
                    resource,
                    operation,
                    Some(previous.to_owned()),
                ) {
                    Ok(_) => {
                        observe_process("kernel.process.effect_external_transition", "unresolved")
                    }
                    Err(change_monitor::ChangeMonitorError::LedgerPoisoned) => {
                        return Err(GovernedProcessEffectPortError::LedgerPoisoned);
                    }
                    Err(_) => observe_process("kernel.process.effect_external_transition", outcome),
                }
                Ok(true)
            }
        }
    }

    /// Admits one host-event hint for a declared target (I10.21 A1). A
    /// conflicting identity under the same hint reuses an operation handle
    /// for different content: evidence is ambiguous, so nothing is recorded
    /// or confirmed for it. Ledger failures are typed, never swallowed
    /// (I10.21 AUD4): a poisoned ledger refuses the observation instead of
    /// recording it as unobserved, and any other ingest refusal pins a
    /// blocking gap marker on the retained baseline instead of leaving the
    /// resource unblocked. Returns the admitted hint identity plus whether
    /// the caller must skip the target (`true`: the hint was refused and
    /// the caller must continue ingest for the next target).
    fn admit_host_event_hint(
        operation: &str,
        target_digest: &str,
        resource: &str,
        lane_path: &str,
        owner_module: &str,
        before_digest: &str,
    ) -> Result<(String, bool), GovernedProcessEffectPortError> {
        let hint_id = change_monitor::host_hint_id(operation, target_digest);
        let hint = change_monitor::KernelChangeHint {
            hint_id: hint_id.clone(),
            resource: resource.to_owned(),
            path: lane_path.to_owned(),
            origin: change_monitor::HintOrigin::HostEvent,
            origin_ref: Some(owner_module.to_owned()),
        };
        match change_monitor::ingest_hint(hint) {
            Ok(_) => Ok((hint_id, false)),
            Err(change_monitor::ChangeMonitorError::LedgerPoisoned) => {
                Err(GovernedProcessEffectPortError::LedgerPoisoned)
            }
            Err(_) => {
                let outcome = match change_monitor::note_unresolved_transition(
                    resource,
                    operation,
                    Some(before_digest.to_owned()),
                ) {
                    Ok(_) => "unresolved",
                    Err(change_monitor::ChangeMonitorError::LedgerPoisoned) => {
                        return Err(GovernedProcessEffectPortError::LedgerPoisoned);
                    }
                    Err(_) => "unobserved",
                };
                observe_process("kernel.process.effect_observed", outcome);
                Ok((hint_id, true))
            }
        }
    }
}

/// Resolves one path lexically (`.`/`..` without touching the filesystem).
/// Returns `None` when `..` escapes past the filesystem root.
fn lexical_normalize(path: &Path) -> Option<PathBuf> {
    use std::path::Component;
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(part) => out.push(part.as_os_str()),
            Component::RootDir => out.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    return None;
                }
            }
            Component::Normal(part) => out.push(part),
        }
    }
    Some(out)
}

/// Derives the declared mutation set for one admitted operation (I10.21
/// A1): argv entries after the program name that resolve inside the
/// lease-owned working directory. Argv is pinned by the intent's
/// `effect_digest`, so these paths are admission-declared; flags, blanks,
/// control-carrying entries, escapes above the working directory, and the
/// working directory itself are never tracked sources. File granularity:
/// a declared directory cannot be checksummed as one unit and is observed
/// only through the files later operations declare.
fn declared_target_paths(argv: &[String], working_directory: &Path) -> Vec<PathBuf> {
    let Some(root) = lexical_normalize(working_directory) else {
        return Vec::new();
    };
    let mut targets = Vec::new();
    for entry in argv.iter().skip(1) {
        if entry.trim().is_empty() || entry.starts_with('-') || entry.chars().any(char::is_control)
        {
            continue;
        }
        let candidate = if Path::new(entry).is_absolute() {
            PathBuf::from(entry)
        } else {
            working_directory.join(entry)
        };
        let Some(normalized) = lexical_normalize(&candidate) else {
            continue;
        };
        if normalized == root || !normalized.starts_with(&root) || targets.contains(&normalized) {
            continue;
        }
        targets.push(normalized);
    }
    targets
}

// I10.21 A1: only a proven transition becomes a governed record. The
// ledger hashes the supplied bytes itself and the diff handle is the
// ledger's own transition binder, so the handle resolves to the recorded
// transition by construction. The record is written before confirmation so
// the confirmation can reconcile against this exact evidence. The
// change identity scopes the record to this operation's exact
// target, so one operation's targets never share one record. A proven
// deletion (agreeing terminal absence against a present baseline, I10.21
// AUD5) records with no after side, so a tool that unlinked its declared
// target reconciles the exact deletion instead of leaving an
// unreconciled unknown no later observation can explain.
fn record_proven_target_transition(
    operation: &str,
    base: &EffectTargetBaseline,
    back: &EffectTargetReceipt,
    baseline: &GovernedProcessEffectBaseline,
    receipt: &GovernedProcessChangeReceipt,
) -> Option<String> {
    let mut recorded_transition: Option<String> = None;
    let present_transition = match (&back.after_first_digest, &back.after_reread_digest) {
        (Some(first), Some(reread)) => first == reread && first != &base.before_digest,
        _ => false,
    };
    let deletion = back.after_first_digest.is_none() && back.after_reread_digest.is_none();
    if present_transition || deletion {
        let target_digest = base.target_digest.as_str();
        let change_id = format!("{operation}:{target_digest}");
        let (_, transition) = change_monitor::material_transition_ids(
            &change_id,
            Some(base.before_digest.as_str()),
            back.after_first_digest.as_deref(),
        );
        let change = change_monitor::GovernedToolChange {
            change_id,
            resource: base.resource.clone(),
            path: base.lane_path.clone(),
            before_path: None,
            before_revision: Some(base.before_digest.clone()),
            before_bytes: Some(base.before_bytes.clone()),
            after_revision: back.after_first_digest.clone(),
            after_bytes: back.after_bytes.clone(),
            session: baseline.binding.session_id.as_str().to_owned(),
            action_lease: baseline.binding.action_lease_ref.as_str().to_owned(),
            operation: operation.to_owned(),
            attempt_receipt: baseline.effect_digest.clone(),
            diff_handle: transition.clone(),
            fence_generation: receipt.terminal_fence.generation().get(),
            fence_invalidated: receipt.terminal_fence != baseline.capture_fence,
        };
        match change_monitor::record_governed_tool_change(&change) {
            Ok(_) => {
                recorded_transition = Some(transition);
                observe_process("kernel.process.effect_observed", "recorded");
            }
            Err(_) => {
                observe_process("kernel.process.effect_observed", "refused");
            }
        }
    }
    recorded_transition
}

impl GovernedProcessEffectPort for KernelGovernedProcessEffectPort {
    fn capture_before(
        &self,
        binding: &GovernedProcessEffectBinding,
        source: &GovernedProcessEffectSource,
    ) -> Result<GovernedProcessEffectBaseline, GovernedProcessEffectPortError> {
        let unobserved = || GovernedProcessEffectBaseline {
            binding: binding.clone(),
            targets: Vec::new(),
            capture_fence: binding.state_fence.clone(),
            effect_digest: source.effect_digest.clone(),
        };
        // I10.21 W2: the readback lane only trusts the lease-owned scope.
        // A launch the lease cannot prove runs unobserved instead of
        // inventing evidence; per-target observation below still reads
        // nothing outside the declared set.
        if source
            .lease
            .validate(
                &source.executable,
                &source.working_directory,
                &source.expected_sha256,
            )
            .is_err()
        {
            observe_process("kernel.process.effect_baseline_unavailable", "unobserved");
            return Ok(unobserved());
        }
        let mut targets = Vec::new();
        let mut mutated = false;
        for target_path in &source.declared_targets {
            let resource = target_path.to_string_lossy().into_owned();
            if resource.trim().is_empty() || resource.chars().any(char::is_control) {
                continue;
            }
            let (target_digest, lane_path) = Self::lane_path_for(&resource);
            let Some(TrackedSourceRead::Present {
                bytes: before_bytes,
                first_digest,
                ..
            }) = Self::read_tracked_source(target_path)
            else {
                // No evidence for this target: it stays out of the baseline
                // instead of inventing bytes. An absent declared path is
                // not a proven absence here: at capture a missing path may
                // be a creation the tool is about to perform, so absence
                // becomes ledger evidence only as a readback deletion
                // against a retained baseline (see `read_after`, I10.21
                // AUD5).
                continue;
            };
            let previous = self
                .last_observed
                .lock()
                .ok()
                .and_then(|last| last.get(&resource).cloned())
                .or_else(|| {
                    // I10.21 durability (AUD3): after a restart this map
                    // starts empty while the ledger-retained tip survived
                    // in the durable sidecar, so the tip is the previous
                    // digest instead of silently establishing a fresh
                    // baseline over an unreconciled mutation.
                    change_monitor::resource_tip(&resource).and_then(|tip| tip.digest)
                });
            let operation = binding.operation_id().as_str().to_owned();
            if let Some(previous) = previous
                && previous != first_digest
            {
                // The declared target moved between independent
                // observations: the retained previous digest against two
                // fresh agreeing reads is evidence no admission explains by
                // itself (a re-pinned admission digest only proves the lease
                // scope, not who wrote the bytes), so the transition is
                // external and uncorrelated until a recorded governed change
                // reconciles it. The real hinted source goes through the
                // filesystem/Git observation adapter against actual
                // Git-substrate plus content re-read evidence; a typed
                // refusal keeps the retained digest so the next capture
                // retries instead of advancing past evidence the ledger
                // never admitted.
                if Self::check_retained_external_transition(
                    &source.working_directory,
                    target_path,
                    &resource,
                    binding.owner.module_id(),
                    &previous,
                    &operation,
                    &mut mutated,
                )? {
                    continue;
                }
            }
            if let Ok(mut last) = self.last_observed.lock() {
                last.insert(resource.clone(), first_digest.clone());
            }
            targets.push(EffectTargetBaseline {
                path: target_path.clone(),
                resource,
                lane_path,
                target_digest,
                before_bytes,
                before_digest: first_digest,
            });
        }
        if targets.is_empty() {
            observe_process("kernel.process.effect_baseline_unavailable", "unobserved");
        }
        // I10.21 durability (AUD3): capture-time ledger mutations
        // (external-transition confirmations) are observations in their
        // own right: persist them best-effort so a crash before reconcile
        // still retains them. The observation stands regardless; only
        // durability is best-effort, and it stays visible instead of
        // silent.
        if mutated && change_monitor::persist_ledger_sidecar().is_err() {
            observe_process("kernel.process.effect_observed", "persist_failed");
        }
        Ok(GovernedProcessEffectBaseline {
            binding: binding.clone(),
            targets,
            capture_fence: binding.state_fence.clone(),
            effect_digest: source.effect_digest.clone(),
        })
    }

    fn read_after(
        &self,
        baseline: &GovernedProcessEffectBaseline,
        terminal_evidence: &ProcessEvidence,
    ) -> Result<GovernedProcessChangeReceipt, GovernedProcessEffectPortError> {
        let unobserved = || GovernedProcessChangeReceipt {
            targets: Vec::new(),
            terminal_fence: terminal_evidence.binding().state_fence().clone(),
        };
        // I10.21: evidence is bound to this operation. Terminal evidence
        // for another operation proves nothing about this baseline.
        if terminal_evidence.binding().operation_id() != baseline.binding.operation_id() {
            observe_process("kernel.process.effect_readback_failed", "unobserved");
            return Ok(unobserved());
        }
        let operation = baseline.binding.operation_id().as_str().to_owned();
        let mut targets = Vec::new();
        for base in &baseline.targets {
            match Self::read_tracked_source(&base.path) {
                Some(TrackedSourceRead::Present {
                    bytes: after_bytes,
                    first_digest,
                    reread_digest,
                }) => targets.push(EffectTargetReceipt {
                    path: base.path.clone(),
                    after_bytes: Some(after_bytes),
                    after_first_digest: Some(first_digest),
                    after_reread_digest: Some(reread_digest),
                }),
                Some(TrackedSourceRead::Absent) => {
                    // I10.21 AUD5: two agreeing not-found observations
                    // against this operation's own retained baseline prove
                    // the declared target was deleted during the run. The
                    // target crosses into the receipt as deletion evidence
                    // so ingest admits an immutable `Absent` observation:
                    // a tool that unlinked its declared target reconciles
                    // the exact deletion, while anything else stays
                    // blocked as an unreconciled unknown-origin deletion.
                    targets.push(EffectTargetReceipt {
                        path: base.path.clone(),
                        after_bytes: None,
                        after_first_digest: None,
                        after_reread_digest: None,
                    });
                    observe_process("kernel.process.effect_readback_deleted", "deleted");
                }
                None => {
                    // No evidence for this declared target: it proves
                    // nothing for this operation and ingests nothing. The
                    // retained digest is kept for the next capture instead
                    // of advancing past evidence the ledger never admitted
                    // (I10.21 AUD4): a previously observed target that can
                    // no longer be read gains a blocking gap marker, while
                    // a never-observed path simply stays out of the
                    // receipt.
                    let previous = self
                        .last_observed
                        .lock()
                        .ok()
                        .and_then(|last| last.get(&base.resource).cloned())
                        .or_else(|| {
                            change_monitor::resource_tip(&base.resource).and_then(|tip| tip.digest)
                        });
                    let outcome = match previous {
                        Some(digest) => match change_monitor::note_unresolved_transition(
                            &base.resource,
                            &operation,
                            Some(digest),
                        ) {
                            Ok(_) => "unresolved",
                            Err(change_monitor::ChangeMonitorError::LedgerPoisoned) => {
                                return Err(GovernedProcessEffectPortError::LedgerPoisoned);
                            }
                            Err(_) => "unobserved",
                        },
                        None => "unobserved",
                    };
                    observe_process("kernel.process.effect_readback_failed", outcome);
                }
            }
        }
        Ok(GovernedProcessChangeReceipt {
            targets,
            terminal_fence: terminal_evidence.binding().state_fence().clone(),
        })
    }

    fn ingest(
        &self,
        baseline: GovernedProcessEffectBaseline,
        receipt: GovernedProcessChangeReceipt,
    ) -> Result<(), GovernedProcessEffectPortError> {
        if !baseline.observed() || !receipt.observed() {
            observe_process("kernel.process.effect_observed", "unobserved");
            return Ok(());
        }
        let operation = baseline.binding.operation_id().as_str().to_owned();
        let mut admitted_any = false;
        for base in &baseline.targets {
            let Some(back) = receipt
                .targets
                .iter()
                .find(|target| target.path == base.path)
            else {
                // The declared target failed readback: it proves nothing
                // for this operation and ingests nothing.
                observe_process("kernel.process.effect_observed", "unobserved");
                continue;
            };
            let target_digest = base.target_digest.as_str();
            let (hint_id, skip_target) = Self::admit_host_event_hint(
                &operation,
                target_digest,
                &base.resource,
                &base.lane_path,
                baseline.binding.owner.module_id(),
                &base.before_digest,
            )?;
            if skip_target {
                continue;
            }
            admitted_any = true;
            let recorded_transition =
                record_proven_target_transition(&operation, base, back, &baseline, &receipt);
            // I10.21 AUD5: a proven terminal absence confirms as an
            // immutable `Absent` observation, never as invented bytes. A
            // mixed present/absent pair cannot have come from agreeing
            // readback and is refused below as `UnstableReadback`, which
            // keeps the hint pending and the resource blocked.
            let to_read = |digest: &Option<String>| match digest {
                Some(sha256) => change_monitor::ContentRead::Present {
                    sha256: sha256.clone(),
                },
                None => change_monitor::ContentRead::Absent,
            };
            let verification = change_monitor::HintVerification {
                before_digest: Some(base.before_digest.clone()),
                first_read: to_read(&back.after_first_digest),
                reread: to_read(&back.after_reread_digest),
                git: None,
            };
            match change_monitor::confirm_hint(&hint_id, &verification) {
                Ok(change_monitor::HintConfirmation::VerifiedImmaterial) => {
                    admitted_any = true;
                    observe_process("kernel.process.effect_observed", "immaterial");
                }
                Ok(change_monitor::HintConfirmation::MaterialRecorded {
                    change_id: unknown_id,
                    reconciled,
                }) => {
                    // I10.21 A2: reconcile explicitly against the exact recorded
                    // transition, and only when the ledger accepted the governed
                    // record. A refused record reconciles nothing: the
                    // unknown-origin change stays unreconciled and keeps
                    // blocking governed acceptance until reconciled.
                    let mut outcome = if reconciled { "reconciled" } else { "material" };
                    if !reconciled
                        && let Some(transition) = recorded_transition.as_deref()
                        && change_monitor::reconcile_unknown_change(&unknown_id, transition).is_ok()
                    {
                        outcome = "reconciled";
                    }
                    // I10.21 AUD4: the retained map advances only past a
                    // ledger-recorded transition, never past unadmitted
                    // evidence. A ledger-recorded deletion retires the
                    // retained digest instead (I10.21 AUD5): the next
                    // capture falls back to the ledger tip (proved absent)
                    // instead of comparing fresh reads against bytes the
                    // ledger proved gone.
                    if let Ok(mut last) = self.last_observed.lock() {
                        match &back.after_first_digest {
                            Some(digest) => {
                                last.insert(base.resource.clone(), digest.clone());
                            }
                            None => {
                                last.remove(base.resource.as_str());
                            }
                        }
                    }
                    admitted_any = true;
                    observe_process("kernel.process.effect_observed", outcome);
                }
                Err(change_monitor::ChangeMonitorError::LedgerPoisoned) => {
                    return Err(GovernedProcessEffectPortError::LedgerPoisoned);
                }
                Err(change_monitor::ChangeMonitorError::UnstableReadback) => {
                    observe_process("kernel.process.effect_observed", "unstable");
                }
                Err(_) => {
                    observe_process("kernel.process.effect_observed", "unobserved");
                }
            }
        }
        // I10.21 durability (AUD3): ingest-time ledger mutations (hint
        // admissions, governed records, confirmations) are observations in
        // their own right: persist them best-effort so a crash before the
        // next mutation still retains them. The observation stands
        // regardless; only durability is best-effort, and it stays visible
        // instead of silent.
        if admitted_any && change_monitor::persist_ledger_sidecar().is_err() {
            observe_process("kernel.process.effect_observed", "persist_failed");
        }
        Ok(())
    }
}

struct OrsProcessEvidenceSink {
    store: Arc<RedbRecoveryStore>,
    owner: ProcessOwnerBinding,
}

impl ProcessEvidenceSink for OrsProcessEvidenceSink {
    /// Records the byte-free ORS observation of one physical result.
    ///
    /// Issue #269, A1: the accepted `ProcessEvidence` is read at this boundary
    /// to take the digest over the ORIGINAL observed bytes, and the bounded
    /// inline preview bytes are then dropped with the borrowed value. They never
    /// reach ORS, so an execution with no stdout/stderr still records its
    /// observation, and an execution with streams records their identity,
    /// locator, exact digests and typed state without their payload.
    fn record(&self, evidence: ProcessEvidence) -> Result<(), eliot_process::EvidenceSinkError> {
        let observed_at_ms = i64::try_from(super::unix_ms()).unwrap_or(i64::MAX);
        let record =
            ProcessEvidenceRecord::from_evidence(&evidence, self.owner.clone(), observed_at_ms)
                .map_err(|error| eliot_process::EvidenceSinkError {
                    message: error.to_string(),
                })?;
        self.store
            .persist_process_evidence(&record)
            .map_err(|error| eliot_process::EvidenceSinkError {
                message: error.to_string(),
            })
    }
}

/// Production sink that retains immutable process-stream recovery evidence
/// (issue #269) on the same live executor handoff as
/// [`OrsProcessEvidenceSink`].
///
/// For every observed physical stream it derives one ORS recovery projection
/// from the evidence and writes it through the existing ORS owner and codec
/// (`RedbRecoveryStore::put_process_stream_recovery`). It adds no second table
/// owner, no second codec and no second write path, and it carries no stream
/// bytes: only the immutable locator identity, the exact durable coverage, the
/// typed transport/persistence state, the exact gap set and the reconciliation
/// owner cross into ORS. The untouched evidence is then handed to the sibling
/// sink, so the process-evidence record remains the one canonical observation of
/// the same physical result.
struct OrsProcessStreamRecoverySink {
    store: Arc<RedbRecoveryStore>,
    owner: ProcessOwnerBinding,
    evidence: Arc<OrsProcessEvidenceSink>,
}

impl ProcessEvidenceSink for OrsProcessStreamRecoverySink {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), eliot_process::EvidenceSinkError> {
        let observed_at_ms = i64::try_from(super::unix_ms()).unwrap_or(i64::MAX);
        for stream in [evidence.stdout(), evidence.stderr()].into_iter().flatten() {
            let binding =
                process_stream_recovery_binding(&evidence, &self.owner, stream, observed_at_ms)
                    .map_err(|error| stream_recovery_sink_error(&error))?;
            let projection = ProcessStreamRecoveryProjection::from_stream_evidence(stream, binding)
                .map_err(|error| stream_recovery_sink_error(&error))?;
            self.store
                .put_process_stream_recovery(&projection)
                .map_err(|error| stream_recovery_sink_error(&error))?;
        }
        self.evidence.record(evidence)
    }
}

/// Binds one observed physical stream to its ORS recovery-projection identity.
///
/// Every field is derived from the observation the executor just produced and
/// from the admitted owner; nothing is synthesized. The provider state-fence
/// digest and the writer-epoch exact tuple come from the admitted execution
/// binding, so the ORS projection's own cross-field lineage check holds without
/// a scalar-to-authority coercion. The governing policy revision is the digest
/// over the exact policy/privacy/visibility/retention/redaction identity set
/// that the retained projection itself carries, and the reconciliation owner is
/// the authenticated module that owns the operation. A stream that cannot be
/// bound fails the sink instead of writing a weakened projection.
fn process_stream_recovery_binding(
    evidence: &ProcessEvidence,
    owner: &ProcessOwnerBinding,
    stream: &ProcessStreamEvidence,
    observed_at_ms: i64,
) -> Result<ProcessStreamRecoveryBinding, eliot_ors::OrsError> {
    let binding = evidence.binding();
    let state_fence_bytes = serde_json::to_vec(binding.state_fence())
        .map_err(|error| eliot_ors::OrsError::Encoding(error.to_string()))?;
    let policy_bytes = serde_json::to_vec(stream.policy())
        .map_err(|error| eliot_ors::OrsError::Encoding(error.to_string()))?;
    let authority_epoch = binding.authority_epoch();
    Ok(ProcessStreamRecoveryBinding {
        state_fence_digest: super::sha256_hex(&state_fence_bytes),
        writer_epoch: EpochLineage {
            current: EpochIdentity {
                lineage_id: OpaqueLabel::new(authority_epoch.lineage_id.as_str())?,
                epoch: authority_epoch.sequence.get(),
            },
            predecessor: None,
        },
        policy_revision: super::sha256_hex(&policy_bytes),
        reconciliation_owner: RecoveryOwner::new(owner.module_id())?,
        observed_at_ms,
    })
}

/// Maps one ORS failure onto the bounded sink error the executor already
/// surfaces. Only the ORS error text crosses; it becomes a failed start, never
/// a success claim.
fn stream_recovery_sink_error(error: &eliot_ors::OrsError) -> eliot_process::EvidenceSinkError {
    eliot_process::EvidenceSinkError {
        message: error.to_string(),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedDispatchSnapshot {
    authority_id: DispatchAuthorityId,
    binding: AuthoritySnapshotBindingWire,
    snapshot: KernelAuthorityReplaySnapshot,
}

pub struct WindowsDispatchSnapshotCodec {
    platform: Arc<WindowsPlatform>,
    key_reference: eliot_platform::SecretReference,
}

impl WindowsDispatchSnapshotCodec {
    pub fn new(
        platform: Arc<WindowsPlatform>,
        key_reference: eliot_platform::SecretReference,
    ) -> Self {
        Self {
            platform,
            key_reference,
        }
    }
}

impl DispatchSnapshotCodec for WindowsDispatchSnapshotCodec {
    fn seal(
        &self,
        snapshot: &KernelAuthorityReplaySnapshot,
        binding: &AuthoritySnapshotBinding,
    ) -> Result<eliot_kernel_core::SealedAuthoritySnapshot, eliot_kernel_core::KernelError> {
        let envelope = ProtectedDispatchSnapshot {
            authority_id: binding.authority_id().clone(),
            binding: binding.to_wire(),
            snapshot: snapshot.clone(),
        };
        let plaintext = serde_json::to_vec(&envelope).map_err(|error| {
            eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
        })?;
        let ciphertext = self.platform.protect_secret(&plaintext).map_err(|error| {
            eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
        })?;
        eliot_kernel_core::SealedAuthoritySnapshot::new(
            self.key_reference.clone(),
            ciphertext.as_bytes().to_vec(),
        )
    }

    fn open(
        &self,
        payload: &eliot_ors::RecoveryPayload,
        binding: &AuthoritySnapshotBinding,
    ) -> Result<KernelAuthorityReplaySnapshot, eliot_kernel_core::KernelError> {
        let eliot_ors::RecoveryPayload::Encrypted { key, ciphertext } = payload else {
            return Err(eliot_kernel_core::KernelError::RecoveryUnavailable(
                "authority snapshot is not encrypted".to_owned(),
            ));
        };
        if key != &self.key_reference {
            return Err(eliot_kernel_core::KernelError::RecoveryUnavailable(
                "authority snapshot credential reference mismatch".to_owned(),
            ));
        }
        let protected = ProtectedSecret::from_ciphertext(ciphertext.clone()).map_err(|error| {
            eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
        })?;
        let plaintext = self
            .platform
            .unprotect_secret(&protected)
            .map_err(|error| {
                eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
            })?;
        let envelope: ProtectedDispatchSnapshot = serde_json::from_slice(plaintext.expose())
            .map_err(|error| {
                eliot_kernel_core::KernelError::RecoveryUnavailable(error.to_string())
            })?;
        AuthoritySnapshotBinding::from_wire_exact(envelope.binding, binding)?;
        if envelope.authority_id != *binding.authority_id() {
            return Err(eliot_kernel_core::KernelError::FenceMismatch);
        }
        envelope.snapshot.validate()?;
        Ok(envelope.snapshot)
    }
}

impl ProcessExecutionReplayStore for OrsProcessReplayStore {
    fn load_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
    ) -> Result<Option<ProcessExecutionReplayRecord>, eliot_kernel_core::KernelError> {
        self.store
            .load_process_start(
                &eliot_ors::OperationIdentity::new(operation_id.as_str()).map_err(|e| {
                    eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string())
                })?,
            )
            .map_err(|e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()))?
            .map(|record| {
                Ok(ProcessExecutionReplayRecord {
                    admission_digest: record.admission_digest,
                    owner: record.owner,
                    state: match record.state {
                        OrsReplayState::Reserved => ProcessExecutionReplayState::Reserved,
                        OrsReplayState::Completed => ProcessExecutionReplayState::Completed,
                        OrsReplayState::Unknown => ProcessExecutionReplayState::Unknown,
                    },
                    receipt: record.receipt,
                })
            })
            .transpose()
    }

    fn begin_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
        admission_digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayBegin, eliot_kernel_core::KernelError> {
        let record = OrsReplayRecord {
            operation_id: eliot_ors::OperationIdentity::new(operation_id.as_str()).map_err(
                |e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()),
            )?,
            admission_digest: admission_digest.to_owned(),
            owner: owner.clone(),
            state: OrsReplayState::Reserved,
            receipt: None,
        };
        self.store
            .begin_process_start(&record)
            .map_err(|e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()))
            .map(|existing| {
                existing.map_or(ProcessExecutionReplayBegin::Acquired, |record| {
                    ProcessExecutionReplayBegin::Existing(ProcessExecutionReplayRecord {
                        admission_digest: record.admission_digest,
                        owner: record.owner,
                        state: match record.state {
                            OrsReplayState::Reserved => ProcessExecutionReplayState::Reserved,
                            OrsReplayState::Completed => ProcessExecutionReplayState::Completed,
                            OrsReplayState::Unknown => ProcessExecutionReplayState::Unknown,
                        },
                        receipt: record.receipt,
                    })
                })
            })
    }

    fn persist_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
        record: ProcessExecutionReplayRecord,
    ) -> Result<(), eliot_kernel_core::KernelError> {
        self.store
            .persist_process_start(&OrsReplayRecord {
                operation_id: eliot_ors::OperationIdentity::new(operation_id.as_str()).map_err(
                    |e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()),
                )?,
                admission_digest: record.admission_digest,
                owner: record.owner,
                state: match record.state {
                    ProcessExecutionReplayState::Reserved => OrsReplayState::Reserved,
                    ProcessExecutionReplayState::Completed => OrsReplayState::Completed,
                    ProcessExecutionReplayState::Unknown => OrsReplayState::Unknown,
                },
                receipt: record.receipt,
            })
            .map_err(|e| eliot_kernel_core::KernelError::DependencyUnavailable(e.to_string()))
    }
}

impl ProcessExecutionReplayStoreWithAbort for OrsProcessReplayStore {
    fn abort_process_start(
        &self,
        operation_id: &eliot_process::OperationId,
        admission_digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayAbort, eliot_kernel_core::KernelError> {
        self.store
            .abort_process_start(
                &eliot_ors::OperationIdentity::new(operation_id.as_str()).map_err(|error| {
                    eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
                })?,
                admission_digest,
                owner,
            )
            .map(|result| match result {
                eliot_ors::ProcessStartReplayAbort::Released => {
                    ProcessExecutionReplayAbort::Released
                }
                eliot_ors::ProcessStartReplayAbort::NotReleased => {
                    ProcessExecutionReplayAbort::NotReleased
                }
            })
            .map_err(|error| {
                eliot_kernel_core::KernelError::DependencyUnavailable(error.to_string())
            })
    }
}

pub(crate) const RESERVED_STORE_SNAPSHOT_HEAD: &str = "__eliot_store_snapshot__";
pub(crate) const STORE_IDENTITY_BINDING: &str = "eliot.storage.store-api";

#[derive(Serialize)]
struct CanonicalStoreRevision<'a> {
    key: &'a str,
    revision: u64,
    state_fence: &'a StoreStateFence,
}

#[derive(Serialize)]
struct CanonicalStoreSnapshot<'a> {
    store_identity: &'static str,
    state_fence: &'a StoreStateFence,
    revision_heads: Vec<CanonicalStoreRevision<'a>>,
    validation_revision: u64,
}

pub(crate) fn project_store_snapshot(
    snapshot: &CanonicalValidationSnapshot,
) -> Result<(FencingToken, BTreeMap<String, String>), ProcessExecutionError> {
    snapshot
        .validate()
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
    let mut ordered_heads: Vec<&RevisionHead> = snapshot.revision_heads.iter().collect();
    ordered_heads.sort_by(|left, right| left.key.cmp(&right.key));
    if ordered_heads
        .iter()
        .any(|head| head.key.as_str() == RESERVED_STORE_SNAPSHOT_HEAD)
    {
        return Err(ProcessExecutionError::Unavailable(
            "Store revision key collides with reserved snapshot binding".to_owned(),
        ));
    }
    let mut projected = BTreeMap::new();
    let mut canonical_heads = Vec::with_capacity(ordered_heads.len());
    for head in ordered_heads {
        let binding = CanonicalStoreRevision {
            key: head.key.as_str(),
            revision: head.revision,
            state_fence: &snapshot.state_fence,
        };
        let digest = super::sha256_hex(
            &canonical_json_bytes(&binding)
                .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?,
        );
        projected.insert(head.key.to_string(), digest);
        canonical_heads.push(binding);
    }
    let snapshot_binding = CanonicalStoreSnapshot {
        store_identity: STORE_IDENTITY_BINDING,
        state_fence: &snapshot.state_fence,
        revision_heads: canonical_heads,
        validation_revision: snapshot.validation_revision,
    };
    let snapshot_digest = super::sha256_hex(
        &canonical_json_bytes(&snapshot_binding)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?,
    );
    projected.insert(
        RESERVED_STORE_SNAPSHOT_HEAD.to_owned(),
        snapshot_digest.clone(),
    );
    let fence = FencingToken::new(
        // INTENDED EpochId shape (B→A→C): snapshot fence carries EpochId after B.
        snapshot.state_fence.authority_epoch.clone(),
        Generation::new(snapshot.state_fence.resource_generation.value())
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?,
        format!("store-snapshot-{snapshot_digest}"),
    )
    .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
    Ok((fence, projected))
}

pub(crate) struct ValidationContextSlot {
    contexts: Mutex<BTreeMap<eliot_process::OperationId, (u64, DispatchValidationContext)>>,
    next_owner: AtomicU64,
}

pub(crate) struct ValidationContextGuard {
    slot: Arc<ValidationContextSlot>,
    operation_id: eliot_process::OperationId,
    owner: u64,
    active: bool,
}

impl Drop for ValidationContextGuard {
    fn drop(&mut self) {
        if self.active {
            self.slot.remove_owned(&self.operation_id, self.owner);
        }
    }
}

impl ValidationContextSlot {
    pub(crate) fn new() -> Self {
        Self {
            contexts: Mutex::new(BTreeMap::new()),
            next_owner: AtomicU64::new(1),
        }
    }

    pub(crate) fn insert(
        self: &Arc<Self>,
        operation_id: eliot_process::OperationId,
        context: DispatchValidationContext,
    ) -> Result<ValidationContextGuard, ProcessExecutionError> {
        let mut contexts = self.contexts.lock().map_err(|_| {
            ProcessExecutionError::Unavailable("validation context lock poisoned".to_owned())
        })?;
        let owner = self.next_owner.fetch_add(1, Ordering::Relaxed);
        match contexts.entry(operation_id.clone()) {
            Entry::Vacant(entry) => {
                entry.insert((owner, context));
                Ok(ValidationContextGuard {
                    slot: Arc::clone(self),
                    operation_id,
                    owner,
                    active: true,
                })
            }
            Entry::Occupied(_) => Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            )),
        }
    }

    pub(crate) fn take(
        &self,
        operation_id: &eliot_process::OperationId,
    ) -> Result<DispatchValidationContext, ProcessExecutionError> {
        self.contexts
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("validation context lock poisoned".to_owned())
            })?
            .remove(operation_id)
            .map(|(_, context)| context)
            .ok_or(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ))
    }

    fn remove_owned(&self, operation_id: &eliot_process::OperationId, owner: u64) {
        if let Ok(mut contexts) = self.contexts.lock()
            && contexts
                .get(operation_id)
                .is_some_and(|(current_owner, _)| *current_owner == owner)
        {
            contexts.remove(operation_id);
        }
    }
}

pub(crate) struct ControllerDispatchPort {
    pub(crate) controller: Arc<Mutex<ProcessDispatchAuthorityController>>,
    pub(crate) binding: AuthoritySnapshotBinding,
    pub(crate) validation_contexts: Arc<ValidationContextSlot>,
}

impl DispatchValidationPort for ControllerDispatchPort {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self.validation_contexts.take(request.operation_id())?;
        self.controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current, &self.binding)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }
}

pub(crate) struct ProcessExecutionGateway {
    pub(crate) controller: Arc<Mutex<ProcessDispatchAuthorityController>>,
    pub(crate) executor: WindowsProcessExecutor,
    pub(crate) replay_store: Arc<dyn ProcessExecutionReplayStoreWithAbort>,
    pub(crate) evidence_store: Arc<RedbRecoveryStore>,
    pub(crate) snapshot_binding: AuthoritySnapshotBinding,
    pub(crate) validation_contexts: Arc<ValidationContextSlot>,
    #[cfg(windows)]
    pub(crate) canonical_store: Arc<Mutex<Option<Arc<KernelStoreGateway>>>>,
    pub(crate) path_admission: Arc<KernelPathAdmission>,
    /// Launched-but-not-closed descendants (CHILD-1/CHILD-2).
    pub(crate) descendants: Arc<Mutex<DescendantRegistry>>,
    /// Governor-owned `ChangeMonitor` ingress for governed tool effects (#1824,
    /// I10.21). Attached at construction to the Kernel-owned readback
    /// adapter below, so process execution is observed with real
    /// open/checksum/re-read evidence; `None` only ever means the gateway
    /// was built without the adapter, in which case execution runs
    /// unobserved rather than inventing source evidence.
    effect_port: Mutex<Option<Arc<dyn GovernedProcessEffectPort>>>,
    /// Pre-effect tracked-source baselines retained between `start` capture
    /// and `reconcile` readback, keyed by exact operation identity.
    effect_baselines: Mutex<BTreeMap<OperationId, GovernedProcessEffectBaseline>>,
}

#[cfg(windows)]
pub(crate) struct CanonicalStoreAttachment<'a> {
    pub(crate) gateway: Arc<KernelStoreGateway>,
    pub(crate) process_gateway: &'a ProcessExecutionGateway,
    pub(crate) active: bool,
}

#[cfg(windows)]
pub(crate) trait CanonicalStoreAttachmentTransaction: Send {
    fn commit(self: Box<Self>);
}

#[cfg(windows)]
impl CanonicalStoreAttachment<'_> {
    pub(crate) fn commit(mut self) {
        self.active = false;
    }
}

#[cfg(windows)]
impl CanonicalStoreAttachmentTransaction for CanonicalStoreAttachment<'_> {
    fn commit(self: Box<Self>) {
        (*self).commit();
    }
}

#[cfg(windows)]
impl Drop for CanonicalStoreAttachment<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut retained) = self.process_gateway.canonical_store.lock()
            && retained
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.gateway))
        {
            *retained = None;
        }
        self.gateway.fence();
    }
}

#[cfg(windows)]
pub(crate) struct CanonicalStoreReplace<'a> {
    pub(crate) gateway: Arc<KernelStoreGateway>,
    pub(crate) process_gateway: &'a ProcessExecutionGateway,
    pub(crate) old: Option<Arc<KernelStoreGateway>>,
    pub(crate) active: bool,
}

#[cfg(windows)]
impl CanonicalStoreReplace<'_> {
    pub(crate) fn commit(mut self) {
        self.active = false;
    }
}

#[cfg(windows)]
impl CanonicalStoreAttachmentTransaction for CanonicalStoreReplace<'_> {
    fn commit(self: Box<Self>) {
        (*self).commit();
    }
}

#[cfg(windows)]
impl Drop for CanonicalStoreReplace<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        if let Ok(mut retained) = self.process_gateway.canonical_store.lock()
            && retained
                .as_ref()
                .is_some_and(|current| Arc::ptr_eq(current, &self.gateway))
        {
            retained.clone_from(&self.old);
        }
        self.gateway.fence();
    }
}

pub(crate) trait ProcessStartGuard: Send {}

impl<T: Send> ProcessStartGuard for T {}

#[allow(async_fn_in_trait)]
pub(crate) trait ProcessStartPorts {
    type PathProof;
    type Request;
    type Receipt: Clone + Send + 'static;

    fn validate_admission(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        owner: &ProcessOwnerBinding,
    ) -> Result<(), ProcessExecutionError>;
    fn now(&self) -> u64;

    fn validate_path(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        path_proof: &Self::PathProof,
    ) -> Result<(), ProcessExecutionError>;
    fn begin(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayBegin, ProcessExecutionError>;
    /// Authorizes one REPLAY of an already-reserved operation on its exact
    /// unexpired effect operation lease (issue #1885; I1.9, W2/W5).
    ///
    /// Called only from the `Existing(replay)` arm, never from the `Acquired`
    /// arm: a first process start is a new operation authorized by admission,
    /// while a replay of an effect-capable operation may resume only under the
    /// unexpired lease that already authorized its effect. The owner binding
    /// supplies the authenticated module identity, generation and live
    /// Authority Epoch; the effect receipt, route scope, manifest digest and
    /// admitting Catalog/Policy revisions are read from the durable ORS rows,
    /// and a denial is persisted as a durable reconciliation intent before this
    /// returns, so a refused replay is never discarded.
    fn require_effect_replay_authority(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: &eliot_process::OperationId,
    ) -> Result<(), ProcessExecutionError>;
    async fn completed_receipt(
        &self,
        record: ProcessExecutionReplayRecord,
    ) -> Result<Option<Self::Receipt>, ProcessExecutionError>;
    async fn snapshot(&self) -> Result<CanonicalValidationSnapshot, ProcessExecutionError>;
    fn build_context(
        &self,
        clock: ClockObservation,
        store_fence: FencingToken,
        // INTENDED EpochId shape (Split A): DispatchValidationContext::new
        // takes EpochId. B→A→C order.
        authority_epoch: eliot_contracts::EpochId,
        revision_heads: BTreeMap<String, String>,
        validation_revision: u64,
    ) -> Result<DispatchValidationContext, ProcessExecutionError>;
    fn insert_context(
        &self,
        operation_id: eliot_process::OperationId,
        context: DispatchValidationContext,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError>;
    fn issue(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        store_fence: FencingToken,
        revision_heads: BTreeMap<String, String>,
        now: u64,
        validation_revision: u64,
    ) -> Result<Self::Request, ProcessExecutionError>;
    fn insert_path(
        &self,
        operation_id: eliot_process::OperationId,
        path_proof: Self::PathProof,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError>;
    async fn execute(
        &self,
        owner: &ProcessOwnerBinding,
        request: Self::Request,
        outer_binding: Option<&HostKernelCandidateBinding>,
    ) -> Result<Self::Receipt, ProcessExecutionError>;
    fn persist_completed(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
        receipt: Self::Receipt,
    ) -> Result<(), ProcessExecutionError>;
    fn mark_unknown(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    );
    fn abort(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayAbort, ProcessExecutionError>;
}

pub(crate) struct ProcessStartReservation<'a, P: ProcessStartPorts + ?Sized> {
    pub(crate) ports: &'a P,
    pub(crate) operation_id: eliot_process::OperationId,
    pub(crate) admission_digest: String,
    pub(crate) owner: ProcessOwnerBinding,
    pub(crate) active: bool,
}

impl<P: ProcessStartPorts + ?Sized> ProcessStartReservation<'_, P> {
    pub(crate) fn release(&mut self) -> Result<(), ProcessExecutionError> {
        if !self.active {
            return Ok(());
        }
        let result = self
            .ports
            .abort(&self.operation_id, &self.admission_digest, &self.owner)?;
        self.active = false;
        match result {
            ProcessExecutionReplayAbort::Released => Ok(()),
            ProcessExecutionReplayAbort::NotReleased => Err(ProcessExecutionError::UnknownOutcome),
        }
    }

    pub(crate) fn disarm(&mut self) {
        self.active = false;
    }
}

impl<P: ProcessStartPorts + ?Sized> Drop for ProcessStartReservation<'_, P> {
    fn drop(&mut self) {
        if self.active {
            let _ = self
                .ports
                .abort(&self.operation_id, &self.admission_digest, &self.owner);
        }
    }
}

#[derive(Debug)]
pub(crate) struct ProcessPathProof {
    pub(crate) executable: PathBuf,
    pub(crate) working_directory: PathBuf,
    pub(crate) lease: Arc<RetainedProcessPathLease>,
}

pub(crate) struct KernelPathAdmission {
    proofs: Mutex<BTreeMap<eliot_process::OperationId, ProcessPathProof>>,
}

pub(crate) struct PathAdmissionGuard {
    admission: Arc<KernelPathAdmission>,
    operation_id: eliot_process::OperationId,
}

impl Drop for PathAdmissionGuard {
    fn drop(&mut self) {
        self.admission.remove(&self.operation_id);
    }
}

impl KernelPathAdmission {
    pub(crate) fn new(_platform: Arc<WindowsPlatform>) -> Self {
        Self {
            proofs: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn insert(
        &self,
        operation_id: eliot_process::OperationId,
        proof: ProcessPathProof,
    ) -> Result<(), ProcessExecutionError> {
        let mut proofs = self.proofs.lock().map_err(|_| {
            ProcessExecutionError::Unavailable("path admission lock poisoned".to_owned())
        })?;
        match proofs.entry(operation_id) {
            Entry::Vacant(entry) => {
                entry.insert(proof);
                Ok(())
            }
            Entry::Occupied(_) => Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            )),
        }
    }

    fn remove(&self, operation_id: &eliot_process::OperationId) {
        if let Ok(mut proofs) = self.proofs.lock() {
            proofs.remove(operation_id);
        }
    }
}

impl ProcessLaunchAdmission for KernelPathAdmission {
    fn validate_launch(
        &self,
        request: &ProcessRequest,
        observed: &SuspendedProcessIdentity,
        launch: &SuspendedLaunchEvidence,
    ) -> Result<(), eliot_process::ContractError> {
        let proofs =
            self.proofs
                .lock()
                .map_err(|_| eliot_process::ContractError::InvalidValue {
                    field: "path_admission",
                    reason: "proof lock poisoned",
                })?;
        let proof = proofs
            .get(request.operation_id())
            .ok_or(eliot_process::ContractError::DispatchBindingMismatch)?;
        if proof.executable.to_string_lossy() != request.executable()
            || proof.working_directory.to_string_lossy() != request.working_directory()
            || observed.executable_sha256() != request.executable_sha256()
            || launch.requested_executable() != request.executable()
            || launch.executable_volume_serial_number()
                != proof.lease.executable_identity().volume_serial_number
            || launch.executable_file_index() != proof.lease.executable_identity().file_index
        {
            return Err(eliot_process::ContractError::DispatchBindingMismatch);
        }
        proof
            .lease
            .validate(
                Path::new(request.executable()),
                Path::new(request.working_directory()),
                request.executable_sha256(),
            )
            .map_err(|_| eliot_process::ContractError::DispatchBindingMismatch)
    }
}

impl ProcessExecutionGateway {
    pub(crate) fn new(
        controller: Arc<Mutex<ProcessDispatchAuthorityController>>,
        ors: Arc<RedbRecoveryStore>,
        snapshot_binding: AuthoritySnapshotBinding,
        path_admission: Arc<KernelPathAdmission>,
    ) -> Self {
        let validation_contexts = Arc::new(ValidationContextSlot::new());
        let replay_store = Arc::new(OrsProcessReplayStore {
            store: Arc::clone(&ors),
        });
        let port = Arc::new(ControllerDispatchPort {
            controller: Arc::clone(&controller),
            binding: snapshot_binding.clone(),
            validation_contexts: Arc::clone(&validation_contexts),
        });
        let launch_admission: Arc<dyn ProcessLaunchAdmission> = path_admission.clone();
        let effect_port: Arc<dyn GovernedProcessEffectPort> =
            Arc::new(KernelGovernedProcessEffectPort::new());
        Self {
            controller,
            executor: WindowsProcessExecutor::new_with_launch_admission(port, launch_admission),
            replay_store,
            evidence_store: ors,
            snapshot_binding,
            validation_contexts,
            #[cfg(windows)]
            canonical_store: Arc::new(Mutex::new(None)),
            path_admission,
            descendants: Arc::new(Mutex::new(DescendantRegistry::new())),
            effect_port: Mutex::new(Some(effect_port)),
            effect_baselines: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn readiness_configuration_valid(&self) -> bool {
        let binding = self.snapshot_binding.to_wire();
        binding.validate().is_ok()
            && self
                .controller
                .lock()
                .is_ok_and(|controller| controller.authority_id() == &binding.authority_id)
    }

    pub(crate) fn issue_origin_challenge(
        &self,
        request: &OriginChallengeRequest,
        expires_at_unix_ms: u64,
    ) -> Result<OriginChallenge, ProcessExecutionError> {
        let issued_at_unix_ms = super::unix_ms();
        if expires_at_unix_ms <= issued_at_unix_ms {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::ExpiredDispatchPermit,
            ));
        }
        // The installation in the request is caller packaging until it is
        // proven against the Kernel-retained composition identity here, so
        // a foreign installation fails before any challenge is minted.
        if request.installation_id() != Self::live_origin_installation_id()? {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::IdentityMismatch,
            ));
        }
        self.controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .issue_origin_challenge(
                request,
                issued_at_unix_ms,
                expires_at_unix_ms,
                &self.snapshot_binding,
            )
            .map_err(Self::origin_contract_error)
    }

    pub(crate) fn decide_origin_control(
        &self,
        presentation: &OriginControlPresentation,
    ) -> Result<OriginControlGrant, ProcessExecutionError> {
        // Same anchor as issuance: the decided installation must still be
        // the Kernel-retained one, not merely the value the caller packaged.
        if presentation.request().installation_id() != Self::live_origin_installation_id()? {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::IdentityMismatch,
            ));
        }
        self.controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .decide_origin_control(presentation, super::unix_ms(), &self.snapshot_binding)
            .map_err(Self::origin_contract_error)
    }

    /// Reads the Kernel-retained installation identity for origin control.
    ///
    /// The anchor is the existing set-once dispatch contour cell
    /// `compose_dispatch_contour` fills from the authenticated Host startup
    /// binding — the same identity `require_setup_admission` and the restore
    /// journal already compare against — never a request, config, or fixture
    /// value. An uncomposed Kernel has no installation identity at all and
    /// refuses; it is never defaulted to a placeholder.
    fn live_origin_installation_id() -> Result<&'static str, ProcessExecutionError> {
        let installation = super::dispatch_contour().map_or(
            "",
            super::dispatch_launch::ComposedDispatchContour::installation_id,
        );
        if installation.trim().is_empty() {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::IdentityMismatch,
            ));
        }
        Ok(installation)
    }

    /// Preserves typed P-03 contract failures across the controller seam.
    ///
    /// The authority journal speaks in matchable `ContractError`s — consumed
    /// vs. unknown nonces, binding mismatches, unproven effects — and this
    /// boundary must keep them matchable instead of flattening them into
    /// `Unavailable` strings. Only non-contract Kernel failures (fenced
    /// authority, persistence loss, lock poisoning) stay `Unavailable`.
    fn origin_contract_error(error: eliot_kernel_core::KernelError) -> ProcessExecutionError {
        match error {
            eliot_kernel_core::KernelError::ProcessContract(contract) => {
                ProcessExecutionError::Contract(contract)
            }
            error => ProcessExecutionError::Unavailable(error.to_string()),
        }
    }

    /// Reads the durable one-shot effect outcome for a decided origin grant.
    ///
    /// The grant-funded kill boundary calls this with the grant's one-shot
    /// nonce before dispatching the effect, so a grant that already funded
    /// an observed effect is never executed twice.
    fn origin_grant_effect_state(
        &self,
        request_nonce: &str,
    ) -> Result<OriginGrantEffectOutcome, ProcessExecutionError> {
        self.controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .origin_grant_effect_state(request_nonce, &self.snapshot_binding)
            .map_err(Self::origin_contract_error)
    }

    /// Durably records the observed effect of a decided origin grant.
    ///
    /// Called with the exact kill receipt after the executor observes it. A
    /// failed record fails the call: a failed snapshot can never report a
    /// clean success.
    fn record_origin_grant_effect(
        &self,
        request_nonce: &str,
        receipt: &eliot_process::CancellationReceipt,
    ) -> Result<(), ProcessExecutionError> {
        self.controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .record_origin_grant_effect(request_nonce, receipt, &self.snapshot_binding)
            .map(|_| ())
            .map_err(Self::origin_contract_error)
    }

    /// Replays the preserved original kill receipt for a proven grant effect.
    ///
    /// Exact-result replay: the caller gets the original receipt the effect
    /// boundary observed, never a re-execution and never live evidence.
    fn origin_grant_effect_receipt(
        &self,
        request_nonce: &str,
    ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
        self.controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .origin_grant_effect_receipt(request_nonce, &self.snapshot_binding)
            .map_err(Self::origin_contract_error)
    }

    /// Reconciles one grant-funded effect after crash or lost response
    /// without duplicating it (issue #1775 A-crash).
    ///
    /// The reconciliation query path: the presented owner is authorized
    /// against the retained operation record first — a changed connection
    /// owner fails here before any journal read — then the original admitted
    /// target/operation for the consumed one-shot nonce is read through the
    /// durable authority journal. The presented operation must equal the
    /// operation the grant was decided for, the journaled installation must
    /// still be the live Kernel installation, and a grant decided for
    /// another operation class cannot reconcile this operation. An unproven
    /// (`Unknown`) effect returns reconciliation-required instead of
    /// re-executing or minting a fresh nonce; a separately admitted new
    /// proof for a proven remaining action goes through the normal decide
    /// path. A proven (`Effected`) effect replays the preserved original
    /// kill receipt for the original operation — never a re-execution and
    /// never live executor evidence.
    pub(crate) fn reconcile_origin_grant_effect(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: &eliot_process::OperationId,
        request_nonce: &str,
    ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
        observe_process("kernel.process.grant_reconcile_requested", "attempt");
        if let Err(error) = self.authorize_operation(owner, operation_id) {
            observe_process("kernel.process.grant_reconcile_rejected", "fenced");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
            return Err(error);
        }
        let source = self
            .controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .origin_grant_reconciliation_source(request_nonce, &self.snapshot_binding)
            .map_err(Self::origin_contract_error)?;
        if source.operation_id() != operation_id {
            observe_process("kernel.process.grant_reconcile_rejected", "fenced");
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        if source.installation_id() != Self::live_origin_installation_id()? {
            observe_process("kernel.process.grant_reconcile_rejected", "fenced");
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::IdentityMismatch,
            ));
        }
        if source.operation() != OriginControlOperation::Kill {
            observe_process("kernel.process.grant_reconcile_rejected", "fenced");
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        if source.effect_outcome() == OriginGrantEffectOutcome::Unknown {
            observe_process("kernel.process.grant_reconcile_unknown", "unknown");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(
                &ProcessExecutionError::UnknownOutcome,
            ));
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        let receipt = self.origin_grant_effect_receipt(request_nonce)?;
        observe_process("kernel.process.grant_reconcile_replayed", "success");
        Ok(receipt)
    }

    #[cfg(windows)]
    pub(crate) fn attach_canonical_store(
        &self,
        gateway: Arc<KernelStoreGateway>,
    ) -> Result<CanonicalStoreAttachment<'_>, super::KernelBuildError> {
        let mut retained = self.canonical_store.lock().map_err(|_| {
            super::KernelBuildError::Service("store gateway lock poisoned".to_owned())
        })?;
        if retained.is_some() {
            return Err(super::KernelBuildError::StoreAlreadyConnected);
        }
        *retained = Some(Arc::clone(&gateway));
        Ok(CanonicalStoreAttachment {
            gateway,
            process_gateway: self,
            active: true,
        })
    }

    #[cfg(windows)]
    pub(crate) fn replace_canonical_store(
        &self,
        gateway: Arc<KernelStoreGateway>,
    ) -> Result<CanonicalStoreReplace<'_>, super::KernelBuildError> {
        let mut retained = self.canonical_store.lock().map_err(|_| {
            super::KernelBuildError::Service("store gateway lock poisoned".to_owned())
        })?;
        let old = retained.clone();
        *retained = Some(Arc::clone(&gateway));
        Ok(CanonicalStoreReplace {
            gateway,
            process_gateway: self,
            old,
            active: true,
        })
    }

    #[cfg(windows)]
    pub(crate) async fn canonical_validation_snapshot(
        &self,
    ) -> Result<CanonicalValidationSnapshot, ProcessExecutionError> {
        let gateway = self
            .canonical_store
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("store gateway lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("canonical store is not connected".to_owned())
            })?;
        gateway
            .validation_snapshot()
            .await
            .map_err(ProcessExecutionError::Unavailable)
    }

    pub(crate) fn attach_path_proof(
        &self,
        operation_id: eliot_process::OperationId,
        path_proof: ProcessPathProof,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
        self.path_admission
            .insert(operation_id.clone(), path_proof)?;
        Ok(Box::new(PathAdmissionGuard {
            admission: Arc::clone(&self.path_admission),
            operation_id,
        }))
    }

    pub(crate) fn mark_unknown(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) {
        let _ = self.replay_store.persist_process_start(
            operation_id,
            ProcessExecutionReplayRecord {
                admission_digest: digest.to_owned(),
                owner: owner.clone(),
                state: ProcessExecutionReplayState::Unknown,
                receipt: None,
            },
        );
    }

    /// Maps one typed effect-port failure to its stable observation outcome.
    ///
    /// Only the variant is emitted; no receipt, handle, or owner string
    /// crosses into diagnostics.
    fn effect_port_outcome(error: GovernedProcessEffectPortError) -> &'static str {
        match error {
            GovernedProcessEffectPortError::LedgerPoisoned => "ledger_poisoned",
        }
    }

    /// Captures the pre-effect tracked-source baseline for one admitted
    /// governed operation (I10.21 A1: exact before revisions, attempt/tool
    /// operation binding; W2: host hint source).
    ///
    /// The readback runs against the retained path proof while its lease is
    /// live: the admitted executable/working directory the lease owns, the
    /// admission-pinned digest the intent validator checked, the
    /// admission-declared (argv) mutation set resolved under the working
    /// directory, and two independent opens per target that must agree.
    /// Anything less than that proof — a lease the port cannot verify, no
    /// readable declared target, or disagreeing reads — runs unobserved with
    /// no hint ingested, so a monitor gap can never wedge governed
    /// acceptance. A malformed binding fails the start with the same typed
    /// contract rejection the admission pipeline would produce.
    fn capture_governed_effect_baseline(
        &self,
        owner: &ProcessOwnerBinding,
        admission: &ProcessExecutionAdmissionRequest,
        path_proof: &ProcessPathProof,
    ) -> Result<(), ProcessExecutionError> {
        let port = self
            .effect_port
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("governed effect port lock poisoned".to_owned())
            })?
            .clone();
        let Some(port) = port else {
            return Ok(());
        };
        let binding = GovernedProcessEffectBinding::from_admission(owner, admission)?;
        let source = GovernedProcessEffectSource {
            executable: path_proof.executable.clone(),
            working_directory: path_proof.working_directory.clone(),
            expected_sha256: admission.intent().executable_sha256().to_owned(),
            effect_digest: admission.intent().effect_digest().to_owned(),
            lease: Arc::clone(&path_proof.lease),
            // I10.21 A1: the observed set is the admission-declared
            // mutation set (digest-pinned argv paths under the working
            // directory), never the tool image.
            declared_targets: declared_target_paths(
                admission.intent().argv(),
                &path_proof.working_directory,
            ),
        };
        match port.capture_before(&binding, &source) {
            Ok(baseline) => {
                if !baseline.observed() {
                    return Ok(());
                }
                self.effect_baselines
                    .lock()
                    .map_err(|_| {
                        ProcessExecutionError::Unavailable(
                            "governed effect baseline lock poisoned".to_owned(),
                        )
                    })?
                    .insert(binding.operation_id().clone(), baseline);
                Ok(())
            }
            Err(error) => {
                observe_process(
                    "kernel.process.effect_baseline_unavailable",
                    Self::effect_port_outcome(error),
                );
                Ok(())
            }
        }
    }

    /// Verifies the retained pre-effect baseline belongs to the exact request
    /// about to be handed to the executor (I10.21: evidence bound to this
    /// operation). A baseline captured for another operation refuses the
    /// handoff; a missing baseline (unobserved operation) proceeds.
    fn verify_governed_effect_request(
        &self,
        owner: &ProcessOwnerBinding,
        request: &ProcessRequest,
    ) -> Result<(), ProcessExecutionError> {
        let baselines = self.effect_baselines.lock().map_err(|_| {
            ProcessExecutionError::Unavailable("governed effect baseline lock poisoned".to_owned())
        })?;
        match baselines.get(request.operation_id()) {
            Some(baseline) if baseline.binding().matches_request(owner, request) => Ok(()),
            Some(_) => Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            )),
            None => Ok(()),
        }
    }

    /// Drops one retained pre-effect baseline without observation (unknown or
    /// failed start claims no governed effect).
    fn release_governed_effect_baseline(&self, operation_id: &eliot_process::OperationId) {
        if let Ok(mut baselines) = self.effect_baselines.lock() {
            baselines.remove(operation_id);
        }
    }

    /// Reads the terminal source state against the retained pre-effect
    /// baseline and ingests the validated receipt bound to that exact
    /// baseline (I10.21 A1: exact before/after revisions, diff handle,
    /// State-Fence invalidation; W2: content checksum/re-read confirmation).
    ///
    /// Monitor-path failures are observed and never fail the reconcile: the
    /// reported terminal evidence stays the owner's. Terminal evidence for
    /// a different operation is likewise observed and skipped, never
    /// compared against this baseline.
    fn ingest_governed_effect_observation(
        &self,
        operation_id: &eliot_process::OperationId,
        evidence: &ProcessEvidence,
    ) {
        let baseline = match self.effect_baselines.lock() {
            Ok(mut baselines) => baselines.remove(operation_id),
            Err(_) => return,
        };
        let Some(baseline) = baseline else {
            return;
        };
        if baseline.binding().operation_id() != operation_id {
            observe_process("kernel.process.effect_observed", "unobserved");
            return;
        }
        let port = match self.effect_port.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => return,
        };
        let Some(port) = port else {
            return;
        };
        match port.read_after(&baseline, evidence) {
            Ok(receipt) => match port.ingest(baseline, receipt) {
                Ok(()) => observe_process("kernel.process.effect_observed", "success"),
                Err(error) => observe_process(
                    "kernel.process.effect_ingest_failed",
                    Self::effect_port_outcome(error),
                ),
            },
            Err(error) => observe_process(
                "kernel.process.effect_readback_failed",
                Self::effect_port_outcome(error),
            ),
        }
    }

    /// Gates one effect-capable process-start REPLAY on its exact unexpired
    /// effect operation lease (issue #1885; I1.9, W2/W5).
    ///
    /// A first process start is a new operation and is authorized by admission
    /// (I1.9: "new effect admission requires a current Module Catalog/Policy
    /// view"). A process start that resumes an already-reserved operation is a
    /// **replay**, and only a replay needs this lease: I1.9 says an
    /// effect-capable generation "may resume only exact already-authorized
    /// operations covered by an unexpired operation lease". This method is
    /// therefore called from the `Existing(replay)` arm of the process-start
    /// pipeline, never from the acquire arm, so a new operation is never gated
    /// on a lease that by definition does not exist yet.
    ///
    /// The observation is the replayed record's own authenticated owner binding
    /// (module identity, generation and the live Authority Epoch it was admitted
    /// under) and the Kernel's clock. The effect receipt, route scope, manifest
    /// digest and admitting Catalog/Policy revisions are read from the durable
    /// rows by
    /// [`eliot_ors::RedbRecoveryStore::authorize_effect_replay_for_operation`],
    /// which also persists the durable reconciliation intent for a denied,
    /// expired or unknown replay, so a refused attempt is never discarded (W5).
    /// Nothing is invented here.
    ///
    /// An authorization state that is absent, invalid, expired, revoked,
    /// gap-affected, epoch-mismatched or Catalog/Policy stale leaves
    /// `authorized_lease()` empty: the replay is refused before the effect is
    /// executed, the shadow/no-effect authority can expose diagnostics but
    /// carries no effect and no canonical write admission. A read that itself
    /// fails is refused too — an unreadable authorization state is the
    /// "unavailable" case I1.9 routes to shadow diagnostics.
    pub(crate) fn require_effect_replay_authority(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: &eliot_process::OperationId,
    ) -> Result<(), ProcessExecutionError> {
        // The store resolves the lease by this operation's own recorded
        // `operation_id`, so no lease key is derived here from the operation
        // string: naming the row is not what authorizes the replay, and a
        // well-formed lease for some other operation cannot satisfy it.
        let replayed_operation_id = eliot_ors::OperationIdentity::new(operation_id.as_str())
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        let current_authority_epoch =
            eliot_contracts::AuthorityEpoch::new(owner.authority_epoch().sequence.get())
                .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        let decision = self
            .evidence_store
            .authorize_effect_replay_for_operation(
                &replayed_operation_id,
                owner.module_id(),
                owner.generation().get(),
                current_authority_epoch,
                i64::try_from(super::unix_ms()).map_err(|error| {
                    ProcessExecutionError::Unavailable(format!(
                        "effect replay observation clock: {error}"
                    ))
                })?,
            )
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        if decision.authority.authorized_lease().is_some() {
            return Ok(());
        }
        observe_process("kernel.process.effect_replay_denied", "shadow_only");
        // The denial's reconciliation kind is already persisted durably by the
        // store query above; it is not logged as a payload here.
        Err(ProcessExecutionError::Contract(
            eliot_process::ContractError::DispatchBindingMismatch,
        ))
    }

    pub(crate) async fn start(
        &self,
        owner: &ProcessOwnerBinding,
        admission: ProcessExecutionAdmissionRequest,
        path_proof: ProcessPathProof,
        outer_binding: HostKernelCandidateBinding,
    ) -> Result<ProcessStartReceipt, ProcessExecutionError> {
        // F-LOG-KERNEL-3 (#901): admitted-launch boundary. Reservation,
        // replay, fence, and executor handoff stay inside
        // `run_process_start`; exactly one terminal is emitted per failed
        // start, and an `UnknownOutcome` (possible launch/response loss)
        // keeps its unknown code instead of a committed-start claim.
        observe_process("kernel.process.start_requested", "attempt");
        // #1824 (I10.21 A1): capture the pre-effect tracked-source baseline
        // before the reservation/executor handoff below. This is the closest
        // pre-effect point that still carries the admission the binding is
        // formed from, and the retained path proof whose lease owns the
        // image the port opens.
        if let Err(error) = self.capture_governed_effect_baseline(owner, &admission, &path_proof) {
            observe_process("kernel.process.start_failed", "rejected");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
            return Err(error);
        }
        let effect_operation_id = admission.intent().operation_id().clone();
        match Box::pin(run_process_start(
            self,
            owner,
            admission,
            path_proof,
            Some(outer_binding),
        ))
        .await
        {
            Ok(receipt) => {
                observe_process("kernel.process.start_committed", "success");
                Ok(receipt)
            }
            Err(error) => {
                // A failed or unknown start claims no governed effect: drop
                // any baseline captured above so a later retry captures fresh
                // pre-effect state.
                self.release_governed_effect_baseline(&effect_operation_id);
                observe_process("kernel.process.start_failed", "rejected");
                super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
                Err(error)
            }
        }
    }

    /// Issues one Kernel-authenticated `ProcessRequest` for `TestD` durable
    /// productive-job admission without starting the process. `TestD` core
    /// consumes the request into its non-serializable admission permit; the
    /// worker later derives the exact same closed-profile intent and runs it
    /// through its one-shot executor.
    pub(crate) async fn issue_testd_process_request(
        &self,
        owner: &ProcessOwnerBinding,
        admission: ProcessExecutionAdmissionRequest,
    ) -> Result<ProcessRequest, ProcessExecutionError> {
        admission.validate()?;
        self.validate_admission(&admission, owner)?;
        let now = self.now();
        if admission.deadline_unix_ms() <= now {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::ExpiredDispatchPermit,
            ));
        }
        let snapshot = self.snapshot().await?;
        snapshot
            .validate()
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        if !admission
            .state_fence()
            .authority_epoch()
            .is_same_authority(&snapshot.state_fence.authority_epoch)
            || admission.state_fence().generation().get()
                != snapshot.state_fence.resource_generation.value()
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::StaleStateFence,
            ));
        }
        let (store_fence, revision_heads) = project_store_snapshot(&snapshot)?;
        let context = self.build_context(
            ClockObservation {
                valid_time_ms: Some(snapshot.observed_at_unix_ms),
                known_time_ms: Some(snapshot.observed_at_unix_ms),
                transaction_sequence: None,
                monotonic_ns: None,
            },
            store_fence.clone(),
            snapshot.state_fence.authority_epoch.clone(),
            revision_heads.clone(),
            snapshot.validation_revision,
        )?;
        let operation_id = admission.intent().operation_id().clone();
        let context_guard = self.insert_context(operation_id, context)?;
        let request = self.issue(
            &admission,
            store_fence,
            revision_heads,
            now,
            snapshot.validation_revision,
        )?;
        request.validate()?;
        drop(context_guard);
        Ok(request)
    }

    pub(crate) async fn inspect(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: eliot_process::OperationId,
    ) -> Result<eliot_process::ProcessExecutionView, ProcessExecutionError> {
        observe_process("kernel.process.inspect_requested", "attempt");
        if let Err(error) = self.authorize_operation(owner, &operation_id) {
            observe_process("kernel.process.inspect_rejected", "fenced");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
            return Err(error);
        }
        match self.executor.inspect(operation_id).await {
            Ok(view) => {
                observe_process("kernel.process.inspect_reported", "success");
                Ok(view)
            }
            Err(error) => {
                observe_process("kernel.process.inspect_failed", "unknown");
                super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
                Err(error)
            }
        }
    }

    #[cfg(windows)]
    pub(crate) async fn inspect_exact_running_receipt(
        &self,
        receipt: &ProcessStartReceipt,
    ) -> Result<(), ProcessExecutionError> {
        receipt.validate()?;
        let record = self
            .replay_store
            .load_process_start(receipt.operation_id())
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?
            .ok_or(ProcessExecutionError::NotFound)?;
        if record.state != ProcessExecutionReplayState::Completed
            || record.receipt.as_ref() != Some(receipt)
        {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        let view = match self
            .inspect(&record.owner, receipt.operation_id().clone())
            .await
        {
            Ok(view) => view,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            Err(error) => return Err(error),
        };
        if view.lifecycle() != ProcessLifecycle::Running
            || view.binding() != receipt.binding()
            || view.identity() != Some(receipt.identity())
        {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        Ok(())
    }

    pub(crate) async fn cancel(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: eliot_process::OperationId,
    ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
        self.cancel_with_origin_grant_inner(owner, operation_id, None)
            .await
    }

    pub(crate) async fn cancel_with_origin_grant(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: eliot_process::OperationId,
        grant: &OriginControlGrant,
    ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
        if grant.operation() != OriginControlOperation::Kill {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        self.cancel_with_origin_grant_inner(owner, operation_id, Some(grant))
            .await
    }

    async fn cancel_with_origin_grant_inner(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: eliot_process::OperationId,
        grant: Option<&OriginControlGrant>,
    ) -> Result<eliot_process::CancellationReceipt, ProcessExecutionError> {
        // F-LOG-KERNEL-3 (#901): cancellation boundary. The returned receipt
        // is delivery acknowledgement, not terminal cancellation; exactly one
        // terminal is emitted per failed cancel.
        observe_process("kernel.process.cancel_requested", "attempt");
        if grant.is_some_and(|value| value.operation() != OriginControlOperation::Kill) {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        if let Err(error) = self.authorize_effect_with_grant(
            owner,
            &operation_id,
            grant,
            OriginControlOperation::Kill,
        ) {
            observe_process("kernel.process.cancel_rejected", "fenced");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
            return Err(error);
        }
        // Issue #1775 W6: one-shot effect journal. The durable journal keeps
        // the consumed one-shot plus its possible-effect state, so a grant
        // that already funded an observed effect replays the preserved
        // original receipt instead of executing twice, and an unproven
        // effect never mints a fresh nonce. The unreadable-journal case
        // fails closed before the effect, never around it. The presented
        // operation must equal the operation the grant was decided for
        // before any journal read or effect.
        if let Some(granted) = grant {
            if let Err(error) = granted
                .binds_operation(&operation_id)
                .map_err(ProcessExecutionError::Contract)
            {
                observe_process("kernel.process.cancel_rejected", "fenced");
                super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
                return Err(error);
            }
            match self.origin_grant_effect_state(granted.request_nonce()) {
                Ok(OriginGrantEffectOutcome::Effected) => {
                    observe_process("kernel.process.cancel_replayed", "unknown");
                    let receipt = self.origin_grant_effect_receipt(granted.request_nonce())?;
                    observe_process("kernel.process.cancel_acknowledged", "success");
                    return Ok(receipt);
                }
                Ok(OriginGrantEffectOutcome::Unknown) => {}
                Err(error) => {
                    observe_process("kernel.process.cancel_rejected", "fenced");
                    super::kernel_diagnostics::observe_terminal_error(process_terminal_code(
                        &error,
                    ));
                    return Err(error);
                }
            }
        }
        let Ok(receipt) = self.executor.cancel(operation_id.clone()).await else {
            // Issue #1775 W5: a failed or hung owned child leaves the
            // effect unproven. The consumed one-shot stays `Unknown` in
            // the durable journal, and the caller gets the exact
            // missing-capability report — reconcile the original
            // target/operation through the retained owner binding and
            // handles — never a downgrade to name/PID control and never
            // a blind re-execution.
            observe_process("kernel.process.cancel_failed", "unknown");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(
                &ProcessExecutionError::UnknownOutcome,
            ));
            return Err(ProcessExecutionError::UnknownOutcome);
        };
        // The receipt is observed: journal the proven effect with
        // its preserved original before reporting success. A failed
        // journal cannot report a clean success; the receipt stays
        // re-derivable through reconcile.
        if let Some(granted) = grant
            && let Err(error) = self.record_origin_grant_effect(granted.request_nonce(), &receipt)
        {
            observe_process("kernel.process.cancel_unrecorded", "unknown");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
            return Err(error);
        }
        observe_process("kernel.process.cancel_acknowledged", "success");
        Ok(receipt)
    }

    /// Closes one registered descendant after cancellation, restart, or
    /// shutdown (CHILD-1/CHILD-2, #1918): authorizes the owner, reads the
    /// exact current view, and builds the descendant-closure receipt. The
    /// registration is removed only when the receipt proves closure; an
    /// open receipt retains it, so no running descendant silently leaves
    /// the registry.
    pub(crate) async fn close_registered_descendant(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: eliot_process::OperationId,
    ) -> Result<DescendantClosureReceipt, ProcessExecutionError> {
        // F-LOG-KERNEL-3 (#901): descendant-close boundary. The receipt is
        // an observation of the exact current view, never a success claim;
        // exactly one terminal is emitted per failed close.
        observe_process("kernel.process.descendant_close_requested", "attempt");
        if let Err(error) = self.authorize_operation(owner, &operation_id) {
            observe_process("kernel.process.descendant_close_rejected", "fenced");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
            return Err(error);
        }
        let registration = self
            .descendants
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("descendant registry lock poisoned".to_owned())
            })?
            .get(&operation_id)
            .cloned()
            .ok_or(ProcessExecutionError::NotFound)?;
        let view = match self.inspect(owner, operation_id.clone()).await {
            Ok(view) => view,
            Err(error) => {
                observe_process("kernel.process.descendant_close_failed", "unknown");
                super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
                return Err(error);
            }
        };
        let receipt = DescendantClosureReceipt::close(&registration, &view);
        if let Err(error) = receipt.validate().map_err(ProcessExecutionError::Contract) {
            observe_process("kernel.process.descendant_close_failed", "unknown");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
            return Err(error);
        }
        if receipt.all_closed() {
            self.descendants
                .lock()
                .map_err(|_| {
                    ProcessExecutionError::Unavailable(
                        "descendant registry lock poisoned".to_owned(),
                    )
                })?
                .remove(&operation_id);
        }
        observe_process(
            "kernel.process.descendant_close_observed",
            if receipt.all_closed() {
                "closed"
            } else {
                "open"
            },
        );
        Ok(receipt)
    }

    /// Closes every still-registered descendant during shutdown (#1918). Each
    /// entry closes under the exact owner its replay record names, so the
    /// shutdown contour authorizes nothing a launch never granted. Outcomes
    /// are per-operation: one unproven closure never hides the rest.
    pub(crate) async fn close_all_registered_descendants(
        &self,
    ) -> Vec<(
        eliot_process::OperationId,
        Result<DescendantClosureReceipt, ProcessExecutionError>,
    )> {
        let registered = self.descendants.lock().map_or_else(
            |_| Vec::new(),
            |registry| registry.registered_operation_ids(),
        );
        let mut outcomes = Vec::with_capacity(registered.len());
        for operation_id in registered {
            let owner = match self.replay_store.load_process_start(&operation_id) {
                Ok(Some(record)) => record.owner,
                Ok(None) => {
                    outcomes.push((operation_id, Err(ProcessExecutionError::NotFound)));
                    continue;
                }
                Err(error) => {
                    outcomes.push((
                        operation_id,
                        Err(ProcessExecutionError::Unavailable(error.to_string())),
                    ));
                    continue;
                }
            };
            outcomes.push((
                operation_id.clone(),
                self.close_registered_descendant(&owner, operation_id).await,
            ));
        }
        outcomes
    }

    pub(crate) async fn reconcile(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: eliot_process::OperationId,
    ) -> Result<ProcessEvidence, ProcessExecutionError> {
        // F-LOG-KERNEL-3 (#901): exit/evidence reconciliation boundary. Exit
        // zero and provider success never imply semantic completion; the
        // reported evidence stays the owner's, and exactly one terminal is
        // emitted per failed reconcile.
        observe_process("kernel.process.reconcile_requested", "attempt");
        if let Err(error) = self.authorize_operation(owner, &operation_id) {
            observe_process("kernel.process.reconcile_rejected", "fenced");
            super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
            return Err(error);
        }
        let effect_operation_id = operation_id.clone();
        match self.executor.reconcile(operation_id).await {
            Ok(evidence) => {
                // #1824 (I10.21 A1/W2): read the terminal source state against
                // the retained pre-effect baseline and ingest the validated
                // receipt. Monitor-path failure never fails the reconcile.
                self.ingest_governed_effect_observation(&effect_operation_id, &evidence);
                observe_process("kernel.process.reconcile_reported", "success");
                Ok(evidence)
            }
            Err(error) => {
                observe_process("kernel.process.reconcile_unknown", "unknown");
                super::kernel_diagnostics::observe_terminal_error(process_terminal_code(&error));
                Err(error)
            }
        }
    }

    fn authorize_operation(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: &eliot_process::OperationId,
    ) -> Result<(), ProcessExecutionError> {
        let record = self
            .replay_store
            .load_process_start(operation_id)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?
            .ok_or(ProcessExecutionError::NotFound)?;
        authorize_process_owner(&record.owner, owner)
    }

    /// Authorizes the owner for the exact operation and, when an origin
    /// control grant funds the effect, proves that grant still names the
    /// admitted operation class and the identity the authoritative durable
    /// record retains for that same operation (issue #1775 W3/W4; I3.4).
    ///
    /// The comparison is against the retained start receipt — the object the
    /// Kernel itself created and persisted — never a PID reopened by number
    /// and never the caller's serialized binding. A grant minted for one
    /// child, one image, one start time, or one managed generation therefore
    /// cannot authorize a substituted or different target, and a grant minted
    /// for one operation class (for example adoption) cannot authorize the
    /// effect named by `expected_operation`. An operation with no proven
    /// retained identity has nothing to compare against and fails closed.
    ///
    /// Currency is rechecked here too, against the live authority contour
    /// and clock rather than the decide-time observation: a grant whose
    /// challenge window has expired, or whose admitted fence no longer
    /// matches the live epoch lineage and sequence, fails before the
    /// privileged effect even when it still names the right operation and
    /// target. The installation the grant binds is rechecked against the
    /// same Kernel-retained composition identity issuance and decide proved,
    /// so a grant minted under a foreign installation fails here even when
    /// every other leg still looks live.
    fn authorize_effect_with_grant(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: &eliot_process::OperationId,
        grant: Option<&OriginControlGrant>,
        expected_operation: OriginControlOperation,
    ) -> Result<(), ProcessExecutionError> {
        let record = self
            .replay_store
            .load_process_start(operation_id)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?
            .ok_or(ProcessExecutionError::NotFound)?;
        authorize_process_owner(&record.owner, owner)?;
        let Some(grant) = grant else {
            return Ok(());
        };
        let identity = record
            .receipt
            .as_ref()
            .ok_or(ProcessExecutionError::UnknownOutcome)?
            .identity();
        grant
            .binds_target_for_operation(
                identity.physical(),
                identity.generation(),
                expected_operation,
            )
            .map_err(ProcessExecutionError::Contract)?;
        let live_epoch = &self.snapshot_binding.authority_epoch().current;
        grant
            .binds_effect_currency(
                live_epoch.lineage_id.as_str(),
                live_epoch.epoch,
                super::unix_ms(),
            )
            .map_err(ProcessExecutionError::Contract)?;
        if grant.installation_id() != Self::live_origin_installation_id()? {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::IdentityMismatch,
            ));
        }
        Ok(())
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "reservation, canonical projection, authority issue, executor handoff, and replay linearization are one ordered operation"
)]
pub(crate) async fn run_process_start<P: ProcessStartPorts>(
    ports: &P,
    owner: &ProcessOwnerBinding,
    admission: ProcessExecutionAdmissionRequest,
    path_proof: P::PathProof,
    outer_binding: Option<HostKernelCandidateBinding>,
) -> Result<P::Receipt, ProcessExecutionError> {
    admission.validate()?;
    ports.validate_path(&admission, &path_proof)?;
    ports.validate_admission(&admission, owner)?;
    let digest = process_admission_digest(&admission)
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
    let now = ports.now();
    if admission.deadline_unix_ms() <= now {
        return Err(ProcessExecutionError::Contract(
            eliot_process::ContractError::ExpiredDispatchPermit,
        ));
    }
    let mut reservation = match ports.begin(admission.intent().operation_id(), &digest, owner)? {
        ProcessExecutionReplayBegin::Acquired => ProcessStartReservation {
            ports,
            operation_id: admission.intent().operation_id().clone(),
            admission_digest: digest.clone(),
            owner: owner.clone(),
            active: true,
        },
        ProcessExecutionReplayBegin::Existing(record) => {
            if record.admission_digest != digest || record.owner != *owner {
                return Err(ProcessExecutionError::Contract(
                    eliot_process::ContractError::DispatchBindingMismatch,
                ));
            }
            // #1885 (I1.9, W2): this is a REPLAY of an already-reserved
            // operation, so an effect-capable one may resume only under an exact
            // unexpired effect operation lease. The gate runs before the
            // recorded receipt is replayed and before any effect is executed;
            // a denial refuses the resume and the store has already persisted
            // the durable reconciliation intent (W5). A first process start
            // takes the `Acquired` arm and is authorized by admission instead,
            // so a new operation is never gated on a lease that cannot exist
            // yet.
            ports.require_effect_replay_authority(
                owner,
                &admission.intent().operation_id().clone(),
            )?;
            return match record.state {
                ProcessExecutionReplayState::Completed => ports
                    .completed_receipt(record)
                    .await?
                    .ok_or(ProcessExecutionError::UnknownOutcome),
                ProcessExecutionReplayState::Reserved | ProcessExecutionReplayState::Unknown => {
                    Err(ProcessExecutionError::UnknownOutcome)
                }
            };
        }
    };
    let snapshot = match ports.snapshot().await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    if let Err(error) = snapshot.validate() {
        let failure = ProcessExecutionError::Unavailable(error.to_string());
        return Err(match reservation.release() {
            Ok(()) => failure,
            Err(_) => ProcessExecutionError::UnknownOutcome,
        });
    }
    // INTENDED EpochId shape (B→A→C): exact-tuple is_same_authority for the
    // fence side; snapshot scalar side resolves with B cutover.
    if !admission
        .state_fence()
        .authority_epoch()
        .is_same_authority(&snapshot.state_fence.authority_epoch)
        || admission.state_fence().generation().get()
            != snapshot.state_fence.resource_generation.value()
    {
        let failure =
            ProcessExecutionError::Contract(eliot_process::ContractError::StaleStateFence);
        return Err(match reservation.release() {
            Ok(()) => failure,
            Err(_) => ProcessExecutionError::UnknownOutcome,
        });
    }
    let (store_fence, revision_heads) = match project_store_snapshot(&snapshot) {
        Ok(projected) => projected,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let context = match ports.build_context(
        ClockObservation {
            valid_time_ms: Some(snapshot.observed_at_unix_ms),
            known_time_ms: Some(snapshot.observed_at_unix_ms),
            transaction_sequence: None,
            monotonic_ns: None,
        },
        store_fence.clone(),
        snapshot.state_fence.authority_epoch.clone(),
        revision_heads.clone(),
        snapshot.validation_revision,
    ) {
        Ok(context) => context,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let operation_id = admission.intent().operation_id().clone();
    let context_guard = match ports.insert_context(operation_id.clone(), context) {
        Ok(guard) => guard,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let request = match ports.issue(
        &admission,
        store_fence,
        revision_heads,
        now,
        snapshot.validation_revision,
    ) {
        Ok(request) => request,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let path_guard = match ports.insert_path(operation_id.clone(), path_proof) {
        Ok(guard) => guard,
        Err(error) => {
            return Err(match reservation.release() {
                Ok(()) => error,
                Err(_) => ProcessExecutionError::UnknownOutcome,
            });
        }
    };
    let receipt = match ports.execute(owner, request, outer_binding.as_ref()).await {
        Ok(receipt) => receipt,
        Err(error) => {
            drop(context_guard);
            drop(path_guard);
            reservation.disarm();
            ports.mark_unknown(admission.intent().operation_id(), &digest, owner);
            return Err(error);
        }
    };
    drop(context_guard);
    drop(path_guard);
    if let Err(error) = ports.persist_completed(
        admission.intent().operation_id(),
        &digest,
        owner,
        receipt.clone(),
    ) {
        reservation.disarm();
        ports.mark_unknown(admission.intent().operation_id(), &digest, owner);
        return Err(error);
    }
    reservation.disarm();
    Ok(receipt)
}

impl ProcessStartPorts for ProcessExecutionGateway {
    type PathProof = ProcessPathProof;
    type Request = ProcessRequest;
    type Receipt = ProcessStartReceipt;

    fn validate_admission(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        owner: &ProcessOwnerBinding,
    ) -> Result<(), ProcessExecutionError> {
        // INTENDED EpochId shape (Split A): exact-tuple is_same_authority for
        // fence/owner; snapshot scalar side resolves with B cutover.
        if admission.recipient_module_id() != owner.module_id()
            || !admission
                .state_fence()
                .authority_epoch()
                .is_same_authority(owner.authority_epoch())
            || admission.state_fence().generation().get() != owner.generation().get()
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        // Scalar ORS snapshot contour (residual): project the canonical fence
        // sequence for the stale-fence join; lineage-exact gating lives in the
        // admission/owner `is_same_authority` check above.
        if admission.state_fence().authority_epoch().sequence.get()
            != self.snapshot_binding.authority_epoch().current.epoch
            || admission.state_fence().generation() != admission.intent().generation()
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::StaleStateFence,
            ));
        }
        Ok(())
    }

    fn now(&self) -> u64 {
        super::unix_ms()
    }

    fn validate_path(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        path_proof: &Self::PathProof,
    ) -> Result<(), ProcessExecutionError> {
        if path_proof.executable.to_string_lossy() != admission.intent().executable()
            || path_proof.working_directory.to_string_lossy()
                != admission.intent().working_directory()
            || path_proof.lease.executable_identity().file_index == 0
        {
            return Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch,
            ));
        }
        Ok(())
    }

    fn begin(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayBegin, ProcessExecutionError> {
        self.replay_store
            .begin_process_start(operation_id, digest, owner)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }

    fn require_effect_replay_authority(
        &self,
        owner: &ProcessOwnerBinding,
        operation_id: &eliot_process::OperationId,
    ) -> Result<(), ProcessExecutionError> {
        ProcessExecutionGateway::require_effect_replay_authority(self, owner, operation_id)
    }

    async fn completed_receipt(
        &self,
        record: ProcessExecutionReplayRecord,
    ) -> Result<Option<Self::Receipt>, ProcessExecutionError> {
        let receipt = record
            .receipt
            .ok_or(ProcessExecutionError::UnknownOutcome)?;
        receipt.validate()?;
        let view = match self.executor.inspect(receipt.operation_id().clone()).await {
            Ok(view) => view,
            Err(ProcessExecutionError::NotFound | ProcessExecutionError::UnknownOutcome) => {
                return Err(ProcessExecutionError::UnknownOutcome);
            }
            Err(error) => return Err(error),
        };
        if view.lifecycle() != ProcessLifecycle::Running
            || view.binding() != receipt.binding()
            || view.identity() != Some(receipt.identity())
        {
            return Err(ProcessExecutionError::UnknownOutcome);
        }
        Ok(Some(receipt))
    }

    async fn snapshot(&self) -> Result<CanonicalValidationSnapshot, ProcessExecutionError> {
        #[cfg(windows)]
        {
            self.canonical_validation_snapshot().await
        }
        #[cfg(not(windows))]
        {
            Err(ProcessExecutionError::Unavailable(
                "canonical store validation is unavailable on this platform".to_owned(),
            ))
        }
    }

    fn build_context(
        &self,
        clock: ClockObservation,
        store_fence: FencingToken,
        authority_epoch: eliot_contracts::EpochId,
        revision_heads: BTreeMap<String, String>,
        validation_revision: u64,
    ) -> Result<DispatchValidationContext, ProcessExecutionError> {
        DispatchValidationContext::new(
            clock,
            store_fence,
            authority_epoch,
            revision_heads,
            validation_revision,
        )
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }

    fn insert_context(
        &self,
        operation_id: eliot_process::OperationId,
        context: DispatchValidationContext,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
        self.validation_contexts
            .insert(operation_id, context)
            .map(|guard| Box::new(guard) as Box<dyn ProcessStartGuard>)
    }

    fn issue(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
        store_fence: FencingToken,
        revision_heads: BTreeMap<String, String>,
        now: u64,
        validation_revision: u64,
    ) -> Result<Self::Request, ProcessExecutionError> {
        let permit_issuance = PermitIssuance::new_with_validation_revision(
            admission.action_lease_ref().clone(),
            store_fence,
            revision_heads,
            now,
            admission.deadline_unix_ms(),
            format!(
                "process-start:{}",
                admission.intent().operation_id().as_str()
            ),
            validation_revision,
        )
        .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        let permit = self
            .controller
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("process authority lock poisoned".to_owned())
            })?
            .issue(admission.intent(), permit_issuance, &self.snapshot_binding)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        ProcessRequest::new(admission.intent().clone(), permit)
            .map_err(ProcessExecutionError::Contract)
    }

    fn insert_path(
        &self,
        operation_id: eliot_process::OperationId,
        path_proof: Self::PathProof,
    ) -> Result<Box<dyn ProcessStartGuard>, ProcessExecutionError> {
        self.attach_path_proof(operation_id, path_proof)
    }

    async fn execute(
        &self,
        owner: &ProcessOwnerBinding,
        request: Self::Request,
        outer_binding: Option<&HostKernelCandidateBinding>,
    ) -> Result<Self::Receipt, ProcessExecutionError> {
        // CHILD-1 (#1918): register the descendant before the executor
        // handoff. A poisoned or conflicting registry refuses the launch: an
        // unregistered child must never start.
        let operation_id = request.operation_id().clone();
        let registration = RegisteredDescendant::new(
            operation_id.clone(),
            owner.module_id().to_owned(),
            owner.authority_epoch().clone(),
            owner.generation(),
        )
        .map_err(ProcessExecutionError::Contract)?;
        self.descendants
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("descendant registry lock poisoned".to_owned())
            })?
            .register(registration)
            .map_err(ProcessExecutionError::Contract)?;
        // #1824 (I10.21): the retained pre-effect baseline must belong to the
        // exact request about to be handed to the executor. A mismatch refuses
        // the handoff and drops the registration like any other failed launch.
        if let Err(error) = self.verify_governed_effect_request(owner, &request) {
            if let Ok(mut registry) = self.descendants.lock() {
                registry.remove(&operation_id);
            }
            return Err(error);
        }
        let sink: Arc<dyn ProcessEvidenceSink> = Arc::new(OrsProcessStreamRecoverySink {
            store: Arc::clone(&self.evidence_store),
            owner: owner.clone(),
            evidence: Arc::new(OrsProcessEvidenceSink {
                store: Arc::clone(&self.evidence_store),
                owner: owner.clone(),
            }),
        });
        #[cfg(windows)]
        let started = match outer_binding {
            Some(candidate) => {
                let binding: Result<RecoverableJobBinding, ProcessExecutionError> =
                    serde_json::to_value(&candidate.job_binding)
                        .map_err(|_| {
                            ProcessExecutionError::Unavailable(
                                "Host Kernel Job binding cannot be encoded".to_owned(),
                            )
                        })
                        .and_then(|value| {
                            serde_json::from_value(value).map_err(|_| {
                                ProcessExecutionError::Unavailable(
                                    "Host Kernel Job binding is malformed".to_owned(),
                                )
                            })
                        });
                match binding {
                    Ok(binding)
                        if binding.job_identity().name() == candidate.job_object_id.as_str() =>
                    {
                        self.executor
                            .start_with_kernel_outer_job_binding(request, sink, binding)
                    }
                    Ok(_) => Err(ProcessExecutionError::Contract(
                        eliot_process::ContractError::DispatchBindingMismatch,
                    )),
                    Err(error) => Err(error),
                }
            }
            None => Err(ProcessExecutionError::Unavailable(
                "current Host Kernel Job binding is required for Kernel child launch".to_owned(),
            )),
        };
        #[cfg(not(windows))]
        let started = {
            let _ = (request, sink, outer_binding);
            Err(ProcessExecutionError::Unavailable(
                "Windows process launch is unavailable on this platform".to_owned(),
            ))
        };
        match started {
            Ok(receipt) => Ok(receipt),
            Err(error) => {
                // A typed UnknownOutcome means the platform could not observe
                // that its still-suspended child was terminated. Keep this
                // operation's owner/epoch/generation registration available
                // for reconciliation; only a proved pre-effect refusal may
                // release the attempt registration here.
                if !matches!(&error, ProcessExecutionError::UnknownOutcome)
                    && let Ok(mut registry) = self.descendants.lock()
                {
                    registry.remove(&operation_id);
                }
                Err(error)
            }
        }
    }

    fn persist_completed(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
        receipt: Self::Receipt,
    ) -> Result<(), ProcessExecutionError> {
        self.replay_store
            .persist_process_start(
                operation_id,
                ProcessExecutionReplayRecord {
                    admission_digest: digest.to_owned(),
                    owner: owner.clone(),
                    state: ProcessExecutionReplayState::Completed,
                    receipt: Some(receipt),
                },
            )
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }

    fn mark_unknown(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) {
        ProcessExecutionGateway::mark_unknown(self, operation_id, digest, owner);
    }

    fn abort(
        &self,
        operation_id: &eliot_process::OperationId,
        digest: &str,
        owner: &ProcessOwnerBinding,
    ) -> Result<ProcessExecutionReplayAbort, ProcessExecutionError> {
        self.replay_store
            .abort_process_start(operation_id, digest, owner)
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))
    }
}

pub(crate) fn authorize_process_owner(
    expected: &ProcessOwnerBinding,
    presented: &ProcessOwnerBinding,
) -> Result<(), ProcessExecutionError> {
    if expected != presented {
        // F-LOG-KERNEL-3 (#901): subordinate observation only; the calling
        // gateway boundary owns the single terminal for the failed operation.
        observe_process("kernel.process.owner_rejected", "fenced");
        return Err(ProcessExecutionError::Contract(
            eliot_process::ContractError::DispatchBindingMismatch,
        ));
    }
    observe_process("kernel.process.owner_admitted", "success");
    Ok(())
}

/// Maps a typed process session validation failure to a bounded stable
/// rejection (issue #79).
///
/// Stale transport, stale session, stale epoch/fence, and wrong owner each
/// keep a distinct wire code so callers can tell a superseded pipe from a
/// foreign session without trusting the pipe. Any other contract failure
/// keeps the existing generic contract projection.
pub(crate) fn process_session_rejection(
    error: eliot_process::ContractError,
) -> eliot_kernel_service::ProcessExecutionRejection {
    let code = match &error {
        eliot_process::ContractError::StaleProcessSession => "STALE_PROCESS_SESSION",
        eliot_process::ContractError::StaleTransportBinding => "STALE_TRANSPORT_BINDING",
        eliot_process::ContractError::StaleAuthorityEpoch => "STALE_AUTHORITY_EPOCH",
        eliot_process::ContractError::StaleStateFence
        | eliot_process::ContractError::FenceMismatch => "STALE_PROCESS_FENCE",
        eliot_process::ContractError::DispatchBindingMismatch => "PROCESS_OWNER_MISMATCH",
        _ => {
            return eliot_kernel_service::ProcessExecutionRejection::from_error(
                &ProcessExecutionError::Contract(error),
            );
        }
    };
    eliot_kernel_service::ProcessExecutionRejection {
        code: code.to_owned(),
        detail: error.to_string().chars().take(512).collect(),
    }
}

impl KernelComposition {
    /// Returns the bounded refusal projection when an exact-fence process
    /// `Start` cannot be admitted under the current supervision coverage.
    ///
    /// This never fabricates coverage and never retries: a missing independent
    /// Host-observed Watchdog carrier, a non-current target generation, or a
    /// stale fence each stop here before the path-proof and gateway steps. A
    /// malformed presented generation is an invalid request, not a coverage
    /// observation, and keeps its own stable code.
    ///
    /// Crate-visible so the production front-door process start
    /// ([`GatewayProcessStarter`](crate::process_execution_client) is built
    /// from the same composition) runs this one guard instead of a parallel
    /// fence reconstruction: the decision, the refusal projection, and the
    /// `kernel.process.request_rejected` observation then have exactly one
    /// owner on every start path.
    pub(crate) fn reject_process_start_without_material_coverage(
        &self,
        admission: &eliot_process::ProcessExecutionAdmissionRequest,
    ) -> Result<HostKernelCandidateBinding, eliot_kernel_service::ProcessExecutionRejection> {
        match self.admit_material_process_start(admission) {
            Ok(candidate) => Ok(candidate),
            Err(error) => {
                observe_process("kernel.process.request_rejected", "watchdog_coverage");
                Err(eliot_kernel_service::ProcessExecutionRejection {
                    code: eliot_kernel_service::ProcessExecutionRejection::WATCHDOG_COVERAGE_UNAVAILABLE
                        .to_owned(),
                    detail: error.to_string().chars().take(512).collect(),
                })
            }
        }
    }

    pub async fn execute_process_request(
        &self,
        session: &Session,
        session_binding: ProcessSessionBinding,
        request: ProcessExecutionRequest,
    ) -> ProcessExecutionResponse {
        // F-LOG-KERNEL-3 (#901): process front-door boundary. Receipt is an
        // observation of the gateway outcome; rejections below are typed
        // responses (subordinate infos), while a failed gateway operation
        // emits exactly one terminal through its own boundary.
        observe_process("kernel.process.request_received", "attempt");
        let Ok((owner, expected_session_binding)) = super::caller_binding(session) else {
            observe_process("kernel.process.request_rejected", "caller_unavailable");
            return ProcessExecutionResponse::Rejected(
                eliot_kernel_service::ProcessExecutionRejection {
                    code: "AUTHENTICATED_CALLER_REQUIRED".to_owned(),
                    detail: "the established authenticated session binding is unavailable"
                        .to_owned(),
                },
            );
        };
        if eliot_process::validate_process_transport_binding(
            &session_binding,
            &expected_session_binding,
        )
        .is_err()
        {
            observe_process("kernel.process.request_rejected", "session_mismatch");
            return ProcessExecutionResponse::Rejected(
                eliot_kernel_service::ProcessExecutionRejection {
                    code: "SESSION_BINDING_MISMATCH".to_owned(),
                    detail: "process operation session binding does not match the established authenticated session".to_owned(),
                },
            );
        }
        // Issue #79: the intent session must validate against the
        // server-derived admitted process-owner/session binding, never
        // against the presenting pipe. Identity validates before authority
        // dispatch: a copied `connection_id`, a foreign or stale session, a
        // stale epoch/fence, and a wrong owner each reject with a distinct
        // typed code, while cancel and reconcile below stay on
        // operation/owner identity.
        if let ProcessExecutionRequest::Start(admission) = &request {
            let caller = match self.admitted_process_caller_session(session) {
                Ok(caller) => caller,
                Err(error) => {
                    observe_process("kernel.process.request_rejected", "caller_session");
                    return ProcessExecutionResponse::Rejected(
                        eliot_kernel_service::ProcessExecutionRejection {
                            code: "ADMITTED_CALLER_SESSION_REQUIRED".to_owned(),
                            detail: error.to_string().chars().take(512).collect(),
                        },
                    );
                }
            };
            if let Err(error) = eliot_process::validate_process_intent_session(
                admission.intent(),
                &caller,
                &owner,
                admission.state_fence(),
            ) {
                observe_process("kernel.process.request_rejected", "intent_session");
                return ProcessExecutionResponse::Rejected(process_session_rejection(error));
            }
        }
        let Some(gateway) = &self.process_gateway else {
            observe_process("kernel.process.request_rejected", "authority_unavailable");
            return ProcessExecutionResponse::Rejected(
                eliot_kernel_service::ProcessExecutionRejection {
                    code: "PROCESS_AUTHORITY_CONFIGURATION_REQUIRED".to_owned(),
                    detail: "external process authority key, snapshot, replay, and evidence bindings are required".to_owned(),
                },
            );
        };
        observe_process("kernel.process.request_admitted", "success");
        let result = match request {
            ProcessExecutionRequest::Start(admission) => {
                // Material/Critical process start is fail-closed on the exact
                // target fence before any external effect owner is entered.
                let outer_binding =
                    match self.reject_process_start_without_material_coverage(&admission) {
                        Ok(outer_binding) => outer_binding,
                        Err(rejection) => return ProcessExecutionResponse::Rejected(rejection),
                    };
                let proof = match self.retain_process_path_proof(&admission) {
                    Ok(proof) => proof,
                    Err(error) => {
                        observe_process("kernel.process.request_rejected", "path_proof");
                        return ProcessExecutionResponse::Rejected(
                            eliot_kernel_service::ProcessExecutionRejection::from_error(&error),
                        );
                    }
                };
                gateway
                    .start(&owner, admission, proof, outer_binding)
                    .await
                    .map(ProcessExecutionResponse::Started)
            }
            ProcessExecutionRequest::Inspect { operation_id } => gateway
                .inspect(&owner, operation_id)
                .await
                .map(ProcessExecutionResponse::Status),
            ProcessExecutionRequest::Cancel { operation_id } => gateway
                .cancel(&owner, operation_id)
                .await
                .map(ProcessExecutionResponse::Cancelled),
            ProcessExecutionRequest::Reconcile { operation_id } => gateway
                .reconcile(&owner, operation_id)
                .await
                .map(ProcessExecutionResponse::Reconciled),
        };
        result.unwrap_or_else(|error| {
            // F-LOG-KERNEL-3 (#901): subordinate observation only; the
            // gateway boundary above owns the single terminal for the failed
            // operation (case 25 across propagation).
            observe_process("kernel.process.request_failed", "rejected");
            ProcessExecutionResponse::Rejected(
                eliot_kernel_service::ProcessExecutionRejection::from_error(&error),
            )
        })
    }

    pub(crate) fn retain_process_path_proof(
        &self,
        admission: &ProcessExecutionAdmissionRequest,
    ) -> Result<ProcessPathProof, ProcessExecutionError> {
        let executable = PathBuf::from(admission.intent().executable());
        let working_directory = PathBuf::from(admission.intent().working_directory());
        executable.strip_prefix(&self.work_root).map_err(|_| {
            ProcessExecutionError::Contract(eliot_process::ContractError::InvalidValue {
                field: "process_root",
                reason: "executable is outside the retained WorkScope root",
            })
        })?;
        working_directory
            .strip_prefix(&self.work_root)
            .map_err(|_| {
                ProcessExecutionError::Contract(eliot_process::ContractError::InvalidValue {
                    field: "process_root",
                    reason: "working directory is outside the retained WorkScope root",
                })
            })?;
        let lease = self
            .platform
            .retain_process_path_lease(
                &executable,
                &working_directory,
                admission.intent().executable_sha256(),
            )
            .map_err(|error| ProcessExecutionError::Unavailable(error.to_string()))?;
        Ok(ProcessPathProof {
            executable,
            working_directory,
            lease: Arc::new(lease),
        })
    }
    pub(super) fn validate_candidate_process_binding(
        &self,
        candidate: &HostKernelCandidateBinding,
    ) -> Result<(), KernelServiceError> {
        #[cfg(test)]
        if candidate.job_object_id.as_str() == "Local\\Eliot-Host-Kernel-test" {
            return Ok(());
        }
        let binding: RecoverableJobBinding =
            serde_json::from_value(serde_json::to_value(&candidate.job_binding).map_err(|_| {
                KernelServiceError::Platform("Kernel Job binding cannot be encoded".to_owned())
            })?)
            .map_err(|_| {
                KernelServiceError::Platform("Kernel Job binding is malformed".to_owned())
            })?;
        if binding.job_identity().name() != candidate.job_object_id.as_str() {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "job_object_id",
            });
        }
        let job = RecoverableJobObject::open(binding)
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        let current = self
            .platform
            .process_identity(std::process::id())
            .map_err(|error| KernelServiceError::Platform(error.to_string()))?;
        if job.binding().root().process() != &current
            || !job
                .live_processes()
                .map_err(|error| KernelServiceError::Platform(error.to_string()))?
                .iter()
                .any(|process| process.process() == &current)
        {
            return Err(KernelServiceError::HandshakeMismatch {
                field: "candidate_process_job_binding",
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod process_execution_diagnostics_tests {
    //! F-LOG-KERNEL-3 (#901) focused diagnostics proof: terminal-code
    //! stability, owner admission-boundary preservation, and secret-free
    //! capture for the process-execution observations added above.

    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct CaptureSink {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for CaptureSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.bytes
                .lock()
                .map_err(|_| std::io::Error::other("capture lock poisoned"))?
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn capture(run: impl FnOnce()) -> String {
        let sink = CaptureSink::default();
        let writer_sink = sink.clone();
        {
            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_writer(move || writer_sink.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, run);
        }
        String::from_utf8_lossy(&sink.bytes.lock().expect("capture lock")).into_owned()
    }

    fn test_owner(digest: &str) -> ProcessOwnerBinding {
        let epoch = eliot_contracts::EpochId::new(
            eliot_contracts::EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                .expect("lineage"),
            std::num::NonZeroU64::new(1).expect("sequence"),
        )
        .expect("epoch");
        ProcessOwnerBinding::new(
            "eliotd",
            digest.to_owned(),
            epoch,
            Generation::new(1).expect("generation"),
        )
        .expect("owner")
    }

    #[test]
    fn process_diagnostics_terminal_mapping_and_owner_boundary() {
        // Every failure variant keeps a distinct stable code even when its
        // payload carries secret-like canaries; only the code may be logged.
        let contract =
            ProcessExecutionError::Contract(eliot_process::ContractError::DispatchBindingMismatch);
        let not_found = ProcessExecutionError::NotFound;
        let unavailable =
            ProcessExecutionError::Unavailable("argv --token=top-secret-canary".to_owned());
        let sink = ProcessExecutionError::EvidenceSink(eliot_process::EvidenceSinkError {
            message: "credential=super-secret-canary".to_owned(),
        });
        let unknown = ProcessExecutionError::UnknownOutcome;
        assert_eq!(process_terminal_code(&contract), "process_contract");
        assert_eq!(process_terminal_code(&not_found), "process_not_found");
        assert_eq!(process_terminal_code(&unavailable), "process_unavailable");
        assert_eq!(process_terminal_code(&sink), "process_evidence_sink");
        assert_eq!(process_terminal_code(&unknown), "process_unknown_outcome");

        // The admission boundary is preserved: the same owner admits, a
        // foreign owner rejects with the exact contract error.
        let owner = test_owner(&"a".repeat(64));
        let foreign = test_owner(&"b".repeat(64));
        assert!(authorize_process_owner(&owner, &owner).is_ok());
        let rejected = authorize_process_owner(&owner, &foreign);
        assert!(matches!(
            rejected,
            Err(ProcessExecutionError::Contract(
                eliot_process::ContractError::DispatchBindingMismatch
            ))
        ));

        // Captured diagnostics carry fixed events and stable codes only; the
        // canary payloads above never reach the sink.
        let text = capture(|| {
            observe_process("kernel.process.start_requested", "attempt");
            observe_process("kernel.process.owner_admitted", "success");
            observe_process("kernel.process.owner_rejected", "fenced");
            for error in [&contract, &not_found, &unavailable, &sink, &unknown] {
                crate::kernel_diagnostics::observe_terminal_error(process_terminal_code(error));
            }
        });
        for marker in [
            "kernel.process.start_requested",
            "kernel.process.owner_admitted",
            "kernel.process.owner_rejected",
            "process_contract",
            "process_not_found",
            "process_unavailable",
            "process_evidence_sink",
            "process_unknown_outcome",
        ] {
            assert!(text.contains(marker), "missing diagnostics marker {marker}");
        }
        for canary in ["top-secret-canary", "super-secret-canary"] {
            assert!(!text.contains(canary), "secret canary leaked: {canary}");
        }
    }
}
