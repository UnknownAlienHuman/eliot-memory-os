//! Kernel-owned ChangeMonitor ledger (issue #1824, I10.21).
//!
//! I10.21 requires that `ChangeMonitor` "combines host events, filesystem
//! notifications, Git reconciliation, process/tool receipts, and artifact
//! scans", that it "records exact before/after resources and revisions,
//! origin attribution confidence, associated Session/ActionLease/tool
//! operation/attempt, unknown-origin changes, diff/artifact/operation
//! handles, and State-Fence invalidations", and that "unknown-origin
//! Material mutation blocks governed acceptance until reconciliation".
//! This module is the Kernel-owned half of that contract: an in-memory
//! ledger over host/filesystem hint ingest, Git/content checksum/re-read
//! confirmation, governed-tool records, and the acceptance block the
//! host-request route queries. The Governor-owned semantic projection
//! lives in `eliot-change-monitor` under `crates/governor`; this module
//! must not depend on it (a `bins` root never depends on Governor/Smart
//! crates), it only mirrors the gate semantics: acceptance is blocked
//! while a hint is still unverified or an unknown-origin Material change
//! is still unreconciled.
//! I10.18 anchored review consumes admitted observations; this ledger
//! preserves immutable original identity (before-revisions are retained
//! and reconciliation appends a link instead of rewriting), so anchors
//! stay historically addressable. Resolver projection itself is a
//! separate lane and is not built here.
//!
//! Evidence rule: the Kernel never invents source bytes. Content checksums
//! are computed here with [`crate::sha256_hex`] over the exact bytes the
//! trusted readback caller supplies, and every record is keyed by its own
//! exact hint or operation identity: a lease/session/operation bound to
//! one operation is never reused for another.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

/// Typed ChangeMonitor failures. Every variant is constructed below; there
/// is no stringly error and no silent drop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ChangeMonitorError {
    /// The ledger lock is poisoned; callers fail closed.
    LedgerPoisoned,
    /// A hint or governed record fails shape validation.
    InvalidHint,
    /// Changed bytes replay under an already-bound hint identity.
    HintConflict,
    /// Confirmation names a hint the ledger never ingested.
    UnknownHint,
    /// The first content read and the independent re-read disagree, so the
    /// readback proves nothing about this operation.
    UnstableReadback,
    /// The Git readback evidence fails shape validation.
    InvalidGitEvidence,
    /// A governed-tool record is immaterial, unbound, or conflicts with the
    /// record already stored under its identity.
    InvalidGovernedChange,
    /// One operation identity is presented under a different lease/session
    /// than the operation that already owns it.
    OperationReuse,
    /// Reconciliation names an unknown-origin change the ledger never
    /// emitted.
    UnknownChange,
    /// Reconciliation evidence does not prove the exact recorded transition.
    TransitionMismatch,
}

impl std::fmt::Display for ChangeMonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::LedgerPoisoned => "change_monitor_ledger_poisoned",
            Self::InvalidHint => "change_monitor_invalid_hint",
            Self::HintConflict => "change_monitor_hint_conflict",
            Self::UnknownHint => "change_monitor_unknown_hint",
            Self::UnstableReadback => "change_monitor_unstable_readback",
            Self::InvalidGitEvidence => "change_monitor_invalid_git_evidence",
            Self::InvalidGovernedChange => "change_monitor_invalid_governed_change",
            Self::OperationReuse => "change_monitor_operation_reuse",
            Self::UnknownChange => "change_monitor_unknown_change",
            Self::TransitionMismatch => "change_monitor_transition_mismatch",
        };
        f.write_str(code)
    }
}

impl std::error::Error for ChangeMonitorError {}

/// Host/filesystem route of one untrusted hint. Only these two origins may
/// enter the ledger as hints; Git/tool/artifact origins belong to the
/// Governor-owned adapter and arrive here only as readback evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HintOrigin {
    HostEvent,
    FilesystemNotification,
}

/// Untrusted host/filesystem event: a re-check hint, never a Material
/// observation by itself.
///
/// STITCH (#1824, I10.21 W2): the designated caller is the host/filesystem
/// hint emitter owned by Governor adapter work; it does not exist
/// Kernel-side yet, so no in-tree caller constructs this today.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelChangeHint {
    pub hint_id: String,
    pub resource: String,
    pub path: String,
    pub origin: HintOrigin,
    pub origin_ref: Option<String>,
}

/// One direct content read: the exact bytes hashed, or absence for a
/// confirmed deletion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ContentRead {
    Present { sha256: String },
    Absent,
}

impl ContentRead {
    fn digest(&self) -> Option<&str> {
        match self {
            Self::Present { sha256 } => Some(sha256.as_str()),
            Self::Absent => None,
        }
    }
}

/// Read-only Git evidence bound by the adapter to the same hinted path as
/// the two direct content reads. The adapter constructs it only from
/// successful read-only Git invocations; the Kernel checks shapes and
/// digest agreement, never repository semantics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GitReadback {
    pub repository: String,
    pub head_before: String,
    pub head_after: String,
    pub status_ref: String,
    pub status_sha256: String,
    pub before_revision: Option<String>,
    pub after_revision: Option<String>,
    pub diff_handle: Option<String>,
}

/// Trusted confirmation evidence for one pending hint: the admitted
/// baseline, two independent content reads that must agree, and the bound
/// Git readback. The adapter performs the real reads; the Kernel confirms
/// stability and materiality against the exact operation's evidence.
///
/// STITCH (#1824, I10.21 W2): the designated caller is the Governor
/// change-monitor adapter performing real content/Git readback; it does
/// not exist Kernel-side yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HintVerification {
    pub before_digest: Option<String>,
    pub first_read: ContentRead,
    pub reread: ContentRead,
    pub git: GitReadback,
}

/// Governed-tool mutation record (I10.21 A1): exact before/after revisions
/// with the exact bytes the adapter read back, the associated
/// Session/ActionLease/tool operation/attempt, the diff handle, and the
/// observed State-Fence invalidation. The Kernel hashes the supplied bytes
/// itself and drops them; only digests are retained.
///
/// STITCH (#1824, I10.21 A1): the designated caller is the Governor
/// change-monitor adapter on the reconcile path (via the
/// `GovernedProcessEffectPort` once its receipt carries revisions); it
/// does not exist Kernel-side yet.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GovernedToolChange {
    pub change_id: String,
    pub resource: String,
    pub path: String,
    pub before_path: Option<String>,
    pub before_revision: Option<String>,
    pub before_bytes: Option<Vec<u8>>,
    pub after_revision: Option<String>,
    pub after_bytes: Option<Vec<u8>>,
    pub session: String,
    pub action_lease: String,
    pub operation: String,
    pub attempt_receipt: String,
    pub diff_handle: String,
    pub fence_generation: u64,
    pub fence_invalidated: bool,
}

/// Admission of one hint: accepted for verification, or replayed when the
/// exact hint was already ingested.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HintAdmission {
    Accepted,
    Replayed,
}

/// Outcome of confirming one hint: either the re-read proves no Material
/// transition, or a Material transition was recorded (with whether
/// matching governed evidence already reconciled it).
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum HintConfirmation {
    VerifiedImmaterial,
    MaterialRecorded { change_id: String, reconciled: bool },
}

/// Admission of one governed-tool record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GovernedAdmission {
    Accepted,
    Replayed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct HintEntry {
    hint: KernelChangeHint,
    confirmation: Option<HintConfirmation>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct GovernedChangeRecord {
    resource: String,
    path: String,
    before_path: Option<String>,
    before_revision: Option<String>,
    before_digest: Option<String>,
    after_revision: Option<String>,
    after_digest: Option<String>,
    session: String,
    action_lease: String,
    operation: String,
    attempt_receipt: String,
    diff_handle: String,
    fence_generation: u64,
    fence_invalidated: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UnknownOriginRecord {
    resource: String,
    after_digest: Option<String>,
    transition_digest: String,
    reconciled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UnknownReconciliation {
    unknown_change_id: String,
    evidence_change_id: String,
}

#[derive(Default)]
struct KernelChangeLedger {
    hints: BTreeMap<String, HintEntry>,
    governed: BTreeMap<String, GovernedChangeRecord>,
    governed_by_operation: BTreeMap<String, String>,
    unknown: BTreeMap<String, UnknownOriginRecord>,
    reconciliations: Vec<UnknownReconciliation>,
}

static CHANGE_LEDGER: OnceLock<Mutex<KernelChangeLedger>> = OnceLock::new();

fn ledger() -> Result<std::sync::MutexGuard<'static, KernelChangeLedger>, ChangeMonitorError> {
    CHANGE_LEDGER
        .get_or_init(|| Mutex::new(KernelChangeLedger::default()))
        .lock()
        .map_err(|_| ChangeMonitorError::LedgerPoisoned)
}

fn text(value: &str) -> bool {
    !value.trim().is_empty() && !value.chars().any(char::is_control)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_relative_path(value: &str) -> bool {
    text(value)
        && !value.starts_with('/')
        && !value.starts_with('\\')
        && !value.contains('\\')
        && !value.contains(':')
        && !value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
}

fn validate_hint(hint: &KernelChangeHint) -> Result<(), ChangeMonitorError> {
    if !text(&hint.hint_id)
        || !text(&hint.resource)
        || !validate_relative_path(&hint.path)
    {
        return Err(ChangeMonitorError::InvalidHint);
    }
    if let Some(origin_ref) = &hint.origin_ref
        && !text(origin_ref)
    {
        return Err(ChangeMonitorError::InvalidHint);
    }
    Ok(())
}

fn validate_git(git: &GitReadback) -> Result<(), ChangeMonitorError> {
    if !text(&git.repository)
        || !text(&git.head_before)
        || !text(&git.head_after)
        || !text(&git.status_ref)
        || !is_sha256_hex(&git.status_sha256)
    {
        return Err(ChangeMonitorError::InvalidGitEvidence);
    }
    for revision in [&git.before_revision, &git.after_revision]
        .into_iter()
        .flatten()
    {
        if !text(revision) {
            return Err(ChangeMonitorError::InvalidGitEvidence);
        }
    }
    if let Some(diff_handle) = &git.diff_handle
        && !text(diff_handle)
    {
        return Err(ChangeMonitorError::InvalidGitEvidence);
    }
    Ok(())
}

fn validate_verification(verification: &HintVerification) -> Result<(), ChangeMonitorError> {
    if let Some(before_digest) = &verification.before_digest
        && !is_sha256_hex(before_digest)
    {
        return Err(ChangeMonitorError::InvalidGitEvidence);
    }
    for read in [&verification.first_read, &verification.reread] {
        if let ContentRead::Present { sha256 } = read
            && !is_sha256_hex(sha256)
        {
            return Err(ChangeMonitorError::InvalidGitEvidence);
        }
    }
    validate_git(&verification.git)
}

/// Ingests one untrusted host/filesystem hint as a pending re-check (I10.21
/// W2, first half). A pending hint is not a Material observation, but it
/// blocks governed acceptance until a verified readback resolves it.
///
/// STITCH (#1824, I10.21 W2): see [`KernelChangeHint`] for the designated
/// caller.
pub(crate) fn ingest_hint(hint: KernelChangeHint) -> Result<HintAdmission, ChangeMonitorError> {
    validate_hint(&hint)?;
    let mut ledger = ledger()?;
    if let Some(existing) = ledger.hints.get(&hint.hint_id) {
        if existing.hint != hint {
            return Err(ChangeMonitorError::HintConflict);
        }
        return Ok(HintAdmission::Replayed);
    }
    ledger.hints.insert(
        hint.hint_id.clone(),
        HintEntry {
            hint,
            confirmation: None,
        },
    );
    Ok(HintAdmission::Accepted)
}

/// Confirms one pending hint with trusted content and Git readback
/// evidence (I10.21 W2, second half). The two content reads must agree or
/// the readback proves nothing; a Material transition (after digest
/// differs from the admitted baseline) emits an unknown-origin Material
/// change (I10.21 A2), reconciled immediately only when a recorded
/// governed change already proves the exact same resource transition.
///
/// STITCH (#1824, I10.21 W2/A2): see [`HintVerification`] for the
/// designated caller.
pub(crate) fn confirm_hint(
    hint_id: &str,
    verification: HintVerification,
) -> Result<HintConfirmation, ChangeMonitorError> {
    validate_verification(&verification)?;
    if verification.first_read != verification.reread {
        return Err(ChangeMonitorError::UnstableReadback);
    }
    let mut ledger = ledger()?;
    if let Some(confirmed) = ledger
        .hints
        .get(hint_id)
        .ok_or(ChangeMonitorError::UnknownHint)?
        .confirmation
        .clone()
    {
        return Ok(confirmed);
    }
    let after_digest = verification.reread.digest().map(str::to_owned);
    if verification.before_digest.as_deref() == after_digest.as_deref() {
        let entry = ledger
            .hints
            .get_mut(hint_id)
            .ok_or(ChangeMonitorError::UnknownHint)?;
        entry.confirmation = Some(HintConfirmation::VerifiedImmaterial);
        return Ok(HintConfirmation::VerifiedImmaterial);
    }
    let transition_preimage = format!(
        "{}>{}",
        verification.before_digest.as_deref().unwrap_or("absent"),
        after_digest.as_deref().unwrap_or("absent")
    );
    let change_id = format!("cmu:{hint_id}:{}", crate::sha256_hex(transition_preimage.as_bytes()));
    let resource = ledger
        .hints
        .get(hint_id)
        .ok_or(ChangeMonitorError::UnknownHint)?
        .hint
        .resource
        .clone();
    let reconciled = ledger
        .governed
        .values()
        .any(|record| record.resource == resource && record.after_digest == after_digest);
    let evidence_id = ledger
        .governed
        .iter()
        .find(|(_, record)| record.resource == resource && record.after_digest == after_digest)
        .map(|(evidence_id, _)| evidence_id.clone());
    ledger
        .unknown
        .entry(change_id.clone())
        .or_insert(UnknownOriginRecord {
            resource: resource.clone(),
            after_digest: after_digest.clone(),
            transition_digest: crate::sha256_hex(transition_preimage.as_bytes()),
            reconciled,
        });
    if reconciled {
        if let Some(evidence_id) = evidence_id {
            ledger.reconciliations.push(UnknownReconciliation {
                unknown_change_id: change_id.clone(),
                evidence_change_id: evidence_id,
            });
        }
    }
    let entry = ledger
        .hints
        .get_mut(hint_id)
        .ok_or(ChangeMonitorError::UnknownHint)?;
    entry.confirmation = Some(HintConfirmation::MaterialRecorded {
        change_id: change_id.clone(),
        reconciled,
    });
    Ok(HintConfirmation::MaterialRecorded {
        change_id,
        reconciled,
    })
}

/// Records one governed-tool mutation with exact before/after revisions,
/// the associated attempt/tool operation, the diff handle, and the
/// observed State-Fence invalidation (I10.21 A1). Content checksums are
/// computed here over the exact bytes supplied; the bytes are dropped and
/// only digests retained. A recorded governed transition reconciles the
/// matching unknown-origin change for the exact same resource transition.
/// History is never rewritten: an exact replay is reported, a conflicting
/// identity is refused, and a lease/session/operation owned by another
/// operation is never reused.
///
/// STITCH (#1824, I10.21 A1): see [`GovernedToolChange`] for the
/// designated caller.
pub(crate) fn record_governed_tool_change(
    change: GovernedToolChange,
) -> Result<GovernedAdmission, ChangeMonitorError> {
    if !text(&change.change_id)
        || !text(&change.resource)
        || !validate_relative_path(&change.path)
        || !text(&change.session)
        || !text(&change.action_lease)
        || !text(&change.operation)
        || !text(&change.attempt_receipt)
        || !text(&change.diff_handle)
    {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    }
    if let Some(before_path) = &change.before_path
        && !validate_relative_path(before_path)
    {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    }
    for revision in [&change.before_revision, &change.after_revision]
        .into_iter()
        .flatten()
    {
        if !text(revision) {
            return Err(ChangeMonitorError::InvalidGovernedChange);
        }
    }
    let before_digest = change
        .before_bytes
        .as_deref()
        .map(crate::sha256_hex);
    let after_digest = change.after_bytes.as_deref().map(crate::sha256_hex);
    if before_digest == after_digest {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    }
    let record = GovernedChangeRecord {
        resource: change.resource.clone(),
        path: change.path.clone(),
        before_path: change.before_path.clone(),
        before_revision: change.before_revision.clone(),
        before_digest: before_digest.clone(),
        after_revision: change.after_revision.clone(),
        after_digest: after_digest.clone(),
        session: change.session.clone(),
        action_lease: change.action_lease.clone(),
        operation: change.operation.clone(),
        attempt_receipt: change.attempt_receipt.clone(),
        diff_handle: change.diff_handle.clone(),
        fence_generation: change.fence_generation,
        fence_invalidated: change.fence_invalidated,
    };
    let mut ledger = ledger()?;
    if let Some(bound) = ledger.governed_by_operation.get(&change.operation).cloned() {
        if bound != change.change_id {
            return Err(ChangeMonitorError::OperationReuse);
        }
    }
    if let Some(existing) = ledger.governed.get(&change.change_id) {
        if *existing != record {
            return Err(ChangeMonitorError::InvalidGovernedChange);
        }
        return Ok(GovernedAdmission::Replayed);
    }
    ledger
        .governed_by_operation
        .insert(change.operation.clone(), change.change_id.clone());
    ledger.governed.insert(change.change_id.clone(), record);
    let matched: Vec<(String, String)> = ledger
        .unknown
        .iter()
        .filter(|(_, unknown)| {
            !unknown.reconciled
                && unknown.resource == change.resource
                && unknown.after_digest == after_digest
        })
        .map(|(unknown_id, _)| (unknown_id.clone(), change.change_id.clone()))
        .collect();
    for (unknown_id, evidence_id) in matched {
        if let Some(unknown) = ledger.unknown.get_mut(&unknown_id) {
            unknown.reconciled = true;
        }
        ledger.reconciliations.push(UnknownReconciliation {
            unknown_change_id: unknown_id,
            evidence_change_id: evidence_id,
        });
    }
    Ok(GovernedAdmission::Accepted)
}

/// Reconciles one unknown-origin Material change against admitted evidence
/// proving the exact same transition (I10.21 A2). The original record is
/// preserved: reconciliation appends a link instead of rewriting history,
/// so human correction keeps the original observation addressable.
///
/// STITCH (#1824, I10.21 A2): the designated caller is the Governor
/// reconciliation entry admitting the evidence; it does not exist
/// Kernel-side yet.
pub(crate) fn reconcile_unknown_change(
    change_id: &str,
    evidence_transition_digest: &str,
) -> Result<(), ChangeMonitorError> {
    if !text(change_id) || !is_sha256_hex(evidence_transition_digest) {
        return Err(ChangeMonitorError::UnknownChange);
    }
    let mut ledger = ledger()?;
    let unknown = ledger
        .unknown
        .get_mut(change_id)
        .ok_or(ChangeMonitorError::UnknownChange)?;
    if unknown.transition_digest != evidence_transition_digest {
        return Err(ChangeMonitorError::TransitionMismatch);
    }
    if unknown.reconciled {
        return Ok(());
    }
    unknown.reconciled = true;
    ledger.reconciliations.push(UnknownReconciliation {
        unknown_change_id: change_id.to_owned(),
        evidence_change_id: format!("transition:{evidence_transition_digest}"),
    });
    Ok(())
}

/// Returns whether governed acceptance is currently blocked: a
/// host/filesystem hint is still unverified, or an unknown-origin
/// Material change is still unreconciled (I10.21 A2). A poisoned ledger
/// fails closed. This mirrors the Governor-side `blocks_acceptance`
/// gate for the Kernel-owned finish leg.
///
/// Caller: `host_request_route::daemon_claim_queue::submit_finish_result`.
pub(crate) fn governed_acceptance_blocked() -> bool {
    let ledger = match ledger() {
        Ok(ledger) => ledger,
        Err(_) => return true,
    };
    ledger.hints.values().any(|entry| entry.confirmation.is_none())
        || ledger.unknown.values().any(|unknown| !unknown.reconciled)
}
