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
//! ledger over host-event/filesystem hint ingest, content checksum/re-read
//! confirmation, governed-tool records, and the acceptance block the
//! host-request route queries. The sole in-tree producer is the Kernel
//! process-effect lane (`crate::process_execution::KernelGovernedProcessEffectPort`,
//! attached in the owning crate): it opens the lease-owned governed image,
//! checksums exact bytes twice per observation, and confirms each hint with
//! pairwise-independent reads, so the Material branch is reachable on real
//! transitions instead of comparing one digest with itself. No VCS substrate
//! is claimed: confirmations carry `git: None` until a real Git-state port
//! exists (see `HintVerification`), and the ledger never invents source
//! bytes or repository state. The Governor-owned semantic projection
//! lives in `eliot-change-monitor` under `crates/governor`; this module
//! must not depend on it (a `bins` root never depends on Governor/Smart
//! crates), it only mirrors the gate semantics: acceptance is blocked
//! while a hint is still unverified or an unknown-origin Material change
//! is still unreconciled.
//! I10.18 anchored review consumes admitted observations; this ledger
//! preserves immutable original identity (before-revisions are retained
//! and reconciliation appends a link instead of rewriting), so anchors
//! stay historically addressable. A proven deletion (two agreeing `Absent`
//! reads from the production readback lane against a retained baseline)
//! is stored as an immutable deletion observation (`after_digest: None`,
//! I10.21 A4) and surfaced through [`deletion_observations_for`] for the
//! resolver's historically addressable `deleted` result. Resolver
//! projection itself is a separate lane and is not built here.
//!
//! Evidence rule: the Kernel never invents source bytes. Content checksums
//! are computed here with [`crate::sha256_hex`] over the exact bytes the
//! trusted readback caller supplies, and every record is keyed by its own
//! exact hint or operation identity: a lease/session/operation bound to
//! one operation is never reused for another.

use std::collections::{BTreeMap, btree_map::Entry};
use std::sync::{Mutex, OnceLock};

/// Typed `ChangeMonitor` failures. Every variant is constructed below; there
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

/// Route of one untrusted hint observed Kernel-side. The Kernel
/// process-effect lane is the only in-crate producer, and it constructs
/// both origins: `HostEvent` for an admitted tool operation whose effect is
/// read back, `FilesystemNotification` for a tracked-image transition the
/// pre-effect capture observes against independently retained state that no
/// admission explains. Filesystem, Git, tool, and artifact semantics beyond
/// that live in the Governor-owned projection (`eliot-change-monitor`
/// under `crates/governor`); Git state in particular is never claimed here
/// (confirmations carry no VCS substrate), so a filesystem-sourced
/// transition surfaces as an unknown-origin Material change on real
/// content evidence, never as an invented repository claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HintOrigin {
    HostEvent,
    FilesystemNotification,
}

/// Untrusted host event: a re-check hint, never a Material observation by
/// itself.
///
/// Caller (I10.21 W2): `crate::process_execution::KernelGovernedProcessEffectPort`,
/// which ingests each governed tool operation as a host-event hint and each
/// unexplained tracked-image transition as a filesystem hint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelChangeHint {
    pub hint_id: String,
    pub resource: String,
    pub path: String,
    pub origin: HintOrigin,
    pub origin_ref: Option<String>,
}

/// One direct content read: the exact bytes hashed, or the proven absence
/// of the tracked path. `Absent` is deletion evidence (I10.21 AUD5, audit
/// 5910747803): two agreeing not-found reads from the production readback
/// lane (`content_read_for` in `crate::process_execution`). Any other read
/// failure is not representable here and must stay outside baselines and
/// receipts — it proves nothing and never becomes a deletion observation.
///
/// Admitted here and bound by content compare in [`confirm_hint`]: the two
/// reads must agree, and only agreement against a retained present baseline
/// mints a deletion observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ContentRead {
    Present { sha256: String },
    Absent,
}

impl ContentRead {
    fn digest(&self) -> Option<&str> {
        match self {
            Self::Present { sha256 } => Some(sha256),
            Self::Absent => None,
        }
    }
}

/// Readback evidence bound to the same hinted artifact as the two direct
/// content reads. `None` is the explicit no-VCS-substrate claim: the Kernel
/// owns no Git-state port, so confirmations decide on content checksum and
/// re-read evidence alone instead of inventing repository state. A `Some`
/// value must pass [`validate_git`]; half-filled repository claims are
/// refused rather than confirmed.
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

/// Trusted confirmation evidence for one hint: the independently retained
/// baseline, two independent content reads that must agree, and optional
/// readback evidence. The Kernel process-effect lane supplies pairwise-
/// independent values: the baseline digest retained at pre-effect capture,
/// and two separate file opens at readback. Agreement of the two reads
/// proves stability; agreement with the baseline proves immateriality; any
/// other outcome is a Material transition, never a self-comparison.
///
/// Caller (I10.21 W2): `crate::process_execution::KernelGovernedProcessEffectPort`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HintVerification {
    pub before_digest: Option<String>,
    pub first_read: ContentRead,
    pub reread: ContentRead,
    pub git: Option<GitReadback>,
}

/// Governed-tool mutation record (I10.21 A1): exact before/after revisions
/// with the exact bytes read back on the completing path, the associated
/// session, fenced-attempt lease, tool operation, and attempt receipt, the
/// diff handle, and the observed State-Fence invalidation. The Kernel
/// hashes the supplied bytes itself and drops them; only digests are
/// retained.
///
/// Ingress contract (fail-closed): at least one content side must be real
/// bytes the producing lane read back, so the ledger hashes source truth
/// instead of envelope identity. `before_bytes: None` with `after_bytes:
/// Some` is a creation, `before_bytes: Some` with `after_bytes: None` is a
/// deletion (I10.21 A4, audit 5910747803); both `None` carries no pair at
/// all and both `Some` with equal digests carries no transition, so both
/// are refused with [`ChangeMonitorError::InvalidGovernedChange`]. The
/// `diff_handle` must be the exact transition digest for `(change_id,
/// before, after)` — a copied unrelated digest does not resolve and is
/// refused with [`ChangeMonitorError::InvalidGovernedChange`]. The fence fields must be
/// the joined generation and the invalidation outcome the producing lane
/// actually observed. A lane that observed only its own IPC envelope
/// (request/result digests, no tracked-source bytes) cannot satisfy this
/// contract; its record is refused, never stored as source identity.
///
/// Caller (I10.21 A1):
/// `crate::process_execution::KernelGovernedProcessEffectPort::ingest`,
/// which feeds the record from real pre-effect/terminal readback bytes.
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
    before_digest: Option<String>,
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
    if !text(&hint.hint_id) || !text(&hint.resource) || !validate_relative_path(&hint.path) {
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
        // A `Present` side must carry exact sha256 hex, while `Absent`
        // carries no digest at all (absence is bound by the agreement
        // check in `confirm_hint`, never by a digest).
        if let Some(digest) = read.digest()
            && !is_sha256_hex(digest)
        {
            return Err(ChangeMonitorError::InvalidGitEvidence);
        }
    }
    if let Some(git) = &verification.git {
        validate_git(git)?;
    }
    Ok(())
}

/// Builds the idempotent hint identity for one governed tool operation.
///
/// The same operation handle always maps to the same hint, so an exact
/// re-ingest of the same hint replays instead of conflicting. A retry that
/// observes new evidence re-evaluates under the same identity
/// ([`confirm_hint`] follows the latest evidence, never a stale
/// confirmation).
pub(crate) fn host_hint_id(operation_id: &str) -> String {
    format!("cmh:{operation_id}")
}

/// Builds the hint identity for one filesystem-observed artifact
/// transition: the lane-stable artifact digest plus the exact before digest
/// the transition leaves. A later transition from a new before digest is a
/// new hint, so a second uncorrelated mutation is never swallowed by the
/// first confirmation.
pub(crate) fn filesystem_hint_id(artifact_digest: &str, before_digest: &str) -> String {
    format!("cmf:{artifact_digest}:{before_digest}")
}

/// Ingests one untrusted hint as a pending re-check (I10.21 W2,
/// first half). A pending hint is not a Material observation, but it blocks
/// governed acceptance until a verified readback resolves it.
///
/// Caller (I10.21 W2): `crate::process_execution::KernelGovernedProcessEffectPort`.
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

/// Derives the unknown-origin change identity and transition digest for one
/// Material transition.
///
/// The transition digest binds the exact before/after pair (`"absent"` for
/// a missing side); the change identity scopes it to the hint that
/// observed it. Shared by [`confirm_hint`] and the effect-lane
/// reconciliation attempt so both name the same transition the same way.
pub(crate) fn material_transition_ids(
    hint_id: &str,
    before_digest: Option<&str>,
    after_digest: Option<&str>,
) -> (String, String) {
    let preimage = format!(
        "{}>{}",
        before_digest.unwrap_or("absent"),
        after_digest.unwrap_or("absent")
    );
    let transition_digest = crate::sha256_hex(preimage.as_bytes());
    (
        format!("cmu:{hint_id}:{transition_digest}"),
        transition_digest,
    )
}

/// Confirms one hint with trusted content and readback evidence (I10.21
/// W2, second half). The two content reads must agree or the readback
/// proves nothing; an `Absent` pair against an absent baseline is
/// immaterial, while a Material transition (after state differs from the
/// retained baseline, including creation and deletion) emits an
/// unknown-origin Material change (I10.21 A2), reconciled immediately only
/// when a recorded governed change already proves the exact same resource
/// transition (same before and after digests, not merely the same after
/// bytes). A proven deletion (present baseline, agreeing `Absent` reads)
/// becomes the immutable deletion observation (`after_digest: None`) the
/// resolver needs for a historically addressable `deleted` result (see
/// [`deletion_observations_for`]; I10.21 A4, audit 5910747803).
///
/// Confirmation is evidence-driven, never sticky: identical evidence
/// replays the identical outcome, while new evidence under a retried
/// operation re-evaluates and emits the transition it actually proves.
/// History is still never rewritten: unknown records are keyed by their
/// exact transition and reconciliation only appends links.
///
/// Caller (I10.21 W2):
/// `crate::process_execution::KernelGovernedProcessEffectPort`.
pub(crate) fn confirm_hint(
    hint_id: &str,
    verification: &HintVerification,
) -> Result<HintConfirmation, ChangeMonitorError> {
    validate_verification(verification)?;
    if verification.first_read != verification.reread {
        return Err(ChangeMonitorError::UnstableReadback);
    }
    let after_digest = verification.reread.digest().map(str::to_owned);
    let before_digest = verification.before_digest.clone();
    let (change_id, transition_digest) =
        material_transition_ids(hint_id, before_digest.as_deref(), after_digest.as_deref());
    let mut ledger = ledger()?;
    let resource = ledger
        .hints
        .get(hint_id)
        .ok_or(ChangeMonitorError::UnknownHint)?
        .hint
        .resource
        .clone();
    if before_digest == after_digest {
        let entry = ledger
            .hints
            .get_mut(hint_id)
            .ok_or(ChangeMonitorError::UnknownHint)?;
        entry.confirmation = Some(HintConfirmation::VerifiedImmaterial);
        return Ok(HintConfirmation::VerifiedImmaterial);
    }
    let evidence_id = ledger
        .governed
        .iter()
        .find(|(_, record)| {
            record.resource == resource
                && record.before_digest == before_digest
                && record.after_digest == after_digest
        })
        .map(|(evidence_id, _)| evidence_id.clone());
    let reconciled = evidence_id.is_some();
    let newly_reconciled = match ledger.unknown.entry(change_id.clone()) {
        Entry::Vacant(slot) => {
            slot.insert(UnknownOriginRecord {
                resource,
                before_digest,
                after_digest: after_digest.clone(),
                transition_digest,
                reconciled,
            });
            reconciled
        }
        Entry::Occupied(mut slot) => {
            let unknown = slot.get_mut();
            let newly = !unknown.reconciled && reconciled;
            if newly {
                unknown.reconciled = true;
            }
            newly
        }
    };
    if newly_reconciled && let Some(evidence_id) = evidence_id {
        ledger.reconciliations.push(UnknownReconciliation {
            unknown_change_id: change_id.clone(),
            evidence_change_id: evidence_id,
        });
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
/// the associated session, fenced-attempt lease, tool operation, and
/// attempt receipt, the diff handle, and the observed State-Fence
/// invalidation (I10.21 A1). Content checksums are computed here over the
/// exact bytes supplied; the bytes are dropped and only digests retained.
/// A creation carries `before_bytes: None`, a deletion carries
/// `after_bytes: None`; a record with neither side, with agreeing present
/// sides, or whose diff handle does not name its exact before/after
/// transition, is refused: the ledger stores source identity, never
/// envelope identity. A recorded governed transition reconciles the
/// matching unknown-origin change for the exact same resource transition,
/// including a governed deletion against its deletion observation.
/// History is never rewritten: an exact replay is reported, a conflicting
/// identity is refused, and a lease/session/operation owned by another
/// operation is never reused.
///
/// Caller (I10.21 A1):
/// `crate::process_execution::KernelGovernedProcessEffectPort::ingest`.
pub(crate) fn record_governed_tool_change(
    change: &GovernedToolChange,
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
    let before_digest = change.before_bytes.as_deref().map(crate::sha256_hex);
    let after_digest = change.after_bytes.as_deref().map(crate::sha256_hex);
    // I10.21 A1 (AUD5): at least one content side must be real bytes the
    // producing lane read back. `None` on exactly one side is the
    // creation/deletion shape; `None` on both sides means no source
    // identity exists for either side (an envelope/request digest is
    // operation identity, not content), so there is no before/after pair
    // to record.
    if before_digest.is_none() && after_digest.is_none() {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    }
    if before_digest.is_some() && before_digest == after_digest {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    }
    // I10.21 A1: the diff handle must resolve to the exact recorded
    // transition through the ledger's own transition binder (shared with
    // `confirm_hint` and the finish-leg reconciliation, never a second
    // resolver). A byte copy of an unrelated digest names no transition
    // this ledger recorded and is refused.
    let (_, transition_digest) = material_transition_ids(
        &change.change_id,
        before_digest.as_deref(),
        after_digest.as_deref(),
    );
    if change.diff_handle != transition_digest {
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
    if let Some(bound) = ledger.governed_by_operation.get(&change.operation).cloned()
        && bound != change.change_id
    {
        return Err(ChangeMonitorError::OperationReuse);
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
                && unknown.before_digest == before_digest
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
/// Caller (I10.21 A2):
/// `crate::process_execution::KernelGovernedProcessEffectPort::ingest`,
/// which reconciles the operation's exact transition when the ledger
/// accepted its governed record.
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

/// One immutable deletion observation for the resolver projection (I10.21
/// A4, audit 5910747803): the ledger identity of a proven tracked-target
/// deletion plus the exact before-state it deletes from. The observation
/// stays addressable after reconciliation (history is never rewritten),
/// so an old review anchor over a deleted target resolves to historically
/// addressable `deleted` instead of vanishing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeletionObservation {
    pub change_id: String,
    pub transition_digest: String,
    pub before_digest: Option<String>,
}

/// Resolver-visible deleted status for one tracked resource (I10.21 A4,
/// I10.18 anchored review): every immutable deletion observation the
/// ledger proved for `resource` — unknown-origin records whose after-state
/// is proven absent (`after_digest: None`), in ledger (change-id) order.
/// Only [`confirm_hint`] mints these, from agreeing `Absent` reads against
/// a retained baseline, so a read failure or an unobserved path can never
/// appear here: absence from this list means no proven deletion, never a
/// silent erase. A poisoned ledger yields no observations here; the global
/// acceptance gate ([`governed_acceptance_blocked`]) already fails closed,
/// so callers must still consult it before accepting governed work.
///
/// Caller: the Kernel process-effect lane in `crate::process_execution`,
/// which consults the minted observations for the exact transition before
/// re-confirming a standing deletion, and the anchored-review/resolver
/// lane resolving an old anchor whose target no longer exists.
pub(crate) fn deletion_observations_for(resource: &str) -> Vec<DeletionObservation> {
    let Ok(ledger) = ledger() else {
        return Vec::new();
    };
    ledger
        .unknown
        .iter()
        .filter(|(_, unknown)| {
            unknown.resource.as_str() == resource && unknown.after_digest.is_none()
        })
        .map(|(change_id, unknown)| DeletionObservation {
            change_id: change_id.clone(),
            transition_digest: unknown.transition_digest.clone(),
            before_digest: unknown.before_digest.clone(),
        })
        .collect()
}

/// Returns whether governed acceptance is currently blocked: a host-event
/// hint is still unverified, or an unknown-origin Material change is still
/// unreconciled (I10.21 A2). A poisoned ledger fails closed. This mirrors
/// the Governor-side `blocks_acceptance` gate for the Kernel-owned finish
/// leg.
///
/// Caller: `host_request_route::daemon_claim_queue::submit_finish_result`.
pub(crate) fn governed_acceptance_blocked() -> bool {
    let Ok(ledger) = ledger() else {
        return true;
    };
    ledger
        .hints
        .values()
        .any(|entry| entry.confirmation.is_none())
        || ledger.unknown.values().any(|unknown| !unknown.reconciled)
}

/// Returns whether governed acceptance for one tracked resource is
/// currently blocked: a hint naming that resource is still unverified, or
/// an unknown-origin Material change naming that resource is still
/// unreconciled (I10.21 A2, per-resource scope).
///
/// Scoping is by the tracked source identity carried on the admitted hint
/// (`KernelChangeHint::resource`) and preserved on the unknown-origin
/// record derived from it. Both blocking sets of the global gate above are
/// covered with the same predicates, so completeness matches the global
/// gate restricted to one resource: a candidate touching a blocked
/// resource still waits for explicit reconciliation of that resource, while
/// an out-of-lane re-pin (or any external mutation) of another resource
/// cannot wedge its acceptance. A poisoned ledger fails closed. The
/// unknown-origin event itself is still emitted by [`confirm_hint`]; this
/// query only scopes the block, never clears it.
///
/// Caller (I10.21 A2):
/// `host_request_route::daemon_claim_queue::submit_finish_result`, which
/// carries the candidate resource from the admitted finish draft and keeps
/// the global gate above as fallback while the leg carries no resource.
pub(crate) fn governed_acceptance_blocked_for(resource: &str) -> bool {
    let Ok(ledger) = ledger() else {
        return true;
    };
    ledger
        .hints
        .values()
        .any(|entry| entry.confirmation.is_none() && entry.hint.resource.as_str() == resource)
        || ledger
            .unknown
            .values()
            .any(|unknown| !unknown.reconciled && unknown.resource.as_str() == resource)
}
