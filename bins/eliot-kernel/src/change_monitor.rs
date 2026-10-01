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
//! ledger over host-event/filesystem hint ingest, Git plus content
//! checksum/re-read confirmation, governed-tool records, and the acceptance
//! block the host-request route queries. Two producers feed it: the Kernel
//! process-effect lane (`crate::process_execution::KernelGovernedProcessEffectPort`,
//! attached in the owning crate) for host-event hints over the
//! admission-declared mutation set (one hint per declared target) plus its
//! poll-reconcile leg ([`observe_filesystem_notification`] with
//! [`HintOrigin::PollReconcile`]) for retained-digest transitions no
//! admission explains, and the same adapter with
//! [`HintOrigin::FilesystemNotification`] for received OS filesystem
//! notifications once the watcher lane attaches. The adapter opens the hinted tracked source twice per
//! observation and reads the real Git substrate (`.git/HEAD` plus the
//! resolved ref, loose or packed) around those reads, so a filesystem hint
//! confirms against actual Git/content re-read evidence instead of content
//! polling over one image. Two agreeing not-found observations confirm as
//! a proven deletion (an immutable unknown-origin deletion until
//! reconciled); any other read failure is refused, never a deletion claim.
//! A filesystem hint without that Git readback is
//! refused with [`ChangeMonitorError::InvalidGitEvidence`]: an inferred
//! transition no admission explains never becomes a `FilesystemNotification`
//! on polling alone. No porcelain status is claimed: the Kernel observes the
//! HEAD substrate read-only (see [`GitReadback`]), worktree status beyond
//! HEAD is decided by the content re-reads, and the ledger never invents
//! source bytes or repository state. The Governor-owned semantic projection
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
//! Durability: the ledger persists a versioned JSON sidecar under the
//! default work root (`.eliot/kernel-change-ledger.v1.json`, beside the
//! `kernel-ors.redb` precedent) after process-effect mutations, and the
//! finish-acceptance leg rehydrates it when this process started fresh.
//! Reads stay fail-closed: a poisoned lock blocks acceptance, tips never
//! advance past unconfirmed or unreconciled Material, and observation
//! failures against a previously observed tip leave an explicit
//! gap-marked unknown that blocks until a proven observation continues
//! from the same before-state. Crash-window boundary: a mutation recorded
//! in memory but not yet persisted is re-detected after restart by
//! comparing the restored tip against fresh reads, which re-emits the
//! unknown-origin record; the first-ever observation of a path establishes
//! the baseline silently because no oracle distinguishes pre-existing
//! bytes from placed ones.
//!
//! Evidence rule: the Kernel never invents source bytes. Content checksums
//! are computed here with [`crate::sha256_hex`] over the exact bytes the
//! trusted readback caller supplies, and every record is keyed by its own
//! exact hint or operation identity: a lease/session/operation bound to
//! one operation is never reused for another. Recorded before/after
//! revisions are bound to those same computed content digests, so a
//! governed record always names the mutated tracked source's identity,
//! never the tool executable image's.

use std::collections::{BTreeMap, btree_map::Entry};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

/// Typed `ChangeMonitor` failures. Every variant is constructed below; there
/// is no stringly error and no silent drop.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ChangeMonitorError {
    /// The ledger lock is poisoned; callers fail closed.
    LedgerPoisoned,
    /// A hint or governed record fails shape validation.
    InvalidHint,
    /// The observation transfer document cannot be encoded.
    TransferEncode,
    /// Changed bytes replay under an already-bound hint identity.
    HintConflict,
    /// Confirmation names a hint the ledger never ingested.
    UnknownHint,
    /// The first content read and the independent re-read disagree, the
    /// tracked source cannot be read twice, the Git substrate moved under
    /// observation, so the readback proves nothing about this operation.
    UnstableReadback,
    /// The Git readback evidence fails shape validation, or a filesystem
    /// hint arrives without any Git readback at all.
    InvalidGitEvidence,
    /// No readable Git substrate exists under the supplied workspace root
    /// (missing or unparsable `.git/HEAD`, unresolvable symref): the ledger
    /// invents no repository state, so Git-bound confirmation is refused.
    NoGitSubstrate,
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
    /// The durable ledger sidecar or observation transfer cannot be read
    /// or written.
    SidecarUnavailable,
    /// The durable ledger sidecar failed integrity validation.
    SidecarCorrupt,
}

impl std::fmt::Display for ChangeMonitorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let code = match self {
            Self::LedgerPoisoned => "change_monitor_ledger_poisoned",
            Self::InvalidHint => "change_monitor_invalid_hint",
            Self::TransferEncode => "change_monitor_transfer_encode",
            Self::HintConflict => "change_monitor_hint_conflict",
            Self::UnknownHint => "change_monitor_unknown_hint",
            Self::UnstableReadback => "change_monitor_unstable_readback",
            Self::InvalidGitEvidence => "change_monitor_invalid_git_evidence",
            Self::NoGitSubstrate => "change_monitor_no_git_substrate",
            Self::InvalidGovernedChange => "change_monitor_invalid_governed_change",
            Self::OperationReuse => "change_monitor_operation_reuse",
            Self::UnknownChange => "change_monitor_unknown_change",
            Self::TransitionMismatch => "change_monitor_transition_mismatch",
            Self::SidecarUnavailable => "change_monitor_sidecar_unavailable",
            Self::SidecarCorrupt => "change_monitor_sidecar_corrupt",
        };
        f.write_str(code)
    }
}

impl std::error::Error for ChangeMonitorError {}

/// Route of one untrusted hint observed Kernel-side. `HostEvent` is built
/// by the Kernel process-effect lane for an admitted tool operation whose
/// effect is read back; `FilesystemNotification` is built only by the
/// filesystem/Git observation adapter ([`observe_filesystem_notification`])
/// from a received OS notification (the future watcher lane) confirmed
/// against actual Git-substrate plus content re-read evidence;
/// `PollReconcile` is built by the same adapter for an inferred
/// declared-target transition the process-effect lane re-checks — real
/// evidence, honestly labeled, never an OS notification. Filesystem, tool,
/// and artifact semantics beyond that live in the Governor-owned projection
/// (`eliot-change-monitor` under `crates/governor`); the Kernel observes
/// the Git HEAD substrate read-only (see [`GitReadback`]) and performs no
/// porcelain status, so a filesystem-sourced transition surfaces as an
/// unknown-origin Material change on real content evidence, never as an
/// invented repository claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum HintOrigin {
    HostEvent,
    FilesystemNotification,
    PollReconcile,
}

/// Untrusted host event: a re-check hint, never a Material observation by
/// itself.
///
/// Caller (I10.21 W2): `crate::process_execution::KernelGovernedProcessEffectPort`
/// ingests each governed tool operation as a host-event hint and each
/// retained-digest transition as a poll-reconcile hint;
/// [`observe_filesystem_notification`] will ingest each received OS
/// filesystem notification as a filesystem hint with real Git-substrate
/// evidence once the watcher lane attaches.
///
/// Correlation (I10.21 W3): a host-event hint carries the Session,
/// `ActionLease`, tool operation, attempt receipt, and State-Fence generation
/// the producing lane claims for it — the claimant's identity, never proof
/// of who wrote the bytes. A filesystem hint carries none of these: an OS
/// notification names no governed claimant, so absent correlation is the
/// explicit uncertain-provenance classification, not a missing field. The
/// new correlation fields default for sidecars written before them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct KernelChangeHint {
    pub hint_id: String,
    pub resource: String,
    pub path: String,
    pub origin: HintOrigin,
    pub origin_ref: Option<String>,
    #[serde(default)]
    pub session: Option<String>,
    #[serde(default)]
    pub action_lease: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
    #[serde(default)]
    pub attempt_receipt: Option<String>,
    #[serde(default)]
    pub fence_generation: Option<u64>,
}

/// One direct content read: the exact bytes hashed, or the proven absence
/// of the tracked path. Absence is deletion/creation evidence (both
/// agreeing reads returned not-found); any other read failure is not
/// representable here and must stay outside baselines and receipts.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

fn is_git_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn resolve_git_dir(dot_git: &Path) -> Option<PathBuf> {
    if dot_git.is_dir() {
        return Some(dot_git.to_path_buf());
    }
    if dot_git.is_file() {
        let pointer = std::fs::read_to_string(dot_git).ok()?;
        let target = pointer.strip_prefix("gitdir:")?.trim();
        if target.is_empty() || target.len() > 1024 {
            return None;
        }
        let resolved = if Path::new(target).is_absolute() {
            PathBuf::from(target)
        } else {
            dot_git.parent()?.join(target)
        };
        if resolved.is_dir() {
            return Some(resolved);
        }
    }
    None
}

/// Readback evidence bound to the same hinted artifact as the two direct
/// content reads. `None` means the confirming lane supplied no Git
/// readback: accepted only for `HostEvent` hints, which decide on content
/// checksum and re-read evidence. A `FilesystemNotification` hint with
/// `None` is refused by [`confirm_hint`] with
/// [`ChangeMonitorError::InvalidGitEvidence`]. A `Some` value must pass
/// [`validate_git`]; half-filled repository claims are refused rather than
/// confirmed. The Kernel observes the Git HEAD substrate read-only and
/// performs no porcelain status: `status_ref`/`status_sha256` carry the
/// exact HEAD-substrate receipt the adapter read around the content reads
/// (SHA-256 over those exact substrate bytes, so the head values are bound
/// to real bytes, never invented), or are both absent when the confirming
/// lane observed no substrate; a half-filled pair is refused.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct GitReadback {
    pub repository: String,
    pub head_before: String,
    pub head_after: String,
    pub status_ref: Option<String>,
    pub status_sha256: Option<String>,
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
/// deletion; both `None` carries no pair at all and both `Some` with equal
/// digests carries no transition, so both are refused with
/// [`ChangeMonitorError::InvalidGovernedChange`]. `diff_handle` must be
/// the exact transition digest for `(change_id, before, after)` — a copied
/// unrelated digest does not resolve and is refused. The fence fields must
/// be the joined generation and the invalidation outcome the producing lane
/// actually observed. `before_revision`/`after_revision` must be the
/// ledger-computed before/after content digests (`None` exactly where the
/// matching bytes are `None`), so the recorded identity is the mutated
/// tracked source's, never the tool executable image's (audit 5910747803
/// AUD1). A lane that observed only its own IPC envelope
/// (request/result digests, no tracked-source bytes) cannot satisfy this
/// contract; its record is refused, never stored as source identity.
///
/// Caller (I10.21 A1):
/// `crate::process_execution::KernelGovernedProcessEffectPort::ingest`,
/// which feeds one record per declared target from real pre-effect/terminal
/// readback bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum HintAdmission {
    Accepted,
    Replayed,
}

/// Outcome of confirming one hint: either the re-read proves no Material
/// transition, or a Material transition was recorded (with whether
/// matching governed evidence already reconciled it).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum HintConfirmation {
    VerifiedImmaterial,
    MaterialRecorded { change_id: String, reconciled: bool },
}

/// Admission of one governed-tool record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum GovernedAdmission {
    Accepted,
    Replayed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct HintEntry {
    hint: KernelChangeHint,
    confirmation: Option<HintConfirmation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct UnknownOriginRecord {
    resource: String,
    before_digest: Option<String>,
    after_digest: Option<String>,
    transition_digest: String,
    reconciled: bool,
    /// A readback failure against a previously observed tip left this
    /// blocking marker instead of a proven transition (`after_digest` is
    /// unknown, not absent). It closes only when a proven observation for
    /// the same resource continues from the same before-state.
    #[serde(default)]
    unresolved_gap: bool,
    /// The observing lane's claimed correlation for a gap marker (I10.21
    /// W3): the Session, lease, operation, attempt, and fence generation
    /// the witness held when the observation failed. `None` for proven
    /// transitions (their claimant correlation lives on the governed record
    /// or the reconciling link) and for markers recorded before witness
    /// correlation existed. A witness names who observed the failure, never
    /// who wrote the bytes: uncertain provenance stays explicit.
    #[serde(default)]
    witness: Option<UnresolvedTransitionWitness>,
}

/// Witness correlation for one unresolved-transition marker (I10.21 W3):
/// the Session, `ActionLease`, tool operation, attempt receipt, and
/// State-Fence generation the observing lane claims for the failed
/// observation. Every field is validated like claimed hint correlation
/// (see [`validate_hint`]): present fields must be well-formed references,
/// and `operation` is always present because the marker identity (`cmx:`)
/// is keyed by it. Absent optionals mean the observing lane held no such
/// evidence, never an unattributed claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct UnresolvedTransitionWitness {
    pub session: Option<String>,
    pub action_lease: Option<String>,
    pub operation: String,
    pub attempt_receipt: Option<String>,
    pub fence_generation: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct UnknownReconciliation {
    unknown_change_id: String,
    evidence_change_id: String,
}

/// Last confirmed state of one tracked resource: the digest the ledger
/// last proved (`None` = last proved absent) plus the last confirmed
/// repository commit. Tips are the effect lane's retained baseline: the
/// external-transition detector compares fresh reads against them, and
/// they advance only on verified-immaterial or reconciled-material
/// confirmations — never past unconfirmed or unreconciled Material.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ResourceTip {
    pub digest: Option<String>,
    pub head_commit: Option<String>,
    pub repository: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct KernelChangeLedger {
    hints: BTreeMap<String, HintEntry>,
    governed: BTreeMap<String, GovernedChangeRecord>,
    governed_by_operation: BTreeMap<String, Vec<String>>,
    unknown: BTreeMap<String, UnknownOriginRecord>,
    reconciliations: Vec<UnknownReconciliation>,
    tips: BTreeMap<String, ResourceTip>,
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
    // I10.21 W3: claimed correlation is validated exactly like any other
    // reference. Absent correlation stays absent: only the producing lane's
    // claimed Session/lease/operation/attempt may appear here, and a
    // filesystem hint (no governed claimant) carries none.
    for reference in [
        hint.session.as_ref(),
        hint.action_lease.as_ref(),
        hint.operation.as_ref(),
        hint.attempt_receipt.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if !text(reference) {
            return Err(ChangeMonitorError::InvalidHint);
        }
    }
    if hint.origin != HintOrigin::HostEvent
        && (hint.session.is_some()
            || hint.action_lease.is_some()
            || hint.operation.is_some()
            || hint.attempt_receipt.is_some())
    {
        return Err(ChangeMonitorError::InvalidHint);
    }
    Ok(())
}

fn validate_git(git: &GitReadback) -> Result<(), ChangeMonitorError> {
    if !text(&git.repository) || !is_git_sha(&git.head_before) || !is_git_sha(&git.head_after) {
        return Err(ChangeMonitorError::InvalidGitEvidence);
    }
    match (&git.status_ref, &git.status_sha256) {
        (None, None) => {}
        (Some(status_ref), Some(status_sha256))
            if text(status_ref) && is_sha256_hex(status_sha256) => {}
        _ => return Err(ChangeMonitorError::InvalidGitEvidence),
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

/// Builds the idempotent hint identity for one governed tool operation
/// target.
///
/// The same operation handle plus the same target digest always maps to the
/// same hint, so an exact re-ingest of the same hint replays instead of
/// conflicting. Distinct targets never share an identity, so a second
/// target's transition is never swallowed by the first confirmation. A
/// retry that observes new evidence re-evaluates under the same identity
/// ([`confirm_hint`] follows the latest evidence, never a stale
/// confirmation).
pub(crate) fn host_hint_id(operation_id: &str, target_digest: &str) -> String {
    format!("cmh:{operation_id}:{target_digest}")
}

/// Builds the idempotent hint identity for one poll-reconciled tracked
/// transition: the lane-stable artifact digest plus the exact before
/// digest the transition leaves. A later transition from a new before
/// digest is a new hint, so a second uncorrelated mutation is never
/// swallowed by the first confirmation.
///
/// Wire stability: the `cmf:` prefix predates the honest `PollReconcile`
/// naming and is frozen — persisted sidecars and crash-window recovery
/// reproduce the same identity from the same inputs, and renaming the
/// bytes would orphan pending hints into a permanent block.
pub(crate) fn poll_reconcile_hint_id(artifact_digest: &str, before_digest: &str) -> String {
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
/// bytes).
///
/// Confirmation is evidence-driven, never sticky: identical evidence
/// replays the identical outcome, while new evidence under a retried
/// operation re-evaluates and emits the transition it actually proves.
/// A filesystem or poll-reconcile hint confirms only against actual Git
/// plus content re-read evidence: `git: None` is refused with
/// [`ChangeMonitorError::InvalidGitEvidence`], so an inferred transition no
/// admission explains never becomes a filesystem observation on content
/// polling alone. The refusal leaves the hint pending, which keeps governed
/// acceptance blocked until a Git-backed readback resolves it.
/// History is still never rewritten: unknown records are keyed by their
/// exact transition and reconciliation only appends links. Tips advance
/// only on verified-immaterial or reconciled-material outcomes, so the
/// retained baseline never moves past an unreconciled Material mutation:
/// the next capture re-detects it and re-surfaces the same unknown record
/// instead of observing it away. A proven observation that continues from
/// a gap-marked before-state also closes that gap, since the gap's guard
/// duty is subsumed by the new blocking unknown.
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
    let (resource, origin) = ledger
        .hints
        .get(hint_id)
        .ok_or(ChangeMonitorError::UnknownHint)
        .map(|entry| (entry.hint.resource.clone(), entry.hint.origin))?;
    // I10.21 W2: a filesystem or poll-reconcile hint is a filesystem/Git
    // observation confirmed against actual Git/content re-reads, never
    // content polling over one image. Such a confirmation without Git
    // readback proves no repository state and is refused instead of
    // recorded. Only a host-event hint (the governed lane's own content
    // re-reads) decides on content evidence alone.
    if origin != HintOrigin::HostEvent && verification.git.is_none() {
        return Err(ChangeMonitorError::InvalidGitEvidence);
    }
    if before_digest == after_digest {
        let entry = ledger
            .hints
            .get_mut(hint_id)
            .ok_or(ChangeMonitorError::UnknownHint)?;
        entry.confirmation = Some(HintConfirmation::VerifiedImmaterial);
        ledger.tips.insert(
            resource,
            ResourceTip {
                digest: before_digest,
                head_commit: verification.git.as_ref().map(|git| git.head_after.clone()),
                repository: verification.git.as_ref().map(|git| git.repository.clone()),
            },
        );
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
                resource: resource.clone(),
                before_digest: before_digest.clone(),
                after_digest: after_digest.clone(),
                transition_digest,
                reconciled,
                unresolved_gap: false,
                // I10.21 W3: a proven transition carries no witness. Its
                // claimant correlation lives on the governed record (or the
                // reconciling link); the unknown record keeps the exact
                // pair plus its reconciliation state.
                witness: None,
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
    close_gaps_from_proven_before(&mut ledger, &resource, before_digest.as_ref(), &change_id);
    if reconciled {
        ledger.tips.insert(
            resource,
            ResourceTip {
                digest: after_digest,
                head_commit: verification.git.as_ref().map(|git| git.head_after.clone()),
                repository: verification.git.as_ref().map(|git| git.repository.clone()),
            },
        );
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

/// One filesystem notification received by the Kernel (I10.21 W2, AUD2
/// defect 2): either a delivered OS event (the watcher observed `path`
/// change and handed over `event_ref`) or the process-effect lane's
/// poll-reconcile re-check of an inferred declared-target transition. The
/// stamped [`HintOrigin`] tells them apart; either way it is still only a
/// hint until [`observe_filesystem_notification`] confirms it against
/// actual Git-substrate plus content re-read evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FilesystemEventNotification {
    pub event_ref: String,
    pub resource: String,
    pub path: String,
}

/// One real Git HEAD-substrate read: the repository handle, the observed
/// HEAD commit, and the exact substrate bytes those values came from. The
/// bytes are retained so the confirmation receipt binds real observations,
/// never invented repository state.
struct GitHeadObservation {
    repository: String,
    head: String,
    exact_bytes: Vec<u8>,
}

/// Reads the real Git HEAD substrate for one governed working directory:
/// `.git/HEAD` plus the symref target (loose ref first, then the
/// packed-refs file), or the detached HEAD commit directly. Every byte that
/// feeds the returned observation comes from those files. The working
/// directory itself is searched first, then each ancestor up to the
/// enclosing repository root: a governed install root or workspace member
/// carries no `./.git` of its own, and refusing before any hint is
/// admitted would lose the emission half of the unknown-origin block
/// (I10.21 A2, audit 5910747803 A2). Anything else — no ancestor with a
/// readable `.git`, an unparsable HEAD, an unresolvable symref — is
/// [`ChangeMonitorError::NoGitSubstrate`], never a synthesized claim.
/// `.git` resolves through [`resolve_git_dir`], so a worktree `gitdir:`
/// pointer file claims its target exactly like a plain directory.
fn read_git_head_substrate(
    workspace_root: &std::path::Path,
) -> Result<GitHeadObservation, ChangeMonitorError> {
    if !text(&workspace_root.to_string_lossy()) {
        return Err(ChangeMonitorError::NoGitSubstrate);
    }
    let mut current = if workspace_root.is_dir() {
        workspace_root.to_path_buf()
    } else {
        workspace_root
            .parent()
            .map(Path::to_path_buf)
            .ok_or(ChangeMonitorError::NoGitSubstrate)?
    };
    loop {
        // An empty ancestor (only reachable from a relative root) would
        // resolve `.git` against the process working directory instead of
        // the governed tree: refuse rather than claim a foreign substrate.
        if !text(&current.to_string_lossy()) {
            return Err(ChangeMonitorError::NoGitSubstrate);
        }
        if let Some(git_dir) = resolve_git_dir(&current.join(".git"))
            && let Some(observation) = read_substrate_in(&current, &git_dir)
        {
            return Ok(observation);
        }
        current = current
            .parent()
            .map(Path::to_path_buf)
            .ok_or(ChangeMonitorError::NoGitSubstrate)?;
    }
}

/// Reads the HEAD substrate from one candidate repository root: the exact
/// HEAD bytes plus the symref target's exact bytes (loose ref first, then
/// the packed-refs file), or the detached HEAD commit directly. Returns
/// `None` when this directory claims no readable substrate, so the caller
/// keeps walking up instead of inventing repository state. The returned
/// handle names the claiming ancestor, matching [`read_git_head_substrate`].
fn read_substrate_in(
    repository_root: &std::path::Path,
    git_dir: &std::path::Path,
) -> Option<GitHeadObservation> {
    let head_bytes = std::fs::read(git_dir.join("HEAD")).ok()?;
    let mut exact_bytes = head_bytes.clone();
    let head_text = String::from_utf8(head_bytes)
        .map(|contents| contents.trim().to_owned())
        .ok()?;
    if !text(&head_text) {
        return None;
    }
    let head = if let Some(refname) = head_text.strip_prefix("ref: ") {
        if refname.is_empty()
            || refname.contains('\\')
            || refname.contains(':')
            || refname
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".." || part == ".git")
        {
            return None;
        }
        if let Ok(ref_bytes) = std::fs::read(git_dir.join(refname)) {
            exact_bytes.extend_from_slice(&ref_bytes);
            String::from_utf8(ref_bytes)
                .map(|contents| contents.trim().to_owned())
                .ok()?
        } else {
            let packed_bytes = std::fs::read(git_dir.join("packed-refs")).ok()?;
            exact_bytes.extend_from_slice(&packed_bytes);
            let packed = String::from_utf8(packed_bytes).ok()?;
            let mut found = None;
            for line in packed.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with('^') {
                    continue;
                }
                let mut parts = line.split_whitespace();
                if let (Some(sha), Some(name)) = (parts.next(), parts.next())
                    && name == refname
                {
                    found = Some(sha.to_owned());
                    break;
                }
            }
            found?
        }
    } else {
        head_text
    };
    if !text(&head) {
        return None;
    }
    Some(GitHeadObservation {
        repository: repository_root.to_string_lossy().into_owned(),
        head,
        exact_bytes,
    })
}

/// Reads one hinted tracked source twice with agreeing-absence semantics
/// (I10.21 AUD2/AUD5): two agreeing present reads prove stable bytes, two
/// agreeing not-found observations prove absence (the deletion evidence
/// [`confirm_hint`] admits as an immutable `Absent` observation), and any
/// other outcome — permissions, transient I/O, or disagreeing reads —
/// proves nothing and is refused as [`ChangeMonitorError::UnstableReadback`],
/// never a deletion claim. The shape mirrors the in-crate capture/readback
/// tracked-source read because both lanes need the same stability proof;
/// the opens themselves stay here so the adapter's confirmation rests on
/// its own pairwise-independent reads, never on caller-supplied bytes.
fn read_hinted_source_twice(
    tracked: &Path,
) -> Result<(ContentRead, ContentRead), ChangeMonitorError> {
    let read_once = |path: &Path| -> Result<Option<Vec<u8>>, ChangeMonitorError> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(ChangeMonitorError::UnstableReadback),
        }
    };
    let to_read = |bytes: Option<Vec<u8>>| match bytes {
        Some(bytes) => ContentRead::Present {
            sha256: crate::sha256_hex(&bytes),
        },
        None => ContentRead::Absent,
    };
    let first_read = to_read(read_once(&tracked)?);
    let reread = to_read(read_once(&tracked)?);
    if first_read != reread {
        return Err(ChangeMonitorError::UnstableReadback);
    }
    Ok((first_read, reread))
}

/// Observes one filesystem hint against actual Git/content re-read
/// evidence and feeds the result through the existing owner port
/// ([`ingest_hint`] + [`confirm_hint`], I10.21 W2): no second ledger, no
/// parallel evidence channel. `origin` names the true producer route:
/// [`HintOrigin::FilesystemNotification`] for a received OS notification
/// (the future OS-watcher lane), or [`HintOrigin::PollReconcile`] for an
/// inferred declared-target transition the process-effect lane re-checks
/// (audit 5910747803 defect 2: a polled transition is never labeled an OS
/// notification). [`HintOrigin::HostEvent`] is refused: the host-event
/// route ingests directly. The adapter opens the hinted tracked source
/// itself twice (pairwise-independent reads that must agree, with agreeing
/// absence proving deletion — see [`read_hinted_source_twice`]), with a real
/// Git HEAD-substrate read before the first content read and another after
/// the re-read; a HEAD move under observation is
/// [`ChangeMonitorError::UnstableReadback`], exactly like disagreeing
/// content reads. `before_digest` is the previously admitted content digest
/// for the hinted source when the caller retains one (`None` on first
/// observation, which the transition binder records as `absent`).
/// Fail-closed and typed throughout: unreadable substrate is
/// [`ChangeMonitorError::NoGitSubstrate`], an unreadable or unstable
/// tracked source is [`ChangeMonitorError::UnstableReadback`], a conflicting
/// identity under the derived hint is [`ChangeMonitorError::HintConflict`].
/// A proven deletion (two agreeing not-found observations against actual
/// Git-substrate evidence) is represented as an immutable unknown-origin
/// deletion observation through the same port — it blocks governed
/// acceptance until reconciled — while any other read failure stays a
/// refusal, never a deletion claim.
///
/// Caller (I10.21 W2): `crate::process_execution::KernelGovernedProcessEffectPort`
/// poll-reconcile leg today; the OS-watcher lane once attached (with
/// `FilesystemNotification`).
pub(crate) fn observe_filesystem_notification(
    workspace_root: &std::path::Path,
    notification: &FilesystemEventNotification,
    before_digest: Option<&str>,
    origin: HintOrigin,
) -> Result<HintConfirmation, ChangeMonitorError> {
    if !matches!(
        origin,
        HintOrigin::FilesystemNotification | HintOrigin::PollReconcile
    ) {
        return Err(ChangeMonitorError::InvalidHint);
    }
    if !text(&notification.event_ref)
        || !text(&notification.resource)
        || !validate_relative_path(&notification.path)
    {
        return Err(ChangeMonitorError::InvalidHint);
    }
    if let Some(before) = before_digest
        && !is_sha256_hex(before)
    {
        return Err(ChangeMonitorError::InvalidGitEvidence);
    }
    let tracked = workspace_root.join(notification.path.as_str());
    let substrate_before = read_git_head_substrate(workspace_root)?;
    let (first_read, reread) = read_hinted_source_twice(&tracked)?;
    let substrate_after = read_git_head_substrate(workspace_root)?;
    if substrate_before.head != substrate_after.head {
        return Err(ChangeMonitorError::UnstableReadback);
    }
    let mut status_bytes = substrate_before.exact_bytes.clone();
    status_bytes.extend_from_slice(&substrate_after.exact_bytes);
    let repository = substrate_before.repository.clone();
    let status_ref = format!("git-head-substrate:{repository}");
    let git = GitReadback {
        repository,
        head_before: substrate_before.head,
        head_after: substrate_after.head,
        status_ref: Some(status_ref),
        status_sha256: Some(crate::sha256_hex(&status_bytes)),
        before_revision: None,
        after_revision: None,
        diff_handle: None,
    };
    let artifact = crate::sha256_hex(notification.resource.as_bytes());
    let hint_id = poll_reconcile_hint_id(&artifact, before_digest.unwrap_or("absent"));
    let hint = KernelChangeHint {
        hint_id: hint_id.clone(),
        resource: notification.resource.clone(),
        path: notification.path.clone(),
        origin,
        origin_ref: Some(notification.event_ref.clone()),
        // I10.21 W3: an OS notification names no governed claimant, so
        // the hint carries no Session/lease/operation/attempt correlation.
        // Absent correlation is the explicit uncertain-provenance
        // classification; invented attribution is refused by
        // [`validate_hint`].
        session: None,
        action_lease: None,
        operation: None,
        attempt_receipt: None,
        fence_generation: None,
    };
    ingest_hint(hint).map(|_| ())?;
    let verification = HintVerification {
        before_digest: before_digest.map(str::to_owned),
        first_read,
        reread,
        git: Some(git),
    };
    confirm_hint(&hint_id, &verification)
}
/// Closes gap-marked unknowns for one resource once a proven observation
/// continues from the gap's exact before-state: the new unknown record
/// (identified by `covering_change_id`) now guards the resource, so the
/// gap's blocking duty is subsumed by it instead of bricking the resource.
fn close_gaps_from_proven_before(
    ledger: &mut KernelChangeLedger,
    resource: &str,
    before_digest: Option<&String>,
    covering_change_id: &str,
) {
    let covered: Vec<String> = ledger
        .unknown
        .iter()
        .filter(|(_, unknown)| {
            unknown.unresolved_gap
                && !unknown.reconciled
                && unknown.resource == resource
                && unknown.before_digest.as_ref() == before_digest
        })
        .map(|(unknown_id, _)| unknown_id.clone())
        .collect();
    for unknown_id in covered {
        if let Some(unknown) = ledger.unknown.get_mut(&unknown_id) {
            unknown.reconciled = true;
        }
        ledger.reconciliations.push(UnknownReconciliation {
            unknown_change_id: unknown_id,
            evidence_change_id: covering_change_id.to_owned(),
        });
    }
}

/// Validates one governed-tool mutation record and binds its content
/// identity (I10.21 A1): shape checks plus the ledger-computed before/after
/// content digests over the supplied tracked-source bytes. Returns those
/// digests so the recorded revisions are the mutated tracked source's own
/// content identity, never an unrelated identity such as the tool
/// executable image.
fn validate_governed_tool_transition(
    change: &GovernedToolChange,
) -> Result<(Option<String>, Option<String>), ChangeMonitorError> {
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
    // I10.21 A1: at least one content side must be real bytes the producing
    // lane read back. `None` on exactly one side is the creation/deletion
    // shape; `None` on both sides means no source identity exists for
    // either side (an envelope/request digest is operation identity, not
    // content), so there is no before/after pair to record.
    if before_digest.is_none() && after_digest.is_none() {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    }
    if before_digest.is_some() && before_digest == after_digest {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    }
    // I10.21 A1 (audit 5910747803 AUD1): the recorded before/after
    // revisions must be the mutated tracked source's own content identity —
    // exactly the digests just computed over the supplied tracked-source
    // bytes — never an unrelated identity such as the tool executable
    // image. A lane naming any other revision is refused, never stored.
    if change.before_revision != before_digest || change.after_revision != after_digest {
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
    Ok((before_digest, after_digest))
}

/// Records one governed-tool mutation with exact before/after revisions,
/// the associated session, fenced-attempt lease, tool operation, and
/// attempt receipt, the diff handle, and the observed State-Fence
/// invalidation (I10.21 A1). Content checksums are computed here over the
/// exact bytes supplied; the bytes are dropped and only digests retained.
/// A creation carries `before_bytes: None`, a deletion carries
/// `after_bytes: None`; a record with neither side, or with agreeing
/// present sides, proves no transition and is refused. The recorded
/// revisions must equal those computed digests (`None` exactly where the
/// matching bytes are `None`), so the before/after identity is the mutated
/// tracked source's, never the tool executable image's (audit 5910747803
/// AUD1). The diff handle
/// must resolve to the exact recorded transition through the ledger's own
/// transition binder (shared with `confirm_hint` and the finish-leg
/// reconciliation, never a second resolver). A byte copy of an unrelated
/// digest names no transition this ledger recorded and is refused. A
/// recorded governed transition reconciles the matching unknown-origin
/// change for the exact same resource transition, and closes a gap-marked
/// unknown that starts from the same before-state. History is never
/// rewritten: an exact replay is reported, a conflicting identity is
/// refused, and a lease/session/operation owned by another change is never
/// reused. Tips are deliberately untouched here: only a confirmed
/// readback advances the retained baseline, never the record alone.
///
/// Caller (I10.21 A1):
/// `crate::process_execution::KernelGovernedProcessEffectPort::ingest`,
/// which feeds one record per declared target from real
/// pre-effect/terminal readback bytes.
pub(crate) fn record_governed_tool_change(
    change: &GovernedToolChange,
) -> Result<GovernedAdmission, ChangeMonitorError> {
    let (before_digest, after_digest) = validate_governed_tool_transition(change)?;
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
    // I10.21 A1: one operation may record one governed change per declared
    // target it mutated. A further change identity under the same operation
    // is admitted only when it carries the owning operation's own
    // session/lease: the same handle under a different lease/session is
    // operation reuse, never an additional target.
    if let Some(bound) = ledger.governed_by_operation.get(&change.operation)
        && !bound.contains(&change.change_id)
        && !bound.iter().any(|bound_id| {
            ledger.governed.get(bound_id).is_some_and(|record| {
                record.session == change.session && record.action_lease == change.action_lease
            })
        })
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
        .entry(change.operation.clone())
        .or_default()
        .push(change.change_id.clone());
    ledger.governed.insert(change.change_id.clone(), record);
    let matched: Vec<(String, String)> = ledger
        .unknown
        .iter()
        .filter(|(_, unknown)| {
            !unknown.reconciled
                && !unknown.unresolved_gap
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
    close_gaps_from_proven_before(
        &mut ledger,
        &change.resource,
        before_digest.as_ref(),
        &change.change_id,
    );
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

/// Records a fail-closed blocking marker after an observation failure
/// against a previously observed tip (I10.21 A2): unreadable or disagreeing
/// readback where fresh reads were expected. The marker carries the frozen
/// before-state with an unknown after-state, so it can never be mistaken
/// for a proven deletion, and it blocks governed acceptance exactly like
/// an unreconciled unknown. It is idempotent per operation: retrying the
/// same failed observation replays the same marker. It closes only when a
/// proven observation for the same resource continues from the same
/// before-state (see [`confirm_hint`] and [`record_governed_tool_change`]),
/// so a transient read glitch is recovered by the next capture instead of
/// bricking the resource, while a real hidden mutation stays blocked
/// behind the re-detected unknown. The marker keeps the observing lane's
/// claimed correlation ([`UnresolvedTransitionWitness`], I10.21 W3): Session,
/// lease, operation, attempt, and fence generation the witness held when
/// the observation failed. The witness names who observed the failure,
/// never who wrote the bytes, and the first observing witness wins on
/// replay — retrying the same failed observation replays the same marker
/// with the same witness instead of conflicting.
///
/// Caller (I10.21 A2/A4):
/// `crate::process_execution::KernelGovernedProcessEffectPort`, on
/// capture/readback/ingest failures where [`resource_tip`] proves a prior
/// observation exists. A failure on a never-observed path records nothing,
/// since there is no baseline to protect and the first successful read
/// establishes it.
pub(crate) fn note_unresolved_transition(
    resource: &str,
    witness: &UnresolvedTransitionWitness,
    before_digest: Option<String>,
) -> Result<String, ChangeMonitorError> {
    if !text(resource) || !text(&witness.operation) {
        return Err(ChangeMonitorError::InvalidHint);
    }
    // I10.21 W3: witness correlation is validated exactly like claimed hint
    // correlation. Absent optionals stay absent: only the observing lane's
    // held Session/lease/attempt may appear here.
    for reference in [
        witness.session.as_ref(),
        witness.action_lease.as_ref(),
        witness.attempt_receipt.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if !text(reference) {
            return Err(ChangeMonitorError::InvalidHint);
        }
    }
    if let Some(before) = &before_digest
        && !is_sha256_hex(before)
    {
        return Err(ChangeMonitorError::InvalidHint);
    }
    let witness_operation = witness.operation.as_str();
    let (change_id, transition_digest) = material_transition_ids(
        &format!("cmx:{witness_operation}"),
        before_digest.as_deref(),
        None,
    );
    let mut ledger = ledger()?;
    match ledger.unknown.entry(change_id.clone()) {
        Entry::Vacant(slot) => {
            slot.insert(UnknownOriginRecord {
                resource: resource.to_owned(),
                before_digest,
                after_digest: None,
                transition_digest,
                reconciled: false,
                unresolved_gap: true,
                witness: Some(witness.clone()),
            });
        }
        Entry::Occupied(slot) => {
            let existing = slot.into_mut();
            if existing.resource != resource || existing.before_digest != before_digest {
                return Err(ChangeMonitorError::HintConflict);
            }
        }
    }
    Ok(change_id)
}

/// Returns the last confirmed state of one tracked resource: the digest
/// the ledger last proved (`None` = last proved absent), or `None` when
/// the resource was never observed. The effect lane compares fresh reads
/// against this tip to detect external transitions, so both live in the
/// same ledger instead of a disconnected side map.
///
/// Caller: `crate::process_execution::KernelGovernedProcessEffectPort`.
pub(crate) fn resource_tip(resource: &str) -> Option<ResourceTip> {
    ledger()
        .ok()
        .and_then(|ledger| ledger.tips.get(resource).cloned())
}

/// Version of the durable ledger sidecar schema.
const LEDGER_SIDECAR_FORMAT_VERSION: u32 = 1;

/// Durable form of the Kernel ledger: the complete in-memory state plus a
/// schema version, so the finish-acceptance leg and a future Governor
/// hydration lane read pending hints and unreconciled unknowns from one
/// projection instead of two disconnected states.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LedgerSidecarFile {
    format_version: u32,
    ledger: KernelChangeLedger,
}

/// Locates the durable ledger sidecar: `.eliot/` under the default work
/// root, beside the `kernel-ors.redb` precedent. The path is stable across
/// restarts for a deployment (same `ELIOT_WORK_ROOT`/current directory),
/// which is the property durability needs; composition may additionally
/// pin `work_root`, but the sidecar contract does not depend on it.
fn ledger_sidecar_path() -> Option<PathBuf> {
    crate::default_work_root()
        .ok()
        .map(|root| root.join(".eliot").join("kernel-change-ledger.v1.json"))
}

/// Persists the current ledger to its durable sidecar, atomically
/// (temporary file plus rename). Best-effort by contract: persistence loss
/// never fails the observation it just recorded — acceptance stays
/// correctly blocked in memory — but the caller must surface the outcome
/// so durability loss stays visible.
///
/// Caller: `crate::process_execution::KernelGovernedProcessEffectPort`,
/// after ledger mutations.
pub(crate) fn persist_ledger_sidecar() -> Result<(), ChangeMonitorError> {
    let Some(path) = ledger_sidecar_path() else {
        return Err(ChangeMonitorError::SidecarUnavailable);
    };
    let snapshot = ledger().map(|ledger| LedgerSidecarFile {
        format_version: LEDGER_SIDECAR_FORMAT_VERSION,
        ledger: ledger.clone(),
    })?;
    let bytes =
        serde_json::to_vec(&snapshot).map_err(|_| ChangeMonitorError::SidecarUnavailable)?;
    write_durable_json(&path, &bytes)
}

/// Writes one durable JSON projection atomically (temporary file plus
/// rename), creating the parent directory first. Shared by the ledger
/// sidecar and the observation transfer so both durable projections keep
/// the same crash-window behavior: a reader never sees a half-written
/// document.
fn write_durable_json(path: &Path, bytes: &[u8]) -> Result<(), ChangeMonitorError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|_| ChangeMonitorError::SidecarUnavailable)?;
    }
    let staging = path.with_extension(format!("tmp.{}", std::process::id()));
    std::fs::write(&staging, bytes).map_err(|_| ChangeMonitorError::SidecarUnavailable)?;
    std::fs::rename(&staging, path).map_err(|_| ChangeMonitorError::SidecarUnavailable)?;
    Ok(())
}

/// Rehydrates the ledger from its durable sidecar when this process
/// started fresh (I10.21 durability: observations are retained across
/// restart, not transient-only). Refuses to clobber live state: a
/// non-empty ledger is left untouched. A missing sidecar is a clean boot,
/// not an error; a corrupt sidecar fails closed so the caller blocks
/// acceptance instead of trusting a half-read projection.
///
/// Caller: `host_request_route::daemon_claim_queue::submit_finish_result`,
/// before consulting the acceptance gate; and
/// `crate::process_execution::KernelGovernedProcessEffectPort::new`, which
/// rebuilds ledger state (and therefore ledger-retained tips) when this
/// process started fresh.
pub(crate) fn hydrate_ledger_sidecar_if_empty() -> Result<bool, ChangeMonitorError> {
    let Some(path) = ledger_sidecar_path() else {
        return Ok(false);
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(ChangeMonitorError::SidecarUnavailable),
    };
    let snapshot: LedgerSidecarFile =
        serde_json::from_slice(&bytes).map_err(|_| ChangeMonitorError::SidecarCorrupt)?;
    if snapshot.format_version != LEDGER_SIDECAR_FORMAT_VERSION {
        return Err(ChangeMonitorError::SidecarCorrupt);
    }
    validate_imported_ledger(&snapshot.ledger)?;
    let mut ledger = ledger()?;
    if !ledger.hints.is_empty()
        || !ledger.governed.is_empty()
        || !ledger.unknown.is_empty()
        || !ledger.tips.is_empty()
    {
        return Ok(false);
    }
    *ledger = snapshot.ledger;
    Ok(true)
}

/// Validates one durable gap-marker witness with the same shape live
/// ingress enforces (issue #1824 W3): the required operation plus the
/// optional session/lease/attempt references. Markers recorded before
/// witness correlation carry none.
fn validate_witness_shape(witness: &UnresolvedTransitionWitness) -> Result<(), ChangeMonitorError> {
    if !text(&witness.operation) {
        return Err(ChangeMonitorError::SidecarCorrupt);
    }
    for reference in [
        witness.session.as_ref(),
        witness.action_lease.as_ref(),
        witness.attempt_receipt.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        if !text(reference) {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
    }
    Ok(())
}

fn validate_imported_ledger(ledger: &KernelChangeLedger) -> Result<(), ChangeMonitorError> {
    for entry in ledger.hints.values() {
        validate_hint(&entry.hint).map_err(|_| ChangeMonitorError::SidecarCorrupt)?;
        if let Some(HintConfirmation::MaterialRecorded { change_id, .. }) = &entry.confirmation
            && !text(change_id)
        {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
    }
    for (change_id, record) in &ledger.governed {
        if !text(change_id)
            || !text(&record.resource)
            || !validate_relative_path(&record.path)
            || !text(&record.session)
            || !text(&record.action_lease)
            || !text(&record.operation)
            || !text(&record.attempt_receipt)
            || !text(&record.diff_handle)
        {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
        if record.before_digest.is_none() && record.after_digest.is_none() {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
        for digest in [&record.before_digest, &record.after_digest]
            .into_iter()
            .flatten()
        {
            if !is_sha256_hex(digest) {
                return Err(ChangeMonitorError::SidecarCorrupt);
            }
        }
        let (_, transition) = material_transition_ids(
            change_id,
            record.before_digest.as_deref(),
            record.after_digest.as_deref(),
        );
        if record.diff_handle != transition {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
        // Audit 5910747803 AUD1: a durable record must carry the same
        // revision binding the live ingress enforces — revisions are the
        // tracked source's own content digests, never the tool image's.
        if record.before_revision != record.before_digest
            || record.after_revision != record.after_digest
        {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
    }
    for (change_id, unknown) in &ledger.unknown {
        if !change_id.starts_with("cmu:") || !text(&unknown.resource) {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
        // I10.21 W3: a durable witness carries the same validated shape
        // live ingress enforces; markers recorded before witness
        // correlation carry none.
        if let Some(witness) = &unknown.witness {
            validate_witness_shape(witness)?;
        }
        for digest in [&unknown.before_digest, &unknown.after_digest]
            .into_iter()
            .flatten()
        {
            if !is_sha256_hex(digest) {
                return Err(ChangeMonitorError::SidecarCorrupt);
            }
        }
        let (_, transition) = material_transition_ids(
            "",
            unknown.before_digest.as_deref(),
            unknown.after_digest.as_deref(),
        );
        if unknown.transition_digest != transition {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
    }
    for reconciliation in &ledger.reconciliations {
        if !text(&reconciliation.unknown_change_id) || !text(&reconciliation.evidence_change_id) {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
    }
    for tip in ledger.tips.values() {
        if tip
            .digest
            .as_deref()
            .is_some_and(|digest| !is_sha256_hex(digest))
            || tip
                .head_commit
                .as_deref()
                .is_some_and(|commit| !is_git_sha(commit))
            || tip
                .repository
                .as_deref()
                .is_some_and(|repository| !text(repository))
        {
            return Err(ChangeMonitorError::SidecarCorrupt);
        }
    }
    Ok(())
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

/// Normalizes one finish-declared resource for the per-resource
/// acceptance gate (I10.21 A2): separator folding (`\` vs `/` across
/// Windows finish drafts and native ledger keys) with redundant trailing
/// separators trimmed. Returns `None` for an empty or control-carrying
/// query, which the gate treats as unmatched. Opaque content-addressed
/// artifact handles that name no path normalize to themselves and keep
/// missing the ledger's tracked-source keys by construction: mapping those
/// needs the admitted handle-to-source mapping owned outside this ledger,
/// so such candidates keep the global gate as fallback (see
/// [`governed_acceptance_blocked_for`]).
fn normalize_gate_resource(value: &str) -> Option<String> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return None;
    }
    let folded = value.replace('\\', "/");
    let trimmed = folded.trim_matches('/').to_owned();
    (!trimmed.is_empty()).then_some(trimmed)
}

/// Returns whether governed acceptance for one tracked resource is
/// currently blocked: a hint naming that resource is still unverified, or
/// an unknown-origin Material change naming that resource is still
/// unreconciled (I10.21 A2, per-resource scope).
///
/// Scoping compares through [`normalize_gate_resource`] on both the
/// finish-declared query and the ledger's tracked-source keys, so a
/// path-shaped finish ref reaches the same resource the effect lane
/// recorded under its native separators. The live finish leg does NOT
/// otherwise assume identity: finish drafts name opaque artifact handles
/// while this ledger keys tracked-source identity, and no admitted mapping
/// proves a handle disjoint from a blocked resource, so the leg keeps the
/// sound global gate above. This query is the per-resource end of the
/// future Kernel-ledger/Governor-monitor identity bridge (see
/// `eliot-change-monitor::ChangeMonitor::blocks_acceptance_for`): it
/// becomes leg-eligible only with an admitted handle-to-source mapping,
/// never by assuming one. A poisoned ledger fails closed.
///
/// Caller: `host_request_route::daemon_claim_queue::submit_finish_result`.
pub(crate) fn governed_acceptance_blocked_for(resource: &str) -> bool {
    let Ok(ledger) = ledger() else {
        return true;
    };
    let Some(query) = normalize_gate_resource(resource) else {
        return false;
    };
    ledger.hints.values().any(|entry| {
        entry.confirmation.is_none()
            && normalize_gate_resource(entry.hint.resource.as_str()).as_ref() == Some(&query)
    }) || ledger.unknown.values().any(|unknown| {
        !unknown.reconciled
            && normalize_gate_resource(unknown.resource.as_str()).as_ref() == Some(&query)
    })
}

/// Version of the Kernel observation transfer schema below. It binds the
/// exact field contract the Governor owner ingests; a schema change bumps
/// this version instead of silently reinterpreting fields.
pub(crate) const OBSERVATION_TRANSFER_FORMAT_VERSION: u32 = 1;

/// Descriptor of the projection that produced one transfer document
/// (I10.21 W6: algorithm/version are recorded, not implied).
pub(crate) const OBSERVATION_TRANSFER_PROJECTION: &str = "kernel-change-ledger/v1";

/// Evidence class for one transferred record (I10.21 W6): the Kernel's
/// origin-attribution confidence vocabulary. A governed-admitted record
/// carries the full Session/lease/operation/attempt/diff/fence correlation
/// the producing lane proved; an unreconciled unknown carries the exact
/// before/after pair with no claimant; a gap marker carries only the frozen
/// before-state its blocking duty guards.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) enum TransferEvidenceClass {
    GovernedAdmitted,
    UnknownUnreconciled,
    UnknownReconciled,
    ObservationGap,
}

/// One pending hint for the Governor owner (I10.21 W4): the hint identity
/// plus the claimant correlation the Kernel admitted (I10.21 W3), so the
/// owner confirms the same re-check instead of minting a parallel one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TransferredPendingHint {
    pub hint_id: String,
    pub resource: String,
    pub path: String,
    pub origin: HintOrigin,
    pub origin_ref: Option<String>,
    pub session: Option<String>,
    pub action_lease: Option<String>,
    pub operation: Option<String>,
    pub attempt_receipt: Option<String>,
    pub fence_generation: Option<u64>,
}

/// One unknown-origin Material change for the Governor owner (I10.21 W4):
/// the exact before/after pair and transition the Kernel ledger recorded,
/// with its reconciliation state and evidence class (I10.21 W6). A gap
/// marker additionally carries the observing witness (I10.21 W3), so the
/// owner keeps the uncertain-provenance classification — who observed the
/// failure, never who wrote the bytes — instead of minting unattributed
/// state. New for transfer documents written with witness correlation;
/// older documents default it absent.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TransferredUnknownChange {
    pub change_id: String,
    pub resource: String,
    pub before_digest: Option<String>,
    pub after_digest: Option<String>,
    pub transition_digest: String,
    pub reconciled: bool,
    pub evidence_class: TransferEvidenceClass,
    #[serde(default)]
    pub witness: Option<UnresolvedTransitionWitness>,
}

/// One governed-tool original for the Governor owner (I10.21 W5): the
/// immutable original anchor identity — the exact operation/diff identity
/// plus the before/after revisions the ledger hashed itself — with the
/// full Session/lease/operation/attempt/fence correlation. These are the
/// immutable candidate/evidence inputs the anchored-review resolver
/// consumes; the Kernel never resolves, it only provisions admitted
/// inputs in ledger key order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TransferredGovernedOriginal {
    pub change_id: String,
    pub resource: String,
    pub path: String,
    pub before_path: Option<String>,
    pub before_revision: Option<String>,
    pub before_digest: Option<String>,
    pub after_revision: Option<String>,
    pub after_digest: Option<String>,
    pub session: String,
    pub action_lease: String,
    pub operation: String,
    pub attempt_receipt: String,
    pub diff_handle: String,
    pub fence_generation: u64,
    pub fence_invalidated: bool,
    /// A governed original is admitted evidence by construction (I10.21
    /// W6): the ledger hashed the tracked-source bytes itself and bound
    /// the full correlation before storing.
    pub evidence_class: TransferEvidenceClass,
}

/// One unknown-to-evidence link for the Governor owner (I10.21 W5/W6):
/// history-preserving reconciliation evidence, never a rewrite.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TransferredReconciliation {
    pub unknown_change_id: String,
    pub evidence_change_id: String,
}

/// One retained resource tip for the Governor owner (I10.21 W4): the last
/// proved digest plus the last confirmed repository commit, so the owner
/// restarts from the same baseline instead of establishing a fresh one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct TransferredResourceTip {
    pub resource: String,
    pub digest: Option<String>,
    pub head_commit: Option<String>,
    pub repository: Option<String>,
}

/// The single-owner projection export (I10.21 W4/W5/W6): every pending
/// hint, unknown-origin change, governed original, reconciliation link,
/// and retained tip in ledger key order, so the Governor owner rebuilds
/// the same projection instead of answering from disconnected state
/// (audit 5910747803 defect 7).
///
/// Section mapping for the Governor seam: pending hints plus tips feed
/// `eliot_change_monitor::ChangeMonitor::confirm_kernel_readback`;
/// governed originals feed
/// `eliot_change_monitor::ChangeMonitor::ingest_governed_tool_mutation`;
/// reconciliation links feed
/// `eliot_change_monitor::ChangeMonitor::reconcile_unknown_change`;
/// governed originals plus tips are the immutable candidate/evidence
/// inputs for `eliot_change_monitor::ChangeMonitor::resolve_anchor`
/// (I10.18: current-location resolution uses I10.21 and remains
/// exact/moved/modified/ambiguous/stale/deleted/unavailable; ambiguous
/// resolution never silently attaches to the most similar fragment).
/// I10.21 W6 is satisfied on this side by `format_version`,
/// `projection`, the per-record `evidence_class`, and the complete
/// inputs/evidence carried inline: the resolver's own
/// `AnchorResolutionObservation` publication stays the Governor owner's
/// duty at its anchored-review caller.
///
/// STITCH: no in-tree Governor caller exists yet. The consumer must live
/// outside this crate (a `bins` root never depends on Governor crates):
/// hydrate the `GovernorOwners.change_monitor` consulted by
/// `crates/governor/eliot-governor/src/finish_attempt.rs::GovernorFinishAttempt::prepare_finish_decision`
/// (acceptance gate) — supplied via
/// `crates/governor/eliot-governor/src/composition.rs::GovernorComposition::prepare_finish_decision`
/// — from the durable `kernel-change-transfer.v1.json` file
/// [`persist_observation_transfer`] maintains beside the ledger sidecar
/// (cross-restart; the only out-of-crate vehicle — there is no live-call
/// seam since a `bins` root never depends on Governor crates and vice versa)
/// before the gate consults `has_pending_hints`/`has_unknown_material_change`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct ObservationTransferDocument {
    pub format_version: u32,
    pub projection: String,
    pub pending_hints: Vec<TransferredPendingHint>,
    pub unknown_changes: Vec<TransferredUnknownChange>,
    pub governed_originals: Vec<TransferredGovernedOriginal>,
    pub reconciliations: Vec<TransferredReconciliation>,
    pub tips: Vec<TransferredResourceTip>,
}

/// Builds the single-owner projection export from the live ledger
/// (I10.21 W4/W5/W6). Iteration follows the ledger's key order, so the
/// same ledger always exports the same document. A poisoned ledger fails
/// closed instead of exporting a half-read projection.
pub(crate) fn export_observation_transfer()
-> Result<ObservationTransferDocument, ChangeMonitorError> {
    let ledger = ledger()?;
    let pending_hints = ledger
        .hints
        .values()
        .filter(|entry| entry.confirmation.is_none())
        .map(|entry| TransferredPendingHint {
            hint_id: entry.hint.hint_id.clone(),
            resource: entry.hint.resource.clone(),
            path: entry.hint.path.clone(),
            origin: entry.hint.origin,
            origin_ref: entry.hint.origin_ref.clone(),
            session: entry.hint.session.clone(),
            action_lease: entry.hint.action_lease.clone(),
            operation: entry.hint.operation.clone(),
            attempt_receipt: entry.hint.attempt_receipt.clone(),
            fence_generation: entry.hint.fence_generation,
        })
        .collect();
    let unknown_changes = ledger
        .unknown
        .iter()
        .map(|(change_id, unknown)| TransferredUnknownChange {
            change_id: change_id.clone(),
            resource: unknown.resource.clone(),
            before_digest: unknown.before_digest.clone(),
            after_digest: unknown.after_digest.clone(),
            transition_digest: unknown.transition_digest.clone(),
            reconciled: unknown.reconciled,
            evidence_class: if unknown.unresolved_gap {
                TransferEvidenceClass::ObservationGap
            } else if unknown.reconciled {
                TransferEvidenceClass::UnknownReconciled
            } else {
                TransferEvidenceClass::UnknownUnreconciled
            },
            witness: unknown.witness.clone(),
        })
        .collect();
    let governed_originals = ledger
        .governed
        .iter()
        .map(|(change_id, record)| TransferredGovernedOriginal {
            change_id: change_id.clone(),
            resource: record.resource.clone(),
            path: record.path.clone(),
            before_path: record.before_path.clone(),
            before_revision: record.before_revision.clone(),
            before_digest: record.before_digest.clone(),
            after_revision: record.after_revision.clone(),
            after_digest: record.after_digest.clone(),
            session: record.session.clone(),
            action_lease: record.action_lease.clone(),
            operation: record.operation.clone(),
            attempt_receipt: record.attempt_receipt.clone(),
            diff_handle: record.diff_handle.clone(),
            fence_generation: record.fence_generation,
            fence_invalidated: record.fence_invalidated,
            evidence_class: TransferEvidenceClass::GovernedAdmitted,
        })
        .collect();
    let reconciliations = ledger
        .reconciliations
        .iter()
        .map(|link| TransferredReconciliation {
            unknown_change_id: link.unknown_change_id.clone(),
            evidence_change_id: link.evidence_change_id.clone(),
        })
        .collect();
    let tips = ledger
        .tips
        .iter()
        .map(|(resource, tip)| TransferredResourceTip {
            resource: resource.clone(),
            digest: tip.digest.clone(),
            head_commit: tip.head_commit.clone(),
            repository: tip.repository.clone(),
        })
        .collect();
    Ok(ObservationTransferDocument {
        format_version: OBSERVATION_TRANSFER_FORMAT_VERSION,
        projection: OBSERVATION_TRANSFER_PROJECTION.to_owned(),
        pending_hints,
        unknown_changes,
        governed_originals,
        reconciliations,
        tips,
    })
}

/// Name of the durable observation transfer beside the ledger sidecar.
const OBSERVATION_TRANSFER_FILE_NAME: &str = "kernel-change-transfer.v1.json";

/// Locates the durable observation transfer: `.eliot/` under the default
/// work root, beside the ledger sidecar. Same stability contract as the
/// sidecar: the path is stable across restarts for a deployment.
fn observation_transfer_path() -> Option<PathBuf> {
    crate::default_work_root()
        .ok()
        .map(|root| root.join(".eliot").join(OBSERVATION_TRANSFER_FILE_NAME))
}

/// Persists the single-owner projection export beside the ledger sidecar
/// (I10.21 W4 durability): the exact document
/// [`export_observation_transfer`] builds, through the shared atomic
/// durable write. Best-effort by the same contract as the sidecar:
/// persistence loss never fails the observation it just recorded, but the
/// caller surfaces the outcome so durability loss stays visible. The
/// Governor hydration lane reads this file to converge its owner on the
/// Kernel projection — including across a Kernel restart, when the live
/// export is unreachable but retained unknowns still block.
///
/// Caller: `crate::process_execution::KernelGovernedProcessEffectPort`,
/// after ledger mutations, beside the sidecar persist.
pub(crate) fn persist_observation_transfer() -> Result<(), ChangeMonitorError> {
    let Some(path) = observation_transfer_path() else {
        return Err(ChangeMonitorError::SidecarUnavailable);
    };
    let document = export_observation_transfer()?;
    let bytes = serde_json::to_vec(&document).map_err(|_| ChangeMonitorError::TransferEncode)?;
    write_durable_json(&path, &bytes)
}
