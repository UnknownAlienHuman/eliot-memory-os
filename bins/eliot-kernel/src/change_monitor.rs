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
//! admission-declared mutation set (one hint per declared target), and the
//! ([`observe_filesystem_notification`]) for received OS filesystem
//! notifications. The adapter opens the hinted tracked source twice per
//! observation and reads the real Git substrate (`.git/HEAD` plus the
//! resolved ref, loose or packed) around those reads, so a filesystem hint
//! confirms against actual Git/content re-read evidence instead of content
//! polling over one image. A filesystem hint without that Git readback is
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
            Self::NoGitSubstrate => "change_monitor_no_git_substrate",
            Self::InvalidGovernedChange => "change_monitor_invalid_governed_change",
            Self::OperationReuse => "change_monitor_operation_reuse",
            Self::UnknownChange => "change_monitor_unknown_change",
            Self::TransitionMismatch => "change_monitor_transition_mismatch",
        };
        f.write_str(code)
    }
}

impl std::error::Error for ChangeMonitorError {}

/// Route of one untrusted hint observed Kernel-side. `HostEvent` is built
/// by the Kernel process-effect lane for an admitted tool operation whose
/// effect is read back; `FilesystemNotification` is built only by the
/// filesystem/Git observation adapter ([`observe_filesystem_notification`])
/// from a received OS notification confirmed against actual Git-substrate
/// plus content re-read evidence. Filesystem, tool, and artifact semantics
/// beyond that live in the Governor-owned projection (`eliot-change-monitor`
/// under `crates/governor`); the Kernel observes the Git HEAD substrate
/// read-only (see [`GitReadback`]) and performs no porcelain status, so a
/// filesystem-sourced transition surfaces as an unknown-origin Material
/// change on real content evidence, never as an invented repository claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HintOrigin {
    HostEvent,
    FilesystemNotification,
}

/// Untrusted host event: a re-check hint, never a Material observation by
/// itself.
///
/// Caller (I10.21 W2): `crate::process_execution::KernelGovernedProcessEffectPort`
/// ingests each governed tool operation as a host-event hint;
/// [`observe_filesystem_notification`] ingests each received OS filesystem
/// notification as a filesystem hint with real Git-substrate evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KernelChangeHint {
    pub hint_id: String,
    pub resource: String,
    pub path: String,
    pub origin: HintOrigin,
    pub origin_ref: Option<String>,
}

/// One direct content read: the exact bytes hashed. Deletion readback has
/// no in-crate producer yet, so absence is expressed only through a missing
/// baseline (`None`), never through this type.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum ContentRead {
    Present { sha256: String },
}

impl ContentRead {
    fn digest(&self) -> &str {
        match self {
            Self::Present { sha256 } => sha256,
        }
    }
}

/// Readback evidence bound to the same hinted artifact as the two direct
/// content reads. `None` means the confirming lane supplied no Git
/// readback: accepted only for `HostEvent` hints, which decide on content
/// checksum and re-read evidence. A `FilesystemNotification` hint with
/// `None` is refused by [`confirm_hint`] with
/// [`ChangeMonitorError::InvalidGitEvidence`]. A `Some` value must pass
/// [`validate_git`]; half-filled repository claims are refused rather than
/// confirmed. The Kernel observes the Git HEAD substrate read-only and
/// performs no porcelain status: `status_ref` names the exact
/// HEAD-substrate receipt the adapter read around the content reads, and
/// `status_sha256` is the SHA-256 over those exact substrate bytes, so the
/// head values are bound to real bytes, never invented.
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
/// Ingress contract (fail-closed): both content sides must be present so the
/// ledger hashes real before/after source bytes, and `diff_handle` must be
/// the exact transition digest for `(change_id, before, after)` — a copied
/// unrelated digest does not resolve and is refused with
/// [`ChangeMonitorError::InvalidGovernedChange`]. The fence fields must be
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
    governed_by_operation: BTreeMap<String, Vec<String>>,
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
        if !is_sha256_hex(read.digest()) {
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
/// proves nothing; a Material transition (after digest differs from the
/// retained baseline) emits an unknown-origin Material change (I10.21 A2),
/// reconciled immediately only when a recorded governed change already
/// proves the exact same resource transition (same before and after
/// digests, not merely the same after bytes).
///
/// Confirmation is evidence-driven, never sticky: identical evidence
/// replays the identical outcome, while new evidence under a retried
/// operation re-evaluates and emits the transition it actually proves.
/// A `FilesystemNotification` hint confirms only against actual Git plus
/// content re-read evidence: `git: None` is refused with
/// [`ChangeMonitorError::InvalidGitEvidence`], so an inferred transition no
/// admission explains never becomes a filesystem observation on content
/// polling alone. The refusal leaves the hint pending, which keeps governed
/// acceptance blocked until a Git-backed readback resolves it.
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
    let after_digest = verification.reread.digest().to_owned();
    let before_digest = verification.before_digest.clone();
    let (change_id, transition_digest) = material_transition_ids(
        hint_id,
        before_digest.as_deref(),
        Some(after_digest.as_str()),
    );
    let mut ledger = ledger()?;
    let (resource, origin) = ledger
        .hints
        .get(hint_id)
        .ok_or(ChangeMonitorError::UnknownHint)
        .map(|entry| (entry.hint.resource.clone(), entry.hint.origin))?;
    // I10.21 W2: a filesystem hint is an OS notification confirmed against
    // actual Git/content re-reads, never content polling over one image. A
    // filesystem confirmation without Git readback proves no repository
    // state and is refused instead of recorded.
    if origin == HintOrigin::FilesystemNotification && verification.git.is_none() {
        return Err(ChangeMonitorError::InvalidGitEvidence);
    }
    if before_digest.as_deref() == Some(after_digest.as_str()) {
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
                && record.before_digest.as_deref() == before_digest.as_deref()
                && record.after_digest.as_deref() == Some(after_digest.as_str())
        })
        .map(|(evidence_id, _)| evidence_id.clone());
    let reconciled = evidence_id.is_some();
    let newly_reconciled = match ledger.unknown.entry(change_id.clone()) {
        Entry::Vacant(slot) => {
            slot.insert(UnknownOriginRecord {
                resource,
                before_digest,
                after_digest: Some(after_digest),
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

/// One operating-system filesystem notification received by the Kernel
/// (I10.21 W2, AUD2 defect 2). Unlike the inferred declared-target
/// transition the process-effect lane polls at pre-effect capture, this is
/// a delivered OS event: the watcher observed `path` change and handed over
/// `event_ref`. It is still only a hint until
/// [`observe_filesystem_notification`] confirms it against actual
/// Git-substrate plus content re-read evidence.
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

/// Reads the real Git HEAD substrate under one workspace root: `.git/HEAD`
/// plus the symref target (loose ref first, then the packed-refs file), or
/// the detached HEAD commit directly. Every byte that feeds the returned
/// observation comes from those files. Anything else — a missing `.git`,
/// an unparsable HEAD, an unresolvable symref — is
/// [`ChangeMonitorError::NoGitSubstrate`], never a synthesized claim.
fn read_git_head_substrate(
    workspace_root: &std::path::Path,
) -> Result<GitHeadObservation, ChangeMonitorError> {
    let repository = workspace_root.to_string_lossy().into_owned();
    if !text(&repository) {
        return Err(ChangeMonitorError::NoGitSubstrate);
    }
    let git_dir = workspace_root.join(".git");
    let head_bytes =
        std::fs::read(git_dir.join("HEAD")).map_err(|_| ChangeMonitorError::NoGitSubstrate)?;
    let mut exact_bytes = head_bytes.clone();
    let head_text = String::from_utf8(head_bytes)
        .map(|contents| contents.trim().to_owned())
        .map_err(|_| ChangeMonitorError::NoGitSubstrate)?;
    if !text(&head_text) {
        return Err(ChangeMonitorError::NoGitSubstrate);
    }
    let head = if let Some(refname) = head_text.strip_prefix("ref: ") {
        if refname.is_empty()
            || refname.contains('\\')
            || refname.contains(':')
            || refname
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == ".." || part == ".git")
        {
            return Err(ChangeMonitorError::NoGitSubstrate);
        }
        if let Ok(ref_bytes) = std::fs::read(git_dir.join(refname)) {
            exact_bytes.extend_from_slice(&ref_bytes);
            String::from_utf8(ref_bytes)
                .map(|contents| contents.trim().to_owned())
                .map_err(|_| ChangeMonitorError::NoGitSubstrate)?
        } else {
            let packed_bytes = std::fs::read(git_dir.join("packed-refs"))
                .map_err(|_| ChangeMonitorError::NoGitSubstrate)?;
            exact_bytes.extend_from_slice(&packed_bytes);
            let packed =
                String::from_utf8(packed_bytes).map_err(|_| ChangeMonitorError::NoGitSubstrate)?;
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
            found.ok_or(ChangeMonitorError::NoGitSubstrate)?
        }
    } else {
        head_text
    };
    if !text(&head) {
        return Err(ChangeMonitorError::NoGitSubstrate);
    }
    Ok(GitHeadObservation {
        repository,
        head,
        exact_bytes,
    })
}

/// Observes one received OS filesystem notification against actual
/// Git/content re-read evidence and feeds the result through the existing
/// owner port ([`ingest_hint`] + [`confirm_hint`], I10.21 W2): no second
/// ledger, no parallel evidence channel. The adapter opens the hinted
/// tracked source itself twice (pairwise-independent reads that must
/// agree), with a real Git HEAD-substrate read before the first content
/// read and another after the re-read; a HEAD move under observation is
/// [`ChangeMonitorError::UnstableReadback`], exactly like disagreeing
/// content reads. `before_digest` is the previously admitted content digest
/// for the hinted source when the caller retains one (`None` on first
/// observation, which the transition binder records as `absent`).
/// Fail-closed and typed throughout: unreadable substrate is
/// [`ChangeMonitorError::NoGitSubstrate`], an unreadable or unstable
/// tracked source is [`ChangeMonitorError::UnstableReadback`], a conflicting
/// identity under the derived hint is [`ChangeMonitorError::HintConflict`].
/// (Deletion readback is a separate lane: an absent tracked source is
/// refused here rather than represented.)
///
/// Caller (I10.21 W2): the OS-watcher lane once attached. No in-tree caller
/// wires an OS watcher yet; until that lane lands, the process-effect lane
/// keeps its host-event leg and its polling-inferred filesystem path — the
/// latter now fails closed under [`confirm_hint`] instead of recording a
/// `FilesystemNotification` on content polling alone.
pub(crate) fn observe_filesystem_notification(
    workspace_root: &std::path::Path,
    notification: &FilesystemEventNotification,
    before_digest: Option<&str>,
) -> Result<HintConfirmation, ChangeMonitorError> {
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
    let first_bytes = std::fs::read(&tracked).map_err(|_| ChangeMonitorError::UnstableReadback)?;
    let reread_bytes = std::fs::read(&tracked).map_err(|_| ChangeMonitorError::UnstableReadback)?;
    let first = crate::sha256_hex(&first_bytes);
    let reread = crate::sha256_hex(&reread_bytes);
    if first != reread {
        return Err(ChangeMonitorError::UnstableReadback);
    }
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
        status_ref,
        status_sha256: crate::sha256_hex(&status_bytes),
        before_revision: None,
        after_revision: None,
        diff_handle: None,
    };
    let artifact = crate::sha256_hex(notification.resource.as_bytes());
    let hint_id = filesystem_hint_id(&artifact, before_digest.unwrap_or("absent"));
    let hint = KernelChangeHint {
        hint_id: hint_id.clone(),
        resource: notification.resource.clone(),
        path: notification.path.clone(),
        origin: HintOrigin::FilesystemNotification,
        origin_ref: Some(notification.event_ref.clone()),
    };
    ingest_hint(hint).map(|_| ())?;
    let verification = HintVerification {
        before_digest: before_digest.map(str::to_owned),
        first_read: ContentRead::Present { sha256: first },
        reread: ContentRead::Present { sha256: reread },
        git: Some(git),
    };
    confirm_hint(&hint_id, &verification)
}

/// Records one governed-tool mutation with exact before/after revisions,
/// the associated session, fenced-attempt lease, tool operation, and
/// attempt receipt, the diff handle, and the observed State-Fence
/// invalidation (I10.21 A1). Content checksums are computed here over the
/// exact bytes supplied; the bytes are dropped and only digests retained.
/// A record without both content sides, or whose diff handle does not name
/// its exact before/after transition, is refused: the ledger stores source
/// identity, never envelope identity. A recorded governed transition
/// reconciles the matching unknown-origin change for the exact same
/// resource transition. History is never rewritten: an exact replay is
/// reported, a conflicting identity is refused, and a lease/session/
/// operation owned by another operation is never reused.
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
    // I10.21 A1: both content sides must be real bytes the producing lane
    // read back. `None` on either side means no source identity exists for
    // that side (an envelope/request digest is operation identity, not
    // content), so there is no before/after pair to record.
    let (Some(before_digest), Some(after_digest)) = (before_digest, after_digest) else {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    };
    if before_digest == after_digest {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    }
    // I10.21 A1: the diff handle must resolve to the exact recorded
    // transition through the ledger's own transition binder (shared with
    // `confirm_hint` and the finish-leg reconciliation, never a second
    // resolver). A byte copy of an unrelated digest names no transition
    // this ledger recorded and is refused.
    let (_, transition_digest) = material_transition_ids(
        &change.change_id,
        Some(before_digest.as_str()),
        Some(after_digest.as_str()),
    );
    if change.diff_handle != transition_digest {
        return Err(ChangeMonitorError::InvalidGovernedChange);
    }
    let record = GovernedChangeRecord {
        resource: change.resource.clone(),
        path: change.path.clone(),
        before_path: change.before_path.clone(),
        before_revision: change.before_revision.clone(),
        before_digest: Some(before_digest.clone()),
        after_revision: change.after_revision.clone(),
        after_digest: Some(after_digest.clone()),
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
                && unknown.resource == change.resource
                && unknown.before_digest.as_deref() == Some(before_digest.as_str())
                && unknown.after_digest.as_deref() == Some(after_digest.as_str())
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
