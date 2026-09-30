//! I4.4.1 cold-start event driver (issue #1790, W3-trigger).
//!
//! [`GovernorComposition::drive_cold_start_for_event`] is the single production
//! entry that fires the [`ColdStartController`](eliot_workscope::ColdStartController)
//! at every event enumerated by I4.4.1 — first project open
//! ([`ColdStartTrigger::FirstProjectOpen`]), attach/launch
//! ([`ColdStartTrigger::AttachOrLaunch`]), unknown-workspace event
//! ([`ColdStartTrigger::UnknownWorkspace`]), explicit onboarding request
//! ([`ColdStartTrigger::OnboardingRequest`]), stale generation
//! ([`ColdStartTrigger::StaleGeneration`]), or resume without a current task
//! ([`ColdStartTrigger::ResumeWithoutTask`]) — and routes the discovery pass
//! through the privacy-bounded scanner. The driver only sequences the existing
//! owning legs ([`GovernorComposition::run_cold_start_trigger_scan`],
//! [`GovernorComposition::join_cold_start_lease`],
//! [`GovernorComposition::compile_cold_start_at_trigger`]); it duplicates no
//! attach flow (issue #1782 owns attach reconciliation) and adds no second
//! compilation path.
//!
//! Ordering per event is scan, then join, then compile:
//! - the trigger's scanner pass runs first through
//!   [`ColdStartController::run_trigger_scan`](eliot_workscope::ColdStartController::run_trigger_scan),
//!   which authorizes the trigger's read set against the discovery lease and
//!   binds it to the scan evidence before
//!   [`BootstrapScanner::scan`](eliot_workscope::BootstrapScanner::scan) runs;
//! - the event then joins the durable single-flight lease, so compatible
//!   concurrent attaches coalesce on exact workspace filesystem/VCS identity
//!   plus privacy boundary plus governing-source generation, while a different
//!   worktree identity or changed governing-source digest splits into a
//!   separate lease instead of reusing the first lease's scope/task decision;
//! - the lease winner compiles exactly one
//!   [`OnboardingReadinessReceipt`](eliot_workscope::OnboardingReadinessReceipt)
//!   before the first scope-sensitive work and publishes it as the lease
//!   terminal, while an already-terminal lease returns its shared terminal
//!   without recompiling.
//!
//! The driver creates no `WorkScope` and infers no latest task: lease
//! participants only ever attach to the shared terminal receipt. Identity,
//! generation, privacy-boundary, or governing-source changes invalidate rather
//! than mutate completed readiness; the replacement arrives as a new receipt
//! revision through the sequenced legs. A scan that needs a privacy boundary
//! fails closed before any join or compile, and compilation without the
//! durable scan receipt is refused by the compile leg.
//!
//! Live status: owning driver for attach/onboarding ingress. Live production
//! caller for `AttachOrLaunch`:
//! `bins/eliotd/src/daemon_runtime.rs::trigger_cold_start_controller`
//! (post-Kernel-ACK via `trigger_accepted_cold_start`) drives the sequenced
//! scan leg through `GovernorComposition::run_cold_start_trigger_scan`; the
//! pre-acceptance question ingress
//! (`DaemonComposition::attach_cold_start_question`) runs the storeless
//! scanner leg. The compile leg re-derives its capability from the durable
//! ORS owner after restart
//! (`GovernorComposition::recover_retained_cold_start_claim`), so a restarted
//! trigger adopts the one retained lease and never mints a second compilation
//! under the same key. Residual: the lease join/compile/drive evidence
//! (admitted privacy profile, source-content digests) is still not threaded
//! through attach transport — `trigger_cold_start_controller` documents the
//! gap — and the other five I4.4.1 producers do not exist yet; that threading
//! lives with the attach-transport/source-owner lanes. Caller: daemon (scan
//! leg); STITCH for join/compile/full drive.

use crate::composition::{
    ColdStartTriggerCompilation, CompositionError, GovernorComposition, KernelGenerationPort,
};
use crate::scan_disclosure_owner::InstallationScanDisclosureStore;
use eliot_contracts::StateFence;
use eliot_security_contracts::PrivacyClass;
use eliot_workscope::{
    BootstrapScanEvidence, BootstrapScanOutcome, ColdStartTrigger, DiscoveryLeaseKey,
    DiscoveryReadLease, GoverningSourceSet, LeaseJoin, OnboardingLease, PrivacyBoundary,
    PrivacyProfile, RepositoryLineageIdentity, ScanDisclosureOwnerBinding, ScopeIdentity,
    ScopeKind, TaskBindingInput, WorkScopeCandidate, WorkspaceInstanceIdentity,
};

impl<P: KernelGenerationPort + ?Sized> GovernorComposition<P> {
    /// Drives one I4.4.1 cold-start event end to end — scanner pass, durable
    /// single-flight join, compile and publish — through the privacy-bounded
    /// scanner (issue #1790, cold-start trigger production driver).
    ///
    /// The caller names the trigger for its live event: first project open,
    /// attach/launch, unknown workspace, onboarding request, stale generation,
    /// or resume without a current task. Every trigger's discovery pass is
    /// authorized against the discovery lease and bound to the scan evidence
    /// before the scanner runs, and the terminal receipt always references the
    /// exact durable scan receipt that fed the compilation. An
    /// already-terminal lease returns its validated claim alongside the shared
    /// terminal instead of recompiling, so compatible concurrent attaches
    /// receive the same receipt and no worker independently creates a second
    /// `WorkScope` or latest task while the lease is active.
    ///
    /// # Errors
    ///
    /// Returns [`CompositionError::NotReady`] when the composition is not
    /// ready; [`CompositionError::Recovery`] when the scan needs a privacy
    /// boundary before persisting, when the lease join is refused, when this
    /// composition did not win the durable lease claim, or when the durable
    /// lease disappeared before compilation;
    /// [`CompositionError::ScanDisclosure`] with its typed
    /// [`WorkScopeError`](eliot_workscope::WorkScopeError)
    /// cause when the scan receipt is missing, inaccessible, corrupt,
    /// replaced, stale, invalidated, or of unknown commit; and
    /// [`CompositionError::ActivationStaleFence`] when the fence, claim, or
    /// lease deadline moved under the trigger.
    #[allow(
        clippy::too_many_arguments,
        clippy::too_many_lines,
        reason = "the event driver carries the trigger, scanner, lease, candidate, source, fence, privacy, task, and receipt inputs of the three sequenced legs in one fail-closed entry"
    )]
    pub fn drive_cold_start_for_event(
        &mut self,
        trigger: ColdStartTrigger,
        discovery_lease: &mut DiscoveryReadLease,
        lease_key: &DiscoveryLeaseKey,
        store: &mut InstallationScanDisclosureStore,
        binding: &ScanDisclosureOwnerBinding,
        candidate_privacy: PrivacyClass,
        privacy_boundary: Option<&PrivacyBoundary>,
        scan: &BootstrapScanEvidence,
        proposed_kind: ScopeKind,
        identity_fingerprint: &str,
        verifier_candidates: &[String],
        governing_source_refs: Vec<String>,
        proposed: &OnboardingLease,
        receipt_ref: &str,
        principal_ref: &str,
        session_ref: &str,
        scope: &ScopeIdentity,
        instance: &WorkspaceInstanceIdentity,
        lineage: Option<&RepositoryLineageIdentity>,
        candidate: &WorkScopeCandidate,
        sources: &GoverningSourceSet,
        state_fence: &StateFence,
        governance_profile_ref: &str,
        limiting_integration_evidence: Vec<String>,
        route_profile_ref: &str,
        serializer_id: &str,
        serializer_version: &str,
        serializer_options_digest: &str,
        tokenizer_id: &str,
        tokenizer_version: &str,
        tokenizer_hash: &str,
        projection_source_ref: &str,
        projection_generation: u64,
        privacy: &PrivacyProfile,
        task: TaskBindingInput,
        now: u64,
    ) -> Result<ColdStartTriggerCompilation, CompositionError> {
        let outcome = Self::run_cold_start_trigger_scan(
            trigger,
            &mut *discovery_lease,
            lease_key,
            &mut *store,
            binding,
            candidate_privacy,
            privacy_boundary,
            scan,
            proposed_kind,
            identity_fingerprint,
            verifier_candidates,
            governing_source_refs,
            now,
        )?;
        let scan_receipt = match &outcome {
            BootstrapScanOutcome::Completed { persisted, .. } => persisted.as_ref(),
            BootstrapScanOutcome::PrivacyBoundaryRequired {
                code,
                discriminative_question,
            } => {
                return Err(CompositionError::Recovery(format!(
                    "cold-start trigger {trigger:?} needs a privacy boundary before its scanner pass: {code}: {discriminative_question}"
                )));
            }
        };
        let claim = self.build_cold_start_readiness_claim(
            proposed,
            candidate,
            sources,
            privacy,
            scan,
            &*store,
            binding,
            scan_receipt,
        )?;
        let join = self.join_cold_start_lease(
            trigger,
            &*discovery_lease,
            proposed,
            candidate,
            sources,
            privacy,
            scan,
            &*store,
            binding,
            scan_receipt,
            now,
        )?;
        if matches!(join, LeaseJoin::JoinedTerminal { .. }) {
            return Ok(ColdStartTriggerCompilation { claim, join });
        }
        self.compile_cold_start_at_trigger(
            trigger,
            &*discovery_lease,
            proposed,
            receipt_ref,
            principal_ref,
            session_ref,
            scope,
            instance,
            lineage,
            candidate,
            sources,
            state_fence,
            governance_profile_ref,
            limiting_integration_evidence,
            route_profile_ref,
            serializer_id,
            serializer_version,
            serializer_options_digest,
            tokenizer_id,
            tokenizer_version,
            tokenizer_hash,
            projection_source_ref,
            projection_generation,
            privacy,
            task,
            scan,
            &*store,
            binding,
            Some(scan_receipt),
            now,
        )
    }
}
