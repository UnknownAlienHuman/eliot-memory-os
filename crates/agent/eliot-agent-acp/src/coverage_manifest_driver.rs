//! Coverage-manifest driver for durable host-event ingest (issue #1936, I7.23).
//!
//! [`run_coverage_manifest`] runs the per-fingerprint flow once the run owner
//! that knows the fingerprint invokes it: for one product/session/attempt/route
//! fingerprint it resolves the host-observed
//! compliance facts for every named stream against the caller-supplied allowed
//! Tool/Facet manifest revision, verifies the denominator plan binds that same
//! revision, records the joined coverage denominator through
//! [`DurableHostEventJournal::record_coverage_manifest`], and returns the run
//! outcome (resolved facts plus the retained manifest) for the downstream
//! evidence-assembly owner. Resolution runs before retention, so
//! staged-but-uncommitted facts abort with [`IngestError::NotCommitted`]
//! before any manifest is retained. This driver mints no declarations
//! (expected sources, observable split, denominator origin, completeness,
//! invalidation) — those arrive in the caller plan, which the run owner that
//! knows the fingerprint supplies per fingerprint.
//!
//! [`run_ingest_for_fingerprint`] is the execution-unit ingest entry: it drives
//! [`produce_execution_unit_events`] first, so the execution-unit producer runs
//! on real events with the run owner's own binding/admission/observation
//! material before the reconnect/intake/coverage stages consume them.

use eliot_evaluation_contracts::ObservationCoverageManifest;

use crate::{
    AllowedHostManifestView, CoverageManifestPlan, DurableHostEventJournal,
    ExecutionUnitDriverEvent, ExecutionUnitRunError, IngestError, ObservedReconnectOutcome,
    ProducedExecutionUnitEvent, ReplayItem, ResolvedHostComplianceFacts, drive_reconnect_observed,
    produce_execution_unit_events,
};

/// Journal-owner run input for one product/session/attempt/route fingerprint
/// (issue #1936 W1, I7.23).
///
/// Every field here is evidence the run owner resolves per fingerprint: the
/// observed stream roster, the pinned allowed-manifest revision (digest plus
/// revision label and declared/forbidden tool sets), and the caller-declared
/// denominator halves ([`CoverageManifestPlan`]) the journal cannot mint.
/// Nothing is derived from model prose or handshake claims.
pub struct CoverageManifestRun<'a> {
    /// Streams this fingerprint observed, resolved per stream by the driver.
    pub stream_ids: &'a [&'a str],
    /// Revision-pinned allowed-manifest digest bound into every resolved fact.
    pub manifest_digest: &'a str,
    /// Human revision label carried into the retained facts.
    pub manifest_revision: &'a str,
    /// Tool names the pinned revision declares.
    pub declared_tool_names: &'a [String],
    /// Tool names the pinned revision forbids.
    pub forbidden_tool_names: &'a [String],
    /// Caller-declared denominator halves for this fingerprint.
    pub plan: CoverageManifestPlan<'a>,
}

/// Complete production output of one fingerprint run (issue #1936 W1, I7.23).
///
/// The downstream evidence-assembly owner consumes both halves: the resolved
/// per-stream facts map into immutable host evidence, and the retained
/// denominator binds the derived compliance trace. Both halves come from the
/// same run, so they always agree on the fingerprint and the allowed-manifest
/// revision.
#[derive(Clone, Debug)]
pub struct CoverageManifestRunOutcome {
    /// Facts resolved per observed stream against the pinned allowed revision.
    pub facts: Vec<ResolvedHostComplianceFacts>,
    /// Denominator retained under the run fingerprint, read back from the
    /// journal after recording.
    pub manifest: ObservationCoverageManifest,
}

/// Runs the journal-owner coverage-manifest flow for one fingerprint: binds
/// the owner-resolved allowed revision into the resolution view, invokes
/// [`drive_coverage_manifest`] with the owner-resolved streams, view, and
/// plan, and returns the run outcome (resolved facts plus the retained
/// manifest) for the downstream evidence-assembly owner.
///
/// The plan-to-revision binding still verifies inside
/// [`drive_coverage_manifest`]: a plan digest that does not equal the
/// owner-resolved revision digest fails closed with
/// [`IngestError::InvalidInput`] and retains nothing. The retained manifest
/// is read back under the plan fingerprint, so the returned halves always
/// agree; a missing retained manifest after a successful record fails closed
/// with [`IngestError::InvalidInput`] and never yields a partial outcome.
pub fn run_coverage_manifest(
    owner: &mut DurableHostEventJournal,
    run: &CoverageManifestRun<'_>,
) -> Result<CoverageManifestRunOutcome, IngestError> {
    let allowed = AllowedHostManifestView {
        manifest_digest: run.manifest_digest,
        manifest_revision: run.manifest_revision,
        declared_tool_names: run.declared_tool_names,
        forbidden_tool_names: run.forbidden_tool_names,
    };
    let facts = drive_coverage_manifest(owner, run.stream_ids, &allowed, &run.plan)?;
    let manifest = owner
        .coverage_manifest(run.plan.fingerprint)
        .cloned()
        .ok_or(IngestError::InvalidInput("coverage_manifest.fingerprint"))?;
    Ok(CoverageManifestRunOutcome { facts, manifest })
}

/// Complete production output of one fingerprint ingestion run (issue #1936
/// W1, I7.23): the per-stream observed drives plus the retained coverage
/// denominator, all from the same run, so they always agree on the
/// fingerprint.
#[derive(Clone, Debug)]
pub struct FingerprintIngestRunOutcome {
    /// Execution-unit events produced by the execution-unit producer at the
    /// start of this run, in declared order, each with its producer outcome and
    /// the route evidence read back from the committed record and re-verified
    /// against that event's own binding/admission/observation.
    pub produced: Vec<ProducedExecutionUnitEvent>,
    /// Observed reconnect drive per stream of the fingerprint, in roster
    /// order: commit recovery, downstream delivery, intake projection, and
    /// drop gaps.
    pub observed: Vec<ObservedReconnectOutcome>,
    /// Resolved facts plus the denominator retained under the fingerprint.
    pub manifest: CoverageManifestRunOutcome,
}

/// Runs the host-event ingestion run flow for one product/session/attempt/
/// route fingerprint: produces every declared execution-unit event through the
/// execution-unit producer, drives the observed reconnect for every stream in
/// the run roster, then persists the coverage denominator through
/// [`run_coverage_manifest`].
///
/// Production comes first so the run actually produces the execution-unit
/// events it then consumes: each declared event carries the run owner's own
/// #361 binding, #369 admission and applicable #369 physical observation, so
/// the producer derives and stages the requested/actual route columns from
/// those owners and commits. The drive then delivers those committed records
/// downstream and projects them to coordinator intake, which is the ordinary
/// consumption path — a produced event is never staged and dropped.
///
/// The drive stays the functional precondition of the denominator: commit
/// recovery commits staged-but-uncommitted records, which would otherwise abort
/// persistence with [`IngestError::NotCommitted`] before anything is retained.
/// A refused downstream delivery stops only that stream's drive
/// (`stopped_early`); its committed records still belong to the denominator, so
/// the manifest run still proceeds. Every failure is typed and retains nothing
/// partial.
///
/// A declared event on a stream outside `run.stream_ids` is refused before any
/// mutation, because the drive below would never deliver it.
pub fn run_ingest_for_fingerprint(
    owner: &mut DurableHostEventJournal,
    run: &CoverageManifestRun<'_>,
    events: &[ExecutionUnitDriverEvent<'_>],
    mut deliver: impl FnMut(&ReplayItem) -> bool,
) -> Result<FingerprintIngestRunOutcome, ExecutionUnitRunError> {
    let produced = produce_execution_unit_events(owner, events, run.stream_ids)?;
    let mut observed = Vec::with_capacity(run.stream_ids.len());
    for stream_id in run.stream_ids.iter().copied() {
        observed.push(drive_reconnect_observed(owner, stream_id, &mut deliver)?);
    }
    let manifest = run_coverage_manifest(owner, run)?;
    Ok(FingerprintIngestRunOutcome {
        produced,
        observed,
        manifest,
    })
}

/// Drives coverage-denominator production for one fingerprint: resolve facts
/// per stream, bind the plan to the allowed revision, record the manifest.
///
/// The plan's `allowed_manifest_digest` must equal the allowed view's
/// `manifest_digest`; a mismatch fails closed with
/// [`IngestError::InvalidInput`] and retains nothing. Every named stream
/// resolves through
/// [`DurableHostEventJournal::resolve_host_compliance_facts`], so an
/// uncommitted record on any stream reports [`IngestError::NotCommitted`]
/// before retention. On success the retained denominator is readable via
/// [`DurableHostEventJournal::coverage_manifest`] under the plan fingerprint.
pub fn drive_coverage_manifest(
    owner: &mut DurableHostEventJournal,
    stream_ids: &[&str],
    allowed: &AllowedHostManifestView<'_>,
    plan: &CoverageManifestPlan<'_>,
) -> Result<Vec<ResolvedHostComplianceFacts>, IngestError> {
    if plan.allowed_manifest_digest != allowed.manifest_digest {
        return Err(IngestError::InvalidInput(
            "coverage_manifest.allowed_manifest_digest",
        ));
    }
    let mut facts = Vec::with_capacity(stream_ids.len());
    for stream_id in stream_ids {
        facts.push(owner.resolve_host_compliance_facts(stream_id, allowed)?);
    }
    owner.record_coverage_manifest(plan)?;
    Ok(facts)
}
