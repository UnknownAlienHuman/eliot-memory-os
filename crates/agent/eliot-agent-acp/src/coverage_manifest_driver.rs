//! Coverage-manifest driver for durable host-event ingest (issue #1936, I7.23).
//!
//! [`run_coverage_manifest`] is the per-fingerprint production caller: for one
//! product/session/attempt/route fingerprint it resolves the host-observed
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

use eliot_evaluation_contracts::ObservationCoverageManifest;

use crate::{
    AllowedHostManifestView, CoverageManifestPlan, DurableHostEventJournal, IngestError,
    ResolvedHostComplianceFacts,
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
