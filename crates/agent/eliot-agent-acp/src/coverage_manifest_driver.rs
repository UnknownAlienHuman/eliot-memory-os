//! Coverage-manifest driver for durable host-event ingest (issue #1936, I7.23).
//!
//! [`drive_coverage_manifest`] is the per-fingerprint production caller for
//! [`DurableHostEventJournal::record_coverage_manifest`]: for one
//! product/session/attempt/route fingerprint it resolves the host-observed
//! compliance facts for every named stream against the caller-supplied allowed
//! Tool/Facet manifest revision, verifies the denominator plan binds that same
//! revision, and then records the joined coverage denominator. Resolution runs
//! before retention, so staged-but-uncommitted facts abort with
//! [`IngestError::NotCommitted`] before any manifest is retained. The resolved
//! facts are returned for the downstream evidence-assembly owner; this driver
//! mints no declarations (expected sources, observable split, denominator
//! origin, completeness, invalidation) — those arrive in the caller plan,
//! which the run owner that knows the fingerprint supplies per fingerprint.

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

/// Runs the journal-owner coverage-manifest flow for one fingerprint: binds
/// the owner-resolved allowed revision into the resolution view, then invokes
/// [`drive_coverage_manifest`] with the owner-resolved streams, view, and
/// plan, returning the resolved facts for the downstream evidence-assembly
/// owner.
///
/// The plan-to-revision binding still verifies inside
/// [`drive_coverage_manifest`]: a plan digest that does not equal the
/// owner-resolved revision digest fails closed with
/// [`IngestError::InvalidInput`] and retains nothing.
pub fn run_coverage_manifest(
    owner: &mut DurableHostEventJournal,
    run: &CoverageManifestRun<'_>,
) -> Result<Vec<ResolvedHostComplianceFacts>, IngestError> {
    let allowed = AllowedHostManifestView {
        manifest_digest: run.manifest_digest,
        manifest_revision: run.manifest_revision,
        declared_tool_names: run.declared_tool_names,
        forbidden_tool_names: run.forbidden_tool_names,
    };
    drive_coverage_manifest(owner, run.stream_ids, &allowed, &run.plan)
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
