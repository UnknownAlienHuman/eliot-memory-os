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
