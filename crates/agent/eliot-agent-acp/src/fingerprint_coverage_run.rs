//! Per-fingerprint coverage-denominator production run (issue #1936 W1, I7.23).
//!
//! [`coverage_manifest_driver`] ships the denominator mechanics
//! ([`run_coverage_manifest`](crate::run_coverage_manifest) resolves the
//! host-observed compliance facts per stream, binds the caller-declared plan to
//! the pinned allowed Tool/Facet manifest revision, and retains the joined
//! denominator under the plan fingerprint). It deliberately mints no run
//! identity: it takes a caller-built
//! [`CoverageManifestRun`](crate::CoverageManifestRun) and never checks that the
//! four fingerprint components, the admitted route, the resolved facts and the
//! retained denominator belong to one another.
//!
//! This module is the production caller that closes that join. It is the
//! ACP-side per-fingerprint contour: the run owner that holds an
//! [`AcpSessionBinding`], its [`ProviderExecutionBinding`], its governing
//! [`AdmittedRouteReceipt`] and the run's caller-resolved
//! [`AllowedHostManifestView`] drives the whole fingerprint through
//! [`run_fingerprint_coverage_denominator`], which
//!
//! 1. validates every supplied identity through its existing owner validator
//!    ([`AcpSessionBinding::validate`], [`ProviderExecutionBinding::validate_internal`],
//!    [`AdmittedRouteReceipt::validate`]) — never a re-implemented check;
//! 2. requires the attempt identity and the admitted route to agree across all
//!    three owners, so facts resolved for one attempt can never be retained
//!    under another attempt's or another route's fingerprint;
//! 3. derives the [`RunFingerprint`] instead of accepting one: the route
//!    component is recomputed by the route owner's own identity function
//!    ([`route_fingerprint_digest_for`], the same recipe
//!    [`acp_adapter_contract`](crate::acp_adapter_contract) binds the admitted
//!    generation with), and the session and attempt components are the
//!    canonical text of the typed owner identities;
//! 4. takes the stream roster from the journal itself
//!    ([`DurableHostEventJournal::known_streams`]), never from a caller list, so
//!    the streams whose facts are resolved and the streams the retained
//!    denominator measures are the same partition by construction; and
//! 5. verifies after the fact that the retained denominator measured exactly
//!    that roster, so a future divergence between the fact-resolution roster and
//!    the measured cursor partition fails closed instead of retaining a
//!    denominator that covers streams no fact was resolved for.
//!
//! Every refusal is a typed [`IngestError`] and retains nothing partial.
//! Completeness, expected sources/classes, the observable/unobservable action
//! split, missing-source reasons, material-action coverage, denominator
//! origin/sampling and invalidation dependencies remain caller-declared
//! [`CoverageManifestDeclarations`] exactly as the driver requires; this
//! module validates nothing about them beyond what the joined manifest's own
//! `ObservationCoverageManifest::validate` already enforces at retention.
//!
//! The product identity and the allowed Tool/Facet manifest revision have no
//! owner inside this crate, so they arrive as the typed
//! [`ProductId`](eliot_contracts::ProductId) and [`AllowedHostManifestView`]
//! their upstream owners issue; this module never mints either. Because that
//! pinned view is the single owner of the revision, the plan digest and the
//! resolution digest both come from it: the driver's own plan-to-revision
//! binding check stays in force for every other caller of the exported driver,
//! and a plan that names any other revision cannot be built from this
//! constructor at all.

use eliot_agent_api::{AdmittedRouteReceipt, ProviderExecutionBinding, route_fingerprint_digest_for};
use eliot_contracts::ProductId;
use eliot_evaluation_contracts::{
    CoverageCompleteness, DenominatorOrigin, MaterialActionCoverage, RunFingerprint,
};

use crate::{
    AcpSessionBinding, AllowedHostManifestView, CoverageManifestPlan, CoverageManifestRun,
    DurableHostEventJournal, FingerprintIngestRunOutcome, IngestError, ReplayItem,
    run_ingest_for_fingerprint,
};

/// Caller-declared denominator halves for one ACP fingerprint run (issue #1936
/// W1, I7.23).
///
/// These are exactly the declarations the journal cannot observe and this
/// crate cannot mint: the expected event sources and classes, the observable
/// versus unobservable action split, the missing-source reasons, the
/// per-material-action and effect-route coverage, the denominator origin and
/// sampling policy, the claimed completeness, and the invalidation dependencies.
/// The fingerprint and the allowed-manifest digest are deliberately absent: the
/// production run derives the fingerprint from the identity owners and takes
/// the digest from the pinned allowed revision, so neither can be declared
/// independently of them.
///
/// The claimed completeness is still checked against the measured facts by the
/// joined denominator's own `ObservationCoverageManifest::validate` when it is
/// retained, so a declared `Complete` over measured blind intervals or
/// unaccounted events fails typed and retains nothing.
#[derive(Clone, Debug)]
pub struct CoverageManifestDeclarations<'a> {
    /// Declared expected event sources and classes.
    pub expected_event_sources_and_event_classes: &'a [String],
    /// Actions host observation can see.
    pub observable_actions: &'a [String],
    /// Actions host observation cannot see. Unobservable host-access coverage
    /// forces the derived trace to `UNKNOWN` or `TAINTED`, never a
    /// self-reported `PASS`.
    pub unobservable_actions: &'a [String],
    /// Declared missing-source reasons.
    pub missing_source_reasons: &'a [String],
    /// Declared per-material-action and effect-route coverage.
    pub coverage_by_material_action_and_effect_route: &'a [MaterialActionCoverage],
    /// Declared denominator origin and sampling policy.
    pub denominator_origin_and_sampling_policy: &'a DenominatorOrigin,
    /// Claimed completeness, checked against the measured facts.
    pub completeness: CoverageCompleteness,
    /// Declared invalidation dependencies.
    pub invalidation_dependencies: &'a [String],
}

/// Owner-issued identity and declarations for one ACP
/// product/session/attempt/route fingerprint (issue #1936 W1, I7.23).
///
/// Every field is a reference to an owner-issued value; nothing here is
/// constructed by this crate. The three identity owners must already agree
/// (attempt identity and admitted route equal across all three), which
/// [`run_fingerprint_coverage_denominator`] enforces before any stream is
/// driven.
#[derive(Clone, Debug)]
pub struct FingerprintCoverageRun<'a> {
    /// ACP session binding: external session identity, attempt identity, bound
    /// route, adapter revision and reconnect epoch.
    pub session: &'a AcpSessionBinding,
    /// Recorded #361 provider-execution binding for the bound attempt.
    pub execution: &'a ProviderExecutionBinding,
    /// Recorded #369 admitted-route receipt governing that binding.
    pub admission: &'a AdmittedRouteReceipt,
    /// Upstream-issued product identity the run belongs to.
    pub product: &'a ProductId,
    /// Caller-resolved pinned allowed Tool/Facet manifest revision.
    pub allowed: &'a AllowedHostManifestView<'a>,
    /// Caller-declared denominator halves for this fingerprint.
    pub declarations: &'a CoverageManifestDeclarations<'a>,
}

/// Drives the production host-event run for one
/// product/session/attempt/route fingerprint and retains its coverage
/// denominator (issue #1936 W1, I7.23).
///
/// This is the production caller of the per-fingerprint ingest flow: it derives
/// the run fingerprint from the identity owners, drives the observed reconnect
/// for every stream the journal actually holds records for, resolves the
/// host-observed compliance facts against the pinned allowed revision, retains
/// the joined denominator under that fingerprint, and returns the complete run
/// outcome (observed drives plus resolved facts plus the read-back manifest) for
/// the downstream evidence-assembly owner.
///
/// Fail-closed order, with nothing retained on any failure:
///
/// ```text
/// session binding validates      (AcpSessionBinding::validate)
///   -> execution binding validates (ProviderExecutionBinding::validate_internal)
///   -> admission validates       (AdmittedRouteReceipt::validate, with its
///                                 recorded self digest)
///   -> attempt identity agrees across all three owners
///   -> admitted route agrees with the session route
///   -> per-stream reconnect drive, then resolution, then retention
///   -> retained denominator covers exactly the resolved roster
/// ```
///
/// A staged-but-uncommitted record on any roster stream reports
/// [`IngestError::NotCommitted`] before any manifest is retained, because
/// uncommitted facts might contain the prohibited action. A refused downstream
/// delivery stops only that stream's drive (`stopped_early`); its committed
/// records still belong to the denominator, so the manifest run still proceeds.
/// An empty journal, an incomplete record set, or a digest-encoding failure are
/// typed refusals, never a partial denominator.
///
/// The plan-to-revision binding still verifies inside the driver: the retained
/// denominator's `allowed_manifest_digest` equals the pinned
/// [`AllowedHostManifestView::manifest_digest`] because both are taken from the
/// same owner-issued view, and any other drift between them is refused there.
pub fn run_fingerprint_coverage_denominator(
    owner: &mut DurableHostEventJournal,
    run: &FingerprintCoverageRun<'_>,
    mut deliver: impl FnMut(&ReplayItem) -> bool,
) -> Result<FingerprintIngestRunOutcome, IngestError> {
    run.session
        .validate()
        .map_err(|_| IngestError::InvalidInput("session.binding"))?;
    run.execution.validate_internal()?;
    run.admission.validate()?;
    if run.session.attempt_id != run.execution.attempt_id
        || run.session.attempt_id != run.admission.attempt_id
    {
        return Err(IngestError::InvalidInput("coverage_manifest.attempt_id"));
    }
    if run.session.route != run.execution.route
        || run.admission.selected_route.as_ref() != Some(&run.session.route)
    {
        return Err(IngestError::InvalidInput("coverage_manifest.route_fingerprint"));
    }
    // The roster is the journal's own observed stream set, never a caller list:
    // facts are resolved over exactly the streams the denominator will measure.
    let streams = owner.known_streams();
    let stream_ids: Vec<&str> = streams.iter().map(String::as_str).collect();
    let fingerprint = RunFingerprint {
        product_id: run.product.as_str().to_owned(),
        session_id: run.session.external_session_id.clone(),
        attempt_id: run.session.attempt_id.as_str().to_owned(),
        route_fingerprint: route_fingerprint_digest_for(&run.session.route)
            .map_err(|_| IngestError::DigestEncoding)?
            .as_str()
            .to_owned(),
    };
    let declared = run.declarations;
    let plan = CoverageManifestPlan {
        fingerprint: &fingerprint,
        allowed_manifest_digest: run.allowed.manifest_digest,
        expected_event_sources_and_event_classes: declared
            .expected_event_sources_and_event_classes,
        observable_actions: declared.observable_actions,
        unobservable_actions: declared.unobservable_actions,
        missing_source_reasons: declared.missing_source_reasons,
        coverage_by_material_action_and_effect_route: declared
            .coverage_by_material_action_and_effect_route,
        denominator_origin_and_sampling_policy: declared.denominator_origin_and_sampling_policy,
        completeness: declared.completeness,
        invalidation_dependencies: declared.invalidation_dependencies,
    };
    let manifest_run = CoverageManifestRun {
        stream_ids: &stream_ids,
        manifest_digest: run.allowed.manifest_digest,
        manifest_revision: run.allowed.manifest_revision,
        declared_tool_names: run.allowed.declared_tool_names,
        forbidden_tool_names: run.allowed.forbidden_tool_names,
        plan,
    };
    let outcome = run_ingest_for_fingerprint(owner, &manifest_run, &mut deliver)?;
    // The retained denominator must measure exactly the roster the facts were
    // resolved over; a divergence between the resolved roster and the measured
    // cursor partition fails closed instead of retaining a denominator that
    // covers streams no fact was resolved for.
    let roster_matches_measurement = {
        let mut measured: Vec<&str> = outcome
            .manifest
            .manifest
            .first_and_last_expected_cursors_by_stream
            .iter()
            .map(|range| range.stream.as_str())
            .collect();
        measured.sort_unstable();
        measured == stream_ids
    };
    if !roster_matches_measurement {
        return Err(IngestError::InvalidInput("coverage_manifest.streams"));
    }
    Ok(outcome)
}
