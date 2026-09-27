//! Versioned report artifacts projected from canonical audit/state only.
//!
//! Every artifact here is a pure projection: canonical state is taken by shared
//! reference, a new artifact is returned, and nothing in this module can write
//! canonical state or decide completion, acceptance, or `Finish`. A prior
//! artifact is never rewritten — changed canonical state produces a new report
//! revision, and the previous revision stays byte-identical.
//!
//! Report prose is a projection, never an authority input (I16.14): the
//! immutable input revisions below are the canonical references a reader
//! expands back to, and the rendered text carries no claim absent from them.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt::Write as _;

use eliot_contracts::{ClockReading, ContractError, StateFence, canonical_json_bytes, sha256_hex};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{CONTRACT_VERSION, ReportError, ReportKind, escape_markdown, valid_text};

/// Canonical source of a report artifact's input.
///
/// A source names where an immutable input revision was read from; it never
/// carries a claim about that source.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReportInputSource {
    /// Canonical audit log records the projection read.
    AuditLog,
    /// Canonical state snapshot the projection read.
    CanonicalState,
    /// Canonical evidence records the projection read.
    Evidence,
    /// Canonical task and completion records the projection read.
    TaskState,
    /// Canonical watchdog security records the projection read.
    WatchdogSecurity,
    /// Canonical backup and recovery records the projection read.
    BackupRecovery,
    /// Canonical architecture conformance records the projection read.
    ArchitectureConformance,
    /// Canonical release readiness records the projection read.
    ReleaseReadiness,
    /// Canonical product support and product evidence records the projection read.
    ProductSupport,
}

/// An immutable reference to one exact canonical input revision.
///
/// `input_id` is the stable source identity, `revision` is that source's
/// canonical revision at read time, and `input_digest` is the digest of the
/// exact canonical bytes the projection consumed. Every field is owned by
/// value, so an artifact cannot alias or later observe mutation of the state it
/// was projected from.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportInputRevision {
    /// Canonical source this input was read from.
    pub source: ReportInputSource,
    /// Stable identity of the read source.
    pub input_id: String,
    /// Canonical revision of the read source.
    pub revision: u64,
    /// Digest of the exact canonical bytes that were read.
    pub input_digest: String,
}

impl ReportInputRevision {
    /// Binds a source identity and revision to the digest of the exact
    /// canonical bytes that were read.
    ///
    /// The digest is computed here rather than accepted from the caller, so an
    /// input revision cannot name bytes it was not projected from.
    pub fn new(
        source: ReportInputSource,
        input_id: impl Into<String>,
        revision: u64,
        canonical_input_bytes: &[u8],
    ) -> Result<Self, ReportError> {
        let input_id = input_id.into();
        valid_text(&input_id, "input_id")?;
        Ok(Self {
            source,
            input_id,
            revision,
            input_digest: sha256_hex(canonical_input_bytes),
        })
    }

    /// Validates the reference without admitting it anywhere.
    pub fn validate(&self) -> Result<(), ReportError> {
        valid_text(&self.input_id, "input_id")
    }

    /// Ordering key used to canonicalize the input set.
    fn sort_key(&self) -> (&ReportInputSource, &str, u64) {
        (&self.source, self.input_id.as_str(), self.revision)
    }
}

/// The support state of the product, as read from canonical state.
///
/// This is the I0.13 product status vocabulary carried as data. The projection
/// surface names only the state that current canonical state actually holds:
/// acceptance is not established and behavior is unverified. No accepted or
/// verified state is representable here, so a projection cannot promote
/// support even by construction.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ProductSupportState {
    /// Product acceptance is absent and product behavior is unverified.
    NotAcceptedUnverified,
}

/// The support a single observed claim or row may carry.
///
/// The ceiling is the product support state itself; test, report, and commit
/// counts are not inputs to this projection and cannot produce a claim state
/// above [`ClaimSupportState::NotAcceptedUnverified`].
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ClaimSupportState {
    /// A direct observation in the named scope, without semantic promotion.
    Observed,
    /// Product acceptance is absent and the behavior is unverified.
    NotAcceptedUnverified,
    /// The behavior is unproven; absence of a signature is not verification.
    Unproven,
}

/// What canonical state observed about a live execution.
///
/// No live execution is representable as observed: the projection can only
/// record that none was observed, which is why live behavior stays unproven
/// instead of being reported as working.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum LiveExecutionObservation {
    /// No live execution of this surface has been observed.
    NotObserved,
}

/// One observed product claim bound to the exact source that observed it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductClaim {
    /// Stable claim identity.
    pub claim_id: String,
    /// Exact scope the claim was observed in; never widened here.
    pub scope: String,
    /// Strongest support the bound source justifies.
    pub support: ClaimSupportState,
    /// Canonical source that observed the claim.
    pub observed_by: ReportInputRevision,
}

/// A surface whose live runtime behavior remains unproven.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnprovenLiveSurface {
    /// Stable identity of the live surface.
    pub surface_id: String,
    /// Exact live behavior that remains unproven.
    pub unproven_behavior: String,
    /// What canonical state observed about live execution of this surface.
    pub live_execution: LiveExecutionObservation,
    /// Canonical source that observed the surface.
    pub observed_by: ReportInputRevision,
}

/// A verified product delta, valid only to its stated scope.
///
/// `stated_scope` is the delta's whole claim: a delta cannot be read outside
/// the scope it was verified to, and no projection extends it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedDelta {
    /// Stable delta identity.
    pub delta_id: String,
    /// Exact scope the delta is verified to; never inferred or widened.
    pub stated_scope: String,
    /// Canonical source that verified the delta at this scope.
    pub verified_by: ReportInputRevision,
}

/// An open causal gap: the link the available evidence does not close.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CausalGap {
    /// Stable gap identity.
    pub gap_id: String,
    /// The causal link that remains open.
    pub open_link: String,
    /// Canonical source that left the link open.
    pub observed_by: ReportInputRevision,
}

/// Canonical state observed for the product.
///
/// The projection borrows this state and owns a detached copy of what it
/// renders, so the artifact cannot observe later mutation of its inputs. This
/// type holds observations only; it is not canonical state and writes nothing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductState {
    /// Exact Product Identity the observations are bound to.
    pub product_identity: String,
    /// Product Objective the observations are bound to.
    pub product_objective: String,
    /// Product support state read from canonical state.
    pub support: ProductSupportState,
    /// Product claims observed in canonical state.
    pub claims: Vec<ProductClaim>,
    /// Live surfaces whose runtime behavior is unproven.
    pub unproven_live_surfaces: Vec<UnprovenLiveSurface>,
    /// Deltas verified to their stated scope only.
    pub verified_deltas: Vec<VerifiedDelta>,
    /// Causal links the available evidence does not close.
    pub causal_gaps: Vec<CausalGap>,
}

/// The `Product Progress` body: product support state, the absence of a live
/// Windows execution, verified deltas each with its stated scope, open causal
/// gaps, and unproven scope — all as structured data.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductProgressProjection {
    /// Exact Product Identity this projection is bound to.
    pub product_identity: String,
    /// Product Objective this projection is bound to.
    pub product_objective: String,
    /// Product support state read from canonical state.
    pub support: ProductSupportState,
    /// Claims observed in canonical state, in canonical order.
    pub claims: Vec<ProductClaim>,
    /// Live surfaces whose runtime behavior is unproven.
    pub unproven_live_surfaces: Vec<UnprovenLiveSurface>,
    /// Verified deltas, each with its stated scope.
    pub verified_deltas: Vec<VerifiedDelta>,
    /// Open causal gaps.
    pub causal_gaps: Vec<CausalGap>,
}

impl ProductProgressProjection {
    /// Projects Product Progress from canonical product state.
    ///
    /// Identical canonical state always yields an identical projection because
    /// every collection is ordered by its stable identity.
    pub fn project(state: &ProductState) -> Self {
        let mut claims = state.claims.clone();
        claims.sort_by(|left, right| left.claim_id.cmp(&right.claim_id));
        let mut unproven_live_surfaces = state.unproven_live_surfaces.clone();
        unproven_live_surfaces.sort_by(|left, right| left.surface_id.cmp(&right.surface_id));
        let mut verified_deltas = state.verified_deltas.clone();
        verified_deltas.sort_by(|left, right| left.delta_id.cmp(&right.delta_id));
        let mut causal_gaps = state.causal_gaps.clone();
        causal_gaps.sort_by(|left, right| left.gap_id.cmp(&right.gap_id));
        Self {
            product_identity: state.product_identity.clone(),
            product_objective: state.product_objective.clone(),
            support: state.support,
            claims,
            unproven_live_surfaces,
            verified_deltas,
            causal_gaps,
        }
    }

    /// Returns the immutable input revisions this projection was read from.
    pub fn input_revisions(&self) -> Vec<ReportInputRevision> {
        let mut inputs: Vec<ReportInputRevision> = Vec::new();
        inputs.extend(self.claims.iter().map(|claim| claim.observed_by.clone()));
        inputs.extend(
            self.unproven_live_surfaces
                .iter()
                .map(|surface| surface.observed_by.clone()),
        );
        inputs.extend(
            self.verified_deltas
                .iter()
                .map(|delta| delta.verified_by.clone()),
        );
        inputs.extend(self.causal_gaps.iter().map(|gap| gap.observed_by.clone()));
        inputs.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        inputs.dedup();
        inputs
    }

    /// Renders the projection; the text repeats structured fields and adds no
    /// claim of its own.
    pub fn markdown(&self) -> Result<String, ReportError> {
        let mut output = String::new();
        output.push_str("## Product Progress\n\n");
        writeln!(
            output,
            "- Product identity: `{}`",
            escape_markdown(&self.product_identity)
        )?;
        writeln!(
            output,
            "- Product objective: `{}`",
            escape_markdown(&self.product_objective)
        )?;
        writeln!(
            output,
            "- Product support: `{}`",
            support_text(self.support)
        )?;
        output.push_str("\n### Verified deltas (stated scope only)\n\n");
        if self.verified_deltas.is_empty() {
            output.push_str("No verified delta was read from canonical state.\n");
        } else {
            output.push_str("| Delta | Stated scope | Verified by |\n|---|---|---|\n");
            for delta in &self.verified_deltas {
                writeln!(
                    output,
                    "| `{}` | {} | `{}`@`{}` |",
                    escape_markdown(&delta.delta_id),
                    escape_markdown(&delta.stated_scope),
                    escape_markdown(&delta.verified_by.input_id),
                    delta.verified_by.revision
                )?;
            }
        }
        output.push_str("\n### Open causal gaps\n\n");
        if self.causal_gaps.is_empty() {
            output.push_str("No open causal gap was read from canonical state.\n");
        } else {
            output.push_str("| Gap | Open link | Observed by |\n|---|---|---|\n");
            for gap in &self.causal_gaps {
                writeln!(
                    output,
                    "| `{}` | {} | `{}`@`{}` |",
                    escape_markdown(&gap.gap_id),
                    escape_markdown(&gap.open_link),
                    escape_markdown(&gap.observed_by.input_id),
                    gap.observed_by.revision
                )?;
            }
        }
        output.push_str("\n### Unproven scope\n\n");
        if self.unproven_live_surfaces.is_empty() {
            output.push_str("No unproven live surface was read from canonical state.\n");
        } else {
            output
                .push_str("| Surface | Unproven behavior | Live execution | Observed by |\n|---|---|---|---|\n");
            for surface in &self.unproven_live_surfaces {
                writeln!(
                    output,
                    "| `{}` | {} | `{}` | `{}`@`{}` |",
                    escape_markdown(&surface.surface_id),
                    escape_markdown(&surface.unproven_behavior),
                    live_text(surface.live_execution),
                    escape_markdown(&surface.observed_by.input_id),
                    surface.observed_by.revision
                )?;
            }
        }
        Ok(output)
    }
}

/// The body of a required report family that is not Product Progress.
///
/// Each family projects the canonical rows it read under its own
/// [`ReportKind`]; the row shape stays the same across families so one
/// projection path serves them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportFamilyProjection {
    /// Family this body projects.
    pub kind: ReportKind,
    /// Canonical rows observed for the family, in canonical order.
    pub rows: Vec<ReportProjectionRow>,
}

/// One canonical row carried into a family projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportProjectionRow {
    /// Stable row identity.
    pub row_id: String,
    /// Exact scope the row was observed in.
    pub scope: String,
    /// Strongest support the bound source justifies.
    pub support: ClaimSupportState,
    /// Canonical source that observed the row.
    pub observed_by: ReportInputRevision,
}

/// Failures while projecting or validating a versioned report artifact.
#[derive(Debug, Error)]
pub enum ProjectionError {
    /// The report kind has no body on this projection surface.
    #[error("{kind:?} has no versioned projection body")]
    UnsupportedKind { kind: ReportKind },
    /// A projected input failed report-level validation.
    #[error("invalid projection input: {0}")]
    Input(#[from] ReportError),
    /// A projected input failed foundation contract validation.
    #[error("invalid projection input: {0}")]
    ContractInput(#[from] ContractError),
    /// Canonical JSON could not be produced.
    #[error("canonical projection serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
    /// Markdown formatting could not be completed.
    #[error("projection formatting failed: {0}")]
    Formatting(#[from] std::fmt::Error),
    /// A versioned artifact must bind at least one input revision.
    #[error("a versioned report artifact must bind at least one input revision")]
    NoInputRevisions,
    /// The stated revision does not advance past the prior artifact.
    #[error("report revision {revision} must exceed prior revision {prior}")]
    NonMonotonicRevision { prior: u64, revision: u64 },
    /// One canonical source identity is bound to two different revisions.
    #[error("input id {input_id} is bound to two different canonical revisions")]
    ConflictingInputRevision { input_id: String },
    /// The artifact hash does not match the artifact content.
    #[error("report_hash does not match canonical projection content")]
    HashMismatch,
}

/// A versioned report artifact projected from canonical state.
///
/// The artifact owns its inputs by value, so projecting again from changed
/// canonical state yields a new revision and leaves every prior artifact
/// unchanged. This type exposes no writer and no acceptance, completion, or
/// `Finish` decision: it is a read-only projection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectedReport {
    /// Stable report identity.
    pub report_id: String,
    /// Family this artifact projects.
    pub kind: ReportKind,
    /// Revision of this report identity; strictly advances past the prior one.
    pub revision: u64,
    /// Clock captured by the projection.
    pub generated_at: ClockReading,
    /// Immutable input revisions the projection was generated from.
    pub input_revisions: Vec<ReportInputRevision>,
    /// State fence at which the projection was read.
    pub state_fence: StateFence,
    /// Contract revision producing this shape.
    pub contract_version: String,
    /// Structured body of the projection.
    pub projection: ReportProjectionBody,
    /// Content digest of this artifact with `report_hash` blank.
    pub report_hash: String,
}

/// The structured body of a versioned report artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum ReportProjectionBody {
    /// Product Progress state, unproven scope, deltas, and causal gaps.
    ProductProgress(ProductProgressProjection),
    /// Canonical rows for one other required report family.
    Family(ReportFamilyProjection),
}

impl ReportProjectionBody {
    /// Returns the family this body projects.
    pub fn kind(&self) -> ReportKind {
        match self {
            Self::ProductProgress(_) => ReportKind::ProductProgress,
            Self::Family(family) => family.kind,
        }
    }
}

/// The read facts one projection was generated from.
///
/// The request is consumed immediately into a new artifact; nothing is stored
/// on it and no canonical state is reachable from it.
struct ProjectionRequest {
    /// Stable report identity being projected.
    report_id: String,
    /// Revision of the existing artifact for this report identity.
    prior_revision: u64,
    /// Revision the new artifact must carry.
    revision: u64,
    /// Family being projected.
    kind: ReportKind,
    /// Immutable input revisions read for this projection.
    input_revisions: Vec<ReportInputRevision>,
    /// Clock captured by the projection.
    generated_at: ClockReading,
    /// State fence at which the projection was read.
    state_fence: StateFence,
    /// Structured body of the projection.
    projection: ReportProjectionBody,
}

impl ProjectedReport {
    /// Projects a new revision of a `Product Progress` artifact from
    /// canonical product state.
    ///
    /// `state` is borrowed and `revision` must exceed `prior_revision`, the
    /// revision of the existing artifact for this `report_id`. A prior artifact
    /// is therefore never rewritten in place: changed canonical state shows up
    /// as a new revision. Nothing here writes canonical state.
    pub fn project_product_progress(
        report_id: impl Into<String>,
        prior_revision: u64,
        revision: u64,
        state: &ProductState,
        generated_at: ClockReading,
        state_fence: StateFence,
    ) -> Result<Self, ProjectionError> {
        let projection = ProductProgressProjection::project(state);
        let input_revisions = projection.input_revisions();
        Self::new(ProjectionRequest {
            report_id: report_id.into(),
            prior_revision,
            revision,
            kind: ReportKind::ProductProgress,
            input_revisions,
            generated_at,
            state_fence,
            projection: ReportProjectionBody::ProductProgress(projection),
        })
    }

    /// Projects a new revision of one other required report family from the
    /// canonical rows it read.
    ///
    /// `Product Progress` has its own body and is rejected here so a family
    /// artifact cannot impersonate it.
    pub fn project_family(
        report_id: impl Into<String>,
        prior_revision: u64,
        revision: u64,
        kind: ReportKind,
        rows: &[ReportProjectionRow],
        generated_at: ClockReading,
        state_fence: StateFence,
    ) -> Result<Self, ProjectionError> {
        if kind == ReportKind::ProductProgress {
            return Err(ProjectionError::UnsupportedKind { kind });
        }
        let mut rows = rows.to_vec();
        rows.sort_by(|left, right| left.row_id.cmp(&right.row_id));
        let mut input_revisions: Vec<ReportInputRevision> =
            rows.iter().map(|row| row.observed_by.clone()).collect();
        input_revisions.sort_by(|left, right| left.sort_key().cmp(&right.sort_key()));
        input_revisions.dedup();
        Self::new(ProjectionRequest {
            report_id: report_id.into(),
            prior_revision,
            revision,
            kind,
            input_revisions,
            generated_at,
            state_fence,
            projection: ReportProjectionBody::Family(ReportFamilyProjection { kind, rows }),
        })
    }

    /// Returns whether this revision supersedes a prior artifact of the same
    /// report identity, meaning the prior artifact is now historical.
    pub fn supersedes(&self, prior: &ProjectedReport) -> bool {
        self.report_id == prior.report_id
            && self.kind == prior.kind
            && self.revision > prior.revision
    }

    /// Returns canonical JSON bytes with recursively sorted object keys.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ProjectionError> {
        self.validate()?;
        Ok(canonical_json_bytes(self)?)
    }

    /// Renders a stable Markdown projection of this artifact.
    ///
    /// The text is a rendering of the structured fields above. It is never an
    /// authority input: a reader expands back to `input_revisions`.
    pub fn markdown(&self) -> Result<String, ProjectionError> {
        self.validate()?;
        let mut output = String::new();
        output.push_str("# ELIOT Versioned Report\n\n");
        writeln!(output, "- Report: `{}`", escape_markdown(&self.report_id))?;
        writeln!(
            output,
            "- Kind: `{}`",
            serde_json::to_string(&self.kind)?.trim_matches('"')
        )?;
        writeln!(output, "- Revision: `{}`", self.revision)?;
        writeln!(output, "- Contract: `{}`", self.contract_version)?;
        writeln!(output, "- Report hash: `{}`", self.report_hash)?;
        output.push_str("\n## Input revisions\n\n");
        output.push_str("| Source | Input | Revision | Digest |\n|---|---|---|---|\n");
        for input in &self.input_revisions {
            writeln!(
                output,
                "| `{}` | `{}` | `{}` | `{}` |",
                serde_json::to_string(&input.source)?.trim_matches('"'),
                escape_markdown(&input.input_id),
                input.revision,
                input.input_digest
            )?;
        }
        match &self.projection {
            ReportProjectionBody::ProductProgress(progress) => {
                output.push_str(&progress.markdown()?);
            }
            ReportProjectionBody::Family(family) => {
                output.push_str("\n## Rows\n\n");
                if family.rows.is_empty() {
                    output.push_str("No canonical row was read for this family.\n");
                } else {
                    output.push_str("| Row | Scope | Support | Observed by |\n|---|---|---|---|\n");
                    for row in &family.rows {
                        writeln!(
                            output,
                            "| `{}` | {} | `{}` | `{}`@`{}` |",
                            escape_markdown(&row.row_id),
                            escape_markdown(&row.scope),
                            claim_text(row.support),
                            escape_markdown(&row.observed_by.input_id),
                            row.observed_by.revision
                        )?;
                    }
                }
            }
        }
        Ok(output)
    }

    /// Validates the artifact and its self-describing deterministic hash.
    pub fn validate(&self) -> Result<(), ProjectionError> {
        valid_text(&self.report_id, "report_id")?;
        if self.input_revisions.is_empty() {
            return Err(ProjectionError::NoInputRevisions);
        }
        for input in &self.input_revisions {
            input.validate()?;
        }
        detect_conflicting_revisions(&self.input_revisions)?;
        if self.projection.kind() != self.kind {
            return Err(ProjectionError::UnsupportedKind { kind: self.kind });
        }
        self.generated_at.validate()?;
        self.state_fence.validate()?;
        if self.report_hash != self.content_hash()? {
            return Err(ProjectionError::HashMismatch);
        }
        Ok(())
    }

    fn new(request: ProjectionRequest) -> Result<Self, ProjectionError> {
        let ProjectionRequest {
            report_id,
            prior_revision,
            revision,
            kind,
            input_revisions,
            generated_at,
            state_fence,
            projection,
        } = request;
        valid_text(&report_id, "report_id")?;
        if revision <= prior_revision {
            return Err(ProjectionError::NonMonotonicRevision {
                prior: prior_revision,
                revision,
            });
        }
        if input_revisions.is_empty() {
            return Err(ProjectionError::NoInputRevisions);
        }
        generated_at.validate()?;
        state_fence.validate()?;
        let mut report = Self {
            report_id,
            kind,
            revision,
            generated_at,
            input_revisions,
            state_fence,
            contract_version: CONTRACT_VERSION.to_owned(),
            projection,
            report_hash: String::new(),
        };
        for input in &report.input_revisions {
            input.validate()?;
        }
        detect_conflicting_revisions(&report.input_revisions)?;
        report.report_hash = report.content_hash()?;
        Ok(report)
    }

    fn content_hash(&self) -> Result<String, ProjectionError> {
        let mut material = self.clone();
        material.report_hash.clear();
        Ok(sha256_hex(&canonical_json_bytes(&material)?))
    }
}

/// Rejects two different canonical revisions bound to one source identity.
///
/// An input revision is immutable, so the same source identity appearing with
/// two different revisions or digests is a contradiction rather than a range.
fn detect_conflicting_revisions(inputs: &[ReportInputRevision]) -> Result<(), ProjectionError> {
    let mut bound: BTreeMap<(&ReportInputSource, &str), (u64, &str)> = BTreeMap::new();
    for input in inputs {
        let current = (input.revision, input.input_digest.as_str());
        match bound.entry((&input.source, input.input_id.as_str())) {
            Entry::Vacant(slot) => {
                slot.insert(current);
            }
            Entry::Occupied(slot) => {
                if slot.get() != &current {
                    return Err(ProjectionError::ConflictingInputRevision {
                        input_id: input.input_id.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn support_text(value: ProductSupportState) -> &'static str {
    match value {
        ProductSupportState::NotAcceptedUnverified => "NOT_ACCEPTED / UNVERIFIED",
    }
}

fn claim_text(value: ClaimSupportState) -> &'static str {
    match value {
        ClaimSupportState::Observed => "OBSERVED",
        ClaimSupportState::NotAcceptedUnverified => "NOT_ACCEPTED / UNVERIFIED",
        ClaimSupportState::Unproven => "UNPROVEN",
    }
}

fn live_text(value: LiveExecutionObservation) -> &'static str {
    match value {
        LiveExecutionObservation::NotObserved => "NOT_OBSERVED",
    }
}
