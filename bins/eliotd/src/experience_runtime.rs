//! Experience runtime driver: terminal observation/quality invocation over
//! the real bridge client (#223 B-consumer lane).
//!
//! Daemon-side production edge for the experience lane, mirroring
//! [`governor_local_read`](super::governor_local_read): a per-call factory
//! over [`DaemonComposition::context_read_client`], so the composition
//! retains no client and no thread and a Governor refresh surfaces as an
//! exact fence mismatch instead of silent divergence. Two drivers:
//!
//! - [`read_current_position`]: the TRUE edge position read. Issues the
//!   existing `GetCurrentEpistemicPosition` catalogue read (scope-bound,
//!   `ExactFence`, `position` subject) through the Governor read owner
//!   ([`ReadService`]) over the real
//!   [`KernelContextReadClient`](super::KernelContextReadClient), and
//!   extracts the `Current` admitted position from the durable readback.
//!   The selection joins the readback to the exact request and requires a
//!   unique current answer ([`select_current_position`]), not an
//!   input-order `find`: a payload carrying another scope, a substituted
//!   position inside it, or several current positions is a refusal, while a
//!   store `null` readback stays the existing explicit absence.
//!   Works today: capability and store handler both exist. Routing the
//!   request through the read owner rather than the raw Store port is what
//!   keeps this leg a consumer of the one read engine instead of a second
//!   answer to the same source/fence/freshness questions (#1144).
//! - [`read_experience_range_page`]: the bounded outcome-experience page
//!   read, one family per call. Issues the bank or feedback range operation
//!   (`GetExperienceBankRange` / `GetAgentFeedbackRange`), but selects it
//!   through the Store's own exported read names
//!   ([`EXPERIENCE_BANK_READ_NAME`], [`EXPERIENCE_FEEDBACK_READ_NAME`]) and
//!   the Store's own read catalogue
//!   ([`named_read_operation_by_name`], [`named_read_operation_name`]), with
//!   the request itself built by the Store's own builders
//!   ([`experience_bank_read_request`], [`experience_feedback_read_request`]),
//!   as a [`ReadApi::bound_query`] read over a per-call [`ReadService`] with
//!   the same observed scope-head dependency minimum the position leg uses.
//!
//!   The `NamedReadOperation` variant is deliberately **not** restated as code
//!   anywhere in this entry, so a Store rename moves it with the rename
//!   instead of leaving a stale literal here. One reader-visible consequence
//!   is worth stating plainly, because it looks like a defect otherwise: a
//!   reader who greps `bins/` for the literal `GetExperienceBankRange` finds
//!   only prose — this paragraph and the entry's own doc — and never a
//!   request construction. That absence is the design, not an omission; the
//!   construction is the Store builder reached through the catalogue lookup,
//!   and a `NamedReadOperation` literal added to satisfy that grep would be
//!   precisely the drift this rule prevents (#1144).
//!
//!   It is the production issuer of the two operations whose Store page
//!   coverage statement the read owner gates on: through it a
//!   source-declared truncated page is refused as `ReadOutcome::Partial`
//!   instead of reaching the experience leg as a page whose truncation nobody
//!   classified (#1144).
//! - [`produce_journal_projection`]: the terminal journal-leg call. Runs
//!   the provider chain
//!   ([`produce_journal_read`](eliot_experience_provider::produce_journal_read))
//!   with the real bridge client and caller-supplied live presence. Fails
//!   closed with `UnknownOperation` until the store side registers the
//!   `GetAuditRange` handler (#19 join); the call itself rides existing
//!   path machinery, exactly like the projection-inputs port-shape probe.
//!
//! Bank/feedback durable supply is read through the read owner by
//! [`read_experience_range_page`] and stays canonical-owner side; the
//! admission context that read is projected under, plus per-attempt receipts
//! and obligation handles, arrive with the trigger edge (O1 registration
//! hunk): this driver invents none of them. No policy, admission, or semantic
//! rule lives here; fence agreement and response identity fail closed before
//! any shaping.
//!
//! # Live status
//!
//! The whole of this module is currently **unreached from a run of this
//! daemon**, so the "Daemon-side production edge" sentence above describes the
//! intended contour rather than an executed one. Measured on this tree by
//! symbol, counting only non-test code (this file now carries one
//! `#[cfg(test)] mod current_position_join_tests`, which exercises
//! [`select_current_position`] and adds no production call site):
//!
//! - `run_experience_quality_event_with_revision` and
//!   `commit_experience_event_records` have **zero call sites**; every other
//!   entry here is called only from inside this module or from the crate-root
//!   `pub use` block in `lib.rs`. `read_current_position`,
//!   `propose_memory_extinction_candidate` and `derive_commit_ingress` each
//!   have exactly one in-file caller, and
//!   `produce_journal_projection` and `read_experience_range_page` are reached
//!   only from the uncalled `run_experience_quality_event`. The new entry is
//!   not in the `lib.rs` `pub use` list either (that block is outside this
//!   delivery's mutable path), so nothing outside this crate can reach it
//!   today either way.
//! - `eliotd` declares **no reverse dependency** in any workspace
//!   `Cargo.toml` and none in `Cargo.lock`, so nothing outside this crate can
//!   call the re-exported surface either.
//! - The two mentions of `run_experience_quality_event` outside this file are
//!   **string literals** in `maintenance_family_catalog.rs` — an
//!   `owned_by!("...run_experience_quality_event")` owner declaration and a
//!   rationale sentence. Neither is a call.
//!
//! What would change this is one call site holding an admitted
//! `ExperienceQualityEvent` (and, for the revision leg, an owner-issued
//! `RevisionIntake`). No caller was invented to close the gap.
//!
//! # Three declared `eliot-dreamer` dependency edges reach only this module
//!
//! `bins/eliotd/Cargo.toml` declares `eliot-dreamer-contracts`,
//! `eliot-dreamer-memory-revision` and `eliot-dreamer-failure`, and the
//! `eliotd` row of `config/architecture-boundaries.toml` lists
//! `eliot-dreamer` under `forbidden_prefix` (issue #18), so all three are
//! reported as `runtime_root_forbidden_direct_dependency` `HARD_VIOLATIONs` by
//! `scripts/audit-architecture-boundaries.py`. The first two are named only
//! here; the third is named in `negative_memory_action_gate.rs`, which carries
//! its own reachability note.
//!
//! This disclosure records **reachability only**. Whether the daemon should
//! keep these three edges — by narrowing the `forbidden_prefix` row, by giving
//! the entries above real callers, or by removing the edges — is an
//! architecture decision that is **not settled here**, and the dependency
//! declarations are left exactly as they are. The types are not wire types for
//! this purpose: the three edges feed pure in-memory owner calls, and the only
//! `Serialize`/`Deserialize` derives in the three donor crates annotate their
//! own record types, not this module's signatures.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use eliot_cognitive_quality::QualityAssessmentCandidate;
use eliot_context_contracts::ActiveUnderstandingView;
use eliot_contracts::{ArtifactId, RequestMetadata, StateFence};
use eliot_dreamer_contracts::self_query::AcceptedSourceProjection;
use eliot_dreamer_memory_revision::{
    NegativeMemoryExtinctionCandidate, RevisionError, RevisionIntake,
};
use eliot_epistemic_contracts::{CurrentEpistemicPosition, Currentness, ProviderContribution};
use eliot_experience_provider::{
    BankShapeInputs, ExperienceView, FeedbackShapeInputs, JournalShapeOutput, ProduceJournalInputs,
    ProviderError, RetentionContext, SelfQualityInputs, SelfQualityRecheckInputs, WithheldMember,
    assess_and_recheck, produce_common_ground_assessment, produce_journal_read,
    produce_memory_quality, produce_understanding_assessment,
};
use eliot_learning_contracts::HarnessActivationReceiptCandidate;
use eliot_memory_quality::{MemoryEcologyAssessment, QualityRequest};
use eliot_observation::{
    GovernorObservationError,
    bank_admission::{
        BankStoreSnapshot, ExperienceRevisionLedger, FeedbackStoreSnapshot,
        bank_records_from_range_payload, feedback_records_from_range_payload, produce_bank_commit,
        produce_feedback_commit, supply_bank_projection_from_store,
        supply_feedback_projection_from_store,
    },
};
use eliot_observation_contracts::{
    AgentFeedbackRecord, ExperienceBankRecord, ObservationScope, ProjectionCoverage,
    ProjectionOmission, RetentionHold, RetentionSchedule,
};
use eliot_protocol::RequestIdentity;
use eliot_read::{
    BoundRead, BranchEnvironmentScope, FreshnessPolicy, NamedParameters, QueryIntent, QueryMode,
    QueryRequest, QueryResult, ReadApi, ReadError, ReadOrderingBinding, ReadService,
    RequiredAssurance, StateRequest, TimeScope, prove_page_state_fence,
};
use eliot_receipts::{RequestBinding, WorkScopeId};
use eliot_store_api::{
    CanonicalReadClient, EXPERIENCE_BANK_READ_NAME, EXPERIENCE_FEEDBACK_READ_NAME,
    EXPERIENCE_PAGE_NEXT_CURSOR, MAX_EXPERIENCE_PAGE_RECORDS, NamedReadOperation,
    OrderingHeadExpectation, ReadConsistency, RevisionHeadExpectation, RevisionKey, ScopeId,
    StoreError, WriteReceipt, epistemic_revision::EpistemicPositionReadback,
    experience_bank_read_request, experience_feedback_read_request, named_read_operation_by_name,
    named_read_operation_name,
};
use eliot_understanding_assessment::{
    AssessmentClosure, AssessmentScope, CommonGroundAssessment, CommonGroundInput, EvidenceCite,
    ExperienceEvidence, OwnerContext, ScopedUnderstandingAssessment,
};
use thiserror::Error;

use super::{DaemonComposition, DaemonKernelClient};

/// Typed failures of the experience runtime driver.
#[derive(Debug, Error)]
pub enum ExperienceDriverError {
    /// The bridge client could not be constructed from the composition.
    #[error("daemon composition refused the bridge client: {0}")]
    Composition(String),
    /// The bridge call failed.
    #[error("bridge read failed: {0}")]
    Bridge(#[from] StoreError),
    /// The Governor read owner refused or degraded the read.
    ///
    /// This keeps the read owner's closed [`ReadOutcome`] vocabulary intact at
    /// the driver boundary: `NotRunning`, `Unknown`, `Partial`,
    /// `Unavailable`, `Stale` and `Conflicted` arrive as distinct typed
    /// values rather than collapsing into one "bridge failed" string, and
    /// none of them can be read back as a successful empty result.
    #[error("governor read owner: {0}")]
    ReadOwner(#[from] ReadError),
    /// The provider chain rejected the read.
    #[error("experience provider: {0}")]
    Provider(#[from] ProviderError),
    /// The Governor owner rejected admission, supply, or readback parsing.
    #[error("governor observation owner: {0}")]
    Governor(#[from] GovernorObservationError),
    /// The position readback holds no usable current position.
    #[error("position field {field}: {reason}")]
    Position {
        field: &'static str,
        reason: &'static str,
    },
    /// Admitted commit ingress could not be derived from retained state.
    #[error("commit ingress field {field}: {reason}")]
    Ingress {
        field: &'static str,
        reason: &'static str,
    },
    /// The Governor-backed experience commit failed.
    #[error("experience commit failed: {0}")]
    Commit(String),
}

/// Maps a Dreamer memory-revision owner rejection into the Governor
/// leg of the driver error.
///
/// The observer-shape rejection maps exactly
/// ([`RevisionError::Observation`] into
/// [`GovernorObservationError::Observation`]: both name
/// `eliot_observation_contracts::ObservationError`). The remaining
/// intake/candidate rejections have no exact Governor counterpart, so
/// they narrow to [`GovernorObservationError::InvalidField`] with the
/// owner-issued field path forwarded verbatim and a fixed reason naming
/// the violated intake contract. The wrapped source detail is not
/// preserved; the field plus reason still fail closed at the same
/// boundary. This mirrors the `produce_memory_quality` pattern: the
/// owner call returns its own error and `?` converts at the call site.
impl From<RevisionError> for ExperienceDriverError {
    fn from(error: RevisionError) -> Self {
        ExperienceDriverError::Governor(match error {
            RevisionError::Observation(inner) => GovernorObservationError::Observation(inner),
            RevisionError::Context(_) => GovernorObservationError::InvalidField {
                field: "dmr.intake.projection",
                reason: "admitted task/safety projection rejected its shape",
            },
            RevisionError::SelfQuery(_) => GovernorObservationError::InvalidField {
                field: "dmr.intake.query",
                reason: "frozen self-query input or accepted-source projection rejected its shape",
            },
            RevisionError::ScopeMismatch { field } => GovernorObservationError::InvalidField {
                field,
                reason: "admitted scope identity does not match its governing scope",
            },
            RevisionError::FenceMismatch { field } => GovernorObservationError::InvalidField {
                field,
                reason: "admitted fence is incompatible with its governing fence",
            },
            RevisionError::DigestMismatch { field } => GovernorObservationError::InvalidField {
                field,
                reason: "posed digest does not match the frozen query it claims",
            },
            RevisionError::StaleCitation { field } => GovernorObservationError::InvalidField {
                field,
                reason: "cited source triple is stale or uncited",
            },
            RevisionError::Bounds { field } => GovernorObservationError::InvalidField {
                field,
                reason: "admitted intake bound exceeded",
            },
            RevisionError::NotDigestible => GovernorObservationError::InvalidField {
                field: "dmr.candidate.digest",
                reason: "candidate is not canonically encodable",
            },
        })
    }
}

/// Dreamer memory-revision consumer invocation: propose one advisory
/// extinction candidate over admitted intake.
///
/// Calls the released `eliot_dreamer_memory_revision::propose`
/// consumer with the edge-supplied owner intake (owner-neutral failure
/// observation, revision evidence refs, admitted task/safety
/// projections, frozen self-query/accepted-source refs, pose digest,
/// candidate id). Intake contract violations fail closed as
/// [`ExperienceDriverError::Governor`]; valid intake with insufficient
/// evidence yields `Ok` with state `Inconclusive` or `Unsupported`
/// naming the exact missing evidence. No automatic trigger lives here:
/// the caller passes intake only when the trigger edge already holds
/// every admitted member; nothing is synthesized from the quality
/// event's bank/feedback envelopes.
///
/// Not reached from a run of this daemon. Its only call site is in
/// `run_experience_quality_event_with_revision`, which has none; see this
/// module's "Live status" section.
pub fn propose_memory_extinction_candidate(
    intake: &RevisionIntake<'_>,
) -> Result<NegativeMemoryExtinctionCandidate, ExperienceDriverError> {
    Ok(eliot_dreamer_memory_revision::propose(intake)?)
}

/// Joins one admitted position readback to the exact request that asked for
/// it and refuses anything that is not uniquely selected.
///
/// The join uses the store's own binding fields, never a name this file
/// supplies. `GetCurrentEpistemicPosition` is keyed by
/// `position_key(candidate.scope, payload.position)` on both backends, so
/// those two members are exactly what the request selected:
///
/// - `readback.candidate.scope` must be the requested scope. That is the
///   scope half of the key the store looked the read up under, so a payload
///   carrying a different one answers a different read.
/// - every returned position's `admission.scope` and `admission.position`
///   must be the requested scope and the requested position subject. The
///   position half reaches the readback through `AdmittedReceipt::position`,
///   which `EpistemicCommit::readback` fills from `payload.position`; note it
///   is NOT `candidate.proposition`, which is a different field of a
///   different type and is deliberately not compared here. One substituted
///   position inside an otherwise-matching readback fails the whole read
///   rather than being skipped.
/// - exactly one of those positions may be `Currentness::Current`. Zero is
///   the existing explicit absence; more than one is a conflict.
///   Input-order selection is not a resolution: `EpistemicCommit::readback`
///   mints one admitted view per claim, so an arbitrary pick among several
///   current views would hand the assessment a claim the owner never singled
///   out, with no field recording which one was chosen.
///
/// Positions are validated by their own `validate()` at the call site before
/// this runs; this adds the request binding and the uniqueness rule, not a
/// second position contract.
fn select_current_position(
    readback_scope: &str,
    positions: &[CurrentEpistemicPosition],
    scope: &ScopeId,
    position_subject: &str,
) -> Result<CurrentEpistemicPosition, ExperienceDriverError> {
    let absent = || ExperienceDriverError::Position {
        field: "positions",
        reason: "no current admitted position in the readback",
    };
    if readback_scope != scope.as_str() {
        return Err(ExperienceDriverError::Position {
            field: "response.payload.candidate.scope",
            reason: "readback candidate does not answer the requested scope",
        });
    }
    let mut current: Option<CurrentEpistemicPosition> = None;
    for position in positions {
        if position.admission.scope != scope.as_str()
            || position.admission.position.as_str() != position_subject
        {
            return Err(ExperienceDriverError::Position {
                field: "positions",
                reason: "admitted position does not answer the requested scope and position subject",
            });
        }
        if position.currentness != Currentness::Current {
            continue;
        }
        if current.is_some() {
            return Err(ExperienceDriverError::Position {
                field: "positions",
                reason: "more than one current admitted position answers the request",
            });
        }
        current = Some(position.clone());
    }
    current.ok_or_else(absent)
}

/// Read the TRUE admitted edge position through the Governor read owner.
///
/// Issues `GetCurrentEpistemicPosition` (scope-bound, `ExactFence`, exact
/// `position` subject) as a [`ReadApi::bound_state`] read over a per-call
/// `ReadService` wrapping the real
/// [`KernelContextReadClient`](super::KernelContextReadClient), then parses
/// the durable readback and returns the `Current` admitted position. A
/// superseded or absent current position fails closed; nothing is synthesized.
///
/// #1144: this leg used to build a bare `NamedReadRequest` and call
/// `CanonicalReadClient::execute_named` directly, which made it a second
/// answer to source, fence and freshness questions the read owner already
/// answers. It now goes through the one engine, which adds the source/schema/
/// coverage comparison, the order-head declaration, the observed-head
/// closure, the exact-fence stale check and the degraded-payload refusal that
/// the raw port had none of. The response is still validated here: the owner
/// proves the read is *current*, and this consumer still has to prove the
/// payload is the versioned position readback it expects.
///
/// The `ExactFence` dependency is **observed, not invented**: the current
/// scope revision head is read first and its revision becomes the declared
/// minimum, so a head that moves between the two reads fails closed as
/// [`ReadError::StaleRevision`] rather than being served as current.
pub async fn read_current_position(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    scope: ScopeId,
    position_subject: String,
) -> Result<CurrentEpistemicPosition, ExperienceDriverError> {
    if position_subject.trim().is_empty() || position_subject.chars().any(char::is_control) {
        return Err(ExperienceDriverError::Position {
            field: "position_subject",
            reason: "must be non-blank and free of control characters",
        });
    }
    ctx.validate()
        .map_err(|_| ExperienceDriverError::Position {
            field: "request_metadata",
            reason: "invalid request metadata",
        })?;
    let client = composition
        .context_read_client(kernel)
        .map_err(|error| ExperienceDriverError::Composition(error.to_string()))?;
    let scope_key = RevisionKey::new(format!("scope:{scope}"))?;
    let observed = client.revision_heads(vec![scope_key.clone()]).await?;
    let minimum = observed.iter().find(|head| head.key == scope_key).ok_or(
        ExperienceDriverError::Position {
            field: "revision_heads",
            reason: "store observed no head for the requested scope",
        },
    )?;
    let mut dependency_revisions = BTreeMap::new();
    dependency_revisions.insert(scope_key, minimum.revision);
    let parameters = NamedParameters::from_map(BTreeMap::from([(
        "position".to_owned(),
        serde_json::Value::String(position_subject.clone()),
    )]))
    .map_err(ExperienceDriverError::ReadOwner)?;
    let reads = ReadService::new(client);
    let bound = reads
        .bound_state(
            ctx,
            StateRequest {
                operation: NamedReadOperation::GetCurrentEpistemicPosition,
                scope_id: Some(scope.clone()),
                consistency: ReadConsistency::ExactFence,
                dependency_revisions,
                // This position read declares no conflict-serialization head:
                // its coherence is proven by the scope revision head observed
                // above plus the request fence. The declaration is explicit so
                // the resolved identity records the absence instead of leaving
                // the order-head dimension unstated.
                ordering: ReadOrderingBinding::without_order_dependency(),
                parameters,
                provenance_handles: Vec::new(),
            },
        )
        .await?;
    let response = &bound.view;
    if response.operation != NamedReadOperation::GetCurrentEpistemicPosition {
        return Err(ExperienceDriverError::Position {
            field: "response.operation",
            reason: "bridge did not answer the position read",
        });
    }
    // An absent position is the store's own `null` readback, which is the
    // explicit absence this entry already reported; it is decoded as such
    // rather than as a malformed payload.
    let readback: Option<EpistemicPositionReadback> =
        serde_json::from_value(response.payload.clone()).map_err(|_| {
            ExperienceDriverError::Position {
                field: "response.payload",
                reason: "position readback is not the versioned shape",
            }
        })?;
    let Some(readback) = readback else {
        return Err(ExperienceDriverError::Position {
            field: "positions",
            reason: "no current admitted position in the readback",
        });
    };
    for position in &readback.positions {
        position
            .validate()
            .map_err(|_| ExperienceDriverError::Position {
                field: "positions",
                reason: "admitted position is invalid",
            })?;
    }
    select_current_position(
        &readback.candidate.scope,
        &readback.positions,
        &scope,
        &position_subject,
    )
}

/// Requested page bound for one outcome-experience range read (#1144).
///
/// Derived from the Store's own ceiling rather than restated as a second page
/// size here, because both backends decide truncation by limit-plus-one: the
/// Surreal contour fetches `start + limit + 1` rows so one probe row decides
/// truncation without a second query
/// (`crates/storage/eliot-store-surreal-adapter/src/apply/read_boundary.rs:3425`),
/// and the memory contour pushes one row past the bound and pops it back out
/// while setting `truncated`
/// (`crates/storage/eliot-store-memory/src/lib.rs:2591`). A page is therefore
/// refused as `ReadOutcome::Partial` exactly when the scope holds MORE rows
/// than the requested bound, which makes the bound the one page-size fact this
/// leg would otherwise be inventing: it is the largest bound strictly below
/// [`MAX_EXPERIENCE_PAGE_RECORDS`], i.e. the closest admissible page to the
/// ceiling. [`read_experience_range_page`] refuses the ceiling itself rather
/// than trusting every call site to stay below it.
const EXPERIENCE_RANGE_PAGE_BOUND: u16 = MAX_EXPERIENCE_PAGE_RECORDS - 1;

/// Read ONE bounded page of an outcome-experience family through the
/// Governor read owner.
///
/// This is the production issuer of the only two operations whose page coverage
/// statement the read owner gates on. The Store declares both
/// ([`EXPERIENCE_BANK_READ_NAME`], [`EXPERIENCE_FEEDBACK_READ_NAME`]), both
/// backends project both, and the Store's own builders
/// ([`experience_bank_read_request`], [`experience_feedback_read_request`])
/// build both, but before this entry nothing in the tree dispatched one — so
/// the owner's only `ReadOutcome::Partial` construction site (the truncated arm
/// of its page-coverage classification, reached only through these two
/// operations) had no issuer at all, and a caller-carried page could reach the
/// experience leg with its truncation flag classified by nobody.
///
/// The family is selected through the Store's own exported read names and the
/// Store's own name owner: `read_name` is resolved into the closed read
/// catalogue, matched against those two names, and the request itself (the
/// operation plus the closed `max_records` selector) is built by the Store's
/// builder. No `NamedReadOperation` variant and no selector spelling is
/// restated here, so a Store rename moves this entry with it. Any other name —
/// including a `NamedReadOperation` this driver cannot spell as a Store read
/// name — is refused before transport.
///
/// # How to find the construction, and why a grep for the literal fails
///
/// This is the place to look when auditing the issuer, and the answer is
/// deliberately not a line that spells `GetExperienceBankRange`. The
/// construction is [`named_read_operation_by_name`] resolving `read_name`
/// against the Store's closed catalogue, [`named_read_operation_name`] naming
/// the resolved operation back into the two exported read names, and the
/// matching [`experience_bank_read_request`] /
/// [`experience_feedback_read_request`] builder minting the request — three
/// Store-owned calls, none of which restates a variant here. So a text search
/// for `GetExperienceBankRange` under `bins/` returns this doc's prose and no
/// request construction, and the correct reading of that result is that the
/// variant is resolved at runtime from the Store's own exported name rather
/// than hardcoded. Writing the literal into the `match` or a binding would
/// satisfy the search and reintroduce the Store-rename drift this rule
/// prevents (#1144); the norm against restating the two operations as
/// `NamedReadOperation` literals is the stronger one.
///
/// The read is served through [`ReadApi::bound_query`], exactly like the
/// sibling [`read_current_position`] leg, so this path gains the source/schema/
/// coverage comparison, the observed-head closure, the exact-fence stale check
/// and the page-coverage gate that classifies a source-declared truncated page
/// as `ReadOutcome::Partial`. A truncated page is therefore refused in the
/// owner's own vocabulary instead of being consumed as if it were complete, and
/// the returned payload is the owner's proven, non-truncated page together with
/// the exact identity closure (`BoundRead::identity`) it was served under.
///
/// The `ExactFence` dependency is **observed, not invented**, by the same rule
/// [`read_current_position`] follows: the scope revision head is read first and
/// its revision becomes the declared minimum, so a head that moves between the
/// two reads fails closed as [`ReadError::StaleRevision`] rather than being
/// served as current. One scope head therefore serves both legs of one
/// assessment run.
///
/// `max_records` is the caller's page bound and must be positive and strictly
/// below [`MAX_EXPERIENCE_PAGE_RECORDS`]; the leg passes
/// [`EXPERIENCE_RANGE_PAGE_BOUND`]. The bound is a real ceiling on what one
/// call can serve, not a completeness claim: a scope holding more rows than the
/// bound is refused as `ReadOutcome::Partial` rather than silently shortened,
/// and the continuation cursor the Store mints for exactly that case lives on
/// the refused page, so this entry cannot page past it. That limit belongs to
/// the Store page contract and the read owner's coverage gate, not to this
/// driver.
///
/// Not reached from a run of this daemon, exactly like the rest of this module:
/// its only call sites are the two inside
/// [`run_experience_quality_event`], which itself has none. See this module's
/// "Live status" section.
pub async fn read_experience_range_page(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    scope: ScopeId,
    read_name: &str,
    max_records: u16,
) -> Result<BoundRead<QueryResult>, ExperienceDriverError> {
    ctx.validate()
        .map_err(|_| ExperienceDriverError::Position {
            field: "request_metadata",
            reason: "invalid request metadata",
        })?;
    // The Store's own page ceiling is not this entry's page bound: a bound at
    // or above it asks for the largest page the Store can return, which is the
    // page most likely to arrive truncated and be refused below. Refusing it
    // here keeps that decision with the entry that issues the read instead of
    // leaving it to each call site.
    if max_records == 0 || max_records >= MAX_EXPERIENCE_PAGE_RECORDS {
        return Err(ExperienceDriverError::Position {
            field: "experience.max_records",
            reason: "page bound must be positive and below the store's declared maximum",
        });
    }
    let client = composition
        .context_read_client(kernel)
        .map_err(|error| ExperienceDriverError::Composition(error.to_string()))?;
    let scope_key = RevisionKey::new(format!("scope:{scope}"))?;
    let observed = client.revision_heads(vec![scope_key.clone()]).await?;
    let minimum = observed.iter().find(|head| head.key == scope_key).ok_or(
        ExperienceDriverError::Position {
            field: "revision_heads",
            reason: "store observed no head for the requested scope",
        },
    )?;
    let mut dependency_revisions = BTreeMap::new();
    dependency_revisions.insert(scope_key, minimum.revision);
    let operation =
        named_read_operation_by_name(read_name).ok_or(ExperienceDriverError::Position {
            field: "experience.read_name",
            reason: "read name is not in the store's closed read catalogue",
        })?;
    let request = match named_read_operation_name(operation) {
        EXPERIENCE_BANK_READ_NAME => {
            experience_bank_read_request(scope.clone(), max_records, ctx.state_fence.clone())?
        }
        EXPERIENCE_FEEDBACK_READ_NAME => {
            experience_feedback_read_request(scope.clone(), max_records, ctx.state_fence.clone())?
        }
        _ => {
            return Err(ExperienceDriverError::Position {
                field: "experience.read_name",
                reason: "read name is not an outcome-experience range read",
            });
        }
    };
    let reads = ReadService::new(client);
    reads
        .bound_query(
            ctx,
            QueryRequest {
                // The mode is the read owner's own intent gate for these two
                // operations, not a second answer to it: only
                // `HistoricalReconstruction` and `Provenance` admit them, and
                // this leg reconstructs a bounded captured record set rather
                // than tracing one record's lineage, so it asks for the former
                // and the owner decides whether that pairing is admissible.
                intent: QueryIntent {
                    mode: QueryMode::HistoricalReconstruction,
                    // The window is this request's own dependency-bound
                    // evidence window; freshness is the exact captured records
                    // rather than a re-read, because the leg must describe the
                    // records the owner captured; and the assurance is
                    // reconstruction-only, because nothing this leg reads may be
                    // presented as verified evidence.
                    time_scope: TimeScope::EvidenceWindow,
                    branch_environment_scope: BranchEnvironmentScope::LocalEnvironment,
                    freshness_policy: FreshnessPolicy::ExactCapturedRecords,
                    required_assurance: RequiredAssurance::InputReconstructionOnly,
                },
                operation: request.operation,
                scope_id: Some(scope),
                consistency: ReadConsistency::ExactFence,
                dependency_revisions,
                // This page read declares no conflict-serialization head: its
                // coherence is proven by the scope revision head observed above
                // plus the request fence, exactly as the sibling position leg
                // states. The declaration is explicit so the resolved identity
                // records the absence instead of leaving the order-head
                // dimension unstated.
                ordering: ReadOrderingBinding::without_order_dependency(),
                // The closed selectors are the Store builder's own map, moved
                // verbatim: the read owner re-derives the envelope (scope,
                // consistency, fence) from `ctx` and the Store re-gates every
                // selector against its own catalogue before dispatch.
                parameters: NamedParameters::from_map(request.parameters)?,
                provenance_handles: Vec::new(),
            },
        )
        .await
        .map_err(ExperienceDriverError::ReadOwner)
}

/// Journal-leg driver inputs: projection context plus live binding.
pub struct ExperienceJournalDriverInputs<'a> {
    /// Stable identity minted by the caller for the projection envelope.
    pub projection_id: ArtifactId,
    /// Read scope governing the projection (consumer-owned filtering).
    pub scope: ObservationScope,
    /// Read consistency for the bridge fetch.
    pub consistency: ReadConsistency,
    /// Record ids read from the live journal at call time for binding.
    pub admitted_record_ids: &'a BTreeSet<String>,
    /// Required revision minimums per head key (revision monotonicity).
    pub minimum_revisions: &'a BTreeMap<RevisionKey, u64>,
}

/// Terminal journal-leg call over the real bridge client.
///
/// Builds the per-call client from the composition and runs the full
/// provider chain (bridge fetch, V1 shaping, Smart view assembly, live
/// presence binding) under the caller-admitted fence in `ctx`. The call
/// itself is production machinery; until the store side registers the
/// `GetAuditRange` handler it fails closed with `UnknownOperation`,
/// exactly like the projection-inputs port-shape probe.
pub async fn produce_journal_projection(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    inputs: &ExperienceJournalDriverInputs<'_>,
) -> Result<JournalShapeOutput, ExperienceDriverError> {
    ctx.validate()
        .map_err(|_| ExperienceDriverError::Position {
            field: "request_metadata",
            reason: "invalid request metadata",
        })?;
    let client = composition
        .context_read_client(kernel)
        .map_err(|error| ExperienceDriverError::Composition(error.to_string()))?;
    produce_journal_read(
        &client,
        &ProduceJournalInputs {
            projection_id: inputs.projection_id.clone(),
            scope: inputs.scope.clone(),
            fence: ctx.state_fence.clone(),
            consistency: inputs.consistency.clone(),
            admitted_record_ids: inputs.admitted_record_ids,
            minimum_revisions: inputs.minimum_revisions,
        },
    )
    .await
    .map_err(ExperienceDriverError::Provider)
}

/// Bank-family event inputs: the admission context the edge owns for the
/// bank page this run reads.
///
/// #1144: the durable page itself is no longer an input. The bank range read
/// is issued by [`read_experience_range_page`] through the read owner, so the
/// page, its fence proof and its truncation verdict all come from the owner
/// that classifies them; a caller-carried payload would be a second answer to
/// the same source/fence/coverage questions.
///
/// Every remaining member is an admission binding rather than read evidence:
/// each one is stamped onto the projection envelope that
/// [`supply_bank_projection_from_store`] assembles, and none of them describes
/// or stands in for the page. In particular the page's own coverage statement
/// and truncation verdict are the read owner's to classify from the page
/// itself, so `coverage` here cannot widen, narrow, or override what that
/// gate proved.
pub struct ExperienceBankEventInputs {
    /// Stable identity minted by the caller for the bank envelope.
    pub projection_id: ArtifactId,
    /// Owner revision marker recorded on the assembled bank projection
    /// envelope. Edge-declared: the revision the page is actually read at is
    /// observed by the read owner, not asserted here.
    pub source_revision: String,
    /// Owner coverage binding recorded on the assembled bank projection
    /// envelope. Edge-declared; the read owner independently classifies the
    /// page's own Store coverage statement.
    pub coverage: ProjectionCoverage,
    /// Owner omissions recorded on the assembled bank projection envelope,
    /// alongside the `ProtectedWithheld` omissions the supply driver derives
    /// from the retention schedule. Edge-declared.
    pub omissions: Vec<ProjectionOmission>,
    /// Owner source identity cursors resolve under (edge passes the
    /// Governor bank source identity); never invented here.
    pub source_id: String,
}

/// Feedback-family event inputs. Same durable-read rule as bank: the page is
/// read by the entry through the read owner, and only the admission context
/// arrives from the edge. Same member-by-member rule: every field below is an
/// admission binding stamped onto the projection envelope
/// [`supply_feedback_projection_from_store`] assembles, not read evidence and
/// not a substitute for the page.
pub struct ExperienceFeedbackEventInputs {
    /// Stable identity minted by the caller for the feedback envelope.
    pub projection_id: ArtifactId,
    /// Owner revision marker recorded on the assembled feedback projection
    /// envelope. Edge-declared: the revision the page is actually read at is
    /// observed by the read owner, not asserted here.
    pub source_revision: String,
    /// Owner coverage binding recorded on the assembled feedback projection
    /// envelope. Edge-declared; the read owner independently classifies the
    /// page's own Store coverage statement.
    pub coverage: ProjectionCoverage,
    /// Owner omissions recorded on the assembled feedback projection
    /// envelope, alongside the `ProtectedWithheld` omissions the supply
    /// driver derives from the retention schedule. Edge-declared.
    pub omissions: Vec<ProjectionOmission>,
    /// Owner source identity cursors resolve under (edge passes the
    /// Governor feedback source identity); never invented here.
    pub source_id: String,
}

/// Governed trigger event for one terminal experience-quality run.
///
/// Understanding leg inputs: everything except outcome-side experience.
///
/// The entry binds outcome-side experience evidence from its own live
/// envelopes; all other inputs arrive edge-supplied from their owners
/// (compiled view, accepted sources, contribution, scope, cites,
/// closure). Product claims stay false unless the edge holds out
/// evidence for them.
pub struct UnderstandingEventInputs<'a> {
    /// Already-compiled understanding view, by handle (edge-supplied).
    pub view: &'a ActiveUnderstandingView,
    /// Accepted-source projection for citation checks (edge-supplied).
    pub sources: &'a AcceptedSourceProjection,
    /// Optional admitted epistemic contribution, echoed by digest/claim.
    pub contribution: Option<&'a ProviderContribution>,
    /// Denominator anchor.
    pub scope: AssessmentScope,
    /// Subject route or coupled system.
    pub subject: String,
    /// Transfer boundary and requalification text.
    pub transfer_boundary: String,
    /// Material unknowns cites.
    pub material_unknowns: Vec<EvidenceCite>,
    /// Abstention precision/coverage cites, where applicable.
    pub abstention: Vec<EvidenceCite>,
    /// Unanswerable/stale case cites, where applicable.
    pub unanswerable: Vec<EvidenceCite>,
    /// Counterfactual intervention cites, where applicable.
    pub counterfactual: Vec<EvidenceCite>,
    /// Rival/prediction/discriminator/verifier/revision closure.
    pub closure: AssessmentClosure,
    /// True when the verdict backs a product claim (held-out required).
    pub product_claims: bool,
}

/// Common-ground leg inputs: everything except outcome-side experience.
///
/// Same binding rule as [`UnderstandingEventInputs`]: the entry binds
/// outcome-side experience evidence from its own live envelopes; all
/// other inputs arrive edge-supplied from their owners.
pub struct CommonGroundEventInputs<'a> {
    /// Already-compiled understanding view, by handle (edge-supplied).
    pub view: &'a ActiveUnderstandingView,
    /// Accepted-source projection for citation checks (edge-supplied).
    pub sources: &'a AcceptedSourceProjection,
    /// Optional admitted epistemic contribution, echoed by digest/claim.
    pub contribution: Option<&'a ProviderContribution>,
    /// Denominator anchor.
    pub scope: AssessmentScope,
    /// Terminology compatibility cites.
    pub terminology: Vec<EvidenceCite>,
    /// Reference compatibility cites.
    pub reference: Vec<EvidenceCite>,
    /// Commitment compatibility cites.
    pub commitment: Vec<EvidenceCite>,
    /// Action-consequence compatibility cites.
    pub action_consequence: Vec<EvidenceCite>,
    /// Survival-across-change cites.
    pub survival: Vec<EvidenceCite>,
    /// Public inheritance transfer refs.
    pub transfer_refs: Vec<EvidenceCite>,
    /// Requalification scope for tacit competence.
    pub requalification_scope: String,
    /// Rival/prediction/discriminator/verifier/revision closure.
    pub closure: AssessmentClosure,
    /// True when the verdict backs a product claim (held-out required).
    pub product_claims: bool,
}

/// The event producer (operator/planner edge, O1 trigger) assembles this
/// from explicit owner-issued inputs only: bridge scope and position
/// subject, journal presence inputs, the bank/feedback admission context their
/// pages are read and projected under, the owner-issued retention schedule with
/// caller-carried holds, per-attempt receipts, obligation handles, edge
/// attestation, plus the memory request and understanding leg when those
/// families run. Reads stay reads: nothing here writes, persists, or
/// submits; the entry returns the frozen candidates plus the validated
/// views and gap postures for the consuming review path.
pub struct ExperienceQualityEvent<'a> {
    /// Assessment identity minted by the caller.
    pub assessment_id: ArtifactId,
    /// Work scope governing the assessment.
    pub assessment_scope: WorkScopeId,
    /// Read scope governing projections and views.
    pub scope: ObservationScope,
    /// Store scope bridge reads run in.
    pub scope_id: ScopeId,
    /// Exact position subject the bridge position read selects.
    pub position_subject: String,
    /// Journal leg inputs, when the journal family is cited.
    pub journal: Option<ExperienceJournalDriverInputs<'a>>,
    /// Bank-family durable inputs.
    pub bank: ExperienceBankEventInputs,
    /// Feedback-family durable inputs.
    pub feedback: ExperienceFeedbackEventInputs,
    /// Owner-issued retention schedule in force for this run.
    pub schedule: &'a RetentionSchedule,
    /// Schedule-issued hold terms by record-handle text.
    pub holds: &'a BTreeMap<String, RetentionHold>,
    /// Per-attempt receipt candidates (at least one; edge-supplied).
    pub receipts: &'a [HarnessActivationReceiptCandidate],
    /// Obligation-profile handles cited by handle only (edge-supplied).
    pub obligation_handles: &'a [ArtifactId],
    /// Edge-attested handles for bodies cited by handle only.
    pub attested_handles: Vec<ArtifactId>,
    /// Memory-quality request, when the memory family runs (edge-supplied
    /// owner batch, applicability verdict, projections, and receipts).
    pub memory: Option<QualityRequest>,
    /// Understanding leg inputs, when the understanding family runs
    /// (edge-supplied owner context minus outcome experience, which the
    /// entry binds from its own live envelopes).
    pub understanding: Option<UnderstandingEventInputs<'a>>,
    /// Common-ground leg inputs, when the common-ground family runs
    /// (same outcome-experience binding rule as the scoped leg).
    pub common_ground: Option<CommonGroundEventInputs<'a>>,
}

/// Terminal output bundle: frozen candidates plus validated views and gaps.
pub struct ExperienceQualityEventOutput {
    /// Frozen self-quality candidate, assessed and re-resolved.
    pub candidate: QualityAssessmentCandidate,
    /// Validated journal view, when the journal family was cited.
    pub journal_view: Option<ExperienceView>,
    /// Validated bank view over owner-issued refs.
    pub bank_view: ExperienceView,
    /// Validated feedback view over owner-issued refs.
    pub feedback_view: ExperienceView,
    /// Withheld bank records with honest postures for gap emission.
    pub bank_withheld: Vec<WithheldMember>,
    /// Withheld feedback records with honest postures for gap emission.
    pub feedback_withheld: Vec<WithheldMember>,
    /// Memory ecology assessment, when the memory family ran.
    pub memory_assessment: Option<MemoryEcologyAssessment>,
    /// Owner-minted bank continuation cursor echoed verbatim from the
    /// consumed range payload ([`EXPERIENCE_PAGE_NEXT_CURSOR`]), or `None`
    /// when the page ends the enumeration.
    ///
    /// #1144: the consumed page is the read owner's own answer, and the owner
    /// refuses a source-declared truncated page as `ReadOutcome::Partial`
    /// before its payload is returned. The Store mints `next_cursor` exactly
    /// on a truncated page, so through this entry the cursor is `None` on every
    /// page that reaches here: a caller that needs the next page gets the
    /// typed `Partial` refusal, not a silent short page. Whether a refused
    /// truncated page should still yield its continuation cursor is a
    /// question for the Store page contract and the read owner's coverage
    /// gate, not for this driver, which neither restates that rule nor
    /// synthesizes or advances a cursor itself.
    pub bank_next_cursor: Option<String>,
    /// Owner-minted feedback continuation cursor, same contract as
    /// `bank_next_cursor` above.
    pub feedback_next_cursor: Option<String>,
    /// Scoped understanding assessment, when the understanding family ran.
    pub understanding: Option<ScopedUnderstandingAssessment>,
    /// Common-ground assessment, when the common-ground family ran.
    pub common_ground: Option<CommonGroundAssessment>,
}

/// Echoes the owner-minted range continuation cursor from a consumed
/// bank/feedback range payload, if the page carries one.
///
/// Reads only the [`EXPERIENCE_PAGE_NEXT_CURSOR`] member minted by the
/// owner page envelope
/// ([`ExperienceRangePage`](eliot_store_api::ExperienceRangePage)): a
/// missing member, a non-string member, or a blank cursor echoes as
/// `None` (page ends the enumeration). The cursor is echoed verbatim,
/// never parsed or advanced here; multi-page iteration belongs to the
/// trigger edge per the output contract.
fn range_next_cursor(payload: &serde_json::Value) -> Option<String> {
    payload
        .get(EXPERIENCE_PAGE_NEXT_CURSOR)
        .and_then(serde_json::Value::as_str)
        .filter(|cursor| !cursor.trim().is_empty())
        .map(str::to_owned)
}

/// Terminal event entry: trigger event to reviewed candidate.
///
/// Runs the full connected runtime path in source terms: TRUE position
/// bridge read, optional journal bridge leg with live presence binding,
/// bank/feedback range pages read through the Governor read owner
/// ([`read_experience_range_page`], so a source-declared truncated page is a
/// typed `Partial` refusal) and consumed through the owner supply drivers
/// ([`supply_bank_projection_from_store`] /
/// [`supply_feedback_projection_from_store`]: wrapper-aware decode with
/// digest re-proof, retention gating, per-ref snapshot resolution),
/// provider view shaping with retention postures and live revalidation,
/// then the consuming call
/// ([`assess_and_recheck`](eliot_experience_provider::assess_and_recheck)):
/// assess over true owner envelopes plus edge receipts, immediately
/// re-resolved against the same inputs plus edge attestation. The ledger
/// is ephemeral per run (rebuilt from decoded records, no durable
/// state). Any drift, malformation, withheld-but-uncited material, or
/// missing family fails closed; nothing partial is emitted as complete
/// and nothing is persisted or submitted by this entry.
#[allow(clippy::too_many_lines)]
pub async fn run_experience_quality_event(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    event: &ExperienceQualityEvent<'_>,
) -> Result<ExperienceQualityEventOutput, ExperienceDriverError> {
    ctx.validate()
        .map_err(|_| ExperienceDriverError::Position {
            field: "request_metadata",
            reason: "invalid request metadata",
        })?;
    if let Some(journal) = &event.journal
        && journal.scope != event.scope
    {
        return Err(ExperienceDriverError::Position {
            field: "event.journal.scope",
            reason: "journal leg scope does not match event scope",
        });
    }
    let position = read_current_position(
        composition,
        kernel,
        ctx,
        event.scope_id.clone(),
        event.position_subject.clone(),
    )
    .await?;
    let (journal_envelope, journal_view) = match &event.journal {
        Some(inputs) => {
            let shaped = produce_journal_projection(composition, kernel, ctx, inputs).await?;
            (Some(shaped.projection), Some(shaped.view))
        }
        None => (None, None),
    };
    let mut ledger = ExperienceRevisionLedger::new();
    // #1144: both outcome-experience pages are READ HERE, through the
    // Governor read owner, instead of arriving as caller-carried payloads.
    // Before this the reconstruction consumed `event.bank.payload` and
    // `event.feedback.payload` directly, so the two operations the read owner
    // admits for this intent were issued by nothing, the Store request builders
    // that own their closed selectors had no issuer, and the owner's
    // `ReadOutcome::Partial` truncation arm could never be taken: a truncated
    // page was indistinguishable from a complete one here. Each page is still
    // proved against this request's fence FIRST, before any coverage member of
    // it is read — `bank_records_from_range_payload` below reads `records` and
    // `range_next_cursor` reads `next_cursor`, and a truncation or cursor
    // member on a page projected under another fence describes that other
    // fence's rows. The proof is the owner's own rule, called rather than
    // restated, so an absent or foreign `state_fence` member is
    // `ReadError::CoverageFenceUnproven` and stays distinct from `Unknown`
    // (the source answered) and from `Partial` (nothing claims rows past the
    // bound). The bound compared against is `ctx.state_fence`, the same fence
    // every projection below is assembled at.
    let bank_page = read_experience_range_page(
        composition,
        kernel,
        ctx,
        event.scope_id.clone(),
        EXPERIENCE_BANK_READ_NAME,
        EXPERIENCE_RANGE_PAGE_BOUND,
    )
    .await?;
    prove_page_state_fence(&bank_page.view.payload, &ctx.state_fence)?;
    let bank_records = bank_records_from_range_payload(&bank_page.view.payload)?;
    let bank_live = supply_bank_projection_from_store(
        &mut ledger,
        BankStoreSnapshot {
            records: &bank_records,
            source_revision: event.bank.source_revision.clone(),
            coverage: event.bank.coverage.clone(),
            omissions: event.bank.omissions.clone(),
        },
        event.bank.projection_id.clone(),
        event.scope.clone(),
        ctx.state_fence.clone(),
        event.schedule,
        event.holds,
    )?;
    let bank_shaped = eliot_experience_provider::shape_bank_view(&BankShapeInputs {
        scope: event.scope.clone(),
        fence: ctx.state_fence.clone(),
        records: &bank_records,
        live: &bank_live,
        source_id: event.bank.source_id.as_str(),
        retention: &RetentionContext {
            schedule: event.schedule,
            holds: event.holds,
        },
    })?;
    // The feedback leg is read through the same owner range read, for the same
    // reason as the bank leg: a caller-carried payload carries no truncation
    // verdict, so a truncated feedback page was indistinguishable from a
    // complete one here too.
    let feedback_page = read_experience_range_page(
        composition,
        kernel,
        ctx,
        event.scope_id.clone(),
        EXPERIENCE_FEEDBACK_READ_NAME,
        EXPERIENCE_RANGE_PAGE_BOUND,
    )
    .await?;
    prove_page_state_fence(&feedback_page.view.payload, &ctx.state_fence)?;
    let feedback_records = feedback_records_from_range_payload(&feedback_page.view.payload)?;
    let feedback_live = supply_feedback_projection_from_store(
        &mut ledger,
        FeedbackStoreSnapshot {
            records: &feedback_records,
            source_revision: event.feedback.source_revision.clone(),
            coverage: event.feedback.coverage.clone(),
            omissions: event.feedback.omissions.clone(),
        },
        event.feedback.projection_id.clone(),
        event.scope.clone(),
        ctx.state_fence.clone(),
        event.schedule,
        event.holds,
    )?;
    let feedback_shaped = eliot_experience_provider::shape_feedback_view(&FeedbackShapeInputs {
        scope: event.scope.clone(),
        fence: ctx.state_fence.clone(),
        records: &feedback_records,
        live: &feedback_live,
        source_id: event.feedback.source_id.as_str(),
        retention: &RetentionContext {
            schedule: event.schedule,
            holds: event.holds,
        },
    })?;
    let candidate = assess_and_recheck(SelfQualityRecheckInputs {
        assess: SelfQualityInputs {
            assessment_id: event.assessment_id.clone(),
            scope: event.assessment_scope.clone(),
            fence: ctx.state_fence.clone(),
            journal: journal_envelope.as_ref(),
            bank: Some(&bank_live),
            feedback: Some(&feedback_live),
            position: &position,
            receipts: event.receipts,
            obligation_handles: event.obligation_handles,
        },
        attested_handles: event.attested_handles.clone(),
    })?;
    let memory_assessment = match &event.memory {
        Some(request) => Some(produce_memory_quality(request)?),
        None => None,
    };
    let mut experience = Vec::new();
    if let Some(journal) = journal_envelope.as_ref() {
        experience.push(ExperienceEvidence::Journal(journal));
    }
    experience.push(ExperienceEvidence::Bank(&bank_live));
    experience.push(ExperienceEvidence::Feedback(&feedback_live));
    let understanding = match &event.understanding {
        Some(inputs) => {
            let scoped = eliot_understanding_assessment::ScopedInput {
                owner: OwnerContext {
                    view: inputs.view,
                    sources: inputs.sources,
                    contribution: inputs.contribution,
                    experience: &experience,
                },
                scope: inputs.scope.clone(),
                subject: inputs.subject.clone(),
                transfer_boundary: inputs.transfer_boundary.clone(),
                material_unknowns: inputs.material_unknowns.clone(),
                abstention: inputs.abstention.clone(),
                unanswerable: inputs.unanswerable.clone(),
                counterfactual: inputs.counterfactual.clone(),
                closure: inputs.closure.clone(),
                product_claims: inputs.product_claims,
            };
            Some(produce_understanding_assessment(scoped)?)
        }
        None => None,
    };
    let common_ground = match &event.common_ground {
        Some(inputs) => {
            let common = CommonGroundInput {
                owner: OwnerContext {
                    view: inputs.view,
                    sources: inputs.sources,
                    contribution: inputs.contribution,
                    experience: &experience,
                },
                scope: inputs.scope.clone(),
                terminology: inputs.terminology.clone(),
                reference: inputs.reference.clone(),
                commitment: inputs.commitment.clone(),
                action_consequence: inputs.action_consequence.clone(),
                survival: inputs.survival.clone(),
                transfer_refs: inputs.transfer_refs.clone(),
                requalification_scope: inputs.requalification_scope.clone(),
                closure: inputs.closure.clone(),
                product_claims: inputs.product_claims,
            };
            Some(produce_common_ground_assessment(common)?)
        }
        None => None,
    };
    Ok(ExperienceQualityEventOutput {
        candidate,
        journal_view,
        bank_view: bank_shaped.view,
        feedback_view: feedback_shaped.view,
        bank_withheld: bank_shaped.withheld,
        feedback_withheld: feedback_shaped.withheld,
        memory_assessment,
        bank_next_cursor: range_next_cursor(&bank_page.view.payload),
        feedback_next_cursor: range_next_cursor(&feedback_page.view.payload),
        understanding,
        common_ground,
    })
}

/// Terminal event entry with an optional admitted extinction intake.
///
/// Runs [`run_experience_quality_event`] unchanged, then — only when
/// `revision` is `Some` — proposes one advisory extinction candidate
/// via [`propose_memory_extinction_candidate`] over that intake.
/// `Some` must be an already-admitted [`RevisionIntake`] held by the
/// trigger edge (the O1-owned daemon trigger assembles it from
/// owner-issued members); this entry never synthesizes intake from
/// the quality event's bank/feedback envelopes and owns no automatic
/// trigger. `None` skips the revision lane entirely. This entry calls
/// [`run_experience_quality_event`] and then the propose wrapper,
/// so both symbols have a production caller in this file; the
/// read-only base path is unaffected.
pub async fn run_experience_quality_event_with_revision(
    composition: &DaemonComposition,
    kernel: &Arc<DaemonKernelClient>,
    ctx: &RequestMetadata,
    event: &ExperienceQualityEvent<'_>,
    revision: Option<&RevisionIntake<'_>>,
) -> Result<
    (
        ExperienceQualityEventOutput,
        Option<NegativeMemoryExtinctionCandidate>,
    ),
    ExperienceDriverError,
> {
    let output = run_experience_quality_event(composition, kernel, ctx, event).await?;
    let extinction = revision
        .map(propose_memory_extinction_candidate)
        .transpose()?;
    Ok((output, extinction))
}

/// Daemon-edge commit lifecycle bound in milliseconds.
///
/// Bounds this run's commit lifecycle only, mirroring the Kernel-client
/// ingress precedent (`daemon_kernel_client` 30s window). It bounds no
/// identity and proves nothing: authority stays with admitted metadata,
/// fence agreement, and the owner checks downstream.
const COMMIT_INGRESS_DEADLINE_MS: u64 = 30_000;

/// Terminal output bundle: durable commit receipts per family.
pub struct ExperienceCommitOutput {
    /// Owner receipts for committed bank records, in input order.
    pub bank_receipts: Vec<WriteReceipt>,
    /// Owner receipts for committed feedback records, in input order.
    pub feedback_receipts: Vec<WriteReceipt>,
    /// True when the composition's dependent view is stale/pending after
    /// this batch, echoed from the composition status projection.
    ///
    /// P2 stale-projection marking: every per-record commit publishes
    /// its owner change through the composition's refresh/stale
    /// discipline (a failed post-commit refresh keeps the already
    /// durable receipt and marks the dependent view stale/pending
    /// instead of hiding divergence). This flag echoes that marker so
    /// the caller can observe it without a second status read; when
    /// set, projections must not be trusted until the caller drops this
    /// composition and re-runs authenticated connect+start. There is no
    /// `refresh_dependent_view` entry: refresh runs inside the
    /// per-record composition commit calls, never as a separate step
    /// from this file.
    pub view_stale: bool,
}

/// Derives admitted commit ingress from retained invocation state.
///
/// Clones the validated invocation metadata (`ctx`) verbatim — the
/// admission contour that invoked this driver — and requires its fence
/// to equal the retained admitted Kernel fence: invocation/Kernel fence
/// drift fails closed here, before any identity exists. The idempotency
/// key is the owner-derived commit key for the exact record being
/// committed (computed by `produce_bank_commit` /
/// `produce_feedback_commit` from admitted record content, never
/// invented); the deadline bounds this run per
/// [`COMMIT_INGRESS_DEADLINE_MS`]; the cancellation identity binds the
/// commit lifecycle to that same record key. Record-fence, scope, and
/// key agreement are re-checked by the commit caller and the owner
/// downstream; nothing here mints identity, heads, or proofs.
pub fn derive_commit_ingress(
    ctx: &RequestMetadata,
    kernel_fence: &StateFence,
    commit_key: &str,
) -> Result<RequestIdentity, ExperienceDriverError> {
    ctx.validate().map_err(|_| ExperienceDriverError::Ingress {
        field: "request_metadata",
        reason: "retained invocation metadata is invalid",
    })?;
    if ctx.state_fence != *kernel_fence {
        return Err(ExperienceDriverError::Ingress {
            field: "request_metadata.state_fence",
            reason: "invocation fence differs from the admitted Kernel fence",
        });
    }
    if commit_key.trim().is_empty() || commit_key.chars().any(char::is_control) {
        return Err(ExperienceDriverError::Ingress {
            field: "idempotency_key",
            reason: "owner-derived commit key is blank or carries control characters",
        });
    }
    Ok(RequestIdentity {
        request: RequestBinding {
            metadata: ctx.clone(),
            state_fence: ctx.state_fence.clone(),
        },
        idempotency_key: commit_key.to_owned(),
        deadline_unix_ms: super::unix_ms().saturating_add(COMMIT_INGRESS_DEADLINE_MS),
        cancellation_id: format!("{commit_key}:cancel"),
    })
}

/// Terminal commit entry: admitted event records to durable rows.
///
/// O1 trigger seam (transcription-ready): the O1 copy transcribes this
/// exact entry plus [`derive_commit_ingress`] and
/// [`ExperienceCommitOutput`]; the read entry
/// ([`run_experience_quality_event`]) is unchanged and stays read-only.
/// Checklist for the O1 copy:
/// - call with the SAME decoded record slices the read entry consumed (the
///   bank/feedback pages it read through the read owner, already digest
///   re-proved by the owner supply drivers);
/// - pass `event.scope_id` verbatim; scope/record mismatch fails closed
///   in the commit caller with an exact owner error;
/// - pass edge-supplied live head expectations when held, else empty
///   vectors (no expectations are fabricated here);
/// - per-record receipts return in input order; a mid-batch failure
///   returns `Err` while already-durable receipts stay durable under
///   their deterministic idempotency keys. Every success is retained on
///   the composition as it happens and retained keys are skipped on
///   retry without re-deriving expectations (P1-1, #1942), so retry is
///   convergent and never double-persists.
///
/// Runs, in source terms: ledger rebuild from the admitted slices (only
/// the greatest admitted revision per handle passes the owner
/// sequencing gate; older revisions fail closed, never silently
/// skipped), per-record owner commit payload (`produce_bank_commit` /
/// `produce_feedback_commit`), admitted ingress derivation, the
/// canonical Governor commit caller (`commit_experience_bank` /
/// `commit_experience_feedback`), and returns the owner `WriteReceipt`s
/// unmodified. Proof refs are verbatim admitted refs from the
/// edge-supplied per-attempt receipts (admission + activation-request
/// receipt identities, blanks dropped); nothing is inferred.
#[allow(clippy::too_many_arguments)]
pub async fn commit_experience_event_records(
    composition: &mut DaemonComposition,
    ctx: &RequestMetadata,
    event: &ExperienceQualityEvent<'_>,
    bank_records: &[ExperienceBankRecord],
    feedback_records: &[AgentFeedbackRecord],
    expected_revision_heads: Vec<RevisionHeadExpectation>,
    expected_ordering_heads: Vec<OrderingHeadExpectation>,
) -> Result<ExperienceCommitOutput, ExperienceDriverError> {
    ctx.validate().map_err(|_| ExperienceDriverError::Ingress {
        field: "request_metadata",
        reason: "retained invocation metadata is invalid",
    })?;
    let kernel_fence = composition.kernel_snapshot().state_fence().clone();
    let mut proof_refs: Vec<String> = Vec::new();
    for receipt in event.receipts {
        for identity in [
            receipt.admission_receipt.as_str(),
            receipt.activation_request_receipt.as_str(),
        ] {
            if !identity.trim().is_empty()
                && !proof_refs.iter().any(|existing| existing == identity)
            {
                proof_refs.push(identity.to_owned());
            }
        }
    }
    let mut ledger = ExperienceRevisionLedger::new();
    ledger.rebuild_bank(bank_records);
    ledger.rebuild_feedback(feedback_records);
    let mut bank_receipts = Vec::with_capacity(bank_records.len());
    for record in bank_records {
        let commit_key = produce_bank_commit(&ledger, record)
            .map_err(ExperienceDriverError::Governor)?
            .idempotency_key;
        // P1-1 (#1942): a key this composition already committed is durable
        // under that key. Reuse the retained receipt without re-deriving
        // ingress or re-submitting: a retry under freshly derived expected
        // heads would hash differently and wedge permanently in
        // `IdentityConflict`. The store triple rule is untouched and no new
        // operation identity is minted.
        if let Some(receipt) = composition.committed_experience_receipt(&commit_key) {
            bank_receipts.push(receipt);
            continue;
        }
        let identity = derive_commit_ingress(ctx, &kernel_fence, &commit_key)?;
        let receipt = composition
            .commit_experience_bank_record(
                &identity,
                &ledger,
                record,
                event.scope_id.clone(),
                proof_refs.clone(),
                expected_revision_heads.clone(),
                expected_ordering_heads.clone(),
            )
            .await
            .map_err(|error| ExperienceDriverError::Commit(error.to_string()))?;
        composition.note_experience_committed(commit_key, receipt.clone());
        bank_receipts.push(receipt);
    }
    let mut feedback_receipts = Vec::with_capacity(feedback_records.len());
    for record in feedback_records {
        let commit_key = produce_feedback_commit(&ledger, record)
            .map_err(ExperienceDriverError::Governor)?
            .idempotency_key;
        // P1-1 (#1942): same convergent-retry rule as the bank leg above.
        if let Some(receipt) = composition.committed_experience_receipt(&commit_key) {
            feedback_receipts.push(receipt);
            continue;
        }
        let identity = derive_commit_ingress(ctx, &kernel_fence, &commit_key)?;
        let receipt = composition
            .commit_experience_feedback_record(
                &identity,
                &ledger,
                record,
                event.scope_id.clone(),
                proof_refs.clone(),
                expected_revision_heads.clone(),
                expected_ordering_heads.clone(),
            )
            .await
            .map_err(|error| ExperienceDriverError::Commit(error.to_string()))?;
        composition.note_experience_committed(commit_key, receipt.clone());
        feedback_receipts.push(receipt);
    }
    let view_stale = composition.status().health.as_str() == "stale";
    Ok(ExperienceCommitOutput {
        bank_receipts,
        feedback_receipts,
        view_stale,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod current_position_join_tests {
    use std::num::NonZeroU64;

    use eliot_contracts::{
        ArtifactId, EpochId, EpochLineageId, ReceiptId, ResourceGeneration, SourceId, StateFence,
    };
    use eliot_epistemic_contracts::{
        AdmittedReceipt, AdmittedReceiptParams, ClaimId, CurrentEpistemicPosition, Currentness,
        PositionId, PositionRevision,
    };
    use eliot_store_api::ScopeId;

    use super::{ExperienceDriverError, select_current_position};

    fn hex64() -> String {
        "0123456789abcdef".repeat(4)
    }

    fn fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new("550e8400-e29b-41d4-a716-446655440000")
                    .expect("fixture lineage"),
                NonZeroU64::new(1).expect("nonzero sequence"),
            )
            .expect("fixture epoch"),
            ResourceGeneration::genesis(),
        )
    }

    /// One admitted view over the exact (scope, position, claim) triple the
    /// join compares. Only the three compared members vary between cases, so
    /// a failing case isolates the join and not a fixture drift.
    fn admitted(
        scope: &str,
        position: &str,
        claim: &str,
        currentness: Currentness,
    ) -> CurrentEpistemicPosition {
        let supersession = match currentness {
            Currentness::Current => std::collections::BTreeSet::new(),
            Currentness::Superseded => {
                std::collections::BTreeSet::from([ArtifactId::new("pos-2").expect("supersession")])
            }
        };
        let admission = AdmittedReceipt::new(AdmittedReceiptParams {
            receipt_id: ReceiptId::new(format!("rc-{claim}")).expect("receipt"),
            payload_digest: hex64(),
            owner: SourceId::new("source-epistemic").expect("source"),
            revision: "rev-1".to_owned(),
            scope: scope.to_owned(),
            fence: fence(),
            evidence_digest: hex64(),
            coverage_digest: hex64(),
            conflict_digest: hex64(),
            proof_digest: hex64(),
            position: PositionId::new(position).expect("position"),
            position_revision: PositionRevision::new(1).expect("revision"),
        })
        .expect("admission");
        CurrentEpistemicPosition::new(
            admission,
            currentness,
            supersession,
            ClaimId::new(claim).expect("claim"),
        )
        .expect("admitted view")
    }

    fn select(
        readback_scope: &str,
        positions: &[CurrentEpistemicPosition],
    ) -> Result<CurrentEpistemicPosition, ExperienceDriverError> {
        select_current_position(
            readback_scope,
            positions,
            &ScopeId::new("scope-1").expect("scope"),
            "position-1",
        )
    }

    #[test]
    fn the_single_current_position_answering_the_request_is_selected() {
        let current = admitted("scope-1", "position-1", "claim-1", Currentness::Current);
        let superseded = admitted("scope-1", "position-1", "claim-0", Currentness::Superseded);
        let selected = select("scope-1", &[superseded, current.clone()])
            .expect("the one current position answers the request");
        assert_eq!(selected, current);
        assert_eq!(selected.currentness, Currentness::Current);
    }

    #[test]
    fn a_readback_answering_another_subject_is_refused() {
        let current = admitted("scope-1", "position-1", "claim-1", Currentness::Current);
        // Same position, foreign scope: the store keyed the read by
        // (scope, position), so a differing scope is a substituted readback.
        let error = select("scope-other", &[current]).expect_err("must fail closed");
        assert!(matches!(
            error,
            ExperienceDriverError::Position {
                field: "response.payload.candidate.scope",
                ..
            }
        ));
    }

    #[test]
    fn a_substituted_position_inside_a_matching_readback_is_refused() {
        let current = admitted("scope-1", "position-1", "claim-1", Currentness::Current);
        let foreign = admitted("scope-1", "position-2", "claim-2", Currentness::Superseded);
        let error = select("scope-1", &[current, foreign])
            .expect_err("a foreign position must fail the whole read");
        assert!(matches!(
            error,
            ExperienceDriverError::Position {
                field: "positions",
                ..
            }
        ));
    }

    #[test]
    fn two_current_positions_are_a_conflict_not_an_input_order_pick() {
        // The store mints one view per claim, so a multi-claim candidate
        // legitimately yields several Current positions. Neither may be
        // selected by position in the vector.
        let first = admitted("scope-1", "position-1", "claim-1", Currentness::Current);
        let second = admitted("scope-1", "position-1", "claim-2", Currentness::Current);
        let error = select("scope-1", &[first, second])
            .expect_err("several current positions must fail closed");
        assert!(matches!(
            error,
            ExperienceDriverError::Position {
                field: "positions",
                ..
            }
        ));
    }

    #[test]
    fn no_current_position_is_the_existing_explicit_absence() {
        let superseded = admitted("scope-1", "position-1", "claim-1", Currentness::Superseded);
        let error = select("scope-1", &[superseded]).expect_err("absence must fail closed");
        assert!(matches!(
            error,
            ExperienceDriverError::Position {
                field: "positions",
                reason: "no current admitted position in the readback",
                ..
            }
        ));
        let empty = select("scope-1", &[]).expect_err("empty readback is absence");
        assert!(matches!(
            empty,
            ExperienceDriverError::Position {
                reason: "no current admitted position in the readback",
                ..
            }
        ));
    }
}
