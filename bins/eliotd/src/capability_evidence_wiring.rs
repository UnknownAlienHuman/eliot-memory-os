//! Daemon-held Governor capability admission view (#1957).
//!
//! The canonical registry and evidence semantics live in `eliot-governor`;
//! legacy normalization lives in `eliot-config`. This module owns only the
//! daemon composition root's handle on that view. The single
//! [`GovernorCapabilityAdmission`] is constructed empty at
//! [`DaemonComposition::start`](super::DaemonComposition::start) and is
//! mutated in production at four sites, all non-test. The first two read the
//! DURABLE capability-evidence rows; the last two commit through the named
//! `RecordCapabilityEvidenceRecord` leg:
//!
//! 1. [`drain_capability_evidence_records`], reached from the startup attach
//!    (`daemon_runtime::hydrate_capability_evidence_view`), which drains the
//!    complete `GetCapabilityEvidenceRecordRange` read to exhaustion;
//! 2. [`GovernorCapabilityAdmission::hydrate_from_evidence_record_page`],
//!    reached from the daemon's live Skill-intake commit step
//!    ([`commit_skill_pair`](super::skill_dispatch::commit_skill_pair)) for the
//!    intake's own Skill, so a record committed while the daemon runs is
//!    observed without waiting for a restart. The one-shot apply installs only
//!    a COMPLETE page: a page that reports further eligible rows is refused
//!    whole before any row is minted, so partial coverage can never present
//!    itself as the view and admit past an unread restriction;
//! 3. [`commit_scope_change_restriction`], also reached from the startup attach,
//!    which applies the installation-scope dependency change the Host admitted
//!    about the daemon's own served bytes and COMMITS every record that change
//!    limited, so a restriction a running process applied cannot be erased by a
//!    restart and leave the stale evidence re-admissible.
//! 4. [`commit_production_observation`], which mints one real `observed` /
//!    `production_observation` record from a validated observed-route receipt
//!    and COMMITS it through the same named leg, so a qualifying record
//!    reaches the store while the daemon runs and the next drain re-serves it
//!    with its store-issued revision. Its production caller is the live
//!    model-invoke gate once a handshake/transport observation producer threads
//!    the receipt it already takes; until then the leg is the contract seam,
//!    not a second service.
//!
//! No semantic rule lives here; every admission decision is the Governor
//! registry's.
//!
//! Where the view is consulted, measured on this base: the production model
//! execution path is
//! [`GovernedDreamerModelAdapter::invoke`](super::dreamer_model_adapter::GovernedDreamerModelAdapter::invoke)
//! -> [`invoke_admitted_model`](super::dreamer_model_adapter::invoke_admitted_model)
//! -> the C1 join `gate_model_capability`, which requires
//! [`admit_production_route`](GovernorCapabilityAdmission::admit_production_route)
//! over this held view for every item of the canonical required set, on the
//! caller-observed route scope, at the caller's observation time, and returns
//! before the `DreamerModelExecution` port is touched. That adapter is
//! constructed in production by `daemon_runtime::attach_dreamer_model`
//! through [`DaemonComposition::dreamer_model`](super::DaemonComposition::dreamer_model).
//!
//! Residual STITCH, measured and not papered over:
//! [`AgentFabric::require_model_route`](super::agent_fabric::AgentFabric::require_model_route)
//! is a second, distinct consumer of the same predicate, reached through
//! [`DaemonComposition::require_admitted_model_route`](super::DaemonComposition::require_admitted_model_route)
//! from [`DaemonComposition::drive_verified_agent_fabric`](super::DaemonComposition::drive_verified_agent_fabric).
//! `drive_verified_agent_fabric` itself has no in-crate caller, and the
//! production B-MOD model-registry port (`ProductionModelRegistryPort`) reports
//! `PortBindingState::Missing`, so a production route resolution cannot succeed
//! in this crate at all. The gate is therefore reachable only once its
//! per-operation executor binds that driver; the driver seam lives outside
//! `bins/eliotd`, and no composition method here invents a caller for it.
//!
//! **Trap recorded for the next writer: do NOT reintroduce an
//! `apply_scope_change` call with an OBSERVED route as `current` and
//! `ScopeDependencySelector::all()`.** `CapabilityRegistry::apply_scope_change`
//! stales a record when its fingerprint DIFFERS from the scope supplied as
//! `current` on a selected dimension, and a scope once invalidated is not
//! revived by a later matching record. A call that passes an OBSERVED route as
//! `current` with `ScopeDependencySelector::all()` therefore inserts every
//! other account's and route's still-valid record into the growing invalidation
//! set, on every call, and permanently. I3.4 requires capability to be
//! route/account-specific, so that call erases exactly the dimension the
//! document protects. The over-broad call has been REMOVED from
//! [`DaemonComposition::require_admitted_model_route`](super::DaemonComposition::require_admitted_model_route),
//! so no production path invokes it any more; staleness is instead DERIVED at the
//! gate (below).
//!
//! [`commit_scope_change_restriction`] IS a production caller, and it is the
//! narrow direction this note describes: the startup attach holds the scope the
//! Host admitted about the daemon's OWN served bytes and selects exactly the two
//! dimensions it can attribute to its own installation — `runtime_hash` and
//! `adapter_hash` — not `all()`. A record whose two selected dimensions already
//! equal the observed ones is therefore not staled at all and keeps its
//! exact-match retention. Narrowing a record needs no capability probe, so
//! reaching this caller did not require the absent positive producer; see that
//! function's own documentation.
//!
//! Evidence bridges, and why there are two. Both are canonical reads, and they
//! carry different things — measured on current store source:
//!
//! * `GetCapabilityEvidenceState` answers committed `ApplyLifecyclePolicy`
//!   authority-receipt rows, each carrying exactly the six declared lifecycle
//!   parameters (`action`, `base_view_digest`, `candidate_digest`,
//!   `candidate_package_digest`, `skill_id`, `verifier_ref`) plus its
//!   commit-order `capture_index`. A row carries no probe status, no evidence
//!   source, and no route-scope fingerprint, so
//!   [`ingest_evidence_response`](Self::ingest_evidence_response) mints no
//!   verified record from it and reports observation currency only.
//!   [`hydrate_from_evidence_response`](Self::hydrate_from_evidence_response)
//!   therefore imports exactly one shape, and it is deliberately non-admitting:
//!   it runs the read's skill through the legacy importer
//!   ([`import_legacy`](Self::import_legacy)) and leaves every
//!   scope-fingerprint field `None`, because the read exposes none of the six
//!   dimensions it could carry. Such a record places the skill in
//!   [`required_set`](Self::required_set) and evaluates as
//!   [`SkillStanding::Unevaluated`]; it can never satisfy
//!   [`admit_production_route`](Self::admit_production_route). Marking the
//!   unavailable dimensions unknown is I3.4's rule; inferring them from the
//!   requested route is not.
//! * `GetCapabilityEvidenceRecordRange` answers the durable evidence rows
//!   themselves — the verbatim `CapabilityEvidenceRecord` document, the
//!   owner-issued `record_digest` of those bytes, and the store-issued
//!   `revision` the fenced compare-and-set assigned. This is the only leg that
//!   can mint a real `probe_passed`, `observed`, or `broken` record, and so the
//!   only leg on which a positive admits, a negative restricts, or a
//!   fingerprint change stales anything. Absence of canonical evidence REFUSES a
//!   production route; it is never treated as a pass, and never as "nothing to
//!   check".
//!
//! Staleness (I3.4: "runtime/adapter/provider/serializer change makes dependent
//! evidence stale") is therefore enforced against real durable records on two
//! independent grounds, both derived rather than remembered:
//! [`admit_production_route`](Self::admit_production_route) compares the
//! observed scope against each retained record's fingerprint by EXACT value, so
//! a record whose adapter hash, serializer fingerprint, or any other dimension
//! no longer matches cannot authorize the changed route; and
//! [`hydrate_from_evidence_record_page`](Self::hydrate_from_evidence_record_page)
//! re-derives the per-`(skill_id, scope_fingerprint)` invalidation index from
//! each served record's own persisted `limitations_and_negative_evidence`, so a
//! committed restriction survives a restart. Either way the exact route must be
//! re-probed before it authorizes production work again.
//!
//! [`drain_capability_evidence_records`] is the production rebuild path and it
//! is atomic: pages are staged and the held view is replaced only after the
//! last page, so a drain that stops early leaves the view exactly as it was
//! rather than partially hydrated.

use std::collections::BTreeMap;

use eliot_config::legacy_capability_import::{
    LegacyCapabilityDeclaration, LegacyScopeFingerprint, import_legacy_declaration,
};
use eliot_governor::{
    CapabilityEvidenceRecord, CapabilityRegistry, CapabilitySource, CapabilityStatus,
    GovernorComposition, KernelGenerationPort, KernelTransitionPort,
    MAX_CAPABILITY_EVIDENCE_RECORDS, OwnerEvidenceRevision, RouteScopeFingerprint,
    ScopeDependencySelector, SkillStanding, capability_evidence_idempotency_key,
    capability_evidence_mutation_request_for_record, commit_capability_evidence_record,
};
use eliot_store_api::{
    EVIDENCE_PACK_MAX_RECORDS, EffectClass, EventProjectionRelationIntents,
    MAX_CAPABILITY_EVIDENCE_PAGE_RECORDS, MAX_CAPABILITY_EVIDENCE_SKILL_ID_BYTES,
    NamedReadOperation, NamedReadRequest, NamedReadResponse, ReadConsistency, ScopeId,
    SecurityContext, TransitionClass, WriteReceipt, WriteReceiptStatus,
    generated_operation_manifests, operation_manifest_set_digest, validate_store_receipt_envelope,
};
use thiserror::Error;

use super::SERVICE_NAME;
use super::route_receipts::{RouteAdmissionVisibility, RouteReceiptError};
use crate::kernel_context_read_client::KernelContextReadClient;

/// Fail-closed errors for the daemon capability-evidence bridge.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum EvidenceBridgeError {
    /// The skill identity is blank or carries control characters.
    #[error("capability evidence skill identity must be non-blank with no control characters")]
    BlankSkill,
    /// The record bound is outside `1..=EVIDENCE_PACK_MAX_RECORDS`.
    #[error("capability evidence max_records must be within 1..=32")]
    BadBound,
    /// The store request is structurally invalid.
    #[error("capability evidence read request is invalid: {0}")]
    Request(String),
    /// The store response answers a different operation, fence, scope, or
    /// skill than the planned read.
    #[error("capability evidence response does not answer the planned read: {0}")]
    ResponseMismatch(&'static str),
    /// The store payload is not the versioned capability-evidence shape.
    #[error("capability evidence payload is not the versioned shape: {0}")]
    Payload(&'static str),
    /// The bounded registry refused a new capability key, so the requested
    /// evidence coverage was not retained.
    #[error("capability evidence registry is full; new capability coverage was refused")]
    CapacityExceeded,
    /// A one-shot page hydration cannot claim complete coverage: the store
    /// reports further eligible rows past this page and the caller supplied no
    /// continuation to drain. Nothing from the page is installed.
    #[error("capability evidence page is truncated; complete coverage requires the paged drain")]
    CoverageIncomplete,
    /// The narrowed dependency change was refused, so nothing was staled and
    /// nothing was committed.
    #[error("capability evidence scope change was refused: {0}")]
    ScopeChange(String),
    /// One restricted record's durable commit leg was refused. The in-process
    /// restriction for every staled key REMAINS (the fail-closed direction) and
    /// every leg already committed stays committed; the message names how far
    /// the commit got so the residual in-process-only restriction is visible.
    #[error("capability evidence restriction commit leg refused: {0}")]
    RestrictionCommit(String),
    /// A production observation receipt is not well formed, so no observed
    /// record was built and nothing was committed.
    #[error("production observation receipt is not well formed: {0}")]
    Observation(RouteReceiptError),
    /// A production-observation commit leg was refused before or by the
    /// store, so nothing was recorded. The held view keeps its previous
    /// contents and any production route it cannot evidence stays refused.
    #[error("production observation commit leg refused: {0}")]
    ObservationCommit(String),
}

/// Daemon-held Governor capability admission view.
///
/// Constructed empty by the daemon composition root and consulted before
/// route execution; hydrated from the canonical evidence read and the
/// legacy importer. Semantics stay in [`CapabilityRegistry`].
#[derive(Debug, Default)]
pub struct GovernorCapabilityAdmission {
    registry: CapabilityRegistry,
}

impl GovernorCapabilityAdmission {
    /// Creates an empty admission view.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registry: CapabilityRegistry::new(),
        }
    }

    /// Returns the underlying canonical registry.
    #[must_use]
    pub const fn registry(&self) -> &CapabilityRegistry {
        &self.registry
    }

    /// Replaces the held registry with a completely drained one.
    ///
    /// Only [`drain_capability_evidence_records`] calls this, and only after it
    /// has drained the canonical read to exhaustion. Taking the whole registry
    /// rather than merging into it is what makes a partial drain harmless: a
    /// drain that stops early never reaches this method, so the held view keeps
    /// exactly the records — and exactly the derived invalidation state — it
    /// had before.
    fn replace_drained_registry(&mut self, drained: Self) {
        self.registry = drained.registry;
    }

    /// Returns the number of retained evidence records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.registry.len()
    }

    /// Returns true when no evidence records are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registry.is_empty()
    }

    /// Inserts one canonical evidence record under the immutable owner-issued
    /// revision the canonical store issued for it (probe/observation path).
    ///
    /// The revision is the only supersession authority the registry accepts;
    /// no semantic rule lives here.
    pub fn insert(
        &mut self,
        record: CapabilityEvidenceRecord,
        revision: OwnerEvidenceRevision,
    ) -> bool {
        self.registry.insert(record, revision)
    }

    /// Imports one legacy declaration as `declared/imported_legacy`.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceBridgeError::BlankSkill`] for an invalid identity or
    /// [`EvidenceBridgeError::CapacityExceeded`] when a new key cannot be
    /// retained by the bounded registry.
    pub fn import_legacy(
        &mut self,
        declaration: &LegacyCapabilityDeclaration,
    ) -> Result<bool, EvidenceBridgeError> {
        let imported =
            import_legacy_declaration(declaration).map_err(|_| EvidenceBridgeError::BlankSkill)?;
        let record = CapabilityEvidenceRecord::from(&imported);
        // A legacy declaration is not evidence and no store arbitrates a
        // revision for it, so it is retained at the reserved floor: it can
        // never displace, reorder, or requalify verified evidence.
        let already_retained = self.registry.retained().iter().any(|retained| {
            retained.record.skill_id == record.skill_id
                && retained.record.scope_fingerprint == record.scope_fingerprint
        });
        let inserted = self
            .registry
            .insert(record, OwnerEvidenceRevision::legacy_declared());
        if !inserted && !already_retained && self.registry.len() >= MAX_CAPABILITY_EVIDENCE_RECORDS
        {
            return Err(EvidenceBridgeError::CapacityExceeded);
        }
        Ok(inserted)
    }

    /// Returns the canonical required capability set: distinct skill
    /// identities with retained evidence records, sorted. No semantic rule
    /// lives here; this is the Governor registry's observed model.
    #[must_use]
    pub fn required_set(&self) -> Vec<String> {
        self.registry.required_set()
    }

    /// Returns the standing of one skill at `now` across its retained
    /// scopes. No semantic rule lives here; this is the Governor
    /// registry's aggregation of its verified predicates.
    #[must_use]
    pub fn skill_standing(&self, skill_id: &str, now: u64) -> SkillStanding {
        self.registry.skill_standing(skill_id, now)
    }

    /// Production admission for one skill on one exact route scope at `now`.
    ///
    /// The observation time is the daemon's real clock reading
    /// (`unix_ms`): positive evidence expires and goes stale in a running
    /// daemon instead of admitting forever.
    #[must_use]
    pub fn admit_production_route(
        &self,
        skill_id: &str,
        scope: &RouteScopeFingerprint,
        now: u64,
    ) -> bool {
        self.registry.admit_production_route(skill_id, scope, now)
    }

    /// Stales dependent evidence after a narrowed dependency change, retaining
    /// the owner-issued cause each invalidated key must be requalified
    /// against. Returns the owner-issued change reference, how many
    /// `(skill_id, scope_fingerprint)` keys it newly limited, and the mutated
    /// records carrying the change reference in their own persisted
    /// `limitations_and_negative_evidence`.
    ///
    /// Those mutated records are the durable form of the restriction. Committing
    /// them through the named `RecordCapabilityEvidenceRecord` leg is what makes
    /// the restriction survive a restart; until they are committed the
    /// restriction holds in this process only, which is the fail-closed
    /// direction. The limitation is also what a later hydration re-derives the
    /// invalidation from, so a committed restriction is never forgotten.
    ///
    /// The daemon commits exactly this at startup: see
    /// [`commit_scope_change_restriction`], which is the only production caller
    /// and which selects only the dimensions the daemon can attribute to its own
    /// installation.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceRevisionError`](eliot_governor::EvidenceRevisionError)
    /// when the applied-change reference is not one hex SHA-256 digest;
    /// nothing is staled in that case.
    pub fn apply_scope_change(
        &mut self,
        current: &RouteScopeFingerprint,
        changed: ScopeDependencySelector,
        blocking_evidence_ref: &str,
    ) -> Result<eliot_governor::InvalidatedCapabilityEvidence, eliot_governor::EvidenceRevisionError>
    {
        self.registry
            .apply_scope_change(current, changed, blocking_evidence_ref)
    }

    /// Hydrates the held view from one canonical evidence-read response.
    ///
    /// Runs the full [`ingest_evidence_response`](Self::ingest_evidence_response)
    /// identity/shape validation first — a response that answers another
    /// operation, fence, scope, skill, or payload version never reaches the
    /// registry — then imports the read's skill through
    /// [`import_legacy`](Self::import_legacy) when the store holds committed
    /// governance rows for it.
    ///
    /// The imported record is `declared` / `imported_legacy_declaration` on a
    /// fully unknown route-scope fingerprint, for the two measured reasons
    /// stated in the module documentation: the served lifecycle row exposes no
    /// status, no source, and no scope fingerprint, and `declared` is the only
    /// status the adopted `CapabilityEvidenceRecord` relation admits without
    /// verified evidence. The record therefore establishes the required
    /// capability key space and the visible-degradation report, and can never
    /// satisfy [`admit_production_route`](Self::admit_production_route).
    ///
    /// A read that matched no row imports nothing: the view keeps its previous
    /// contents and no absence is ever promoted into evidence.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceBridgeError`] when the response does not answer the
    /// planned read, the payload is not the versioned shape, or the read's
    /// skill identity is not importable.
    pub fn hydrate_from_evidence_response(
        &mut self,
        request: &NamedReadRequest,
        response: &NamedReadResponse,
    ) -> Result<CapabilityHydration, EvidenceBridgeError> {
        let summary = self.ingest_evidence_response(request, response)?;
        let mut declared_records = 0;
        if summary.returned > 0 {
            let imported = self.import_legacy(&LegacyCapabilityDeclaration {
                skill_id: summary.skill_id.clone(),
                scope: LegacyScopeFingerprint::default(),
            })
            // Identity failures were rejected by the response decoder; any
            // bridge-level refusal here means coverage was not retained.
            ?;
            declared_records = usize::from(imported);
        }
        Ok(CapabilityHydration {
            summary,
            declared_records,
            retained: self.len(),
        })
    }

    /// Plans one page of the closed canonical capability-evidence RECORD read.
    ///
    /// `GetCapabilityEvidenceRecordRange` is the only read that can rebuild
    /// this view: it serves the real durable evidence rows with their
    /// owner-issued `record_digest` and the store-issued `revision` the fenced
    /// compare-and-set assigned, so a hydration can mint real
    /// [`CapabilityEvidenceRecord`]s with real owner-issued revisions.
    /// `GetCapabilityEvidenceState` cannot: it answers committed lifecycle
    /// governance rows carrying no status, source, scope fingerprint, or
    /// revision.
    ///
    /// `skill_id` is the optional exact filter over one skill; `None` selects
    /// every skill in scope, which is what a complete registry rebuild needs.
    /// `cursor` is the opaque continuation token the previous page issued;
    /// `None` reads from the start of the eligible set, and the store fails
    /// closed on a cursor that does not decode against the current fence and
    /// revision heads.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceBridgeError`] when the skill identity or page bound is
    /// not closed, or the built request is structurally invalid.
    pub fn plan_evidence_record_read(
        skill_id: Option<&str>,
        max_records: u16,
        cursor: Option<String>,
        scope: ScopeId,
        fence: eliot_contracts::StateFence,
    ) -> Result<NamedReadRequest, EvidenceBridgeError> {
        if let Some(skill) = skill_id
            && (!eliot_store_api::valid_skill_id(skill)
                || skill.len() > MAX_CAPABILITY_EVIDENCE_SKILL_ID_BYTES)
        {
            return Err(EvidenceBridgeError::BlankSkill);
        }
        if max_records == 0 || max_records > MAX_CAPABILITY_EVIDENCE_PAGE_RECORDS {
            return Err(EvidenceBridgeError::BadBound);
        }
        let request = eliot_store_api::capability_evidence_read_request(
            scope,
            skill_id.map(str::to_owned),
            max_records,
            cursor,
            fence,
        );
        request
            .validate()
            .map_err(|error| EvidenceBridgeError::Request(error.to_string()))?;
        Ok(request)
    }

    /// Applies one COMPLETE capability-evidence RECORD page to the held view,
    /// minting real records under the store-issued owner revision.
    ///
    /// Each projected row is re-proved at this read edge before it can become
    /// registry state: the row's presented `record_digest` must equal the
    /// digest over the exact record bytes, and the record's own
    /// `(skill_id, scope_fingerprint)` must be the key the row was addressed
    /// by. A row that fails either check is refused whole, so a substituted
    /// document can never displace a retained record or clear an invalidation.
    ///
    /// This is the mutating sibling the audit required: `ingest_evidence_response`
    /// is `&self` and mints nothing, so it cannot be the path that rebuilds
    /// this view.
    ///
    /// A page that reports further eligible rows (`truncated`) is refused whole
    /// with [`EvidenceBridgeError::CoverageIncomplete`] before any row is
    /// minted. A one-shot apply has no continuation to drain, so installing its
    /// prefix would present partial coverage as the view: a restriction, or a
    /// newer revision, sitting past the cursor would stay invisible while the
    /// installed prefix admits. The complete paged drain
    /// ([`drain_capability_evidence_records`]) remains the only multi-page path;
    /// it follows every continuation to exhaustion instead.
    ///
    /// The apply is atomic: envelope and row re-proofs, the truncation refusal,
    /// and the capacity fit check all run before the first insert, so an error
    /// leaves the held view exactly as it was. A refusal therefore keeps every
    /// retained restriction and admits nothing new, which is the fail-closed
    /// direction.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceBridgeError`] when the response does not answer the
    /// planned read, the payload is not the versioned record shape, a row fails
    /// its digest/key re-proof, the page reports further eligible rows, or the
    /// page carries more new keys than the bounded registry can retain.
    pub fn hydrate_from_evidence_record_page(
        &mut self,
        request: &NamedReadRequest,
        response: &NamedReadResponse,
    ) -> Result<EvidenceRecordPage, EvidenceBridgeError> {
        let decoded = decode_evidence_record_page(request, response)?;
        if decoded.truncated {
            return Err(EvidenceBridgeError::CoverageIncomplete);
        }
        // Atomic fit check before the first insert: the distinct new keys the
        // page carries must fit the bound alongside what is already retained,
        // so a page that cannot be installed whole is refused whole instead of
        // leaving a minted prefix behind.
        {
            let mut unseen_new: Vec<(&str, &RouteScopeFingerprint)> = Vec::new();
            for (record, _) in &decoded.rows {
                if self
                    .registry
                    .retained_revision(&record.skill_id, &record.scope_fingerprint)
                    .is_some()
                {
                    continue;
                }
                if unseen_new.iter().any(|(skill, scope)| {
                    *skill == record.skill_id.as_str() && *scope == &record.scope_fingerprint
                }) {
                    continue;
                }
                unseen_new.push((record.skill_id.as_str(), &record.scope_fingerprint));
            }
            if self.registry.len() + unseen_new.len() > MAX_CAPABILITY_EVIDENCE_RECORDS {
                return Err(EvidenceBridgeError::CapacityExceeded);
            }
        }
        let mut minted = 0_usize;
        for (record, revision) in decoded.rows {
            // The fit check above guarantees a new key is never refused here.
            // An equal/older replay converges silently: it displaces nothing.
            if self.registry.insert(record, revision) {
                minted = minted.saturating_add(1);
            }
        }
        Ok(EvidenceRecordPage {
            minted,
            truncated: false,
            next_cursor: decoded.next_cursor,
            retained: self.len(),
        })
    }

    /// Applies one RECORD page to the held view while tolerating truncation.
    ///
    /// Only [`drain_capability_evidence_records`] calls this, and only with the
    /// continuation the page issued: the drain follows every page to exhaustion
    /// and replaces the held view solely after the last one, so a truncated
    /// page here is a drain in progress, never installed partial coverage.
    fn apply_evidence_record_page(
        &mut self,
        request: &NamedReadRequest,
        response: &NamedReadResponse,
    ) -> Result<EvidenceRecordPage, EvidenceBridgeError> {
        let decoded = decode_evidence_record_page(request, response)?;
        let mut minted = 0_usize;
        for (record, revision) in decoded.rows {
            // A new key refused because the bounded registry is full means the
            // requested coverage was NOT retained, so hydration reports the
            // refusal instead of claiming coverage. An equal/older replay
            // converges silently: it displaces nothing.
            let already_retained = self
                .registry
                .retained_revision(&record.skill_id, &record.scope_fingerprint)
                .is_some();
            if self.registry.insert(record, revision) {
                minted = minted.saturating_add(1);
            } else if !already_retained {
                return Err(EvidenceBridgeError::CapacityExceeded);
            }
        }
        Ok(EvidenceRecordPage {
            minted,
            truncated: decoded.truncated,
            next_cursor: decoded.next_cursor,
            retained: self.len(),
        })
    }

    /// Plans the closed canonical evidence read for one skill.
    ///
    /// The request carries the exact `skill_id` + `max_records` selectors
    /// the store catalogue declares for `GetCapabilityEvidenceState`, under
    /// the caller-supplied scope and `ExactFence` fence. It executes through
    /// [`KernelContextReadClient`](super::kernel_context_read_client::KernelContextReadClient),
    /// which remains the downstream authority on the wire shape.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceBridgeError`] when the skill identity or bound is
    /// not closed, or the built request is structurally invalid.
    pub fn plan_evidence_read(
        skill_id: &str,
        max_records: u32,
        scope: ScopeId,
        fence: eliot_contracts::StateFence,
    ) -> Result<NamedReadRequest, EvidenceBridgeError> {
        if skill_id.trim().is_empty() || skill_id.chars().any(char::is_control) {
            return Err(EvidenceBridgeError::BlankSkill);
        }
        if max_records == 0 || max_records > EVIDENCE_PACK_MAX_RECORDS {
            return Err(EvidenceBridgeError::BadBound);
        }
        let mut parameters = BTreeMap::new();
        parameters.insert(
            "skill_id".to_owned(),
            serde_json::Value::String(skill_id.to_owned()),
        );
        parameters.insert(
            "max_records".to_owned(),
            serde_json::Value::String(max_records.to_string()),
        );
        let request = NamedReadRequest {
            operation: NamedReadOperation::GetCapabilityEvidenceState,
            scope_id: Some(scope),
            consistency: ReadConsistency::ExactFence,
            state_fence: fence,
            parameters,
        };
        request
            .validate()
            .map_err(|error| EvidenceBridgeError::Request(error.to_string()))?;
        Ok(request)
    }

    /// Decodes one evidence-read response planned by
    /// [`plan_evidence_read`](Self::plan_evidence_read).
    ///
    /// Validates operation, fence, scope, skill, and payload-version
    /// identity, then reports how many admitted lifecycle records the store
    /// holds for the skill. Lifecycle rows carry no probe status, source,
    /// or scope fingerprint, so ingest mints no evidence records: the
    /// count is observation currency for operators, never admission.
    ///
    /// # Errors
    ///
    /// Returns [`EvidenceBridgeError`] when the response does not answer
    /// the planned read or the payload is not the versioned shape.
    pub fn ingest_evidence_response(
        &self,
        request: &NamedReadRequest,
        response: &NamedReadResponse,
    ) -> Result<ObservedLifecycleSummary, EvidenceBridgeError> {
        if response.operation != NamedReadOperation::GetCapabilityEvidenceState
            || response.operation != request.operation
        {
            return Err(EvidenceBridgeError::ResponseMismatch("operation"));
        }
        if response.state_fence != request.state_fence {
            return Err(EvidenceBridgeError::ResponseMismatch("fence"));
        }
        response
            .validate()
            .map_err(|_| EvidenceBridgeError::ResponseMismatch("shape"))?;
        let payload = &response.payload;
        let version = payload.get("version").and_then(serde_json::Value::as_u64);
        if version != Some(1) {
            return Err(EvidenceBridgeError::Payload("version"));
        }
        let planned_skill = request
            .parameters
            .get("skill_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(EvidenceBridgeError::Payload("skill"))?;
        let payload_skill = payload
            .get("skill_id")
            .and_then(serde_json::Value::as_str)
            .ok_or(EvidenceBridgeError::Payload("skill"))?;
        if payload_skill != planned_skill {
            return Err(EvidenceBridgeError::Payload("skill"));
        }
        let planned_scope = request
            .scope_id
            .clone()
            .ok_or(EvidenceBridgeError::Payload("scope"))?;
        let payload_scope = payload
            .get("scope_id")
            .ok_or(EvidenceBridgeError::Payload("scope"))?;
        let planned_scope_value = serde_json::to_value(&planned_scope)
            .map_err(|_| EvidenceBridgeError::Payload("scope"))?;
        if payload_scope != &planned_scope_value {
            return Err(EvidenceBridgeError::Payload("scope"));
        }
        let provenance = payload
            .get("provenance")
            .ok_or(EvidenceBridgeError::Payload("provenance"))?;
        let matched_total = provenance
            .get("matched_total")
            .and_then(serde_json::Value::as_u64)
            .ok_or(EvidenceBridgeError::Payload("provenance"))?;
        let returned = provenance
            .get("returned")
            .and_then(serde_json::Value::as_u64)
            .ok_or(EvidenceBridgeError::Payload("provenance"))?;
        let truncated = provenance
            .get("truncated")
            .and_then(serde_json::Value::as_bool)
            .ok_or(EvidenceBridgeError::Payload("provenance"))?;
        Ok(ObservedLifecycleSummary {
            skill_id: planned_skill.to_owned(),
            matched_total,
            returned,
            truncated,
        })
    }
}

/// Observation currency decoded from one evidence-read response: how many
/// admitted lifecycle records the store holds for the skill. Never
/// admission by itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedLifecycleSummary {
    /// Skill the read selected.
    pub skill_id: String,
    /// Total matching lifecycle records at the admitted fence.
    pub matched_total: u64,
    /// Records carried in this payload.
    pub returned: u64,
    /// Whether the store truncated to the requested bound.
    pub truncated: bool,
}

/// One decoded capability-evidence RECORD page: envelope validated, every row
/// re-proved, nothing yet applied to any registry.
struct DecodedEvidenceRecordPage {
    rows: Vec<(CapabilityEvidenceRecord, OwnerEvidenceRevision)>,
    truncated: bool,
    next_cursor: Option<String>,
}

/// Validates one RECORD-page envelope and re-proves every row it carries.
///
/// Operation, fence, scope, version, truncation-token, and per-row
/// digest/key checks are exactly the ones the page apply used to inline, so a
/// page accepted here carries the same owner authority wherever it is applied.
/// Rows are decoded and re-proved but NOTHING is inserted: the caller decides
/// whether this page may become registry state (complete pages only for a
/// one-shot apply; continued pages only inside the drain).
fn decode_evidence_record_page(
    request: &NamedReadRequest,
    response: &NamedReadResponse,
) -> Result<DecodedEvidenceRecordPage, EvidenceBridgeError> {
    if response.operation != NamedReadOperation::GetCapabilityEvidenceRecordRange
        || response.operation != request.operation
    {
        return Err(EvidenceBridgeError::ResponseMismatch("operation"));
    }
    if response.state_fence != request.state_fence {
        return Err(EvidenceBridgeError::ResponseMismatch("fence"));
    }
    response
        .validate()
        .map_err(|_| EvidenceBridgeError::ResponseMismatch("shape"))?;
    let payload = &response.payload;
    if payload.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(EvidenceBridgeError::Payload("version"));
    }
    let planned_scope = request
        .scope_id
        .clone()
        .ok_or(EvidenceBridgeError::Payload("scope"))?;
    let planned_scope_value =
        serde_json::to_value(&planned_scope).map_err(|_| EvidenceBridgeError::Payload("scope"))?;
    if payload.get("scope_id") != Some(&planned_scope_value) {
        return Err(EvidenceBridgeError::Payload("scope"));
    }
    let truncated = payload
        .get("truncated")
        .and_then(serde_json::Value::as_bool)
        .ok_or(EvidenceBridgeError::Payload("truncated"))?;
    let next_cursor = match payload.get("next_cursor") {
        Some(serde_json::Value::Null) | None => None,
        Some(serde_json::Value::String(cursor)) => Some(cursor.clone()),
        Some(_) => return Err(EvidenceBridgeError::Payload("next_cursor")),
    };
    // A page that reports truncation without a usable continuation token is
    // not a prefix a caller can drain; it is a coverage claim the store did
    // not back, and it is refused rather than reported as hydrated.
    if truncated && next_cursor.is_none() {
        return Err(EvidenceBridgeError::Payload("next_cursor"));
    }
    let rows = payload
        .get("records")
        .and_then(serde_json::Value::as_array)
        .ok_or(EvidenceBridgeError::Payload("records"))?;
    let mut decoded = Vec::with_capacity(rows.len());
    for row in rows {
        decoded.push(decode_evidence_record_row(row)?);
    }
    Ok(DecodedEvidenceRecordPage {
        rows: decoded,
        truncated,
        next_cursor,
    })
}

/// Decodes one projected capability-evidence row into a real record plus the
/// store-issued owner revision that orders its key.
///
/// Re-proves the row at the Governor read edge, which is where the owner
/// authority is established: the presented `record_digest` must equal the digest
/// over the exact record bytes, and the record's own `(skill_id,
/// scope_fingerprint)` must reproduce the row's `scope_key` address. A row that
/// fails either check is refused whole, so no substituted document can become
/// registry state under a reference the canonical store never issued for it.
///
/// Those two checks together already bind the whole record, so no third
/// field-completeness check is added here. Measured: the only producer of a
/// record document is `canonical_json_bytes(record)` in the Governor's commit
/// owner, and [`RouteScopeFingerprint`] has no `skip_serializing_if`, so every
/// field is always present as an explicit key or an explicit `null` — I3.4's
/// "unknown rather than inferred" marker. A document that dropped a field would
/// change its `reference_digest()` and therefore fail the `scope_key`
/// re-proof, and any substituted bytes change the `record_digest`. A check that
/// cannot fire is not a check.
fn decode_evidence_record_row(
    row: &serde_json::Value,
) -> Result<(CapabilityEvidenceRecord, OwnerEvidenceRevision), EvidenceBridgeError> {
    let text = |field: &'static str| -> Result<String, EvidenceBridgeError> {
        row.get(field)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
            .ok_or(EvidenceBridgeError::Payload(field))
    };
    let record_json = text("record_json")?;
    let record_digest = text("record_digest")?;
    if eliot_store_api::sha256_hex(record_json.as_bytes()) != record_digest {
        return Err(EvidenceBridgeError::Payload("record_digest"));
    }
    let scope_key = text("scope_key")?;
    let row_skill_id = text("skill_id")?;
    let owner_revision = row
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .ok_or(EvidenceBridgeError::Payload("revision"))?;
    // Read the ORIGINAL recorded bytes, not a re-derivation over what we hold:
    // the record is taken from the document the store committed under the digest
    // it echoed, and the two re-proofs below bind those exact bytes.
    let record: CapabilityEvidenceRecord =
        serde_json::from_str(&record_json).map_err(|_| EvidenceBridgeError::Payload("record"))?;
    if record.skill_id != row_skill_id {
        return Err(EvidenceBridgeError::Payload("skill_id"));
    }
    if record.scope_fingerprint.reference_digest() != scope_key {
        return Err(EvidenceBridgeError::Payload("scope_key"));
    }
    let revision = OwnerEvidenceRevision::issued(owner_revision, &record_digest)
        .map_err(|_| EvidenceBridgeError::Payload("revision"))?;
    Ok((record, revision))
}

/// Drains the complete capability-evidence record read into the held view.
///
/// The loop is the "complete paged hydration" the audit required: it plans one
/// page, executes it through the authenticated Kernel route, applies it, and
/// continues with the exact continuation token the store issued until a page
/// reports no further eligible row. It is fail-closed in both directions:
///
/// * a page that reports truncation without a usable cursor is refused, so a
///   bounded prefix is never reported as complete coverage;
/// * a page that reports truncation must carry a continuation, and that
///   continuation must **strictly advance** past the previous one. This is the
///   house paging rule in `notification_board_attach.rs`: a short truncated page
///   would mean the store knows of more eligible rows but cannot say where they
///   resume, and continuing from a non-advancing cursor would either spin or
///   silently under-read. Both are refused rather than accepted and hoped over,
///   so a future provider cannot quietly break the coverage claim.
///
/// **Atomicity.** Pages are applied to a *staging* view and the held view is
/// replaced only after the last page. A drain that stops early — a capacity
/// refusal, a transport error, an invalid cursor — therefore leaves the held
/// view byte-identical to what it was, instead of leaving a partially hydrated
/// view that could admit the subset it happened to read. This is the difference
/// between "no coverage" and "wrong coverage", and only the second one is a
/// safety failure.
///
/// A returned report therefore always describes a **complete** drain: the view
/// either holds every durable evidence record the store serves at this fence, or
/// the call is an error and the view keeps its previous contents. The view
/// never believes it is fully hydrated after a partial read.
pub fn drain_capability_evidence_records(
    admission: &mut GovernorCapabilityAdmission,
    kernel: &super::daemon_kernel_client::DaemonKernelClient,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
    page_records: u16,
) -> Result<CapabilityHydrationReport, EvidenceBridgeError> {
    let mut staging = GovernorCapabilityAdmission::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0_u32;
    let mut minted = 0_usize;
    let mut issued: Vec<String> = Vec::new();
    let drained = loop {
        let request = GovernorCapabilityAdmission::plan_evidence_record_read(
            None,
            page_records,
            cursor,
            scope.clone(),
            fence.clone(),
        )?;
        let response = kernel
            .store_named_blocking(request.clone())
            .map_err(|error| EvidenceBridgeError::Request(error.to_string()))?;
        let page = staging.apply_evidence_record_page(&request, &response)?;
        pages = pages.saturating_add(1);
        minted = minted.saturating_add(page.minted);
        if !page.truncated {
            // Coverage is the staging view's own retained key count, read AFTER
            // the final page is applied. Both endpoints of that number are named
            // here so it does not have to be re-derived:
            //
            // WRITE SIDE  `CapabilityRegistry::insert`
            //             (eliot-governor/capability_evidence.rs) locates an
            //             existing key by `skill_id` + `scope_fingerprint`, and
            //             `CapabilityRegistry::len` is that key vector's length.
            // READ SIDE   `staging.len()` -> `GovernorCapabilityAdmission::len`
            //             -> `self.registry.len()`, where `self.registry` is the
            //             registry `apply_evidence_record_page` inserts
            //             into above.
            //
            // It therefore counts DISTINCT keys, so a store that re-serves a
            // page under a fresh cursor cannot inflate it. The `minted` sum is
            // reported separately and is likewise duplicate-safe, because a
            // replayed key contributes nothing to `minted`.
            break (pages, staging.len(), minted);
        }
        // House paging rule (see `notification_board_attach.rs`): a page that
        // reports truncation MUST carry a usable continuation, and that
        // continuation must strictly advance. Both providers currently set
        // `truncated` only after observing a further eligible row, so a short
        // truncated page is not reachable today — but accepting one would let a
        // future provider silently under-read the eligible set, which is the
        // wrong direction for a coverage claim. Refuse instead.
        let Some(next) = page.next_cursor else {
            return Err(EvidenceBridgeError::Payload("next_cursor"));
        };
        if issued
            .last()
            .is_some_and(|previous| next.as_str() <= previous.as_str())
        {
            return Err(EvidenceBridgeError::Request(
                "capability evidence hydration cursor did not advance".to_owned(),
            ));
        }
        issued.push(next.clone());
        cursor = Some(next);
    };
    admission.replace_drained_registry(staging);
    let (pages, observed_records, minted_records) = drained;
    let observed_records = u64::try_from(observed_records).unwrap_or(u64::MAX);
    Ok(CapabilityHydrationReport {
        pages,
        observed_records,
        minted_records,
        retained: usize::try_from(observed_records).unwrap_or(usize::MAX),
    })
}

/// Bound the one canonical evidence commit's deadline from the daemon clock.
const CAPABILITY_EVIDENCE_COMMIT_DEADLINE_MS: u64 = 30_000;

/// Applies one narrowed dependency change to the held admission view and
/// COMMITS every record that change limited, through the named
/// `RecordCapabilityEvidenceRecord` leg (issue #1773, I3.4, W2).
///
/// # Why this exists and why it needs no probe
///
/// [`CapabilityRegistry::apply_scope_change`] only ever *narrows* a record: it
/// writes the owner-issued change reference into the record's already-declared
/// [`limitations_and_negative_evidence`](CapabilityEvidenceRecord::limitations_and_negative_evidence)
/// field. That is not a capability claim, so I3.4's "production admission
/// requires matching `probe_passed` or `observed` evidence" does not gate it and
/// no probe has to exist for it to be honest. What the mutation was missing was
/// durability: an un-committed limitation lives only in this process and is
/// erased by a restart, after which the evidence it limited can be re-admitted.
/// Committing it is therefore the whole of the repair, and it commits bytes the
/// owner already held.
///
/// # Order, and why it cannot partially clear
///
/// 1. [`GovernorCapabilityAdmission::apply_scope_change`] mutates the registry
///    and derives the invalidation index. A malformed change reference stales
///    nothing and returns an error, so nothing is committed.
/// 2. Each newly staled record is committed through
///    [`commit_capability_evidence_record`], presented at the CAS predecessor
///    the hydration gave it (the store-issued revision the registry retained),
///    so the store arbitrates `expected + 1` under its own compare-and-set.
/// 3. The store-issued revision is then installed into the held view, so the
///    registry orders the restricted record by the revision the store actually
///    holds and the next hydration re-presents it as the next predecessor.
///
/// Any refusal short-circuits. The in-process restriction REMAINS for every
/// staled key — that is the fail-closed direction, and it is why an un-committed
/// leg degrades to "this process refuses" rather than "the change did not
/// happen". Legs already committed stay committed: progress is monotone, and
/// there is no path here that clears an invalidation.
///
/// **The fence is read once, before the batch, not per leg.** That is the
/// existing house shape: the improvement-intake path commits its candidate
/// record and then a loop of archive receipts under one pre-batch
/// `state_fence` (`improvement_intake_dispatch::commit_intake_artifact`), and
/// the daemon's retained Kernel snapshot does not advance mid-process. If a
/// provider ever did move the fence between legs, the later leg is simply
/// refused and the message names how many legs committed — fail-closed, never a
/// partial clear, and never a silent success.
///
/// # The write path is the existing one
///
/// This is the Governor's own commit leg through
/// [`GovernorComposition::commit_canonical`](eliot_governor::GovernorComposition::commit_canonical)
/// — the same single canonical write the composition root uses for every other
/// durable record. No second capability service, registry or fingerprint type is
/// introduced, and the registry's own ordering/requalification rules are reused
/// unchanged rather than re-derived.
///
/// # Failures
///
/// Returns [`EvidenceBridgeError::ScopeChange`] when the change itself is
/// refused, and [`EvidenceBridgeError::RestrictionCommit`] naming the committed
/// prefix when a leg cannot be built or committed.
pub async fn commit_scope_change_restriction<P>(
    governor: &GovernorComposition<P>,
    admission: &mut GovernorCapabilityAdmission,
    observed: &RouteScopeFingerprint,
    changed: ScopeDependencySelector,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
) -> Result<ScopeChangeRestrictionReport, EvidenceBridgeError>
where
    P: KernelGenerationPort + ?Sized,
{
    // The owner-issued change reference is the exact reference of the OBSERVED
    // scope, i.e. a digest over the caller's own admitted observation — not over
    // a probe result, and not over anything inferred. It is therefore stable for
    // one observed scope across processes, which is what makes a retried startup
    // present the same cause, and it is exactly the digest shape
    // `is_evidence_ref` requires. `RouteScopeFingerprint` is eleven `Option<String>`
    // fields with no `skip_serializing_if`, so its canonical encoding cannot
    // fail and this cannot panic.
    let blocking_evidence_ref = observed.reference_digest();
    let staled = admission
        .apply_scope_change(observed, changed, &blocking_evidence_ref)
        .map_err(|error| EvidenceBridgeError::ScopeChange(error.to_string()))?;
    let restricted = staled.records.len();
    let mut committed = 0_usize;
    for retained in &staled.records {
        // The presented predecessor is the store-issued revision the hydration
        // read back for this exact key. The registry is then re-inserted at the
        // revision the store issues, so a requalification is still measured
        // entirely in owner authority.
        let outcome = commit_restriction_leg(
            governor,
            admission,
            &retained.record,
            retained.revision.owner_revision,
            &blocking_evidence_ref,
            scope,
            fence,
        )
        .await;
        if let Err(error) = outcome {
            // Name exactly how much of the restriction reached the store, so the
            // residual in-process-only invalidation is observable rather than
            // silently narrower than the change applied.
            return Err(EvidenceBridgeError::RestrictionCommit(format!(
                "{error} ({committed} of {restricted} restricted records were committed)"
            )));
        }
        committed += 1;
    }
    Ok(ScopeChangeRestrictionReport {
        blocking_evidence_ref,
        restricted,
        committed,
    })
}

/// Commits a runtime-only change against one exact original capability row.
///
/// `affected_skill_id` and `affected_prior_scope` must be the canonical key of
/// a row already retained by the Governor. The observed hash comes from the
/// authenticated installation owner; every other route dimension remains
/// unknown here. This entry first selects that exact prior row, then reuses the
/// registry's declared runtime dependency rule and the same canonical
/// restriction commit leg. It cannot invalidate another route or another
/// skill merely because their runtime hashes differ from the observed one.
pub async fn commit_targeted_runtime_scope_change_restriction<P>(
    governor: &GovernorComposition<P>,
    admission: &mut GovernorCapabilityAdmission,
    affected_skill_id: &str,
    affected_prior_scope: &RouteScopeFingerprint,
    observed_runtime_hash: &str,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
) -> Result<ScopeChangeRestrictionReport, EvidenceBridgeError>
where
    P: KernelGenerationPort + ?Sized,
{
    if affected_skill_id.trim().is_empty()
        || affected_skill_id.chars().any(char::is_control)
        || affected_skill_id.len() > MAX_CAPABILITY_EVIDENCE_SKILL_ID_BYTES
    {
        return Err(EvidenceBridgeError::BlankSkill);
    }
    if !eliot_governor::is_evidence_ref(observed_runtime_hash) {
        return Err(EvidenceBridgeError::ScopeChange(
            "observed runtime hash is not a lowercase SHA-256 digest".to_owned(),
        ));
    }
    if !affected_prior_scope
        .runtime_hash
        .as_deref()
        .is_some_and(eliot_governor::is_evidence_ref)
    {
        return Err(EvidenceBridgeError::ScopeChange(
            "the original capability row has no valid observed runtime fingerprint".to_owned(),
        ));
    }

    let observed = RouteScopeFingerprint {
        runtime_hash: Some(observed_runtime_hash.to_owned()),
        ..RouteScopeFingerprint::default()
    };
    let changed = ScopeDependencySelector {
        runtime_hash: true,
        ..ScopeDependencySelector::none()
    };
    let blocking_evidence_ref = observed.reference_digest();
    let staled = prepare_targeted_runtime_scope_change(
        admission,
        affected_skill_id,
        affected_prior_scope,
        &observed,
        changed,
        &blocking_evidence_ref,
    )?;
    install_targeted_restrictions(admission, &staled)?;
    let restricted = staled.records.len();
    let mut committed = 0_usize;
    for retained in &staled.records {
        let outcome = commit_restriction_leg(
            governor,
            admission,
            &retained.record,
            retained.revision.owner_revision,
            &blocking_evidence_ref,
            scope,
            fence,
        )
        .await;
        if let Err(error) = outcome {
            return Err(EvidenceBridgeError::RestrictionCommit(format!(
                "{error} ({committed} of {restricted} targeted records were committed)"
            )));
        }
        committed += 1;
    }
    Ok(ScopeChangeRestrictionReport {
        blocking_evidence_ref,
        restricted,
        committed,
    })
}

/// Restricts only canonical evidence rows that name the original runtime
/// fingerprint retained by the installation owner, and reconciles those
/// restrictions through the original Kernel receipt port.
///
/// The prior hash is an owner-produced lookup boundary, never a caller-authored
/// scope. Every row selected by it is independently checked against its
/// retained Governor fingerprint. An absent prior hash is an explicit gap and
/// cannot fall back to a broad current-scope comparison.
#[allow(clippy::too_many_arguments)]
pub(super) async fn commit_exact_prior_runtime_scope_change_restriction<P, K>(
    governor: &GovernorComposition<P>,
    kernel: &K,
    reads: &KernelContextReadClient,
    admission: &mut GovernorCapabilityAdmission,
    previous_runtime_hash: Option<&str>,
    observed_runtime_hash: &str,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
    deadline_unix_ms: u64,
) -> Result<ScopeChangeRestrictionReport, EvidenceBridgeError>
where
    P: KernelGenerationPort + ?Sized,
    K: KernelTransitionPort + ?Sized,
{
    let previous_runtime_hash =
        checked_previous_runtime_hash(previous_runtime_hash, observed_runtime_hash)?;

    let observed = RouteScopeFingerprint {
        runtime_hash: Some(observed_runtime_hash.to_owned()),
        ..RouteScopeFingerprint::default()
    };
    let blocking_evidence_ref = observed.reference_digest();
    let staled = prepare_exact_prior_runtime_scope_change(
        admission,
        previous_runtime_hash,
        &observed,
        &blocking_evidence_ref,
    )?;
    install_targeted_restrictions(admission, &staled)?;
    let restricted = staled.records.len();
    let mut committed = 0_usize;
    for retained in &staled.records {
        if let Err(error) = commit_restriction_leg_with_receipt(
            governor,
            kernel,
            reads,
            admission,
            &retained.record,
            retained.revision.owner_revision,
            &blocking_evidence_ref,
            scope,
            fence,
            deadline_unix_ms,
        )
        .await
        {
            return Err(EvidenceBridgeError::RestrictionCommit(format!(
                "{error} ({committed} of {restricted} exact-prior-runtime restrictions were committed)"
            )));
        }
        committed += 1;
    }
    Ok(ScopeChangeRestrictionReport {
        blocking_evidence_ref,
        restricted,
        committed,
    })
}

/// Builds the exact pending mutations from rows whose retained fingerprint
/// names the original runtime. A row already limited by this same change stays
/// pending when its owner revision still points to the pre-change record; once
/// the row's own bytes and owner-issued digest agree, the durable readback has
/// completed the work and it is not submitted again.
fn prepare_exact_prior_runtime_scope_change(
    admission: &GovernorCapabilityAdmission,
    previous_runtime_hash: &str,
    observed: &RouteScopeFingerprint,
    blocking_evidence_ref: &str,
) -> Result<eliot_governor::InvalidatedCapabilityEvidence, EvidenceBridgeError> {
    let changed = ScopeDependencySelector {
        runtime_hash: true,
        ..ScopeDependencySelector::none()
    };
    let mut targeted = CapabilityRegistry::new();
    let mut pending = Vec::new();
    for retained in admission.registry().retained().iter().filter(|retained| {
        retained.record.scope_fingerprint.runtime_hash.as_deref() == Some(previous_runtime_hash)
    }) {
        if retained.record.is_limited() {
            if retained.record.blocking_limitation() == Some(blocking_evidence_ref)
                && !retained_record_is_durable(retained)?
            {
                pending.push(retained.clone());
            }
            continue;
        }
        if !targeted.insert(retained.record.clone(), retained.revision.clone()) {
            return Err(EvidenceBridgeError::CapacityExceeded);
        }
    }

    let mut staled = targeted
        .apply_scope_change(observed, changed, blocking_evidence_ref)
        .map_err(|error| EvidenceBridgeError::ScopeChange(error.to_string()))?;
    staled.records.extend(pending);
    Ok(staled)
}

fn retained_record_is_durable(
    retained: &eliot_governor::RetainedCapabilityEvidence,
) -> Result<bool, EvidenceBridgeError> {
    let bytes = eliot_contracts::canonical_json_bytes(&retained.record)
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?;
    Ok(eliot_contracts::sha256_hex(&bytes) == retained.revision.evidence_ref)
}

fn checked_previous_runtime_hash<'a>(
    previous_runtime_hash: Option<&'a str>,
    observed_runtime_hash: &str,
) -> Result<&'a str, EvidenceBridgeError> {
    let previous_runtime_hash = previous_runtime_hash.ok_or_else(|| {
        EvidenceBridgeError::ScopeChange(
            "the original previous runtime fingerprint is unknown; exact runtime restriction is a visible gap"
                .to_owned(),
        )
    })?;
    if !eliot_governor::is_evidence_ref(previous_runtime_hash)
        || !eliot_governor::is_evidence_ref(observed_runtime_hash)
    {
        return Err(EvidenceBridgeError::ScopeChange(
            "original and observed runtime fingerprints must be lowercase SHA-256 digests"
                .to_owned(),
        ));
    }
    Ok(previous_runtime_hash)
}

/// Selects and narrows exactly one existing `(skill_id, scope_fingerprint)`
/// row in a temporary view. The production caller later commits only these
/// returned rows into the held/canonical owner; unrelated retained rows never
/// enter the mutation set.
fn prepare_targeted_runtime_scope_change(
    admission: &GovernorCapabilityAdmission,
    affected_skill_id: &str,
    affected_prior_scope: &RouteScopeFingerprint,
    observed: &RouteScopeFingerprint,
    changed: ScopeDependencySelector,
    blocking_evidence_ref: &str,
) -> Result<eliot_governor::InvalidatedCapabilityEvidence, EvidenceBridgeError> {
    let mut matches = admission.registry().retained().iter().filter(|retained| {
        retained.record.skill_id == affected_skill_id
            && retained
                .record
                .scope_fingerprint
                .exact_match(affected_prior_scope)
    });
    let target = matches.next().ok_or_else(|| {
        EvidenceBridgeError::ScopeChange(
            "the exact original capability row is not retained".to_owned(),
        )
    })?;
    if matches.next().is_some() {
        return Err(EvidenceBridgeError::ScopeChange(
            "the original capability key is ambiguous".to_owned(),
        ));
    }

    let mut targeted = CapabilityRegistry::new();
    if !targeted.insert(target.record.clone(), target.revision.clone()) {
        return Err(EvidenceBridgeError::ScopeChange(
            "the exact original capability row could not be retained for restriction".to_owned(),
        ));
    }
    targeted
        .apply_scope_change(observed, changed, blocking_evidence_ref)
        .map_err(|error| EvidenceBridgeError::ScopeChange(error.to_string()))
}

/// Installs only the selected owner records into the held view before their
/// canonical commit legs. Rebuilding the existing registry from its complete
/// retained rows preserves its derived invalidation index; refusing a latched
/// capacity failure prevents this reconstruction from clearing the registry's
/// fail-closed admission state.
fn install_targeted_restrictions(
    admission: &mut GovernorCapabilityAdmission,
    staled: &eliot_governor::InvalidatedCapabilityEvidence,
) -> Result<(), EvidenceBridgeError> {
    if staled.records.is_empty() {
        return Ok(());
    }
    if admission.registry().restriction_capacity_exhausted() {
        return Err(EvidenceBridgeError::CapacityExceeded);
    }
    let mut registry = CapabilityRegistry::new();
    for retained in admission.registry().retained() {
        let replacement = staled.records.iter().find(|restricted| {
            restricted.record.skill_id == retained.record.skill_id
                && restricted
                    .record
                    .scope_fingerprint
                    .exact_match(&retained.record.scope_fingerprint)
        });
        let record = replacement.map_or_else(
            || retained.record.clone(),
            |restricted| restricted.record.clone(),
        );
        if !registry.insert(record, retained.revision.clone()) {
            return Err(EvidenceBridgeError::CapacityExceeded);
        }
    }
    if staled.records.iter().any(|restricted| {
        !admission.registry().retained().iter().any(|retained| {
            retained.record.skill_id == restricted.record.skill_id
                && retained
                    .record
                    .scope_fingerprint
                    .exact_match(&restricted.record.scope_fingerprint)
        })
    }) {
        return Err(EvidenceBridgeError::ScopeChange(
            "a targeted restriction no longer has its original retained key".to_owned(),
        ));
    }
    admission.registry = registry;
    Ok(())
}

/// Commits one restricted record's durable leg and installs the store-issued
/// revision into the held view.
///
/// The idempotency key is derived by the SAME owner function that derives the
/// committed `operation_id`, from the same skill + scope + record digest, so a
/// retried startup converges at the store rather than appending a second row for
/// one record.
async fn commit_restriction_leg<P>(
    governor: &GovernorComposition<P>,
    admission: &mut GovernorCapabilityAdmission,
    restricted: &CapabilityEvidenceRecord,
    expected_canonical_revision: u64,
    blocking_evidence_ref: &str,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
) -> Result<(), EvidenceBridgeError>
where
    P: KernelGenerationPort + ?Sized,
{
    let idempotency_key =
        capability_evidence_idempotency_key(restricted).map_err(restriction_commit_refused)?;
    let request = capability_evidence_mutation_request_for_record(
        restricted,
        expected_canonical_revision,
        idempotency_key.clone(),
    )
    .map_err(restriction_commit_refused)?;
    let identity = restriction_commit_identity(&idempotency_key, fence)?;
    // The proof refs are the owner-issued change reference, passed through
    // unchanged: this commit is authorized by the observed dependency change,
    // not by a probe result.
    let (_receipt, revision) = commit_capability_evidence_record(
        governor,
        &identity,
        request,
        scope.clone(),
        vec![blocking_evidence_ref.to_owned()],
        Vec::new(),
        Vec::new(),
    )
    .await
    .map_err(restriction_commit_refused)?;
    // The install is checked, not assumed: `insert` accepts only a strictly
    // newer owner-issued revision, and the successor installed here is the
    // store contract `expected + 1` re-derived locally rather than read back
    // from the receipt (see `capability_evidence_commit`). A provider that
    // issued anything else would make this refuse; surfacing that as a
    // commit-leg refusal keeps the held revision from silently disagreeing
    // with the store. The in-process restriction REMAINS either way —
    // `apply_scope_change` already limited the retained record — so the
    // failure direction is closed and the next startup drain re-reads the
    // store revision and converges.
    if !admission.insert(restricted.clone(), revision) {
        return Err(EvidenceBridgeError::RestrictionCommit(format!(
            "store-issued revision for {} was not installed into the held view",
            restricted.skill_id
        )));
    }
    Ok(())
}

/// Commits or reconciles one exact restriction using the retained Kernel
/// receipt owner. The prepared canonical hash is reconstructed from the same
/// closed mutation, fence, scope, proof and manifest before any existing
/// receipt is accepted; the post-commit receipt readback must be byte-for-byte
/// the receipt returned by the canonical writer.
#[allow(clippy::too_many_arguments)]
async fn commit_restriction_leg_with_receipt<P, K>(
    governor: &GovernorComposition<P>,
    kernel: &K,
    reads: &KernelContextReadClient,
    admission: &mut GovernorCapabilityAdmission,
    restricted: &CapabilityEvidenceRecord,
    expected_canonical_revision: u64,
    blocking_evidence_ref: &str,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
    deadline_unix_ms: u64,
) -> Result<(), EvidenceBridgeError>
where
    P: KernelGenerationPort + ?Sized,
    K: KernelTransitionPort + ?Sized,
{
    let idempotency_key =
        capability_evidence_idempotency_key(restricted).map_err(restriction_commit_refused)?;
    let operation_id = eliot_contracts::OperationId::new(idempotency_key.clone())
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?;
    let request = capability_evidence_mutation_request_for_record(
        restricted,
        expected_canonical_revision,
        idempotency_key.clone(),
    )
    .map_err(restriction_commit_refused)?;
    let mut identity = restriction_commit_identity(&idempotency_key, fence)?;
    // ClockReading::default() is valid but explicitly unknown. Fixing this
    // clock for the original restriction identity keeps an unknown-outcome
    // retry's canonical bytes identical; the shared identity producer retains
    // its ordinary sampled clock for unrelated commit legs.
    identity.request.metadata.clock = eliot_contracts::ClockReading::default();
    identity.deadline_unix_ms = deadline_unix_ms;
    identity
        .validate()
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?;
    let prior_receipt = kernel
        .receipt(operation_id.clone())
        .await
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?;
    let ordering_head = match prior_receipt.as_ref() {
        Some(receipt) => crate::installation_capability_observation::ordering_head_from_receipt(
            receipt, scope, fence,
        )
        .map_err(EvidenceBridgeError::RestrictionCommit)?,
        None => crate::installation_capability_observation::read_ordering_head(reads, scope, fence)
            .await
            .map_err(EvidenceBridgeError::RestrictionCommit)?,
    };
    let expected_ordering_heads = vec![ordering_head];
    let (manifest_digest, prepared) = prepare_restriction_receipt_expectation(
        &identity,
        &request,
        scope,
        blocking_evidence_ref,
        &operation_id,
        &idempotency_key,
        &expected_ordering_heads,
    )?;

    if let Some(receipt) = prior_receipt {
        validate_restriction_receipt(
            &receipt,
            &identity,
            &prepared,
            &operation_id,
            &idempotency_key,
            &manifest_digest,
            fence,
        )?;
        let revision = restriction_revision_after_commit(&request, expected_canonical_revision)?;
        if !admission.insert(restricted.clone(), revision) {
            return Err(EvidenceBridgeError::CapacityExceeded);
        }
        return Ok(());
    }

    let (receipt, revision) = commit_capability_evidence_record(
        governor,
        &identity,
        request.clone(),
        scope.clone(),
        vec![blocking_evidence_ref.to_owned()],
        Vec::new(),
        expected_ordering_heads,
    )
    .await
    .map_err(restriction_commit_refused)?;
    validate_restriction_receipt(
        &receipt,
        &identity,
        &prepared,
        &operation_id,
        &idempotency_key,
        &manifest_digest,
        fence,
    )?;
    let readback = kernel
        .receipt(operation_id)
        .await
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?
        .ok_or_else(|| {
            EvidenceBridgeError::RestrictionCommit(
                "original restriction receipt is not yet readable; same operation must be reconciled"
                    .to_owned(),
            )
        })?;
    validate_restriction_receipt(
        &readback,
        &identity,
        &prepared,
        &receipt.operation_id,
        &idempotency_key,
        &manifest_digest,
        fence,
    )?;
    if readback != receipt {
        return Err(EvidenceBridgeError::RestrictionCommit(
            "Kernel restriction receipt readback differs from the canonical commit receipt"
                .to_owned(),
        ));
    }
    if !admission.insert(restricted.clone(), revision) {
        return Err(EvidenceBridgeError::CapacityExceeded);
    }
    Ok(())
}

fn prepare_restriction_receipt_expectation(
    identity: &eliot_protocol::RequestIdentity,
    request: &eliot_store_api::NamedMutationRequest,
    scope: &ScopeId,
    blocking_evidence_ref: &str,
    operation_id: &eliot_contracts::OperationId,
    idempotency_key: &str,
    expected_ordering_heads: &[eliot_store_api::OrderingHeadExpectation],
) -> Result<
    (
        eliot_store_api::OperationManifestDigest,
        eliot_store_api::PreparedTransition,
    ),
    EvidenceBridgeError,
> {
    let manifest_digest =
        operation_manifest_set_digest(&generated_operation_manifests().map_err(|error| {
            EvidenceBridgeError::RestrictionCommit(format!("operation catalogue: {error}"))
        })?)
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?;
    let envelope = eliot_canonical::CanonicalWriteEnvelope {
        operation_id: operation_id.clone(),
        request: identity.request.metadata.clone(),
        idempotency_key: idempotency_key.to_owned(),
        scope_id: scope.clone(),
        task_id: None,
        transition_class: TransitionClass::CaptureCandidate,
        requested_effect_ceiling: EffectClass::Candidate,
        admission_contract_set_digest: eliot_canonical::supported_admission_contract_set_digest()
            .map_err(|error| {
            EvidenceBridgeError::RestrictionCommit(error.to_string())
        })?,
        operation_manifest_digest: manifest_digest.clone(),
        semantic_commands: vec![request.clone()],
        event_projection_relation_intents: EventProjectionRelationIntents {
            event_ids: Vec::new(),
            projection_kinds: Vec::new(),
            relation_kinds: Vec::new(),
        },
        security: SecurityContext::default(),
        required_proof_and_approval_refs: vec![blocking_evidence_ref.to_owned()],
        expected_revision_heads: Vec::new(),
        expected_ordering_heads: expected_ordering_heads.to_vec(),
    };
    envelope
        .validate()
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?;
    let prepared = envelope
        .prepare()
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?;
    Ok((manifest_digest, prepared))
}

fn validate_restriction_receipt(
    receipt: &WriteReceipt,
    identity: &eliot_protocol::RequestIdentity,
    prepared: &eliot_store_api::PreparedTransition,
    operation_id: &eliot_contracts::OperationId,
    idempotency_key: &str,
    manifest_digest: &eliot_store_api::OperationManifestDigest,
    fence: &eliot_contracts::StateFence,
) -> Result<(), EvidenceBridgeError> {
    receipt
        .validate()
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?;
    validate_store_receipt_envelope(&identity.request.metadata, prepared, receipt)
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))?;
    if receipt.status != WriteReceiptStatus::Committed
        || receipt.operation_id != *operation_id
        || receipt.idempotency_key != idempotency_key
        || receipt.canonical_request_hash != prepared.identity.canonical_request_hash
        || receipt.transition_class != TransitionClass::CaptureCandidate
        || receipt.operation_manifest_digest != *manifest_digest
        || receipt.state_fence != *fence
        || receipt.envelope.is_none()
    {
        return Err(EvidenceBridgeError::RestrictionCommit(
            "original restriction receipt does not match the frozen command, manifest, hash, and fence"
                .to_owned(),
        ));
    }
    Ok(())
}

fn restriction_revision_after_commit(
    request: &eliot_store_api::NamedMutationRequest,
    expected_canonical_revision: u64,
) -> Result<OwnerEvidenceRevision, EvidenceBridgeError> {
    let digest = request
        .parameters
        .get("record_digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            EvidenceBridgeError::RestrictionCommit(
                "frozen restriction command has no exact evidence record digest".to_owned(),
            )
        })?;
    let successor = expected_canonical_revision.checked_add(1).ok_or_else(|| {
        EvidenceBridgeError::RestrictionCommit("restriction revision overflow".to_owned())
    })?;
    OwnerEvidenceRevision::issued(successor, digest)
        .map_err(|error| EvidenceBridgeError::RestrictionCommit(error.to_string()))
}

/// Names one refused restriction commit leg without inventing a second error
/// vocabulary for it.
fn restriction_commit_refused(error: impl std::fmt::Display) -> EvidenceBridgeError {
    EvidenceBridgeError::RestrictionCommit(error.to_string())
}

/// Builds the admitted ingress identity for one evidence commit leg.
///
/// Shared by the restriction leg and the production-observation leg: the
/// idempotency key IS the deterministic evidence operation text, so a retry
/// re-presents the same key and converges at the store. The request and
/// cancellation identities are the house `{SERVICE_NAME}:{operation}` shape
/// used by `improvement_intake_dispatch::improvement_commit_identity`;
/// nothing here mints an authority the Kernel has not admitted.
pub(super) fn commit_leg_identity(
    idempotency_key: &str,
    fence: &eliot_contracts::StateFence,
) -> Result<eliot_protocol::RequestIdentity, String> {
    let now = crate::unix_ms_i64();
    let metadata = eliot_contracts::RequestMetadata {
        request_id: eliot_contracts::RequestId::new(format!("{SERVICE_NAME}:{idempotency_key}"))
            .map_err(|error| error.to_string())?,
        session_id: None,
        task_id: None,
        product_id: eliot_contracts::ProductId::new(SERVICE_NAME)
            .map_err(|error| error.to_string())?,
        source_id: eliot_contracts::SourceId::new(SERVICE_NAME)
            .map_err(|error| error.to_string())?,
        state_fence: fence.clone(),
        clock: eliot_contracts::ClockReading {
            valid_time_ms: Some(now),
            known_time_ms: Some(now),
            transaction_sequence: None,
            monotonic_ns: None,
        },
    };
    metadata.validate().map_err(|error| error.to_string())?;
    Ok(eliot_protocol::RequestIdentity {
        request: eliot_receipts::RequestBinding {
            metadata,
            state_fence: fence.clone(),
        },
        idempotency_key: idempotency_key.to_owned(),
        deadline_unix_ms: crate::unix_ms().saturating_add(CAPABILITY_EVIDENCE_COMMIT_DEADLINE_MS),
        cancellation_id: format!("{SERVICE_NAME}:{idempotency_key}:cancel"),
    })
}

/// Builds the admitted ingress identity for one restriction commit leg.
fn restriction_commit_identity(
    idempotency_key: &str,
    fence: &eliot_contracts::StateFence,
) -> Result<eliot_protocol::RequestIdentity, EvidenceBridgeError> {
    commit_leg_identity(idempotency_key, fence).map_err(EvidenceBridgeError::RestrictionCommit)
}

/// What one applied-and-committed dependency change did.
///
/// `committed == restricted` on success, and only then is every restriction the
/// change applied also an owner-issued durable fact. A refusal is an error
/// rather than a report, because a partially committed restriction set must not
/// be readable as a complete one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScopeChangeRestrictionReport {
    /// The exact owner-issued reference of the applied change.
    pub blocking_evidence_ref: String,
    /// How many `(skill_id, scope_fingerprint)` keys the change limited.
    pub restricted: usize,
    /// How many of those limitations are now committed in the canonical store.
    pub committed: usize,
}

/// Projects one daemon-local observed-route receipt into the Governor evidence
/// scope admission compares (issue #1773, I3.4, W1).
///
/// This is the explicit checked projection Implementation item 1 licenses for
/// roles that differ: the receipt owner (`route_receipts`) separates the
/// policy-selected requested route from the runtime-observed route, while the
/// registry owner (`eliot-governor`) keys evidence on the complete effective
/// scope. The projection carries the OBSERVED route only, never the requested
/// one: the requested route is the planning reference, and capability evidence
/// is qualified against the route the runtime actually executed. The receipt
/// itself is not exported as a physical execution receipt; the Governor
/// registry is the only consumer of the projected scope.
///
/// The ORIGINAL receipt is validated first with its existing
/// [`RouteAdmissionVisibility::validate`](super::route_receipts::RouteAdmissionVisibility::validate),
/// so a malformed receipt fails with its own typed [`RouteReceiptError`]
/// before any scope is derived.
///
/// Dimensions the receipt does not observe stay unknown, never inferred
/// (I3.4: "If runtime does not expose provider/model/billing evidence, the
/// field is `unknown`, not inferred from UI selection or prompt text"):
/// `os_architecture` and `auth_profile_class` have no observed source in the
/// receipt and stay `None`, and `provider_model_route` is present only when
/// the runtime exposed both provider and model. Billing never enters the
/// scope, by the Governor registry's own rule that billing takes part in the
/// requested-versus-observed comparison but must not silently become evidence
/// scope. The composite joins (`provider|model`,
/// `reasoning_mode|continuation_behavior`,
/// `serializer_hash|feature_flags_hash` with the serializer first) are
/// internal to exact-fingerprint equality: writer and reader use this same
/// projection, so one scope changes exactly when the observed behavior does,
/// and an adapter or serializer change still moves the key.
///
/// # Errors
///
/// Returns the receipt's typed [`RouteReceiptError`] when the ORIGINAL
/// receipt is malformed.
pub fn evidence_scope_for_observed_route(
    receipt: &RouteAdmissionVisibility,
) -> Result<RouteScopeFingerprint, RouteReceiptError> {
    receipt.validate()?;
    let observed = &receipt.observed_route;
    let provider_model_route = if receipt.provider_unobserved() || receipt.model_unobserved() {
        None
    } else {
        let provider = observed.provider.as_str();
        let model = observed.model.as_str();
        Some(format!("{provider}|{model}"))
    };
    let reasoning = observed.reasoning_mode.as_str();
    let continuation = observed.continuation_behavior.as_str();
    let serializer = observed.serializer_hash.as_str();
    let flags = observed.feature_flags_hash.as_str();
    Ok(RouteScopeFingerprint {
        host_family: Some(observed.host_family.clone()),
        adapter_id: Some(observed.adapter.clone()),
        protocol_transport: Some(observed.protocol_transport.clone()),
        runtime_hash: Some(observed.runtime_hash.as_str().to_owned()),
        adapter_hash: Some(observed.adapter_hash.as_str().to_owned()),
        // The receipt observes no OS architecture and no auth-profile class,
        // so both stay unknown rather than inferred from the requested route.
        os_architecture: None,
        auth_profile_class: None,
        provider_model_route,
        tool_call_id_and_role_ordering: Some(observed.tool_semantics_hash.as_str().to_owned()),
        reasoning_continuation_and_compaction: Some(format!("{reasoning}|{continuation}")),
        feature_flags_and_serializer: Some(format!("{serializer}|{flags}")),
    })
}

/// Mints one `observed` / `production_observation` record from a validated
/// observed-route receipt and commits it through the named
/// `RecordCapabilityEvidenceRecord` leg (issue #1773, I3.4, W1/AUD1).
///
/// # Why this mint is evidence, not fabrication
///
/// I3.4 admits production work only on "matching `probe_passed` or `observed`
/// evidence", and a receipt built from runtime handshake/transport facts IS
/// the production observation: [`RouteAdmissionVisibility::observe`](super::route_receipts::RouteAdmissionVisibility::observe)
/// refuses receipts without at least one evidence-bearing reference, and this
/// leg stores those same references on the record and passes them as the
/// commit proof refs. No probe is minted, no lifecycle row count is promoted,
/// and the scope is the observed-only projection above — never the requested
/// route. The record carries no expiry the owner did not set: staleness still
/// runs through scope change and invalidation, not through an invented
/// duration.
///
/// # Requalification is structural
///
/// When the held view already invalidates this `(skill_id, scope_fingerprint)`
/// key, the minted record names the retained blocking cause, so the commit —
/// presented at the store-issued successor of the retained revision — clears
/// exactly that cause on insert and nothing wider (I3.4: "A capability failure
/// is scoped to the narrowest observed lifecycle"). A record for a key with no
/// cause carries no requalification claim and clears nothing.
///
/// # Order and failures
///
/// Validate the receipt, project the observed scope, read the retained cause
/// and CAS predecessor from the held view, build, commit, then insert at the
/// store-issued revision. Any refusal before the store returns before the
/// store is touched; a commit the bounded registry cannot retain returns
/// [`EvidenceBridgeError::CapacityExceeded`] rather than claimed coverage.
/// The write path is the existing Governor→Kernel→Store leg
/// ([`commit_capability_evidence_record`]) — no second capability service,
/// registry, or fingerprint type.
///
/// # Errors
///
/// Returns [`EvidenceBridgeError::Observation`] when the receipt is malformed,
/// [`EvidenceBridgeError::BlankSkill`] for an invalid skill identity,
/// [`EvidenceBridgeError::CapacityExceeded`] when a committed new key cannot
/// be retained, and [`EvidenceBridgeError::ObservationCommit`] when a commit
/// leg cannot be built or is refused by the store.
pub async fn commit_production_observation<P>(
    governor: &GovernorComposition<P>,
    admission: &mut GovernorCapabilityAdmission,
    skill_id: &str,
    receipt: &RouteAdmissionVisibility,
    observed_at: u64,
    scope: &ScopeId,
    fence: &eliot_contracts::StateFence,
) -> Result<ProductionObservationReport, EvidenceBridgeError>
where
    P: KernelGenerationPort + ?Sized,
{
    receipt
        .validate()
        .map_err(EvidenceBridgeError::Observation)?;
    if skill_id.trim().is_empty()
        || skill_id.chars().any(char::is_control)
        || skill_id.len() > MAX_CAPABILITY_EVIDENCE_SKILL_ID_BYTES
    {
        return Err(EvidenceBridgeError::BlankSkill);
    }
    let evidence_scope =
        evidence_scope_for_observed_route(receipt).map_err(EvidenceBridgeError::Observation)?;
    // The requalification this fresh evidence answers, when the held view
    // already restricts this key: the retained cause's own reference, which
    // the registry requires exactly before it clears.
    let blocking = admission
        .registry()
        .invalidation_cause(skill_id, &evidence_scope)
        .cloned();
    let mut record = CapabilityEvidenceRecord::verified(
        skill_id,
        CapabilityStatus::Observed,
        CapabilitySource::ProductionObservation,
        evidence_scope,
        observed_at,
    )
    .map_err(|error| EvidenceBridgeError::ObservationCommit(error.to_string()))?;
    if let Some(cause) = blocking.as_ref() {
        record = record
            .requalifying(&cause.blocking_evidence_ref)
            .map_err(|error| EvidenceBridgeError::ObservationCommit(error.to_string()))?;
    }
    // The receipt's own backing refs travel on the record and as the commit
    // proof refs: the observation is evidenced, not declared.
    record.evidence_refs = receipt.evidence_refs.clone();
    // The presented predecessor is the store-issued revision the hydration
    // read back for this exact key, or zero for a key the store never issued
    // (the store issues one for the first write and refuses a stale
    // predecessor after that). A delayed observation therefore cannot displace
    // newer evidence before it can reach the registry.
    let predecessor = admission
        .registry()
        .retained_revision(skill_id, &record.scope_fingerprint)
        .map_or(0, |revision| revision.owner_revision);
    let idempotency_key = capability_evidence_idempotency_key(&record)
        .map_err(|error| EvidenceBridgeError::ObservationCommit(error.to_string()))?;
    let request = capability_evidence_mutation_request_for_record(
        &record,
        predecessor,
        idempotency_key.clone(),
    )
    .map_err(|error| EvidenceBridgeError::ObservationCommit(error.to_string()))?;
    let identity = commit_leg_identity(&idempotency_key, fence)
        .map_err(EvidenceBridgeError::ObservationCommit)?;
    let (_receipt, revision) = commit_capability_evidence_record(
        governor,
        &identity,
        request,
        scope.clone(),
        receipt.evidence_refs.clone(),
        Vec::new(),
        Vec::new(),
    )
    .await
    .map_err(|error| EvidenceBridgeError::ObservationCommit(error.to_string()))?;
    // The store issued exactly predecessor + 1 under its own compare-and-set,
    // so a same-key insert is strictly newer than the retained revision and a
    // requalification carries the authority the registry requires. Only a new
    // key past the bound is refused, and that refusal is reported rather than
    // claimed as coverage: the row is durable and a later drain retains it.
    if !admission.insert(record, revision.clone()) {
        return Err(EvidenceBridgeError::CapacityExceeded);
    }
    Ok(ProductionObservationReport {
        owner_revision: revision.owner_revision,
        requalified: blocking.is_some(),
        retained: admission.len(),
    })
}

/// What one committed production observation did.
///
/// A returned report always describes a durable row the held view retains: the
/// store-issued revision orders the key from here on, and the next complete
/// drain re-serves the same row. A refusal is an error rather than a report,
/// because an uncommitted observation must not be readable as evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionObservationReport {
    /// The store-issued owner revision the committed row now holds.
    pub owner_revision: u64,
    /// Whether the committed record named the retained blocking cause for
    /// its key, requalifying exactly that restriction on insert.
    pub requalified: bool,
    /// Records the held view retains after the commit.
    pub retained: usize,
}

/// One applied page of the capability-evidence record read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EvidenceRecordPage {
    /// Records this page newly retained (replays converge and are not counted).
    ///
    /// This is the count a coverage claim may use, because it counts DISTINCT
    /// keys: a page that re-serves an already-retained key adds nothing. There is
    /// deliberately no per-page row count alongside it. A served-row count
    /// double-counts whenever a provider re-serves a page under a fresh cursor,
    /// which would make a drain report more coverage than it actually read, and
    /// that is the specific failure a coverage figure exists to exclude.
    pub minted: usize,
    /// Whether the store observed a further eligible row beyond this page.
    pub truncated: bool,
    /// The exact continuation token to present next, when truncated.
    pub next_cursor: Option<String>,
    /// Records the held view retains after this page.
    pub retained: usize,
}

/// Coverage report of one complete capability-evidence drain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityHydrationReport {
    /// Pages drained to exhaustion.
    pub pages: u32,
    /// Durable evidence rows observed across every page.
    /// Distinct `(skill_id, scope_fingerprint)` evidence keys the drained view
    /// holds. This is the honest coverage figure: it is the registry's own
    /// retained count, so a store that re-served a page under a fresh cursor
    /// cannot inflate it. Never a sum of per-page row counts.
    pub observed_records: u64,
    /// Records the drain newly retained; a replayed record is not re-counted.
    pub minted_records: usize,
    /// Records the held view retains after the drain.
    pub retained: usize,
}

/// Result of hydrating the held view from one canonical evidence read.
///
/// `declared_records` is the count of `declared` / `imported_legacy`
/// contributions the read newly retained; a read that matched no committed
/// governance row or replayed an already-retained record adds none. Capacity
/// refusal returns an error and is never reported as hydrated coverage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilityHydration {
    /// Observation currency decoded from the served payload.
    pub summary: ObservedLifecycleSummary,
    /// Declared/imported records this read contributed (0 or 1).
    pub declared_records: usize,
    /// Records the held view retains after hydration.
    pub retained: usize,
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_config::legacy_capability_import::LegacyScopeFingerprint;
    use eliot_contracts::{EpochId, EpochLineageId, ResourceGeneration, StateFence};
    use eliot_governor::{CapabilitySource, CapabilityStatus};
    use std::num::NonZeroU64;

    const TEST_LINEAGE_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn fence() -> StateFence {
        StateFence::new(
            EpochId::new(
                EpochLineageId::new(TEST_LINEAGE_A).expect("lineage"),
                NonZeroU64::new(1).expect("sequence"),
            )
            .expect("epoch"),
            ResourceGeneration::new(1).expect("generation"),
        )
    }

    fn scope() -> RouteScopeFingerprint {
        RouteScopeFingerprint {
            host_family: Some("host-family-1".into()),
            adapter_id: Some("adapter-id-1".into()),
            protocol_transport: Some("app-server|stdio".into()),
            runtime_hash: Some("runtime-hash-1".into()),
            adapter_hash: Some("adapter-hash-1".into()),
            os_architecture: Some("x86_64-windows".into()),
            auth_profile_class: Some("user-broker".into()),
            provider_model_route: Some("provider/model/auth".into()),
            tool_call_id_and_role_ordering: Some("tool-call-id-1".into()),
            reasoning_continuation_and_compaction: Some("reasoning-compaction-1".into()),
            feature_flags_and_serializer: Some("serializer-v1".into()),
        }
    }

    fn probe(skill: &str, observed_at: u64) -> CapabilityEvidenceRecord {
        CapabilityEvidenceRecord::verified(
            skill,
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            scope(),
            observed_at,
        )
        .expect("valid probe verifies")
    }

    fn scope_id() -> ScopeId {
        ScopeId::new("governor").expect("scope")
    }

    /// Deterministic stand-in for a store-issued evidence revision.
    fn test_owner_revision(owner_revision: u64) -> OwnerEvidenceRevision {
        OwnerEvidenceRevision::issued(
            owner_revision,
            &eliot_store_api::sha256_hex(&owner_revision.to_be_bytes()),
        )
        .expect("fixture revision is well formed")
    }

    #[test]
    fn admission_is_held_and_consulted_with_real_time() {
        let mut admission = GovernorCapabilityAdmission::new();
        assert!(admission.is_empty());
        admission
            .import_legacy(&LegacyCapabilityDeclaration {
                skill_id: "skill-demo".into(),
                scope: LegacyScopeFingerprint::default(),
            })
            .expect("legacy imports");
        assert_eq!(admission.len(), 1);
        // Declared/imported evidence never admits, even with no other data.
        assert!(!admission.admit_production_route("skill-demo", &scope(), 10));
        admission.insert(probe("skill-demo", 1), test_owner_revision(1));
        assert!(admission.admit_production_route("skill-demo", &scope(), 10));
        // Positive evidence goes stale in the running daemon: expiry ends
        // admission without any other write.
        let mut expiring = GovernorCapabilityAdmission::new();
        expiring.insert(
            probe("skill-demo", 1).expires_at(10),
            test_owner_revision(1),
        );
        assert!(expiring.admit_production_route("skill-demo", &scope(), 9));
        assert!(!expiring.admit_production_route("skill-demo", &scope(), 10));
    }

    #[test]
    fn scope_change_stales_through_the_held_view() {
        let mut admission = GovernorCapabilityAdmission::new();
        admission.insert(probe("skill-demo", 1), test_owner_revision(1));
        assert!(admission.admit_production_route("skill-demo", &scope(), 10));
        let mut changed = scope();
        changed.adapter_hash = Some("adapter-hash-2".into());
        let selector = ScopeDependencySelector {
            adapter_hash: true,
            ..ScopeDependencySelector::none()
        };
        assert_eq!(
            admission
                .apply_scope_change(&changed, selector, &test_owner_revision(1).evidence_ref)
                .expect("fixture change reference is owner-referenced")
                .newly_staled,
            1
        );
        assert!(!admission.admit_production_route("skill-demo", &changed, 10));
    }

    #[test]
    fn targeted_runtime_change_limits_only_the_exact_original_capability_key() {
        let old_runtime = "a".repeat(64);
        let new_runtime = "b".repeat(64);
        let unrelated_runtime = "c".repeat(64);
        let mut prior_scope = scope();
        prior_scope.runtime_hash = Some(old_runtime);
        let mut unrelated_scope = scope();
        unrelated_scope.runtime_hash = Some(unrelated_runtime);
        let observed = RouteScopeFingerprint {
            runtime_hash: Some(new_runtime),
            ..RouteScopeFingerprint::default()
        };
        let changed = ScopeDependencySelector {
            runtime_hash: true,
            ..ScopeDependencySelector::none()
        };
        let blocking_ref = observed.reference_digest();

        let mut admission = GovernorCapabilityAdmission::new();
        let target = CapabilityEvidenceRecord::verified(
            "skill-target",
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            prior_scope.clone(),
            1,
        )
        .expect("target probe is a valid evidence relation");
        let sibling = CapabilityEvidenceRecord::verified(
            "skill-sibling",
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            prior_scope.clone(),
            1,
        )
        .expect("sibling probe is a valid evidence relation");
        let other_route = CapabilityEvidenceRecord::verified(
            "skill-target",
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            unrelated_scope.clone(),
            1,
        )
        .expect("unrelated route probe is a valid evidence relation");
        admission.insert(target, test_owner_revision(1));
        admission.insert(sibling, test_owner_revision(1));
        admission.insert(other_route, test_owner_revision(1));

        let staled = prepare_targeted_runtime_scope_change(
            &admission,
            "skill-target",
            &prior_scope,
            &observed,
            changed,
            &blocking_ref,
        )
        .expect("exact retained prior key is selected");
        assert_eq!(staled.newly_staled, 1);
        assert_eq!(staled.records.len(), 1);
        assert_eq!(staled.records[0].record.skill_id, "skill-target");
        assert_eq!(staled.records[0].record.scope_fingerprint, prior_scope);

        // The held view closes this exact key before the canonical leg, so a
        // refused write cannot leave stale positive evidence live in-process.
        install_targeted_restrictions(&mut admission, &staled)
            .expect("only the exact original key is installed as restricted");
        assert!(!admission.admit_production_route("skill-target", &prior_scope, 10));
        assert!(admission.admit_production_route("skill-sibling", &prior_scope, 10));
        assert!(admission.admit_production_route("skill-target", &unrelated_scope, 10));

        // Model the owner commit leg advancing only the selected canonical
        // row. Rows outside that original key remain admitted in the held view.
        assert!(admission.insert(staled.records[0].record.clone(), test_owner_revision(2)));
        assert!(!admission.admit_production_route("skill-target", &prior_scope, 10));
        assert!(admission.admit_production_route("skill-sibling", &prior_scope, 10));
        assert!(admission.admit_production_route("skill-target", &unrelated_scope, 10));
    }

    #[test]
    fn targeted_runtime_change_refuses_a_missing_original_capability_key() {
        let old_runtime = "a".repeat(64);
        let observed = RouteScopeFingerprint {
            runtime_hash: Some("b".repeat(64)),
            ..RouteScopeFingerprint::default()
        };
        let prior_scope = RouteScopeFingerprint {
            runtime_hash: Some(old_runtime),
            ..scope()
        };
        let changed = ScopeDependencySelector {
            runtime_hash: true,
            ..ScopeDependencySelector::none()
        };

        assert!(matches!(
            prepare_targeted_runtime_scope_change(
                &GovernorCapabilityAdmission::new(),
                "skill-target",
                &prior_scope,
                &observed,
                changed,
                &observed.reference_digest(),
            ),
            Err(EvidenceBridgeError::ScopeChange(_))
        ));
    }

    #[test]
    fn targeted_runtime_change_with_unchanged_hash_does_not_limit_the_original_key() {
        let runtime = "a".repeat(64);
        let prior_scope = RouteScopeFingerprint {
            runtime_hash: Some(runtime.clone()),
            ..scope()
        };
        let observed = RouteScopeFingerprint {
            runtime_hash: Some(runtime),
            ..RouteScopeFingerprint::default()
        };
        let changed = ScopeDependencySelector {
            runtime_hash: true,
            ..ScopeDependencySelector::none()
        };
        let mut admission = GovernorCapabilityAdmission::new();
        let record = CapabilityEvidenceRecord::verified(
            "skill-target",
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            prior_scope.clone(),
            1,
        )
        .expect("target probe is a valid evidence relation");
        admission.insert(record, test_owner_revision(1));

        let staled = prepare_targeted_runtime_scope_change(
            &admission,
            "skill-target",
            &prior_scope,
            &observed,
            changed,
            &observed.reference_digest(),
        )
        .expect("exact retained prior key is selected");
        assert_eq!(staled.newly_staled, 0);
        assert!(staled.records.is_empty());
        assert!(admission.admit_production_route("skill-target", &prior_scope, 10));
    }

    #[test]
    fn exact_prior_runtime_change_limits_only_rows_bound_to_that_runtime() {
        let old_runtime = "a".repeat(64);
        let new_runtime = "b".repeat(64);
        let unrelated_runtime = "c".repeat(64);
        let mut prior_a = scope();
        prior_a.runtime_hash = Some(old_runtime.clone());
        let mut prior_b = scope();
        prior_b.runtime_hash = Some(old_runtime.clone());
        prior_b.adapter_id = Some("adapter-other".to_owned());
        let mut unrelated = scope();
        unrelated.runtime_hash = Some(unrelated_runtime);
        let observed = RouteScopeFingerprint {
            runtime_hash: Some(new_runtime),
            ..RouteScopeFingerprint::default()
        };
        let blocking_ref = observed.reference_digest();
        let mut admission = GovernorCapabilityAdmission::new();
        for (skill, route) in [
            ("skill-first", prior_a.clone()),
            ("skill-second", prior_b.clone()),
            ("skill-first", unrelated.clone()),
        ] {
            assert!(
                admission.insert(
                    CapabilityEvidenceRecord::verified(
                        skill,
                        CapabilityStatus::ProbePassed,
                        CapabilitySource::ActiveProbe,
                        route,
                        1,
                    )
                    .expect("valid fixture evidence"),
                    test_owner_revision(1),
                )
            );
        }

        let staled = prepare_exact_prior_runtime_scope_change(
            &admission,
            &old_runtime,
            &observed,
            &blocking_ref,
        )
        .expect("original digest narrows the affected rows");
        assert_eq!(staled.newly_staled, 2);
        assert_eq!(staled.records.len(), 2);
        assert!(staled.records.iter().all(|row| {
            row.record.is_limited()
                && row.record.blocking_limitation() == Some(blocking_ref.as_str())
                && row.record.scope_fingerprint.runtime_hash.as_deref()
                    == Some(old_runtime.as_str())
        }));

        install_targeted_restrictions(&mut admission, &staled)
            .expect("only exact prior runtime keys enter the held restriction view");
        assert!(!admission.admit_production_route("skill-first", &prior_a, 10));
        assert!(!admission.admit_production_route("skill-second", &prior_b, 10));
        assert!(admission.admit_production_route("skill-first", &unrelated, 10));
    }

    #[test]
    fn exact_prior_runtime_unchanged_fingerprint_keeps_matching_routes_admitted() {
        let runtime = "a".repeat(64);
        let mut route = scope();
        route.runtime_hash = Some(runtime.clone());
        let observed = RouteScopeFingerprint {
            runtime_hash: Some(runtime.clone()),
            ..RouteScopeFingerprint::default()
        };
        let blocking_ref = observed.reference_digest();
        let mut admission = GovernorCapabilityAdmission::new();
        assert!(
            admission.insert(
                CapabilityEvidenceRecord::verified(
                    "skill-unchanged",
                    CapabilityStatus::ProbePassed,
                    CapabilitySource::ActiveProbe,
                    route.clone(),
                    1,
                )
                .expect("valid fixture evidence"),
                test_owner_revision(1),
            )
        );

        let staled = prepare_exact_prior_runtime_scope_change(
            &admission,
            &runtime,
            &observed,
            &blocking_ref,
        )
        .expect("matching original fingerprint is a no-op");
        assert!(staled.records.is_empty());
        assert_eq!(staled.newly_staled, 0);
        assert!(admission.admit_production_route("skill-unchanged", &route, 10));
    }

    #[test]
    fn exact_prior_runtime_retry_keeps_uncommitted_original_restriction_pending() {
        let old_runtime = "a".repeat(64);
        let observed = RouteScopeFingerprint {
            runtime_hash: Some("b".repeat(64)),
            ..RouteScopeFingerprint::default()
        };
        let blocking_ref = observed.reference_digest();
        let mut prior = scope();
        prior.runtime_hash = Some(old_runtime.clone());
        let mut admission = GovernorCapabilityAdmission::new();
        let original = CapabilityEvidenceRecord::verified(
            "skill-pending",
            CapabilityStatus::ProbePassed,
            CapabilitySource::ActiveProbe,
            prior.clone(),
            1,
        )
        .expect("valid fixture evidence");
        assert!(admission.insert(original, test_owner_revision(1)));

        let first = prepare_exact_prior_runtime_scope_change(
            &admission,
            &old_runtime,
            &observed,
            &blocking_ref,
        )
        .expect("first owner change limits its exact prior row");
        assert_eq!(first.records.len(), 1);
        install_targeted_restrictions(&mut admission, &first)
            .expect("the held view closes before the durable commit");

        let retry = prepare_exact_prior_runtime_scope_change(
            &admission,
            &old_runtime,
            &observed,
            &blocking_ref,
        )
        .expect("the same original change retains pending durable work");
        assert_eq!(retry.newly_staled, 0);
        assert_eq!(retry.records.len(), 1);
        assert_eq!(retry.records[0].record, first.records[0].record);
        assert_eq!(retry.records[0].revision, first.records[0].revision);
        assert!(
            !retained_record_is_durable(&retry.records[0])
                .expect("the pre-change owner digest is not the limited record digest")
        );

        let limited = retry.records[0].record.clone();
        let limited_digest = eliot_contracts::sha256_hex(
            &eliot_contracts::canonical_json_bytes(&limited).expect("limited canonical bytes"),
        );
        let durable_revision = OwnerEvidenceRevision::issued(2, &limited_digest)
            .expect("the store readback carries the limited row digest");
        assert!(admission.insert(limited, durable_revision));
        let durable_replay = prepare_exact_prior_runtime_scope_change(
            &admission,
            &old_runtime,
            &observed,
            &blocking_ref,
        )
        .expect("exact owner readback closes the original pending restriction");
        assert!(durable_replay.records.is_empty());
    }

    #[test]
    fn exact_prior_runtime_change_keeps_unknown_or_malformed_hash_visible() {
        let observed = "b".repeat(64);
        assert!(matches!(
            checked_previous_runtime_hash(None, &observed),
            Err(EvidenceBridgeError::ScopeChange(_))
        ));
        assert!(matches!(
            checked_previous_runtime_hash(Some("not-a-digest"), &observed),
            Err(EvidenceBridgeError::ScopeChange(_))
        ));
        assert_eq!(
            checked_previous_runtime_hash(Some(&"a".repeat(64)), &observed)
                .expect("original owner hash is exact"),
            "a".repeat(64)
        );
    }

    #[test]
    fn required_set_and_standing_read_through_the_held_view() {
        let mut admission = GovernorCapabilityAdmission::new();
        assert!(admission.required_set().is_empty());
        admission.insert(probe("skill-demo", 1), test_owner_revision(1));
        assert_eq!(admission.required_set(), vec!["skill-demo".to_owned()]);
        assert_eq!(
            admission.skill_standing("skill-demo", 10),
            SkillStanding::Holding
        );
        assert_eq!(
            admission.skill_standing("skill-unknown", 10),
            SkillStanding::Unevaluated
        );
    }

    #[test]
    fn evidence_read_plan_carries_the_closed_selectors() {
        let request =
            GovernorCapabilityAdmission::plan_evidence_read("skill-demo", 8, scope_id(), fence())
                .expect("closed plan builds");
        assert_eq!(
            request.operation,
            NamedReadOperation::GetCapabilityEvidenceState
        );
        assert_eq!(request.consistency, ReadConsistency::ExactFence);
        assert_eq!(
            request.parameters.get("skill_id"),
            Some(&serde_json::Value::String("skill-demo".to_owned()))
        );
        assert_eq!(
            request.parameters.get("max_records"),
            Some(&serde_json::Value::String("8".to_owned()))
        );
        assert_eq!(
            GovernorCapabilityAdmission::plan_evidence_read("  ", 8, scope_id(), fence()),
            Err(EvidenceBridgeError::BlankSkill)
        );
        assert_eq!(
            GovernorCapabilityAdmission::plan_evidence_read("skill-demo", 0, scope_id(), fence()),
            Err(EvidenceBridgeError::BadBound)
        );
        assert_eq!(
            GovernorCapabilityAdmission::plan_evidence_read(
                "skill-demo",
                EVIDENCE_PACK_MAX_RECORDS + 1,
                scope_id(),
                fence()
            ),
            Err(EvidenceBridgeError::BadBound)
        );
    }

    #[test]
    fn ingest_reports_lifecycle_observations_without_minting_evidence() {
        let admission = GovernorCapabilityAdmission::new();
        let request =
            GovernorCapabilityAdmission::plan_evidence_read("skill-demo", 8, scope_id(), fence())
                .expect("plan builds");
        let scope_value = serde_json::to_value(scope_id()).expect("scope serializes");
        let response = NamedReadResponse {
            operation: NamedReadOperation::GetCapabilityEvidenceState,
            state_fence: fence(),
            revision_heads: Vec::new(),
            payload: serde_json::json!({
                "version": 1,
                "skill_id": "skill-demo",
                "scope_id": scope_value,
                "records": [],
                "provenance": {
                    "state_fence": serde_json::to_value(fence()).expect("fence serializes"),
                    "matched_total": 3,
                    "returned": 3,
                    "max_records": 8,
                    "truncated": false,
                },
            }),
        };
        let summary = admission
            .ingest_evidence_response(&request, &response)
            .expect("versioned payload ingests");
        assert_eq!(summary.skill_id, "skill-demo");
        assert_eq!(summary.matched_total, 3);
        assert!(!summary.truncated);
        // Ingest mints nothing: the view still holds no evidence.
        assert!(admission.is_empty());
        assert!(!admission.admit_production_route("skill-demo", &scope(), 10));
    }

    #[test]
    fn ingest_rejects_identity_substitution() {
        let admission = GovernorCapabilityAdmission::new();
        let request =
            GovernorCapabilityAdmission::plan_evidence_read("skill-demo", 8, scope_id(), fence())
                .expect("plan builds");
        let scope_value = serde_json::to_value(scope_id()).expect("scope serializes");
        let payload = serde_json::json!({
            "version": 1,
            "skill_id": "skill-other",
            "scope_id": scope_value,
            "records": [],
            "provenance": {"matched_total": 0, "returned": 0, "truncated": false},
        });
        let response = NamedReadResponse {
            operation: NamedReadOperation::GetCapabilityEvidenceState,
            state_fence: fence(),
            revision_heads: Vec::new(),
            payload,
        };
        assert_eq!(
            admission.ingest_evidence_response(&request, &response),
            Err(EvidenceBridgeError::Payload("skill"))
        );
        let wrong_op = NamedReadResponse {
            operation: NamedReadOperation::GetTaskState,
            state_fence: fence(),
            revision_heads: Vec::new(),
            payload: serde_json::json!({}),
        };
        assert_eq!(
            admission.ingest_evidence_response(&request, &wrong_op),
            Err(EvidenceBridgeError::ResponseMismatch("operation"))
        );
    }
}
