//! Native curation-handler invocation binding with full result-content handoff.
//!
//! Cell `smart.dreamer.contracts` (Level-0, candidate-only, fail-closed).
//! Binds one selected [`CurationHandlerDescriptor`][crate::registry::CurationHandlerDescriptor]
//! (registry.rs descriptor closure) and its injected
//! [`CurationHandlerPort`][crate::registry::CurationHandlerPort] identity to one
//! [`ValidatedCurationItem`][crate::draft::ValidatedCurationItem] (draft.rs
//! `validate`/`accept`/`item_digest`), one
//! [`TypedCurationHandlerRequest`][crate::registry::TypedCurationHandlerRequest],
//! the [`StateFence`][eliot_contracts::StateFence], the
//! [`TargetDenominator`][crate::registry::TargetDenominator]
//! `{mode, members, expected_total}`, and the [`ScreenBinding`][crate::screen::ScreenBinding]
//! compatibility checks (`check_screen_compat`, `check_curation_request_compat`).
//!
//! [`invoke`] is pure and native: it runs intrinsic plus cross-envelope
//! compatibility plus [`ValidatedCurationItem::accept`][crate::draft::ValidatedCurationItem::accept]
//! before exactly one handler call, then seals a [`FullCurationResult`]
//! carrying the complete [`CurationPayload`][crate::curation::CurationPayload]
//! subtype output (all eleven closed payloads), the seven-dimension
//! preservation evidence, explicit mutable-target versus
//! immutable-evidence/counterevidence roles, and the common
//! request/job/scope/task/fence/registry-digest identities. A digest alone is
//! never content: the result carries the full typed content and a digest
//! binding over it. Altered item, fence, or result bindings fail closed with
//! the existing [`ContractViolation::BindingMismatch`][crate::error::ContractViolation];
//! no second violation type is introduced.
//!
//! The [`NativeCurationHandler`] trait is shaped so the A-31 local trait
//! (`CurationHandler::handle` plus `InjectedCurationPort`/`CurationPortSet` in
//! the curation crate) can migrate to this hub binding in a follow-up. A-31
//! is not edited here.
//!
//! Owns no handler logic, no routing, no I/O, no `DurableJob`, and no
//! dependency on the A-05 candidate-validation crate.

#![forbid(unsafe_code)]

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::candidate::{CandidateDisposition, PreservationReport};
use crate::curation::{CurationKind, CurationPayload, parse_kind};
use crate::draft::{CurationAcceptanceCtx, ValidatedCurationItem};
use crate::encoding;
use crate::error::is_hex64_lower;
use crate::error::{ContractViolation, check_fence, check_text, check_vec_bound, sorted_set_eq};
use crate::registry::{
    CurationFamily, CurationHandlerPort, CurationHandlerRegistry, TypedCurationHandlerRequest,
    family_of,
};

/// Maximum bytes admitted for a produced support or rollback note.
const MAX_NOTE_CHARS: usize = 256;
/// Maximum counterevidence handles admitted in one produced content.
const MAX_COUNTEREVIDENCE: usize = 1_024;
/// Maximum aggregate bytes admitted across counterevidence handles.
const MAX_COUNTEREVIDENCE_BYTES: usize = 1_048_576;
/// Maximum bytes admitted for a counterevidence handle.
const MAX_HANDLE_CHARS: usize = 128;
/// Maximum bytes admitted for a hub identity field.
const MAX_IDENTITY_CHARS: usize = 128;

/// Native handler port contract owned by the A-03 hub.
///
/// Implementors are the ten concrete subtype owners (or faithful test doubles
/// counting real calls against an injected port). The hub calls
/// [`NativeCurationHandler::handle`] exactly once per accepted invocation and
/// preserves any returned [`ContractViolation`] terminally with no retry, no
/// fallback, and no sibling call. A-31 can migrate its local
/// `CurationHandler::handle` (typed request in, digest-only result envelope
/// out) to this shape (bound call in, full result content out) in a
/// follow-up; that migration is out of scope here.
pub trait NativeCurationHandler {
    /// Handles one bound curation call, returning full result content.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] when the owner cannot form content; the
    /// caller preserves the failure terminally.
    fn handle(
        &self,
        call: &BoundCurationCall,
    ) -> Result<ProducedCurationContent, ContractViolation>;
}

/// Validated frozen view handed to the selected native handler: the injected
/// port, the accepted item, the typed request, and the closed-registry digest
/// the port descriptor was bound against.
///
/// Owned so the call view is frozen at invocation time and so implementors
/// (including a future A-31 migration) face no lifetime plumbing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundCurationCall {
    /// Injected port bound to the registered descriptor of its family.
    pub port: CurationHandlerPort,
    /// Accepted curation item proposed for handling.
    pub item: ValidatedCurationItem,
    /// Typed handler request compatible with the item and screen.
    pub request: TypedCurationHandlerRequest,
    /// Hex digest of the closed registry covering the port descriptor.
    pub registry_digest: String,
}

impl BoundCurationCall {
    /// Validates port, item, request, and registry-digest shape.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] on any intrinsic or digest-shape drift.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.port.validate()?;
        self.item.validate()?;
        self.request.validate()?;
        if !is_hex64_lower(&self.registry_digest) {
            return Err(ContractViolation::Malformed {
                field: "registry_digest",
                reason: "must be 64-character lowercase hex sha256".to_owned(),
            });
        }
        Ok(())
    }
}

/// Full result content produced by the selected native handler.
///
/// Carries the complete typed payload (not a digest alone), the
/// seven-dimension preservation evidence, an explicit counterevidence role
/// disjoint from mutable targets, and human-readable support/rollback notes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProducedCurationContent {
    /// Complete typed payload output for the invoked kind.
    pub payload: CurationPayload,
    /// Disposition of the produced candidate.
    pub disposition: CandidateDisposition,
    /// Seven-dimension preservation evidence for the produced content.
    pub preservation: PreservationReport,
    /// Support note for the produced content (non-blank).
    pub support_note: String,
    /// Rollback note for the produced content (non-blank).
    pub rollback_note: String,
    /// Handler-surfaced counterevidence handles; never mutable targets.
    pub counterevidence_refs: Vec<String>,
}

impl ProducedCurationContent {
    /// Validates intrinsic bounds, preservation, notes, and role separation.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] on bad payload, failed or unknown
    /// preservation, blank notes, hostile counterevidence, or
    /// counterevidence colliding with a mutable target.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.payload.validate()?;
        self.preservation.overall()?;
        check_text(&self.support_note, "support_note", MAX_NOTE_CHARS)?;
        check_text(&self.rollback_note, "rollback_note", MAX_NOTE_CHARS)?;
        check_vec_bound(
            self.counterevidence_refs.len(),
            MAX_COUNTEREVIDENCE,
            "counterevidence_refs",
        )?;
        let aggregate: usize = self
            .counterevidence_refs
            .iter()
            .map(String::len)
            .fold(0usize, usize::saturating_add);
        check_vec_bound(aggregate, MAX_COUNTEREVIDENCE_BYTES, "counterevidence_refs")?;
        for handle in &self.counterevidence_refs {
            check_text(handle, "counterevidence_refs", MAX_HANDLE_CHARS)?;
        }
        let mut ordered = self.counterevidence_refs.clone();
        ordered.sort();
        ordered.dedup();
        if ordered.len() != self.counterevidence_refs.len() {
            return Err(ContractViolation::BindingMismatch {
                field: "counterevidence_refs",
                reason: "duplicate counterevidence ref".to_owned(),
            });
        }
        if let Some(handle) = self
            .counterevidence_refs
            .iter()
            .find(|handle| self.payload.facets().targets.contains(handle))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "counterevidence_refs",
                reason: format!("counterevidence {handle} must not be a mutable target"),
            });
        }
        Ok(())
    }

    /// Validates this content against the bound call that produced it.
    ///
    /// The handler must preserve kind, must not retarget the mutation set,
    /// and must not invent immutable evidence: produced targets must equal
    /// the item targets as a set, and every produced evidence ref must
    /// already appear in the item evidence refs.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] on kind drift, retargeting, or invented
    /// evidence.
    pub fn validate_for(&self, call: &BoundCurationCall) -> Result<(), ContractViolation> {
        self.validate()?;
        call.validate()?;
        let item_kind = parse_kind(&call.item.kind_spelling)?;
        if self.payload.kind() != item_kind || self.payload.kind() != call.request.kind {
            return Err(ContractViolation::KindPayload(format!(
                "produced payload carries kind {}, invoked kind is {}",
                self.payload.kind().as_str(),
                call.request.kind.as_str()
            )));
        }
        if !sorted_set_eq(
            &self.payload.facets().targets,
            &call.item.payload.facets().targets,
        ) {
            return Err(ContractViolation::BindingMismatch {
                field: "targets",
                reason: "produced targets must equal the accepted item targets".to_owned(),
            });
        }
        let admitted = &call.item.payload.facets().evidence_refs;
        if let Some(handle) = self
            .payload
            .facets()
            .evidence_refs
            .iter()
            .find(|handle| !admitted.contains(handle))
        {
            return Err(ContractViolation::BindingMismatch {
                field: "evidence_refs",
                reason: format!("produced evidence {handle} is outside the accepted evidence"),
            });
        }
        Ok(())
    }
}

/// Sealed native invocation result: full content plus the common identities
/// and digests binding the content to the exact accepted call.
///
/// Precedent for content-carrying results is the Concept surface
/// (`ConceptCandidate` `proposal`/`preservation`/`rollback`/`handler_result`) as
/// opposed to a digest-only envelope: this result likewise carries the
/// complete payload, preservation, and role evidence, with `result_digest`
/// recomputed over the canonical content at validation time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FullCurationResult {
    /// Typed request identity preserved from the invocation.
    pub request_id: String,
    /// Owning job identity preserved from the invocation.
    pub job_id: String,
    /// Decision scope identity preserved from the invocation.
    pub scope_id: String,
    /// Owning task identity preserved from the invocation.
    pub task_id: String,
    /// Invoked curation kind.
    pub kind: CurationKind,
    /// Invoked handler family.
    pub family: CurationFamily,
    /// Handler identity of the selected port descriptor.
    pub handler_id: String,
    /// Injected port identity of the selected binding.
    pub port_id: String,
    /// Hex digest of the closed registry the descriptor was bound against.
    pub registry_digest: String,
    /// State fence the invocation ran under.
    pub state_fence: StateFence,
    /// Hex digest of the canonical typed request bytes.
    pub request_digest: String,
    /// Hex digest binding the canonical result content and identities.
    pub result_digest: String,
    /// Full produced content: typed payload, preservation, and roles.
    pub content: ProducedCurationContent,
}

/// Canonical preimage hashed by [`FullCurationResult::computed_result_digest`].
#[derive(Serialize)]
struct ResultDigestPreimage<'a> {
    request_id: &'a str,
    job_id: &'a str,
    scope_id: &'a str,
    task_id: &'a str,
    kind: CurationKind,
    family: CurationFamily,
    handler_id: &'a str,
    port_id: &'a str,
    registry_digest: &'a str,
    state_fence: &'a StateFence,
    request_digest: &'a str,
    content: &'a ProducedCurationContent,
}

impl FullCurationResult {
    /// Recomputes the canonical result digest over identities plus content.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation::Malformed`] when canonicalization fails.
    pub fn computed_result_digest(&self) -> Result<String, ContractViolation> {
        let preimage = ResultDigestPreimage {
            request_id: &self.request_id,
            job_id: &self.job_id,
            scope_id: &self.scope_id,
            task_id: &self.task_id,
            kind: self.kind,
            family: self.family,
            handler_id: &self.handler_id,
            port_id: &self.port_id,
            registry_digest: &self.registry_digest,
            state_fence: &self.state_fence,
            request_digest: &self.request_digest,
            content: &self.content,
        };
        Ok(encoding::digest_hex(&encoding::canonical_bytes(&preimage)?))
    }

    /// Validates identities, kind/family agreement, fence, content, and both
    /// digests; `result_digest` is recomputed, never trusted.
    ///
    /// # Errors
    ///
    /// Returns [`ContractViolation`] on any identity drift, kind drift,
    /// content failure, digest-shape failure, or digest mismatch. Protected
    /// immutable evidence validates as evidence only: any evidence or
    /// counterevidence handle appearing as a mutable target fails.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        check_text(&self.request_id, "request_id", MAX_IDENTITY_CHARS)?;
        check_text(&self.job_id, "job_id", MAX_IDENTITY_CHARS)?;
        check_text(&self.scope_id, "scope_id", MAX_IDENTITY_CHARS)?;
        check_text(&self.task_id, "task_id", MAX_IDENTITY_CHARS)?;
        check_text(&self.handler_id, "handler_id", MAX_IDENTITY_CHARS)?;
        check_text(&self.port_id, "port_id", MAX_IDENTITY_CHARS)?;
        if self.family != family_of(self.kind) {
            return Err(ContractViolation::KindPayload(format!(
                "kind {} belongs to family {}, not {}",
                self.kind.as_str(),
                family_of(self.kind).as_str(),
                self.family.as_str()
            )));
        }
        if self.content.payload.kind() != self.kind {
            return Err(ContractViolation::KindPayload(format!(
                "result content carries kind {}, result declares {}",
                self.content.payload.kind().as_str(),
                self.kind.as_str()
            )));
        }
        check_fence(&self.state_fence)?;
        self.content.validate()?;
        for (field, digest) in [
            ("registry_digest", &self.registry_digest),
            ("request_digest", &self.request_digest),
            ("result_digest", &self.result_digest),
        ] {
            if !is_hex64_lower(digest) {
                return Err(ContractViolation::Malformed {
                    field,
                    reason: "must be 64-character lowercase hex sha256".to_owned(),
                });
            }
        }
        let computed = self.computed_result_digest()?;
        if computed != self.result_digest {
            return Err(ContractViolation::BindingMismatch {
                field: "result_digest",
                reason: "result digest does not bind canonical result content".to_owned(),
            });
        }
        Ok(())
    }
}

/// Returns the hex digest over the canonical bytes of a typed request.
///
/// # Errors
///
/// Returns [`ContractViolation::Malformed`] when canonicalization fails.
pub fn request_digest_of(
    request: &TypedCurationHandlerRequest,
) -> Result<String, ContractViolation> {
    Ok(encoding::digest_hex(&encoding::canonical_bytes(request)?))
}

/// Invokes the selected native handler once with a full result-content handoff.
///
/// Order: injected-port validation, closed-registry validation, live-port
/// descriptor binding against the registered owner, port/request/fence
/// binding, full [`ValidatedCurationItem::accept`][crate::draft::ValidatedCurationItem::accept]
/// (intrinsic, receipt, job, bundle, grounding, budget, screen, and
/// item/request compatibility), exactly one
/// [`NativeCurationHandler::handle`] call, produced-content validation
/// against the bound call, then sealing of the [`FullCurationResult`].
/// Any failure — including an altered item, fence, or result binding — fails
/// closed with the existing [`ContractViolation`]; handler errors are
/// terminal with no retry, no fallback, and no sibling call.
///
/// # Errors
///
/// Returns [`ContractViolation`] on any binding drift, failed acceptance,
/// handler failure, produced-content violation, or sealing failure.
pub fn invoke(
    port: &CurationHandlerPort,
    handler: &dyn NativeCurationHandler,
    item: &ValidatedCurationItem,
    ctx: &CurationAcceptanceCtx<'_>,
    registry: &CurationHandlerRegistry,
) -> Result<FullCurationResult, ContractViolation> {
    port.validate()?;
    registry.validate_closure()?;
    let Some(registered) = registry
        .handlers
        .iter()
        .find(|entry| entry.family == port.descriptor.family)
    else {
        return Err(ContractViolation::BindingMismatch {
            field: "handler_descriptor",
            reason: format!(
                "registry declares no descriptor for family {}",
                port.descriptor.family.as_str()
            ),
        });
    };
    if *registered != port.descriptor {
        return Err(ContractViolation::BindingMismatch {
            field: "handler_descriptor",
            reason: format!(
                "live port for family {} is not the registered owner",
                port.descriptor.family.as_str()
            ),
        });
    }
    let request = ctx.request;
    if port.descriptor.family != request.family {
        return Err(ContractViolation::BindingMismatch {
            field: "family",
            reason: "selected port family must equal the typed request family".to_owned(),
        });
    }
    if !port.descriptor.accepted_kinds.contains(&request.kind) {
        return Err(ContractViolation::BindingMismatch {
            field: "accepted_kinds",
            reason: "selected port does not accept the requested kind".to_owned(),
        });
    }
    if request.state_fence != item.state_fence {
        return Err(ContractViolation::BindingMismatch {
            field: "state_fence",
            reason: "typed request fence must equal the accepted item fence".to_owned(),
        });
    }
    item.accept(ctx)?;
    let registry_digest = registry.digest()?;
    let call = BoundCurationCall {
        port: port.clone(),
        item: item.clone(),
        request: request.clone(),
        registry_digest: registry_digest.clone(),
    };
    call.validate()?;
    let content = handler.handle(&call)?;
    content.validate_for(&call)?;
    let mut result = FullCurationResult {
        request_id: request.request_id.clone(),
        job_id: request.job_id.clone(),
        scope_id: request.scope_id.clone(),
        task_id: request.task_id.clone(),
        kind: request.kind,
        family: request.family,
        handler_id: port.descriptor.handler_id.clone(),
        port_id: port.port_id.clone(),
        registry_digest,
        state_fence: item.state_fence.clone(),
        request_digest: request_digest_of(request)?,
        result_digest: String::new(),
        content,
    };
    result.result_digest = result.computed_result_digest()?;
    result.validate()?;
    Ok(result)
}
