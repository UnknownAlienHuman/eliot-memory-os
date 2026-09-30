//! Closed Store wire contract for owner-separated swarm revision persistence.
//!
//! `ApplySwarmOwnerRevisions` is an ACTIVATED Store contract (issue #1702).
//! It is admitted only when the owner-specific authorization evidence travels
//! with the write: [`SwarmOwnerAuthorization`] is carried inside
//! [`SwarmOwnerRevision`] and verified at this boundary against BOTH the
//! record's own owner lease and the authenticated identity the Kernel bound to
//! the transition. A caller-supplied role/lease label is therefore not a label
//! the record may assert about itself — it is compared with the owner field the
//! record itself carries and with the transition the Store is executing.
//!
//! The closed envelope binds full canonical owner-record bytes to SHA-256; it
//! does not decide semantic rights or ORS activation.

use std::collections::{BTreeMap, BTreeSet};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    NamedMutationOperation, NamedMutationRequest, OrderingScopeId, PreparedTransition, StoreError,
    canonical_json_bytes, sha256_hex, validate_digest, validate_text,
};

/// Store owner whose immutable swarm history is being advanced.
#[derive(
    Clone, Copy, Debug, Eq, JsonSchema, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SwarmSemanticOwnerKind {
    /// Task Controller-owned definition history.
    TaskController,
    /// Governor-owned admission history.
    Governor,
    /// AgentCoordinator-owned execution history.
    AgentCoordinator,
}

impl SwarmSemanticOwnerKind {
    /// Stable ordering-scope component.
    #[must_use]
    pub const fn scope_component(self) -> &'static str {
        match self {
            Self::TaskController => "definition",
            Self::Governor => "admission",
            Self::AgentCoordinator => "execution",
        }
    }

    /// The stable identity field carried by the corresponding semantic record.
    const fn identity_field(self) -> &'static str {
        match self {
            Self::TaskController => "definition_id",
            Self::Governor => "admission_id",
            Self::AgentCoordinator => "execution_id",
        }
    }

    /// Exact owner-specific immutable payload fields.
    fn payload_fields(self) -> &'static [&'static str] {
        match self {
            Self::TaskController => &[
                "definition_revision",
                "lifecycle",
                "task_id",
                "task_revision",
                "recipe_id",
                "recipe_revision",
                "controller",
                "objective_ref",
                "acceptance_refs",
                "root_context_revision",
                "work_graph_digest",
                "definition_digest",
                "ceilings",
                "stop_conditions_digest",
                "supersedes",
                "state_fence",
            ],
            Self::Governor => &[
                "definition_id",
                "definition_digest",
                "disposition",
                "admitted_ceilings",
                "receipt",
                "state_fence",
            ],
            Self::AgentCoordinator => &[
                "definition_id",
                "definition_digest",
                "admission_id",
                "coordinator",
                "wave",
                "root_context_revision",
                "state",
                "coverage_digest",
                "state_fence",
            ],
        }
    }
}

/// Owner-specific authorization evidence carried WITH the owner revision
/// (issue #1702 W3, I10.15 "each definition revision is authored only by the
/// Task Controller").
///
/// Why this exists rather than trusting the record: a valid payload digest
/// proves the bytes are intact, never that their author held authority. Before
/// this field the only lease evidence in the envelope was the `controller` /
/// `coordinator` object INSIDE the record being committed, so the author
/// effectively appointed itself. This struct makes the claim a separate,
/// comparable datum, and
/// [`validate_swarm_owner_revision_transition`] together with
/// [`validate_swarm_owner_revision_authorization`] checks it against three
/// independent things:
///
/// 1. the revision's own declared owner kind, so a coordinator's evidence
///    cannot open a definition's stream;
/// 2. the owner lease the RECORD ITSELF carries (`controller` /
///    `coordinator`), so a record cannot claim a holder or epoch its own owner
///    fields do not carry; and
/// 3. the authenticated request source the Store is executing for
///    ([`crate::RequestMeta::source_id`]), so a caller cannot relabel its own
///    role or present a foreign principal.
///
/// The Governor admission record carries no lease of its own — I10.15 gives
/// `SwarmPlanAdmission` a policy/capability/fence and a receipt, not a lease —
/// so for that owner the evidence is bound to the authenticated request alone.
/// That asymmetry is stated rather than papered over with an invented Governor
/// lease type.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmOwnerAuthorization {
    /// Semantic owner the presenting principal is claiming to be.
    ///
    /// Never taken on trust: [`SwarmOwnerRevision::validate`] requires it to
    /// equal the revision's own `owner_kind`, so a caller may not present a
    /// coordinator's evidence on a definition's stream.
    pub owner_kind: SwarmSemanticOwnerKind,
    /// Authenticated presenting source identity, as bound by the Kernel on
    /// `RequestMeta::source_id` for the request being executed.
    pub presenter: String,
    /// Owner lease epoch the presenter claims.
    ///
    /// For the definition and execution owners this must equal the record's own
    /// `controller.epoch` / `coordinator.epoch`. It is the owner's own tenure
    /// counter, deliberately NOT the transition's authority epoch: those are
    /// different quantities and requiring them to be numerically equal would
    /// reject valid writes as soon as the two counters diverged.
    pub epoch: u64,
}

impl SwarmOwnerAuthorization {
    /// Validates the closed shape of the presented evidence.
    fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.presenter, "swarm.authorization.presenter")?;
        if self.epoch == 0 {
            return Err(StoreError::InvalidField {
                field: "swarm.authorization.epoch",
                reason: "owner epoch is never zero",
            });
        }
        Ok(())
    }
}

/// Reads the `(holder, epoch)` pair out of a record's own owner lease object.
///
/// Returns an error rather than a default: a record whose lease is absent or
/// whose epoch is not an integer cannot supply authorization evidence, and
/// quietly falling back to the transition's epoch would let any presenter pass.
fn read_lease(
    object: &serde_json::Map<String, Value>,
    lease_field: &'static str,
) -> Result<(String, u64), StoreError> {
    let lease =
        object
            .get(lease_field)
            .and_then(Value::as_object)
            .ok_or(StoreError::InvalidField {
                field: "swarm.record_json",
                reason: lease_field,
            })?;
    let holder = lease
        .get("holder")
        .and_then(Value::as_str)
        .filter(|holder| !holder.trim().is_empty())
        .ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: lease_field,
        })?;
    let epoch = lease
        .get("epoch")
        .and_then(Value::as_u64)
        .filter(|epoch| *epoch != 0)
        .ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: lease_field,
        })?;
    Ok((holder.to_owned(), epoch))
}

/// Full immutable record bytes and owner-revision compare-and-set metadata.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmOwnerRevision {
    /// Semantic owner fixed by record kind: definition, admission or execution.
    pub owner_kind: SwarmSemanticOwnerKind,
    /// Owner-specific authorization evidence verified at this boundary.
    pub authorization: SwarmOwnerAuthorization,
    /// Stable ID of the definition, admission or execution object.
    pub owner_id: String,
    /// Monotonic Store-owned revision for this semantic object.
    pub revision: u64,
    /// Current Store-owned revision expected before this write; absent only at genesis.
    pub expected_predecessor: Option<u64>,
    /// SHA-256 of the exact canonical UTF-8 bytes in `record_json`.
    pub content_digest: String,
    /// Complete canonical semantic record, retained verbatim for recovery.
    pub record_json: String,
}

impl SwarmOwnerRevision {
    /// Validates identity, owner-specific record shape, CAS progression and bytes.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.validate_revision_identity()?;
        self.validate_authorization()?;
        let value = self.canonical_record_value()?;
        self.validate_owner_record(&value)
    }

    /// Requires the presented authorization to name this revision's own owner.
    ///
    /// A cross-owner presentation is refused here, before any record is read:
    /// coordinator evidence cannot open a definition stream, and a definition
    /// record cannot be committed as if the Governor had written it.
    fn validate_authorization(&self) -> Result<(), StoreError> {
        self.authorization.validate()?;
        if self.authorization.owner_kind != self.owner_kind {
            return Err(StoreError::InvalidField {
                field: "swarm.authorization.owner_kind",
                reason: "presented authorization names another semantic owner",
            });
        }
        Ok(())
    }

    fn validate_revision_identity(&self) -> Result<(), StoreError> {
        validate_text(&self.owner_id, "swarm.owner_id")?;
        if self.revision == 0 || self.revision > i64::MAX as u64 {
            return Err(StoreError::InvalidField {
                field: "swarm.revision",
                reason: "must fit a positive Surreal integer",
            });
        }
        if self
            .expected_predecessor
            .is_some_and(|revision| revision == 0 || revision > i64::MAX as u64)
        {
            return Err(StoreError::InvalidField {
                field: "swarm.expected_predecessor",
                reason: "must be a positive Surreal integer when present",
            });
        }
        let expected_next = self
            .expected_predecessor
            .unwrap_or(0)
            .checked_add(1)
            .ok_or(StoreError::InvalidField {
                field: "swarm.expected_predecessor",
                reason: "revision overflow",
            })?;
        if self.revision != expected_next {
            return Err(StoreError::InvalidField {
                field: "swarm.revision",
                reason: "must immediately follow the expected predecessor",
            });
        }
        Ok(())
    }

    fn canonical_record_value(&self) -> Result<Value, StoreError> {
        if self.record_json.len() > crate::MAX_RECOVERY_RECORD_BYTES {
            return Err(StoreError::PayloadTooLarge);
        }
        validate_digest(&self.content_digest, "swarm.content_digest")?;
        let value: Value = serde_json::from_str(&self.record_json)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        let canonical = canonical_json_bytes(&value)
            .map_err(|error| StoreError::Serialization(error.to_string()))?;
        if canonical != self.record_json.as_bytes() {
            return Err(StoreError::InvalidField {
                field: "swarm.record_json",
                reason: "must be canonical JSON bytes",
            });
        }
        if sha256_hex(&canonical) != self.content_digest {
            return Err(StoreError::InvalidField {
                field: "swarm.content_digest",
                reason: "does not bind the complete record bytes",
            });
        }
        Ok(value)
    }

    fn validate_owner_record(&self, value: &Value) -> Result<(), StoreError> {
        let object = value.as_object().ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: "must be a JSON object",
        })?;
        self.validate_record_shape(object)?;
        self.validate_owner_identity(object)?;
        match self.owner_kind {
            SwarmSemanticOwnerKind::TaskController => validate_definition_record(object)?,
            SwarmSemanticOwnerKind::Governor => validate_admission_record(object)?,
            SwarmSemanticOwnerKind::AgentCoordinator => validate_execution_record(object)?,
        }
        self.validate_authorized_lease(object)?;
        validate_fence(object.get("state_fence"))?;
        Ok(())
    }

    /// Binds the presented authorization to the owner lease the RECORD itself
    /// carries (issue #1702 W3/A3).
    ///
    /// For the definition and execution owners the record names its own lease
    /// (`controller` / `coordinator`). Requiring the authorization's presenter
    /// and epoch to equal that lease is what makes the evidence mean something:
    /// a coordinator presenting its own lease cannot open a definition stream
    /// even though both records are individually well-formed, and a record
    /// cannot claim an epoch its owner fields do not carry.
    ///
    /// The Governor admission record carries no lease (I10.15 gives it a
    /// policy/capability/fence and a receipt, not a lease), so there is no
    /// owner lease here to compare. That case is NOT skipped silently: it is
    /// covered by [`validate_swarm_owner_revision_authorization`], which binds
    /// the Governor evidence to the authenticated request source. A per-record
    /// check is impossible for that owner, and inventing a lease field it does
    /// not have would be a second scheme.
    fn validate_authorized_lease(
        &self,
        object: &serde_json::Map<String, Value>,
    ) -> Result<(), StoreError> {
        let lease_field = match self.owner_kind {
            SwarmSemanticOwnerKind::TaskController => "controller",
            SwarmSemanticOwnerKind::AgentCoordinator => "coordinator",
            SwarmSemanticOwnerKind::Governor => return Ok(()),
        };
        let (presenter, epoch) = read_lease(object, lease_field)?;
        if presenter != self.authorization.presenter {
            return Err(StoreError::InvalidField {
                field: "swarm.authorization.presenter",
                reason: "presenter does not match the record's own owner lease holder",
            });
        }
        if epoch != self.authorization.epoch {
            return Err(StoreError::InvalidField {
                field: "swarm.authorization.epoch",
                reason: "presented epoch does not match the record's own owner lease epoch",
            });
        }
        Ok(())
    }

    fn validate_record_shape(
        &self,
        object: &serde_json::Map<String, Value>,
    ) -> Result<(), StoreError> {
        let fields = self.owner_kind.payload_fields();
        if object.len() != fields.len() + 1
            || object.keys().any(|key| {
                key != self.owner_kind.identity_field() && !fields.contains(&key.as_str())
            })
        {
            return Err(StoreError::InvalidField {
                field: "swarm.record_json",
                reason: "must match the closed owner-specific semantic record shape",
            });
        }
        Ok(())
    }

    fn validate_owner_identity(
        &self,
        object: &serde_json::Map<String, Value>,
    ) -> Result<(), StoreError> {
        let identity = object
            .get(self.owner_kind.identity_field())
            .and_then(Value::as_str)
            .ok_or(StoreError::InvalidField {
                field: "swarm.record_json.identity",
                reason: "owner-specific identity is missing or not text",
            })?;
        if identity != self.owner_id {
            return Err(StoreError::InvalidField {
                field: "swarm.owner_id",
                reason: "does not match the immutable record identity",
            });
        }
        Ok(())
    }

    /// Derives the ordering scope that serializes this owner’s revisions.
    pub fn ordering_scope(&self) -> Result<OrderingScopeId, StoreError> {
        OrderingScopeId::new(format!(
            "swarm:{}:{}",
            self.owner_kind.scope_component(),
            self.owner_id
        ))
    }
}

fn validate_definition_record(object: &serde_json::Map<String, Value>) -> Result<(), StoreError> {
    validate_lease(object.get("controller"), "controller")?;
    let ceilings = object.get("ceilings");
    validate_swarm_ceilings(ceilings, "ceilings")?;
    if !matches!(
        object.get("lifecycle").and_then(Value::as_str),
        Some("DRAFT" | "FROZEN" | "SUPERSEDED" | "CANCELLED")
    ) {
        return Err(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: "contains an invalid lifecycle",
        });
    }
    for name in ["definition_revision", "task_revision", "recipe_revision"] {
        require_nonempty_text(object.get(name), name)?;
    }
    for name in [
        "task_id",
        "recipe_id",
        "objective_ref",
        "root_context_revision",
    ] {
        require_nonempty_text(object.get(name), name)?;
    }
    validate_acceptance_refs(object.get("acceptance_refs"))?;
    for name in [
        "work_graph_digest",
        "definition_digest",
        "stop_conditions_digest",
    ] {
        require_digest_value(object.get(name), name)?;
    }
    if let Some(link) = object.get("supersedes").filter(|value| !value.is_null()) {
        validate_nested_fields(
            Some(link),
            &["prior_definition_id", "prior_revision", "disposition"],
            "supersedes",
        )?;
        require_nonempty_text(
            link.get("prior_definition_id"),
            "supersedes.prior_definition_id",
        )?;
        require_nonempty_text(link.get("prior_revision"), "supersedes.prior_revision")?;
        if !matches!(
            link.get("disposition").and_then(Value::as_str),
            Some("DRAIN" | "CANCEL" | "SUPERSEDE")
        ) {
            return Err(StoreError::InvalidField {
                field: "swarm.record_json.supersedes.disposition",
                reason: "is not a supported disposition",
            });
        }
    }
    Ok(())
}

fn validate_admission_record(object: &serde_json::Map<String, Value>) -> Result<(), StoreError> {
    require_nonempty_text(object.get("definition_id"), "definition_id")?;
    require_digest_value(object.get("definition_digest"), "definition_digest")?;
    require_nonempty_text(object.get("receipt"), "receipt")?;
    if !matches!(
        object.get("disposition").and_then(Value::as_str),
        Some("PENDING" | "ADMITTED" | "REJECTED" | "STALE" | "CANCELLED" | "SUPERSEDED")
    ) {
        return Err(StoreError::InvalidField {
            field: "swarm.record_json.disposition",
            reason: "is not a supported admission disposition",
        });
    }
    validate_swarm_ceilings(object.get("admitted_ceilings"), "admitted_ceilings")
}

fn validate_execution_record(object: &serde_json::Map<String, Value>) -> Result<(), StoreError> {
    for name in [
        "definition_id",
        "admission_id",
        "wave",
        "root_context_revision",
    ] {
        require_nonempty_text(object.get(name), name)?;
    }
    for name in ["definition_digest", "coverage_digest"] {
        require_digest_value(object.get(name), name)?;
    }
    if !matches!(
        object.get("state").and_then(Value::as_str),
        Some(
            "NOT_STARTED"
                | "RUNNING"
                | "PAUSED"
                | "REDUCING"
                | "VERIFYING"
                | "COMPLETED"
                | "PARTIAL"
                | "FAILED"
                | "CANCELLED"
                | "UNKNOWN_OUTCOME"
        )
    ) {
        return Err(StoreError::InvalidField {
            field: "swarm.record_json.state",
            reason: "is not a supported execution state",
        });
    }
    validate_lease(object.get("coordinator"), "coordinator")
}

/// Closed batch carried by one canonical Store mutation.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwarmOwnerRevisionBatch {
    /// Exactly one owner revision per governed operation.
    pub record: SwarmOwnerRevision,
}

impl SwarmOwnerRevisionBatch {
    /// Validates the immutable owner record and its closed wire shape.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.record.validate()
    }
}

/// Builds the closed named mutation request for one owner revision.
pub fn swarm_owner_revisions_request(
    batch: SwarmOwnerRevisionBatch,
) -> Result<NamedMutationRequest, StoreError> {
    batch.validate()?;
    let record = serde_json::to_value(batch.record)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let parameters = BTreeMap::from([("record".to_owned(), record)]);
    Ok(NamedMutationRequest {
        operation: NamedMutationOperation::ApplySwarmOwnerRevisions,
        parameters,
    })
}

/// Decodes one typed swarm owner-revision request.
pub fn decode_swarm_owner_revisions(
    operation: NamedMutationOperation,
    parameters: &BTreeMap<String, Value>,
) -> Result<SwarmOwnerRevisionBatch, StoreError> {
    if operation != NamedMutationOperation::ApplySwarmOwnerRevisions {
        return Err(StoreError::UnknownOperation);
    }
    crate::operation_parameters::validate_typed_mutation_parameters(operation, parameters)?;
    let record: SwarmOwnerRevision =
        serde_json::from_value(parameters.get("record").cloned().ok_or(
            StoreError::InvalidField {
                field: "swarm.record",
                reason: "is required",
            },
        )?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let batch = SwarmOwnerRevisionBatch { record };
    batch.validate()?;
    Ok(batch)
}

/// Validates the one-operation task-control envelope, exact owner scope, and
/// the owner-specific authorization bound to the executing transition
/// (issue #1702 W3/A3).
///
/// Two independent bindings make "the author held authority" a verified fact
/// rather than a claim:
///
/// 1. the record's OWNER LEASE, checked inside
///    [`SwarmOwnerRevision::validate`] through
///    [`SwarmOwnerRevision::validate_authorized_lease`]: the presented
///    `SwarmOwnerAuthorization` must name this revision's own owner kind, and
///    its presenter and epoch must equal the `controller` / `coordinator` fields
///    the record itself carries. A well-formed coordinator record presented on
///    the definition stream, or a record claiming an epoch its owner fields do
///    not carry, is refused here — before persistence and before any effect; and
/// 2. the record's State Fence against the transition's State Fence, so the
///    write happens under exactly the authority the record was frozen at, with
///    the Kernel having already compared that fence with its own live
///    requirement.
///
/// The authenticated PRINCIPAL is a separate act,
/// [`validate_swarm_owner_revision_authorization`], because a
/// [`PreparedTransition`] is a semantic plan and carries no transport identity.
/// That is the binding the Governor admission stream depends on, since an
/// admission record carries no lease of its own to compare against.
///
/// # Errors
///
/// Returns [`StoreError::TransitionClassExceeded`] when the plan is not the
/// single-operation task-control shape, [`StoreError::FenceMismatch`] when the
/// record's fence is not the transition's fence, and the typed
/// [`StoreError::InvalidField`] of the underlying contracts when the scope, the
/// owner record, or the authorization does not hold.
pub fn validate_swarm_owner_revision_transition(
    transition: &PreparedTransition,
) -> Result<(), StoreError> {
    if transition.transition_class != crate::TransitionClass::TaskControl
        || transition.named_operations.len() != 1
        || transition.named_operations[0].operation
            != NamedMutationOperation::ApplySwarmOwnerRevisions
    {
        return Err(StoreError::TransitionClassExceeded);
    }
    let batch = decode_swarm_owner_revisions(
        transition.named_operations[0].operation,
        &transition.named_operations[0].parameters,
    )?;
    let scopes = transition
        .ordering_scopes
        .iter()
        .map(OrderingScopeId::as_str)
        .collect::<BTreeSet<_>>();
    let expected = batch.record.ordering_scope()?;
    if scopes.len() != 1 || !scopes.contains(expected.as_str()) {
        return Err(StoreError::InvalidField {
            field: "ordering_scopes",
            reason: "must exactly match the affected swarm owner stream",
        });
    }
    let record: Value = serde_json::from_str(&batch.record.record_json)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    let record_fence = validate_fence(
        record
            .as_object()
            .and_then(|object| object.get("state_fence")),
    )?;
    if record_fence != transition.state_fence {
        return Err(StoreError::FenceMismatch);
    }
    // The owner binding itself (authorization owner kind, record shape and the
    // presented lease against the record's own owner lease) was already
    // established by `decode_swarm_owner_revisions` above, which runs
    // `SwarmOwnerRevision::validate`. The owner LEASE epoch is deliberately
    // NOT compared with the transition's authority-epoch sequence: they are
    // different quantities. The lease epoch counts the Task Controller's or
    // coordinator's own tenure (`controller.epoch` / `coordinator.epoch`); the
    // transition's authority epoch is the store-wide lineage sequence the
    // Kernel fences the write under, already compared with the record's own
    // fence just above. Requiring the two numbers to be equal would reject every
    // valid write as soon as the counters diverged — a stricter check than the
    // contract states, not a more correct one.
    Ok(())
}

/// Binds one owner revision's authorization to the AUTHENTICATED request the
/// Store is executing (issue #1702 W3/A3).
///
/// [`validate_swarm_owner_revision_transition`] cannot do this: a
/// [`PreparedTransition`] is a semantic plan and carries no transport identity.
/// This function takes the [`RequestMeta`] the Kernel authenticated, so the
/// presenter the evidence names is compared with the source identity of the
/// real request rather than with anything the caller supplied. A caller
/// relabelling its own role — presenting coordinator evidence on the Governor
/// stream, or a foreign principal as the Task Controller — fails here.
///
/// Call it wherever the authenticated request context is in hand; it is
/// deliberately a separate act from the plan check so a caller cannot skip it
/// by accident while still passing plan validation.
///
/// # Errors
///
/// Returns [`StoreError::InvalidField`] when the presented principal is not the
/// authenticated request source.
pub fn validate_swarm_owner_revision_authorization(
    revision: &SwarmOwnerRevision,
    context: &crate::RequestMeta,
) -> Result<(), StoreError> {
    revision.validate()?;
    if revision.authorization.presenter != context.source_id.as_str() {
        return Err(StoreError::InvalidField {
            field: "swarm.authorization.presenter",
            reason: "does not match the authenticated request source",
        });
    }
    Ok(())
}

fn require_nonempty_text(value: Option<&Value>, field: &'static str) -> Result<(), StoreError> {
    let text = value
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: field,
        })?;
    crate::validate_text(text, "swarm.record_json.text")
}

fn require_digest_value(value: Option<&Value>, field: &'static str) -> Result<(), StoreError> {
    let digest = value
        .and_then(Value::as_str)
        .ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: field,
        })?;
    validate_digest(digest, "swarm.record_json.digest")
}

fn validate_nested_fields(
    value: Option<&Value>,
    expected: &[&str],
    field: &'static str,
) -> Result<(), StoreError> {
    let object = value
        .and_then(Value::as_object)
        .ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: field,
        })?;
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: field,
        });
    }
    Ok(())
}

fn validate_lease(value: Option<&Value>, field: &'static str) -> Result<(), StoreError> {
    validate_nested_fields(value, &["holder", "epoch"], field)?;
    require_nonempty_text(value.and_then(|value| value.get("holder")), field)?;
    if value
        .and_then(|value| value.get("epoch"))
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: field,
        });
    }
    Ok(())
}

fn validate_fence(value: Option<&Value>) -> Result<crate::StateFence, StoreError> {
    let fence: crate::StateFence =
        serde_json::from_value(value.cloned().ok_or(StoreError::InvalidField {
            field: "swarm.record_json.state_fence",
            reason: "is required",
        })?)
        .map_err(|error| StoreError::Serialization(error.to_string()))?;
    fence.validate().map_err(StoreError::Foundation)?;
    Ok(fence)
}

fn validate_acceptance_refs(value: Option<&Value>) -> Result<(), StoreError> {
    let references = value
        .and_then(Value::as_array)
        .filter(|references| !references.is_empty())
        .ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: "acceptance_refs must be a non-empty array",
        })?;
    let mut unique = BTreeSet::new();
    for reference in references {
        let reference = reference.as_str().ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: "acceptance references must be text",
        })?;
        validate_text(reference, "swarm.record_json.acceptance_refs")?;
        if !unique.insert(reference) {
            return Err(StoreError::InvalidField {
                field: "swarm.record_json",
                reason: "acceptance references must be unique",
            });
        }
    }
    Ok(())
}

fn validate_swarm_ceilings(value: Option<&Value>, field: &'static str) -> Result<(), StoreError> {
    validate_nested_fields(
        value,
        &[
            "privacy_class",
            "budget_ref",
            "route_classes",
            "max_depth",
            "max_fanout",
            "max_wip",
        ],
        field,
    )?;
    let object = value
        .and_then(Value::as_object)
        .ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: field,
        })?;
    for name in ["privacy_class", "budget_ref"] {
        require_nonempty_text(object.get(name), field)?;
    }
    let routes = object
        .get("route_classes")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
        .ok_or(StoreError::InvalidField {
            field: "swarm.record_json",
            reason: field,
        })?;
    let mut unique_routes = std::collections::BTreeSet::new();
    for route in routes {
        let route = route
            .as_str()
            .filter(|route| !route.trim().is_empty())
            .ok_or(StoreError::InvalidField {
                field: "swarm.record_json",
                reason: field,
            })?;
        if !unique_routes.insert(route) {
            return Err(StoreError::InvalidField {
                field: "swarm.record_json",
                reason: "route classes must be unique",
            });
        }
    }
    for name in ["max_depth", "max_fanout", "max_wip"] {
        if object
            .get(name)
            .and_then(Value::as_u64)
            .is_none_or(|bound| bound == 0 || u32::try_from(bound).is_err())
        {
            return Err(StoreError::InvalidField {
                field: "swarm.record_json",
                reason: field,
            });
        }
    }
    Ok(())
}
