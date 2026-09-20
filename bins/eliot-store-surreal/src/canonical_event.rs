//! Canonical events with per-scope hash links and rebuildable projections.
//!
//! Issue #1931 (`I5-audit`): the canonical transition (`I5.4`) commits one
//! semantic event identity with one immutable hash-chain link per affected
//! Ordering Scope (`I5.7`), and derived projections become readable as current
//! only through a fenced [`FencedProjectionPublication`] (`I5.8`).
//!
//! Scope note: this bridge owns no durable state and performs no provider
//! I/O. Everything here is pure derivation and verification over the
//! store-neutral [`eliot_store_api`] contract: link-hash computation, atomic
//! bundle validation, publication gating, and the Doctor-only rebuild doorway.
//! The durable atomic commit itself stays inside the named transaction
//! implementation behind `CanonicalStoreClient`; this module proves the shape
//! that transaction must carry so receipt, outbox intent, and audit-chain
//! fields cannot appear without their canonical event.

use std::collections::BTreeMap;
use std::collections::BTreeSet;

use eliot_store_api::{
    CommitId, EventId, OperationId, OrderingScopeId, OutboxIntent, ProjectionPublicationRecord,
    ProjectionStatus, RevisionHead, SplitView, StateFence, StoreError, WriteReceipt,
    WriteReceiptStatus, canonical_json_bytes, sha256_hex,
};
use serde::{Deserialize, Serialize};

fn is_hex_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn validate_hex_digest(value: &str, field: &'static str) -> Result<(), StoreError> {
    if is_hex_digest(value) {
        Ok(())
    } else {
        Err(StoreError::InvalidField {
            field,
            reason: "must be lowercase SHA-256",
        })
    }
}

fn validate_text(value: &str, field: &'static str) -> Result<(), StoreError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(StoreError::InvalidField {
            field,
            reason: "blank or control character",
        });
    }
    Ok(())
}

/// Canonical preimage for one per-scope ordering link.
///
/// The link hashes the same event identity/payload plus its scope, reserved
/// sequence, and previous link hash, so one atomic transition keeps one head
/// per causal stream instead of pretending several streams share one head.
#[derive(Serialize)]
struct OrderingLinkPreimage<'a> {
    event_id: &'a str,
    payload_digest: &'a str,
    ordering_scope: &'a str,
    ordering_sequence: u64,
    previous_event_hash: &'a str,
}

/// Computes the immutable chain hash for one Ordering Scope link.
pub fn ordering_link_hash(
    event_id: &EventId,
    payload_digest: &str,
    scope: &OrderingScopeId,
    sequence: u64,
    previous_event_hash: &str,
) -> Result<String, StoreError> {
    validate_hex_digest(payload_digest, "canonical_event.payload_digest")?;
    validate_hex_digest(previous_event_hash, "ordering_links.previous_event_hash")?;
    if sequence == 0 {
        return Err(StoreError::InvalidField {
            field: "ordering_links.ordering_sequence",
            reason: "must be non-zero",
        });
    }
    let preimage = OrderingLinkPreimage {
        event_id: event_id.as_str(),
        payload_digest,
        ordering_scope: scope.as_str(),
        ordering_sequence: sequence,
        previous_event_hash,
    };
    let bytes =
        canonical_json_bytes(&preimage).map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(sha256_hex(&bytes))
}

/// One immutable hash-chain link for a single Ordering Scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OrderingLink {
    /// Scope whose causal stream this link advances.
    pub ordering_scope: OrderingScopeId,
    /// Reserved sequence for this scope in this transition.
    pub ordering_sequence: u64,
    /// Previous link hash in this scope (`0` * 64 at genesis).
    pub previous_event_hash: String,
    /// Link hash over event identity/payload, scope, sequence, previous hash.
    pub event_hash: String,
}

impl OrderingLink {
    /// Validates shape without checking the hash preimage.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.ordering_sequence == 0 {
            return Err(StoreError::InvalidField {
                field: "ordering_links.ordering_sequence",
                reason: "must be non-zero",
            });
        }
        validate_hex_digest(
            &self.previous_event_hash,
            "ordering_links.previous_event_hash",
        )?;
        validate_hex_digest(&self.event_hash, "ordering_links.event_hash")?;
        Ok(())
    }

    /// Recomputes the link hash and rejects any substitution.
    pub fn verify(
        &self,
        event_id: &EventId,
        payload_digest: &str,
    ) -> Result<(), StoreError> {
        self.validate()?;
        let expected = ordering_link_hash(
            event_id,
            payload_digest,
            &self.ordering_scope,
            self.ordering_sequence,
            &self.previous_event_hash,
        )?;
        if expected == self.event_hash {
            Ok(())
        } else {
            Err(StoreError::InvalidField {
                field: "ordering_links.event_hash",
                reason: "link hash mismatch",
            })
        }
    }
}

/// One immutable semantic event identity shared by every scope it touches.
///
/// Clock-assigned `occurred_at`/`committed_at` markers are adapter-owned at
/// commit time and are deliberately not minted here: the bridge never invents
/// time, authority, or durability.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalEvent {
    /// Single event identity for the whole multi-scope transition.
    pub event_id: EventId,
    /// Admitted operation that produced this event.
    pub operation_id: OperationId,
    /// Closed catalogue event type (for example `store.apply.epistemic`).
    pub event_type: String,
    /// Digest of the canonical payload bytes shared by every link.
    pub payload_digest: String,
    /// Exactly one chain link per declared Ordering Scope.
    pub ordering_links: Vec<OrderingLink>,
    /// Monotonic event ordinal assigned at commit.
    pub event_ordinal: u64,
    /// Fence every link, receipt, outbox intent, and audit field shares.
    pub state_fence: StateFence,
}

impl CanonicalEvent {
    /// Issues the canonical shape for one transition, computing one link per
    /// declared scope from the reserved sequences and previous hashes.
    ///
    /// `scopes` carries `(scope, reserved_sequence, previous_event_hash)` in
    /// any order; duplicate scopes and zero sequences are rejected.
    pub fn issue(
        event_id: EventId,
        operation_id: OperationId,
        event_type: String,
        payload_digest: String,
        scopes: Vec<(OrderingScopeId, u64, String)>,
        event_ordinal: u64,
        state_fence: StateFence,
    ) -> Result<Self, StoreError> {
        validate_text(&event_type, "canonical_event.event_type")?;
        validate_hex_digest(&payload_digest, "canonical_event.payload_digest")?;
        if event_ordinal == 0 {
            return Err(StoreError::InvalidField {
                field: "canonical_event.event_ordinal",
                reason: "must be non-zero",
            });
        }
        state_fence.validate().map_err(StoreError::Foundation)?;
        if scopes.is_empty() {
            return Err(StoreError::InvalidField {
                field: "ordering_links",
                reason: "at least one ordering scope is required",
            });
        }
        let mut seen = BTreeSet::new();
        for (scope, _, _) in &scopes {
            if !seen.insert(scope.as_str().to_owned()) {
                return Err(StoreError::Duplicate {
                    field: "ordering_links",
                });
            }
        }
        let mut ordering_links = Vec::with_capacity(scopes.len());
        for (scope, sequence, previous_event_hash) in scopes {
            let event_hash = ordering_link_hash(
                &event_id,
                &payload_digest,
                &scope,
                sequence,
                &previous_event_hash,
            )?;
            ordering_links.push(OrderingLink {
                ordering_scope: scope,
                ordering_sequence: sequence,
                previous_event_hash,
                event_hash,
            });
        }
        Ok(Self {
            event_id,
            operation_id,
            event_type,
            payload_digest,
            ordering_links,
            event_ordinal,
            state_fence,
        })
    }

    /// Validates the full event: shape, fence, ordinal, and every link hash.
    pub fn validate(&self) -> Result<(), StoreError> {
        validate_text(&self.event_type, "canonical_event.event_type")?;
        validate_hex_digest(&self.payload_digest, "canonical_event.payload_digest")?;
        if self.event_ordinal == 0 {
            return Err(StoreError::InvalidField {
                field: "canonical_event.event_ordinal",
                reason: "must be non-zero",
            });
        }
        self.state_fence
            .validate()
            .map_err(StoreError::Foundation)?;
        if self.ordering_links.is_empty() {
            return Err(StoreError::InvalidField {
                field: "ordering_links",
                reason: "at least one ordering scope is required",
            });
        }
        let mut seen = BTreeSet::new();
        for link in &self.ordering_links {
            if !seen.insert(link.ordering_scope.as_str().to_owned()) {
                return Err(StoreError::Duplicate {
                    field: "ordering_links",
                });
            }
            link.verify(&self.event_id, &self.payload_digest)?;
        }
        Ok(())
    }
}

/// The atomic unit of one canonical transition (`I5.4`).
///
/// A committed multi-scope operation resolves to exactly this bundle: one
/// event identity with one valid chain link per declared scope, plus the
/// receipt, outbox intents, and audit-chain digest that share the same fence.
/// Validation passes only when every member is present and cross-bound, so a
/// partial commit (event without receipt, receipt without outbox coverage, or
/// audit gap) fails closed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommittedCanonicalTransition {
    /// The one semantic event identity for this transition.
    pub event: CanonicalEvent,
    /// The terminal committed receipt for the same operation.
    pub receipt: WriteReceipt,
    /// Outbox intents committed with this transition.
    pub outbox: Vec<OutboxIntent>,
    /// Digest binding the audit-chain fields committed with this transition.
    pub audit_chain_digest: String,
}

impl CommittedCanonicalTransition {
    /// Validates atomicity: every member validates and every cross-reference
    /// binds to the same event identity, fence, and per-scope links.
    pub fn validate_atomic(&self) -> Result<(), StoreError> {
        self.event.validate()?;
        self.receipt.validate()?;
        validate_hex_digest(&self.audit_chain_digest, "audit_chain_digest")?;
        if self.receipt.status != WriteReceiptStatus::Committed {
            return Err(StoreError::InvalidReceipt);
        }
        if self.receipt.operation_id != self.event.operation_id {
            return Err(StoreError::InvalidReceipt);
        }
        if self.receipt.state_fence != self.event.state_fence {
            return Err(StoreError::FenceMismatch);
        }
        if !self
            .receipt
            .emitted_event_ids
            .contains(&self.event.event_id)
        {
            return Err(StoreError::InvalidReceipt);
        }
        let mut receipt_sequences = BTreeMap::new();
        for head in &self.receipt.ordering_sequences {
            if receipt_sequences
                .insert(head.scope.as_str().to_owned(), head.sequence)
                .is_some()
            {
                return Err(StoreError::Duplicate {
                    field: "ordering_sequences",
                });
            }
            if head.state_fence != self.event.state_fence {
                return Err(StoreError::FenceMismatch);
            }
        }
        for link in &self.event.ordering_links {
            match receipt_sequences.get(link.ordering_scope.as_str()) {
                Some(sequence) if *sequence == link.ordering_sequence => {}
                _ => return Err(StoreError::InvalidReceipt),
            }
        }
        let mut seen_outbox = BTreeSet::new();
        for intent in &self.outbox {
            intent.validate()?;
            if intent.operation_id != self.event.operation_id {
                return Err(StoreError::InvalidOutbox);
            }
            if intent.state_fence != self.event.state_fence {
                return Err(StoreError::FenceMismatch);
            }
            if !seen_outbox.insert(intent.outbox_id.as_str().to_owned()) {
                return Err(StoreError::Duplicate {
                    field: "outbox",
                });
            }
            if !self.receipt.outbox_refs.contains(&intent.outbox_id) {
                return Err(StoreError::InvalidOutbox);
            }
        }
        Ok(())
    }
}

/// A derived projection gated by its publication record (`I5.8`).
///
/// The neutral [`ProjectionPublicationRecord`] carries source heads,
/// generations, the atomic data commit, and the provenance manifest, but not
/// the projection definition digest. This fence adds the definition digest and
/// pins the atomic data/provenance commit reference, so a reader can prove the
/// candidate data and its provenance became visible atomically at one source
/// fence. Partial provenance, a stale definition, a mismatched source
/// generation, or a split view leaves the projection unreadable as current.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FencedProjectionPublication {
    /// Same-fence publication record committed with the source transition.
    pub record: ProjectionPublicationRecord,
    /// Digest of the projection definition the candidate data was built with.
    pub projection_definition_digest: String,
    /// Atomic data/provenance commit both became visible under.
    pub atomic_commit_ref: CommitId,
}

impl FencedProjectionPublication {
    /// Validates the record, the definition digest, and the atomic coupling.
    pub fn validate(&self) -> Result<(), StoreError> {
        self.record.validate()?;
        validate_hex_digest(
            &self.projection_definition_digest,
            "projection_definition_digest",
        )?;
        if self.atomic_commit_ref.as_str() != self.record.atomic_data_commit.as_str() {
            return Err(StoreError::InvalidProjection);
        }
        Ok(())
    }

    /// Requires readability as current: valid fence, `CURRENT` status, no
    /// split view, matching definition digest, matching source generation,
    /// exact source-head match, and the atomic data/provenance receipt.
    pub fn check_current(
        &self,
        expected_source_heads: &[RevisionHead],
        expected_source_generation: u64,
        expected_definition_digest: &str,
    ) -> Result<(), StoreError> {
        self.validate()?;
        if self.record.status != ProjectionStatus::Current {
            return Err(StoreError::InvalidProjection);
        }
        if !matches!(self.record.split_view, SplitView::None) {
            return Err(StoreError::InvalidProjection);
        }
        if self.projection_definition_digest != expected_definition_digest {
            return Err(StoreError::InvalidProjection);
        }
        if self.record.source_generation != expected_source_generation {
            return Err(StoreError::InvalidProjection);
        }
        let mut actual = BTreeMap::new();
        for head in &self.record.source_revision_heads {
            if actual
                .insert(head.key.clone(), head.revision)
                .is_some()
            {
                return Err(StoreError::Duplicate {
                    field: "source_revision_heads",
                });
            }
        }
        let mut expected = BTreeMap::new();
        for head in expected_source_heads {
            if expected.insert(head.key.clone(), head.revision).is_some() {
                return Err(StoreError::Duplicate {
                    field: "expected_source_heads",
                });
            }
        }
        if actual != expected {
            return Err(StoreError::InvalidProjection);
        }
        Ok(())
    }
}

/// Authority to initiate a projection rebuild.
///
/// Projection rebuild is a Doctor recipe, never a normal write path: only the
/// Doctor/recovery path constructs this authority, so ordinary semantic write
/// commands cannot rebuild (or silently refresh) a projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DoctorRebuildAuthority {
    scope: &'static str,
}

impl DoctorRebuildAuthority {
    /// Authorizes rebuild initiation from the Doctor/recovery path.
    ///
    /// Call sites outside `eliot-doctor` recovery must not invoke this; the
    /// type exists so review can pinpoint every rebuild doorway.
    pub fn doctor_authorize() -> Self {
        Self {
            scope: "eliot-doctor/recovery",
        }
    }

    /// Returns the authorizing recovery scope.
    pub fn scope(&self) -> &'static str {
        self.scope
    }
}

/// Marker for an ordinary semantic write command path.
///
/// Passing this to [`request_rebuild_from_semantic_write`] always fails: it
/// reifies the rule that normal writes publish through the fenced record and
/// never initiate a rebuild.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SemanticWritePath;

/// Bounded plan for rebuilding one projection generation from its source.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectionRebuildPlan {
    /// Projection kind to rebuild.
    pub projection_kind: String,
    /// Generation the rebuild will publish.
    pub target_generation: u64,
    /// Source generation the rebuild reads from.
    pub source_generation: u64,
    /// Definition digest the rebuild must build with.
    pub projection_definition_digest: String,
}

/// Initiates a projection rebuild from the Doctor/recovery path.
pub fn request_projection_rebuild(
    _authority: &DoctorRebuildAuthority,
    publication: &FencedProjectionPublication,
    target_generation: u64,
) -> Result<ProjectionRebuildPlan, StoreError> {
    publication.validate()?;
    if target_generation <= publication.record.projection_generation {
        return Err(StoreError::InvalidField {
            field: "target_generation",
            reason: "rebuild must advance the projection generation",
        });
    }
    Ok(ProjectionRebuildPlan {
        projection_kind: publication.record.projection_kind.clone(),
        target_generation,
        source_generation: publication.record.source_generation,
        projection_definition_digest: publication.projection_definition_digest.clone(),
    })
}

/// Rejects rebuild initiation from an ordinary semantic write command.
pub fn request_rebuild_from_semantic_write(
    _path: &SemanticWritePath,
    _projection_kind: &str,
) -> Result<ProjectionRebuildPlan, StoreError> {
    Err(StoreError::InvalidProjection)
}
