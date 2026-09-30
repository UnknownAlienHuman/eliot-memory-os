//! Governor-derived expiry, damage-gap, and retention-release records (issue #1694 W7).
//!
//! When the evaluator is unavailable, an admitted trigger outlives its
//! applicability window or meets damage the intake path cannot repair. The
//! Kernel delivery ledger owns the terminal/gap/compact transitions
//! (`MaintenanceTriggerDeliveryLedger::apply_expiry`,
//! `apply_supersession`, `record_gap`, `compact`) and the authenticated
//! gateway session that authorizes them; the provider-neutral wire family
//! owns the record shapes. Neither owner can derive Governor-side content:
//! only the intake derivation knows the exact trigger identity, the
//! source-attested operation hash, the derivation-local payload binding, the
//! preserved source/evidence references, and whether a successor revision is
//! a live explicitly linked evaluation. This module derives exactly that
//! content, so the gateway authorizes and records proof-bound values instead
//! of free-text reasons.
//!
//! The derivation is pure and deterministic: the same intake statement and
//! observation always yield the same disposition or gap record, so an exact
//! replay converges while changed content arrives under a different binding
//! and conflicts downstream. It persists nothing, evaluates nothing, and
//! authorizes nothing — recording stays behind the gateway's live session
//! (I1.8 governed writes), and interpretation stays with the Governor
//! evaluator (I14.22 single decision owner).
//!
//! Expiry withdraws eligibility only; it never deletes an unresolved trigger
//! or its retained effects (I5.2: `expires_at` is a cleanup horizon only
//! after a terminal reconciliation/disposition). Every disposition therefore
//! carries the preserved source and evidence references — source event
//! identity, evidence locators, the staged envelope reference when staging
//! preceded expiry, and the opaque privacy/visibility references — and the
//! semantic payload bytes never travel here (I5.2 opaque payload rules).
//! Supersession links the live successor explicitly instead of overwriting
//! the old result: the old row stays readable under its own disposition.
//!
//! Damage this layer can name — a missing decryption key, a corrupt staged
//! payload, an unreachable retained source — produces a visible gap record
//! bound to the trigger's retry identity and payload binding, never a
//! plaintext fallback and never silent deletion (I14.24 secret-provider and
//! self-observation rows). Enumeration and commit gaps stay with their owning
//! ledger transitions (`pending_page` emits `IncompleteEnumeration`;
//! `mark_ambiguous` emits `AmbiguousCommit`), so they are not derivable here.
//!
//! Compaction is authorized only after an exact ack or terminal disposition
//! plus required downstream retention: [`RetentionReleaseProof`] binds the
//! gateway authorization to the exact settlement reference and refuses any
//! release for unresolved work. Every failure is a typed
//! [`MaintenanceError`]; no acknowledgement, cursor advance, or compaction
//! may be emitted from an error.

use super::MaintenanceError;
use super::trigger_intake::{
    MaintenanceTriggerIntake, TriggerIntakePersistReceipt, TriggerIntakeSourceEvent,
    check_intake_shape,
};

/// Explicit successor link for one superseded trigger intake.
///
/// The successor is a live, explicitly linked evaluation revision carrying
/// materially new policy or source evidence. It never overwrites the old
/// result: the old row keeps its own disposition, record, and receipts under
/// the retention policy, and both rows stay readable.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerRetentionSuccessor {
    /// Stable successor trigger identity; must differ from the superseded one.
    pub trigger_id: String,
    /// Source-attested operation hash of the successor intake.
    pub operation_hash: String,
}

/// Governor-derived terminal expiry/supersession disposition content.
///
/// Bound to the exact intake statement it settles: trigger identity, the
/// source-attested operation hash, the derivation-local payload binding, the
/// applicability window, and the observed time that withdrew eligibility. The
/// gateway copies these fields onto the wire terminal-disposition record when
/// it authorizes recording, binding its session proof to
/// `disposition_ref` instead of free text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerRetentionDisposition {
    /// Stable trigger identity receiving its terminal disposition.
    pub trigger_id: String,
    /// Lowercase SHA-256 of the exact producer operation bytes, echoed.
    pub operation_hash: String,
    /// Derivation-local binding of the exact durable payload content.
    pub payload_binding: String,
    /// Creation time as Unix milliseconds, echoed from the intake.
    pub created_at_ms: i64,
    /// Latest eligible applicability time as Unix milliseconds, echoed.
    pub applicable_until_ms: i64,
    /// Observed time that withdrew eligibility as Unix milliseconds.
    pub observed_now_ms: i64,
    /// Explicit successor link; present exactly for supersession.
    pub successor: Option<TriggerRetentionSuccessor>,
    /// Preserved source event identity; never deleted by expiry.
    pub source_event: TriggerIntakeSourceEvent,
    /// Preserved evidence locators; never content.
    pub evidence_locators: Vec<String>,
    /// Staged envelope reference, when staging preceded expiry.
    pub envelope_reference: Option<String>,
    /// Opaque owner-issued privacy-class reference, preserved under I5.2.
    pub privacy_class_reference: String,
    /// Opaque owner-issued visibility-class reference, preserved under I5.2.
    pub visibility_reference: String,
    /// Stable reason reference for the disposition.
    pub reason: String,
    /// Deterministic disposition identity bound by the gateway authorization.
    pub disposition_ref: String,
}

impl TriggerRetentionDisposition {
    /// Derives terminal expiry content for an intake past its window.
    ///
    /// Refuses a still-eligible intake — mirroring the ledger rule that a
    /// still-applicable trigger must not expire — so eligibility withdrawal
    /// and stale-execution refusal stay one fact. When `staging` is present
    /// the intake must echo its trigger identity and operation hash, binding
    /// the preserved envelope reference to this exact intake; changed content
    /// conflicts instead of recording. A bare error would silently drop the
    /// unresolved trigger; this record preserves its source and evidence
    /// under the retention policy instead.
    ///
    /// Production caller (STITCH, issue #1694): the authenticated daemon
    /// intake/expiry path, which copies this content onto the wire
    /// terminal-disposition record and submits it through
    /// `handle_maintenance_trigger_expiry` in
    /// `crates/kernel/eliot-kernel-service/src/maintenance_trigger_delivery.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a malformed intake, a
    /// still-eligible window, a non-positive observation time, or a blank
    /// reason; [`MaintenanceError::IdentityConflict`] when the staging
    /// receipt echoes another trigger or operation hash.
    pub fn expire(
        intake: &MaintenanceTriggerIntake,
        staging: Option<&TriggerIntakePersistReceipt>,
        observed_now_ms: i64,
        reason: &str,
    ) -> Result<Self, MaintenanceError> {
        check_intake_shape(intake)?;
        if observed_now_ms <= 0 {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.observed_now_ms",
            ));
        }
        if observed_now_ms < intake.applicable_until_ms {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.observed_now_ms",
            ));
        }
        require_text(reason, "trigger_retention.reason")?;
        let envelope_reference = match staging {
            Some(receipt) => {
                if receipt.trigger_id != intake.trigger_id
                    || receipt.operation_hash != intake.operation_hash
                {
                    return Err(MaintenanceError::IdentityConflict);
                }
                require_text(
                    &receipt.envelope_reference,
                    "trigger_retention.envelope_reference",
                )?;
                Some(receipt.envelope_reference.clone())
            }
            None => None,
        };
        Ok(Self {
            trigger_id: intake.trigger_id.clone(),
            operation_hash: intake.operation_hash.clone(),
            payload_binding: intake.payload_binding.clone(),
            created_at_ms: intake.created_at_ms,
            applicable_until_ms: intake.applicable_until_ms,
            observed_now_ms,
            successor: None,
            source_event: intake.source_event.clone(),
            evidence_locators: intake.evidence_locators.clone(),
            envelope_reference,
            privacy_class_reference: intake.privacy_class_reference.clone(),
            visibility_reference: intake.visibility_reference.clone(),
            reason: reason.to_owned(),
            disposition_ref: disposition_ref(&intake.trigger_id, false, &intake.payload_binding),
        })
    }

    /// Derives supersession content linking a live successor revision.
    ///
    /// The successor must be a different trigger identity carrying materially
    /// new evidence, and it must still be eligible at the observed time: a
    /// self-link would overwrite the old result, and a stale successor is no
    /// revision at all. Both statements are shape-checked, so the link names
    /// two exact bindings instead of two claims.
    ///
    /// Production caller (STITCH, issue #1694): the authenticated daemon
    /// intake path holding the new evaluation revision, which copies this
    /// content onto the wire terminal-disposition record and submits it
    /// through `handle_maintenance_trigger_supersession` in
    /// `crates/kernel/eliot-kernel-service/src/maintenance_trigger_delivery.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a malformed intake or
    /// successor, a self-link, a successor that is no longer eligible at the
    /// observed time, a non-positive observation time, or a blank reason.
    pub fn supersede(
        intake: &MaintenanceTriggerIntake,
        successor: &MaintenanceTriggerIntake,
        observed_now_ms: i64,
        reason: &str,
    ) -> Result<Self, MaintenanceError> {
        check_intake_shape(intake)?;
        check_intake_shape(successor)?;
        if observed_now_ms <= 0 {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.observed_now_ms",
            ));
        }
        if successor.trigger_id == intake.trigger_id {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.successor_trigger_id",
            ));
        }
        if observed_now_ms >= successor.applicable_until_ms {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.successor_trigger_id",
            ));
        }
        require_text(reason, "trigger_retention.reason")?;
        Ok(Self {
            trigger_id: intake.trigger_id.clone(),
            operation_hash: intake.operation_hash.clone(),
            payload_binding: intake.payload_binding.clone(),
            created_at_ms: intake.created_at_ms,
            applicable_until_ms: intake.applicable_until_ms,
            observed_now_ms,
            successor: Some(TriggerRetentionSuccessor {
                trigger_id: successor.trigger_id.clone(),
                operation_hash: successor.operation_hash.clone(),
            }),
            source_event: intake.source_event.clone(),
            evidence_locators: intake.evidence_locators.clone(),
            envelope_reference: None,
            privacy_class_reference: intake.privacy_class_reference.clone(),
            visibility_reference: intake.visibility_reference.clone(),
            reason: reason.to_owned(),
            disposition_ref: disposition_ref(&intake.trigger_id, true, &intake.payload_binding),
        })
    }

    /// Whether this disposition links an explicit successor revision.
    ///
    /// The gateway maps `true` onto the wire supersession kind and `false`
    /// onto expiry when it authorizes recording.
    #[must_use]
    pub const fn is_supersession(&self) -> bool {
        self.successor.is_some()
    }

    /// Validates the closed disposition shape and successor rule.
    ///
    /// Expiry must not name a successor; supersession requires an explicit
    /// one that differs from the settled trigger. The gateway re-checks this
    /// before copying the content onto its wire record.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for any malformed identity,
    /// digest, window, reference, or successor pairing, and
    /// [`MaintenanceError::IdentityConflict`] when the stored disposition
    /// identity is not the deterministic identity of this content.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        require_text(&self.trigger_id, "trigger_retention.trigger_id")?;
        require_digest(&self.operation_hash, "trigger_retention.operation_hash")?;
        require_digest(&self.payload_binding, "trigger_retention.payload_binding")?;
        if self.applicable_until_ms <= self.created_at_ms {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.applicable_until_ms",
            ));
        }
        if self.observed_now_ms <= 0 {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.observed_now_ms",
            ));
        }
        match &self.successor {
            Some(successor) => {
                require_text(
                    &successor.trigger_id,
                    "trigger_retention.successor_trigger_id",
                )?;
                require_digest(
                    &successor.operation_hash,
                    "trigger_retention.successor_operation_hash",
                )?;
                if successor.trigger_id == self.trigger_id {
                    return Err(MaintenanceError::InvalidField(
                        "trigger_retention.successor_trigger_id",
                    ));
                }
            }
            None => {
                if self.observed_now_ms < self.applicable_until_ms {
                    return Err(MaintenanceError::InvalidField(
                        "trigger_retention.observed_now_ms",
                    ));
                }
            }
        }
        require_text(
            &self.source_event.producer_id,
            "trigger_retention.source_event.producer_id",
        )?;
        if self.source_event.producer_generation == 0 {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.source_event.producer_generation",
            ));
        }
        require_text(
            &self.source_event.stream_id,
            "trigger_retention.source_event.stream_id",
        )?;
        require_text(
            &self.source_event.event_id,
            "trigger_retention.source_event.event_id",
        )?;
        if self.evidence_locators.is_empty() {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.evidence_locators",
            ));
        }
        for locator in &self.evidence_locators {
            require_text(locator, "trigger_retention.evidence_locators")?;
        }
        if let Some(envelope) = &self.envelope_reference {
            require_text(envelope, "trigger_retention.envelope_reference")?;
        }
        require_text(
            &self.privacy_class_reference,
            "trigger_retention.privacy_class_reference",
        )?;
        require_text(
            &self.visibility_reference,
            "trigger_retention.visibility_reference",
        )?;
        require_text(&self.reason, "trigger_retention.reason")?;
        if self.disposition_ref
            != disposition_ref(
                &self.trigger_id,
                self.is_supersession(),
                &self.payload_binding,
            )
        {
            return Err(MaintenanceError::IdentityConflict);
        }
        Ok(())
    }
}

/// Damage class this layer can name for one retained trigger.
///
/// A missing decryption key, a staged payload that fails integrity
/// validation, or a retained source/evidence reference the owner cannot
/// reach. Enumeration and commit gaps stay with their owning ledger
/// transitions and are not derivable here, mirroring the ledger's own
/// refusal of those kinds from generic gap callers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TriggerDamageKind {
    /// Required decryption key is missing; no plaintext fallback exists.
    MissingKey,
    /// Staged payload fails integrity validation.
    CorruptPayload,
    /// Referenced source event or evidence cannot be reached.
    InaccessibleSource,
}

/// Governor-derived visible recovery-gap content for trigger damage.
///
/// Bound to the trigger's retry identity (trigger identity, operation hash,
/// payload binding) and the preserved evidence locators, so the same damage
/// re-presents the same gap instead of silently deleting the trigger or
/// falling back to plaintext. The gateway copies this content onto the wire
/// gap record when it authorizes recording; the payload bytes themselves
/// never travel here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TriggerDamageGap {
    /// Deterministic gap identity derived from the trigger binding.
    pub gap_ref: String,
    /// Affected trigger identity.
    pub trigger_id: String,
    /// Source-attested operation hash of the damaged intake.
    pub operation_hash: String,
    /// Binding of the exact damaged content; evidence, never bytes.
    pub payload_binding: String,
    /// Damage class.
    pub kind: TriggerDamageKind,
    /// Evidence locator or reason reference; never payload content.
    pub detail: String,
    /// Observation time as Unix milliseconds.
    pub observed_now_ms: i64,
    /// Preserved evidence locators the recovery path can still reach.
    pub evidence_locators: Vec<String>,
}

impl TriggerDamageGap {
    /// Derives a visible gap for damage the intake path cannot repair.
    ///
    /// The intake statement must still shape-check: damage names what the
    /// exact staged content suffered, so the gap binds the retry identity
    /// the producer keeps. `detail` must name the missing key, the integrity
    /// report, or the unreachable reference — a locator or reason reference,
    /// never payload bytes.
    ///
    /// Production caller (STITCH, issue #1694): the authenticated daemon
    /// staging/recovery path observing the owner failure, which copies this
    /// content onto the wire gap record and submits it through
    /// `handle_maintenance_trigger_gap` in
    /// `crates/kernel/eliot-kernel-service/src/maintenance_trigger_delivery.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a malformed intake, a
    /// blank detail, or a non-positive observation time.
    pub fn record(
        intake: &MaintenanceTriggerIntake,
        kind: TriggerDamageKind,
        detail: &str,
        observed_now_ms: i64,
    ) -> Result<Self, MaintenanceError> {
        check_intake_shape(intake)?;
        if observed_now_ms <= 0 {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.observed_now_ms",
            ));
        }
        require_text(detail, "trigger_retention.detail")?;
        Ok(Self {
            gap_ref: gap_ref(&intake.trigger_id, kind, &intake.payload_binding),
            trigger_id: intake.trigger_id.clone(),
            operation_hash: intake.operation_hash.clone(),
            payload_binding: intake.payload_binding.clone(),
            kind,
            detail: detail.to_owned(),
            observed_now_ms,
            evidence_locators: intake.evidence_locators.clone(),
        })
    }

    /// Validates the closed gap shape.
    ///
    /// The gateway re-checks this before copying the content onto its wire
    /// gap record.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for any malformed identity,
    /// digest, detail, or observation time, and
    /// [`MaintenanceError::IdentityConflict`] when the stored gap identity is
    /// not the deterministic identity of this content.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        require_text(&self.trigger_id, "trigger_retention.trigger_id")?;
        require_digest(&self.operation_hash, "trigger_retention.operation_hash")?;
        require_digest(&self.payload_binding, "trigger_retention.payload_binding")?;
        require_text(&self.detail, "trigger_retention.detail")?;
        if self.observed_now_ms <= 0 {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.observed_now_ms",
            ));
        }
        if self.evidence_locators.is_empty() {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.evidence_locators",
            ));
        }
        for locator in &self.evidence_locators {
            require_text(locator, "trigger_retention.evidence_locators")?;
        }
        if self.gap_ref != gap_ref(&self.trigger_id, self.kind, &self.payload_binding) {
            return Err(MaintenanceError::IdentityConflict);
        }
        Ok(())
    }
}

/// Settlement class a retention release answers.
///
/// Exactly one of an acknowledged delivery or a terminal expiry/supersession
/// disposition. Unresolved work — pending, claimed, decision-recorded, or
/// reconciling — has no representation here, so no release can name it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionSettlementClass {
    /// Delivery acknowledged with the exact decision receipt.
    Acknowledged,
    /// Terminal expiry disposition recorded with identity preserved.
    Expired,
    /// Terminal supersession disposition recorded with successor linked.
    Superseded,
}

/// Gateway-authorized retention-release proof for one retained trigger.
///
/// Binds the gateway authorization — the opaque gateway principal plus the
/// digest of its canonical authorization bytes — to the exact settlement
/// reference it answers (an ack receipt reference or a terminal disposition
/// identity) and to the required downstream retention evidence. Signature
/// verification of the authorization digest stays with the issuing gateway
/// owner; this proof carries the shape that owner checks, mirroring the
/// protected-routing grant discipline. Compaction of anything unresolved is
/// unrepresentable: the settlement class admits no pending state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionReleaseProof {
    /// Stable trigger identity this release settles.
    pub trigger_id: String,
    /// Source-attested operation hash of the settled intake.
    pub operation_hash: String,
    /// Settlement class this release answers.
    pub settlement_class: RetentionSettlementClass,
    /// Exact settlement reference: ack receipt ref or disposition identity.
    pub settlement_ref: String,
    /// Opaque gateway principal authorizing this release.
    pub gateway_id: String,
    /// Lowercase SHA-256 digest of the gateway's canonical auth bytes.
    pub authorization_digest: String,
    /// Required downstream retention evidence references; non-empty.
    pub downstream_retention_refs: Vec<String>,
    /// Authorization time as Unix milliseconds.
    pub authorized_at_ms: i64,
}

impl RetentionReleaseProof {
    /// Authorizes release against a recorded terminal disposition.
    ///
    /// The settlement reference echoes the disposition's deterministic
    /// identity, so the authorization answers this exact expiry or
    /// supersession and no other row. Downstream retention evidence is
    /// required: the terminal record alone never releases the retained
    /// source and evidence.
    ///
    /// Production caller (STITCH, issue #1694): the retention sweeper behind
    /// the Kernel gateway session, which presents this proof to the
    /// session-bound compact handler owning
    /// `MaintenanceTriggerDeliveryLedger::compact` in
    /// `crates/kernel/eliot-kernel-service/src/maintenance_trigger_delivery.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a malformed
    /// disposition, gateway identity, digest, settlement binding, empty
    /// downstream retention, or non-positive authorization time.
    pub fn for_terminal_disposition(
        gateway_id: &str,
        authorization_digest: &str,
        disposition: &TriggerRetentionDisposition,
        downstream_retention_refs: &[String],
        authorized_at_ms: i64,
    ) -> Result<Self, MaintenanceError> {
        disposition.validate()?;
        let settlement_class = if disposition.is_supersession() {
            RetentionSettlementClass::Superseded
        } else {
            RetentionSettlementClass::Expired
        };
        authorize_inner(
            gateway_id,
            authorization_digest,
            &disposition.trigger_id,
            &disposition.operation_hash,
            settlement_class,
            &disposition.disposition_ref,
            downstream_retention_refs,
            authorized_at_ms,
        )
    }

    /// Authorizes release against an acknowledged delivery.
    ///
    /// The settlement reference is the exact canonical ack receipt reference
    /// the ledger acknowledged — never an arbitrary receipt ID or a
    /// transport acknowledgement — and the intake statement proves which
    /// exact trigger and operation hash that receipt must have answered.
    ///
    /// Production caller (STITCH, issue #1694): the retention sweeper behind
    /// the Kernel gateway session, which presents this proof to the
    /// session-bound compact handler owning
    /// `MaintenanceTriggerDeliveryLedger::compact` in
    /// `crates/kernel/eliot-kernel-service/src/maintenance_trigger_delivery.rs`.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for a malformed intake,
    /// gateway identity, digest, ack reference, empty downstream retention,
    /// or non-positive authorization time.
    pub fn for_acknowledged_delivery(
        gateway_id: &str,
        authorization_digest: &str,
        intake: &MaintenanceTriggerIntake,
        ack_receipt_ref: &str,
        downstream_retention_refs: &[String],
        authorized_at_ms: i64,
    ) -> Result<Self, MaintenanceError> {
        check_intake_shape(intake)?;
        require_text(ack_receipt_ref, "trigger_retention.settlement_ref")?;
        authorize_inner(
            gateway_id,
            authorization_digest,
            &intake.trigger_id,
            &intake.operation_hash,
            RetentionSettlementClass::Acknowledged,
            ack_receipt_ref,
            downstream_retention_refs,
            authorized_at_ms,
        )
    }

    /// Validates the closed release-proof shape.
    ///
    /// The gateway re-checks this at compaction time, before its ledger
    /// transition: only an exact ack or terminal settlement with gateway
    /// authorization and retained downstream evidence may release a row.
    ///
    /// # Errors
    ///
    /// Returns [`MaintenanceError::InvalidField`] for any malformed identity,
    /// digest, settlement binding, gateway authorization, empty downstream
    /// retention, or non-positive authorization time.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        require_text(&self.trigger_id, "trigger_retention.trigger_id")?;
        require_digest(&self.operation_hash, "trigger_retention.operation_hash")?;
        require_text(&self.settlement_ref, "trigger_retention.settlement_ref")?;
        require_text(&self.gateway_id, "trigger_retention.gateway_id")?;
        require_digest(
            &self.authorization_digest,
            "trigger_retention.authorization_digest",
        )?;
        require_downstream_refs(&self.downstream_retention_refs)?;
        if self.authorized_at_ms <= 0 {
            return Err(MaintenanceError::InvalidField(
                "trigger_retention.authorized_at_ms",
            ));
        }
        Ok(())
    }

    /// Permits compaction of one retained row under this proof.
    ///
    /// The proof is re-validated and must name this exact trigger identity
    /// and operation hash: a proof for another trigger, another operation,
    /// or any unresolved settlement never opens this row. Only the consumed
    /// live-claim binding may drop; the record, receipts, dispositions, and
    /// gaps stay readable under the retention policy.
    ///
    /// Production caller (STITCH, issue #1694): the session-bound compact
    /// handler owning `MaintenanceTriggerDeliveryLedger::compact` (see
    /// `for_terminal_disposition`).
    ///
    /// # Errors
    ///
    /// Returns the proof's own [`MaintenanceError::InvalidField`] when the
    /// proof is malformed, and [`MaintenanceError::IdentityConflict`] when it
    /// answers another trigger or operation hash.
    pub fn compact_permitted(
        &self,
        trigger_id: &str,
        operation_hash: &str,
    ) -> Result<(), MaintenanceError> {
        self.validate()?;
        if self.trigger_id != trigger_id || self.operation_hash != operation_hash {
            return Err(MaintenanceError::IdentityConflict);
        }
        Ok(())
    }
}

/// Authorizes one release proof after the caller bound every dimension.
///
/// Both settlement constructors converge here, so gateway identity, digest,
/// downstream retention, and authorization time are checked once for every
/// release. Every error authorizes nothing.
fn authorize_inner(
    gateway_id: &str,
    authorization_digest: &str,
    trigger_id: &str,
    operation_hash: &str,
    settlement_class: RetentionSettlementClass,
    settlement_ref: &str,
    downstream_retention_refs: &[String],
    authorized_at_ms: i64,
) -> Result<RetentionReleaseProof, MaintenanceError> {
    require_text(trigger_id, "trigger_retention.trigger_id")?;
    require_digest(operation_hash, "trigger_retention.operation_hash")?;
    require_text(settlement_ref, "trigger_retention.settlement_ref")?;
    require_text(gateway_id, "trigger_retention.gateway_id")?;
    require_digest(
        authorization_digest,
        "trigger_retention.authorization_digest",
    )?;
    require_downstream_refs(downstream_retention_refs)?;
    if authorized_at_ms <= 0 {
        return Err(MaintenanceError::InvalidField(
            "trigger_retention.authorized_at_ms",
        ));
    }
    Ok(RetentionReleaseProof {
        trigger_id: trigger_id.to_owned(),
        operation_hash: operation_hash.to_owned(),
        settlement_class,
        settlement_ref: settlement_ref.to_owned(),
        gateway_id: gateway_id.to_owned(),
        authorization_digest: authorization_digest.to_owned(),
        downstream_retention_refs: downstream_retention_refs.to_owned(),
        authorized_at_ms,
    })
}

/// Derives the deterministic identity of one terminal disposition.
///
/// Pure function of the settled trigger identity, the terminal class, and
/// the exact content binding: re-deriving the same settlement yields the
/// same reference, and changed content yields a different one, so the
/// gateway authorization binds one exact settlement.
fn disposition_ref(trigger_id: &str, superseded: bool, payload_binding: &str) -> String {
    let class = if superseded { "SUPERSEDED" } else { "EXPIRED" };
    format!("maintenance-trigger-disposition:{trigger_id}:{class}:{payload_binding}")
}

/// Derives the deterministic identity of one damage gap.
///
/// Pure function of the affected trigger identity, the damage class, and the
/// exact content binding: re-presenting the same damage names the same gap,
/// so a repeated observation reconciles instead of duplicating the record.
fn gap_ref(trigger_id: &str, kind: TriggerDamageKind, payload_binding: &str) -> String {
    let class = match kind {
        TriggerDamageKind::MissingKey => "MISSING_KEY",
        TriggerDamageKind::CorruptPayload => "CORRUPT_PAYLOAD",
        TriggerDamageKind::InaccessibleSource => "INACCESSIBLE_SOURCE",
    };
    format!("maintenance-trigger-gap:{trigger_id}:{class}:{payload_binding}")
}

/// Requires non-blank wire text without control characters.
fn require_text(value: &str, field: &'static str) -> Result<(), MaintenanceError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(MaintenanceError::InvalidField(field));
    }
    Ok(())
}

/// Requires a lowercase SHA-256 digest shape.
fn require_digest(value: &str, field: &'static str) -> Result<(), MaintenanceError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MaintenanceError::InvalidField(field));
    }
    Ok(())
}

/// Requires at least one downstream retention evidence reference, all shaped.
fn require_downstream_refs(refs: &[String]) -> Result<(), MaintenanceError> {
    if refs.is_empty() {
        return Err(MaintenanceError::InvalidField(
            "trigger_retention.downstream_retention_refs",
        ));
    }
    for reference in refs {
        require_text(reference, "trigger_retention.downstream_retention_refs")?;
    }
    Ok(())
}
