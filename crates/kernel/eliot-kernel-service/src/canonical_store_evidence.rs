//! Scoped proofs from the authenticated canonical Store owner for ORS.
//!
//! ORS callbacks are synchronous, while the Store client is asynchronous. This
//! provider therefore accepts only an owner readback already obtained and
//! validated by `KernelStoreGateway`, and exposes it only while the matching
//! local ORS transaction runs. No readback or receipt survives that call.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use eliot_contracts::StateFence;
use eliot_ors::{
    CanonicalEvidenceProvider, CanonicalReconciliation, OrsError, RecoveryInboxItem,
    ReservationRequest, ScopeReservationRequest, StateFenceSnapshot, WriterReservationToken,
};
use eliot_receipts::ReceiptEnvelope;
use eliot_store_api::{OrderingHeadReadback, WriteReceipt};

/// Shared production evidence bridge between the Kernel Store gateway and ORS.
///
/// The same instance must be bound into `RedbRecoveryStore::open_with_evidence`
/// and `KernelStoreGateway::new_with_evidence`. Without that shared instance,
/// each ORS evidence callback refuses. The provider never contacts the Store;
/// callers install verified owner observations for one synchronous local ORS
/// transaction and the registration is removed immediately afterward.
#[derive(Clone, Debug)]
pub struct CanonicalStoreEvidence {
    inner: Arc<CanonicalStoreEvidenceInner>,
}

#[derive(Debug, Default)]
struct CanonicalStoreEvidenceInner {
    transaction: Mutex<()>,
    active: Mutex<Option<ScopedCanonicalEvidence>>,
}

#[derive(Clone, Debug)]
enum ScopedCanonicalEvidence {
    Ordering {
        operation_id: String,
        transition_sha256: String,
        state_fence: StateFence,
        readbacks: BTreeMap<String, OrderingHeadReadback>,
    },
    Receipt {
        token: WriterReservationToken,
        reconciliation: CanonicalReconciliation,
        store_receipt: WriteReceipt,
        envelope: ReceiptEnvelope,
    },
}

impl CanonicalStoreEvidence {
    /// Creates an empty fail-closed provider for composition to share with ORS
    /// and the Store gateway.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CanonicalStoreEvidenceInner::default()),
        }
    }

    /// Runs one local ORS reservation transaction against Store-owned ordering
    /// head readbacks. The caller must have obtained these readbacks from the
    /// authenticated Store gateway and checked the active route on both sides
    /// of the RPC. This function performs only local validation and ORS work.
    pub(crate) fn with_ordering_readbacks<T>(
        &self,
        operation_id: &str,
        transition_sha256: &str,
        state_fence: &StateFence,
        readbacks: &[OrderingHeadReadback],
        action: impl FnOnce() -> T,
    ) -> Result<T, OrsError> {
        let mut by_scope = BTreeMap::new();
        for readback in readbacks {
            readback
                .validate()
                .map_err(|error| OrsError::CanonicalEvidence(error.to_string()))?;
            if &readback.head.state_fence != state_fence
                || by_scope
                    .insert(readback.head.scope.as_str().to_owned(), readback.clone())
                    .is_some()
            {
                return Err(OrsError::CanonicalEvidence(
                    "Store ordering readbacks do not have unique scopes at the admitted fence"
                        .to_owned(),
                ));
            }
        }
        if by_scope.is_empty() {
            return Err(OrsError::CanonicalEvidence(
                "Store returned no canonical ordering head readbacks".to_owned(),
            ));
        }
        validate_digest(transition_sha256)?;
        validate_nonblank(operation_id, "operation_id")?;

        self.with_scope(
            ScopedCanonicalEvidence::Ordering {
                operation_id: operation_id.to_owned(),
                transition_sha256: transition_sha256.to_owned(),
                state_fence: state_fence.clone(),
                readbacks: by_scope,
            },
            action,
        )
    }

    /// Runs one local ORS reconciliation transaction against the exact receipt
    /// returned by the Store owner. The receipt and reconciliation must already
    /// be joined to the supplied reservation token by the gateway's admission
    /// path (or by the named authenticated startup receipt route).
    pub(crate) fn with_store_receipt<T>(
        &self,
        token: &WriterReservationToken,
        reconciliation: &CanonicalReconciliation,
        store_receipt: &WriteReceipt,
        action: impl FnOnce() -> T,
    ) -> Result<T, OrsError> {
        store_receipt
            .validate()
            .map_err(|error| OrsError::CanonicalEvidence(error.to_string()))?;
        let envelope = store_receipt
            .require_reconciliation_envelope()
            .map_err(|error| OrsError::CanonicalEvidence(error.to_string()))?
            .clone();
        envelope
            .validate()
            .map_err(|error| OrsError::CanonicalEvidence(error.to_string()))?;
        let write_binding = token.write_binding.as_ref().ok_or_else(|| {
            OrsError::CanonicalEvidence(
                "Store receipt cannot reconcile a reservation without its original write binding"
                    .to_owned(),
            )
        })?;
        if reconciliation.receipt != envelope
            || reconciliation.operation_id != token.operation_id
            || reconciliation.reservation_id != token.reservation_id
            || reconciliation.reservation_order != token.reservation_order
            || reconciliation.state_fence != token.state_fence
            || reconciliation.recovery_owner != token.recovery_owner
            || store_receipt.operation_id.as_str() != token.operation_id.as_str()
            || write_binding.operation_id != token.operation_id
            || write_binding.prepared_transition_sha256 != token.prepared_transition_sha256
            || write_binding.idempotency_key.as_str() != store_receipt.idempotency_key.as_str()
            || write_binding.canonical_request_sha256 != store_receipt.canonical_request_hash
            || write_binding.operation_manifest_digest.as_str()
                != store_receipt.operation_manifest_digest.as_str()
            || write_binding.state_fence != token.state_fence
            || store_receipt.ordering_sequences.len() != token.scopes.len()
            || reconciliation.scopes.len() != token.scopes.len()
        {
            return Err(OrsError::CanonicalEvidence(
                "Store receipt does not join the exact ORS reservation token".to_owned(),
            ));
        }
        let captured_fence = eliot_ors::StateFenceSnapshot::capture(
            &store_receipt.state_fence,
            envelope.core.authority.authority_epoch.sequence.get(),
        )?;
        if captured_fence != token.state_fence {
            return Err(OrsError::FenceMismatch);
        }
        for reserved in &token.scopes {
            let Some(receipt_head) = store_receipt
                .ordering_sequences
                .iter()
                .find(|head| head.scope.as_str() == reserved.scope.as_str())
            else {
                return Err(OrsError::CanonicalEvidence(
                    "Store receipt misses a reserved ordering scope".to_owned(),
                ));
            };
            if receipt_head.sequence != reserved.reserved_sequence
                || !reconciliation.scopes.iter().any(|scope| {
                    scope.scope == reserved.scope
                        && scope.prior_head == reserved.expected_head
                        && scope.committed_sequence == reserved.reserved_sequence
                        && scope.receipt_id.as_str() == envelope.identity.receipt_id.as_str()
                })
            {
                return Err(OrsError::CanonicalEvidence(
                    "Store receipt scope or sequence differs from its reserved token".to_owned(),
                ));
            }
        }

        self.with_scope(
            ScopedCanonicalEvidence::Receipt {
                token: token.clone(),
                reconciliation: reconciliation.clone(),
                store_receipt: store_receipt.clone(),
                envelope,
            },
            action,
        )
    }

    fn with_scope<T>(
        &self,
        evidence: ScopedCanonicalEvidence,
        action: impl FnOnce() -> T,
    ) -> Result<T, OrsError> {
        let _transaction = self
            .inner
            .transaction
            .lock()
            .map_err(|_| OrsError::CanonicalEvidence("evidence scope lock poisoned".to_owned()))?;
        {
            let mut active = self
                .inner
                .active
                .lock()
                .map_err(|_| OrsError::CanonicalEvidence("evidence state lock poisoned".to_owned()))?;
            if active.is_some() {
                return Err(OrsError::CanonicalEvidence(
                    "another canonical Store proof scope is active".to_owned(),
                ));
            }
            *active = Some(evidence);
        }
        let reset = ActiveEvidenceReset {
            inner: &self.inner,
        };
        let result = action();
        drop(reset);
        Ok(result)
    }

    fn active(&self) -> Result<ScopedCanonicalEvidence, OrsError> {
        self.inner
            .active
            .lock()
            .map_err(|_| OrsError::CanonicalEvidence("evidence state lock poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| {
                OrsError::CanonicalEvidence(
                    "no live canonical Store owner observation is registered".to_owned(),
                )
            })
    }
}

impl Default for CanonicalStoreEvidence {
    fn default() -> Self {
        Self::new()
    }
}

impl CanonicalEvidenceProvider for CanonicalStoreEvidence {
    fn verify_reservation(&self, request: &ReservationRequest) -> Result<(), OrsError> {
        let ScopedCanonicalEvidence::Ordering {
            operation_id,
            transition_sha256,
            state_fence,
            readbacks,
        } = self.active()?
        else {
            return Err(OrsError::CanonicalEvidence(
                "reservation verification requires a live Store readback".to_owned(),
            ));
        };
        let expected_fence = StateFenceSnapshot::capture(
            &state_fence,
            request.envelope.state_fence.observed_authority_epoch,
        )?;
        if request.envelope.operation_or_checkpoint_id.as_str() != operation_id
            || request.prepared_transition_sha256 != transition_sha256
            || request.envelope.state_fence != expected_fence
        {
            return Err(OrsError::CanonicalEvidence(
                "reservation operation, transition digest, or full fence differs from the live Store observation"
                    .to_owned(),
            ));
        }
        verify_store_ordering_heads(&state_fence, &readbacks, &request.scopes)
    }

    fn verify_ordering_heads(
        &self,
        scopes: &[ScopeReservationRequest],
    ) -> Result<(), OrsError> {
        let ScopedCanonicalEvidence::Ordering {
            operation_id,
            transition_sha256,
            state_fence,
            readbacks,
        } = self.active()?
        else {
            return Err(OrsError::CanonicalEvidence(
                "ordering head verification requires a live Store readback".to_owned(),
            ));
        };
        validate_nonblank(&operation_id, "operation_id")?;
        validate_digest(&transition_sha256)?;
        verify_store_ordering_heads(&state_fence, &readbacks, scopes)
    }

    fn verify_reconciliation(
        &self,
        token: &WriterReservationToken,
        reconciliation: &CanonicalReconciliation,
    ) -> Result<(), OrsError> {
        let ScopedCanonicalEvidence::Receipt {
            token: observed_token,
            reconciliation: observed_reconciliation,
            store_receipt,
            envelope,
        } = self.active()?
        else {
            return Err(OrsError::CanonicalEvidence(
                "reconciliation requires a live Store receipt".to_owned(),
            ));
        };
        if token != &observed_token
            || reconciliation != &observed_reconciliation
            || reconciliation.receipt != envelope
            || store_receipt.require_reconciliation_envelope().ok() != Some(&envelope)
        {
            return Err(OrsError::CanonicalEvidence(
                "ORS reconciliation differs from the scoped Store receipt and token".to_owned(),
            ));
        }
        Ok(())
    }

    fn verify_receipt(&self, receipt: &ReceiptEnvelope) -> Result<(), OrsError> {
        match self.active()? {
            ScopedCanonicalEvidence::Receipt { envelope, .. } if &envelope == receipt => Ok(()),
            _ => Err(OrsError::CanonicalEvidence(
                "receipt verification requires the exact live Store owner receipt".to_owned(),
            )),
        }
    }

    fn verify_recovery_inbox(&self, _item: &RecoveryInboxItem) -> Result<(), OrsError> {
        Err(OrsError::CanonicalEvidence(
            "recovery inbox signer proof source is not installed".to_owned(),
        ))
    }
}

fn verify_store_ordering_heads(
    state_fence: &StateFence,
    readbacks: &BTreeMap<String, OrderingHeadReadback>,
    scopes: &[ScopeReservationRequest],
) -> Result<(), OrsError> {
    if scopes.is_empty() || scopes.len() != readbacks.len() {
        return Err(OrsError::CanonicalEvidence(
            "ORS scope set differs from the Store readback set".to_owned(),
        ));
    }
    let requested_scopes = scopes
        .iter()
        .map(|scope| scope.scope.as_str())
        .collect::<BTreeSet<_>>();
    let observed_scopes = readbacks.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if requested_scopes.len() != scopes.len() || requested_scopes != observed_scopes {
        return Err(OrsError::CanonicalEvidence(
            "ORS reservation scope set is not the exact Store readback scope set".to_owned(),
        ));
    }
    for scope in scopes {
        let observed = readbacks
            .get(scope.scope.as_str())
            .ok_or_else(|| OrsError::CanonicalEvidence("Store readback scope missing".to_owned()))?;
        if observed.head.state_fence != *state_fence
            || observed.head.sequence != scope.expected_head.sequence
            || observed.canonical_sha256 != scope.expected_head.head_sha256
            || scope.expected_head.revision_head.is_some()
        {
            return Err(OrsError::CanonicalEvidence(
                "ORS expected head does not match the Store owner readback".to_owned(),
            ));
        }
    }
    Ok(())
}

struct ActiveEvidenceReset<'a> {
    inner: &'a CanonicalStoreEvidenceInner,
}

impl Drop for ActiveEvidenceReset<'_> {
    fn drop(&mut self) {
        if let Ok(mut active) = self.inner.active.lock() {
            *active = None;
        }
    }
}

fn validate_digest(value: &str) -> Result<(), OrsError> {
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(OrsError::CanonicalEvidence(
            "prepared transition digest is not lowercase SHA-256".to_owned(),
        ));
    }
    Ok(())
}

fn validate_nonblank(value: &str, field: &'static str) -> Result<(), OrsError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(OrsError::InvalidField {
            field,
            reason: "must be non-blank bounded text",
        });
    }
    Ok(())
}
