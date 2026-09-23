//! Ephemeral P03 parent dispatch authority (issue #1955).
//!
//! Mirrors the proven testd/doctor/broker shape: a per-process
//! [`DispatchPermitAuthority`] around fresh in-memory key material issues
//! exactly one permit per admitted owner grant, and the stored
//! [`DispatchValidationContext`] lets the real executor validate-and-consume
//! behind this port. The key never leaves this process and only binds
//! permits this same instance issued; replay protection is per-instance and
//! the process exits after one shot. Owner time arrives as `now_ms` from the
//! composition edge (read once, threaded through); contour and permit types
//! enforce it against the owner grant window. Nothing here mints authority:
//! fence, lease, heads, digest, and window all come from the validated owner
//! grant, and failures refuse fail-closed without echoing owner internals.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use eliot_contracts::EpochId;
use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    FencingToken, Generation, KernelDispatchKey, PermitIssuance, ProcessExecutionError,
    ProcessIntent, ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
};

use crate::dispatch_drive::DriveError;
use crate::dispatch_material::ValidatedDispatchGrant;

/// Parent dispatch authority fronting the real executor.
///
/// Constructed per drive around fresh key material; the executor holds it by
/// `Arc` without borrowing the drive frame.
pub struct ParentDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

fn contract_denied(field: &'static str) -> DriveError {
    DriveError::Admission { field }
}

/// Generates fresh per-process key bytes from process-unique std sources
/// mixed through splitmix64. Uniqueness (not secrecy) is load-bearing: the
/// key never leaves this process, is never persisted, and only binds permits
/// issued by this same authority instance.
fn fresh_key_bytes() -> [u8; 32] {
    static MIXER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    let mut state = (std::process::id() as u64).wrapping_add(MIXER.fetch_add(1, Ordering::Relaxed));
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    out
}

/// Reads the composition-edge wall clock once, in Unix milliseconds.
pub fn edge_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}

impl ParentDispatchAuthority {
    /// Activates one ephemeral parent authority around fresh in-memory key
    /// material. The authority id names this process invocation only.
    pub fn activate() -> Result<Self, DriveError> {
        let id = format!(
            "wasm-parent-dispatch-{}-{}",
            std::process::id(),
            edge_now_ms()
        );
        let authority_id =
            DispatchAuthorityId::new(id).map_err(|_| contract_denied("authority-id"))?;
        let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())
            .map_err(|_| contract_denied("authority-key"))?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    /// Issues the single permit-bound process request for one admitted
    /// intent, one owner grant, and one owner-typed epoch.
    ///
    /// The fence comes from the grant epoch, generation, and fence nonce;
    /// the lease from the grant idempotency key; the `launch-grant`
    /// revision head and the one-shot nonce both carry the grant digest;
    /// issuance runs from just before `now_ms` to the grant expiry; and the
    /// stored validation context pins revision 1. Freshness is enforced by
    /// the contour types, never assumed.
    pub fn issue_permit(
        &self,
        intent: &ProcessIntent,
        grant: &ValidatedDispatchGrant,
        epoch: &EpochId,
        now_ms: u64,
    ) -> Result<ProcessRequest, DriveError> {
        let generation = Generation::new(grant.fence_generation)
            .map_err(|_| contract_denied("permit-generation"))?;
        let fence = FencingToken::new(epoch.clone(), generation, grant.fence_nonce.clone())
            .map_err(|_| contract_denied("permit-fence"))?;
        let lease = ActionLeaseRef::new(grant.idempotency_key.clone())
            .map_err(|_| contract_denied("permit-lease"))?;
        let heads = BTreeMap::from([(
            "launch-grant".to_owned(),
            grant.grant_digest.as_str().to_owned(),
        )]);
        let issuance = PermitIssuance::new(
            lease,
            fence.clone(),
            heads.clone(),
            now_ms.saturating_sub(1).max(1),
            grant.expires_at,
            grant.grant_digest.as_str().to_owned(),
        )
        .map_err(|_| contract_denied("permit-issuance"))?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| contract_denied("authority-lock"))?
            .issue(intent, issuance)
            .map_err(|_| contract_denied("permit-issue"))?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(now_ms).unwrap_or(i64::MAX)),
                known_time_ms: Some(i64::try_from(now_ms).unwrap_or(i64::MAX)),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            epoch.clone(),
            heads,
            1,
        )
        .map_err(|_| contract_denied("permit-context"))?;
        *self
            .context
            .lock()
            .map_err(|_| contract_denied("context-lock"))? = Some(context);
        ProcessRequest::new(intent.clone(), permit).map_err(|_| contract_denied("permit-request"))
    }
}

impl eliot_process_executor::DispatchValidationPort for ParentDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable(
                    "parent dispatch context lock poisoned".to_owned(),
                )
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable(
                    "missing parent dispatch validation context".to_owned(),
                )
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable(
                    "parent dispatch authority lock poisoned".to_owned(),
                )
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}
