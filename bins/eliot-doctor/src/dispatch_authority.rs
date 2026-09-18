//! Local doctor dispatch authority: the child half of the merged User Broker
//! pattern (`bins/eliot-user-broker/src/lib.rs:120-216`).
//!
//! This module owns the ephemeral doctor-process `DispatchPermitAuthority`:
//! the key is generated in memory at composition time and never crosses the
//! launch-grant or stdin boundary, and `DispatchPermitAuthority` supplies
//! the one-shot replay fence. It consumes a validated launch grant (see
//! [`crate::dispatched_material::DispatchGrant`], already proved fail-closed
//! by the reader) to build the single in-process [`ProcessRequest`] via
//! `FencingToken::new` + `PermitIssuance::new` +
//! `DispatchValidationContext::new` + `ProcessRequest::new`, exactly like
//! the broker, and it implements [`DispatchValidationPort`] so the real
//! [`WindowsProcessExecutor`] can validate-and-consume behind it.
//!
//! The [`ProcessIntent`] is supplied by the caller (the Drive arm), never
//! derived here and never taken from argv, stdin, or environment: this
//! module mints no executable binding. The production Drive arm
//! (`drive_validated_dispatched_attempt`, called from the composition root)
//! supplies the honest admitted intent derived from the Kernel-admitted
//! executable binding; the module tests exercise the same seam with
//! test-only intents.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    FencingToken, Generation, KernelDispatchKey, PermitIssuance, ProcessExecutionError,
    ProcessIntent, ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::DispatchValidationPort;

use crate::dispatched_material::DispatchGrant;

/// Typed failure for the local doctor dispatch authority. Every variant is
/// fail-closed: the one-shot entry maps each to exit 78 without effect.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DoctorAuthorityError {
    /// The grant, intent, or issuance shape cannot be consumed.
    #[error("doctor dispatch authority refused invalid material: {0}")]
    Invalid(String),
    /// The authority or its validation context is unavailable.
    #[error("doctor dispatch authority unavailable: {0}")]
    Unavailable(String),
}

/// Ephemeral doctor-owned dispatch authority. The key lives only in this
/// process's memory for one shot; the authority instance plus the stored
/// validation context bind exactly one issued permit to its consuming
/// validation, mirroring the broker.
pub struct DoctorDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl DoctorDispatchAuthority {
    /// Activates one ephemeral doctor authority around fresh in-memory key
    /// material. The authority id names this process invocation; the key
    /// never leaves this process.
    pub fn new() -> Result<Self, DoctorAuthorityError> {
        let pid = std::process::id();
        let nanos = system_nanos();
        let authority_id = DispatchAuthorityId::new(format!("doctor-dispatch-{pid}-{nanos}"))
            .map_err(|error| DoctorAuthorityError::Invalid(error.to_string()))?;
        let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())
            .map_err(|error| DoctorAuthorityError::Invalid(error.to_string()))?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    /// Issues the single permit-bound process request for one validated
    /// grant and one caller-supplied admitted intent.
    ///
    /// Mirrors the broker exactly: the fence comes from the grant epoch,
    /// generation, and fence nonce; the lease from the grant idempotency
    /// key; the `launch-grant` revision head and the one-shot nonce both
    /// carry the grant digest; issuance runs from just before `now_unix_ms`
    /// to the grant expiry; and the stored validation context pins
    /// revision 1. Freshness (`issued_at < expires_at`, and later
    /// `now < expires_at` at consume time) is enforced by the contour
    /// types, never assumed.
    pub fn issue(
        &self,
        intent: &ProcessIntent,
        grant: &DispatchGrant,
        now_unix_ms: u64,
    ) -> Result<ProcessRequest, DoctorAuthorityError> {
        let invalid = |error: eliot_process::ContractError| {
            DoctorAuthorityError::Invalid(truncate_detail(&error.to_string()))
        };
        let generation = Generation::new(grant.fence_generation).map_err(invalid)?;
        let fence = FencingToken::new(
            grant.authority_epoch.clone(),
            generation,
            grant.fence_nonce.clone(),
        )
        .map_err(invalid)?;
        let lease = ActionLeaseRef::new(grant.idempotency_key.clone()).map_err(invalid)?;
        let heads = BTreeMap::from([("launch-grant".to_owned(), grant.grant_digest.clone())]);
        let issuance = PermitIssuance::new(
            lease,
            fence.clone(),
            heads.clone(),
            now_unix_ms.saturating_sub(1).max(1),
            grant.expires_at,
            grant.grant_digest.clone(),
        )
        .map_err(invalid)?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| DoctorAuthorityError::Unavailable("authority lock poisoned".to_owned()))?
            .issue(intent, issuance)
            .map_err(invalid)?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(now_unix_ms).unwrap_or(i64::MAX)),
                known_time_ms: Some(i64::try_from(now_unix_ms).unwrap_or(i64::MAX)),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            grant.authority_epoch.clone(),
            heads,
            1,
        )
        .map_err(invalid)?;
        *self
            .context
            .lock()
            .map_err(|_| DoctorAuthorityError::Unavailable("context lock poisoned".to_owned()))? =
            Some(context);
        ProcessRequest::new(intent.clone(), permit).map_err(invalid)
    }
}

impl DispatchValidationPort for DoctorDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("doctor context lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("missing doctor validation context".to_owned())
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("doctor authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}

/// Derives the process-invocation component of the authority id from the
/// wall clock. Uniqueness (not secrecy) is load-bearing here: the id only
/// names the instance.
fn system_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Generates fresh per-process key bytes from process-unique std sources
/// mixed through splitmix64, without adding a randomness dependency.
///
/// The load-bearing property is per-process uniqueness, not
/// unpredictability: the key never leaves this process, is never persisted,
/// and only binds permits issued by this same authority instance (which the
/// executor shares by `Arc`, never by value). The replay fence is
/// per-instance regardless, and the process exits after one shot.
fn fresh_key_bytes() -> [u8; 32] {
    static MIXER: AtomicU64 = AtomicU64::new(0x9E37_79B9_7F4A_7C15);

    fn splitmix64(state: &mut u64) -> u64 {
        *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    let probe = 0u64;
    let stack = std::ptr::addr_of!(probe) as usize as u64;
    let pid = u64::from(std::process::id());
    let count = MIXER.fetch_add(1, Ordering::Relaxed);
    let mut state = system_nanos()
        ^ pid.wrapping_mul(0xBF58_476D_1CE4_E5B9)
        ^ stack.rotate_left(17)
        ^ count.wrapping_mul(0x94D0_49BB_1331_11EB);
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        chunk.copy_from_slice(&splitmix64(&mut state).to_le_bytes());
    }
    if out.iter().all(|byte| *byte == 0) {
        out[31] = 1;
    }
    out
}

/// Bounds third-party error detail carried into deny lines.
fn truncate_detail(detail: &str) -> String {
    const LIMIT: usize = 256;
    detail.chars().take(LIMIT).collect()
}

/// Keeps the executor behind the port in the dependency closure so the
/// Drive arm cannot drift to another implementation.
#[allow(
    dead_code,
    reason = "DISPATCH-CAUSE-FIX doctor Drive execution awaits an honest admitted intent source; proves the executor seam type-checks behind this authority"
)]
fn executor_for(
    authority: Arc<DoctorDispatchAuthority>,
) -> eliot_process_executor::WindowsProcessExecutor {
    eliot_process_executor::WindowsProcessExecutor::new(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eliot_contracts::{EpochId, EpochLineageId};
    use eliot_process::{
        EnvironmentProjection, ImageId, JobId, OperationId, PhysicalProcessBinding, ProcessId,
        ProcessTreeId, ResourceLimits, SessionId,
    };
    use std::num::NonZeroU64;

    const TEST_LINEAGE: &str = "550e8400-e29b-41d4-a716-446655440000";

    fn digest(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn test_epoch() -> Result<EpochId, String> {
        let lineage = EpochLineageId::new(TEST_LINEAGE).map_err(|error| error.to_string())?;
        let sequence = NonZeroU64::new(7).ok_or_else(|| "test sequence is zero".to_owned())?;
        EpochId::new(lineage, sequence).map_err(|error| error.to_string())
    }

    // Clearly-marked test-only intent scaffolding standing in for the
    // admitted intent the production Drive arm derives via
    // derive_intent_from_admitted_binding. Production never builds intents
    // from fixture executables; this only proves the authority consumes a
    // validated grant through the real contour constructors.
    fn test_intent() -> Result<ProcessIntent, String> {
        let bad = |error: eliot_process::ContractError| error.to_string();
        let generation = Generation::new(3).map_err(bad)?;
        let limits = ResourceLimits::new(5_000, Some(1_000), Some(1_048_576), 4_096, 4_096, 2)
            .map_err(bad)?;
        ProcessIntent::new(
            OperationId::new("op-reconnect").map_err(bad)?,
            ProcessTreeId::new("tree-authority-1").map_err(bad)?,
            JobId::new("job-authority-1").map_err(bad)?,
            ImageId::new("image-authority-1").map_err(bad)?,
            SessionId::new("session-authority-1").map_err(bad)?,
            generation,
            "doctor-test-effect-host.exe",
            digest(0xc1),
            vec!["--admitted-effect".to_owned()],
            "C:/eliot/doctor",
            EnvironmentProjection::default(),
            limits,
        )
        .map_err(bad)
    }

    fn test_grant(expires_at: u64) -> Result<DispatchGrant, String> {
        Ok(DispatchGrant {
            grant_digest: digest(0x61),
            authority_epoch: test_epoch()?,
            fence_generation: 3,
            fence_nonce: "doctor-launch-fence-test01".to_owned(),
            idempotency_key: "doctor-launch-lease-test01".to_owned(),
            expires_at,
        })
    }

    /// The authority issues a permit-bound request from a validated grant
    /// through the real contour constructors, the port seam type-checks
    /// behind the real executor, the consuming validation round-trips
    /// against staged observed identity, and an expired grant is refused
    /// fail-closed before anything issues.
    #[test]
    fn authority_issues_consumes_and_refuses_expired_grant() -> Result<(), String> {
        let bad = |error: eliot_process::ContractError| error.to_string();
        let now_ms = 1_750_000_000_000u64;
        let grant = test_grant(1_750_000_060_000)?;
        let authority = DoctorDispatchAuthority::new().map_err(|error| error.to_string())?;
        let intent = test_intent()?;
        let request = authority
            .issue(&intent, &grant, now_ms)
            .map_err(|error| error.to_string())?;
        request.validate().map_err(|error| error.to_string())?;
        assert_eq!(request.operation_id().as_str(), "op-reconnect");
        assert_eq!(request.generation().get(), grant.fence_generation);

        // The port seam behind the real executor type: object-safe and
        // constructible, so the production Drive arm cannot drift
        // implementations.
        let _port: Arc<dyn DispatchValidationPort> =
            Arc::new(DoctorDispatchAuthority::new().map_err(|error| error.to_string())?);
        let _executor = executor_for(Arc::new(
            DoctorDispatchAuthority::new().map_err(|error| error.to_string())?,
        ));

        // Consuming validation round-trips against observed identity staged
        // from the same intent, through the real contour check.
        let binding = PhysicalProcessBinding::new(
            4242,
            11,
            intent.executable(),
            "Local\\Eliot-Doctor-Authority-Test",
        )
        .map_err(bad)?;
        let process_id = ProcessId::new("process-9").map_err(bad)?;
        let observed = SuspendedProcessIdentity::new(
            process_id,
            intent.process_tree_id().clone(),
            intent.job_id().clone(),
            intent.image_id().clone(),
            intent.session_id().clone(),
            intent.generation(),
            binding,
            120,
            intent.executable_sha256(),
        )
        .map_err(|error| error.to_string())?;
        authority
            .validate_and_consume(request, observed)
            .map_err(|error| error.to_string())?;

        // An expired grant (expiry at or before issuance) is refused before
        // any permit exists: exactly one shot, never a fallback.
        let expired = test_grant(2)?;
        match authority.issue(&intent, &expired, now_ms) {
            Err(DoctorAuthorityError::Invalid(_)) => Ok(()),
            Err(other) => Err(format!("expired grant refused with wrong cause: {other}")),
            Ok(_) => Err("expired grant must be refused".to_owned()),
        }
    }
}
