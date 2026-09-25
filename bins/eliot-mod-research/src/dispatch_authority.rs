//! Production dispatch authority and evidence recorder for one bounded
//! research-provider operation.
//!
//! This module owns exactly three runtime seams and nothing else:
//!
//! 1. [`ResearchDispatchAuthority`] — the ephemeral `DispatchPermitAuthority`
//!    plus its one-shot replay fence and `DispatchValidationContext`. The key
//!    is generated in memory at composition time, never crosses the front-door
//!    boundary, and never leaves this process. It is the sole issuer and sole
//!    consumer for this operation, exactly like
//!    `bins/eliot-user-broker/src/lib.rs::BrokerDispatchAuthority` and
//!    `bins/eliot-doctor/src/dispatch_authority.rs::DoctorDispatchAuthority`,
//!    and it implements
//!    [`eliot_process_executor::DispatchValidationPort`] so the real
//!    `WindowsProcessExecutor` validates and consumes behind it.
//!
//! 2. [`AdmittedRequestPort`] — the production [`ResearchRequestPort`]. It
//!    builds the single [`ProcessIntent`] from the **Kernel-admitted dispatch
//!    material** carried in [`ProviderAdmission`], and issues exactly one
//!    [`ProcessRequest`] against that authority. It reads no environment
//!    variable, no argv, no stdin and no task text: the executable path, its
//!    content digest, the process generation, the Authority Epoch, the State
//!    Fence nonce, the working directory and the resource limits all come from
//!    the admission. That is the "admitted immutable manifest" requirement; it
//!    is consumed here, never re-derived.
//!
//! 3. [`ProviderEvidenceRecorder`] — the production
//!    [`ProcessEvidenceSink`]. I7.23: "The ingest path stores an exact
//!    transport hash plus either the allowed raw bytes or a deterministic
//!    redacted representation with a redaction receipt." Each retained record
//!    therefore carries the transport hash of the exact evidence bytes, a
//!    deterministic redacted projection (digests, byte counts, dispositions —
//!    never provider prose), and the redaction receipt that names what was
//!    withheld. The records are read back by the one-shot terminal receipt, so
//!    nothing recorded here is dropped.
//!
//! Forbidden authority: this module mints no research semantics, no evidence
//! admission, no task progress and no finish. The Kernel-issued dispatch
//! receipt is the only admission source, and a `ProviderEvidenceRecorder`
//! record is evidence custody, never a verdict.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use eliot_contracts::canonical_json_bytes;
use eliot_kernel_service::ResearchProviderDispatch;
use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    EnvironmentProjection, EvidenceSinkError, FencingToken, ImageId, JobId, KernelDispatchKey,
    PermitIssuance, ProcessEvidence, ProcessEvidenceSink, ProcessExecutionError, ProcessIntent,
    ProcessRequest, ResourceLimits, SessionId, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_process_executor::DispatchValidationPort;
use eliot_research_exchange_api::ResearchQueryRequest;

use crate::admission::ProviderAdmission;
use crate::evidence::{ProviderEvidenceRecord, RedactedEvidence, RedactionReceipt, sha256_hex};
use crate::execution::{RequestPortError, ResearchRequestPort};

/// Fixed argv selector naming the ELIOT-owned bounded submit projection.
///
/// The shared process contour has no stdin channel, and opening one would
/// reintroduce the ambient-caller surface this issue removes. The envelope is
/// instead projected into the **admitted** `ProcessIntent` argv, which the
/// dispatch permit seals through `effect_digest`: the provider therefore
/// receives a Kernel-authorized, digest-bound description of exactly which
/// request it must answer, and the full canonical envelope bytes stay with the
/// receipt as the exact reconciliation record.
pub const SUBMIT_BINDING_ARGV: &str = "--eliot-submit-binding";

/// Fixed argv selector carrying the admitted operation identity.
pub const OPERATION_ARGV: &str = "--eliot-operation";

/// Typed failure of the local research dispatch authority. Every variant is
/// fail-closed: the one-shot entry maps each to a typed coverage gap, never to
/// a spawned child and never to a fabricated result.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ResearchAuthorityError {
    /// The admitted material cannot be turned into launch material.
    #[error("research dispatch authority refused invalid admitted material: {0}")]
    Invalid(String),
    /// The authority or its validation context is unavailable.
    #[error("research dispatch authority unavailable: {0}")]
    Unavailable(String),
}

/// Ephemeral research-owned dispatch authority.
///
/// The authority instance plus the stored validation context bind exactly one
/// issued permit to its consuming validation. The one-shot process exits after
/// one bounded operation, so a second issuance is impossible without a fresh
/// process: the replay fence is per-instance regardless.
pub struct ResearchDispatchAuthority {
    authority: Mutex<DispatchPermitAuthority>,
    context: Mutex<Option<DispatchValidationContext>>,
}

impl ResearchDispatchAuthority {
    /// Activates one ephemeral research authority around fresh in-memory key
    /// material. The authority id names this process invocation; the key
    /// never leaves this process and is never persisted.
    pub fn new() -> Result<Self, ResearchAuthorityError> {
        let authority_id = DispatchAuthorityId::new(format!(
            "research-dispatch-{}-{}",
            std::process::id(),
            system_nanos()
        ))
        .map_err(|error| invalid(&error))?;
        let key = KernelDispatchKey::from_secret_bytes(fresh_key_bytes())
            .map_err(|error| invalid(&error))?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }

    /// Issues the single permit-bound process request for one admitted
    /// research operation.
    ///
    /// The fence comes from the admitted Authority Epoch, admitted process
    /// generation, and a fence nonce derived from the admitted operation
    /// identity; the lease comes from the admitted idempotency key; the
    /// issuance window runs from just before `now_unix_ms` to the admitted
    /// deadline; and the stored validation context pins revision 1. Freshness
    /// is enforced by the contour types, never assumed.
    pub fn issue(
        &self,
        intent: &ProcessIntent,
        admission: &ProviderAdmission,
        dispatch: &ResearchProviderDispatch,
        submit_binding_sha256: &str,
        now_unix_ms: u64,
    ) -> Result<ProcessRequest, ResearchAuthorityError> {
        let generation = admission.process_generation();
        let fence = FencingToken::new(
            admission.epoch().clone(),
            generation,
            format!("research-fence-{}", admission.operation_id().as_str()),
        )
        .map_err(|error| invalid(&error))?;
        let lease = ActionLeaseRef::new(dispatch.idempotency_key.clone())
            .map_err(|error| invalid(&error))?;
        let dispatch_sha256 = dispatch.canonical_sha256().map_err(invalid_dispatch)?;
        let heads = BTreeMap::from([
            ("research-dispatch".to_owned(), dispatch_sha256.clone()),
            (
                "research-submit-binding".to_owned(),
                submit_binding_sha256.to_owned(),
            ),
        ]);
        let expires_at = u64::try_from(admission.deadline_ms()).map_err(|_| {
            ResearchAuthorityError::Invalid("admitted deadline is out of range".to_owned())
        })?;
        let issuance = PermitIssuance::new(
            lease,
            fence.clone(),
            heads.clone(),
            now_unix_ms.saturating_sub(1).max(1),
            expires_at,
            dispatch_sha256,
        )
        .map_err(|error| invalid(&error))?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| ResearchAuthorityError::Unavailable("authority lock poisoned".to_owned()))?
            .issue(intent, issuance)
            .map_err(|error| invalid(&error))?;
        let context = DispatchValidationContext::new(
            ClockObservation {
                valid_time_ms: Some(i64::try_from(now_unix_ms).unwrap_or(i64::MAX)),
                known_time_ms: Some(i64::try_from(now_unix_ms).unwrap_or(i64::MAX)),
                transaction_sequence: None,
                monotonic_ns: Some(1),
            },
            fence,
            admission.epoch().clone(),
            heads,
            1,
        )
        .map_err(|error| invalid(&error))?;
        *self.context.lock().map_err(|_| {
            ResearchAuthorityError::Unavailable("context lock poisoned".to_owned())
        })? = Some(context);
        ProcessRequest::new(intent.clone(), permit).map_err(|error| invalid(&error))
    }
}

impl DispatchValidationPort for ResearchDispatchAuthority {
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
                    "research validation context lock poisoned".to_owned(),
                )
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("missing research validation context".to_owned())
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("research authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}

/// The production request-minting port.
///
/// It is the only party that may mint a `ProcessRequest` for this operation,
/// and it can only mint from the bound [`ProviderAdmission`]. There is no
/// constructor that accepts a caller-supplied executable, argv, working
/// directory, or environment, so no ambient or task-supplied launch material
/// can reach the shared executor through this seam.
pub struct AdmittedRequestPort {
    authority: Arc<ResearchDispatchAuthority>,
    dispatch: ResearchProviderDispatch,
    request: ResearchQueryRequest,
    now_unix_ms: u64,
}

impl AdmittedRequestPort {
    /// Binds this port to one Kernel-admitted dispatch and its matching
    /// exchange request. Nothing starts until `bind` is called by the bridge
    /// after it has re-validated the request/admission binding.
    #[must_use]
    pub fn new(
        authority: Arc<ResearchDispatchAuthority>,
        dispatch: ResearchProviderDispatch,
        request: ResearchQueryRequest,
        now_unix_ms: u64,
    ) -> Self {
        Self {
            authority,
            dispatch,
            request,
            now_unix_ms,
        }
    }

    /// Returns the Kernel-admitted dispatch this port is bound to.
    #[must_use]
    pub const fn dispatch(&self) -> &ResearchProviderDispatch {
        &self.dispatch
    }
}

impl ResearchRequestPort for AdmittedRequestPort {
    fn bind(
        &self,
        admission: &ProviderAdmission,
        submit_binding: &(String, String),
    ) -> Result<ProcessRequest, RequestPortError> {
        let authority = |error: ResearchAuthorityError| match error {
            // Absent or unusable Kernel-issued process authority degrades to
            // the typed source-unavailable gap, never a fabricated result and
            // never a fallback launch path.
            ResearchAuthorityError::Invalid(_) | ResearchAuthorityError::Unavailable(_) => {
                RequestPortError::NoAuthority
            }
        };
        let (_request_sha256, binding) =
            crate::execution::build_submit_binding(admission, &self.request)
                .map_err(|_| RequestPortError::Refused)?;
        // The port re-derives the delivered projection itself and refuses to
        // mint when it disagrees with what the bridge computed, so a stale or
        // mismatched binding can never reach the executor.
        let submit_binding_sha256 = binding.digest().map_err(|_| RequestPortError::Refused)?;
        if submit_binding_sha256 != submit_binding.1 {
            return Err(RequestPortError::Refused);
        }
        let intent = self
            .admitted_intent(admission, &submit_binding_sha256)
            .map_err(authority)?;
        self.authority
            .issue(
                &intent,
                admission,
                &self.dispatch,
                &submit_binding_sha256,
                self.now_unix_ms,
            )
            .map_err(authority)
    }
}

impl AdmittedRequestPort {
    /// Derives the single admitted [`ProcessIntent`] from bound admission
    /// material.
    ///
    /// The working directory is the canonical generation-addressed artifact
    /// root of the admitted module generation, so it is derived from admitted
    /// identity rather than from the process's current directory or any
    /// ambient variable. The environment projection is the empty one
    /// (`EnvironmentInheritance::None`): the child receives no inherited
    /// environment at all, so credentials, proxy configuration and user
    /// resources cannot leak into the provider.
    fn admitted_intent(
        &self,
        admission: &ProviderAdmission,
        submit_binding_sha256: &str,
    ) -> Result<ProcessIntent, ResearchAuthorityError> {
        let operation = admission.operation_id().clone();
        let generation = admission.process_generation();
        let artifact_root = artifact_root(admission.module_id(), admission.module_generation_id());
        let intent = ProcessIntent::new(
            operation,
            eliot_process::ProcessTreeId::new(format!("tree-{}", admission.module_generation_id()))
                .map_err(|error| invalid(&error))?,
            JobId::new(format!("job-{}", admission.module_generation_id()))
                .map_err(|error| invalid(&error))?,
            ImageId::new(admission.module_id().to_owned()).map_err(|error| invalid(&error))?,
            SessionId::new(format!("session-{}", admission.module_generation_id()))
                .map_err(|error| invalid(&error))?,
            generation,
            admission.bridge().executable(),
            admission.bridge().executable_sha256(),
            vec![
                SUBMIT_BINDING_ARGV.to_owned(),
                submit_binding_sha256.to_owned(),
                OPERATION_ARGV.to_owned(),
                admission.operation_id().as_str().to_owned(),
            ],
            artifact_root,
            EnvironmentProjection::default(),
            ResourceLimits::new(
                u64::try_from(admission.deadline_ms()).map_err(|_| {
                    ResearchAuthorityError::Invalid("admitted deadline is out of range".to_owned())
                })?,
                Some(1_000),
                Some(512_000_000),
                65_536,
                65_536,
                4,
            )
            .map_err(|error| invalid(&error))?,
        )
        .map_err(|error| invalid(&error))?;
        // The bounded argv projection is the exact contract digest the
        // provider must be answering; refuse to launch if the exchange
        // request's own route/schema binding does not match the admitted one.
        if self.request.bridge_generation != admission.bridge_generation()
            || self.request.required_schema != admission.required_schema()
            || self.request.protocol_revision != *admission.protocol_revision()
        {
            return Err(ResearchAuthorityError::Invalid(
                "exchange request disagrees with the admitted route binding".to_owned(),
            ));
        }
        Ok(intent)
    }
}

/// Canonical generation-addressed artifact root of one admitted module
/// generation.
///
/// Mirrors the `modules/<module_id>/<generation>/<artifact_hash>/` layout that
/// `eliot_ors::versioned_artifact::VersionedArtifact::canonical_path` owns,
/// without importing ORS into this runtime root: the admitted manifest already
/// carries the exact executable path, so the working directory is derived from
/// admitted identity only and is never read from disk.
fn artifact_root(module_id: &str, module_generation_id: &str) -> String {
    let separator = std::path::MAIN_SEPARATOR;
    ["modules", module_id, module_generation_id].join(&separator.to_string())
}

/// Production evidence sink for one bounded research-provider operation.
///
/// Retains, per executor settlement, the exact transport hash of the canonical
/// evidence bytes plus a deterministic redacted projection and its redaction
/// receipt. The retained records are read by the one-shot terminal receipt, so
/// this is custody of evidence, never a discard.
#[derive(Default)]
pub struct ProviderEvidenceRecorder {
    records: Mutex<Vec<ProviderEvidenceRecord>>,
}

impl ProviderEvidenceRecorder {
    /// Returns an empty recorder bound to no operation.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the retained records in settlement order.
    ///
    /// # Errors
    ///
    /// Returns [`ResearchAuthorityError::Unavailable`] when the record lock is
    /// poisoned, so a caller can never read a silently truncated evidence set.
    pub fn records(&self) -> Result<Vec<ProviderEvidenceRecord>, ResearchAuthorityError> {
        self.records
            .lock()
            .map(|records| records.clone())
            .map_err(|_| ResearchAuthorityError::Unavailable("evidence lock poisoned".to_owned()))
    }
}

impl ProcessEvidenceSink for ProviderEvidenceRecorder {
    fn record(&self, evidence: ProcessEvidence) -> Result<(), EvidenceSinkError> {
        let transport_sha256 = canonical_json_bytes(&evidence).map_err(|_| EvidenceSinkError {
            message: "research evidence is not canonical JSON".to_owned(),
        })?;
        let redacted = RedactedEvidence::from_evidence(&evidence);
        let redaction = RedactionReceipt::for_evidence(&redacted, &sha256_hex(&transport_sha256));
        let record = ProviderEvidenceRecord {
            operation_id: evidence.operation_id().as_str().to_owned(),
            request_digest: evidence.request_digest().to_owned(),
            transport_sha256: sha256_hex(&transport_sha256),
            redacted,
            redaction,
            view: evidence.view().clone(),
        };
        self.records
            .lock()
            .map_err(|_| EvidenceSinkError {
                message: "research evidence lock poisoned".to_owned(),
            })?
            .push(record);
        Ok(())
    }
}

/// Derives the process-unique key component of the authority id from the wall
/// clock. Uniqueness (not secrecy) is load-bearing here: the id only names the
/// instance.
fn system_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)
        })
}

/// Generates fresh per-process key bytes from process-unique standard-library
/// sources mixed through splitmix64, without adding a randomness dependency.
///
/// The load-bearing property is per-process uniqueness, not unpredictability:
/// the key never leaves this process, is never persisted, and only binds
/// permits issued by this same authority instance, which the executor shares by
/// `Arc` and never by value.
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

/// Maps one contract error into a bounded typed refusal.
fn invalid(error: &eliot_process::ContractError) -> ResearchAuthorityError {
    ResearchAuthorityError::Invalid(truncate_detail(&error.to_string()))
}

/// Maps one wire-owner refusal into a bounded typed refusal.
fn invalid_dispatch(error: eliot_kernel_service::ResearchProviderError) -> ResearchAuthorityError {
    ResearchAuthorityError::Invalid(truncate_detail(&error.to_string()))
}

/// Returns the current wall clock in Unix milliseconds, saturating at zero.
#[must_use]
pub fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
}
