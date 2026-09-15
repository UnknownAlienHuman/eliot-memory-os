//! In-child P-03 dispatch authority for the native-worker dispatch contour.
//!
//! Mirrors the merged User Broker pattern
//! (`bins/eliot-user-broker/src/lib.rs`, `BrokerDispatchAuthority`): a local
//! struct holding a [`DispatchPermitAuthority`] plus an optional
//! [`DispatchValidationContext`], with `new` / `issue` /
//! `validate_and_consume` entries, fronting the real
//! [`WindowsProcessExecutor`](eliot_process_executor::WindowsProcessExecutor).
//! Deriving the one-shot permit inside the child from the Kernel-issued
//! launch grant is the documented broker pattern, not minted authority:
//! the Kernel still owns the grant, the epoch, the fence, and the validation
//! context, and every value below is re-proved against them fail-closed.
//!
//! ## The one deliberate broker delta: deterministic issuance
//!
//! The broker mints its authority key from fresh entropy because nothing
//! downstream must predict its permits. This contour cannot do that: the
//! T9-02 executable join carries `process_invocation_digest`, and the
//! production gates compare it against the issued [`ProcessRequest`]
//! invocation digest both at the `from_claim` join
//! (`crates/modules/eliot-native-worker-core/src/ports.rs`,
//! `validate_claim_executable_hello_process_binding`) and after admission
//! (`crates/modules/eliot-native-worker-core/src/lib.rs`,
//! `require_claim_executable_binding`). The invocation digest covers the
//! permit digest, which covers the authentication tag, which is keyed by the
//! authority key (`crates/kernel/eliot-process/src/dispatch_permit.rs`).
//! A fresh-entropy key therefore makes the issued digest unpredictable, and
//! no owner — however cooperating — could ever publish a join that closes.
//! The issuance tuple is consequently derived deterministically from
//! pre-binding admitted material (claim identity, operation, generation,
//! epoch, and the claim-bound launch nonce), so the owner-side publisher can
//! run the identical forward computation and embed the matching digest:
//!
//! ```text
//! base      = ["eliot-native-worker-dispatch/v1", claim_id, operation_id,
//!              worker_generation, authority_epoch, launch_nonce]
//! key       = SHA-256("key:" + base_json)
//! authority = "native-worker-dispatch-authority-" + hex(SHA-256("authority:" + base_json))
//! nonce     = the claim-bound launch nonce (the join `launch_nonce`)
//! heads     = {"launch-grant": hex(SHA-256("head:" + base_json))}
//! issued    = the receipt admission time (`admitted_at_unix_ms`, carried in
//!             the file — the grant window opens at admission by kernel
//!             construction)
//! expires   = grant.expires_at
//! ```
//!
//! Every input above is fixed before the claim binding digest exists, so the
//! owner computation is acyclic: intent, then permit, then invocation digest,
//! then join, then binding digest, then grant. Wall-clock time never enters
//! the permit (only the validation-context observation, which is not
//! digest-covered). Replay-stable by construction: the same admitted file
//! re-derives the identical permit and digest.
//!
//! ## Why this stays sound
//!
//! Determinism costs the broker's key secrecy, and the containment is
//! explicit: permits never leave this process ([`ProcessRequest`] is
//! `Serialize`-only by design and is never deserialized here), so there is
//! no cross-process verification for a derived key to weaken and no
//! interface that accepts an outside permit. What the key still provides —
//! per-grant domain separation, so permits issued under one claim never
//! validate under another — determinism preserves (distinct claims hash to
//! distinct keys). Admission itself stays kernel-side: the transport must be
//! live and the Kernel re-gates every submit (registration shape, claim
//! binding digest, executable expectation against the live owner record),
//! the dispatch file is consumed once, and the executor re-hashes the
//! executable file before any start. A forged file still dies at the Kernel
//! submit and at the executable check; determinism only lets a *genuine*
//! admitted claim close the join gate.
//!
//! ## Dependency-frozen hashing
//!
//! This crate may not add dependencies, and no SHA-256 reaches production
//! code through the current dependency set, so the KDF above uses a small
//! `forbid(unsafe_code)`-compatible SHA-256 over `std` only. It is proven
//! in the test suite against the standard vectors and byte-for-byte against
//! `eliot_contracts::sha256_hex` on real file bytes.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Mutex;

use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    FencingToken, KernelDispatchKey, PermitIssuance, ProcessExecutionError, ProcessIntent,
    ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
};

use crate::NativeWorkerError;

/// Domain separating the dispatch derivation from every other hash use.
const DISPATCH_DERIVATION_DOMAIN: &str = "eliot-native-worker-dispatch/v1";
/// Single revision head name carried on every native-worker issuance and its
/// validation context, mirroring the broker's `launch-grant` head. It binds
/// a domain-separated digest of the derivation base here instead of the
/// post-binding grant digest, which the owner cannot predict (see the module
/// documentation). The digest rules (`validate_revision_heads`) require the
/// 64-character hexadecimal shape.
const LAUNCH_GRANT_HEAD: &str = "launch-grant";
/// Validation revision carried on every native-worker issuance and its
/// validation context, mirroring the broker.
const VALIDATION_REVISION: u64 = 1;

/// Kernel-issued launch grant after fail-closed validation, ready to issue.
///
/// Carries exactly the broker's issuance inputs: the fence and lease rebuilt
/// through their production constructors from the grant fields, the opaque
/// grant digest retained for correlation, and the file-derived freshness
/// window (receipt admission time through grant expiry). The authority epoch
/// is not stored: it is proven equal to the admitted claim epoch (as
/// canonical JSON) before construction, and the fence already carries the
/// proven value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDispatchGrant {
    /// Fence rebuilt via `FencingToken::new` from the grant fields.
    fence: FencingToken,
    /// Lease rebuilt via `ActionLeaseRef::new` from the grant lease.
    lease: ActionLeaseRef,
    /// Opaque grant digest; never inverted, only retained for correlation.
    grant_digest: String,
    /// Window opening: the receipt admission time carried in the file.
    issued_at: u64,
    /// Grant expiry in Unix milliseconds for `PermitIssuance::new`.
    expires_at: u64,
}

impl ValidatedDispatchGrant {
    /// Builds one validated grant from its already-proven parts.
    ///
    /// Re-checks the digest shape and the freshness window so a misuse of
    /// the constructor still fails closed instead of issuing.
    pub fn new(
        fence: FencingToken,
        lease: ActionLeaseRef,
        grant_digest: String,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, NativeWorkerError> {
        if !is_lowercase_sha256(&grant_digest) {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "dispatch grant digest must be a lowercase SHA-256 digest".to_owned(),
            ));
        }
        if issued_at == 0 || expires_at <= issued_at {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "dispatch grant window must open non-zero and before expiry".to_owned(),
            ));
        }
        Ok(Self {
            fence,
            lease,
            grant_digest,
            issued_at,
            expires_at,
        })
    }

    /// Returns the rebuilt dispatch fence.
    pub fn fence(&self) -> &FencingToken {
        &self.fence
    }

    /// Returns the rebuilt action lease.
    pub fn lease(&self) -> &ActionLeaseRef {
        &self.lease
    }

    /// Returns the opaque grant digest.
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }

    /// Returns the window opening in Unix milliseconds.
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Returns the grant expiry in Unix milliseconds.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

/// In-child P-03 dispatch authority, mirroring `BrokerDispatchAuthority`.
///
/// The issuance tuple is derived per admitted claim (see the module
/// documentation for the proof that fresh entropy cannot close the T9-02
/// join gate). Key material lives only in this struct: it is never
/// serialized, logged, or transported, and is dropped with the process.
pub struct NativeWorkerDispatchAuthority {
    /// Issuing and consuming authority; the one-shot nonce ledger lives here.
    authority: Mutex<DispatchPermitAuthority>,
    /// Current validation snapshot installed at issue time.
    context: Mutex<Option<DispatchValidationContext>>,
    /// Canonical derivation base; the head digest re-derives from it at
    /// issue time so issuance and context agree exactly.
    derivation_base: String,
}

impl NativeWorkerDispatchAuthority {
    /// Derives one authority instance for exactly one admitted claim.
    ///
    /// All inputs are pre-binding admitted material (see the module
    /// documentation): the owner-side publisher runs the identical
    /// computation, so both sides derive the same key, authority identity,
    /// and — together with the canonical intent — the same permit and
    /// invocation digest.
    pub fn new(
        claim_id: &str,
        operation_id: &str,
        worker_generation: u64,
        authority_epoch_json: &serde_json::Value,
        launch_nonce: &str,
    ) -> Result<Self, NativeWorkerError> {
        let base = serde_json::to_string(&serde_json::json!([
            DISPATCH_DERIVATION_DOMAIN,
            claim_id,
            operation_id,
            worker_generation,
            authority_epoch_json,
            launch_nonce,
        ]))
        .map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "dispatch derivation failed: {error}"
            ))
        })?;
        let key =
            KernelDispatchKey::from_secret_bytes(tagged_hash("key", &base)).map_err(|error| {
                NativeWorkerError::KernelAdmissionRequired(format!(
                    "dispatch key derivation failed: {error}"
                ))
            })?;
        let authority_id = DispatchAuthorityId::new(format!(
            "native-worker-dispatch-authority-{}",
            hex_bytes(&tagged_hash("authority", &base))
        ))
        .map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "dispatch authority identity failed: {error}"
            ))
        })?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
            derivation_base: base,
        })
    }

    /// Issues one permit bound to the exact immutable intent.
    ///
    /// Mirrors the broker issue: the fence and lease come from the validated
    /// grant, the head map binds the derivation digest, the one-shot nonce
    /// is the claim-bound launch nonce, and freshness is file-derived
    /// (receipt admission time through grant expiry, never wall time, so
    /// replays rebuild the identical permit). The validation context
    /// snapshots the live observation clock. A stale grant (`expires_at` at
    /// or before now) is refused without effect.
    pub fn issue(
        &self,
        intent: &ProcessIntent,
        grant: &ValidatedDispatchGrant,
        launch_nonce: &str,
        now_ms: u64,
    ) -> Result<ProcessRequest, NativeWorkerError> {
        if now_ms == 0 {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "dispatch clock is unavailable".to_owned(),
            ));
        }
        if grant.expires_at() <= now_ms {
            return Err(NativeWorkerError::KernelAdmissionRequired(
                "dispatch grant window is stale or expired".to_owned(),
            ));
        }
        let head_digest = hex_bytes(&tagged_hash("head", &self.derivation_base));
        let issuance = PermitIssuance::new(
            grant.lease().clone(),
            grant.fence().clone(),
            BTreeMap::from([(LAUNCH_GRANT_HEAD.to_owned(), head_digest.clone())]),
            grant.issued_at(),
            grant.expires_at(),
            launch_nonce.to_owned(),
        )
        .map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "dispatch permit issuance failed: {error}"
            ))
        })?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| {
                NativeWorkerError::KernelAdmissionRequired(
                    "dispatch authority lock poisoned".to_owned(),
                )
            })?
            .issue(intent, issuance)
            .map_err(|error| {
                NativeWorkerError::KernelAdmissionRequired(format!(
                    "dispatch permit issuance failed: {error}"
                ))
            })?;
        let context = validation_context(now_ms, grant.fence(), &head_digest)?;
        *self.context.lock().map_err(|_| {
            NativeWorkerError::KernelAdmissionRequired(
                "dispatch validation context lock poisoned".to_owned(),
            )
        })? = Some(context);
        ProcessRequest::new(intent.clone(), permit).map_err(|error| {
            NativeWorkerError::KernelAdmissionRequired(format!(
                "dispatch process request failed: {error}"
            ))
        })
    }

    /// Validates fresh P-02 launch evidence and consumes a permit exactly once.
    ///
    /// Delegates to the active authority under the installed validation
    /// context, mirroring the broker delegation including the poisoned-lock
    /// and missing-context mappings.
    pub fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("native-worker context lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable(
                    "missing native-worker validation context".to_owned(),
                )
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable(
                    "native-worker authority lock poisoned".to_owned(),
                )
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}

impl eliot_process_executor::DispatchValidationPort for NativeWorkerDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        NativeWorkerDispatchAuthority::validate_and_consume(self, request, observed)
    }
}

/// Builds the current validation snapshot for one issuance.
///
/// The `DispatchValidationContext` constructor needs the platform clock type,
/// which this dependency-frozen crate cannot name (no `eliot-platform`
/// dependency and none may be added). The context type itself is
/// `Serialize`/`Deserialize`, so the snapshot is built through its canonical
/// JSON shape instead: the fence and epoch serialize from the live values
/// already held here, the head map repeats the issuance head exactly, and
/// only the scalar clock observation is written by hand. A shape drift fails
/// closed here (deserialization error) and again at consume time
/// (`DispatchValidationContext::validate` runs inside
/// `validate_and_consume`), never silently.
fn validation_context(
    now_ms: u64,
    fence: &FencingToken,
    head_digest: &str,
) -> Result<DispatchValidationContext, NativeWorkerError> {
    let now = i64::try_from(now_ms).map_err(|_| {
        NativeWorkerError::KernelAdmissionRequired("dispatch clock is out of range".to_owned())
    })?;
    let fence_value = serde_json::to_value(fence).map_err(NativeWorkerError::Json)?;
    let epoch_value =
        serde_json::to_value(fence.authority_epoch()).map_err(NativeWorkerError::Json)?;
    // Canonical context shape: clock, state_fence, authority_epoch,
    // revision_heads, validation_revision. The heads repeat the issuance
    // head exactly (the consume gate compares them for equality); the fence
    // equality plus epoch agreement are re-enforced by the context validator
    // at consume time.
    let context_value = serde_json::json!({
        "clock": {
            "valid_time_ms": now,
            "known_time_ms": now,
            "transaction_sequence": null,
            "monotonic_ns": 1,
        },
        "state_fence": fence_value,
        "authority_epoch": epoch_value,
        "revision_heads": {LAUNCH_GRANT_HEAD: head_digest},
        "validation_revision": VALIDATION_REVISION,
    });
    serde_json::from_value(context_value).map_err(NativeWorkerError::Json)
}

/// Current Unix time in milliseconds for issuance freshness checks.
pub fn now_unix_ms() -> Result<u64, NativeWorkerError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| {
            NativeWorkerError::KernelAdmissionRequired("worker clock is unavailable".to_owned())
        })?
        .as_millis()
        .try_into()
        .map_err(|_| {
            NativeWorkerError::KernelAdmissionRequired("worker clock is out of range".to_owned())
        })
}

/// Returns true for a lowercase SHA-256 digest shape.
fn is_lowercase_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Hashes one domain-separated derivation input with the contour SHA-256.
fn tagged_hash(tag: &str, base_json: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(tag.len().saturating_add(1).saturating_add(base_json.len()));
    input.extend_from_slice(tag.as_bytes());
    input.push(b':');
    input.extend_from_slice(base_json.as_bytes());
    sha256_bytes(&input)
}

/// Lowercase hex encoding of 32 digest bytes.
pub(crate) fn hex_bytes(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    output
}

/// SHA-256 over `std` only (FIPS 180-4), for the dependency-frozen KDF.
///
/// No hash implementation reaches production code through the current
/// dependency set and none may be added, so this contour carries its own.
/// Proven in the test suite against the standard vectors and byte-for-byte
/// against `eliot_contracts::sha256_hex` on real file bytes.
#[allow(
    clippy::too_many_lines,
    reason = "the round-constant table and the pad/schedule/compress rounds are one inseparable primitive; splitting them would obscure the FIPS 180-4 structure"
)]
pub(crate) fn sha256_bytes(input: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let bit_len = u64::try_from(input.len())
        .unwrap_or(u64::MAX)
        .wrapping_mul(8);
    let mut padded = Vec::with_capacity(input.len().saturating_add(72));
    padded.extend_from_slice(input);
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.chunks_exact(64) {
        let mut schedule = [0_u32; 64];
        for (index, word) in schedule.iter_mut().enumerate().take(16) {
            let offset = index.saturating_mul(4);
            *word = u32::from(block[offset]) << 24
                | u32::from(block[offset.saturating_add(1)]) << 16
                | u32::from(block[offset.saturating_add(2)]) << 8
                | u32::from(block[offset.saturating_add(3)]);
        }
        for index in 16_usize..64 {
            let word_two = schedule[index.saturating_sub(2)];
            let word_seven = schedule[index.saturating_sub(7)];
            let word_fifteen = schedule[index.saturating_sub(15)];
            let small_zero =
                word_fifteen.rotate_right(7) ^ word_fifteen.rotate_right(18) ^ (word_fifteen >> 3);
            let small_one =
                word_two.rotate_right(17) ^ word_two.rotate_right(19) ^ (word_two >> 10);
            schedule[index] = schedule[index.saturating_sub(16)]
                .wrapping_add(small_zero)
                .wrapping_add(word_seven)
                .wrapping_add(small_one);
        }
        let mut working = state;
        for index in 0..64 {
            let schedule_word = schedule[index];
            let big_one = working[4].rotate_right(6)
                ^ working[4].rotate_right(11)
                ^ working[4].rotate_right(25);
            let choice = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
            let temp_one = working[7]
                .wrapping_add(big_one)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(schedule_word);
            let big_zero = working[0].rotate_right(2)
                ^ working[0].rotate_right(13)
                ^ working[0].rotate_right(22);
            let majority =
                (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
            let temp_two = big_zero.wrapping_add(majority);
            working[7] = working[6];
            working[6] = working[5];
            working[5] = working[4];
            working[4] = working[3].wrapping_add(temp_one);
            working[3] = working[2];
            working[2] = working[1];
            working[1] = working[0];
            working[0] = temp_one.wrapping_add(temp_two);
        }
        for (slot, word) in state.iter_mut().zip(working.iter()) {
            *slot = slot.wrapping_add(*word);
        }
    }
    let mut digest = [0_u8; 32];
    for (index, word) in state.iter().enumerate() {
        let offset = index.saturating_mul(4);
        digest[offset..offset.saturating_add(4)].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

#[cfg(test)]
mod tests {
    //! R1 byte-identity: the child derivation matches the owner-side mirror
    //! (`bins/eliot-kernel/src/dispatch_launch.rs`) for the same fixed vector.
    //! Both files assert the same literals; agreement here is the interop proof.

    use super::*;
    use eliot_process::{
        EnvironmentInheritance, EnvironmentProjection, Generation, ImageId, JobId, OperationId,
        ProcessTreeId, ResourceLimits, SessionId as ProcessSessionId,
    };

    /// Unwraps one issuance fixture without `expect` (this module carries
    /// no test `expect` allow, and none is added): a fixture failure
    /// panics with the failing step named.
    fn must<T, E: std::fmt::Debug>(result: Result<T, E>, what: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("dispatch-r1 issuance fixture failed ({what}): {error:?}"),
        }
    }

    /// Builds the canonical test intent for one issuance pin: every identity
    /// fixed, the executable bound to the real test-binary bytes (never a
    /// canned digest), arg-less argv, and a secret-free environment.
    fn issuance_intent() -> ProcessIntent {
        let exe = must(std::env::current_exe(), "test executable path");
        let image_bytes = must(std::fs::read(&exe), "test image reads");
        let image_digest = hex_bytes(&sha256_bytes(&image_bytes));
        let generation = must(Generation::new(7), "issuance generation");
        let environment = must(
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None),
            "issuance environment",
        );
        let limits = must(
            ResourceLimits::new(30_000, None, None, 4_096, 4_096, 4),
            "issuance limits",
        );
        must(
            ProcessIntent::new(
                must(
                    OperationId::new("operation-dispatch-r1-001"),
                    "operation id",
                ),
                must(ProcessTreeId::new("tree-dispatch-r1-001"), "tree id"),
                must(JobId::new("parent-job-dispatch-r1-001"), "job id"),
                must(ImageId::new("image-dispatch-r1-001"), "image id"),
                must(
                    ProcessSessionId::new("session-dispatch-r1-001"),
                    "session id",
                ),
                generation,
                std::env::temp_dir().to_string_lossy().into_owned(),
                image_digest,
                Vec::new(),
                std::env::temp_dir().to_string_lossy().into_owned(),
                environment,
                limits,
            ),
            "issuance intent builds",
        )
    }

    #[test]
    fn child_dispatch_derivation_matches_owner_vector() {
        let epoch_json = serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 3,
        });
        let authority = NativeWorkerDispatchAuthority::new(
            "claim-dispatch-r1-001",
            "operation-dispatch-r1-001",
            7,
            &epoch_json,
            "launch-nonce-r1-0001-abcdef0123",
        )
        .expect("child derivation builds");
        assert_eq!(
            authority.derivation_base,
            "[\"eliot-native-worker-dispatch/v1\",\"claim-dispatch-r1-001\",\"operation-dispatch-r1-001\",7,{\"lineage_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"sequence\":3},\"launch-nonce-r1-0001-abcdef0123\"]"
        );
        assert_eq!(
            hex_bytes(&tagged_hash("key", &authority.derivation_base)),
            "4c82b9a89995676ac0d0114db3615a47a8de2f9e59080c59d8354af881211f16"
        );
        assert_eq!(
            format!(
                "native-worker-dispatch-authority-{}",
                hex_bytes(&tagged_hash("authority", &authority.derivation_base))
            ),
            "native-worker-dispatch-authority-4354a8cb909128f86c445a7c19de3e0345b5b1f63e5dfbfe3a20ce6e6da3a6ff"
        );
        assert_eq!(
            hex_bytes(&tagged_hash("head", &authority.derivation_base)),
            "d0fb93eaece8fc98051cd9501616d9c9f4eb8f755cc010931a6b2b80aac32197"
        );
        assert_eq!(
            DISPATCH_DERIVATION_DOMAIN,
            "eliot-native-worker-dispatch/v1"
        );
        assert_eq!(LAUNCH_GRANT_HEAD, "launch-grant");
    }

    /// R1 issuance pin (Implements #22): two independent authorities
    /// derived from identical admitted material must issue byte-identical
    /// invocation digests through the production issuance entries — this
    /// replay-stability is what lets the owner publish the matching join.
    /// A distinct launch nonce must diverge. Real constructors, real
    /// crypto, no transport, no doubles.
    #[test]
    fn dispatch_issuance_is_replay_stable_and_nonce_bound() {
        use eliot_contracts::EpochId;

        let epoch_json = serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 3,
        });
        let epoch: EpochId = must(
            serde_json::from_value(epoch_json.clone()),
            "issuance epoch parses",
        );
        let fence = must(
            FencingToken::new(
                epoch,
                must(Generation::new(7), "fence generation"),
                "fence-r1-001".to_owned(),
            ),
            "issuance fence builds",
        );
        let lease = must(
            ActionLeaseRef::new("lease-r1-001".to_owned()),
            "issuance lease builds",
        );
        let grant_image = hex_bytes(&sha256_bytes(b"dispatch-r1 grant identity"));
        // Fixed freshness window: wall-clock never enters the permit, only
        // the file-derived window the Kernel proves at admission.
        let issued_at = 4_000_000_000_000_u64;
        let expires_at = 4_000_001_000_000_u64;
        let now_ms = 4_000_000_500_000_u64;
        let grant = must(
            ValidatedDispatchGrant::new(fence, lease, grant_image, issued_at, expires_at),
            "issuance grant validates",
        );

        let nonce = "launch-nonce-r1-0001-abcdef0123";
        let first = must(
            NativeWorkerDispatchAuthority::new(
                "claim-dispatch-r1-001",
                "operation-dispatch-r1-001",
                7,
                &epoch_json,
                nonce,
            ),
            "first authority derives",
        );
        let second = must(
            NativeWorkerDispatchAuthority::new(
                "claim-dispatch-r1-001",
                "operation-dispatch-r1-001",
                7,
                &epoch_json,
                nonce,
            ),
            "second authority derives",
        );
        let intent = issuance_intent();
        let first_process = must(
            first.issue(&intent, &grant, nonce, now_ms),
            "first issuance",
        );
        let second_process = must(
            second.issue(&intent, &grant, nonce, now_ms),
            "second issuance",
        );
        assert_eq!(
            first_process.invocation_digest(),
            second_process.invocation_digest(),
            "identical admitted material must issue the identical invocation digest"
        );
        assert_eq!(
            first_process.invocation_digest().len(),
            64,
            "invocation digest is SHA-256 hex"
        );

        let other_nonce = "launch-nonce-r1-0002-abcdef0123";
        let other = must(
            NativeWorkerDispatchAuthority::new(
                "claim-dispatch-r1-001",
                "operation-dispatch-r1-001",
                7,
                &epoch_json,
                other_nonce,
            ),
            "third authority derives",
        );
        let other_process = must(
            other.issue(&intent, &grant, other_nonce, now_ms),
            "third issuance",
        );
        assert_ne!(
            first_process.invocation_digest(),
            other_process.invocation_digest(),
            "a distinct launch nonce must issue a distinct invocation digest"
        );
    }
}
