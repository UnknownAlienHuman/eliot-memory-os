//! In-child P-03 dispatch authority for the WASM dispatch contour (issue
//! #1955, I14.19).
//!
//! Mirrors the native-worker broker pattern
//! (`bins/eliot-native-worker/src/dispatch_authority.rs`,
//! `NativeWorkerDispatchAuthority`, itself mirroring the merged User Broker
//! pattern): a local struct holding a [`DispatchPermitAuthority`] plus an
//! optional [`DispatchValidationContext`], with `new` / `issue` /
//! `validate_and_consume` entries, fronting the real
//! [`WindowsProcessExecutor`](eliot_process_executor::WindowsProcessExecutor).
//! Deriving the one-shot permit inside the child from the Kernel-issued
//! dispatch material is the documented broker pattern, not minted
//! authority: the Kernel still owns the grant, the epoch, the fence, and
//! the validation context, and every value below is re-proved against them
//! fail-closed.
//!
//! Deterministic issuance (no fresh entropy): the owner-side publisher
//! (`eliot-kernel-service::wasm_dispatch`) runs the identical forward
//! computation from pre-binding admitted material and embeds the matching
//! digests, so the published join closes. Base, key, authority identity,
//! and head construction are byte-identical to the owner mirror; the R1
//! fixed vectors asserted literally here and there are the interop proof.
//!
//! ```text
//! base      = ["eliot-wasm-host-dispatch/v1", claim_id, operation_id,
//!              generation, authority_epoch_json, launch_nonce]
//! key       = SHA-256("key:" + base_json)
//! authority = "wasm-host-dispatch-authority-" + hex(SHA-256("authority:" + base_json))
//! nonce     = the claim-bound launch nonce
//! heads     = {"wasm-launch-grant": hex(SHA-256("head:" + base_json))}
//! issued    = admitted_at_unix_ms (the grant window opens at admission by
//!             kernel construction)
//! expires   = grant.expires_at
//! ```
//!
//! Permits never leave this process (`ProcessRequest` is `Serialize`-only
//! by design and is never deserialized here). Hashing uses the real
//! `Sha256Digest` byte identity — no parallel implementation to drift.

use std::collections::BTreeMap;
use std::sync::Mutex;

use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    FencingToken, KernelDispatchKey, PermitIssuance, ProcessExecutionError, ProcessIntent,
    ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
};
use eliot_wasm_runtime::Sha256Digest;

/// Deterministic dispatch derivation domain for the WASM child contour.
/// Byte-identical to the owner mirror.
pub const WASM_DISPATCH_DERIVATION_DOMAIN: &str = "eliot-wasm-host-dispatch/v1";
/// Single revision head name, byte-identical to the owner mirror.
pub const WASM_LAUNCH_GRANT_HEAD: &str = "wasm-launch-grant";
/// Authority identity prefix, byte-identical to the owner mirror.
pub const WASM_DISPATCH_AUTHORITY_PREFIX: &str = "wasm-host-dispatch-authority-";
/// Validation revision carried on every issuance and its context.
pub const WASM_VALIDATION_REVISION: u64 = 1;

/// Fail-closed dispatch-authority errors. Stable codes only — no material,
/// paths, or digests echoed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DispatchAuthorityError {
    /// Admitted material failed shape validation.
    InvalidMaterial {
        /// Stable field name.
        field: &'static str,
    },
    /// The authority is unusable (stale grant, lock, missing context).
    Unavailable {
        /// Stable field name.
        field: &'static str,
    },
}

impl std::fmt::Display for DispatchAuthorityError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidMaterial { field } => {
                write!(formatter, "WASM_DISPATCH_INVALID_MATERIAL:{field}")
            }
            Self::Unavailable { field } => {
                write!(formatter, "WASM_DISPATCH_UNAVAILABLE:{field}")
            }
        }
    }
}

impl std::error::Error for DispatchAuthorityError {}

/// Kernel-issued dispatch grant after fail-closed validation, ready to issue.
///
/// Carries exactly the broker issuance inputs: the fence and lease rebuilt
/// through their production constructors from the grant fields, the opaque
/// grant digest retained for correlation, and the file-derived freshness
/// window. The authority epoch is proven equal to the admitted claim epoch
/// before construction; the fence already carries the proven value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedDispatchGrant {
    /// Fence rebuilt via `FencingToken::new` from the grant fields.
    fence: FencingToken,
    /// Lease rebuilt via `ActionLeaseRef::new` from the grant lease.
    lease: ActionLeaseRef,
    /// Opaque grant digest; never inverted, only retained for correlation.
    grant_digest: String,
    /// Window opening: receipt admission time carried in the file.
    issued_at: u64,
    /// Grant expiry in Unix milliseconds for `PermitIssuance::new`.
    expires_at: u64,
}

impl ValidatedDispatchGrant {
    /// Builds one validated grant from its already-proven parts.
    /// Re-checks digest shape and window so misuse still fails closed.
    pub fn new(
        fence: FencingToken,
        lease: ActionLeaseRef,
        grant_digest: String,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, DispatchAuthorityError> {
        if grant_digest.len() != 64
            || !grant_digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(DispatchAuthorityError::InvalidMaterial {
                field: "grant-digest",
            });
        }
        if issued_at == 0 || expires_at <= issued_at {
            return Err(DispatchAuthorityError::InvalidMaterial {
                field: "grant-window",
            });
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
    #[must_use]
    pub const fn fence(&self) -> &FencingToken {
        &self.fence
    }

    /// Returns the rebuilt action lease.
    #[must_use]
    pub const fn lease(&self) -> &ActionLeaseRef {
        &self.lease
    }

    /// Returns the opaque grant digest.
    #[must_use]
    pub fn grant_digest(&self) -> &str {
        &self.grant_digest
    }

    /// Returns the window opening in Unix milliseconds.
    #[must_use]
    pub const fn issued_at(&self) -> u64 {
        self.issued_at
    }

    /// Returns the grant expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Returns the fence generation bound at admission.
    #[must_use]
    pub fn fence_generation(&self) -> u64 {
        self.fence.generation().get()
    }
}

/// In-child P-03 dispatch authority for the WASM contour.
///
/// The issuance tuple is derived per admitted claim. Key material lives
/// only in this struct: never serialized, logged, or transported, and
/// dropped with the process.
pub struct WasmDispatchAuthority {
    /// Issuing and consuming authority; the one-shot nonce ledger lives here.
    authority: Mutex<DispatchPermitAuthority>,
    /// Current validation snapshot installed at issue time.
    context: Mutex<Option<DispatchValidationContext>>,
    /// Canonical derivation base; the head digest re-derives from it at
    /// issue time so issuance and context agree exactly.
    derivation_base: String,
}

impl WasmDispatchAuthority {
    /// Derives one authority instance for exactly one admitted claim.
    /// All inputs are pre-binding admitted material: the owner-side
    /// publisher runs the identical computation.
    pub fn new(
        claim_id: &str,
        operation_id: &str,
        generation: u64,
        authority_epoch_json: &serde_json::Value,
        launch_nonce: &str,
    ) -> Result<Self, DispatchAuthorityError> {
        if claim_id.trim().is_empty()
            || operation_id.trim().is_empty()
            || launch_nonce.trim().is_empty()
        {
            return Err(DispatchAuthorityError::InvalidMaterial {
                field: "derivation-identities",
            });
        }
        if generation == 0 {
            return Err(DispatchAuthorityError::InvalidMaterial {
                field: "derivation-generation",
            });
        }
        let base = serde_json::to_string(&serde_json::json!([
            WASM_DISPATCH_DERIVATION_DOMAIN,
            claim_id,
            operation_id,
            generation,
            authority_epoch_json,
            launch_nonce,
        ]))
        .map_err(|_| DispatchAuthorityError::InvalidMaterial {
            field: "derivation-base",
        })?;
        let key =
            KernelDispatchKey::from_secret_bytes(tagged_hash("key", &base)).map_err(|_| {
                DispatchAuthorityError::InvalidMaterial {
                    field: "derivation-key",
                }
            })?;
        let authority_id = DispatchAuthorityId::new(format!(
            "{WASM_DISPATCH_AUTHORITY_PREFIX}{}",
            hex_bytes(&tagged_hash("authority", &base))
        ))
        .map_err(|_| DispatchAuthorityError::InvalidMaterial {
            field: "derivation-authority",
        })?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
            derivation_base: base,
        })
    }

    /// Issues one permit bound to the exact immutable intent.
    /// Freshness is file-derived (receipt admission time through grant
    /// expiry, never wall time, so replays rebuild the identical permit).
    /// A stale grant is refused without effect.
    pub fn issue(
        &self,
        intent: &ProcessIntent,
        grant: &ValidatedDispatchGrant,
        launch_nonce: &str,
        now_ms: u64,
    ) -> Result<ProcessRequest, DispatchAuthorityError> {
        if now_ms == 0 {
            return Err(DispatchAuthorityError::Unavailable { field: "clock" });
        }
        if grant.expires_at() <= now_ms {
            return Err(DispatchAuthorityError::Unavailable {
                field: "grant-window",
            });
        }
        if launch_nonce.trim().is_empty() {
            return Err(DispatchAuthorityError::InvalidMaterial {
                field: "launch-nonce",
            });
        }
        let head_digest = hex_bytes(&tagged_hash("head", &self.derivation_base));
        let issuance = PermitIssuance::new(
            grant.lease().clone(),
            grant.fence().clone(),
            BTreeMap::from([(WASM_LAUNCH_GRANT_HEAD.to_owned(), head_digest.clone())]),
            grant.issued_at(),
            grant.expires_at(),
            launch_nonce.to_owned(),
        )
        .map_err(|_| DispatchAuthorityError::InvalidMaterial {
            field: "permit-issuance",
        })?;
        let permit = self
            .authority
            .lock()
            .map_err(|_| DispatchAuthorityError::Unavailable {
                field: "authority-lock",
            })?
            .issue(intent, issuance)
            .map_err(|_| DispatchAuthorityError::InvalidMaterial {
                field: "permit-issue",
            })?;
        let context = validation_context(now_ms, grant.fence(), &head_digest)?;
        *self
            .context
            .lock()
            .map_err(|_| DispatchAuthorityError::Unavailable {
                field: "context-lock",
            })? = Some(context);
        ProcessRequest::new(intent.clone(), permit).map_err(|_| {
            DispatchAuthorityError::InvalidMaterial {
                field: "process-request",
            }
        })
    }

    /// Validates fresh P-02 launch evidence and consumes a permit exactly once.
    pub fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        let current = self
            .context
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("wasm context lock poisoned".to_owned())
            })?
            .clone()
            .ok_or_else(|| {
                ProcessExecutionError::Unavailable("missing wasm validation context".to_owned())
            })?;
        self.authority
            .lock()
            .map_err(|_| {
                ProcessExecutionError::Unavailable("wasm authority lock poisoned".to_owned())
            })?
            .validate_and_consume(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}

impl eliot_process_executor::DispatchValidationPort for WasmDispatchAuthority {
    fn validate_and_consume(
        &self,
        request: ProcessRequest,
        observed: SuspendedProcessIdentity,
    ) -> Result<ValidatedDispatch, ProcessExecutionError> {
        WasmDispatchAuthority::validate_and_consume(self, request, observed)
    }
}

/// Builds the current validation snapshot for one issuance.
///
/// The `DispatchValidationContext` constructor needs the platform clock
/// type, which this crate cannot name (no `eliot-platform` dependency and
/// none is added). The context type is `Serialize`/`Deserialize`, so the
/// snapshot is built through its canonical JSON shape instead: the fence
/// and epoch serialize from the live values already held here, the head
/// map repeats the issuance head exactly, and only the scalar clock
/// observation is written by hand. A shape drift fails closed here and
/// again at consume time, never silently.
fn validation_context(
    now_ms: u64,
    fence: &FencingToken,
    head_digest: &str,
) -> Result<DispatchValidationContext, DispatchAuthorityError> {
    let now = i64::try_from(now_ms).map_err(|_| DispatchAuthorityError::Unavailable {
        field: "clock-range",
    })?;
    let fence_value =
        serde_json::to_value(fence).map_err(|_| DispatchAuthorityError::InvalidMaterial {
            field: "fence-shape",
        })?;
    let epoch_value = serde_json::to_value(fence.authority_epoch()).map_err(|_| {
        DispatchAuthorityError::InvalidMaterial {
            field: "epoch-shape",
        }
    })?;
    let context_value = serde_json::json!({
        "clock": {
            "valid_time_ms": now,
            "known_time_ms": now,
            "transaction_sequence": null,
            "monotonic_ns": 1,
        },
        "state_fence": fence_value,
        "authority_epoch": epoch_value,
        "revision_heads": {WASM_LAUNCH_GRANT_HEAD: head_digest},
        "validation_revision": WASM_VALIDATION_REVISION,
    });
    serde_json::from_value(context_value).map_err(|_| DispatchAuthorityError::InvalidMaterial {
        field: "context-shape",
    })
}

/// Hashes one domain-separated derivation input: `SHA-256(tag + ":" +
/// base_json)` over the real byte identity.
fn tagged_hash(tag: &str, base_json: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(tag.len().saturating_add(1).saturating_add(base_json.len()));
    input.extend_from_slice(tag.as_bytes());
    input.push(b':');
    input.extend_from_slice(base_json.as_bytes());
    let digest = Sha256Digest::of_bytes(&input);
    let mut bytes = [0_u8; 32];
    for (index, chunk) in digest.as_str().as_bytes().chunks(2).enumerate() {
        bytes[index] =
            u8::from_str_radix(std::str::from_utf8(chunk).unwrap_or("00"), 16).unwrap_or(0);
    }
    bytes
}

/// Lowercase hex encoding of 32 digest bytes.
fn hex_bytes(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0F)]));
    }
    output
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use eliot_process::{Generation, SessionId};

    fn epoch_json() -> serde_json::Value {
        serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 3
        })
    }

    /// R1 child vector: the owner mirror asserts the identical `base_json`
    /// (`eliot-kernel-service::wasm_dispatch` tests). Agreement is the
    /// interop proof.
    #[test]
    fn child_derivation_matches_owner_vector() {
        let authority = WasmDispatchAuthority::new(
            "claim-wasm-r1-001",
            "operation-wasm-r1-001",
            7,
            &epoch_json(),
            "launch-nonce-wasm-r1-0001",
        )
        .expect("child derivation builds");
        assert_eq!(
            authority.derivation_base,
            "[\"eliot-wasm-host-dispatch/v1\",\"claim-wasm-r1-001\",\"operation-wasm-r1-001\",7,{\"lineage_id\":\"550e8400-e29b-41d4-a716-446655440000\",\"sequence\":3},\"launch-nonce-wasm-r1-0001\"]"
        );
        assert_eq!(
            WASM_DISPATCH_DERIVATION_DOMAIN,
            "eliot-wasm-host-dispatch/v1"
        );
        assert_eq!(WASM_LAUNCH_GRANT_HEAD, "wasm-launch-grant");
        assert_eq!(
            WASM_DISPATCH_AUTHORITY_PREFIX,
            "wasm-host-dispatch-authority-"
        );
    }

    #[test]
    fn blank_derivation_inputs_fail_closed() {
        assert!(matches!(
            WasmDispatchAuthority::new("", "op", 7, &epoch_json(), "n"),
            Err(DispatchAuthorityError::InvalidMaterial { .. })
        ));
        assert!(matches!(
            WasmDispatchAuthority::new("c", "op", 0, &epoch_json(), "n"),
            Err(DispatchAuthorityError::InvalidMaterial { .. })
        ));
    }

    fn test_fence() -> FencingToken {
        use eliot_contracts::EpochId;
        let epoch: EpochId = serde_json::from_value(epoch_json()).expect("test epoch parses");
        FencingToken::new(
            epoch,
            Generation::new(7).expect("generation"),
            "fence-r1-001".to_owned(),
        )
        .expect("test fence builds")
    }

    fn test_grant() -> ValidatedDispatchGrant {
        ValidatedDispatchGrant::new(
            test_fence(),
            ActionLeaseRef::new("lease-r1-001".to_owned()).expect("lease"),
            "e".repeat(64),
            4_000_000_000_000,
            4_000_001_000_000,
        )
        .expect("test grant validates")
    }

    fn test_intent() -> ProcessIntent {
        use eliot_process::{
            EnvironmentInheritance, EnvironmentProjection, ImageId, JobId, OperationId,
            ProcessTreeId, ResourceLimits,
        };
        use std::collections::BTreeMap;
        let environment =
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .expect("environment");
        let limits = ResourceLimits::new(30_000, None, None, 4_096, 4_096, 4).expect("limits");
        ProcessIntent::new(
            OperationId::new("operation-wasm-r1-001").expect("operation"),
            ProcessTreeId::new("tree-wasm-r1-001").expect("tree"),
            JobId::new("job-wasm-r1-001").expect("job"),
            ImageId::new("image-wasm-r1-001").expect("image"),
            SessionId::new("session-wasm-r1-001").expect("session"),
            Generation::new(7).expect("generation"),
            std::env::temp_dir().to_string_lossy().into_owned(),
            "f".repeat(64),
            Vec::new(),
            std::env::temp_dir().to_string_lossy().into_owned(),
            environment,
            limits,
        )
        .expect("intent builds")
    }

    /// Replay stability: two independent authorities from identical
    /// admitted material issue byte-identical invocation digests; a
    /// distinct nonce diverges. Real constructors, no transport.
    #[test]
    fn issuance_is_replay_stable_and_nonce_bound() {
        let nonce = "launch-nonce-wasm-r1-0001";
        let first = WasmDispatchAuthority::new(
            "claim-wasm-r1-001",
            "operation-wasm-r1-001",
            7,
            &epoch_json(),
            nonce,
        )
        .expect("first authority derives");
        let second = WasmDispatchAuthority::new(
            "claim-wasm-r1-001",
            "operation-wasm-r1-001",
            7,
            &epoch_json(),
            nonce,
        )
        .expect("second authority derives");
        let grant = test_grant();
        let intent = test_intent();
        let now_ms = 4_000_000_500_000_u64;
        let first_process = first
            .issue(&intent, &grant, nonce, now_ms)
            .expect("first issuance");
        let second_process = second
            .issue(&intent, &grant, nonce, now_ms)
            .expect("second issuance");
        assert_eq!(
            first_process.invocation_digest(),
            second_process.invocation_digest(),
            "identical admitted material must issue the identical invocation digest"
        );
        let other = WasmDispatchAuthority::new(
            "claim-wasm-r1-001",
            "operation-wasm-r1-001",
            7,
            &epoch_json(),
            "launch-nonce-wasm-r1-0002",
        )
        .expect("third authority derives");
        let other_process = other
            .issue(&intent, &grant, "launch-nonce-wasm-r1-0002", now_ms)
            .expect("third issuance");
        assert_ne!(
            first_process.invocation_digest(),
            other_process.invocation_digest(),
            "a distinct launch nonce must issue a distinct invocation digest"
        );
    }

    #[test]
    fn stale_grant_and_blank_nonce_refuse_without_effect() {
        let authority = WasmDispatchAuthority::new(
            "claim-wasm-r1-001",
            "operation-wasm-r1-001",
            7,
            &epoch_json(),
            "launch-nonce-wasm-r1-0001",
        )
        .expect("authority derives");
        let grant = test_grant();
        let intent = test_intent();
        // Expired window: refused.
        assert_eq!(
            authority.issue(
                &intent,
                &grant,
                "launch-nonce-wasm-r1-0001",
                4_000_001_000_000
            ),
            Err(DispatchAuthorityError::Unavailable {
                field: "grant-window"
            })
        );
        // Blank nonce: refused.
        assert!(matches!(
            authority.issue(&intent, &grant, "", 4_000_000_500_000),
            Err(DispatchAuthorityError::InvalidMaterial { .. })
        ));
    }

    /// R1 join mirror: the identical forward issuance the owner runs in
    /// `eliot-kernel-service::wasm_dispatch::wasm_join_gate` over the same
    /// admitted values must produce the identical invocation digest. The
    /// owner test pins the same literal; agreement is the join interop
    /// proof — the owner-published join closes if and only if this
    /// derivation matches. Pure crypto, no filesystem, no spawn.
    #[test]
    fn join_issuance_matches_owner_vector() {
        use eliot_process::{
            EnvironmentInheritance, EnvironmentProjection, ImageId, JobId, OperationId,
            ProcessTreeId, ResourceLimits, SessionId,
        };
        use std::collections::BTreeMap;

        let nonce = "launch-nonce-wasm-join-0001";
        let authority = WasmDispatchAuthority::new(
            "claim-wasm-join-001",
            "operation-wasm-join-001",
            7,
            &epoch_json_for_join(),
            nonce,
        )
        .expect("join authority derives");
        let epoch: eliot_contracts::EpochId =
            serde_json::from_value(epoch_json_for_join()).expect("join epoch parses");
        let fence = FencingToken::new(
            epoch,
            Generation::new(7).expect("generation"),
            "wasm-host-launch-fence-aaaaaaaaaaaaaaaa".to_owned(),
        )
        .expect("join fence builds");
        let grant = ValidatedDispatchGrant::new(
            fence,
            ActionLeaseRef::new("wasm-host-launch-lease-aaaaaaaaaaaaaaaa".to_owned())
                .expect("lease"),
            "e".repeat(64),
            4_000_000_000_000,
            4_000_000_060_000,
        )
        .expect("join grant validates");
        let artifact_digest = Sha256Digest::of_bytes(b"join-artifact-bytes");
        let environment =
            EnvironmentProjection::new(BTreeMap::new(), Vec::new(), EnvironmentInheritance::None)
                .expect("environment");
        let limits =
            ResourceLimits::new(30_000, None, Some(536_870_912), 4096, 4096, 1).expect("limits");
        let intent = ProcessIntent::new(
            OperationId::new("operation-wasm-join-001").expect("operation"),
            ProcessTreeId::new("scope-1955").expect("tree"),
            JobId::new("operation-wasm-join-001").expect("job"),
            ImageId::new("wasm-host-image-dddddddddddddddd").expect("image"),
            SessionId::new("claim-wasm-join-001").expect("session"),
            Generation::new(7).expect("generation"),
            "C:\\Kernel\\eliot-wasm-host.exe",
            "d".repeat(64),
            vec![
                "--profile".to_owned(),
                "D2_OPERATIONAL".to_owned(),
                "--guest-exec".to_owned(),
                "--guest-exec-artifact".to_owned(),
                "C:\\Kernel\\eliot-wasm-host.guest-artifact.bin".to_owned(),
                "--guest-exec-input".to_owned(),
                "C:\\Kernel\\eliot-wasm-host.guest-input.bin".to_owned(),
                "--guest-exec-artifact-digest".to_owned(),
                artifact_digest.as_str().to_owned(),
                "--guest-exec-max-output".to_owned(),
                "4096".to_owned(),
                "--guest-exec-max-fuel".to_owned(),
                "100000".to_owned(),
                "--guest-exec-max-memory".to_owned(),
                "536870912".to_owned(),
                "--guest-exec-wall-ms".to_owned(),
                "30000".to_owned(),
                "--guest-exec-epoch-ticks".to_owned(),
                "100".to_owned(),
            ],
            "C:\\Kernel",
            environment,
            limits,
        )
        .expect("join intent builds");
        let issued = authority
            .issue(&intent, &grant, nonce, 4_000_000_030_000)
            .expect("join issuance");
        assert_eq!(
            issued.invocation_digest(),
            "5ac10e759c80ae9256faf09b1cf420635c3b917593f5f1f57e57fe95000914eb"
        );
    }

    fn epoch_json_for_join() -> serde_json::Value {
        serde_json::json!({
            "lineage_id": "550e8400-e29b-41d4-a716-446655440000",
            "sequence": 3
        })
    }

    #[test]
    fn tagged_hash_matches_byte_identity() {
        // The hex decode/encode round-trips the trusted primitive exactly:
        // any drift here would break owner interop silently.
        let base = "r1-round-trip-base";
        assert_eq!(
            hex_bytes(&tagged_hash("head", base)),
            Sha256Digest::of_bytes(format!("head:{base}").as_bytes()).as_str()
        );
        assert_eq!(
            hex_bytes(&tagged_hash("key", base)),
            Sha256Digest::of_bytes(format!("key:{base}").as_bytes()).as_str()
        );
    }
}
