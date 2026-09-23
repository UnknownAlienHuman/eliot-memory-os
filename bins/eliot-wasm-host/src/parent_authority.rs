//! Owner-derived P03 parent dispatch authority (issue #1955).
//!
//! Every bound value is recomputed here through the canonical owner
//! derivation contract (`wasm_dispatch_derivation_from_epoch_json` shape in
//! `crates/kernel/eliot-kernel-service/src/wasm_dispatch.rs` at `7f157a7b`,
//! unchanged through the `2f30cb67` lane merge — see constants below) from
//! validated admitted material, so this drive's key, authority identity,
//! heads, nonce, window, and invocation digest are byte-identical to the
//! owner `WasmJoinTable` record and admit instead of `Mismatched`-deny. The
//! `DispatchPermitAuthority` state machine still enforces issuance and
//! consumption locally (one-shot nonce ledgers, fence/epoch/heads
//! agreement, window check); it carries owner values, never local
//! inventions. Issuance opens at the owner admission time: no backdated
//! local clock enters the permit. Owner time arrives as `now_ms` from the
//! composition edge for the validation context only. Failures refuse
//! fail-closed without echoing owner internals.
//!
//! Trust boundary (for the Gauss/A3 caller): this authority is a
//! process-confined enforcement binding over owner-derived values, NOT
//! canonical owner authority. Its digests match the owner join table if and
//! only if every intent string (notably the executable and
//! working-directory spellings) matches the owner derivation inputs
//! byte-for-byte; a spelling skew fails closed at the join, never silently.

use std::collections::BTreeMap;
use std::sync::Mutex;

use eliot_contracts::{sha256_hex, EpochId};
use eliot_platform::ClockObservation;
use eliot_process::{
    ActionLeaseRef, DispatchAuthorityId, DispatchPermitAuthority, DispatchValidationContext,
    FencingToken, Generation, KernelDispatchKey, PermitIssuance, ProcessExecutionError,
    ProcessIntent, ProcessRequest, SuspendedProcessIdentity, ValidatedDispatch,
};

use crate::dispatch_drive::DriveError;
use crate::dispatch_material::ValidatedDispatchMaterial;

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

/// Owner derivation domain, byte-identical to
/// `WASM_DISPATCH_DERIVATION_DOMAIN` in `wasm_dispatch.rs` (verified above).
/// Wire-stable protocol constant: changing it breaks the owner join on both
/// sides, so any change must land there first and be mirrored here.
const OWNER_DERIVATION_DOMAIN: &str = "eliot-wasm-host-dispatch/v1";

/// Owner authority-identity prefix, byte-identical to
/// `WASM_DISPATCH_AUTHORITY_PREFIX` in `wasm_dispatch.rs` (verified above).
const OWNER_AUTHORITY_PREFIX: &str = "wasm-host-dispatch-authority-";

/// Owner launch-grant head key, byte-identical to
/// `WASM_DISPATCH_LAUNCH_GRANT_HEAD` in `wasm_dispatch.rs` (verified above).
const OWNER_LAUNCH_GRANT_HEAD: &str = "wasm-launch-grant";

/// Lowercase hex of `SHA-256(tag + ":" + base)`, exactly like the owner
/// `dispatch_tagged_hex`.
fn owner_tagged_hex(tag: &str, base_json: &str) -> String {
    let mut material =
        String::with_capacity(tag.len().saturating_add(1).saturating_add(base_json.len()));
    material.push_str(tag);
    material.push(':');
    material.push_str(base_json);
    sha256_hex(material.as_bytes())
}

/// Decodes 64 lowercase-hex characters into 32 key bytes. Pure hex parsing,
/// no authority semantics.
fn decode_key_hex(hex: &str) -> Result<[u8; 32], DriveError> {
    if hex.len() != 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(contract_denied("derivation-key"));
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    for (index, slot) in out.iter_mut().enumerate() {
        let pair = std::str::from_utf8(&bytes[2 * index..2 * index + 2])
            .map_err(|_| contract_denied("derivation-key"))?;
        *slot = u8::from_str_radix(pair, 16).map_err(|_| contract_denied("derivation-key"))?;
    }
    Ok(out)
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
    /// Activates one parent authority around the owner-derived key.
    ///
    /// The key, authority identity, heads, nonce, and window all derive
    /// through [`owner_derivation`] below — byte-identical to the owner
    /// `WasmJoinTable` record for the same admitted material.
    pub fn activate(
        material: &ValidatedDispatchMaterial,
        epoch: &EpochId,
    ) -> Result<Self, DriveError> {
        let derived = owner_derivation(material, epoch)?;
        let authority_id = DispatchAuthorityId::new(derived.authority_id)
            .map_err(|_| contract_denied("authority-id"))?;
        let key = KernelDispatchKey::from_secret_bytes(derived.key_bytes)
            .map_err(|_| contract_denied("authority-key"))?;
        Ok(Self {
            authority: Mutex::new(DispatchPermitAuthority::activate(authority_id, key)),
            context: Mutex::new(None),
        })
    }
}

/// Owner derivation values recomputed from validated admitted material.
///
/// Byte-identical forward computation to owner
/// `wasm_dispatch_derivation_from_epoch_json`: base array
/// `[domain, claim, operation, generation, epoch-json, nonce]`
/// serialized once, then domain-separated `SHA-256(tag + ":" + base)`.
/// The epoch JSON round-trips through the TYPED [`EpochId`] (parse then
/// `to_value`), exactly like the owner pipeline, so struct field order —
/// and therefore every digest — agrees by construction.
struct OwnerDerivation {
    authority_id: String,
    key_bytes: [u8; 32],
    head_digest: String,
}

fn owner_derivation(
    material: &ValidatedDispatchMaterial,
    epoch: &EpochId,
) -> Result<OwnerDerivation, DriveError> {
    if material.claim_id.trim().is_empty()
        || material.operation_id.trim().is_empty()
        || material.launch_nonce.trim().is_empty()
    {
        return Err(contract_denied("derivation-identities"));
    }
    if material.generation == 0 {
        return Err(contract_denied("derivation-generation"));
    }
    let epoch_json =
        serde_json::to_value(epoch).map_err(|_| contract_denied("derivation-epoch"))?;
    let base_json = serde_json::to_string(&serde_json::json!([
        OWNER_DERIVATION_DOMAIN,
        material.claim_id,
        material.operation_id,
        material.generation,
        epoch_json,
        material.launch_nonce,
    ]))
    .map_err(|_| contract_denied("derivation-base"))?;
    Ok(OwnerDerivation {
        authority_id: format!(
            "{OWNER_AUTHORITY_PREFIX}{}",
            owner_tagged_hex("authority", &base_json)
        ),
        key_bytes: decode_key_hex(&owner_tagged_hex("key", &base_json))?,
        head_digest: owner_tagged_hex("head", &base_json),
    })
}

impl ParentDispatchAuthority {
    /// Issues the single permit-bound process request for one admitted
    /// intent, one owner grant, and one owner-typed epoch.
    ///
    /// Owner-issuance parity with `wasm_join_gate`: heads
    /// `{"wasm-launch-grant": head}`, one-shot nonce = claim launch nonce,
    /// window opens at the owner admission time (never a backdated local
    /// clock — D2), closes at the grant expiry. The revision pin stays
    /// `None` via plain `new`, exactly like the owner gate: pinning a local
    /// revision the owner does not carry would diverge the permit bytes and
    /// re-break join identity (D3, explicitly declined for interop; a
    /// Store-bound revision needs an owner-side semantic first).
    pub fn issue_permit(
        &self,
        intent: &ProcessIntent,
        material: &ValidatedDispatchMaterial,
        epoch: &EpochId,
        now_ms: u64,
    ) -> Result<ProcessRequest, DriveError> {
        let grant = &material.grant;
        let derived = owner_derivation(material, epoch)?;
        let generation = Generation::new(grant.fence_generation)
            .map_err(|_| contract_denied("permit-generation"))?;
        let fence = FencingToken::new(epoch.clone(), generation, grant.fence_nonce.clone())
            .map_err(|_| contract_denied("permit-fence"))?;
        let lease = ActionLeaseRef::new(grant.idempotency_key.clone())
            .map_err(|_| contract_denied("permit-lease"))?;
        let heads = BTreeMap::from([(OWNER_LAUNCH_GRANT_HEAD.to_owned(), derived.head_digest)]);
        let issuance = PermitIssuance::new(
            lease,
            fence.clone(),
            heads.clone(),
            material.admitted_at_unix_ms,
            grant.expires_at,
            material.launch_nonce.clone(),
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
    /// Canonical consume: the exact-tuple gate (`StateFence::authorizes_canonical`
    /// inside `validate_and_consume_canonical`), chosen deliberately (D4) so
    /// this port enforces the same fence-authority agreement central
    /// validation will require — plain self-consistency is insufficient once
    /// the owner join consults these digests.
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
            .validate_and_consume_canonical(request, observed, &current)
            .map_err(ProcessExecutionError::from)
    }
}
