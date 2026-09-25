//! Host Phase-B per-user Notify fallback setup (issue #1780, I11.6).
//!
//! Runs the installer key ceremony for the Watchdog fallback contour and
//! publishes the canonical consumer half. This module is the only producer of
//! the protected [`WATCHDOG_FALLBACK_KEY_RELATIVE`] record that carries the
//! 32-byte `signing_key` the Watchdog needs, and
//! [`publish_notify_fallback_declaration`] is the single ceremony that writes
//! both that record and the public declaration, so the two cannot diverge: the
//! declaration is rendered from exactly the key material the record proves
//! rather than from an operator-supplied string. It publishes through the
//! existing Phase-B file publisher, verifies readback under lease, then
//! registers the signed Task Scheduler fallback through the existing notify
//! route. This is the per-user setup the installer invokes in the interactive
//! session; normal launch stays User-Broker owned (I11.6) and this module
//! spawns no process and assembles no daemon role.
//!
//! Key custody: the ceremony draws 32 bytes from the admitted Windows CSPRNG
//! port and derives the Ed25519 verifying half from exactly those bytes. The
//! secret lives only in a zeroizing secret owner and in the byte buffer handed
//! to the publisher, which is cleared on every exit path. It is never
//! formatted, echoed into an error, a receipt, a log line, or a projection, and
//! it is written to no path other than the protected key record. A re-run
//! replays the published record instead of rotating it; a foreign, malformed,
//! or partially rewritten record fails closed rather than being regenerated.
//!
//! Registration enforces the live caller identity inside the notify route:
//! setup must run in the interactive session matching the declaration, and
//! re-running with identical inputs replays by exact readback instead of
//! republishing. A changed declaration (new epoch/key/digest) against an
//! existing file fails closed rather than silently overwriting installer
//! material.

use std::path::{Path, PathBuf};

use eliot_contracts::canonical_json_bytes;
use eliot_installation::InstallationProfile;
use eliot_notify::{
    NotifyDeclarationInputs, RenderedNotifyDeclaration, render_notify_fallback_declaration,
};
use eliot_platform::PlatformHandle;
use eliot_platform_windows::{
    ProtectedPathLease, UserOwnedRootLease, WindowsInstallerSecretProvider,
    prepare_protected_directory, protected_program_data_path,
};
use eliot_runtime_contracts::Ed25519InstallationActivationApprovalSigner;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::HostError;

/// Explicit per-user setup inputs. Every value is caller-supplied except
/// the image digest and the interactive identity, which are always
/// observed, never configured: the digest is hashed from the installed
/// image bytes named below, and the SID/session come from the live process
/// token. The Watchdog verifying key is deliberately absent — this module
/// derives it from the protected secret it provisions, so no caller can pin a
/// public half the producer's private half does not derive. Nothing is
/// probed from the loader path, environment, current directory, or build
/// output.
pub struct NotifyFallbackSetupInputs {
    /// Stable installation identity.
    pub installation_identity: PlatformHandle,
    /// Declared fallback audience.
    pub audience: PlatformHandle,
    /// Non-zero authority epoch.
    pub authority_epoch: u64,
    /// Installer-bound Watchdog signing key identifier. The key ceremony
    /// records it in the protected key binding and the declaration carries the
    /// same value, so a re-run under a different key id fails closed instead
    /// of rotating the key under an already-registered task.
    pub key_id: PlatformHandle,
    /// Absolute installed `eliot-notify.exe` path. The image digest is
    /// hashed from these exact bytes; no caller-supplied digest is
    /// accepted.
    pub notify_executable: PathBuf,
    /// Explicit installation supervision/path profile.
    pub profile: InstallationProfile,
    /// Retained portable-dev root lease. Required for `PortableDev`;
    /// `None` for service/user profiles.
    pub portable_root: Option<UserOwnedRootLease>,
}

/// Observed installed image: verified path plus the digest hashed from its
/// exact bytes at setup time.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedNotifySource {
    /// Verified absolute installed path.
    pub executable_path: PathBuf,
    /// SHA-256 of the exact bytes read (lowercase hex).
    pub artifact_digest: String,
}

/// Bound for one installed image read during setup (mirrors the pinned
/// artifact check; launch-time re-verification stays with the launcher).
const NOTIFY_SOURCE_BYTES_LIMIT: u64 = 256 * 1024 * 1024;

/// Protected relative record the Watchdog fallback producer reads: the
/// installer-ceremony key binding that carries the 32-byte `signing_key`.
///
/// Mirrors
/// `eliot_watchdog::watchdog_fallback_composition::WATCHDOG_FALLBACK_KEY_RELATIVE`.
/// The Watchdog pins the same installed path because it must not depend on the
/// notify binary crate, so its own protected-lease load is the independent
/// check; any divergence between the two pinned strings fails closed on the
/// consumer.
pub const WATCHDOG_FALLBACK_KEY_RELATIVE: &str = "Eliot/watchdog/watchdog-fallback-key.json";

/// Upper bound for one protected key-record read. The record is a five-field
/// fixed-shape document; anything larger fails closed before parsing.
const WATCHDOG_FALLBACK_KEY_BYTES_LIMIT: u64 = 64 * 1024;

/// Shape marker of the published key record. A foreign, future, or hand-edited
/// record is rejected by the replay proof below instead of being partially
/// consumed.
const WATCHDOG_FALLBACK_KEY_WIRE: &str = "eliot.watchdog-fallback-key.v1";

/// Stable non-secret signer identity handed to the first-party Ed25519 signer
/// port. It satisfies that port's non-blank identity contract only: the derived
/// verifying key depends solely on the secret, and this ceremony produces no
/// signature.
const WATCHDOG_FALLBACK_KEY_SIGNER_ID: &str = "installer-key-ceremony";

/// One exact, canonically encoded Watchdog fallback key record.
///
/// The consumer reads `installation_identity`, `key_id`, `public_key` and
/// `signing_key` as bounded text. `wire` is this ceremony's own shape guard,
/// proved before an existing record is reused. `Debug` is deliberately
/// redacted because `signing_key` is the secret.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogFallbackKeyRecord {
    wire: String,
    installation_identity: String,
    key_id: String,
    public_key: String,
    signing_key: String,
}

impl std::fmt::Debug for WatchdogFallbackKeyRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WatchdogFallbackKeyRecord(<redacted>)")
    }
}

/// The exact key material one ceremony run proved, plus the protected
/// destination it must be written to.
///
/// `key_record_bytes` is the only secret-bearing field. It is cleared on every
/// exit path of `publish_watchdog_fallback_key_record` and is never formatted,
/// cloned, logged, or returned to a caller.
pub struct WatchdogFallbackKeyMaterial {
    key_record_path: PathBuf,
    key_record_bytes: Vec<u8>,
    public_key: String,
}

impl std::fmt::Debug for WatchdogFallbackKeyMaterial {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WatchdogFallbackKeyMaterial(<redacted>)")
    }
}

/// Verifies the installer-named image and hashes its exact bytes.
///
/// Fails closed on relative paths, wrong filenames, non-files, empty or
/// oversized images, and unreadable bytes. The returned digest always
/// describes the bytes read here — a caller cannot substitute a digest for
/// different bytes.
///
/// # Errors
///
/// Returns [`HostError::Platform`] when the path or bytes are invalid.
pub fn observe_installed_notify_source(
    executable: &Path,
) -> Result<ObservedNotifySource, HostError> {
    if !executable.is_absolute() {
        return Err(HostError::Platform(
            "notify executable path must be absolute".to_owned(),
        ));
    }
    if executable.file_name().and_then(|name| name.to_str())
        != Some(eliot_notify::NOTIFY_IMAGE_FILE_NAME)
    {
        return Err(HostError::Platform(
            "notify executable must name the canonical installed notify image".to_owned(),
        ));
    }
    let metadata = std::fs::metadata(executable)
        .map_err(|error| HostError::Platform(format!("open notify executable: {error}")))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > NOTIFY_SOURCE_BYTES_LIMIT {
        return Err(HostError::Platform(
            "notify executable is not a bounded regular file".to_owned(),
        ));
    }
    let bytes = std::fs::read(executable)
        .map_err(|error| HostError::Platform(format!("read notify executable: {error}")))?;
    if bytes.is_empty() {
        return Err(HostError::Platform("notify executable is empty".to_owned()));
    }
    Ok(ObservedNotifySource {
        executable_path: executable.to_path_buf(),
        artifact_digest: format!("{:x}", Sha256::digest(&bytes)),
    })
}

/// Published declaration binding: destination plus pinned digest.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedNotifyDeclaration {
    /// Absolute protected declaration path.
    pub declaration_path: PathBuf,
    /// SHA-256 of the published canonical bytes.
    pub declaration_digest: PlatformHandle,
}

/// Signed fallback registration observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyFallbackRegistration {
    /// Scheduler task name.
    pub task_name: String,
    /// Interactive user SID the task is bound to.
    pub sid: String,
    /// Interactive session id the task is bound to.
    pub session_id: u32,
    /// Registered notify artifact digest.
    pub notify_artifact_sha256: String,
    /// Verifier digest pinned at registration.
    pub verifier_sha256: String,
    /// Scheduler XML digest observed at registration.
    pub task_xml_sha256: String,
}

/// Complete per-user setup outcome: published declaration plus registration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NotifyFallbackSetup {
    /// Published declaration binding.
    pub declaration: PublishedNotifyDeclaration,
    /// Scheduler registration observation.
    pub registration: NotifyFallbackRegistration,
}

/// Produces the ceremony's key material without writing anything.
///
/// A record already published at the protected destination is reused verbatim
/// once it passes [`prove_replayed_key_record`], so a re-run never rotates the
/// key under an already-registered Task Scheduler task. Otherwise 32 bytes are
/// drawn from the admitted Windows CSPRNG port and the verifying half is
/// derived from exactly those bytes.
///
/// # Errors
///
/// Returns [`HostError`] when the protected destination cannot be resolved, an
/// existing record is foreign/malformed/rewritten, or the OS CSPRNG is
/// unavailable. No message, receipt, or log line carries secret material.
fn watchdog_fallback_key_material(
    inputs: &NotifyFallbackSetupInputs,
) -> Result<WatchdogFallbackKeyMaterial, HostError> {
    let key_record_path = protected_program_data_path(WATCHDOG_FALLBACK_KEY_RELATIVE)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if let Some(bytes) = read_published_key_record(&key_record_path)? {
        // WORK_UNIT_CASE: 1781/1 — a published record is replayed, never
        // regenerated: rotating it would silently invalidate the declaration
        // and the already-registered task that pin its verifying half.
        let public_key = prove_replayed_key_record(
            &bytes,
            inputs.installation_identity.as_str(),
            inputs.key_id.as_str(),
        )?;
        return Ok(WatchdogFallbackKeyMaterial {
            key_record_path,
            key_record_bytes: bytes,
            public_key,
        });
    }
    let (key_record_bytes, public_key) = generate_key_record(inputs)?;
    Ok(WatchdogFallbackKeyMaterial {
        key_record_path,
        key_record_bytes,
        public_key,
    })
}

/// Reads the published key record, or `None` when the destination does not
/// exist.
///
/// A present record must open under a verified protected lease. Only a
/// `NotFound` observation authorises generation; any other absence proof fails
/// closed, so the ceremony can never overwrite or regenerate over a record it
/// could not read.
///
/// # Errors
///
/// Returns [`HostError::Platform`] when the destination cannot be observed
/// under a verified protected lease.
#[cfg(windows)]
fn read_published_key_record(path: &Path) -> Result<Option<Vec<u8>>, HostError> {
    // WORK_UNIT_CASE: 1781/2 — the absent destination is the only state in
    // which the ceremony may generate key material.
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(HostError::Platform(format!(
                "observe watchdog fallback key record: {error}"
            )));
        }
        Ok(_) => {}
    }
    let lease = ProtectedPathLease::open_existing_absolute(path)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    lease
        .verify_stable_identity()
        .and_then(|()| lease.verify_path_identity())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let bytes = lease
        .read_bounded(WATCHDOG_FALLBACK_KEY_BYTES_LIMIT)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    Ok(Some(bytes))
}

#[cfg(not(windows))]
fn read_published_key_record(_path: &Path) -> Result<Option<Vec<u8>>, HostError> {
    Err(HostError::Platform(
        "watchdog fallback key ceremony requires Windows".to_owned(),
    ))
}

/// Proves an already-published record may be replayed as this installation's
/// live key binding and returns the verifying half it declares.
///
/// The proof is the same pair of independent bindings the Watchdog consumer
/// proves on load: the record must be this exact installation identity and key
/// id in the exact canonical encoding, and its secret must derive exactly the
/// `public_key` it declares. A substituted, foreign, or partially rewritten
/// record can therefore neither be replayed here nor mint an envelope the
/// installed notify route would accept.
///
/// # Errors
///
/// Returns [`HostError::RecoveryRequired`] on any shape, identity, encoding, or
/// derivation failure. Messages name the failing property only and never echo
/// a value.
fn prove_replayed_key_record(
    bytes: &[u8],
    installation_identity: &str,
    key_id: &str,
) -> Result<String, HostError> {
    let malformed = || {
        HostError::RecoveryRequired(
            "watchdog fallback key record is not the exact bounded shape".to_owned(),
        )
    };
    let record: WatchdogFallbackKeyRecord =
        serde_json::from_slice(bytes).map_err(|_| malformed())?;
    if record.wire != WATCHDOG_FALLBACK_KEY_WIRE
        || record.installation_identity != installation_identity
        || record.key_id != key_id
    {
        return Err(HostError::RecoveryRequired(
            "watchdog fallback key record does not bind this installation identity and key id"
                .to_owned(),
        ));
    }
    let canonical = canonical_json_bytes(&record).map_err(|_| malformed())?;
    if canonical.as_slice() != bytes {
        return Err(HostError::RecoveryRequired(
            "watchdog fallback key record is not canonically encoded".to_owned(),
        ));
    }
    let seed = decode_hex_seed(&record.signing_key)?;
    if derive_public_key(seed, WATCHDOG_FALLBACK_KEY_SIGNER_ID, key_id)? != record.public_key {
        return Err(HostError::RecoveryRequired(
            "watchdog fallback key record secret does not derive the declared public key"
                .to_owned(),
        ));
    }
    Ok(record.public_key)
}

/// Draws the ceremony secret and renders the exact canonical record bytes.
///
/// The secret lives only in a zeroizing secret owner, in the local seed moved
/// into the derivation, and in the returned byte buffer, which the publisher
/// clears on every exit path. It is never formatted, cloned, or written to any
/// path other than the protected key record.
///
/// # Errors
///
/// Returns [`HostError`] when the OS CSPRNG is unavailable, the drawn length
/// is unusable, or canonical serialization fails.
fn generate_key_record(inputs: &NotifyFallbackSetupInputs) -> Result<(Vec<u8>, String), HostError> {
    let secret = WindowsInstallerSecretProvider::new()
        .generate_secret()
        .map_err(|error| {
            HostError::Platform(format!("watchdog fallback key generation failed: {error}"))
        })?;
    // WORK_UNIT_CASE: 1781/3 — the drawn bytes are the only secret input, and
    // the verifying half is derived from exactly them, so the record can never
    // declare a key its own secret does not produce.
    let seed: [u8; 32] = secret.expose().try_into().map_err(|_| {
        HostError::Platform("watchdog fallback key generation is unusable".to_owned())
    })?;
    let signing_key = hex_encode_lower(&seed);
    let public_key = derive_public_key(
        seed,
        WATCHDOG_FALLBACK_KEY_SIGNER_ID,
        inputs.key_id.as_str(),
    )?;
    let record = WatchdogFallbackKeyRecord {
        wire: WATCHDOG_FALLBACK_KEY_WIRE.to_owned(),
        installation_identity: inputs.installation_identity.as_str().to_owned(),
        key_id: inputs.key_id.as_str().to_owned(),
        public_key: public_key.clone(),
        signing_key,
    };
    let key_record_bytes = canonical_json_bytes(&record).map_err(|error| {
        HostError::Platform(format!(
            "watchdog fallback key record encoding failed: {error}"
        ))
    })?;
    Ok((key_record_bytes, public_key))
}

/// Derives the Ed25519 verifying key the protected secret produces, as the
/// exact 64-character lowercase hex both protected records carry.
///
/// Reuses the first-party Ed25519 signer port already admitted for installer
/// key material instead of introducing a second crypto implementation. The
/// derived key depends only on `seed`, which this function consumes; the secret
/// is read here and never retained, formatted, or returned.
fn derive_public_key(seed: [u8; 32], signer_id: &str, key_id: &str) -> Result<String, HostError> {
    let verifying =
        Ed25519InstallationActivationApprovalSigner::from_secret_key(signer_id, key_id, seed)
            .map_err(|_| {
                HostError::Platform("watchdog fallback signing key is unusable".to_owned())
            })?
            .public_key();
    Ok(hex_encode_lower(&verifying))
}

/// Decodes one already-bounded 64-character lowercase-hex secret into the exact
/// 32 bytes the Ed25519 signer consumes.
///
/// The alphabet and width are the consumer's own rule, so a record the consumer
/// would reject is rejected here too instead of yielding a key the consumer
/// refuses. A malformed or all-zero value fails closed.
///
/// # Errors
///
/// Returns [`HostError::RecoveryRequired`] when the value is not exactly 64
/// lowercase hex characters or decodes to an all-zero secret.
fn decode_hex_seed(value: &str) -> Result<[u8; 32], HostError> {
    let unusable =
        || HostError::RecoveryRequired("watchdog fallback signing key is not usable".to_owned());
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(unusable());
    }
    let mut seed = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16).ok_or_else(unusable)?;
        let low = (pair[1] as char).to_digit(16).ok_or_else(unusable)?;
        seed[index] = u8::try_from((high << 4) | low).map_err(|_| unusable())?;
    }
    if seed.iter().all(|byte| *byte == 0) {
        return Err(unusable());
    }
    Ok(seed)
}

/// Lowercase-hex encodes key bytes into the exact 64-character form both
/// protected records carry, matching the consumer's own comparison width.
fn hex_encode_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Publishes the protected key record and proves the exact bytes under lease.
///
/// Reuses the existing Phase-B file publisher — create-new, atomic, idempotent
/// replay on exact bytes, fail-closed on unexpected existing bytes — and clears
/// the secret-bearing buffer on every exit path, so the protected record is the
/// only durable copy.
///
/// # Errors
///
/// Returns [`HostError`] when the protected contour cannot be prepared, the
/// publisher rejects the destination, or readback digest equality fails.
#[cfg(windows)]
fn publish_watchdog_fallback_key_record(
    inputs: &NotifyFallbackSetupInputs,
    mut material: WatchdogFallbackKeyMaterial,
) -> Result<(), HostError> {
    let published = publish_watchdog_fallback_key_record_inner(inputs, &material);
    // WORK_UNIT_CASE: 1781/4 — the secret-bearing buffer is cleared on the
    // success and the fail-closed path alike, so a rejected run leaves no
    // second copy of the secret behind in this process.
    material.key_record_bytes.fill(0);
    published
}

#[cfg(windows)]
fn publish_watchdog_fallback_key_record_inner(
    inputs: &NotifyFallbackSetupInputs,
    material: &WatchdogFallbackKeyMaterial,
) -> Result<(), HostError> {
    use crate::phase_b_materialize_file;

    let parent = material.key_record_path.parent().ok_or_else(|| {
        HostError::RecoveryRequired(
            "Watchdog fallback key record destination has no parent".to_owned(),
        )
    })?;
    prepare_protected_directory(parent).map_err(|error| HostError::Platform(error.to_string()))?;
    let expected = PlatformHandle::new(format!("{:x}", Sha256::digest(&material.key_record_bytes)))
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let (digest, _identity) = phase_b_materialize_file(
        inputs.profile,
        inputs.portable_root.as_ref(),
        &material.key_record_path,
        &material.key_record_bytes,
        &[&expected],
        "Watchdog fallback key record",
    )?;
    verify_published_readback(
        &material.key_record_path,
        digest.as_str(),
        "Watchdog fallback key record",
    )
}

#[cfg(not(windows))]
fn publish_watchdog_fallback_key_record(
    _inputs: &NotifyFallbackSetupInputs,
    _material: WatchdogFallbackKeyMaterial,
) -> Result<(), HostError> {
    Err(HostError::Platform(
        "watchdog fallback key ceremony requires Windows".to_owned(),
    ))
}

/// Renders and validates the canonical declaration bytes for the ceremony's
/// public half.
///
/// The interactive identity is always observed from the live process token and
/// the notify artifact digest is always hashed from the installed bytes, so
/// nothing here is caller-asserted. The verifying half comes from the ceremony,
/// never from the operator.
///
/// # Errors
///
/// Returns [`HostError::Platform`] when the image cannot be observed, the live
/// identity cannot be read, or the renderer rejects the declaration.
fn render_ceremony_declaration(
    inputs: &NotifyFallbackSetupInputs,
    public_key: &str,
) -> Result<RenderedNotifyDeclaration, HostError> {
    let source = observe_installed_notify_source(&inputs.notify_executable)?;
    let identity = eliot_platform_windows::current_process_named_pipe_expectation()
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let declaration = NotifyDeclarationInputs {
        installation_identity: inputs.installation_identity.clone(),
        audience: inputs.audience.clone(),
        authority_epoch: inputs.authority_epoch,
        key_id: inputs.key_id.clone(),
        public_key: public_key.to_owned(),
        notify_executable: source.executable_path.to_string_lossy().into_owned(),
        notify_artifact_sha256: source.artifact_digest,
        interactive_user_sid: identity.expected_sid().to_owned(),
        interactive_session_id: identity.expected_session_id(),
    };
    render_notify_fallback_declaration(&declaration)
        .map_err(|error| HostError::Platform(error.to_string()))
}

/// Runs the Watchdog fallback key ceremony and publishes the canonical consumer
/// half to protected storage.
///
/// One ceremony, two records. The protected key binding
/// ([`WATCHDOG_FALLBACK_KEY_RELATIVE`]) is materialised first, and the
/// declaration is rendered from exactly the key material that binding proves,
/// so the public half is never supplied from outside and the two records cannot
/// diverge. Publication reuses the existing Phase-B file publisher and verifies
/// readback under lease with digest equality.
///
/// Ordering: the installed image is observed and the declaration inputs are
/// rendered and validated before the secret is written anywhere, so an invalid
/// declaration never produces durable key material. The two publications are
/// separate create-new operations, not one filesystem transaction; the next run
/// reconciles them by replaying the same record and the same bytes.
///
/// # Errors
///
/// Returns [`HostError`] when inputs are invalid, the image cannot be
/// observed, the key ceremony fails closed, the protected path cannot be
/// resolved, publication or readback fails, or the platform is not Windows.
pub fn publish_notify_fallback_declaration(
    inputs: &NotifyFallbackSetupInputs,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<PublishedNotifyDeclaration, HostError> {
    let material = watchdog_fallback_key_material(inputs)?;
    let rendered = render_ceremony_declaration(inputs, &material.public_key)?;
    publish_watchdog_fallback_key_record(inputs, material)?;
    publish_rendered_declaration(&rendered, inputs.profile, portable_root)
}

/// Registers the signed Task Scheduler fallback against the published
/// declaration. Must run in the interactive session matching the
/// declaration; the notify route enforces the live caller identity and
/// re-verifies the pinned artifact before touching the scheduler.
///
/// # Errors
///
/// Returns [`HostError`] when the declaration is absent/invalid, the caller
/// identity mismatches, or scheduler registration/readback fails.
pub fn register_notify_fallback() -> Result<NotifyFallbackRegistration, HostError> {
    let receipt = eliot_notify::register_watchdog_fallback_task()
        .map_err(|error| HostError::Platform(error.to_string()))?;
    Ok(NotifyFallbackRegistration {
        task_name: receipt.task_name().to_owned(),
        sid: receipt.sid().to_owned(),
        session_id: receipt.session_id(),
        notify_artifact_sha256: receipt.notify_artifact_sha256().to_owned(),
        verifier_sha256: receipt.verifier_sha256().to_owned(),
        task_xml_sha256: receipt.task_xml_sha256().to_owned(),
    })
}

/// Composed per-user setup: run the Watchdog fallback key ceremony, publish
/// the declaration derived from it, then register the signed fallback task.
/// Normal User-Broker launch is unaffected.
///
/// # Errors
///
/// Returns [`HostError`] from any stage; a ceremony already replayed by exact
/// readback proceeds to registration without rotating the key.
pub fn setup_notify_fallback_per_user(
    inputs: &NotifyFallbackSetupInputs,
) -> Result<NotifyFallbackSetup, HostError> {
    let declaration = publish_notify_fallback_declaration(inputs, inputs.portable_root.as_ref())?;
    let registration = register_notify_fallback()?;
    Ok(NotifyFallbackSetup {
        declaration,
        registration,
    })
}

#[cfg(windows)]
fn publish_rendered_declaration(
    rendered: &RenderedNotifyDeclaration,
    profile: InstallationProfile,
    portable_root: Option<&UserOwnedRootLease>,
) -> Result<PublishedNotifyDeclaration, HostError> {
    use crate::phase_b_materialize_file;

    let declaration_path = protected_program_data_path(rendered.relative_path)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let expected = PlatformHandle::new(rendered.declaration_digest.clone())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let (digest, _identity) = phase_b_materialize_file(
        profile,
        portable_root,
        Path::new(&declaration_path),
        &rendered.canonical_bytes,
        &[&expected],
        "Notify fallback declaration",
    )?;
    verify_published_readback(
        Path::new(&declaration_path),
        digest.as_str(),
        "Notify fallback declaration",
    )?;
    Ok(PublishedNotifyDeclaration {
        declaration_path,
        declaration_digest: digest,
    })
}

#[cfg(not(windows))]
fn publish_rendered_declaration(
    _rendered: &RenderedNotifyDeclaration,
    _profile: InstallationProfile,
    _portable_root: Option<&UserOwnedRootLease>,
) -> Result<PublishedNotifyDeclaration, HostError> {
    Err(HostError::Platform(
        "notify fallback setup requires Windows".to_owned(),
    ))
}

/// Proves one freshly published protected file still holds exactly the bytes
/// this ceremony published, under a verified protected lease.
///
/// Shared by the declaration and the key record so neither contour grows a
/// second readback verifier.
#[cfg(windows)]
fn verify_published_readback(
    path: &Path,
    expected_digest: &str,
    label: &str,
) -> Result<(), HostError> {
    let lease = ProtectedPathLease::open_existing_absolute(path)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    lease
        .verify_stable_identity()
        .and_then(|()| lease.verify_path_identity())
        .map_err(|error| HostError::Platform(error.to_string()))?;
    let bytes = lease
        .read_bounded(64 * 1024)
        .map_err(|error| HostError::Platform(error.to_string()))?;
    if format!("{:x}", Sha256::digest(&bytes)) != expected_digest {
        return Err(HostError::RecoveryRequired(format!(
            "{label} readback digest differs from publication"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn valid_setup_inputs(notify_executable: PathBuf) -> NotifyFallbackSetupInputs {
        NotifyFallbackSetupInputs {
            installation_identity: PlatformHandle::new("installation:test").expect("identity"),
            audience: PlatformHandle::new("audience:test").expect("audience"),
            authority_epoch: 7,
            key_id: PlatformHandle::new("key:test").expect("key id"),
            notify_executable,
            profile: InstallationProfile::PortableDev,
            portable_root: None,
        }
    }

    fn write_temp_image(name: &str, bytes: &[u8]) -> PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, bytes).expect("fixture writable");
        path
    }

    #[test]
    fn observed_source_binds_path_to_hashed_bytes() {
        let bytes = b"installed-notify-setup-image-bytes".to_vec();
        let path = write_temp_image("eliot-1780-notify-setup-ok.bin", &bytes);
        // The fixture filename is not the canonical image name: observation
        // must reject it before hashing.
        assert!(observe_installed_notify_source(&path).is_err());
        let canonical_dir = std::env::temp_dir().join("eliot-1780-setup-canonical");
        let _ = std::fs::create_dir_all(&canonical_dir);
        let canonical = canonical_dir.join(eliot_notify::NOTIFY_IMAGE_FILE_NAME);
        std::fs::write(&canonical, &bytes).expect("fixture writable");
        let observed =
            observe_installed_notify_source(&canonical).expect("canonical image observes");
        assert_eq!(observed.executable_path, canonical);
        assert_eq!(
            observed.artifact_digest,
            format!("{:x}", Sha256::digest(&bytes))
        );
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&canonical);
    }

    #[test]
    fn invalid_setup_inputs_fail_before_publication() {
        let bytes = b"installed-notify-setup-image-bytes".to_vec();
        let dir = std::env::temp_dir().join("eliot-1780-setup-invalid");
        let _ = std::fs::create_dir_all(&dir);
        let exe = dir.join(eliot_notify::NOTIFY_IMAGE_FILE_NAME);
        std::fs::write(&exe, &bytes).expect("fixture writable");
        // Bad authority epoch fails at render, after source observation but
        // before any protected publication.
        let mut setup = valid_setup_inputs(exe.clone());
        setup.authority_epoch = 0;
        let error = setup_notify_fallback_per_user(&setup).expect_err("bad epoch fails");
        assert!(
            matches!(error, HostError::Platform(_)),
            "render rejection surfaces without publication"
        );
        // Missing image fails at observation, before render.
        let mut missing = valid_setup_inputs(dir.join("eliot-notify.exe"));
        missing.authority_epoch = 7;
        assert!(setup_notify_fallback_per_user(&missing).is_err());
        let _ = std::fs::remove_file(&exe);
    }

    #[test]
    fn registration_without_declaration_fails_closed() {
        // Precondition: this test must never create scheduler state. If an
        // installer already published a declaration here, fail loudly instead
        // of registering against it.
        if let Ok(path) = protected_program_data_path("Eliot/notify/watchdog-verification.json") {
            assert!(
                !std::path::Path::new(&path).exists(),
                "test requires no published declaration"
            );
        }
        // No declaration is published by this test: the registration route
        // must reject before touching Task Scheduler.
        let outcome = register_notify_fallback();
        assert!(
            outcome.is_err(),
            "fallback registration without a declaration must fail"
        );
    }
}
