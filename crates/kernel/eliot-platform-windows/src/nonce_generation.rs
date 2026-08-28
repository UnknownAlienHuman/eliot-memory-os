//! Windows OS-random nonce-generation closure.
//!
//! This private child generates nonce material only. It owns no SCM, service,
//! pipe, process, lifecycle, daemon, Host, watchdog, eliotd, canonical-write,
//! filesystem, credential, listener, or `SurrealDB` authority.
//!
//! Normative anchors (verified in this worktree):
//! - `A12.2` (`docs/normative/ELIOT_ARCHITECTURE.md:1912-1922`) binds identity
//!   at the harness/installation boundary and gives unknown identity minimum
//!   privilege with no Material authority.
//! - `I1.8` (`docs/normative/ELIOT_IMPLEMENTATION.md:1687-1708`) assigns
//!   identity, authority, State Fence, idempotency, ordering, and generation
//!   checks to Kernel; no component may invent semantics, authorize them, and
//!   commit them alone.

use eliot_platform::{KernelActivationNonce, PlatformHandle};

use super::WindowsAdapterError;

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let mut value = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        let _ = write!(&mut value, "{byte:02x}");
    }
    value
}

#[cfg(windows)]
pub(crate) fn fill_system_random(bytes: &mut [u8]) -> Result<(), WindowsAdapterError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };

    let length = u32::try_from(bytes.len()).map_err(|_| WindowsAdapterError::InvalidInput)?;
    let status = unsafe {
        // SAFETY: `bytes` is a live writable slice and `length` exactly matches it.
        BCryptGenRandom(
            std::ptr::null_mut(),
            bytes.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        Err(WindowsAdapterError::Failed)
    }
}

#[cfg(not(windows))]
pub(crate) fn fill_system_random(_bytes: &mut [u8]) -> Result<(), WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Issues an unpredictable public nonce for one durable SCM registration
/// intent.  The value is not a secret; it is bound into the service command
/// line and the protected installer ownership marker.
///
/// # Errors
/// Returns `Unavailable` when the Windows system CSPRNG cannot issue a nonce.
#[must_use = "the nonce must be durably bound before SCM mutation"]
pub fn fresh_service_registration_nonce() -> Result<PlatformHandle, WindowsAdapterError> {
    let mut random = [0_u8; 32];
    fill_system_random(&mut random)?;
    let value = hex_lower(&random);
    random.fill(0);
    PlatformHandle::new(value).map_err(|_| WindowsAdapterError::InvalidInput)
}

pub(crate) const ACTIVATION_NONCE_PREFIX: &str = "eliot-activation-";
pub(crate) const ACTIVATION_NONCE_RANDOM_BYTES: usize = 32;
pub(crate) const ACTIVATION_NONCE_HEX_BYTES: usize = ACTIVATION_NONCE_RANDOM_BYTES * 2;

/// Issues fresh OS-random material exclusively for Kernel activation.
///
/// The nonce deliberately has no lineage, time, process, or other caller
/// input.  Any `BCrypt` failure is terminal for this issuance attempt; callers
/// must not substitute a deterministic or weak fallback. Composition must wrap
/// the returned handle in the canonical `eliot_platform::KernelActivationNonce`
/// and must never substitute a Host installation-epoch nonce.
///
/// # Errors
///
/// Returns [`WindowsAdapterError::Failed`] when the system RNG rejects the
/// request, or [`WindowsAdapterError::InvalidInput`] if the resulting handle
/// cannot satisfy the bounded nonce shape.
#[cfg(windows)]
pub fn fresh_activation_nonce_material() -> Result<PlatformHandle, WindowsAdapterError> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };

    let mut random = [0_u8; ACTIVATION_NONCE_RANDOM_BYTES];
    let status = unsafe {
        // SAFETY: `random` is an initialized, writable fixed-size buffer and
        // its length is within BCryptGenRandom's u32 parameter range.
        BCryptGenRandom(
            std::ptr::null_mut(),
            random.as_mut_ptr(),
            u32::try_from(random.len()).map_err(|_| WindowsAdapterError::InvalidInput)?,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(WindowsAdapterError::Failed);
    }

    let mut value = String::with_capacity(ACTIVATION_NONCE_HEX_BYTES);
    for byte in random {
        use std::fmt::Write;
        write!(&mut value, "{byte:02x}").map_err(|_| WindowsAdapterError::Failed)?;
    }

    let handle = PlatformHandle::new(value).map_err(|_| WindowsAdapterError::InvalidInput)?;
    if handle.as_str().len() != ACTIVATION_NONCE_HEX_BYTES
        || !handle
            .as_str()
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(WindowsAdapterError::InvalidInput);
    }
    Ok(handle)
}

#[cfg(not(windows))]
pub fn fresh_activation_nonce_material() -> Result<PlatformHandle, WindowsAdapterError> {
    Err(WindowsAdapterError::Unavailable)
}

/// Issues the canonical typed one-use Kernel activation permit from Windows OS RNG material.
///
/// This is the production composition seam. It cannot accept a Host-process
/// nonce and its formatting remains redacted by [`KernelActivationNonce`].
///
/// # Errors
///
/// Returns the classified OS RNG failure, or [`WindowsAdapterError::InvalidInput`]
/// if the generated material violates the canonical 256-bit nonce contract.
pub fn fresh_kernel_activation_nonce() -> Result<KernelActivationNonce, WindowsAdapterError> {
    KernelActivationNonce::new(fresh_activation_nonce_material()?)
        .map_err(|_| WindowsAdapterError::InvalidInput)
}

/// Compatibility wrapper retaining the historical prefixed handle shape.
/// New Kernel activation code must call [`fresh_kernel_activation_nonce`].
///
/// # Errors
///
/// Returns the classified OS RNG failure, or [`WindowsAdapterError::InvalidInput`]
/// if the compatibility handle cannot be constructed from the generated material.
pub fn fresh_activation_nonce() -> Result<PlatformHandle, WindowsAdapterError> {
    let material = fresh_activation_nonce_material()?;
    PlatformHandle::new(format!("{ACTIVATION_NONCE_PREFIX}{}", material.as_str()))
        .map_err(|_| WindowsAdapterError::InvalidInput)
}
