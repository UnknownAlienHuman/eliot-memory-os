//! Bound independent sensor samples for the Watchdog's wired adapters (#1755 W2).
//!
//! Architecture: A8.1 (docs/architecture/A08-01-purpose.md#a81-purpose), ARCH-WDG-01.
//! Implementation: I8.2 (docs/architecture/I08-02-independent-observation-routes.md#i82-independent-observation-routes), I8.1 (docs/architecture/I08-01-process-and-authority.md#i81-process-and-authority), I1.4 (docs/architecture/I01-04-supervision-tree.md#i14-supervision-tree).
//!
//! Every sample this module produces is bound to the approved installation and
//! target generation retained from the registry-selected manifest
//! ([`ApprovedSensorBinding`]) and to the retained OS identity: the approved
//! artifact digest is read through the retained no-follow [`ProtectedPathLease`]
//! handle whose identity is verified before and after the read. A PID, a
//! service name, a port-open result, or a self-reported healthy flag alone can
//! never produce a sample here — no constructor takes one.
//!
//! Probe outcomes stay distinct by construction ([`SensorProbeError`]): absent
//! (no such subject), inaccessible (the probe was denied or unavailable —
//! never stopped or healthy), and changed (the retained identity moved under
//! observation). Liveness is preserved separately from semantic readiness
//! ([`SensorReadiness`]): this owner holds no readiness probe, so a live
//! sample is integrity evidence with readiness explicitly unprobed, never an
//! upgrade to application readiness.
//!
//! The digest is event evidence, not file contents: bytes are hashed through
//! the retained handle and never retained, so no observation carries file
//! contents, tool intent, or principal identity (see `observation_attribution`
//! for the attribution limits that rule consumes).
//!
//! Forbidden by construction: lifecycle effects, authority, database access,
//! and any claim about a subject with no retained binding or lease.

use eliot_contracts::sha256_hex;
use eliot_installation::CandidateManifest;
use eliot_platform_windows::{ProtectedPathError, ProtectedPathLease};
use thiserror::Error;

/// Upper bound, in bytes, for one approved-artifact digest read.
///
/// One tick performs at most one such read, and only while no cached digest
/// is bound to the still-verifying retained lease, so the per-interval cost
/// is bounded by this value rather than by the artifact size.
pub const MAX_APPROVED_ARTIFACT_DIGEST_BYTES: u64 = 32 * 1024 * 1024;

/// Typed refusal for an unusable approved sensor binding.
///
/// The installation identity and target generation are validated
/// nonsecret coordination identities: refusal names which one is missing
/// rather than substituting a placeholder generation.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum SensorBindingError {
    /// The installation identity is empty.
    #[error("approved sensor binding requires a non-empty installation identity")]
    EmptyInstallation,
    /// The target generation is empty.
    #[error("approved sensor binding requires a non-empty target generation")]
    EmptyGeneration,
}

/// Approved installation and target generation governing one sensor target.
///
/// Built only from the registry-selected manifest's retained values
/// ([`ApprovedSensorBinding::from_candidate_manifest`]), never from a working
/// directory, a process name, or caller input. Every sample stamped with this
/// binding was observed under exactly this installation and generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ApprovedSensorBinding {
    installation: String,
    generation: String,
}

impl ApprovedSensorBinding {
    /// Binds an approved installation and target generation.
    ///
    /// # Errors
    ///
    /// Returns [`SensorBindingError`] when either identity is empty.
    pub fn new(installation: &str, generation: &str) -> Result<Self, SensorBindingError> {
        if installation.is_empty() {
            return Err(SensorBindingError::EmptyInstallation);
        }
        if generation.is_empty() {
            return Err(SensorBindingError::EmptyGeneration);
        }
        Ok(Self {
            installation: installation.to_owned(),
            generation: generation.to_owned(),
        })
    }

    /// Binds the exact approved installation and target generation retained
    /// in the registry-selected manifest.
    ///
    /// Both values are validated, not trusted: an empty installation or
    /// generation refuses the binding instead of stamping samples with it.
    ///
    /// # Errors
    ///
    /// Returns [`SensorBindingError`] when the retained manifest carries an
    /// empty installation identity or target generation.
    pub fn from_candidate_manifest(
        manifest: &CandidateManifest,
    ) -> Result<Self, SensorBindingError> {
        Self::new(
            manifest
                .runtime_launch
                .installation_epoch
                .installation
                .as_str(),
            manifest.generation.as_str(),
        )
    }

    /// Returns the approved installation identity this binding governs.
    #[must_use]
    pub fn installation(&self) -> &str {
        &self.installation
    }

    /// Returns the approved target generation this binding governs.
    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }
}

/// Typed probe outcome for one bound sensor read.
///
/// Absent, inaccessible, and changed stay distinct: a denied probe is an
/// [`SensorProbeError::Inaccessible`], never absence and never health, and a
/// retained identity that moved mid-read is a [`SensorProbeError::Changed`],
/// never a fresh baseline.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum SensorProbeError {
    /// No such subject under the retained binding (no lease, no binding).
    #[error("sensor probe found no such subject: {0}")]
    Absent(&'static str),
    /// The probe was denied, unavailable, or over its bound.
    #[error("sensor probe was denied or unavailable: {0}")]
    Inaccessible(&'static str),
    /// The retained identity moved under observation.
    #[error("retained sensor identity changed under observation: {0}")]
    Changed(&'static str),
}

/// Semantic readiness of a sensor subject, kept separate from liveness.
///
/// This owner holds no semantic or application-readiness probe: a live
/// process or digest sample preserves liveness with readiness explicitly
/// unprobed. There is no constructor for a ready verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SensorReadiness {
    /// No semantic or application-readiness probe exists in this owner.
    /// Liveness evidence stays liveness evidence.
    Unprobed,
}

impl SensorReadiness {
    /// Returns the stable wire name of this readiness.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unprobed => "unprobed",
        }
    }
}

/// One bound content-digest observation of the approved artifact.
///
/// The digest is event evidence: file bytes are hashed through the retained
/// handle and never retained, so this carries the installation, the
/// generation, the digest, and the byte count — never file contents, tool
/// intent, or principal identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ArtifactDigestObservation {
    installation: String,
    generation: String,
    digest: String,
    bytes: u64,
    readiness: SensorReadiness,
}

impl ArtifactDigestObservation {
    /// Returns the approved installation identity this sample was bound to.
    #[must_use]
    pub fn installation(&self) -> &str {
        &self.installation
    }

    /// Returns the approved target generation this sample was bound to.
    #[must_use]
    pub fn generation(&self) -> &str {
        &self.generation
    }

    /// Returns the hex content digest observed through the retained lease.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Returns the number of bytes hashed.
    #[must_use]
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Returns the semantic readiness, always unprobed in this owner.
    #[must_use]
    pub fn readiness(&self) -> SensorReadiness {
        self.readiness
    }
}

/// Reads the bounded content digest of the approved artifact through its
/// retained no-follow lease.
///
/// The retained handle identity is verified before and after the bounded
/// read: a replacement between the two checks discards the digest instead of
/// binding it to the retained identity. The path alone never authorizes the
/// read — without the verified lease there is no sample at all.
///
/// # Errors
///
/// Returns [`SensorProbeError::Changed`] when the retained lease identity
/// fails verification, and [`SensorProbeError::Inaccessible`] when the
/// bounded read is denied, exceeds `limit`, or `limit` is zero.
pub fn observe_approved_artifact_digest(
    binding: &ApprovedSensorBinding,
    lease: &ProtectedPathLease,
    limit: u64,
) -> Result<ArtifactDigestObservation, SensorProbeError> {
    if limit == 0 {
        return Err(SensorProbeError::Inaccessible(
            "ARTIFACT_READ_LIMIT_ZERO",
        ));
    }
    lease
        .verify_stable_identity()
        .map_err(|_| SensorProbeError::Changed("IMAGE_IDENTITY_CHANGED"))?;
    lease
        .verify_path_identity()
        .map_err(|_| SensorProbeError::Changed("IMAGE_IDENTITY_CHANGED"))?;
    let bytes =
        lease
            .read_bounded(limit)
            .map_err(|error| match error {
                ProtectedPathError::SizeExceeded => {
                    SensorProbeError::Inaccessible("ARTIFACT_OVER_READ_LIMIT")
                }
                _ => SensorProbeError::Inaccessible("ARTIFACT_READ_DENIED"),
            })?;
    // Re-verify after the read: a replacement between the pre-read verify
    // and the read discards the digest instead of binding it.
    lease
        .verify_stable_identity()
        .map_err(|_| SensorProbeError::Changed("IMAGE_IDENTITY_CHANGED"))?;
    Ok(ArtifactDigestObservation {
        installation: binding.installation().to_owned(),
        generation: binding.generation().to_owned(),
        digest: sha256_hex(&bytes),
        bytes: bytes.len() as u64,
        readiness: SensorReadiness::Unprobed,
    })
}
