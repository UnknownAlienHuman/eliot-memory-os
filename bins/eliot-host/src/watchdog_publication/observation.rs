//! Read-only watchdog publication observation and exact bundle decoding.
//!
//! Architecture anchors: `A8` (Watchdog) and `ARCH-WDG-01` (independent
//! supervision). Implementation anchors: `I8.2` (independent observation
//! routes), `I8.3` (deterministic supervision loop), and `I8.14` (observables).
//!
//! This child owns only decoding, exact single-publication observation, and
//! ordered scanning. Publication, ORS reads, identity construction, and
//! retention remain with the parent Host facade.

use super::super::{
    HostError, OwnedDirectoryRetirementPrecondition, Path, PathBuf, SUPERVISION_LEASE_FILE_NAME,
    SignedSupervisionLease, WATCHDOG_ADMISSION_FILE_NAME, WATCHDOG_PUBLICATION_DIRECTORY_PREFIX,
    WATCHDOG_PUBLICATION_FILE_NAME, WatchdogAdmissionTemplate, WatchdogPublicationBundle,
};

// F-LOG-HOST-4 (#979) publication observation helpers.
//
// Through the #889 facade only: one closed typed
// `crate::watchdog_publication::HostWatchdogObservation` record per boundary,
// emitted by that record's own `emit` as `info!` at
// `crate::host_diagnostics::HOST_DIAGNOSTICS_TARGET`, with the sink disposition
// noted through the shared bounded observer
// (`crate::host_diagnostics::note_event_log_sink_status`, over #984's landed
// safe port).
//
// Observation-only contract: every record projects facts the semantic owner has
// already produced at this boundary. `phase` is a short static token naming the
// boundary and never carries an identity; every identity travels in its own
// slot, projected through `bound_field` from an owner field this boundary
// already holds, and a slot this boundary cannot establish stays explicitly
// unavailable instead of being replaced by a sentence. Nothing is re-derived to
// enrich a record: no digest is recomputed, no protected file is reread, no SCM
// is probed and no clock is read, so bounding limits size, not sensitivity:
// `host_diagnostics::bound_field` bounds bytes only, so this caller must pass
// nonsecret material. Sink outcome never alters result/order/status/cleanup.
// There is no mutable global dedup cache and no terminal guard here: the
// single designated terminal per failed operation stays with the outer
// #891/#893 operation that owns the failure decision; these records
// correlate by the identity they carry and never emit a terminal.
#[cfg(windows)]
use crate::watchdog_publication::HostWatchdogObservation;

/// The nonsecret identity claims one decode/verify/scan boundary already holds.
///
/// Each field is `None` exactly when this boundary holds no such identity, and
/// then renders empty together with its own `<slot>_missing` flag set, so a
/// reader checks the flag before the value and an identity this boundary could
/// not establish can never be read as one it did.
///
/// Slot sourcing, so a record never mixes owners: `installation` and
/// `approved_generation` are the decoded marker's own claim,
/// `ors_receipt_digest` is the decoded marker's ORS receipt digest, and
/// `activation` plus `lease_identity` are the decoded lease payload's own
/// claims. Signed lease bytes, the signature, the nonce and every raw path stay
/// with their owner types.
///
/// Slots this read-only cell never fills: the publisher's canonical-marker
/// `publication_digest` (computed by the publishing parent as
/// `sha256_json(&marker)`; recomputing it here would be re-hashing purely to
/// enrich diagnostics), the structured `StateFence` (no canonical text handle
/// exists, so any rendering would be a fresh derivation), and the service, SCM,
/// process-start, approved-image, start-attempt, deadline-basis and supervision
/// disposition identities, none of which a decode/verify/scan boundary holds.
#[cfg(windows)]
struct PublicationIdentities<'identity> {
    /// Installation identity the decoded marker claims.
    installation: Option<&'identity str>,
    /// Exact approved generation the decoded marker claims.
    approved_generation: Option<&'identity str>,
    /// Activation identity the decoded lease payload carries.
    activation: Option<&'identity str>,
    /// Lease identity the decoded lease payload carries.
    lease_identity: Option<&'identity str>,
    /// Exact ORS receipt digest the decoded marker carries.
    ors_receipt_digest: Option<&'identity str>,
}

/// Every identity slot explicitly missing: this boundary holds none yet.
#[cfg(windows)]
const NO_PUBLICATION_IDENTITY: PublicationIdentities<'static> = PublicationIdentities {
    installation: None,
    approved_generation: None,
    activation: None,
    lease_identity: None,
    ors_receipt_digest: None,
};

/// The identity claims one already decoded publication carries.
///
/// Used from the signature check onward, where the marker and the lease payload
/// are the two children this boundary holds; before the binding check those
/// claims are still unproven and only the contested slots differ.
#[cfg(windows)]
fn decoded_publication_identities<'identity>(
    marker: &'identity WatchdogPublicationBundle,
    lease: &'identity SignedSupervisionLease,
) -> PublicationIdentities<'identity> {
    PublicationIdentities {
        installation: Some(marker.installation_id.as_str()),
        approved_generation: Some(marker.approved_generation.as_str()),
        activation: Some(lease.payload.activation_id.as_str()),
        lease_identity: Some(lease.payload.lease_id.as_str()),
        ors_receipt_digest: Some(marker.ors_receipt_sha256.as_str()),
    }
}

/// Emits one typed publication observation record.
///
/// `phase` is the boundary's short static token. Every identity slot renders its
/// bounded value plus its own `_missing` flag, so an absent identity is an
/// explicit unavailable field. Sink disposition is noted first and never alters
/// what this boundary returns.
#[cfg(windows)]
fn observe_watchdog_observation(phase: &'static str, identities: &PublicationIdentities<'_>) {
    // Destructured so each slot is projected from the boundary's own claim set
    // and the identity value is consumed here rather than re-read field by field.
    let PublicationIdentities {
        installation,
        approved_generation,
        activation,
        lease_identity,
        ors_receipt_digest,
    } = *identities;
    let mut observation = HostWatchdogObservation::default();
    if let Some(installation) = installation {
        observation.set_installation(installation);
    }
    if let Some(approved_generation) = approved_generation {
        observation.set_approved_generation(approved_generation);
    }
    if let Some(activation) = activation {
        observation.set_activation(activation);
    }
    if let Some(lease_identity) = lease_identity {
        observation.set_lease_identity(lease_identity);
    }
    if let Some(ors_receipt_digest) = ors_receipt_digest {
        observation.set_ors_receipt_digest(ors_receipt_digest);
    }

    observation.emit(phase);
}

#[cfg(windows)]
pub struct HostWatchdogPublicationObservation {
    pub(super) path: PathBuf,
    pub(super) marker: WatchdogPublicationBundle,
    pub(super) admission: WatchdogAdmissionTemplate,
    pub(super) lease: SignedSupervisionLease,
    pub(super) retirement: OwnedDirectoryRetirementPrecondition,
}

#[cfg(windows)]
#[allow(
    clippy::too_many_lines,
    reason = "exact single-publication decoding keeps child extraction, validation, canonical comparison, signature, binding, and content-address checks ordered"
)]
pub(super) fn decode_watchdog_publication_observation(
    path: &Path,
    observation: &eliot_platform_windows::OwnedDirectoryObservation,
    require_final_name: bool,
) -> Result<HostWatchdogPublicationObservation, HostError> {
    let admission_bytes = observation
        .bytes(WATCHDOG_ADMISSION_FILE_NAME)
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — absent publication child, never ready/current.
            observe_watchdog_observation(
                "publication.admission_child_absent",
                &NO_PUBLICATION_IDENTITY,
            );
            HostError::RecoveryRequired("Watchdog admission child is absent".to_owned())
        })?;
    let lease_bytes = observation
        .bytes(SUPERVISION_LEASE_FILE_NAME)
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — absent publication child, never ready/current.
            observe_watchdog_observation(
                "publication.lease_child_absent",
                &NO_PUBLICATION_IDENTITY,
            );
            HostError::RecoveryRequired("Watchdog lease child is absent".to_owned())
        })?;
    let marker_bytes = observation
        .bytes(WATCHDOG_PUBLICATION_FILE_NAME)
        .ok_or_else(|| {
            // WORK_UNIT_CASE: 979/3 — absent publication child, never ready/current.
            observe_watchdog_observation(
                "publication.marker_child_absent",
                &NO_PUBLICATION_IDENTITY,
            );
            HostError::RecoveryRequired("Watchdog publication marker is absent".to_owned())
        })?;
    let admission: WatchdogAdmissionTemplate =
        serde_json::from_slice(admission_bytes).map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — undecodable child, never ready/current.
            observe_watchdog_observation(
                "publication.admission_child_decode_rejected",
                &NO_PUBLICATION_IDENTITY,
            );
            HostError::RecoveryRequired(format!("Watchdog admission decode failed: {error}"))
        })?;
    let marker: WatchdogPublicationBundle =
        serde_json::from_slice(marker_bytes).map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — undecodable child, never ready/current.
            // The admission template is decoded at this point, so its claims name
            // which publication's admission could not be decoded; the marker
            // itself, the ORS receipt digest and the lease are not yet held.
            observe_watchdog_observation(
                "publication.marker_child_decode_rejected",
                &PublicationIdentities {
                    installation: Some(admission.installation_id.as_str()),
                    approved_generation: Some(admission.approved_generation.as_str()),
                    ..NO_PUBLICATION_IDENTITY
                },
            );
            HostError::RecoveryRequired(format!("Watchdog marker decode failed: {error}"))
        })?;
    let lease: SignedSupervisionLease = serde_json::from_slice(lease_bytes).map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — undecodable child, never ready/current.
        // The marker is decoded at this point and names the publication under
        // observation; the lease payload, so the activation and the lease
        // identity, is not yet held.
        observe_watchdog_observation(
            "publication.lease_child_decode_rejected",
            &PublicationIdentities {
                installation: Some(marker.installation_id.as_str()),
                approved_generation: Some(marker.approved_generation.as_str()),
                ors_receipt_digest: Some(marker.ors_receipt_sha256.as_str()),
                ..NO_PUBLICATION_IDENTITY
            },
        );
        HostError::RecoveryRequired(format!("Watchdog lease decode failed: {error}"))
    })?;
    admission.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid child, never ready/current.
        observe_watchdog_observation(
            "publication.admission_child_validation_rejected",
            &decoded_publication_identities(&marker, &lease),
        );
        HostError::RecoveryRequired(error.to_string())
    })?;
    marker.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid child, never ready/current.
        observe_watchdog_observation(
            "publication.marker_child_validation_rejected",
            &decoded_publication_identities(&marker, &lease),
        );
        HostError::RecoveryRequired(error.to_string())
    })?;
    lease.validate().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — invalid child, never ready/current.
        observe_watchdog_observation(
            "publication.lease_child_validation_rejected",
            &decoded_publication_identities(&marker, &lease),
        );
        HostError::RecoveryRequired(error.to_string())
    })?;
    if admission.canonical_bytes().map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — uncanonicalizable child, never ready/current.
        observe_watchdog_observation(
            "publication.admission_child_canonical_rejected",
            &decoded_publication_identities(&marker, &lease),
        );
        HostError::RecoveryRequired(error.to_string())
    })? != admission_bytes
        || marker.canonical_bytes().map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — uncanonicalizable child, never ready/current.
            observe_watchdog_observation(
                "publication.marker_child_canonical_rejected",
                &decoded_publication_identities(&marker, &lease),
            );
            HostError::RecoveryRequired(error.to_string())
        })? != marker_bytes
        || serde_json::to_vec(&lease).map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — uncanonicalizable child, never ready/current.
            observe_watchdog_observation(
                "publication.lease_child_canonical_rejected",
                &decoded_publication_identities(&marker, &lease),
            );
            HostError::RecoveryRequired(error.to_string())
        })? != lease_bytes
    {
        // WORK_UNIT_CASE: 979/3 — non-canonical children, never ready/current.
        observe_watchdog_observation(
            "publication.children_not_canonical",
            &decoded_publication_identities(&marker, &lease),
        );
        return Err(HostError::RecoveryRequired(
            "Watchdog publication children are not canonical".to_owned(),
        ));
    }
    marker
        .verify_bytes(admission_bytes, lease_bytes)
        .map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unverified marker, never ready/current.
            // The signature outcome is the phase; the record carries only the
            // identities the marker and lease payload already state, never the
            // signature or any signed lease byte.
            observe_watchdog_observation(
                "publication.marker_signature_rejected",
                &decoded_publication_identities(&marker, &lease),
            );
            HostError::RecoveryRequired(error.to_string())
        })?;
    if marker.installation_id != admission.installation_id
        || marker.approved_generation != admission.approved_generation
        || marker.supervision_lease_scope_id != admission.supervision_lease_scope_id
        || marker.supervision_lease_id != lease.payload.lease_id
    {
        // WORK_UNIT_CASE: 979/3 — conflicting marker/admission binding, never current.
        // FOUR identities are contested by this comparison, not three:
        // `marker.installation_id`, `marker.approved_generation`,
        // `marker.supervision_lease_scope_id` and `marker.supervision_lease_id`.
        // The first, second and fourth have a record slot, so two decoded children
        // disagree and no single value is established; each renders as explicitly
        // missing rather than projecting one child's claim as the publication's
        // identity. The lease SCOPE has NO SLOT on the shared record, so a
        // scope-only conflict emits exactly the same contested slots — every
        // `*_missing` flag true — and is NOT distinguishable from an installation
        // conflict. Closing that gap needs a new slot on the shared record, which
        // this read-only cell does not own; until it exists, only this comment and
        // the returned error text state the scope conflict. The uncontested lease
        // activation and the marker's ORS receipt digest, which this comparison
        // never reaches, stay filled.
        observe_watchdog_observation(
            "publication.marker_binding_conflicting",
            &PublicationIdentities {
                activation: Some(lease.payload.activation_id.as_str()),
                ors_receipt_digest: Some(marker.ors_receipt_sha256.as_str()),
                ..NO_PUBLICATION_IDENTITY
            },
        );
        return Err(HostError::RecoveryRequired(
            "Watchdog marker is not bound to its admission template".to_owned(),
        ));
    }
    if require_final_name {
        let expected_name = marker.directory_name().map_err(|error| {
            // WORK_UNIT_CASE: 979/4 — directory name not derivable, identity unproven.
            observe_watchdog_observation(
                "publication.marker_directory_name_rejected",
                &decoded_publication_identities(&marker, &lease),
            );
            HostError::RecoveryRequired(error.to_string())
        })?;
        let actual_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                // WORK_UNIT_CASE: 979/4 — path name unusable, identity unproven.
                // The publication's own identities are fully proven by now; the
                // raw path stays with the owner and is never recorded.
                observe_watchdog_observation(
                    "publication.directory_path_name_rejected",
                    &decoded_publication_identities(&marker, &lease),
                );
                HostError::RecoveryRequired("Watchdog publication path is not canonical".to_owned())
            })?;
        if !actual_name.eq_ignore_ascii_case(&expected_name) {
            // WORK_UNIT_CASE: 979/3 — conflicting directory name, never current.
            observe_watchdog_observation(
                "publication.directory_name_conflicting",
                &decoded_publication_identities(&marker, &lease),
            );
            return Err(HostError::RecoveryRequired(
                "Watchdog publication directory is not content-addressed by its ORS receipt"
                    .to_owned(),
            ));
        }
    }
    // The exact retained readback is its own fact and its own phase, distinct
    // from the current-ORS comparison `verify_exact_current_watchdog_publication`
    // records. A temporary-directory decode carries no content-addressed final
    // name, so it never files under the destination phase.
    let decoded_phase = if require_final_name {
        "publication.decoded"
    } else {
        "publication.temporary_decoded"
    };
    // WORK_UNIT_CASE: 979/2 — decoded owner-observed publication with exact identity.
    // WORK_UNIT_CASE: 979/4 — service/process-start/generation identity preserved.
    observe_watchdog_observation(
        decoded_phase,
        &decoded_publication_identities(&marker, &lease),
    );
    Ok(HostWatchdogPublicationObservation {
        path: path.to_path_buf(),
        marker,
        admission,
        lease,
        retirement: observation.retirement_precondition(),
    })
}

#[cfg(windows)]
pub fn observe_host_watchdog_publication(
    path: &Path,
) -> Result<HostWatchdogPublicationObservation, HostError> {
    let observation = eliot_platform_windows::observe_owned_directory_exact(
        path,
        &[
            WATCHDOG_ADMISSION_FILE_NAME,
            SUPERVISION_LEASE_FILE_NAME,
            WATCHDOG_PUBLICATION_FILE_NAME,
        ],
        super::WATCHDOG_PUBLICATION_CHILD_LIMIT,
    )
    .map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — unreadable publication directory, never ready/current.
        observe_watchdog_observation("publication.directory_unreadable", &NO_PUBLICATION_IDENTITY);
        HostError::RecoveryRequired(error.to_string())
    })?;
    // WORK_UNIT_CASE: 979/2 — owner-observed publication directory, distinct from verified current.
    // Children are present but nothing has been decoded, so the directory holds no
    // identity yet: its content address is proven only by decode plus the
    // final-name check, and no child is reread to enrich this record.
    observe_watchdog_observation("publication.directory_observed", &NO_PUBLICATION_IDENTITY);
    decode_watchdog_publication_observation(path, &observation, true)
}

#[cfg(windows)]
pub fn verify_exact_current_watchdog_publication(
    observed: &HostWatchdogPublicationObservation,
    template: &WatchdogAdmissionTemplate,
    current: &eliot_ors::SupervisionLeaseSnapshot,
) -> Result<(), HostError> {
    if observed.admission != *template
        || observed.lease != current.record.artifact
        || observed.marker.lease_revision != current.record.revision
        || observed.marker.ors_record_id != current.record.record_id.as_str()
        || observed.marker.ors_receipt_sha256 != current.receipt.receipt_sha256
    {
        // WORK_UNIT_CASE: 979/2 — observed publication is not the exact current head.
        // WORK_UNIT_CASE: 979/3 — stale/conflicting publication, never ready/current.
        // The slots carry the OBSERVED publication, the subject under comparison.
        // The requested template and the current ORS head are the comparison
        // basis and are never merged into these slots, so a rejected record can
        // never be read as the current head's own identity.
        observe_watchdog_observation(
            "publication.exact_current_rejected",
            &decoded_publication_identities(&observed.marker, &observed.lease),
        );
        return Err(HostError::RecoveryRequired(
            "Watchdog publication is not the exact authoritative ORS head".to_owned(),
        ));
    }
    // WORK_UNIT_CASE: 979/2 — publication verified as the exact authoritative ORS head.
    // This phase exists only after the exact retained readback above and this
    // current-ORS comparison both passed; it is never emitted for an unverified
    // or merely occupied publication directory.
    observe_watchdog_observation(
        "publication.exact_current_verified",
        &decoded_publication_identities(&observed.marker, &observed.lease),
    );
    Ok(())
}

#[cfg(windows)]
pub(super) fn scan_host_watchdog_publications(
    host_state_root: &Path,
) -> Result<Vec<HostWatchdogPublicationObservation>, HostError> {
    let mut observed = Vec::new();
    for entry in std::fs::read_dir(host_state_root).map_err(|error| {
        // WORK_UNIT_CASE: 979/3 — unreadable spool root, never ready/current.
        observe_watchdog_observation(
            "publication.spool_root_unreadable",
            &NO_PUBLICATION_IDENTITY,
        );
        HostError::RecoveryRequired(error.to_string())
    })? {
        let entry = entry.map_err(|error| {
            // WORK_UNIT_CASE: 979/3 — unreadable spool entry, never ready/current.
            observe_watchdog_observation(
                "publication.spool_entry_unreadable",
                &NO_PUBLICATION_IDENTITY,
            );
            HostError::RecoveryRequired(error.to_string())
        })?;
        let name = entry
            .file_name()
            .to_str()
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                // WORK_UNIT_CASE: 979/4 — non-Unicode spool name, identity unproven.
                // The name itself is the rejected value and a raw path component,
                // so it is never recorded; nothing else is held here yet.
                observe_watchdog_observation(
                    "publication.spool_name_rejected",
                    &NO_PUBLICATION_IDENTITY,
                );
                HostError::RecoveryRequired("Host state child name is not Unicode".to_owned())
            })?;
        if !name
            .to_ascii_lowercase()
            .starts_with(WATCHDOG_PUBLICATION_DIRECTORY_PREFIX)
        {
            continue;
        }
        // `?` propagates the already-observed inner decode boundary; no second record.
        observed.push(observe_host_watchdog_publication(&entry.path())?);
    }
    observed.sort_by(|left, right| left.path.cmp(&right.path));
    // WORK_UNIT_CASE: 979/2 — ordered spool scan of owner-observed publications.
    // This boundary holds a SET of decoded publications, not one publication, and
    // a single-valued identity slot could only attribute one member to the whole
    // scan. Every slot therefore stays explicitly missing here; each member's own
    // identity travels in that member's own decode and verify records.
    observe_watchdog_observation("publication.spool_scanned", &NO_PUBLICATION_IDENTITY);
    Ok(observed)
}
