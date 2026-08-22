use eliot_contracts::sha256_hex;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    RegisteredActivityWakePolicy, SignedSupervisionLease, SupervisionLeaseError,
    SupervisionObservationScope, SupervisionTrustAnchor, canonical_observation_scope,
    canonical_wake_policy,
};

/// Canonical schema for the immutable, public Watchdog admission template.
pub const WATCHDOG_ADMISSION_SCHEMA: &str = "eliot.watchdog-admission.v2";
/// Canonical schema for one immutable Host publication bundle.
pub const WATCHDOG_PUBLICATION_SCHEMA: &str = "eliot.watchdog-publication.v2";
/// Content-addressed directory prefix below the approved Host state root.
pub const WATCHDOG_PUBLICATION_DIRECTORY_PREFIX: &str = "watchdog-supervision-";
/// Canonical admission child inside one immutable publication directory.
pub const WATCHDOG_ADMISSION_FILE_NAME: &str = "watchdog-admission.json";
/// Canonical signed-lease child inside one immutable publication directory.
pub const SUPERVISION_LEASE_FILE_NAME: &str = "supervision-lease.json";
/// Canonical bundle marker child inside one immutable publication directory.
pub const WATCHDOG_PUBLICATION_FILE_NAME: &str = "watchdog-publication.json";
/// Current bundle plus one predecessor retained for bounded audit/recovery.
pub const WATCHDOG_PUBLICATION_RETAINED_LIMIT: usize = 2;

/// Validation failure for public Watchdog admission/publication contracts.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum WatchdogPublicationError {
    /// A required textual field is blank or contains a control character.
    #[error("{field} is not valid text")]
    InvalidText { field: &'static str },
    /// A strict schema marker did not match the supported contract.
    #[error("{field} has an unsupported schema")]
    UnsupportedSchema { field: &'static str },
    /// A digest is not canonical lowercase SHA-256.
    #[error("{field} is not a lowercase SHA-256 digest")]
    InvalidDigest { field: &'static str },
    /// The externally provisioned public trust anchor is invalid.
    #[error("watchdog admission trust anchor: {0}")]
    TrustAnchor(#[from] SupervisionLeaseError),
    /// The contract could not be serialized canonically.
    #[error("watchdog publication canonical encoding failed")]
    Encoding,
    /// The marker does not bind the exact admission/lease bytes.
    #[error("watchdog publication marker does not bind the exact file bytes")]
    ContentMismatch,
    /// The observed immutable spool cannot be reduced without risking the
    /// exact current ORS-bound publication.
    #[error("watchdog publication retention set is invalid")]
    InvalidRetentionSet,
}

fn validate_text(value: &str, field: &'static str) -> Result<(), WatchdogPublicationError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(WatchdogPublicationError::InvalidText { field });
    }
    Ok(())
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_digest(value: &str, field: &'static str) -> Result<(), WatchdogPublicationError> {
    if !is_sha256_hex(value) {
        return Err(WatchdogPublicationError::InvalidDigest { field });
    }
    Ok(())
}

/// Immutable public admission selected by an approved installation manifest.
///
/// Dynamic lease state is deliberately absent. The provisioned Phase-B
/// authority binds the digest of these canonical bytes; Host publishes the
/// current signed ORS artifact in a separate immutable bundle. No private key
/// locator crosses this type.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogAdmissionTemplate {
    /// Strict public admission schema.
    pub schema: String,
    /// Installation identity which owns the public trust anchor.
    pub installation_id: String,
    /// Exact approved manifest generation.
    pub approved_generation: String,
    /// Exact installation-approved supervision lease scope identity.
    pub supervision_lease_scope_id: String,
    /// Immutable observation policy covered by the admission digest.
    pub observation_scope: SupervisionObservationScope,
    /// Immutable wake policy covered by the admission digest.
    pub wake_policy: RegisteredActivityWakePolicy,
    /// Public verifier provisioned by the installer authority lane.
    pub trust_anchor: SupervisionTrustAnchor,
}

impl WatchdogAdmissionTemplate {
    /// Builds the strict current public template.
    pub fn new(
        installation_id: impl Into<String>,
        approved_generation: impl Into<String>,
        supervision_lease_scope_id: impl Into<String>,
        trust_anchor: SupervisionTrustAnchor,
    ) -> Result<Self, WatchdogPublicationError> {
        let template = Self {
            schema: WATCHDOG_ADMISSION_SCHEMA.to_owned(),
            installation_id: installation_id.into(),
            approved_generation: approved_generation.into(),
            supervision_lease_scope_id: supervision_lease_scope_id.into(),
            observation_scope: canonical_observation_scope(),
            wake_policy: canonical_wake_policy(),
            trust_anchor,
        };
        template.validate()?;
        Ok(template)
    }

    /// Validates strict schema, identities and the externally provisioned key.
    pub fn validate(&self) -> Result<(), WatchdogPublicationError> {
        if self.schema != WATCHDOG_ADMISSION_SCHEMA {
            return Err(WatchdogPublicationError::UnsupportedSchema {
                field: "watchdog_admission.schema",
            });
        }
        validate_text(&self.installation_id, "watchdog_admission.installation_id")?;
        validate_text(
            &self.approved_generation,
            "watchdog_admission.approved_generation",
        )?;
        validate_text(
            &self.supervision_lease_scope_id,
            "watchdog_admission.supervision_lease_scope_id",
        )?;
        self.observation_scope
            .validate()
            .map_err(|_| WatchdogPublicationError::InvalidText {
                field: "watchdog_admission.observation_scope",
            })?;
        self.wake_policy
            .validate()
            .map_err(|_| WatchdogPublicationError::InvalidText {
                field: "watchdog_admission.wake_policy",
            })?;
        if self.observation_scope != canonical_observation_scope()
            || self.wake_policy != canonical_wake_policy()
        {
            return Err(WatchdogPublicationError::InvalidText {
                field: "watchdog_admission.policy",
            });
        }
        self.trust_anchor.validate()?;
        if self.trust_anchor.installation_id != self.installation_id {
            return Err(WatchdogPublicationError::InvalidText {
                field: "watchdog_admission.trust_anchor.installation_id",
            });
        }
        Ok(())
    }

    /// Returns the exact canonical JSON bytes covered by the Phase-B binding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WatchdogPublicationError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| WatchdogPublicationError::Encoding)
    }

    /// Computes the Phase-B-facing lowercase SHA-256 template digest.
    pub fn digest(&self) -> Result<String, WatchdogPublicationError> {
        Ok(sha256_hex(&self.canonical_bytes()?))
    }
}

/// Marker inside one atomically published, content-addressed directory.
/// Readers derive the directory solely from the current ORS receipt digest,
/// retain all three children, and reject any byte, identity, or ORS mismatch.
#[derive(Clone, Debug, Eq, JsonSchema, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchdogPublicationBundle {
    /// Strict marker schema.
    pub schema: String,
    /// Manifest-bound installation identity.
    pub installation_id: String,
    /// Manifest-bound approved generation.
    pub approved_generation: String,
    /// Manifest-bound supervision lease scope identity.
    pub supervision_lease_scope_id: String,
    /// Manifest-bound supervision lease identity.
    pub supervision_lease_id: String,
    /// Exact committed ORS lease revision.
    pub lease_revision: u64,
    /// Exact current ORS record identity.
    pub ors_record_id: String,
    /// Exact current ORS receipt digest.
    pub ors_receipt_sha256: String,
    /// Digest of the exact canonical admission file bytes.
    pub admission_sha256: String,
    /// Digest of the exact canonical signed-lease file bytes.
    pub lease_sha256: String,
}

impl WatchdogPublicationBundle {
    /// Constructs the canonical marker for exact admission and lease bytes.
    pub fn new(
        admission: &WatchdogAdmissionTemplate,
        lease_revision: u64,
        ors_record_id: impl Into<String>,
        ors_receipt_sha256: impl Into<String>,
        lease_bytes: &[u8],
    ) -> Result<Self, WatchdogPublicationError> {
        let admission_bytes = admission.canonical_bytes()?;
        let signed: SignedSupervisionLease =
            serde_json::from_slice(lease_bytes).map_err(|_| WatchdogPublicationError::Encoding)?;
        signed
            .validate()
            .map_err(|_| WatchdogPublicationError::ContentMismatch)?;
        let marker = Self {
            schema: WATCHDOG_PUBLICATION_SCHEMA.to_owned(),
            installation_id: admission.installation_id.clone(),
            approved_generation: admission.approved_generation.clone(),
            supervision_lease_scope_id: admission.supervision_lease_scope_id.clone(),
            supervision_lease_id: signed.payload.lease_id,
            lease_revision,
            ors_record_id: ors_record_id.into(),
            ors_receipt_sha256: ors_receipt_sha256.into(),
            admission_sha256: sha256_hex(&admission_bytes),
            lease_sha256: sha256_hex(lease_bytes),
        };
        marker.validate()?;
        Ok(marker)
    }

    /// Validates marker shape without trusting the referenced files.
    pub fn validate(&self) -> Result<(), WatchdogPublicationError> {
        if self.schema != WATCHDOG_PUBLICATION_SCHEMA {
            return Err(WatchdogPublicationError::UnsupportedSchema {
                field: "watchdog_publication.schema",
            });
        }
        validate_text(
            &self.installation_id,
            "watchdog_publication.installation_id",
        )?;
        validate_text(
            &self.approved_generation,
            "watchdog_publication.approved_generation",
        )?;
        validate_text(
            &self.supervision_lease_scope_id,
            "watchdog_publication.supervision_lease_scope_id",
        )?;
        validate_text(
            &self.supervision_lease_id,
            "watchdog_publication.supervision_lease_id",
        )?;
        validate_text(&self.ors_record_id, "watchdog_publication.ors_record_id")?;
        if self.lease_revision == 0 {
            return Err(WatchdogPublicationError::InvalidText {
                field: "watchdog_publication.lease_revision",
            });
        }
        validate_digest(
            &self.ors_receipt_sha256,
            "watchdog_publication.ors_receipt_sha256",
        )?;
        validate_digest(
            &self.admission_sha256,
            "watchdog_publication.admission_sha256",
        )?;
        validate_digest(&self.lease_sha256, "watchdog_publication.lease_sha256")
    }

    /// Confirms the marker covers the exact two public child byte strings.
    pub fn verify_bytes(
        &self,
        admission_bytes: &[u8],
        lease_bytes: &[u8],
    ) -> Result<(), WatchdogPublicationError> {
        self.validate()?;
        if sha256_hex(admission_bytes) != self.admission_sha256
            || sha256_hex(lease_bytes) != self.lease_sha256
        {
            return Err(WatchdogPublicationError::ContentMismatch);
        }
        Ok(())
    }

    /// Returns the sole allowed directory name for this ORS head.
    pub fn directory_name(&self) -> Result<String, WatchdogPublicationError> {
        self.validate()?;
        Ok(format!(
            "{WATCHDOG_PUBLICATION_DIRECTORY_PREFIX}{}",
            self.ors_receipt_sha256
        ))
    }

    /// Returns the canonical marker bytes stored inside the bundle directory.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WatchdogPublicationError> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| WatchdogPublicationError::Encoding)
    }
}

/// Deterministic bounded-retention decision for an already durable current
/// publication. Only the exact ORS receipt digests are returned; filesystem
/// retirement still requires an independently retained directory/file
/// identity fence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WatchdogPublicationRetentionPlan {
    retained_receipt_digests: Vec<String>,
    retired_receipt_digests: Vec<String>,
}

impl WatchdogPublicationRetentionPlan {
    /// Selects current plus at most one immediately preceding revision. The
    /// current receipt must occur exactly once and can never be selected for
    /// retirement. Duplicate receipt digests fail closed.
    pub fn for_current(
        current: &WatchdogPublicationBundle,
        observed: &[WatchdogPublicationBundle],
    ) -> Result<Self, WatchdogPublicationError> {
        current.validate()?;
        if observed.is_empty() {
            return Err(WatchdogPublicationError::InvalidRetentionSet);
        }
        let mut unique = std::collections::BTreeSet::new();
        let mut unique_revisions = std::collections::BTreeSet::new();
        let mut current_count = 0_usize;
        for marker in observed {
            marker.validate()?;
            if marker.installation_id != current.installation_id
                || marker.approved_generation != current.approved_generation
                || marker.supervision_lease_scope_id != current.supervision_lease_scope_id
                || marker.admission_sha256 != current.admission_sha256
                || (marker.ors_receipt_sha256 != current.ors_receipt_sha256
                    && marker.lease_revision >= current.lease_revision)
            {
                return Err(WatchdogPublicationError::InvalidRetentionSet);
            }
            if !unique.insert(marker.ors_receipt_sha256.as_str())
                || !unique_revisions.insert(marker.lease_revision)
            {
                return Err(WatchdogPublicationError::InvalidRetentionSet);
            }
            if marker.ors_receipt_sha256 == current.ors_receipt_sha256 {
                current_count += 1;
                if marker != current {
                    return Err(WatchdogPublicationError::InvalidRetentionSet);
                }
            }
        }
        if current_count != 1 {
            return Err(WatchdogPublicationError::InvalidRetentionSet);
        }

        let mut prior = observed
            .iter()
            .filter(|marker| marker.ors_receipt_sha256 != current.ors_receipt_sha256)
            .collect::<Vec<_>>();
        prior.sort_by(|left, right| {
            right
                .lease_revision
                .cmp(&left.lease_revision)
                .then_with(|| right.ors_receipt_sha256.cmp(&left.ors_receipt_sha256))
        });
        let mut retained_receipt_digests = vec![current.ors_receipt_sha256.clone()];
        if WATCHDOG_PUBLICATION_RETAINED_LIMIT > 1 {
            retained_receipt_digests.extend(
                prior
                    .iter()
                    .take(WATCHDOG_PUBLICATION_RETAINED_LIMIT - 1)
                    .map(|marker| marker.ors_receipt_sha256.clone()),
            );
        }
        let retained = retained_receipt_digests
            .iter()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        let retired_receipt_digests: Vec<String> = observed
            .iter()
            .filter(|marker| !retained.contains(marker.ors_receipt_sha256.as_str()))
            .map(|marker| marker.ors_receipt_sha256.clone())
            .collect();
        debug_assert!(
            !retired_receipt_digests
                .iter()
                .any(|digest| digest == &current.ors_receipt_sha256)
        );
        Ok(Self {
            retained_receipt_digests,
            retired_receipt_digests,
        })
    }

    /// Exact current/prior digest set retained after successful cleanup.
    #[must_use]
    pub fn retained_receipt_digests(&self) -> &[String] {
        &self.retained_receipt_digests
    }

    /// Exact non-current digest set eligible for identity-bound retirement.
    #[must_use]
    pub fn retired_receipt_digests(&self) -> &[String] {
        &self.retired_receipt_digests
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use eliot_contracts::{AuthorityEpoch, ResourceGeneration, StateFence};

    fn signed_lease_bytes(lease_id: &str) -> Vec<u8> {
        let signer = crate::Ed25519SupervisionLeaseSigner::from_secret_key(
            "eliot-kernel",
            "test-supervision-key",
            [7; 32],
        )
        .expect("signer");
        let generation = ResourceGeneration::new(1).expect("generation");
        let kernel_epoch = AuthorityEpoch::new(2).expect("kernel epoch");
        let lease = crate::SupervisionLease {
            schema: crate::SUPERVISION_LEASE_SCHEMA.to_owned(),
            contract_name: crate::SUPERVISION_LEASE_CONTRACT_NAME.to_owned(),
            contract_version: crate::SUPERVISION_LEASE_CONTRACT_VERSION,
            lease_id: lease_id.to_owned(),
            scope_ref: "scope-ref".to_owned(),
            observation_scope: crate::canonical_observation_scope(),
            installation_id: "installation-1".to_owned(),
            host_epoch: AuthorityEpoch::new(1).expect("host epoch"),
            activation_id: "activation-1".to_owned(),
            activation_generation: generation,
            kernel_epoch,
            watchdog_epoch: AuthorityEpoch::new(1).expect("watchdog epoch"),
            generation_binding: crate::SupervisionGenerationBinding {
                target_id: "eliot-kernel".to_owned(),
                target_generation: generation,
                module_id: "eliot-kernel".to_owned(),
                module_generation: generation,
                process_id: "process-1".to_owned(),
                process_generation: generation,
            },
            state_fence: StateFence::new(kernel_epoch, generation),
            ors_mirror: crate::SupervisionOrsMirrorBinding {
                record_id: "record-1".to_owned(),
                subject_lease_id: lease_id.to_owned(),
                lease_revision: 1,
                ticket_sha256: "a".repeat(64),
                previous_receipt_sha256: None,
            },
            issued_at_ms: 1,
            expires_at_ms: 3,
            renew_before_ms: 2,
            wake_policy: crate::canonical_wake_policy(),
            state: crate::LeaseState::Active,
            terminal_disposition: None,
            revocation_reason: None,
            revocation_id: None,
            revocation_epoch: None,
        };
        serde_json::to_vec(&lease.sign(&signer).expect("signed lease")).expect("lease bytes")
    }

    fn anchor() -> SupervisionTrustAnchor {
        let signer =
            crate::Ed25519SupervisionLeaseSigner::from_secret_key("kernel", "key", [7; 32])
                .expect("signer");
        SupervisionTrustAnchor::new(
            "installation-1",
            "kernel",
            "key",
            signer.public_key().to_vec(),
        )
        .expect("anchor")
    }

    #[test]
    fn admission_digest_binds_public_anchor_and_lease_identity() {
        let template =
            WatchdogAdmissionTemplate::new("installation-1", "generation-7", "lease-7", anchor())
                .expect("template");
        let digest = template.digest().expect("digest");
        assert!(is_sha256_hex(&digest));

        let mut substituted = template;
        substituted.supervision_lease_scope_id = "scope-8".to_owned();
        assert_ne!(substituted.digest().expect("substituted digest"), digest);
    }

    #[test]
    fn marker_rejects_mixed_admission_and_lease_bytes() {
        let lease = signed_lease_bytes("lease-v1");
        let template =
            WatchdogAdmissionTemplate::new("installation-1", "generation-7", "lease-7", anchor())
                .expect("template");
        let marker =
            WatchdogPublicationBundle::new(&template, 3, "record-3", "a".repeat(64), &lease)
                .expect("marker");
        let admission = template.canonical_bytes().expect("admission bytes");
        marker
            .verify_bytes(&admission, &lease)
            .expect("exact bundle");
        assert_eq!(
            marker.verify_bytes(&admission, b"lease-v2"),
            Err(WatchdogPublicationError::ContentMismatch)
        );
        assert_eq!(
            marker.directory_name().expect("directory name"),
            format!("{WATCHDOG_PUBLICATION_DIRECTORY_PREFIX}{}", "a".repeat(64))
        );
    }

    #[test]
    fn renewal_flood_stays_bounded_and_never_retires_current() {
        let template =
            WatchdogAdmissionTemplate::new("installation-1", "generation-7", "lease-7", anchor())
                .expect("template");
        let mut durable = Vec::new();
        for revision in 1_u64..=64 {
            let current = WatchdogPublicationBundle::new(
                &template,
                revision,
                format!("record-{revision}"),
                format!("{revision:064x}"),
                &signed_lease_bytes(&format!("lease-{revision}")),
            )
            .expect("marker");
            durable.push(current.clone());
            let plan = WatchdogPublicationRetentionPlan::for_current(&current, &durable)
                .expect("retention plan");
            assert!(
                !plan
                    .retired_receipt_digests()
                    .contains(&current.ors_receipt_sha256),
                "current publication must never be selected for retirement"
            );
            durable.retain(|marker| {
                !plan
                    .retired_receipt_digests()
                    .contains(&marker.ors_receipt_sha256)
            });
            assert!(durable.len() <= WATCHDOG_PUBLICATION_RETAINED_LIMIT);
            assert!(
                durable
                    .iter()
                    .any(|marker| marker.ors_receipt_sha256 == current.ors_receipt_sha256)
            );
        }
    }

    #[test]
    fn retention_rejects_foreign_template_even_at_higher_revision() {
        let template =
            WatchdogAdmissionTemplate::new("installation-1", "generation-7", "lease-7", anchor())
                .expect("template");
        let current = WatchdogPublicationBundle::new(
            &template,
            7,
            "record-7",
            "7".repeat(64),
            &signed_lease_bytes("lease-7"),
        )
        .expect("current");
        let foreign_template =
            WatchdogAdmissionTemplate::new("installation-1", "generation-8", "lease-8", anchor())
                .expect("foreign template");
        let foreign = WatchdogPublicationBundle::new(
            &foreign_template,
            999,
            "foreign-record",
            "f".repeat(64),
            &signed_lease_bytes("foreign-lease"),
        )
        .expect("foreign marker");
        assert_eq!(
            WatchdogPublicationRetentionPlan::for_current(&current, &[current.clone(), foreign]),
            Err(WatchdogPublicationError::InvalidRetentionSet)
        );
    }

    #[test]
    fn retention_rejects_noncurrent_same_or_future_revision() {
        let template =
            WatchdogAdmissionTemplate::new("installation-1", "generation-7", "lease-7", anchor())
                .expect("template");
        let current = WatchdogPublicationBundle::new(
            &template,
            7,
            "record-7",
            "7".repeat(64),
            &signed_lease_bytes("lease-7"),
        )
        .expect("current");
        for revision in [7, 8] {
            let forged = WatchdogPublicationBundle::new(
                &template,
                revision,
                format!("record-{revision}-forged"),
                format!("{revision:064x}"),
                &signed_lease_bytes("forged"),
            )
            .expect("forged marker");
            assert_eq!(
                WatchdogPublicationRetentionPlan::for_current(&current, &[current.clone(), forged]),
                Err(WatchdogPublicationError::InvalidRetentionSet)
            );
        }
    }

    #[test]
    fn retention_rejects_duplicate_prior_revision() {
        let template =
            WatchdogAdmissionTemplate::new("installation-1", "generation-7", "lease-7", anchor())
                .expect("template");
        let marker = |revision: u64, digest_byte: char| {
            WatchdogPublicationBundle::new(
                &template,
                revision,
                format!("record-{revision}-{digest_byte}"),
                digest_byte.to_string().repeat(64),
                &signed_lease_bytes(&format!("lease-{revision}-{digest_byte}")),
            )
            .expect("marker")
        };
        let current = marker(7, '7');
        assert_eq!(
            WatchdogPublicationRetentionPlan::for_current(
                &current,
                &[current.clone(), marker(6, 'a'), marker(6, 'b')]
            ),
            Err(WatchdogPublicationError::InvalidRetentionSet)
        );
    }
}
