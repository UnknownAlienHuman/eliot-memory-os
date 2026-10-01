//! Owner-side typed load and compare-and-swap publication for the Human
//! model preference policy (issue #485, audit 5872395796 step 2).
//!
//! Owner: `eliot-host-state`. The schema stays where step 1 put it
//! (`eliot-agent-contracts::model_preference`, I/O-free); the pure validator
//! stays in `eliot-config` (no I/O added there); the A-02 coordinator only
//! consumes the published policy. This crate durably publishes exactly one
//! versioned preference document per configured store file and arbitrates
//! every replacement against the exact current store/policy identity inside
//! one redb write transaction. redb takes an exclusive OS file lock and
//! serializes writers across processes, so the read/compare/commit section
//! is a genuine interprocess CAS: no new mutex, `&mut` handle, or
//! last-writer-wins file overwrite stands in for it.
//!
//! Semantics owned here are purely mechanical: absolute-path and
//! symlink/reparse guards, versioned-envelope classification, byte-size
//! bound, identity/digest equality, and monotonically checked store-revision
//! advance. Policy meaning (roles, selectors, billing) is interpreted only
//! by the contract owner through
//! [`HumanModelPreferencePolicy::validate`](eliot_agent_contracts::model_preference::HumanModelPreferencePolicy::validate)
//! and
//! [`preference_policy_digest`](eliot_agent_contracts::model_preference::preference_policy_digest);
//! this module never branches on preference content.
//!
//! Residuals (later slices, not this one): R3 serializes the daemon-side
//! publication critical section and pins the exact protected storage
//! contour; R4 reconstructs the immutable publication receipt from the
//! retained committed document; R5 wires the #484 candidate-side CAS anchor
//! to this owner recheck. No production caller exists yet on purpose: the
//! daemon/publication wiring is STITCH and must arrive with its own review.

use std::path::{Path, PathBuf};

use eliot_agent_contracts::{
    HumanModelPreferencePolicy, ModelControlError, preference_policy_digest,
};
use redb::{Database, ReadOnlyDatabase, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Magic of the preference store metadata envelope.
pub const MODEL_PREFERENCE_STORE_MAGIC: &str = "ELIOT-MODEL-PREFERENCE-STORE-V1";
/// Version of the preference store metadata and document envelopes.
pub const MODEL_PREFERENCE_ENVELOPE_VERSION: u16 = 1;
/// Largest retained preference document (envelope bytes) accepted on read
/// or offered for commit. Oversized input fails closed; it is never
/// truncated or partially applied.
pub const MAX_MODEL_PREFERENCE_DOCUMENT_BYTES: usize = 262_144;

const META_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_model_preference_meta_v1");
const PREFS_TABLE: TableDefinition<&str, &[u8]> =
    TableDefinition::new("eliot_model_preferences_v1");
const META_KEY: &str = "meta";
const CURRENT_KEY: &str = "current";

/// Typed failure of preference load or compare-and-swap.
///
/// Every variant fails closed: stale, mismatched, corrupt, oversized, or
/// unknown-version input never commits, never invents a publication, and
/// never reports success.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ModelPreferenceStoreError {
    /// The store file or database backend is unavailable.
    #[error("model preference store is unavailable")]
    Unavailable,
    /// Stored bytes are not a valid versioned preference publication.
    #[error("model preference store is corrupt")]
    Corrupt,
    /// The retained or offered document exceeds the byte bound.
    #[error("model preference document exceeds the byte bound")]
    Oversized,
    /// The store carries an envelope version this owner does not publish.
    #[error("model preference store envelope version {version} is not supported")]
    Legacy { version: u16 },
    /// The expected predecessor identity does not match the retained
    /// publication. Includes the absent-store/nonzero-expectation case and
    /// the second-writer-loses case: the same expected predecessor with
    /// different replacement bytes commits at most once.
    #[error("model preference predecessor is stale")]
    Stale,
    /// The replacement changes the account scope of the retained policy.
    #[error("model preference replacement changes account scope")]
    ScopeMismatch,
    /// The replacement changes the policy ID of the retained policy.
    #[error("model preference replacement changes policy ID")]
    PolicyIdMismatch,
    /// The offered replacement policy is structurally invalid.
    #[error(transparent)]
    Policy(#[from] ModelControlError),
}

/// Validated read view of the retained preference publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelPreferencePublication {
    /// Monotonic store revision of the retained document. Genesis is 1;
    /// 0 never names a committed publication.
    pub store_revision: u64,
    /// The exact retained policy. Structural validity and digest match
    /// against `policy_digest` were both rechecked on load.
    pub policy: HumanModelPreferencePolicy,
    /// Canonical digest of `policy` recomputed by the owner on load, never
    /// copied from an unverified caller claim.
    pub policy_digest: String,
}

/// Exact expected predecessor identity for compare-and-swap.
///
/// Revision 0 with empty policy fields names the absent store (genesis
/// publication). Any other expectation must match the retained publication
/// field-for-field or the CAS fails closed with
/// [`ModelPreferenceStoreError::Stale`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreferenceCasExpected {
    /// Expected store revision of the retained document; 0 means the store
    /// must hold no publication.
    pub store_revision: u64,
    /// Expected policy ID of the retained document; empty for genesis.
    pub policy_id: String,
    /// Expected policy revision of the retained document; empty for genesis.
    pub policy_revision: String,
    /// Expected canonical digest of the retained document; empty for genesis.
    pub policy_digest: String,
}

/// Outcome of
/// [`ModelPreferenceStore::compare_and_swap_model_preferences`].
///
/// There are exactly two success shapes: a committed advance and an
/// identical replay. A replay performs no write and bumps no revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ModelPreferenceCasOutcome {
    /// The replacement committed as a new store revision.
    Committed {
        /// The newly committed store revision (predecessor + 1).
        store_revision: u64,
    },
    /// The replacement was canonically identical to the retained policy
    /// under a matching predecessor: idempotent, no write performed.
    Replayed {
        /// The retained store revision, unchanged.
        store_revision: u64,
    },
}

impl ModelPreferenceCasOutcome {
    /// The store revision this outcome leaves retained.
    #[must_use]
    pub const fn store_revision(self) -> u64 {
        match self {
            Self::Committed { store_revision } | Self::Replayed { store_revision } => {
                store_revision
            }
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreMeta {
    magic: String,
    version: u16,
}

/// The retained versioned preference document: exact policy, exact policy
/// digest, monotonically changing store revision, and the prior
/// revision/digest link. Genesis carries prior revision 0 and an empty
/// prior digest; every later document links its verified predecessor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredModelPreferenceEnvelope {
    /// Store magic. Must equal [`MODEL_PREFERENCE_STORE_MAGIC`].
    pub magic: String,
    /// Envelope version. Must equal [`MODEL_PREFERENCE_ENVELOPE_VERSION`].
    pub envelope_version: u16,
    /// Monotonic store revision. Genesis is 1; 0 never commits.
    pub store_revision: u64,
    /// Store revision of the superseded document; 0 for genesis.
    pub prior_store_revision: u64,
    /// Canonical policy digest of the superseded document; empty for genesis.
    pub prior_policy_digest: String,
    /// The exact published policy.
    pub policy: HumanModelPreferencePolicy,
    /// Owner-recomputed canonical digest of `policy`.
    pub policy_digest: String,
}

/// Owner handle for one configured preference store file.
///
/// Bound with [`ModelPreferenceStore::open`], which validates the
/// configured absolute path and existing-file shape but performs no
/// publication. Reads never create; the first committed publication mints
/// the file inside the genesis CAS. Parent directories are never created:
/// a missing parent fails closed with
/// [`ModelPreferenceStoreError::Unavailable`].
#[derive(Clone, Debug)]
pub struct ModelPreferenceStore {
    path: PathBuf,
}

fn validate_store_path(path: &Path) -> Result<PathBuf, ModelPreferenceStoreError> {
    if !path.is_absolute() {
        return Err(ModelPreferenceStoreError::Unavailable);
    }
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ModelPreferenceStoreError::Unavailable);
            }
        }
        Err(_) => return Err(ModelPreferenceStoreError::Unavailable),
    }
    Ok(path.to_path_buf())
}

fn map_database_error(error: &redb::DatabaseError) -> ModelPreferenceStoreError {
    match error {
        redb::DatabaseError::Storage(redb::StorageError::Corrupted(_)) => {
            ModelPreferenceStoreError::Corrupt
        }
        redb::DatabaseError::UpgradeRequired(version) => ModelPreferenceStoreError::Legacy {
            version: u16::from(*version),
        },
        _ => ModelPreferenceStoreError::Unavailable,
    }
}

fn classify_meta(bytes: &[u8]) -> Result<(), ModelPreferenceStoreError> {
    if bytes.len() > MAX_MODEL_PREFERENCE_DOCUMENT_BYTES {
        return Err(ModelPreferenceStoreError::Oversized);
    }
    let meta: StoreMeta =
        serde_json::from_slice(bytes).map_err(|_| ModelPreferenceStoreError::Corrupt)?;
    if meta.magic != MODEL_PREFERENCE_STORE_MAGIC {
        return Err(ModelPreferenceStoreError::Corrupt);
    }
    if meta.version != MODEL_PREFERENCE_ENVELOPE_VERSION {
        return Err(ModelPreferenceStoreError::Legacy {
            version: meta.version,
        });
    }
    Ok(())
}

fn decode_envelope(
    bytes: &[u8],
) -> Result<StoredModelPreferenceEnvelope, ModelPreferenceStoreError> {
    if bytes.len() > MAX_MODEL_PREFERENCE_DOCUMENT_BYTES {
        return Err(ModelPreferenceStoreError::Oversized);
    }
    let envelope: StoredModelPreferenceEnvelope =
        serde_json::from_slice(bytes).map_err(|_| ModelPreferenceStoreError::Corrupt)?;
    if envelope.magic != MODEL_PREFERENCE_STORE_MAGIC
        || envelope.envelope_version != MODEL_PREFERENCE_ENVELOPE_VERSION
    {
        return Err(ModelPreferenceStoreError::Corrupt);
    }
    if envelope.store_revision == 0 {
        return Err(ModelPreferenceStoreError::Corrupt);
    }
    Ok(envelope)
}

fn validated_publication(
    envelope: StoredModelPreferenceEnvelope,
) -> Result<ModelPreferencePublication, ModelPreferenceStoreError> {
    envelope.policy.validate()?;
    let digest = preference_policy_digest(&envelope.policy)?;
    if digest != envelope.policy_digest {
        return Err(ModelPreferenceStoreError::Corrupt);
    }
    Ok(ModelPreferencePublication {
        store_revision: envelope.store_revision,
        policy: envelope.policy,
        policy_digest: envelope.policy_digest,
    })
}

/// Pending CAS envelope for a validated predecessor: genesis demands a
/// zero/empty expectation; a retained publication demands an exact
/// predecessor match with scope/policy continuity, then replay on identical
/// digest or the next-revision envelope. No I/O, no writes.
enum CasPendingEnvelope {
    /// Canonically identical replacement under a matching predecessor:
    /// idempotent, persists nothing.
    Replayed {
        /// The retained store revision, unchanged.
        store_revision: u64,
    },
    /// Fresh envelope to persist as the next store revision.
    Commit(Box<StoredModelPreferenceEnvelope>),
}

/// Decides the CAS envelope for `compare_and_swap_model_preferences`
/// without touching the store.
fn decide_cas_envelope(
    expected: &PreferenceCasExpected,
    replacement: &HumanModelPreferencePolicy,
    replacement_digest: &str,
    current: Option<ModelPreferencePublication>,
) -> Result<CasPendingEnvelope, ModelPreferenceStoreError> {
    match current {
        None => {
            if expected.store_revision != 0
                || !expected.policy_id.is_empty()
                || !expected.policy_revision.is_empty()
                || !expected.policy_digest.is_empty()
            {
                return Err(ModelPreferenceStoreError::Stale);
            }
            Ok(CasPendingEnvelope::Commit(Box::new(
                StoredModelPreferenceEnvelope {
                    magic: MODEL_PREFERENCE_STORE_MAGIC.to_owned(),
                    envelope_version: MODEL_PREFERENCE_ENVELOPE_VERSION,
                    store_revision: 1,
                    prior_store_revision: 0,
                    prior_policy_digest: String::new(),
                    policy: replacement.clone(),
                    policy_digest: replacement_digest.to_owned(),
                },
            )))
        }
        Some(current) => {
            if expected.store_revision != current.store_revision
                || expected.policy_id != current.policy.policy_id
                || expected.policy_revision != current.policy.revision
                || expected.policy_digest != current.policy_digest
            {
                return Err(ModelPreferenceStoreError::Stale);
            }
            if replacement.account_scope != current.policy.account_scope {
                return Err(ModelPreferenceStoreError::ScopeMismatch);
            }
            if replacement.policy_id != current.policy.policy_id {
                return Err(ModelPreferenceStoreError::PolicyIdMismatch);
            }
            if replacement_digest == current.policy_digest {
                return Ok(CasPendingEnvelope::Replayed {
                    store_revision: current.store_revision,
                });
            }
            let next = current
                .store_revision
                .checked_add(1)
                .ok_or(ModelPreferenceStoreError::Unavailable)?;
            Ok(CasPendingEnvelope::Commit(Box::new(
                StoredModelPreferenceEnvelope {
                    magic: MODEL_PREFERENCE_STORE_MAGIC.to_owned(),
                    envelope_version: MODEL_PREFERENCE_ENVELOPE_VERSION,
                    store_revision: next,
                    prior_store_revision: current.store_revision,
                    prior_policy_digest: current.policy_digest,
                    policy: replacement.clone(),
                    policy_digest: replacement_digest.to_owned(),
                },
            )))
        }
    }
}

impl ModelPreferenceStore {
    /// Binds this owner to one configured absolute store path.
    ///
    /// Unlike the journal's creating open, this performs no I/O beyond the
    /// path-shape check: no file, directory, table, or publication is
    /// created here. A relative path, a symlink or reparse point, or a
    /// non-file object fails closed.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ModelPreferenceStoreError> {
        Ok(Self {
            path: validate_store_path(path.as_ref())?,
        })
    }

    /// The configured absolute store path this handle is bound to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads and validates the retained preference publication.
    ///
    /// Returns `Ok(None)` only for explicit absence: a missing file, or a
    /// reachable store whose metadata envelope was never initialized.
    /// Corrupt, oversized, unknown-version, digest-mismatched, or
    /// structurally invalid content fails closed; it is never returned
    /// as a publication.
    pub fn load_model_preferences(
        &self,
    ) -> Result<Option<ModelPreferencePublication>, ModelPreferenceStoreError> {
        validate_store_path(&self.path)?;
        let database = match ReadOnlyDatabase::open(&self.path) {
            Ok(database) => database,
            Err(error) => {
                if matches!(
                    error,
                    redb::DatabaseError::Storage(redb::StorageError::Io(ref io))
                        if io.kind() == std::io::ErrorKind::NotFound
                ) {
                    return Ok(None);
                }
                return Err(map_database_error(&error));
            }
        };
        let read = database
            .begin_read()
            .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
        let meta = match read.open_table(META_TABLE) {
            Ok(meta) => meta,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(_) => return Err(ModelPreferenceStoreError::Corrupt),
        };
        match meta
            .get(META_KEY)
            .map_err(|_| ModelPreferenceStoreError::Corrupt)?
        {
            None => return Ok(None),
            Some(guard) => classify_meta(guard.value())?,
        }
        let prefs = match read.open_table(PREFS_TABLE) {
            Ok(prefs) => prefs,
            Err(redb::TableError::TableDoesNotExist(_)) => {
                return Err(ModelPreferenceStoreError::Corrupt);
            }
            Err(_) => return Err(ModelPreferenceStoreError::Corrupt),
        };
        let envelope = match prefs
            .get(CURRENT_KEY)
            .map_err(|_| ModelPreferenceStoreError::Corrupt)?
        {
            None => return Err(ModelPreferenceStoreError::Corrupt),
            Some(guard) => decode_envelope(guard.value())?,
        };
        validated_publication(envelope).map(Some)
    }

    /// Atomically compares the retained publication against the exact
    /// expected predecessor identity and, on match, publishes the full
    /// replacement as the next store revision.
    ///
    /// The read/compare/commit section runs inside one redb write
    /// transaction, which the backend serializes across processes: the
    /// predecessor is re-read from the same transaction that commits, so
    /// two writers against one predecessor cannot both commit and the
    /// loser observes [`ModelPreferenceStoreError::Stale`]. The stored
    /// policy digest and the replacement digest are always recomputed by
    /// the owner; caller-supplied digests are expectations to check, never
    /// values to retain.
    ///
    /// Genesis (first publication) requires
    /// `expected.store_revision == 0` with empty policy identity fields and
    /// a store holding no publication; anything else is
    /// [`ModelPreferenceStoreError::Stale`]. A non-genesis CAS requires
    /// the full expected triple plus policy ID to match the retained
    /// document, stable account scope and policy ID in the replacement,
    /// and commits revision predecessor + 1 with the prior revision/digest
    /// link. A canonically identical replacement under a matching
    /// predecessor replays without writing.
    pub fn compare_and_swap_model_preferences(
        &self,
        expected: &PreferenceCasExpected,
        replacement: &HumanModelPreferencePolicy,
    ) -> Result<ModelPreferenceCasOutcome, ModelPreferenceStoreError> {
        replacement.validate()?;
        let replacement_digest = preference_policy_digest(replacement)?;
        validate_store_path(&self.path)?;
        let database = match std::fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Database::create(&self.path).map_err(|error| map_database_error(&error))?
            }
            Ok(_) => Database::open(&self.path).map_err(|error| map_database_error(&error))?,
            Err(_) => return Err(ModelPreferenceStoreError::Unavailable),
        };
        let write = database
            .begin_write()
            .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
        let outcome = {
            let mut meta = write
                .open_table(META_TABLE)
                .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
            let mut prefs = write
                .open_table(PREFS_TABLE)
                .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
            let current_meta: Option<Vec<u8>> = meta
                .get(META_KEY)
                .map_err(|_| ModelPreferenceStoreError::Corrupt)?
                .map(|guard| guard.value().to_vec());
            let current = match current_meta {
                None => {
                    let meta_bytes = serde_json::to_vec(&StoreMeta {
                        magic: MODEL_PREFERENCE_STORE_MAGIC.to_owned(),
                        version: MODEL_PREFERENCE_ENVELOPE_VERSION,
                    })
                    .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
                    meta.insert(META_KEY, meta_bytes.as_slice())
                        .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
                    None
                }
                Some(bytes) => {
                    classify_meta(&bytes)?;
                    match prefs
                        .get(CURRENT_KEY)
                        .map_err(|_| ModelPreferenceStoreError::Corrupt)?
                    {
                        None => return Err(ModelPreferenceStoreError::Corrupt),
                        Some(guard) => {
                            Some(validated_publication(decode_envelope(guard.value())?)?)
                        }
                    }
                }
            };
            let committed =
                match decide_cas_envelope(expected, replacement, &replacement_digest, current)? {
                    CasPendingEnvelope::Replayed { store_revision } => {
                        return Ok(ModelPreferenceCasOutcome::Replayed { store_revision });
                    }
                    CasPendingEnvelope::Commit(envelope) => *envelope,
                };
            let bytes = serde_json::to_vec(&committed)
                .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
            if bytes.len() > MAX_MODEL_PREFERENCE_DOCUMENT_BYTES {
                return Err(ModelPreferenceStoreError::Oversized);
            }
            prefs
                .insert(CURRENT_KEY, bytes.as_slice())
                .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
            ModelPreferenceCasOutcome::Committed {
                store_revision: committed.store_revision,
            }
        };
        write
            .commit()
            .map_err(|_| ModelPreferenceStoreError::Unavailable)?;
        Ok(outcome)
    }
}
