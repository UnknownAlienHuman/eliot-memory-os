//! Watchdog-domain audit anchor sink (issue #1840; I16.10, A13.8, I1.2).
//!
//! The Watchdog owns this directory and independently verifies the periodic
//! digest anchors the Kernel copies here through its bound anchor sink. Each
//! observed anchor is checked for shape, self-digest, chain identity, and
//! anchor-hash-chain continuity; the latest verified head (chain identity,
//! covered sequence, head digest) is the independent failure-domain evidence
//! that the corresponding chain prefix existed with that head.
//!
//! Format boundary, stated exactly: the anchor bytes verified here are the
//! Kernel `AuditAnchor` JSON wire format at
//! [`WATCHDOG_ANCHOR_FORMAT_VERSION`], which is bound to the Kernel's
//! `KERNEL_AUDIT_FORMAT_VERSION`. This sink introduces no second chain, no
//! alternate anchor scheme, and no new transport: the Kernel remains the
//! sole anchor writer and the file copy remains the transport. Prefix
//! verification against the retained chain stays Kernel-side through
//! `verify_audit_anchor_file` over [`WatchdogAuditAnchorSink::latest_anchor_path`];
//! this sink proves independent presence, self-integrity, and continuity.
//! Anchors store a digest, never semantic memory (A13.8).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use eliot_contracts::canonical_json_bytes;
use serde::{Deserialize, Serialize};

/// Anchor wire format version verified by this sink.
///
/// Bound to the Kernel's `KERNEL_AUDIT_FORMAT_VERSION`: a Kernel format
/// bump must update this constant together, never silently.
pub const WATCHDOG_ANCHOR_FORMAT_VERSION: u16 = 1;
/// Anchor sink directory name below the Watchdog root.
pub const WATCHDOG_ANCHOR_DIR_NAME: &str = "audit-anchors";
/// Stable `latest` anchor pointer file name inside the sink.
pub const WATCHDOG_ANCHOR_LATEST_FILE_NAME: &str = "latest-anchor.json";
/// Previous-anchor hash of the first anchor: 64 zero hex digits.
pub const WATCHDOG_ANCHOR_GENESIS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
/// Largest accepted single anchor file, in bytes.
pub const WATCHDOG_ANCHOR_MAX_FILE_BYTES: u64 = 64 * 1024;

/// Resolves the Watchdog-owned anchor sink below the Watchdog root.
#[must_use]
pub fn watchdog_anchor_dir(watchdog_root: &Path) -> PathBuf {
    watchdog_root.join(WATCHDOG_ANCHOR_DIR_NAME)
}

/// Returns the BLAKE3 hex digest of `bytes`.
#[must_use]
fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

/// Typed anchor-sink failure. Only the variant crosses diagnostics; path and
/// reason strings never reach the observation channel.
#[derive(Debug)]
pub enum AuditAnchorSinkError {
    /// The sink root is not absolute.
    NotAbsoluteRoot,
    /// The sink directory could not be created or read.
    Io {
        /// Failing path, for the caller only.
        path: PathBuf,
        /// OS error text, for the caller only.
        reason: String,
    },
    /// Canonical JSON encoding failed.
    Serialization(String),
}

impl std::fmt::Display for AuditAnchorSinkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAbsoluteRoot => formatter.write_str("anchor sink root must be absolute"),
            Self::Io { path, reason } => {
                write!(
                    formatter,
                    "anchor sink IO failed for {}: {reason}",
                    path.display()
                )
            }
            Self::Serialization(reason) => {
                write!(formatter, "anchor sink serialization failed: {reason}")
            }
        }
    }
}

impl std::error::Error for AuditAnchorSinkError {}

/// Kernel anchor wire view verified by this sink.
///
/// Field-for-field the Kernel `AuditAnchor` JSON shape; any unknown field
/// fails the anchor closed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnchorFileView {
    format_version: u16,
    chain_id: String,
    head_seq: u64,
    head_hash: String,
    prev_anchor_hash: String,
    record_count: u64,
    exported_at_ms: u64,
    anchor_digest: String,
}

/// Hash-covered anchor view: every field except `anchor_digest`, in the
/// exact Kernel field order the digest covers.
#[derive(Serialize)]
struct AnchorFileHashView<'a> {
    format_version: u16,
    chain_id: &'a str,
    head_seq: u64,
    head_hash: &'a str,
    prev_anchor_hash: &'a str,
    record_count: u64,
    exported_at_ms: u64,
}

impl AnchorFileView {
    /// Returns the canonical bytes covered by `anchor_digest`.
    fn signing_bytes(&self) -> Result<Vec<u8>, AuditAnchorSinkError> {
        let view = AnchorFileHashView {
            format_version: self.format_version,
            chain_id: &self.chain_id,
            head_seq: self.head_seq,
            head_hash: &self.head_hash,
            prev_anchor_hash: &self.prev_anchor_hash,
            record_count: self.record_count,
            exported_at_ms: self.exported_at_ms,
        };
        canonical_json_bytes(&view)
            .map_err(|error| AuditAnchorSinkError::Serialization(error.to_string()))
    }

    /// Recomputes the anchor digest from the anchor's own fields.
    fn recomputed_digest(&self) -> Result<String, AuditAnchorSinkError> {
        Ok(blake3_hex(&self.signing_bytes()?))
    }
}

/// One independently verified anchor head.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuditAnchorHead {
    /// Chain identity the anchor covers.
    pub chain_id: String,
    /// Covered prefix head sequence.
    pub head_seq: u64,
    /// Current hash of the covered head record.
    pub head_hash: String,
    /// Self-digest of the verified anchor.
    pub anchor_digest: String,
    /// Caller-supplied milliseconds when the sink verified the anchor.
    pub observed_at_ms: u64,
}

/// One rejected anchor file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorRejection {
    /// File name that failed verification.
    pub file: String,
    /// Stable rejection reason code.
    pub reason: &'static str,
}

/// Terminal view of one sink observation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AnchorSinkObservation {
    /// Anchors newly verified by this observation.
    pub verified_new: u64,
    /// Anchors already verified by an earlier observation.
    pub already_verified: u64,
    /// Rejected anchor files, each with its stable reason.
    pub rejected: Vec<AnchorRejection>,
    /// Latest verified head after this observation.
    pub latest: Option<VerifiedAuditAnchorHead>,
}

/// The Watchdog-owned audit anchor sink.
///
/// Owns the Watchdog-domain anchor directory: the Watchdog creates it and
/// the Kernel only copies anchor files into the bound path. Observation is
/// monotonic per sink handle — verified history is never re-verified and a
/// rejected file never advances the verified head — while every rejection
/// stays visible in the returned observation.
pub struct WatchdogAuditAnchorSink {
    dir: PathBuf,
    verified_through_seq: u64,
    verified_chain_id: Option<String>,
    prev_anchor_hash: String,
    latest: Option<VerifiedAuditAnchorHead>,
}

impl WatchdogAuditAnchorSink {
    /// Opens the sink over one Watchdog-owned directory.
    ///
    /// The directory is created when missing: unlike the Kernel's foreign
    /// binding, this directory is Watchdog-owned. No anchor is verified at
    /// open; the caller runs [`Self::observe`] with its own clock.
    ///
    /// # Errors
    ///
    /// Returns [`AuditAnchorSinkError`] when the directory is not absolute
    /// or cannot be created.
    pub fn open(dir: &Path) -> Result<Self, AuditAnchorSinkError> {
        if !dir.is_absolute() {
            return Err(AuditAnchorSinkError::NotAbsoluteRoot);
        }
        std::fs::create_dir_all(dir).map_err(|error| AuditAnchorSinkError::Io {
            path: dir.to_path_buf(),
            reason: error.to_string(),
        })?;
        Ok(Self {
            dir: dir.to_path_buf(),
            verified_through_seq: 0,
            verified_chain_id: None,
            prev_anchor_hash: WATCHDOG_ANCHOR_GENESIS_HASH.to_owned(),
            latest: None,
        })
    }

    /// Returns the sink directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the latest verified anchor head, if any.
    #[must_use]
    pub fn latest_verified(&self) -> Option<&VerifiedAuditAnchorHead> {
        self.latest.as_ref()
    }

    /// Returns the stable latest-anchor path for Kernel-side prefix proof.
    ///
    /// Feeding this path to the Kernel's `verify_audit_anchor_file` proves
    /// the Watchdog-domain copy against the retained chain prefix.
    #[must_use]
    pub fn latest_anchor_path(&self) -> PathBuf {
        self.dir.join(WATCHDOG_ANCHOR_LATEST_FILE_NAME)
    }

    /// Observes the sink directory, verifying newly arrived anchors.
    ///
    /// Anchor files verify in ascending head-sequence order; each must be
    /// self-consistent, carry the sink's chain identity, and continue the
    /// anchor hash chain. The stable `latest-anchor.json` pointer must
    /// agree with the highest verified anchor. Rejections never advance
    /// the verified head and never fail the observation itself.
    ///
    /// # Errors
    ///
    /// Returns [`AuditAnchorSinkError`] only when the sink directory
    /// cannot be read. Rejected anchors are observation data, not errors.
    pub fn observe(
        &mut self,
        observed_at_ms: u64,
    ) -> Result<AnchorSinkObservation, AuditAnchorSinkError> {
        let mut files = self.anchor_files()?;
        files.sort_unstable();
        let mut observation = AnchorSinkObservation {
            verified_new: 0,
            already_verified: 0,
            rejected: Vec::new(),
            latest: self.latest.clone(),
        };
        for (seq, name) in &files {
            if *seq <= self.verified_through_seq {
                observation.already_verified += 1;
                continue;
            }
            match self.verify_anchor_file(name, *seq, observed_at_ms) {
                Ok(head) => {
                    observation.verified_new += 1;
                    observation.latest = Some(head);
                }
                Err(reason) => observation.rejected.push(AnchorRejection {
                    file: name.clone(),
                    reason,
                }),
            }
        }
        self.check_latest_pointer(&mut observation);
        Ok(observation)
    }

    /// Lists `(head_seq, file_name)` anchor files in the sink directory.
    fn anchor_files(&self) -> Result<Vec<(u64, String)>, AuditAnchorSinkError> {
        let entries = std::fs::read_dir(&self.dir).map_err(|error| AuditAnchorSinkError::Io {
            path: self.dir.clone(),
            reason: error.to_string(),
        })?;
        let mut files = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| AuditAnchorSinkError::Io {
                path: self.dir.clone(),
                reason: error.to_string(),
            })?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(rest) = name
                .strip_prefix("anchor-")
                .and_then(|rest| rest.strip_suffix(".json"))
            else {
                continue;
            };
            let Ok(seq) = rest.parse::<u64>() else {
                continue;
            };
            files.push((seq, name));
        }
        Ok(files)
    }

    /// Verifies one anchor file and advances the verified head.
    fn verify_anchor_file(
        &mut self,
        name: &str,
        seq: u64,
        observed_at_ms: u64,
    ) -> Result<VerifiedAuditAnchorHead, &'static str> {
        let path = self.dir.join(name);
        let bytes = std::fs::read(&path).map_err(|_| "anchor_unreadable")?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > WATCHDOG_ANCHOR_MAX_FILE_BYTES {
            return Err("anchor_overbound");
        }
        let anchor: AnchorFileView =
            serde_json::from_slice(&bytes).map_err(|_| "anchor_unparseable")?;
        if anchor.format_version != WATCHDOG_ANCHOR_FORMAT_VERSION {
            return Err("format_version");
        }
        if anchor.head_seq == 0 || anchor.record_count != anchor.head_seq {
            return Err("anchor_prefix");
        }
        if anchor.head_seq != seq {
            return Err("anchor_file_name");
        }
        if anchor.chain_id.is_empty() || anchor.head_hash.is_empty() {
            return Err("anchor_identity");
        }
        let digest = anchor.recomputed_digest().map_err(|_| "anchor_digest")?;
        if digest != anchor.anchor_digest {
            return Err("anchor_digest");
        }
        match &self.verified_chain_id {
            Some(known) if known != &anchor.chain_id => return Err("chain_id_changed"),
            Some(_) => {}
            None => self.verified_chain_id = Some(anchor.chain_id.clone()),
        }
        if anchor.prev_anchor_hash != self.prev_anchor_hash {
            if self.verified_through_seq == 0 {
                self.verified_chain_id = None;
            }
            return Err("anchor_chain_gap");
        }
        self.verified_through_seq = anchor.head_seq;
        self.prev_anchor_hash.clone_from(&anchor.anchor_digest);
        let head = VerifiedAuditAnchorHead {
            chain_id: anchor.chain_id.clone(),
            head_seq: anchor.head_seq,
            head_hash: anchor.head_hash.clone(),
            anchor_digest: anchor.anchor_digest.clone(),
            observed_at_ms,
        };
        self.latest = Some(head.clone());
        Ok(head)
    }

    /// Checks the stable latest-anchor pointer against verified history.
    fn check_latest_pointer(&self, observation: &mut AnchorSinkObservation) {
        let Some(latest) = &observation.latest else {
            return;
        };
        let Ok(bytes) = std::fs::read(self.latest_anchor_path()) else {
            observation.rejected.push(AnchorRejection {
                file: WATCHDOG_ANCHOR_LATEST_FILE_NAME.to_owned(),
                reason: "latest_pointer_missing",
            });
            return;
        };
        let Ok(anchor) = serde_json::from_slice::<AnchorFileView>(&bytes) else {
            observation.rejected.push(AnchorRejection {
                file: WATCHDOG_ANCHOR_LATEST_FILE_NAME.to_owned(),
                reason: "latest_pointer_unparseable",
            });
            return;
        };
        if anchor.anchor_digest != latest.anchor_digest
            || anchor.head_seq != latest.head_seq
            || anchor.chain_id != latest.chain_id
        {
            observation.rejected.push(AnchorRejection {
                file: WATCHDOG_ANCHOR_LATEST_FILE_NAME.to_owned(),
                reason: "latest_pointer_mismatch",
            });
        }
    }
}
