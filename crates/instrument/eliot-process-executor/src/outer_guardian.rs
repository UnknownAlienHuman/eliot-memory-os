//! Outer Host/OS guardian scenario checks for `ProcessExecutor` self-changes.
//!
//! I18.31 special case: a `ProcessExecutor` change needs an outer guardian
//! scenario verifying tree cleanup and evidence. The pure check mechanics
//! live in this owner crate; the Kernel dispatch composition wires the
//! strict launch path around [`verify_outer_guardian`] when the next
//! executor-surface generation ships (issue #2385: code first, behavior
//! acceptance follows).
//!
//! The guardian re-verifies from the machine, never from executor
//! internals: the scenario evidence digest is recomputed over the exact
//! presented bytes, and the scenario worktree must be absent or empty. An
//! unreadable tree is unverifiable, never silently cleaned.

use std::fmt;
use std::path::{Path, PathBuf};

/// Scenario the outer guardian verifies after a `ProcessExecutor` change.
#[derive(Clone, Debug)]
pub struct OuterGuardianScenario {
    worktree_root: PathBuf,
    evidence: Vec<u8>,
    expected_evidence_sha256: String,
}

impl OuterGuardianScenario {
    /// Declares one guardian scenario.
    ///
    /// # Errors
    ///
    /// Returns [`OuterGuardianError::EmptyWorktreeRoot`] for a blank root
    /// or [`OuterGuardianError::InvalidDigest`] unless the expected digest
    /// is 64 lowercase hex characters.
    pub fn new(
        worktree_root: PathBuf,
        evidence: Vec<u8>,
        expected_evidence_sha256: impl Into<String>,
    ) -> Result<Self, OuterGuardianError> {
        if worktree_root.as_os_str().is_empty() {
            return Err(OuterGuardianError::EmptyWorktreeRoot);
        }
        let expected_evidence_sha256 = expected_evidence_sha256.into();
        let valid = expected_evidence_sha256.len() == 64
            && expected_evidence_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase());
        if !valid {
            return Err(OuterGuardianError::InvalidDigest);
        }
        Ok(Self {
            worktree_root,
            evidence,
            expected_evidence_sha256,
        })
    }

    /// The scenario worktree the guardian inspects for cleanup.
    #[must_use]
    pub fn worktree_root(&self) -> &Path {
        &self.worktree_root
    }

    /// The exact evidence bytes the guardian re-hashes.
    #[must_use]
    pub fn evidence(&self) -> &[u8] {
        &self.evidence
    }

    /// The expected evidence digest the recomputed value must equal.
    #[must_use]
    pub fn expected_evidence_sha256(&self) -> &str {
        &self.expected_evidence_sha256
    }
}

/// Observed cleanup state of a verified scenario worktree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardianTreeState {
    /// The worktree path is absent: cleanup removed the tree.
    Absent,
    /// The worktree path exists and holds no entry.
    Emptied,
}

/// Evidence produced by [`verify_outer_guardian`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GuardianEvidence {
    /// The observed cleanup state.
    pub tree_state: GuardianTreeState,
    /// The recomputed evidence digest, equal to the expected value.
    pub evidence_sha256: String,
}

/// Failures raised while verifying an outer guardian scenario.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OuterGuardianError {
    /// The scenario worktree root is blank.
    EmptyWorktreeRoot,
    /// The expected digest is not 64 lowercase hex characters.
    InvalidDigest,
    /// The recomputed evidence digest differs from the expected value.
    EvidenceDigestMismatch,
    /// The worktree still holds residue.
    TreeNotCleaned {
        /// The offending root.
        root: PathBuf,
    },
    /// The worktree state cannot be proven from the machine.
    TreeUnverifiable {
        /// The unprovable root.
        root: PathBuf,
    },
}

impl fmt::Display for OuterGuardianError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyWorktreeRoot => write!(f, "guardian scenario worktree root is empty"),
            Self::InvalidDigest => write!(
                f,
                "guardian expected digest must be 64 lowercase hex characters"
            ),
            Self::EvidenceDigestMismatch => {
                write!(
                    f,
                    "guardian evidence digest does not match the expected value"
                )
            }
            Self::TreeNotCleaned { root } => {
                write!(
                    f,
                    "guardian worktree still holds residue: {}",
                    root.display()
                )
            }
            Self::TreeUnverifiable { root } => {
                write!(
                    f,
                    "guardian worktree state cannot be proven: {}",
                    root.display()
                )
            }
        }
    }
}

impl std::error::Error for OuterGuardianError {}

/// Verifies one outer guardian scenario from the machine.
///
/// Recomputes the SHA-256 digest over the exact scenario evidence bytes
/// and requires the scenario worktree to be absent or empty. A missing
/// tree counts as cleaned; an unreadable tree, a non-directory residue,
/// or any surviving entry fails closed.
///
/// # Errors
///
/// Returns [`OuterGuardianError::EvidenceDigestMismatch`] on digest
/// drift, [`OuterGuardianError::TreeNotCleaned`] on surviving residue,
/// or [`OuterGuardianError::TreeUnverifiable`] when the tree state
/// cannot be proven.
pub fn verify_outer_guardian(
    scenario: &OuterGuardianScenario,
) -> Result<GuardianEvidence, OuterGuardianError> {
    let observed = eliot_contracts::sha256_hex(scenario.evidence());
    if observed != scenario.expected_evidence_sha256() {
        return Err(OuterGuardianError::EvidenceDigestMismatch);
    }
    let root = scenario.worktree_root();
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(GuardianEvidence {
                tree_state: GuardianTreeState::Absent,
                evidence_sha256: observed,
            });
        }
        Err(_) => {
            return Err(OuterGuardianError::TreeUnverifiable {
                root: root.to_path_buf(),
            });
        }
    };
    if !metadata.is_dir() {
        return Err(OuterGuardianError::TreeNotCleaned {
            root: root.to_path_buf(),
        });
    }
    let mut entries =
        std::fs::read_dir(root).map_err(|_| OuterGuardianError::TreeUnverifiable {
            root: root.to_path_buf(),
        })?;
    if entries.next().is_some() {
        return Err(OuterGuardianError::TreeNotCleaned {
            root: root.to_path_buf(),
        });
    }
    Ok(GuardianEvidence {
        tree_state: GuardianTreeState::Emptied,
        evidence_sha256: observed,
    })
}
