use serde::{Deserialize, Serialize};

use crate::{
    ImplementationBriefError,
    validation::{
        MAX_ID_BYTES, MAX_ITEMS, MAX_TEXT_BYTES, canonical_digest, check_collection_len,
        check_digest, check_id, check_text, sorted_unique_strings,
    },
};

/// Acceptance lifecycle of the externally supplied Implementation source.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationSourceStatus {
    Accepted,
    Draft,
    Rejected,
    Superseded,
    Stale,
    Unavailable,
}

/// Closed classes of Implementation material retained in the brief.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImplementationStatementKind {
    Contract,
    Mechanism,
    Owner,
    Interface,
    Dependency,
    State,
    FailureBehavior,
    SecurityBoundary,
    ResourceBoundary,
    Recovery,
    Replacement,
    Default,
    ResearchGate,
    NonGoal,
    OpenParameter,
}

/// Relationship declared between Implementation material and governing Architecture.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchitectureAlignment {
    Compatible,
    Conflict,
    Unknown,
}

/// One exact accepted-Implementation statement.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationStatement {
    pub schema_version: u32,
    pub statement_id: String,
    pub mechanism_id: String,
    pub kind: ImplementationStatementKind,
    pub source_handle: String,
    pub source_revision: String,
    pub source_digest: String,
    pub architecture_refs: Vec<String>,
    pub dependency_refs: Vec<String>,
    pub alignment: ArchitectureAlignment,
    pub text: String,
    pub statement_digest: String,
}

#[derive(Serialize)]
struct StatementDigestPreimage<'a> {
    schema_version: u32,
    statement_id: &'a str,
    mechanism_id: &'a str,
    kind: ImplementationStatementKind,
    source_handle: &'a str,
    source_revision: &'a str,
    source_digest: &'a str,
    architecture_refs: &'a [String],
    dependency_refs: &'a [String],
    alignment: ArchitectureAlignment,
    text: &'a str,
}

impl ImplementationStatement {
    fn digest_preimage(&self) -> StatementDigestPreimage<'_> {
        StatementDigestPreimage {
            schema_version: self.schema_version,
            statement_id: &self.statement_id,
            mechanism_id: &self.mechanism_id,
            kind: self.kind,
            source_handle: &self.source_handle,
            source_revision: &self.source_revision,
            source_digest: &self.source_digest,
            architecture_refs: &self.architecture_refs,
            dependency_refs: &self.dependency_refs,
            alignment: self.alignment,
            text: &self.text,
        }
    }

    /// Canonicalizes set-like references and seals the statement digest.
    pub fn seal(&mut self) -> Result<(), ImplementationBriefError> {
        self.architecture_refs =
            sorted_unique_strings(&self.architecture_refs, "statement.architecture_refs")?;
        self.dependency_refs =
            sorted_unique_strings(&self.dependency_refs, "statement.dependency_refs")?;
        self.statement_digest =
            canonical_digest(&self.digest_preimage(), "statement.statement_digest")?;
        self.validate()
    }

    /// Validates intrinsic statement shape and digest.
    pub fn validate(&self) -> Result<(), ImplementationBriefError> {
        if self.schema_version != super::IMPLEMENTATION_BRIEF_SCHEMA_VERSION {
            return Err(ImplementationBriefError::Invalid {
                field: "statement.schema_version",
                reason: "unsupported schema version",
            });
        }
        check_id(&self.statement_id, "statement.statement_id")?;
        check_id(&self.mechanism_id, "statement.mechanism_id")?;
        check_id(&self.source_handle, "statement.source_handle")?;
        check_text(
            &self.source_revision,
            "statement.source_revision",
            MAX_ID_BYTES,
        )?;
        check_digest(&self.source_digest, "statement.source_digest")?;
        check_text(&self.text, "statement.text", MAX_TEXT_BYTES)?;
        let architecture_refs =
            sorted_unique_strings(&self.architecture_refs, "statement.architecture_refs")?;
        if architecture_refs != self.architecture_refs {
            return Err(ImplementationBriefError::Invalid {
                field: "statement.architecture_refs",
                reason: "collection is not in canonical order",
            });
        }
        let dependency_refs =
            sorted_unique_strings(&self.dependency_refs, "statement.dependency_refs")?;
        if dependency_refs != self.dependency_refs {
            return Err(ImplementationBriefError::Invalid {
                field: "statement.dependency_refs",
                reason: "collection is not in canonical order",
            });
        }
        check_digest(&self.statement_digest, "statement.statement_digest")?;
        if self.statement_digest
            != canonical_digest(&self.digest_preimage(), "statement.statement_digest")?
        {
            return Err(ImplementationBriefError::DigestMismatch {
                field: "statement.statement_digest",
            });
        }
        Ok(())
    }
}

/// Immutable externally accepted Implementation projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationSourceSnapshot {
    pub schema_version: u32,
    pub source_handle: String,
    pub owner: String,
    pub revision: String,
    pub source_digest: String,
    pub status: ImplementationSourceStatus,
    pub acceptance_receipt: Option<String>,
    pub complete: bool,
    pub statements: Vec<ImplementationStatement>,
    pub supersedes: Vec<String>,
    pub invalidation_refs: Vec<String>,
    pub snapshot_digest: String,
}

#[derive(Serialize)]
struct SourceDigestPreimage<'a> {
    schema_version: u32,
    source_handle: &'a str,
    owner: &'a str,
    revision: &'a str,
    source_digest: &'a str,
    status: ImplementationSourceStatus,
    acceptance_receipt: &'a Option<String>,
    complete: bool,
    statements: &'a [ImplementationStatement],
    supersedes: &'a [String],
    invalidation_refs: &'a [String],
}

impl ImplementationSourceSnapshot {
    fn digest_preimage(&self) -> SourceDigestPreimage<'_> {
        SourceDigestPreimage {
            schema_version: self.schema_version,
            source_handle: &self.source_handle,
            owner: &self.owner,
            revision: &self.revision,
            source_digest: &self.source_digest,
            status: self.status,
            acceptance_receipt: &self.acceptance_receipt,
            complete: self.complete,
            statements: &self.statements,
            supersedes: &self.supersedes,
            invalidation_refs: &self.invalidation_refs,
        }
    }

    /// Canonicalizes statements and lineage before sealing the snapshot.
    pub fn seal(&mut self) -> Result<(), ImplementationBriefError> {
        for statement in &mut self.statements {
            statement.seal()?;
        }
        self.statements
            .sort_by(|left, right| left.statement_id.cmp(&right.statement_id));
        self.supersedes = sorted_unique_strings(&self.supersedes, "source.supersedes")?;
        self.invalidation_refs =
            sorted_unique_strings(&self.invalidation_refs, "source.invalidation_refs")?;
        self.snapshot_digest =
            canonical_digest(&self.digest_preimage(), "source.snapshot_digest")?;
        self.validate()
    }

    /// Validates source identity, acceptance closure and statement lineage.
    pub fn validate(&self) -> Result<(), ImplementationBriefError> {
        if self.schema_version != super::IMPLEMENTATION_BRIEF_SCHEMA_VERSION {
            return Err(ImplementationBriefError::Invalid {
                field: "source.schema_version",
                reason: "unsupported schema version",
            });
        }
        check_id(&self.source_handle, "source.source_handle")?;
        check_id(&self.owner, "source.owner")?;
        check_text(&self.revision, "source.revision", MAX_ID_BYTES)?;
        check_digest(&self.source_digest, "source.source_digest")?;
        if let Some(receipt) = &self.acceptance_receipt {
            check_id(receipt, "source.acceptance_receipt")?;
        }
        check_collection_len(self.statements.len(), MAX_ITEMS, "source.statements")?;
        if self.status == ImplementationSourceStatus::Accepted {
            if self.acceptance_receipt.is_none() {
                return Err(ImplementationBriefError::Missing {
                    field: "source.acceptance_receipt",
                });
            }
            if self.statements.is_empty() {
                return Err(ImplementationBriefError::Missing {
                    field: "source.statements",
                });
            }
        } else if self.acceptance_receipt.is_some() {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "source.acceptance_receipt",
            });
        }
        if self.complete && self.status != ImplementationSourceStatus::Accepted {
            return Err(ImplementationBriefError::BindingMismatch {
                field: "source.complete",
            });
        }

        let mut previous = None;
        for statement in &self.statements {
            statement.validate()?;
            if statement.source_handle != self.source_handle
                || statement.source_revision != self.revision
                || statement.source_digest != self.source_digest
            {
                return Err(ImplementationBriefError::BindingMismatch {
                    field: "source.statement_lineage",
                });
            }
            if previous.is_some_and(|id: &str| id >= statement.statement_id.as_str()) {
                return Err(ImplementationBriefError::Invalid {
                    field: "source.statements",
                    reason: "collection is not in canonical order",
                });
            }
            previous = Some(statement.statement_id.as_str());
        }

        let supersedes = sorted_unique_strings(&self.supersedes, "source.supersedes")?;
        if supersedes != self.supersedes {
            return Err(ImplementationBriefError::Invalid {
                field: "source.supersedes",
                reason: "collection is not in canonical order",
            });
        }
        let invalidation =
            sorted_unique_strings(&self.invalidation_refs, "source.invalidation_refs")?;
        if invalidation != self.invalidation_refs {
            return Err(ImplementationBriefError::Invalid {
                field: "source.invalidation_refs",
                reason: "collection is not in canonical order",
            });
        }
        if self
            .supersedes
            .iter()
            .chain(self.invalidation_refs.iter())
            .any(|value| value == &self.source_handle)
        {
            return Err(ImplementationBriefError::IdentityConflict {
                field: "source.lineage",
            });
        }
        check_digest(&self.snapshot_digest, "source.snapshot_digest")?;
        if self.snapshot_digest
            != canonical_digest(&self.digest_preimage(), "source.snapshot_digest")?
        {
            return Err(ImplementationBriefError::DigestMismatch {
                field: "source.snapshot_digest",
            });
        }
        Ok(())
    }
}
