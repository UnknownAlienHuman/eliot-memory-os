use std::{collections::BTreeSet, convert::TryFrom};

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    ContractError, Digest, FiniteDenominator, MemberId, ProfileId, QueryIdentity, SnapshotId,
    SourceIdentity, contract_digest,
};

/// Exactly one aggregate disposition is retained per source member.
#[derive(
    Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MemberDisposition {
    /// Eligible for a later semantic owner.
    Eligible,
    /// Protected by owner evidence.
    Protected,
    /// Blocked by missing, unknown, or malformed evidence.
    Blocked,
    /// Immutable reference retained outside the proposed target set.
    PreservedReference,
    /// Not processed in this bounded page.
    Unprocessed,
}

/// Explicit terminal/frontier state for a bounded screen.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenFrontier {
    /// Whether all denominator members have terminal dispositions.
    pub complete: bool,
    /// Exact members still unresolved or unprocessed.
    pub remaining: Vec<MemberId>,
}
impl ScreenFrontier {
    /// Validates complete/frontier consistency.
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.complete && !self.remaining.is_empty() {
            return Err(ContractError::Reconciliation {
                field: "frontier.complete",
            });
        }
        Ok(())
    }
}

/// Cumulative resource use, never reset by a continuation cursor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkUsage {
    /// Members processed cumulatively.
    pub processed_items: u64,
    /// Work units consumed cumulatively.
    pub work_units: u64,
    /// Input bytes consumed cumulatively.
    pub input_bytes: u64,
    /// Output bytes emitted cumulatively.
    pub output_bytes: u64,
}

/// Continuation identity and cumulative budget fence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CumulativeCursor {
    /// Request identity.
    pub request_id: eliot_contracts::RequestId,
    /// Digest of the immutable request inputs, excluding this continuation cursor.
    pub request_fingerprint: Digest,
    /// Source snapshot identity.
    pub snapshot_id: SnapshotId,
    /// Exact query identity carried across pages.
    pub query: QueryIdentity,
    /// Exact source revision and owner digest.
    pub source_revision: u64,
    pub source_digest: Digest,
    /// Profile identity.
    pub profile_id: ProfileId,
    /// Digest of the complete frozen profile (rules and limits included).
    pub profile_digest: Digest,
    /// Denominator retained in the cursor.
    pub denominator: FiniteDenominator,
    /// Scope and source fence.
    pub scope: eliot_receipts::WorkScopeId,
    /// Fence used for all pages.
    pub state_fence: StateFence,
    /// Digest of exactly processed source members in source order.
    pub processed_member_digest: Digest,
    /// Number of source members already processed.
    pub position: u64,
    /// Cumulative usage.
    pub usage: WorkUsage,
    /// Previous cursor digest, if this is a continuation.
    pub predecessor: Option<Digest>,
}
impl CumulativeCursor {
    /// Validates cursor identity against its request and prevents budget reset.
    pub fn validate(&self, request: &crate::CurationScreenRequest) -> Result<(), ContractError> {
        if self.request_id != request.binding.request_id
            || self.request_fingerprint != request.request_fingerprint()?
            || self.snapshot_id != request.source.snapshot_id
            || self.query != request.source.query
            || self.source_revision != request.source.revision
            || self.source_digest != request.source.digest
            || self.profile_id != request.profile.profile_id
            || self.profile_digest != contract_digest(&request.profile)?
            || self.denominator != request.denominator
            || self.scope != request.source.scope
            || self.state_fence != request.source.state_fence
        {
            return Err(ContractError::BindingMismatch {
                field: "cursor.request",
            });
        }
        if self.position != self.usage.processed_items {
            return Err(ContractError::Reconciliation {
                field: "cursor.position",
            });
        }
        request.profile.limits.validate()?;
        if self.usage.work_units > request.profile.limits.max_work_units
            || self.usage.input_bytes > request.profile.limits.max_bytes
            || self.usage.output_bytes > request.profile.limits.max_output_bytes
        {
            return Err(ContractError::Bound {
                field: "cursor.cumulative_usage",
            });
        }
        self.state_fence
            .validate()
            .map_err(|_| ContractError::BindingMismatch {
                field: "cursor.state_fence",
            })
    }

    /// Validates a continuation against the exact source prefix and prior page.
    pub fn validate_progress(
        &self,
        request: &crate::CurationScreenRequest,
        source: &crate::SourceSnapshot,
        prior: Option<&Self>,
        page_members: &[MemberId],
    ) -> Result<(), ContractError> {
        self.validate(request)?;
        source.validate()?;
        if let Some(previous) = prior {
            previous.validate(request)?;
        }
        let start = prior
            .map_or(Ok(0), |cursor| usize::try_from(cursor.position))
            .map_err(|_| ContractError::Bound {
                field: "cursor.position",
            })?;
        let end = usize::try_from(self.position).map_err(|_| ContractError::Bound {
            field: "cursor.position",
        })?;
        if start > end || start > source.members.len() || end > source.members.len() {
            return Err(ContractError::Reconciliation {
                field: "cursor.position",
            });
        }
        if let Some(previous) = prior {
            let prefix: Vec<_> = source.members[..start]
                .iter()
                .map(|member| member.member_id.clone())
                .collect();
            if contract_digest(&prefix)? != previous.processed_member_digest {
                return Err(ContractError::Reconciliation {
                    field: "cursor.processed_member_digest",
                });
            }
        }
        let expected_page: Vec<_> = source.members[start..end]
            .iter()
            .map(|member| member.member_id.clone())
            .collect();
        if expected_page != page_members {
            return Err(ContractError::Reconciliation {
                field: "cursor.page_members",
            });
        }
        let processed: Vec<_> = source.members[..end]
            .iter()
            .map(|member| member.member_id.clone())
            .collect();
        if contract_digest(&processed)? != self.processed_member_digest {
            return Err(ContractError::Reconciliation {
                field: "cursor.processed_member_digest",
            });
        }
        if let Some(previous) = prior {
            if self.predecessor.as_ref() != Some(&contract_digest(previous)?)
                || self.usage.processed_items < previous.usage.processed_items
                || self.usage.work_units < previous.usage.work_units
                || self.usage.input_bytes < previous.usage.input_bytes
                || self.usage.output_bytes < previous.usage.output_bytes
            {
                return Err(ContractError::Reconciliation {
                    field: "cursor.predecessor",
                });
            }
        } else if self.predecessor.is_some() {
            return Err(ContractError::Reconciliation {
                field: "cursor.genesis_predecessor",
            });
        }
        Ok(())
    }
}

/// One member's coverage and subordinate identities.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MemberCoverage {
    /// Exact member identity.
    pub member_id: MemberId,
    /// One and only one aggregate disposition.
    pub disposition: MemberDisposition,
    /// Findings retained for this member.
    pub finding_ids: BTreeSet<crate::FindingId>,
    /// Optional eligibility identity is represented by the member result.
    pub eligible: bool,
}

/// Coverage receipt for one bounded result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScreenCoverage {
    /// Full source denominator.
    pub denominator: FiniteDenominator,
    /// Zero-based position of this page in immutable source order.
    pub start_position: u64,
    /// Member dispositions in source order.
    pub members: Vec<MemberCoverage>,
    /// Explicit unresolved frontier.
    pub frontier: ScreenFrontier,
    /// Cumulative usage.
    pub usage: WorkUsage,
    /// Continuation emitted for a partial result.
    pub next_cursor: Option<CumulativeCursor>,
    /// Digest of this coverage receipt.
    pub digest: Digest,
}
impl ScreenCoverage {
    /// Computes the coverage digest while excluding the digest field itself.
    pub fn computed_digest(&self) -> Result<Digest, ContractError> {
        #[derive(Serialize)]
        struct Payload<'a> {
            denominator: &'a FiniteDenominator,
            start_position: u64,
            members: &'a [MemberCoverage],
            frontier: &'a ScreenFrontier,
            usage: &'a WorkUsage,
            next_cursor: &'a Option<CumulativeCursor>,
        }
        contract_digest(&Payload {
            denominator: &self.denominator,
            start_position: self.start_position,
            members: &self.members,
            frontier: &self.frontier,
            usage: &self.usage,
            next_cursor: &self.next_cursor,
        })
    }
    /// Validates denominator, uniqueness, frontier, and digest shape.
    pub fn validate(&self, source: &SourceIdentity) -> Result<(), ContractError> {
        self.denominator.validate(self.members.len())?;
        self.frontier.validate()?;
        if self.digest != self.computed_digest()? {
            return Err(ContractError::Reconciliation {
                field: "coverage.digest",
            });
        }
        let mut ids = BTreeSet::new();
        for member in &self.members {
            if !ids.insert(member.member_id.clone()) {
                return Err(ContractError::Duplicate {
                    field: "coverage.members",
                });
            }
            if member.finding_ids.len() > 256 {
                return Err(ContractError::Bound {
                    field: "coverage.findings",
                });
            }
            if member.eligible != (member.disposition == crate::MemberDisposition::Eligible) {
                return Err(ContractError::Reconciliation {
                    field: "coverage.eligible",
                });
            }
        }
        let processed = self
            .members
            .iter()
            .filter(|member| member.disposition != crate::MemberDisposition::Unprocessed)
            .count() as u64;
        if self.usage.processed_items != processed {
            return Err(ContractError::Reconciliation {
                field: "coverage.processed_items",
            });
        }
        if let Some(cursor) = &self.next_cursor
            && (cursor.snapshot_id != source.snapshot_id || cursor.scope != source.scope)
        {
            return Err(ContractError::BindingMismatch {
                field: "coverage.cursor",
            });
        }
        Ok(())
    }
    /// Validates source-order and one-disposition coverage against a snapshot.
    pub fn validate_against_source(
        &self,
        source: &crate::SourceSnapshot,
    ) -> Result<(), ContractError> {
        self.validate(&source.identity)?;
        if self.denominator != source.denominator {
            return Err(ContractError::BindingMismatch {
                field: "coverage.denominator",
            });
        }
        let source_ids: Vec<_> = source
            .members
            .iter()
            .map(|member| member.member_id.clone())
            .collect();
        let coverage_ids: Vec<_> = self
            .members
            .iter()
            .map(|member| member.member_id.clone())
            .collect();
        let start = usize::try_from(self.start_position).map_err(|_| ContractError::Bound {
            field: "coverage.start_position",
        })?;
        let end = coverage_ids.len();
        if start > source_ids.len() || start > end || end > source_ids.len() {
            return Err(ContractError::Reconciliation {
                field: "coverage.source_order",
            });
        }
        if source_ids[..end] != coverage_ids {
            return Err(ContractError::Reconciliation {
                field: "coverage.source_order",
            });
        }
        let mut expected_remaining: Vec<_> = source_ids.get(end..).unwrap_or(&[]).to_vec();
        expected_remaining.splice(
            0..0,
            self.members
                .iter()
                .filter(|member| member.disposition == crate::MemberDisposition::Unprocessed)
                .map(|member| member.member_id.clone()),
        );
        if self.frontier.remaining != expected_remaining {
            return Err(ContractError::Reconciliation {
                field: "coverage.frontier_members",
            });
        }
        Ok(())
    }
    /// Returns the source-order member identity set.
    pub fn member_ids(&self) -> BTreeSet<MemberId> {
        self.members
            .iter()
            .map(|member| member.member_id.clone())
            .collect()
    }
    /// Returns the exclusive source-order end position of this page.
    pub fn end_position(&self) -> Result<u64, ContractError> {
        u64::try_from(self.members.len()).map_err(|_| ContractError::Bound {
            field: "coverage.end_position",
        })
    }
}
