//! Provenance closure: every handle behind a position, nothing invented.
//!
//! A [`ProvenanceClosure`] carries the exact record handles, typed source
//! identities, raw handles, and revisions behind a position, whether sources
//! are mixed, the weakest assertability across the closure, and the scope and
//! fence it was frozen under. It is data, never authority: the closure proves
//! which material was consulted, not what the material means.
//!
//! Donor disposition (`crates/smart/eliot-epistemic/src/lib.rs`, donor scope
//! `ProvenanceView` plus assumption/investigation fields): the donor
//! `ProvenanceView` is subsumed here and disposed — there is exactly one owner
//! of this shape and it is this module. Field mapping, all hardened:
//! `record_handles` ( donor `Vec`, order-significant) becomes `records`, a
//! set, because consultation membership never depended on presentation order;
//! `source_ids` (donor untyped `Vec<String>`) becomes typed
//! `BTreeSet<SourceId>` so a source is an identity, not prose;
//! `raw_handles` and `revisions` become sets for the same reason;
//! `mixed_sources` is no longer asserted but derived and checked, so a claim
//! of single-source over mixed material fails validation; `assertability`
//! reuses the foundation vocabulary unchanged. `scope`, `fence`, and the
//! frozen `digest` are added because unscoped, unfenced provenance is not
//! closable. The donor `lowest_assertability` computation is explicitly not
//! carried: combining assertabilities is resolver policy, and this crate
//! carries no resolver.

use std::collections::BTreeSet;

use eliot_contracts::{ArtifactId, SourceId, StateFence};
use eliot_evidence::Assertability;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{
    ContractError, MAX_HANDLES, MAX_SHORT_TEXT, shape_digest, validate_bounded_text,
    validate_digest,
};

/// Marker proving a document is a provenance closure and never a view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum ProvenanceClosureKind {
    /// The single admitted spelling of a provenance closure.
    #[serde(rename = "PROVENANCE_CLOSURE")]
    #[schemars(rename = "PROVENANCE_CLOSURE")]
    ProvenanceClosure,
}

/// The exact, frozen provenance closure of one position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceClosure {
    /// Marker binding this document to the closure decoding.
    pub closure_kind: ProvenanceClosureKind,
    /// Every record consulted; order carries no meaning.
    pub records: BTreeSet<ArtifactId>,
    /// Every source consulted, typed; order carries no meaning.
    pub sources: BTreeSet<SourceId>,
    /// Every raw handle consulted; order carries no meaning.
    pub raw_handles: BTreeSet<String>,
    /// Every revision consulted; order carries no meaning.
    pub revisions: BTreeSet<String>,
    /// Whether more than one source was consulted; derived, never asserted.
    pub mixed_sources: bool,
    /// Weakest assertability across the closure, supplied by the resolver.
    pub assertability: Assertability,
    /// Scope the closure was frozen under.
    pub scope: String,
    /// Fence the closure was frozen under.
    pub fence: StateFence,
    /// Canonical digest of the closure shape, excluding this field.
    pub digest: String,
}

impl ProvenanceClosure {
    /// Constructs a closure and freezes its canonical digest.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        records: BTreeSet<ArtifactId>,
        sources: BTreeSet<SourceId>,
        raw_handles: BTreeSet<String>,
        revisions: BTreeSet<String>,
        mixed_sources: bool,
        assertability: Assertability,
        scope: impl Into<String>,
        fence: StateFence,
    ) -> Result<Self, ContractError> {
        let mut closure = Self {
            closure_kind: ProvenanceClosureKind::ProvenanceClosure,
            records,
            sources,
            raw_handles,
            revisions,
            mixed_sources,
            assertability,
            scope: scope.into(),
            fence,
            digest: String::new(),
        };
        closure.validate_shape()?;
        closure.digest = closure.compute_digest()?;
        Ok(closure)
    }

    /// Recomputes the canonical digest of the closure shape.
    pub fn compute_digest(&self) -> Result<String, ContractError> {
        shape_digest(&(
            &self.closure_kind,
            &self.records,
            &self.sources,
            &self.raw_handles,
            &self.revisions,
            &self.mixed_sources,
            &self.assertability,
            &self.scope,
            &self.fence,
        ))
    }

    fn validate_shape(&self) -> Result<(), ContractError> {
        if self.closure_kind != ProvenanceClosureKind::ProvenanceClosure {
            return Err(ContractError::ImpossibleCombination {
                field: "provenance.closure_kind",
            });
        }
        if self.records.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "provenance.records",
            });
        }
        if self.records.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "provenance.records",
            });
        }
        if self.sources.is_empty() {
            return Err(ContractError::EmptyCollection {
                field: "provenance.sources",
            });
        }
        if self.sources.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "provenance.sources",
            });
        }
        if self.raw_handles.len() > MAX_HANDLES || self.revisions.len() > MAX_HANDLES {
            return Err(ContractError::TooMany {
                field: "provenance.handles",
            });
        }
        for handle in self.raw_handles.iter().chain(self.revisions.iter()) {
            validate_bounded_text(handle.as_str(), "provenance.handles", MAX_SHORT_TEXT)?;
        }
        if self.mixed_sources != (self.sources.len() > 1) {
            return Err(ContractError::ImpossibleCombination {
                field: "provenance.mixed_sources",
            });
        }
        validate_bounded_text(&self.scope, "provenance.scope", MAX_SHORT_TEXT)?;
        self.fence
            .validate()
            .map_err(|_| ContractError::FenceMismatch {
                field: "provenance.fence",
            })?;
        Ok(())
    }

    /// Validates the closure shape and its frozen digest.
    pub fn validate(&self) -> Result<(), ContractError> {
        self.validate_shape()?;
        validate_digest(&self.digest, "provenance.digest")?;
        if self.digest != self.compute_digest()? {
            return Err(ContractError::DigestMismatch {
                field: "provenance.digest",
            });
        }
        Ok(())
    }
}
