//! Use-time instruction/data separation and bounded optional analysis
//! admission (issue #1760, items W4 and W6).
//!
//! I8.7 requires that "model confidence alone cannot create quarantine,
//! Incident or authority change". I12.20 requires that "revocation/taint
//! traverses model summaries, compiled views/wiki, SessionEpisode-derived
//! claims, procedures, answer/context projections", and that a mixed-lineage
//! derived item inherits the minimum allowed influence of its material sources.
//! This module is where both sentences are enforced rather than described:
//!
//! - [`authorize_source_use`] resolves what a source-derived subject may
//!   actually be used for, from the CURRENT [`SourceAssurance`] of the sources
//!   that produced it, and refuses an authority surface for a subject whose
//!   recomputed taint is above [`InstructionTaint::DataOnly`].
//! - [`BoundedAnalysisRequest`] bounds one optional analysis over that
//!   material to the handles, disclosure domain, question, budget, output
//!   contract and stop condition it names.
//!
//! A [`SourceSecurityAssessment`], a [`ModelProposedInterpretation`] and an
//! [`AssessmentConfidence`] are deliberately not parameters of
//! [`authorize_source_use`]. There is therefore no path by which a detector's
//! output, however confident, reaches the branch that decides whether a
//! tainted value may become a standing instruction, a tool definition, a
//! policy, a credential, or an effect grant.

use std::collections::{BTreeMap, BTreeSet};

use eliot_contracts::StateFence;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::{
    EpistemicUse, EffectCeiling, InstructionTaint, ObservationDomainKind, SecurityContractError,
    SourceAssurance, TransformationLineage,
};

/// The surface a source-derived subject is being consumed at.
///
/// A tainted value may be carried, quoted, summarised, compiled, and shown to a
/// human on [`Self::Data`]. It may never become a standing instruction, a tool
/// definition, a policy, a credential, or an effect grant: every one of those
/// is [`Self::Authority`]. The two variants are the two answers the decision
/// reads, so the five authority kinds the issue names are not spelled out as
/// variants the decision cannot tell apart.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SourceUseSurface {
    /// Retained inert evidence, an observation, a summary, a compiled view, a
    /// procedure candidate, a diagnostic, or a model-derived artifact shown to
    /// a human.
    Data,
    /// A standing instruction, a tool definition, a policy, a credential, or an
    /// effect grant.
    Authority,
}

impl SourceUseSurface {
    /// Whether consuming this surface grants or changes authority.
    #[must_use]
    pub const fn is_authority_surface(self) -> bool {
        matches!(self, Self::Authority)
    }
}

/// One use-time request to consume a source-derived subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SourceUseRequest {
    /// Subject being consumed: the derived artifact, compiled view, procedure,
    /// or model-derived artifact the caller is about to use.
    pub subject_ref: String,
    /// Surface this consumption targets.
    pub surface: SourceUseSurface,
    /// Use the consumer claims it needs.
    pub requested_use: EpistemicUse,
    /// Effect the consumer claims it needs.
    pub requested_effect: EffectCeiling,
}

/// What the current state actually permits for one subject.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSourceUse {
    /// Subject this resolution is for.
    pub subject_ref: String,
    /// Surface the request targeted.
    pub surface: SourceUseSurface,
    /// Taint recomputed from the current `SourceAssurance` of every source the
    /// subject's derivations name. It is never read from a detector.
    pub propagated_taint: InstructionTaint,
    /// Intersection of the current `allowed_epistemic_use` of those sources.
    pub allowed_epistemic_use: Vec<EpistemicUse>,
    /// Intersection of the current `allowed_effects` of those sources.
    pub allowed_effects: Vec<EffectCeiling>,
    /// The current sources this resolution was recomputed from.
    pub lineage_roots: Vec<String>,
}

/// Resolves and authorizes one use of a source-derived subject.
///
/// Uses and effects come from the CURRENT [`SourceAssurance`] of the sources
/// the supplied derivations name, intersected, so a derived subject can never
/// widen what any one of its sources permits. A second model repeating one
/// source inherits that source's ceilings for the same reason.
///
/// An empty `current_assurances` set restricts nothing here: whether a
/// transition was built from source material at all is the transition
/// admission owner's decision, and the store already reduces an absent set to
/// the highest taint at its staging boundary.
///
/// # Errors
///
/// Returns [`SecurityContractError::TaintLaundering`] when a derivation
/// declares an input taint weaker than the material it actually consumed,
/// [`SecurityContractError::InstructionDataSeparation`] when a tainted subject
/// is aimed at an authority surface, and
/// [`SecurityContractError::SourceUseRefused`] when the requested use or
/// effect is outside what the current evidence permits.
pub fn authorize_source_use(
    request: &SourceUseRequest,
    current_assurances: &[SourceAssurance],
    derivations: &[TransformationLineage],
) -> Result<ResolvedSourceUse, SecurityContractError> {
    text(&request.subject_ref, "source_use.subject_ref")?;
    for assurance in current_assurances {
        assurance.validate()?;
    }
    for derivation in derivations {
        derivation.validate()?;
    }

    let assurance_taint = assurance_taints(current_assurances)?;
    let produced_taint = produced_taints(derivations)?;
    for derivation in derivations {
        // The taint a derivation declares it consumed is compared with the taint
        // recomputed from the CURRENT assurance of the sources it names and from
        // the recorded output taint of the derivations that produced them. A
        // summary or a compile step that re-created a tainted value from text
        // and then re-declared a weaker input taint is refused here, whatever
        // it claims and whatever a detector said about it.
        //
        // A derivation that carries its own `declassification_receipt_ref` is
        // outside this comparison, exactly as `TransformationLineage::validate`
        // already treats it: the receipt is the owner's proof that a verified
        // transformation removed the taint, and re-deriving it here would need
        // the `DeclassificationReceipt` bytes this record does not carry. Such a
        // derivation may carry its own lower taint, but it does not lower the
        // propagated taint below, which stays the maximum over the sources.
        if derivation.declassification_receipt_ref.is_some() {
            continue;
        }
        let resolved = resolved_input_taint(derivation, &assurance_taint, &produced_taint);
        if derivation.input_taint < resolved {
            return Err(SecurityContractError::TaintLaundering);
        }
    }

    // The propagated taint is the maximum over the whole current evidence set
    // and over every recorded derivation output, so dropping a source from a
    // derivation's `input_refs` cannot lower it: the dropped source is still in
    // the evidence set, and a dropped origin is a taint escape, not a cleaning.
    //
    // This is deliberately the maximum over the SOURCES and not over the
    // derivations alone, so a declassified derivation cannot buy an authority
    // surface for the source it consumed. `DeclassificationReceipt` is the
    // owner's proof about a transformation's output, not a statement that its
    // input source was never untrusted; lowering the authority ceiling below a
    // tainted source is a quarantine/release decision, and those stay with the
    // Governor (#1760 W5) rather than with this gate. The cost is that a fully
    // declassified lineage over a tainted source is refused on an authority
    // surface until that source is released; a false refusal is recoverable and
    // a false admission is not.
    let propagated_taint = propagated_taint(current_assurances, derivations);

    // Instruction/data separation. This branch reads the recomputed taint and
    // nothing else: a `SourceSecurityAssessment`, a
    // `ModelProposedInterpretation`, and an `AssessmentConfidence` are not
    // parameters of this function, so no detector output can reach it.
    if request.surface.is_authority_surface() && propagated_taint > InstructionTaint::DataOnly {
        return Err(SecurityContractError::InstructionDataSeparation {
            subject_ref: request.subject_ref.clone(),
            surface: request.surface,
            taint: propagated_taint,
        });
    }

    let mut lineage_roots: BTreeSet<&str> = BTreeSet::new();
    for derivation in derivations {
        for input in &derivation.input_refs {
            if assurance_taint.contains_key(input.as_str()) {
                lineage_roots.insert(input.as_str());
            }
        }
    }
    let lineage_roots: Vec<String> = lineage_roots.into_iter().map(str::to_owned).collect();

    let allowed_uses: Vec<&[EpistemicUse]> = current_assurances
        .iter()
        .map(|assurance| assurance.allowed_epistemic_use.as_slice())
        .collect();
    let allowed_effects: Vec<&[EffectCeiling]> = current_assurances
        .iter()
        .map(|assurance| assurance.allowed_effects.as_slice())
        .collect();
    let resolved_use = intersect(&allowed_uses);
    let resolved_effect = intersect(&allowed_effects);
    if !current_assurances.is_empty() {
        if !resolved_use.contains(&request.requested_use) {
            return Err(SecurityContractError::SourceUseRefused {
                subject_ref: request.subject_ref.clone(),
                field: "source_use.requested_use",
            });
        }
        if !resolved_effect.contains(&request.requested_effect) {
            return Err(SecurityContractError::SourceUseRefused {
                subject_ref: request.subject_ref.clone(),
                field: "source_use.requested_effect",
            });
        }
    }
    Ok(ResolvedSourceUse {
        subject_ref: request.subject_ref.clone(),
        surface: request.surface,
        propagated_taint,
        allowed_epistemic_use: resolved_use,
        allowed_effects: resolved_effect,
        lineage_roots,
    })
}

/// Maximum handles one bounded analysis request may name.
pub const MAX_ANALYSIS_HANDLES: usize = 64;
/// Maximum bytes for one bounded-analysis text or handle field.
pub const MAX_ANALYSIS_TEXT_BYTES: usize = 1024;
/// Maximum source bytes one bounded analysis may consume.
pub const MAX_ANALYSIS_INPUT_BYTES: u64 = 1_048_576;
/// Maximum produced bytes one bounded analysis may return.
pub const MAX_ANALYSIS_OUTPUT_BYTES: u64 = 65_536;
/// Maximum wall milliseconds one bounded analysis may spend.
pub const MAX_ANALYSIS_WALL_MS: u64 = 600_000;

/// One bounded optional analysis request over source material (issue #1760,
/// item W6).
///
/// Every field is a bound the requester must fill: the analysis reads exactly
/// the named handles, discloses only into the named domain, answers only the
/// named question, spends only the named budget, satisfies only the named
/// output contract, and ends on the named stop condition.
///
/// The shape carries no field for a reusable credential, a corpus selector, a
/// standing mutation permission, or a waiting hard gate, so it cannot express
/// one. A blocked gate is not a licence to run a model call: the only way to
/// reach this request is to fill in a question, and a gate that has none
/// cannot produce one.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BoundedAnalysisRequest {
    /// Stable identity of this request.
    pub request_ref: String,
    /// Subject the analysis is admitted for.
    pub subject_ref: String,
    /// The exact question this analysis answers.
    pub question: String,
    /// Exact retained handles the analysis may read. A handle is an opaque
    /// reference; a wildcard, a prefix selector, and an empty list are refused.
    pub permitted_handles: Vec<String>,
    /// The one kind of disclosure domain the answer may be disclosed within.
    pub recipient_disclosure_domain: ObservationDomainKind,
    /// Opaque identity of that domain.
    pub recipient_disclosure_domain_ref: String,
    /// Ceiling on source bytes the analysis may consume.
    pub max_input_bytes: u64,
    /// Ceiling on produced bytes the analysis may return.
    pub max_output_bytes: u64,
    /// Ceiling on wall time the analysis may spend, in milliseconds.
    pub max_wall_ms: u64,
    /// The exact contract the answer must satisfy.
    pub output_contract: String,
    /// The condition that ends the analysis whether or not it answered.
    pub stop_condition: String,
    /// Fence the analysis is admitted under.
    pub state_fence: StateFence,
}

impl BoundedAnalysisRequest {
    /// Validates all six bounds of one optional analysis request.
    ///
    /// # Errors
    ///
    /// Returns a typed [`SecurityContractError`] naming the bound that failed:
    /// a blank, control-bearing, or oversize text field; an empty, oversized,
    /// duplicated, wildcarded, or prefix-selecting handle list; a secret or
    /// user-private recipient domain; a zero or over-ceiling budget; or an
    /// invalid state fence.
    pub fn validate(&self) -> Result<(), SecurityContractError> {
        for (value, field) in [
            (&self.request_ref, "analysis.request_ref"),
            (&self.subject_ref, "analysis.subject_ref"),
            (&self.question, "analysis.question"),
            (
                &self.recipient_disclosure_domain_ref,
                "analysis.recipient_disclosure_domain_ref",
            ),
            (&self.output_contract, "analysis.output_contract"),
            (&self.stop_condition, "analysis.stop_condition"),
        ] {
            bounded_text(value, field)?;
        }
        self.check_handles()?;
        // A secret or user-private domain is a credential surface. An analysis
        // is never handed one, so naming it here is refused before any call.
        if matches!(
            self.recipient_disclosure_domain,
            ObservationDomainKind::SecretClass | ObservationDomainKind::UserPrivate
        ) {
            return Err(SecurityContractError::SourceUseRefused {
                subject_ref: self.subject_ref.clone(),
                field: "analysis.recipient_disclosure_domain",
            });
        }
        for (value, ceiling, field) in [
            (
                self.max_input_bytes,
                MAX_ANALYSIS_INPUT_BYTES,
                "analysis.max_input_bytes",
            ),
            (
                self.max_output_bytes,
                MAX_ANALYSIS_OUTPUT_BYTES,
                "analysis.max_output_bytes",
            ),
            (self.max_wall_ms, MAX_ANALYSIS_WALL_MS, "analysis.max_wall_ms"),
        ] {
            if value == 0 || value > ceiling {
                return Err(SecurityContractError::InvalidText { field });
            }
        }
        self.state_fence
            .validate()
            .map_err(|_| SecurityContractError::InvalidFence {
                field: "analysis.state_fence",
            })
    }

    /// Checks the exact-handle bound: the list is non-empty, bounded, free of
    /// duplicates, and every member is an opaque reference rather than a
    /// wildcard or a prefix selector, so a request can never widen into a broad
    /// corpus extraction.
    fn check_handles(&self) -> Result<(), SecurityContractError> {
        if self.permitted_handles.is_empty() {
            return Err(SecurityContractError::EmptyCollection {
                field: "analysis.permitted_handles",
            });
        }
        if self.permitted_handles.len() > MAX_ANALYSIS_HANDLES {
            return Err(SecurityContractError::SourceUseRefused {
                subject_ref: self.subject_ref.clone(),
                field: "analysis.permitted_handles",
            });
        }
        let mut seen = BTreeSet::new();
        for handle in &self.permitted_handles {
            bounded_text(handle, "analysis.permitted_handles")?;
            if handle.contains('*') || handle.contains('%') || handle.contains("..") {
                return Err(SecurityContractError::SourceUseRefused {
                    subject_ref: self.subject_ref.clone(),
                    field: "analysis.permitted_handles",
                });
            }
            if !seen.insert(handle.as_str()) {
                return Err(SecurityContractError::DuplicateReference {
                    field: "analysis.permitted_handles",
                });
            }
        }
        Ok(())
    }
}

fn text(value: &str, field: &'static str) -> Result<(), SecurityContractError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(SecurityContractError::InvalidText { field });
    }
    Ok(())
}

fn bounded_text(value: &str, field: &'static str) -> Result<(), SecurityContractError> {
    if value.len() > MAX_ANALYSIS_TEXT_BYTES {
        return Err(SecurityContractError::InvalidText { field });
    }
    text(value, field)
}

/// Intersects ordered-per-source allow-lists into the one set a derived subject
/// may use. The result preserves the declared order of the first source, so the
/// resolution is stable for a given evidence set.
fn intersect<T: Copy + PartialEq>(sets: &[&[T]]) -> Vec<T> {
    let Some((first, rest)) = sets.split_first() else {
        return Vec::new();
    };
    first
        .iter()
        .copied()
        .filter(|candidate| rest.iter().all(|set| set.contains(candidate)))
        .collect()
}

fn assurance_taints(
    assurances: &[SourceAssurance],
) -> Result<BTreeMap<&str, InstructionTaint>, SecurityContractError> {
    let mut taints = BTreeMap::new();
    for assurance in assurances {
        if taints
            .insert(assurance.source_ref.as_str(), assurance.instruction_taint)
            .is_some()
        {
            return Err(SecurityContractError::DuplicateReference {
                field: "source_use.current_assurances",
            });
        }
    }
    Ok(taints)
}

fn produced_taints(
    derivations: &[TransformationLineage],
) -> Result<BTreeMap<&str, InstructionTaint>, SecurityContractError> {
    let mut taints = BTreeMap::new();
    for derivation in derivations {
        if taints
            .insert(derivation.output_ref.as_str(), derivation.output_taint)
            .is_some()
        {
            return Err(SecurityContractError::DuplicateReference {
                field: "source_use.derivations",
            });
        }
    }
    Ok(taints)
}

fn resolved_input_taint(
    derivation: &TransformationLineage,
    assurance_taints: &BTreeMap<&str, InstructionTaint>,
    produced_taints: &BTreeMap<&str, InstructionTaint>,
) -> InstructionTaint {
    let mut resolved = InstructionTaint::Cleared;
    for input in &derivation.input_refs {
        let taint = assurance_taints
            .get(input.as_str())
            .or_else(|| produced_taints.get(input.as_str()))
            .copied()
            // An input that names neither a current source nor a supplied
            // derivation has no resolvable taint, so it is read at the ceiling:
            // an incomplete lineage is bounded uncertainty, never evidence of a
            // clean input.
            .unwrap_or(InstructionTaint::CommandLike);
        resolved = resolved.max(taint);
    }
    resolved
}

fn propagated_taint(
    assurances: &[SourceAssurance],
    derivations: &[TransformationLineage],
) -> InstructionTaint {
    let mut taint = InstructionTaint::Cleared;
    for assurance in assurances {
        taint = taint.max(assurance.instruction_taint);
    }
    for derivation in derivations {
        taint = taint.max(derivation.output_taint);
    }
    taint
}
