#![forbid(unsafe_code)]

//! `RGF-AGENT-ROUTES` admission for the `DeepSeek/OpenCode` route (issue #1835,
//! I10.11 and I10.6).
//!
//! I10.11, verbatim: "`DeepSeek V4 Flash` through `OpenCode` Go is an
//! **Empirical Route Profile**, not a capability inferred from the checkpoint
//! name. Admission requires RGF-AGENT-ROUTES and an exact fingerprint covering
//! provider endpoint, `OpenCode`/runtime version, serializer/chat template,
//! tool-role ordering, reasoning mode, reasoning-continuation preservation,
//! compaction and auth/quota surface."
//!
//! ## What this cell owns, and what it does not
//!
//! Route identity stays owned by
//! [`RouteFingerprint`](eliot_agent_api::RouteFingerprint): this module adds
//! **no second route-fingerprint type**. [`OpenCodeRouteProfile`] carries that
//! canonical fingerprint plus exactly the required content the fingerprint
//! type has no field for, and the selection gate compares a requested route
//! against the **recorded** admitted fingerprint of this route profile (never
//! a fresh recomputation over whatever the caller holds).
//!
//! Execution identity and the User Broker launch boundary keep their existing
//! owner (`eliotd::route_execution_identity`, issue #1816); nothing here
//! re-declares `service | interactive_user | remote`.
//!
//! The six mandatory pilot probes are named, and their retained artifacts are
//! the only thing that can move a route to [`OpenCodeRouteAdmissionState::Admitted`].
//! This module never runs a probe and never mints an observation: the evidence
//! it reads is exactly what a pilot producer retained.
//!
//! I10.11 again, verbatim: "Until the pilot demonstrates architecture/planning
//! and verification quality, the route is eligible mainly for bounded
//! implementation, read-only scouting and broad inexpensive coverage. It does
//! not become sole Task Controller, Architecture authority or independent
//! verifier by price or advertised context size." — that is
//! [`opencode_route_role_permitted`].

use eliot_agent_api::{RouteFingerprint, route_divergence_fields};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

use crate::{OPENCODE_ADAPTER_ID, OPENCODE_HOST_FAMILY, OPENCODE_PROTOCOL_TRANSPORT};

/// The research-gate family that admits a Codex/`OpenCode`/Claude/ACP agent
/// route (`docs/architecture/APPENDIX-G-research-gate-families.md`, row
/// `RGF-AGENT-ROUTES`).
pub const RGF_AGENT_ROUTES: &str = "RGF-AGENT-ROUTES";

/// Schema version of the retained `RGF-AGENT-ROUTES` route-admission receipt.
pub const OPENCODE_ROUTE_ADMISSION_SCHEMA_VERSION: &str = "eliot.opencode-route-admission.v1";

/// The six mandatory pilot probes of I10.11, as closed probe identities.
/// Admission is a property of these six artifacts, never of a route name.
pub const OPENCODE_MANDATED_PROBES: [&str; 6] = [
    "multi-turn-tool-continuation",
    "host-serializer-reasoning-preservation",
    "provider-model-and-missing-field-honesty",
    "measured-limits-and-compaction",
    "sourced-quota-reset-usage",
    "equal-stack-fallback-comparison",
];

/// The role a route is selected to serve.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenCodeRouteRole {
    /// Bounded implementation work.
    BoundedImplementation,
    /// Read-only scouting and orientation.
    ReadOnlyScouting,
    /// Broad inexpensive coverage.
    BroadCoverage,
    /// Sole Task Controller of a task DAG.
    SoleController,
    /// Architecture authority.
    ArchitectureAuthority,
    /// Independent verifier of another agent's work.
    IndependentVerifier,
}

impl OpenCodeRouteRole {
    /// True for the three scopes I10.11 keeps eligible for an unadmitted or
    /// partially admitted empirical route: bounded implementation, read-only
    /// scouting, and broad inexpensive coverage. The remaining three roles are
    /// authority roles this route never gains from route admission.
    #[must_use]
    pub const fn is_empirical_scope(self) -> bool {
        matches!(
            self,
            Self::BoundedImplementation | Self::ReadOnlyScouting | Self::BroadCoverage
        )
    }
}

/// The role policy of I10.11: whether this empirical route may be selected for
/// `role` at all, independent of its admission standing.
///
/// The three authority roles — sole Task Controller, Architecture authority,
/// independent verifier — are refused unconditionally: I10.11 states the route
/// "does not become sole Task Controller, Architecture authority or independent
/// verifier by price or advertised context size", and route admission proves
/// measured route behavior, never planning or verification quality. The three
/// empirical scopes are the only roles the route may ever be selected for,
/// whether it is unadmitted, partially admitted, or admitted.
#[must_use]
pub const fn opencode_route_role_permitted(role: OpenCodeRouteRole) -> bool {
    role.is_empirical_scope()
}

/// `RGF-AGENT-ROUTES` standing of one `OpenCode` route profile, derived from the
/// retained pilot evidence and never declared.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenCodeRouteAdmissionState {
    /// No mandated probe evidence retained.
    Unadmitted,
    /// Some, but not all, of the six mandated probes retained a passing
    /// artifact.
    PartiallyAdmitted,
    /// All six mandated probes retained a passing artifact.
    Admitted,
}

/// Measured outcome of one mandated pilot probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenCodeProbeOutcome {
    /// The probe executed and its retained artifact shows the required behavior.
    Passed,
    /// The probe executed and its retained artifact shows the behavior is absent.
    Failed,
}

/// One mandated probe's retained route-admission artifact.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeRouteProbeEvidence {
    /// One exact member of [`OPENCODE_MANDATED_PROBES`].
    pub probe: String,
    pub outcome: OpenCodeProbeOutcome,
    /// Reference to the retained route-admission artifact for this probe.
    pub artifact_ref: String,
}

/// The named route profile of one `OpenCode` route: the canonical route
/// fingerprint plus the entire required fingerprint content of I10.11.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeRouteProfile {
    /// The named route profile, for example `opencode.server.http-sse`. A
    /// package with no named route profile has no admission.
    pub profile_id: String,
    /// Canonical route identity: adapter/runtime version and hash, serializer
    /// and tool-role-ordering hashes, reasoning mode, continuation behavior,
    /// feature flags, provider, model, and account/credential mode.
    pub fingerprint: RouteFingerprint,
    /// Provider endpoint the fingerprint was measured against.
    pub endpoint: String,
    /// Observed `OpenCode` server version and pinned executable hash.
    pub opencode_runtime_version: String,
    /// Observed serializer / chat-template revision.
    pub serializer_template_revision: String,
    /// Exact tool-role ordering the host emitted, not a capability summary.
    pub tool_role_ordering: String,
    /// Measured compaction behavior for the declared route.
    pub compaction_behavior: String,
    /// Auth and quota surface the route exposes, including what it does not.
    pub auth_quota_surface: String,
}

impl OpenCodeRouteProfile {
    /// Validates that this is a named route profile of the exact `OpenCode`
    /// HTTP/SSE route whose required content is all present.
    ///
    /// # Errors
    ///
    /// Returns [`OpenCodeRouteSelectionError::InvalidAdmission`] with the
    /// failing field name on the first incomplete or malformed component.
    pub fn validate(&self) -> Result<(), OpenCodeRouteSelectionError> {
        for (field, value) in [
            ("profile.profile_id", self.profile_id.as_str()),
            ("profile.endpoint", self.endpoint.as_str()),
            (
                "profile.opencode_runtime_version",
                self.opencode_runtime_version.as_str(),
            ),
            (
                "profile.serializer_template_revision",
                self.serializer_template_revision.as_str(),
            ),
            (
                "profile.tool_role_ordering",
                self.tool_role_ordering.as_str(),
            ),
            (
                "profile.compaction_behavior",
                self.compaction_behavior.as_str(),
            ),
            (
                "profile.auth_quota_surface",
                self.auth_quota_surface.as_str(),
            ),
        ] {
            if value.trim().is_empty() || value.chars().any(char::is_control) {
                return Err(OpenCodeRouteSelectionError::InvalidAdmission(field));
            }
        }
        if self.fingerprint.host_family != OPENCODE_HOST_FAMILY
            || self.fingerprint.adapter != OPENCODE_ADAPTER_ID
            || self.fingerprint.protocol_transport != OPENCODE_PROTOCOL_TRANSPORT
        {
            return Err(OpenCodeRouteSelectionError::InvalidAdmission(
                "profile.fingerprint",
            ));
        }
        self.fingerprint
            .validate()
            .map_err(|_| OpenCodeRouteSelectionError::InvalidAdmission("profile.fingerprint"))?;
        Ok(())
    }
}

/// The retained `RGF-AGENT-ROUTES` route-admission receipt for one named
/// `OpenCode` route profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodeRouteAdmission {
    pub schema_version: String,
    /// Always [`RGF_AGENT_ROUTES`]; another gate family is not an admission
    /// for this route.
    pub gate: String,
    pub profile: OpenCodeRouteProfile,
    /// Retained artifacts of the six mandated pilot probes. An absent probe is
    /// a probe that was not run, never a passing one.
    pub probe_evidence: Vec<OpenCodeRouteProbeEvidence>,
}

impl OpenCodeRouteAdmission {
    /// Validates the receipt: schema version, gate family, the named route
    /// profile, and probe evidence that names only mandated probes exactly
    /// once each with a retained artifact.
    ///
    /// # Errors
    ///
    /// Returns [`OpenCodeRouteSelectionError::InvalidAdmission`] with the
    /// failing field name on the first invalid component.
    pub fn validate(&self) -> Result<(), OpenCodeRouteSelectionError> {
        if self.schema_version != OPENCODE_ROUTE_ADMISSION_SCHEMA_VERSION {
            return Err(OpenCodeRouteSelectionError::InvalidAdmission(
                "schema_version",
            ));
        }
        if self.gate != RGF_AGENT_ROUTES {
            return Err(OpenCodeRouteSelectionError::InvalidAdmission("gate"));
        }
        self.profile.validate()?;
        let mut seen = BTreeSet::new();
        for evidence in &self.probe_evidence {
            if !OPENCODE_MANDATED_PROBES.contains(&evidence.probe.as_str()) {
                return Err(OpenCodeRouteSelectionError::InvalidAdmission(
                    "probe_evidence.probe",
                ));
            }
            if !seen.insert(evidence.probe.as_str()) {
                return Err(OpenCodeRouteSelectionError::InvalidAdmission(
                    "probe_evidence.probe",
                ));
            }
            if evidence.artifact_ref.trim().is_empty()
                || evidence.artifact_ref.chars().any(char::is_control)
            {
                return Err(OpenCodeRouteSelectionError::InvalidAdmission(
                    "probe_evidence.artifact_ref",
                ));
            }
        }
        Ok(())
    }

    /// The `RGF-AGENT-ROUTES` standing derived from the retained evidence:
    /// admitted only when all six mandated probes passed, partially admitted
    /// when some did, unadmitted when none did.
    #[must_use]
    pub fn admission_state(&self) -> OpenCodeRouteAdmissionState {
        let passed = self
            .probe_evidence
            .iter()
            .filter(|evidence| evidence.outcome == OpenCodeProbeOutcome::Passed)
            .count();
        if passed == OPENCODE_MANDATED_PROBES.len() {
            OpenCodeRouteAdmissionState::Admitted
        } else if passed == 0 {
            OpenCodeRouteAdmissionState::Unadmitted
        } else {
            OpenCodeRouteAdmissionState::PartiallyAdmitted
        }
    }
}

/// Typed policy disposition for a refused `OpenCode` route selection. Every arm
/// refuses before any provider call and names the exact cause.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum OpenCodeRouteSelectionError {
    /// The admission receipt or the requested route is not a usable
    /// `RGF-AGENT-ROUTES` record.
    #[error("OpenCode route admission is not a usable RGF-AGENT-ROUTES record: {0}")]
    InvalidAdmission(&'static str),
    /// The requested route is not the admitted route profile's recorded
    /// fingerprint. `fields` names the diverging fingerprint fields in the
    /// route owner's canonical order.
    #[error("OpenCode route selection does not match the admitted route fingerprint: {fields:?}")]
    FingerprintMismatch { fields: Vec<String> },
    /// The route is not admitted under `RGF-AGENT-ROUTES`, so it admits no
    /// selection at all.
    #[error("OpenCode route is {admission:?} under RGF-AGENT-ROUTES and admits no selection")]
    RouteNotAdmitted {
        admission: OpenCodeRouteAdmissionState,
    },
    /// The requested role is an authority role this empirical route never
    /// gains, or the route is not admitted and the role needs admission.
    #[error("OpenCode route may not be selected as {role:?} while it is {admission:?}")]
    RoleNotPermitted {
        role: OpenCodeRouteRole,
        admission: OpenCodeRouteAdmissionState,
    },
}

/// Gates one `OpenCode` route selection on `RGF-AGENT-ROUTES`.
///
/// The requested route is compared field-by-field against the **recorded**
/// admitted fingerprint of the named route profile, which is validated in its
/// own right first; no digest is recomputed over the caller's own copy. A
/// selection is admitted only when that fingerprint matches, the standing
/// derived from the retained pilot evidence is
/// [`OpenCodeRouteAdmissionState::Admitted`], and the requested role is one of
/// the three empirical scopes I10.11 keeps eligible.
///
/// # Errors
///
/// Returns [`OpenCodeRouteSelectionError::InvalidAdmission`] for an unusable
/// record, [`OpenCodeRouteSelectionError::FingerprintMismatch`] when the
/// requested route is not the admitted one, and the standing-specific
/// `RouteNotAdmitted` / `RoleNotPermitted` otherwise.
pub fn select_opencode_route(
    admission: &OpenCodeRouteAdmission,
    requested: &RouteFingerprint,
    role: OpenCodeRouteRole,
) -> Result<(), OpenCodeRouteSelectionError> {
    admission.validate()?;
    requested
        .validate()
        .map_err(|_| OpenCodeRouteSelectionError::InvalidAdmission("requested_route"))?;
    let admitted = &admission.profile.fingerprint;
    if admitted != requested {
        return Err(OpenCodeRouteSelectionError::FingerprintMismatch {
            fields: route_divergence_fields(requested, admitted),
        });
    }
    let state = admission.admission_state();
    if state != OpenCodeRouteAdmissionState::Admitted {
        return Err(OpenCodeRouteSelectionError::RouteNotAdmitted { admission: state });
    }
    if !opencode_route_role_permitted(role) {
        return Err(OpenCodeRouteSelectionError::RoleNotPermitted {
            role,
            admission: state,
        });
    }
    Ok(())
}

/// Whether the bounded pilot observed the behavior a mandated probe requires.
/// Absence is never a pass: an unobserved behavior is
/// [`Self::NotObserved`], which the probe evaluation records as `Failed`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OpenCodeProbeReading {
    /// The pilot observed the required behavior in the live run.
    Observed,
    /// The pilot did not observe it; the host did not demonstrate it.
    NotObserved,
}

/// One measured pilot observation, exactly as the bounded pilot run observed
/// it from the live `OpenCode` route.
///
/// Every field is a live reading or an explicit absence. The harness never
/// infers a value the host did not expose, so a probe whose required reading
/// is absent records [`OpenCodeProbeOutcome::Failed`], never `Passed`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpenCodePilotObservation {
    /// Turn count of tool call → tool result → continued tool call/reasoning
    /// observed on one session.
    pub continuation_turns_observed: u32,
    /// Whether a reasoning/assistant continuation survived the host
    /// serializer intact.
    pub reasoning_continuation_preserved: OpenCodeProbeReading,
    /// Provider actually reported by the host, if it exposed one.
    pub observed_provider: Option<String>,
    /// Model actually reported by the host, if it exposed one.
    pub observed_model: Option<String>,
    /// Count of provider/model fields the host did not expose; they are
    /// reported as missing rather than inferred.
    pub missing_fields_observed: u32,
    /// Measured context limit in tokens, if the host exposed one.
    pub measured_context_limit: Option<u64>,
    /// Measured output limit in tokens, if the host exposed one.
    pub measured_output_limit: Option<u64>,
    /// Whether compaction was observed happening during the pilot.
    pub compaction_observed: OpenCodeProbeReading,
    /// Whether quota/reset/usage came from a host-reported source.
    pub quota_usage_sourced: OpenCodeProbeReading,
    /// Whether the equal-stack fallback comparison ran and retained its
    /// artifact.
    pub equal_stack_comparison_retained: OpenCodeProbeReading,
}

/// The bounded pilot harness of I10.11: it executes the six mandated probes
/// against one live bounded attempt and returns the derived probe outcomes as
/// route-admission artifacts.
///
/// Each outcome is computed from the corresponding live reading; the harness
/// has no path that records a probe as passed without its required reading.
/// The harness measures only, and never selects a route: admission of the
/// resulting evidence is [`select_opencode_route`]'s decision.
#[must_use]
pub fn opencode_pilot_probe_evidence(
    observation: &OpenCodePilotObservation,
) -> Vec<OpenCodeRouteProbeEvidence> {
    let probe = |name: &str, outcome: OpenCodeProbeOutcome| OpenCodeRouteProbeEvidence {
        probe: name.to_owned(),
        outcome,
        artifact_ref: format!("opencode-pilot:{name}"),
    };
    let passed = OpenCodeProbeOutcome::Passed;
    let failed = OpenCodeProbeOutcome::Failed;
    let outcome = |reading: OpenCodeProbeReading| match reading {
        OpenCodeProbeReading::Observed => passed,
        OpenCodeProbeReading::NotObserved => failed,
    };
    vec![
        // multi-turn tool call → tool result → continued reasoning/tool call
        probe(
            OPENCODE_MANDATED_PROBES[0],
            if observation.continuation_turns_observed >= 2 {
                passed
            } else {
                failed
            },
        ),
        // reasoning/assistant continuation survives the host serializer
        probe(
            OPENCODE_MANDATED_PROBES[1],
            outcome(observation.reasoning_continuation_preserved),
        ),
        // actual provider/model and missing fields are reported honestly
        probe(
            OPENCODE_MANDATED_PROBES[2],
            if observation.observed_provider.is_some()
                && observation.observed_model.is_some()
                && observation.missing_fields_observed == 0
            {
                passed
            } else {
                failed
            },
        ),
        // context/output limits and compaction are measured, not inferred
        probe(
            OPENCODE_MANDATED_PROBES[3],
            if observation.measured_context_limit.is_some()
                && observation.measured_output_limit.is_some()
            {
                outcome(observation.compaction_observed)
            } else {
                failed
            },
        ),
        // quota/reset/usage are sourced and never treated as zero
        probe(
            OPENCODE_MANDATED_PROBES[4],
            outcome(observation.quota_usage_sourced),
        ),
        // controlled comparison against an equal-stack fallback route
        probe(
            OPENCODE_MANDATED_PROBES[5],
            outcome(observation.equal_stack_comparison_retained),
        ),
    ]
}
