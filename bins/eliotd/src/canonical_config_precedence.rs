//! Typed canonical configuration precedence (I3.9).
//!
//! Architecture: I3.9 (configuration layers), I3.5 (first-run user decisions),
//! I3.6 (model, route and portfolio policy).
//! Implementation: I3.9 seven-layer precedence with narrow-only merge.
//!
//! This module is pure configuration decoding owned by the Governor
//! application (`eliotd`, #18). It carries no Kernel, Store, session,
//! credential, provider, or effect semantics: it decodes one typed setting
//! chain from TOML/JSON layer documents, resolves the winning value in
//! canonical precedence order, and rejects lower-layer expansions unless each
//! tighter boundary crossed by the request has an explicit delegation within
//! the authority inherited from all higher layers.
//! Arbitrary executable scripts are invalid policy input, never a fallback
//! configuration source.
//!
//! Proven setting chains: [`CANONICAL_SETTING_KEY`] (`task.budget.per_job`),
//! a per-job budget limit where a smaller value narrows authority/cost.
//! Lower layers may narrow this limit; they may not expand it unless a higher
//! layer's `delegation_ceiling` covers the exact requested value.
//!
//! Second proven chain: [`RETENTION_POLICY_SETTING_KEY`]
//! (`retention_and_backup_policy`), the I3.11 WorkScope Profile field that
//! declares the closed set of retention policy refs the schedule owner attests.
//! It is ref-typed rather than numeric, so it has no numeric limit: it is
//! resolved by the same seven-layer narrow-only merge and the same typed
//! decoders, and a layer may only narrow the running ref set. A ref vocabulary
//! has no interval to delegate, so a ref the running set does not name is
//! refused ([`PrecedenceError::UndeclaredRetentionPolicy`]) rather than granted.
//! The set is never empty: an empty attestation would refuse every retention
//! read, so both the resolver and the declared owner
//! (`eliot_config::declared_retention_policy_refs`) refuse it.
//!
//! The legacy `governor.toml` surface (`bins/eliot`, #1687) adopts nothing:
//! a present legacy file still fails closed through the legacy rejector,
//! which now names this canonical surface as the sole typed replacement.
//!
//! [`resolve_effective_configuration`] is the production entry point: the
//! protected daemon config boundary calls it while loading the Host-approved
//! launch file, so an effective configuration that cannot be resolved refuses
//! the load and the generation never becomes ready.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The numeric proven setting chain for issue #1966.
///
/// A per-job budget limit: smaller narrows cost/authority, larger expands it.
pub const CANONICAL_SETTING_KEY: &str = "task.budget.per_job";

/// The I3.11 WorkScope Profile retention/backup declaration.
///
/// The exact spelling is owned by the immutable-configuration owner
/// (`eliot_config::RETENTION_POLICY_SETTING_KEY`, I3.11
/// `retention_and_backup_policy:`); this module re-exports that one name rather
/// than declaring a second spelling of the same setting, so the decoder here
/// and the declared owner in `eliot-governor` cannot disagree about which field
/// names the retention policy set.
pub use eliot_config::RETENTION_POLICY_SETTING_KEY;

/// Compiled safe default for [`CANONICAL_SETTING_KEY`], the broadest layer.
///
/// The compiled defaults delegate nothing, so this value is the ceiling of the
/// whole chain: no lower layer can raise the per-job budget above it. A lower
/// layer that narrows can only delegate expansion back up to a ceiling it
/// itself inherited.
pub const COMPILED_SAFE_DEFAULT_PER_JOB_BUDGET: u64 = 64;

/// Canonical precedence order, broadest (index 0) to narrowest (index 6).
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConfigLayer {
    /// Compiled safe defaults. Always present; seeds the merge.
    CompiledDefaults,
    /// Installation config (`%ProgramData%\Eliot\config\installation.toml`).
    InstallationConfig,
    /// System Owner policy (`%ProgramData%\Eliot\config\policy.toml`).
    SystemOwnerPolicy,
    /// `WorkScope` Profile (`<scope>\.eliot\profile.toml`, untrusted until admitted).
    WorkScopeProfile,
    /// Task/work-item policy.
    TaskPolicy,
    /// Session capability token.
    SessionCapabilityToken,
    /// Exact human approval. Narrowest layer.
    ExactHumanApproval,
}

/// All seven layers in canonical precedence order.
pub const ALL_LAYERS: [ConfigLayer; 7] = [
    ConfigLayer::CompiledDefaults,
    ConfigLayer::InstallationConfig,
    ConfigLayer::SystemOwnerPolicy,
    ConfigLayer::WorkScopeProfile,
    ConfigLayer::TaskPolicy,
    ConfigLayer::SessionCapabilityToken,
    ConfigLayer::ExactHumanApproval,
];

impl ConfigLayer {
    /// Canonical zero-based precedence position (0 = broadest).
    #[must_use]
    pub const fn order(self) -> u8 {
        match self {
            Self::CompiledDefaults => 0,
            Self::InstallationConfig => 1,
            Self::SystemOwnerPolicy => 2,
            Self::WorkScopeProfile => 3,
            Self::TaskPolicy => 4,
            Self::SessionCapabilityToken => 5,
            Self::ExactHumanApproval => 6,
        }
    }

    /// Stable `snake_case` identity used in typed TOML/JSON documents.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CompiledDefaults => "compiled_defaults",
            Self::InstallationConfig => "installation_config",
            Self::SystemOwnerPolicy => "system_owner_policy",
            Self::WorkScopeProfile => "workscope_profile",
            Self::TaskPolicy => "task_policy",
            Self::SessionCapabilityToken => "session_capability_token",
            Self::ExactHumanApproval => "exact_human_approval",
        }
    }

    /// Parses a document layer identity. Unknown identities are rejected.
    pub fn from_name(value: &str) -> Result<Self, PrecedenceError> {
        for layer in ALL_LAYERS {
            if layer.name() == value {
                return Ok(layer);
            }
        }
        Err(PrecedenceError::UnknownLayer(value.to_owned()))
    }
}

/// One layer's typed contribution to the proven setting chain.
///
/// `limit` is the layer's proposed value (`None` = layer abstains and the
/// running value carries forward). `delegation_ceiling` is an explicit
/// higher-layer delegation: an interval cap naming how far lower layers may
/// expand. A delegation is usable only when its ceiling is within the
/// authority currently inherited from all higher layers. Every explicit
/// lower-layer limit without a delegation is itself the next boundary,
/// including a repeat or an expansion permitted by an older grant; the next
/// effective ceiling is then the minimum of inherited authority and that
/// limit. An older grant therefore cannot survive an undelegated boundary.
/// The ceiling never raises the granting layer's own value, and a
/// delegation-only layer may grant only what it inherited.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayerInput {
    pub layer: ConfigLayer,
    pub limit: Option<u64>,
    pub delegation_ceiling: Option<u64>,
}

/// One accepted layer contribution in canonical precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedContribution {
    /// Canonical precedence position of the contributing layer.
    pub order: u8,
    /// Stable layer identity.
    pub layer: &'static str,
    /// Value applied after this layer merged.
    pub applied_value: u64,
    /// True when this layer narrowed the running value.
    pub narrowed: bool,
    /// True when this layer expanded under a higher-layer delegation.
    pub delegated_expansion: bool,
}

/// The resolved setting chain: winning value plus every contributing layer
/// in canonical precedence order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedChain {
    key: String,
    winning_value: u64,
    contributions: Vec<ResolvedContribution>,
}

impl ResolvedChain {
    /// The resolved setting key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The winning value after all seven layers merged.
    #[must_use]
    pub const fn winning_value(&self) -> u64 {
        self.winning_value
    }

    /// Each contributing layer in canonical precedence order.
    #[must_use]
    pub fn contributions(&self) -> &[ResolvedContribution] {
        &self.contributions
    }
}

/// Typed precedence failures. Every rejection is fail-closed with a bounded
/// reason; secrets, digests, and file bytes never enter the error text.
#[derive(Clone, Debug, Eq, PartialEq, Error)]
pub enum PrecedenceError {
    /// Compiled safe defaults are absent, so no chain can resolve.
    #[error("compiled safe defaults must seed the precedence chain")]
    MissingCompiledDefaults,
    /// The setting key is blank or outside the single proven chain.
    #[error("unsupported setting key: {0}")]
    InvalidKey(String),
    /// The document names a layer outside the seven canonical layers.
    #[error("unknown configuration layer: {0}")]
    UnknownLayer(String),
    /// Two contributions name the same canonical layer. Layer authority
    /// must be unambiguous: the first contribution must not silently win
    /// over a conflicting same-layer document.
    #[error("duplicate configuration layer: {0}")]
    DuplicateLayer(&'static str),
    /// Typed TOML/JSON decoding or schema validation failed.
    #[error("layer document schema rejected: {0}")]
    SchemaRejected(String),
    /// Executable script input was offered as policy and refused.
    #[error("script policy input is invalid: {0}")]
    ScriptPolicyRejected(String),
    /// A lower layer attempted to expand the running limit with no higher
    /// layer delegation covering the exact requested value.
    #[error(
        "layer {layer} may not expand {key} from {current} to {requested} without an explicit higher-layer delegation"
    )]
    ExpansionWithoutDelegation {
        layer: &'static str,
        key: String,
        current: u64,
        requested: u64,
    },
    /// A layer declared a retention policy ref the running set does not name.
    ///
    /// I3.9:15 permits narrowing only, and a ref vocabulary has no interval for
    /// a higher layer to delegate, so an expansion has no legal form and is
    /// refused instead of being granted by an undeclared vocabulary.
    #[error(
        "layer {layer} may not declare retention policy ref {policy_ref} that the running {key} set does not name"
    )]
    UndeclaredRetentionPolicy {
        layer: &'static str,
        key: String,
        policy_ref: String,
    },
    /// A layer declared no retention policy ref at all.
    ///
    /// An empty set attests nothing, so every retention-gated read would resolve
    /// to `ExperienceRetentionReadPosture::UnknownPolicy`. That is an
    /// always-refusing issuer, not a policy, so it is refused here rather than
    /// published as a successful resolution.
    #[error("layer {layer} may not leave {key} with no declared retention policy ref")]
    EmptyRetentionPolicySet { layer: &'static str, key: String },
    /// A layer declared the same retention policy ref twice.
    ///
    /// A repeated ref is ambiguous about whether the layer declared a set or a
    /// scalar, and the schedule contract rejects a duplicate in
    /// `known_policy_refs`, so the declaration is refused here rather than
    /// silently collapsed.
    #[error("layer {layer} declared a duplicate retention policy ref for {key}")]
    DuplicateRetentionPolicy { layer: &'static str, key: String },
}

/// Resolves one setting chain across all seven layers in canonical order.
///
/// The compiled-defaults layer must seed the chain. Each lower layer carrying
/// `Some(limit)` narrows (`limit <= running`), repeats (`limit == running`),
/// or expands (`limit > running`) only when the current effective delegation
/// ceiling covers the requested value. Every explicit lower-layer limit with
/// no valid delegation then becomes the next boundary, so repeats and
/// permitted expansions also replace the next ceiling with
/// `min(inherited_ceiling, limit)`; an older grant cannot cross it. A layer
/// can explicitly delegate an interval up to its `delegation_ceiling` only
/// within the ceiling it inherited from higher layers; a full inherited
/// ceiling is valid explicit delegation and is not a special strict-
/// sub-envelope policy. Abstaining layers (`None`) contribute no value but
/// may explicitly delegate within their inherited authority; an invalid
/// over-ceiling claim mints nothing.
///
/// # Errors
/// Returns [`PrecedenceError`] when the key is unsupported, defaults are
/// missing, layers repeat, or an expansion lacks a live covering
/// higher-layer delegation.
pub fn resolve_canonical_chain(
    key: &str,
    inputs: &[LayerInput],
) -> Result<ResolvedChain, PrecedenceError> {
    if key.trim().is_empty() || key != CANONICAL_SETTING_KEY {
        return Err(PrecedenceError::InvalidKey(key.to_owned()));
    }
    let mut claimed = [false; ALL_LAYERS.len()];
    for input in inputs {
        let slot = input.layer.order() as usize;
        if claimed[slot] {
            return Err(PrecedenceError::DuplicateLayer(input.layer.name()));
        }
        claimed[slot] = true;
    }
    let seed = inputs
        .iter()
        .find(|input| input.layer == ConfigLayer::CompiledDefaults)
        .and_then(|input| input.limit)
        .ok_or(PrecedenceError::MissingCompiledDefaults)?;
    let mut running = seed;
    let mut contributions = vec![ResolvedContribution {
        order: ConfigLayer::CompiledDefaults.order(),
        layer: ConfigLayer::CompiledDefaults.name(),
        applied_value: seed,
        narrowed: false,
        delegated_expansion: false,
    }];
    // Effective authority available to the next lower layer. A delegation
    // replaces this ceiling only when it is within the ceiling inherited from
    // above. A narrowing layer without a delegation replaces it with its own
    // value, retiring older grants at the boundary that just arrived.
    let mut lower_expansion_ceiling = seed;
    if let Some(seed_input) = inputs
        .iter()
        .find(|input| input.layer == ConfigLayer::CompiledDefaults)
        && let Some(ceiling) = seed_input.delegation_ceiling
        && ceiling <= lower_expansion_ceiling
    {
        lower_expansion_ceiling = ceiling;
    }
    for layer in ALL_LAYERS.iter().skip(1) {
        let Some(input) = inputs.iter().find(|input| input.layer == *layer) else {
            continue;
        };
        let inherited = lower_expansion_ceiling;
        let delegation = input
            .delegation_ceiling
            .filter(|ceiling| *ceiling <= inherited);
        let Some(requested) = input.limit else {
            if let Some(ceiling) = delegation {
                lower_expansion_ceiling = ceiling;
            }
            continue;
        };
        if requested <= running {
            contributions.push(ResolvedContribution {
                order: layer.order(),
                layer: layer.name(),
                applied_value: requested,
                narrowed: requested < running,
                delegated_expansion: false,
            });
            running = requested;
        } else if requested <= lower_expansion_ceiling {
            contributions.push(ResolvedContribution {
                order: layer.order(),
                layer: layer.name(),
                applied_value: requested,
                narrowed: false,
                delegated_expansion: true,
            });
            running = requested;
        } else {
            return Err(PrecedenceError::ExpansionWithoutDelegation {
                layer: layer.name(),
                key: key.to_owned(),
                current: running,
                requested,
            });
        }
        if let Some(ceiling) = delegation {
            lower_expansion_ceiling = ceiling;
        } else {
            lower_expansion_ceiling = inherited.min(requested);
        }
    }
    Ok(ResolvedChain {
        key: key.to_owned(),
        winning_value: running,
        contributions,
    })
}

/// One layer's typed contribution to the declared retention policy set.
///
/// `policy_refs` is the layer's proposed set (`None` = the layer abstains and
/// the running set carries forward). The narrow-only rule is the same one
/// `resolve_canonical_chain` applies to a numeric limit, minus delegation: a
/// requested set must be a subset of the running set. There is no
/// `delegation_ceiling` counterpart, because I3.9:15 lets a higher layer
/// delegate only when it "explicitly delegates expansion", and a closed ref
/// vocabulary has no such declaration anywhere in the configuration surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetentionLayerInput {
    /// The layer this contribution claims.
    pub layer: ConfigLayer,
    /// The declared ref set, or `None` when the layer abstains.
    pub policy_refs: Option<Vec<String>>,
}

/// One accepted layer contribution to the declared retention policy set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedRetentionContribution {
    /// Canonical precedence position of the contributing layer.
    pub order: u8,
    /// Stable layer identity.
    pub layer: &'static str,
    /// Ref set applied after this layer merged.
    pub applied_policy_refs: Vec<String>,
    /// True when this layer changed the running set.
    pub narrowed: bool,
}

/// The resolved declared retention policy set.
///
/// `policy_refs` is the exact closed set the schedule owner attests; it is
/// never empty, so a retention-gated read is refused for a genuinely undeclared
/// policy and never for an absent declaration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResolvedRetentionSet {
    key: String,
    policy_refs: Vec<String>,
    contributions: Vec<ResolvedRetentionContribution>,
}

impl ResolvedRetentionSet {
    /// The resolved setting key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// The winning declared ref set after all seven layers merged.
    #[must_use]
    pub fn policy_refs(&self) -> &[String] {
        &self.policy_refs
    }

    /// Each contributing layer in canonical precedence order.
    #[must_use]
    pub fn contributions(&self) -> &[ResolvedRetentionContribution] {
        &self.contributions
    }
}

/// Typed layer document shared by the JSON and TOML decoders.
///
/// One document carries one setting chain's value, discriminated by `key`:
/// `limit`/`delegation_ceiling` belong to the numeric chain, and
/// `policy_refs` belongs to the retention chain. A document that mixes the two,
/// or that omits its own chain's value, is a schema rejection rather than a
/// silently defaulted contribution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalLayerDocument {
    layer: String,
    key: String,
    limit: Option<u64>,
    delegation_ceiling: Option<u64>,
    policy_refs: Option<Vec<String>>,
}

/// One decoded layer contribution, typed by the chain its `key` names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DecodedLayerInput {
    /// A contribution to the numeric budget chain.
    Budget(LayerInput),
    /// A contribution to the declared retention policy set.
    Retention(RetentionLayerInput),
}

impl CanonicalLayerDocument {
    fn into_input(self) -> Result<DecodedLayerInput, PrecedenceError> {
        let key = self.key.trim();
        let layer = ConfigLayer::from_name(self.layer.trim())?;
        match key {
            CANONICAL_SETTING_KEY => {
                if self.policy_refs.is_some() {
                    return Err(PrecedenceError::SchemaRejected(format!(
                        "field \"policy_refs\" does not belong to setting key {key}"
                    )));
                }
                Ok(DecodedLayerInput::Budget(LayerInput {
                    layer,
                    limit: self.limit,
                    delegation_ceiling: self.delegation_ceiling,
                }))
            }
            RETENTION_POLICY_SETTING_KEY => {
                if self.limit.is_some() || self.delegation_ceiling.is_some() {
                    return Err(PrecedenceError::SchemaRejected(format!(
                        "numeric limit fields do not belong to setting key {key}"
                    )));
                }
                let Some(policy_refs) = self.policy_refs else {
                    return Err(PrecedenceError::SchemaRejected(format!(
                        "field \"policy_refs\" is required for setting key {key}"
                    )));
                };
                if policy_refs
                    .iter()
                    .any(|policy_ref| policy_ref.trim().is_empty())
                {
                    return Err(PrecedenceError::SchemaRejected(format!(
                        "field \"policy_refs\" must not contain a blank ref for setting key {key}"
                    )));
                }
                Ok(DecodedLayerInput::Retention(RetentionLayerInput {
                    layer,
                    policy_refs: Some(policy_refs),
                }))
            }
            _ => Err(PrecedenceError::InvalidKey(key.to_owned())),
        }
    }
}

/// Substrings that mark executable script content. Scripts are never policy.
const SCRIPT_MARKERS: [&str; 12] = [
    "#!",
    "<script",
    "invoke-",
    "powershell",
    "set-executionpolicy",
    "import os",
    "import sys",
    "os.system",
    "subprocess",
    "console.log",
    "require(",
    "| sh",
];

/// File extensions that are executable scripts, never typed policy.
const SCRIPT_EXTENSIONS: [&str; 7] = ["sh", "ps1", "py", "js", "bat", "cmd", "exe"];

fn content_is_script(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    SCRIPT_MARKERS.iter().any(|marker| lower.contains(marker))
}

/// Classifies untrusted policy input before any typed decoding.
///
/// Rejects executable scripts by file extension or script markers, and
/// rejects non-UTF-8 bytes as untyped input. Typed TOML/JSON decoding runs
/// only after this gate passes.
///
/// # Errors
/// Returns [`PrecedenceError::ScriptPolicyRejected`] for script input and
/// [`PrecedenceError::SchemaRejected`] for non-UTF-8 bytes.
pub fn classify_policy_input(file_name: &str, bytes: &[u8]) -> Result<(), PrecedenceError> {
    let extension = file_name
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if SCRIPT_EXTENSIONS.contains(&extension.as_str()) {
        return Err(PrecedenceError::ScriptPolicyRejected(format!(
            "refused executable policy file extension for {file_name}"
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PrecedenceError::SchemaRejected("policy input is not UTF-8".to_owned()))?;
    if content_is_script(text) {
        return Err(PrecedenceError::ScriptPolicyRejected(format!(
            "refused executable script content offered as policy for {file_name}"
        )));
    }
    Ok(())
}

/// Decodes one typed layer document from JSON.
///
/// Unknown fields are rejected (`deny_unknown_fields`); scripts are refused
/// before decoding; only [`CANONICAL_SETTING_KEY`] and
/// [`RETENTION_POLICY_SETTING_KEY`] are admitted, and the returned
/// [`DecodedLayerInput`] names which chain the document's value belongs to.
///
/// # Errors
/// Returns [`PrecedenceError`] for script, schema, layer, or key failures.
pub fn parse_canonical_layer_json(bytes: &[u8]) -> Result<DecodedLayerInput, PrecedenceError> {
    classify_policy_input("layer.json", bytes)?;
    let text = std::str::from_utf8(bytes)
        .map_err(|_| PrecedenceError::SchemaRejected("policy input is not UTF-8".to_owned()))?;
    let document: CanonicalLayerDocument = serde_json::from_str(text)
        .map_err(|error| PrecedenceError::SchemaRejected(error.to_string()))?;
    document.into_input()
}

/// Decodes one typed layer document from a minimal TOML subset.
///
/// Accepted shape only (flat table, one setting per document):
///
/// ```toml
/// layer = "task_policy"
/// key = "task.budget.per_job"
/// limit = 40
/// delegation_ceiling = 80
/// ```
///
/// and, for the declared retention policy set:
///
/// ```toml
/// layer = "workscope_profile"
/// key = "retention_and_backup_policy"
/// policy_refs = ["<declared retention policy ref>"]
/// ```
///
/// `layer` and `key` are required double-quoted strings; `limit` and
/// `delegation_ceiling` are optional bare integers; `policy_refs` is a
/// single-line array of double-quoted refs. Any other field, duplicate field,
/// missing required field, or unquoted value is a schema rejection. Unknown TOML
/// features (tables, multi-line arrays, inline documents) are rejected as
/// untyped input. Scripts are refused before decoding.
///
/// # Errors
/// Returns [`PrecedenceError`] for script, schema, layer, or key failures.
pub fn parse_canonical_layer_toml(text: &str) -> Result<DecodedLayerInput, PrecedenceError> {
    classify_policy_input("layer.toml", text.as_bytes())?;
    let mut layer: Option<String> = None;
    let mut key: Option<String> = None;
    let mut limit: Option<u64> = None;
    let mut delegation_ceiling: Option<u64> = None;
    let mut policy_refs: Option<Vec<String>> = None;
    let mut seen: Vec<&'static str> = Vec::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            return Err(PrecedenceError::SchemaRejected(
                "toml tables are not part of the canonical layer shape".to_owned(),
            ));
        }
        let Some((field, value)) = line.split_once('=') else {
            return Err(PrecedenceError::SchemaRejected(format!(
                "expected field = value, found {line:?}"
            )));
        };
        let field = field.trim();
        let value = value.trim();
        let slot: &'static str = match field {
            "layer" => "layer",
            "key" => "key",
            "limit" => "limit",
            "delegation_ceiling" => "delegation_ceiling",
            "policy_refs" => "policy_refs",
            _ => {
                return Err(PrecedenceError::SchemaRejected(format!(
                    "unknown layer field {field:?}"
                )));
            }
        };
        if seen.contains(&slot) {
            return Err(PrecedenceError::SchemaRejected(format!(
                "duplicate layer field {field:?}"
            )));
        }
        seen.push(slot);
        match slot {
            "layer" | "key" => {
                let unquoted = value
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'));
                let Some(unquoted) = unquoted else {
                    return Err(PrecedenceError::SchemaRejected(format!(
                        "field {field:?} must be a double-quoted string"
                    )));
                };
                if slot == "layer" {
                    layer = Some(unquoted.to_owned());
                } else {
                    key = Some(unquoted.to_owned());
                }
            }
            "policy_refs" => {
                policy_refs = Some(parse_policy_ref_array(value)?);
            }
            _ => {
                let parsed: u64 = value.parse().map_err(|_| {
                    PrecedenceError::SchemaRejected(format!(
                        "field {field:?} must be a bare integer"
                    ))
                })?;
                if slot == "limit" {
                    limit = Some(parsed);
                } else {
                    delegation_ceiling = Some(parsed);
                }
            }
        }
    }
    let (Some(layer), Some(key)) = (layer, key) else {
        return Err(PrecedenceError::SchemaRejected(
            "layer document requires layer and key".to_owned(),
        ));
    };
    CanonicalLayerDocument {
        layer,
        key,
        limit,
        delegation_ceiling,
        policy_refs,
    }
    .into_input()
}

/// Parses the single-line `policy_refs` array of a retention layer document.
///
/// Only a one-line array of double-quoted, non-blank, duplicate-free refs is
/// accepted, and the count is bounded by the same ceiling the declared owner
/// uses, so this minimal TOML subset cannot express an unbounded ref list. A
/// multi-line array, a non-string element, a blank ref, or a repeated ref is a
/// schema rejection rather than a partially accepted set.
fn parse_policy_ref_array(value: &str) -> Result<Vec<String>, PrecedenceError> {
    let Some(inner) = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    else {
        return Err(PrecedenceError::SchemaRejected(
            "field \"policy_refs\" must be a single-line array of double-quoted refs".to_owned(),
        ));
    };
    let mut refs: Vec<String> = Vec::new();
    for element in inner.split(',') {
        let element = element.trim();
        if element.is_empty() {
            continue;
        }
        let unquoted = element
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or_else(|| {
                PrecedenceError::SchemaRejected(
                    "each \"policy_refs\" element must be a double-quoted string".to_owned(),
                )
            })?;
        if unquoted.trim().is_empty() {
            return Err(PrecedenceError::SchemaRejected(
                "\"policy_refs\" must not contain a blank ref".to_owned(),
            ));
        }
        if refs.iter().any(|seen| seen == unquoted) {
            return Err(PrecedenceError::SchemaRejected(format!(
                "duplicate retention policy ref {unquoted:?}"
            )));
        }
        refs.push(unquoted.to_owned());
    }
    if refs.len() > eliot_config::MAX_DECLARED_RETENTION_POLICY_REFS {
        return Err(PrecedenceError::SchemaRejected(format!(
            "\"policy_refs\" exceeds the bound of {} refs",
            eliot_config::MAX_DECLARED_RETENTION_POLICY_REFS
        )));
    }
    Ok(refs)
}

/// Published JSON Schema for the canonical layer document.
///
/// This is the generated schema for the supported TOML/JSON layer files:
/// `layer` is the seven-name enum, `key` is one of the two proven setting
/// chains, `limit`/`delegation_ceiling` are the optional non-negative integers
/// of the numeric chain, `policy_refs` is the bounded ref array of the retention
/// chain, and unknown properties are forbidden. Exactly one chain's value shape
/// is admitted per document, and the decoder refuses a document that carries
/// both, so the schema admits the pair and the decoder discriminates by `key`.
#[must_use]
pub fn canonical_layer_json_schema() -> serde_json::Value {
    serde_json::json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://eliot.local/schemas/canonical-layer/v1",
        "title": "CanonicalLayerDocument",
        "type": "object",
        "required": ["layer", "key"],
        "additionalProperties": false,
        "properties": {
            "layer": {
                "type": "string",
                "enum": [
                    "compiled_defaults",
                    "installation_config",
                    "system_owner_policy",
                    "workscope_profile",
                    "task_policy",
                    "session_capability_token",
                    "exact_human_approval"
                ]
            },
            "key": {
                "type": "string",
                "enum": [CANONICAL_SETTING_KEY, RETENTION_POLICY_SETTING_KEY]
            },
            "limit": { "type": "integer", "minimum": 0 },
            "delegation_ceiling": { "type": "integer", "minimum": 0 },
            "policy_refs": {
                "type": "array",
                "items": { "type": "string", "minLength": 1 },
                "maxItems": eliot_config::MAX_DECLARED_RETENTION_POLICY_REFS,
                "uniqueItems": true
            }
        }
    })
}

/// Pretty-printed rendering of [`canonical_layer_json_schema`] for publishing.
#[must_use]
pub fn canonical_layer_json_schema_pretty() -> String {
    serde_json::to_string_pretty(&canonical_layer_json_schema()).unwrap_or_else(|_| "{}".to_owned())
}

/// One typed I3.9 configuration file as read by the protected config boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyDocument<'a> {
    /// File name of the document. Its extension selects the typed decoder and
    /// refuses executable script extensions before any decoding runs.
    pub file_name: &'a str,
    /// Exact document bytes as read through the protected config boundary.
    pub bytes: &'a [u8],
}

/// Resolves the effective canonical configuration from the I3.9 typed
/// configuration files and enforces the seven-layer precedence.
///
/// [`COMPILED_SAFE_DEFAULT_PER_JOB_BUDGET`] seeds the chain, so a document set
/// that names no layer still resolves to the compiled safe default. Every
/// supplied document is classified by [`classify_policy_input`] first, so a
/// script or non-UTF-8 input is refused before it can act as configuration,
/// and is then decoded by the typed decoder its extension names: `.toml`
/// through [`parse_canonical_layer_toml`] and `.json` through
/// [`parse_canonical_layer_json`]. Any other extension is a schema rejection,
/// so an untyped file is never read as a fallback configuration source.
/// [`resolve_canonical_chain`] merges the documents in canonical precedence
/// order and refuses any lower-layer expansion that no higher layer delegated,
/// so the returned chain is the effective configuration or the call fails
/// closed. A document may not claim a layer outside the seven canonical
/// layers, and two documents may not claim the same layer.
///
/// # Errors
/// Returns [`PrecedenceError`] for script, schema, unknown-layer,
/// duplicate-layer, or undelegated-expansion input.
pub fn resolve_effective_configuration(
    documents: &[PolicyDocument<'_>],
) -> Result<ResolvedChain, PrecedenceError> {
    let mut inputs = vec![LayerInput {
        layer: ConfigLayer::CompiledDefaults,
        limit: Some(COMPILED_SAFE_DEFAULT_PER_JOB_BUDGET),
        delegation_ceiling: None,
    }];
    for document in documents {
        let file_name = document.file_name;
        classify_policy_input(file_name, document.bytes)?;
        let extension = file_name
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match extension.as_str() {
            "json" => {
                if let DecodedLayerInput::Budget(input) =
                    parse_canonical_layer_json(document.bytes)?
                {
                    inputs.push(input);
                }
            }
            "toml" => {
                let text = std::str::from_utf8(document.bytes).map_err(|_| {
                    PrecedenceError::SchemaRejected("policy input is not UTF-8".to_owned())
                })?;
                if let DecodedLayerInput::Budget(input) = parse_canonical_layer_toml(text)? {
                    inputs.push(input);
                }
            }
            _ => {
                return Err(PrecedenceError::SchemaRejected(format!(
                    "unsupported policy file type for {file_name}"
                )));
            }
        }
    }
    resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
}

/// Resolves the effective declared retention policy set from the same I3.9
/// typed configuration files.
///
/// The declared vocabulary
/// ([`eliot_config::COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS`]) seeds the
/// chain, so a document set that names no layer still resolves to a non-empty
/// declared set and the schedule owner is never an always-refusing issuer. The
/// documents are read, classified, and decoded exactly as
/// [`resolve_effective_configuration`] reads them, through the same
/// [`classify_policy_input`] gate and the same typed decoders; only documents
/// naming [`RETENTION_POLICY_SETTING_KEY`] contribute to this chain, so a
/// document set may carry both proven chains without either one reading the
/// other's value.
///
/// [`resolve_canonical_retention_set`] merges in canonical precedence order and
/// refuses any lower layer that declares a ref the running set does not name
/// (I3.9:15 permits narrowing only) or that declares no ref at all, so the
/// returned set is the effective declared policy set or the call fails closed.
///
/// # Errors
/// Returns [`PrecedenceError`] for script, schema, unknown-layer,
/// duplicate-layer, undeclared-ref, or empty-set input.
pub fn resolve_effective_retention_set(
    documents: &[PolicyDocument<'_>],
) -> Result<ResolvedRetentionSet, PrecedenceError> {
    let mut inputs = vec![RetentionLayerInput {
        layer: ConfigLayer::CompiledDefaults,
        policy_refs: Some(eliot_config::compiled_default_retention_policy_refs()),
    }];
    for document in documents {
        let file_name = document.file_name;
        classify_policy_input(file_name, document.bytes)?;
        let extension = file_name
            .rsplit('.')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        match extension.as_str() {
            "json" => {
                if let DecodedLayerInput::Retention(input) =
                    parse_canonical_layer_json(document.bytes)?
                {
                    inputs.push(input);
                }
            }
            "toml" => {
                let text = std::str::from_utf8(document.bytes).map_err(|_| {
                    PrecedenceError::SchemaRejected("policy input is not UTF-8".to_owned())
                })?;
                if let DecodedLayerInput::Retention(input) = parse_canonical_layer_toml(text)? {
                    inputs.push(input);
                }
            }
            _ => {
                return Err(PrecedenceError::SchemaRejected(format!(
                    "unsupported policy file type for {file_name}"
                )));
            }
        }
    }
    resolve_canonical_retention_set(RETENTION_POLICY_SETTING_KEY, &inputs)
}

/// Resolves the declared retention policy set across all seven layers in
/// canonical order.
///
/// [`ConfigLayer::CompiledDefaults`] must seed the chain, exactly as for the
/// numeric chain: without the broadest layer there is no declared vocabulary to
/// narrow, and seeding from anywhere else would let a narrower layer define the
/// ceiling. Each lower layer carrying `Some(policy_refs)` must declare a subset
/// of the running set; an abstaining layer (`None`) contributes no value and
/// the running set carries forward. A requested set is applied in the running
/// set's canonical order, so the resolved set is a function of the layer order
/// and not of the order the refs were written in a document.
///
/// # Errors
/// Returns [`PrecedenceError`] when the key is unsupported, defaults are
/// missing, a layer repeats, a layer declares a ref outside the running set, or
/// a layer would leave the set empty.
pub fn resolve_canonical_retention_set(
    key: &str,
    inputs: &[RetentionLayerInput],
) -> Result<ResolvedRetentionSet, PrecedenceError> {
    if key.trim().is_empty() || key != RETENTION_POLICY_SETTING_KEY {
        return Err(PrecedenceError::InvalidKey(key.to_owned()));
    }
    let mut claimed = [false; ALL_LAYERS.len()];
    for input in inputs {
        let slot = input.layer.order() as usize;
        if claimed[slot] {
            return Err(PrecedenceError::DuplicateLayer(input.layer.name()));
        }
        claimed[slot] = true;
    }
    let seed = inputs
        .iter()
        .find(|input| input.layer == ConfigLayer::CompiledDefaults)
        .and_then(|input| input.policy_refs.clone())
        .ok_or(PrecedenceError::MissingCompiledDefaults)?;
    if seed.is_empty() {
        return Err(PrecedenceError::EmptyRetentionPolicySet {
            layer: ConfigLayer::CompiledDefaults.name(),
            key: key.to_owned(),
        });
    }
    let mut running = seed;
    let mut contributions = vec![ResolvedRetentionContribution {
        order: ConfigLayer::CompiledDefaults.order(),
        layer: ConfigLayer::CompiledDefaults.name(),
        narrowed: false,
        applied_policy_refs: running.clone(),
    }];
    for layer in ALL_LAYERS.iter().skip(1) {
        let Some(input) = inputs.iter().find(|input| input.layer == *layer) else {
            continue;
        };
        let Some(requested) = input.policy_refs.as_ref() else {
            continue;
        };
        if requested.is_empty() {
            return Err(PrecedenceError::EmptyRetentionPolicySet {
                layer: layer.name(),
                key: key.to_owned(),
            });
        }
        // A ref vocabulary has no delegated interval, so narrowing is a plain
        // subset test against the running set. The applied set keeps the running
        // set's order, so the result is deterministic per layer order.
        let mut narrowed: Vec<String> = Vec::with_capacity(requested.len());
        for policy_ref in requested {
            if !running.iter().any(|known| known == policy_ref) {
                return Err(PrecedenceError::UndeclaredRetentionPolicy {
                    layer: layer.name(),
                    key: key.to_owned(),
                    policy_ref: policy_ref.clone(),
                });
            }
            if narrowed.contains(policy_ref) {
                return Err(PrecedenceError::DuplicateRetentionPolicy {
                    layer: layer.name(),
                    key: key.to_owned(),
                });
            }
            narrowed.push(policy_ref.clone());
        }
        contributions.push(ResolvedRetentionContribution {
            order: layer.order(),
            layer: layer.name(),
            narrowed: narrowed != running,
            applied_policy_refs: narrowed.clone(),
        });
        running = narrowed;
    }
    Ok(ResolvedRetentionSet {
        key: key.to_owned(),
        policy_refs: running,
        contributions,
    })
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "precedence unit tests assert exact fail-closed shapes with real inputs"
)]
mod tests {
    use super::{
        CANONICAL_SETTING_KEY, COMPILED_SAFE_DEFAULT_PER_JOB_BUDGET, ConfigLayer,
        DecodedLayerInput, LayerInput, PolicyDocument, RETENTION_POLICY_SETTING_KEY,
        RetentionLayerInput, canonical_layer_json_schema, parse_canonical_layer_json,
        parse_canonical_layer_toml, resolve_canonical_chain, resolve_canonical_retention_set,
        resolve_effective_configuration, resolve_effective_retention_set,
    };

    fn narrowing_chain() -> Vec<LayerInput> {
        vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::InstallationConfig,
                limit: None,
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(80),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::WorkScopeProfile,
                limit: None,
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::TaskPolicy,
                limit: Some(60),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::SessionCapabilityToken,
                limit: Some(40),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::ExactHumanApproval,
                limit: None,
                delegation_ceiling: None,
            },
        ]
    }

    #[test]
    fn resolved_chain_reports_winning_value_and_canonical_order() {
        let chain = resolve_canonical_chain(CANONICAL_SETTING_KEY, &narrowing_chain())
            .expect("narrowing chain must resolve");
        assert_eq!(chain.key(), CANONICAL_SETTING_KEY);
        assert_eq!(chain.winning_value(), 40);
        let orders: Vec<u8> = chain
            .contributions()
            .iter()
            .map(|item| item.order)
            .collect();
        assert_eq!(orders, vec![0, 2, 4, 5]);
        let mut sorted = orders.clone();
        sorted.sort_unstable();
        assert_eq!(orders, sorted, "contributions must be in canonical order");
    }

    #[test]
    fn narrowing_allowed_but_expansion_fails_without_delegation() {
        let mut inputs = narrowing_chain();
        inputs[5] = LayerInput {
            layer: ConfigLayer::SessionCapabilityToken,
            limit: Some(90),
            delegation_ceiling: None,
        };
        let error = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect_err("expansion without delegation must fail");
        assert!(
            error
                .to_string()
                .contains("without an explicit higher-layer delegation"),
            "unexpected: {error}"
        );

        inputs[2] = LayerInput {
            layer: ConfigLayer::SystemOwnerPolicy,
            limit: Some(80),
            delegation_ceiling: Some(90),
        };
        inputs[4] = LayerInput {
            layer: ConfigLayer::TaskPolicy,
            limit: Some(60),
            delegation_ceiling: Some(90),
        };
        let chain = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect("every crossed boundary must explicitly delegate");
        assert_eq!(chain.winning_value(), 90);
        assert!(
            chain
                .contributions()
                .last()
                .is_some_and(|item| item.delegated_expansion),
            "expansion must be marked delegated"
        );
    }

    #[test]
    fn duplicate_layer_documents_reject_before_resolution() {
        let mut inputs = narrowing_chain();
        inputs.push(LayerInput {
            layer: ConfigLayer::TaskPolicy,
            limit: Some(10),
            delegation_ceiling: None,
        });
        let error = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect_err("duplicate layer must fail closed");
        assert!(
            error.to_string().contains("duplicate configuration layer"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn self_granted_delegation_cannot_launder_expansion() {
        // Task mints ceiling 1000 beyond its inherited 100 and the session
        // spends it. The grant clamps to inherited authority, so the session
        // expansion must fail closed.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::TaskPolicy,
                limit: Some(50),
                delegation_ceiling: Some(1000),
            },
            LayerInput {
                layer: ConfigLayer::SessionCapabilityToken,
                limit: Some(1000),
                delegation_ceiling: None,
            },
        ];
        let error = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect_err("self-minted delegation must not authorize expansion");
        assert!(
            error
                .to_string()
                .contains("without an explicit higher-layer delegation"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn older_delegation_cannot_bypass_intervening_tighter_boundary() {
        // Abstaining installation grants 1000, clamped to its inherited 100.
        // System Owner then tightens to 50, so the task request for 1000 has
        // no exact effective cover and must fail.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::InstallationConfig,
                limit: None,
                delegation_ceiling: Some(1000),
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(50),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::TaskPolicy,
                limit: Some(1000),
                delegation_ceiling: None,
            },
        ];
        let error = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect_err("stale broad delegation must not bypass the tighter boundary");
        assert!(
            error
                .to_string()
                .contains("without an explicit higher-layer delegation"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn stale_exact_grant_cannot_override_later_tighter_boundary() {
        // Compiled explicitly delegates its full 100 envelope. System Owner
        // then tightens to 60 without delegating, so that later boundary
        // retires the older grant before the session is evaluated.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: Some(100),
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(60),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::SessionCapabilityToken,
                limit: Some(100),
                delegation_ceiling: None,
            },
        ];
        let error = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect_err("stale restatement grant must not override the tighter boundary");
        assert!(
            error
                .to_string()
                .contains("without an explicit higher-layer delegation"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn abstaining_grant_does_not_cross_later_undelegated_boundary() {
        // An abstaining layer may explicitly delegate its inherited 100
        // envelope, but System Owner's later 60 boundary has no delegation,
        // so the session request for 100 fails.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::InstallationConfig,
                limit: None,
                delegation_ceiling: Some(100),
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(60),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::SessionCapabilityToken,
                limit: Some(100),
                delegation_ceiling: None,
            },
        ];
        let error = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect_err("abstaining restatement must grant nothing");
        assert!(
            error
                .to_string()
                .contains("without an explicit higher-layer delegation"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn later_undelegated_boundary_retires_older_interval_grant() {
        // This is the production regression: compiled 100 delegates 90,
        // System Owner narrows to 60 without delegating, and the session's
        // stale request for 90 must not reuse the compiled grant.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: Some(90),
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(60),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::SessionCapabilityToken,
                limit: Some(90),
                delegation_ceiling: None,
            },
        ];
        let error = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect_err("a later undelegated boundary must retire the older grant");
        assert!(
            error
                .to_string()
                .contains("without an explicit higher-layer delegation"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn repeated_explicit_limit_establishes_a_new_boundary() {
        // Installation narrows to 60 while delegating 90. System Owner
        // repeats that 60 limit without delegating, so the repeated limit is
        // itself the boundary that retires the older 90 grant.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::InstallationConfig,
                limit: Some(60),
                delegation_ceiling: Some(90),
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(60),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::SessionCapabilityToken,
                limit: Some(80),
                delegation_ceiling: None,
            },
        ];
        let error = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect_err("a repeated undelegated limit must retire the older grant");
        assert!(
            error
                .to_string()
                .contains("without an explicit higher-layer delegation"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn undelegated_expansion_establishes_a_new_boundary() {
        // System Owner delegates 90 across its 60 limit. Task may therefore
        // expand to 80, but without its own delegation that 80 becomes the
        // next boundary and Session cannot expand to 85.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(60),
                delegation_ceiling: Some(90),
            },
            LayerInput {
                layer: ConfigLayer::TaskPolicy,
                limit: Some(80),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::SessionCapabilityToken,
                limit: Some(85),
                delegation_ceiling: None,
            },
        ];
        let error = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect_err("an undelegated expansion must establish its own boundary");
        assert!(
            error
                .to_string()
                .contains("without an explicit higher-layer delegation"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn delegated_system_owner_boundary_allows_session_expansion() {
        // A System Owner limit of 60 may explicitly delegate 90. The session
        // may then expand directly to 80 within that inherited authority.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(60),
                delegation_ceiling: Some(90),
            },
            LayerInput {
                layer: ConfigLayer::SessionCapabilityToken,
                limit: Some(80),
                delegation_ceiling: None,
            },
        ];
        let chain = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect("a session expansion inside explicit delegation must resolve");
        assert_eq!(chain.winning_value(), 80);
        assert!(
            chain
                .contributions()
                .last()
                .is_some_and(|item| item.delegated_expansion),
            "session expansion must be marked delegated"
        );
    }

    #[test]
    fn live_grant_covers_interval_up_to_its_ceiling() {
        // Installation grants 95, and System Owner explicitly carries that
        // delegation across its 80 boundary. The task expansion to 90 then
        // stays inside the current live grant interval.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::InstallationConfig,
                limit: None,
                delegation_ceiling: Some(95),
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(80),
                delegation_ceiling: Some(95),
            },
            LayerInput {
                layer: ConfigLayer::TaskPolicy,
                limit: Some(90),
                delegation_ceiling: None,
            },
        ];
        let chain = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect("request inside a live grant interval must resolve");
        assert_eq!(chain.winning_value(), 90);
        assert!(
            chain
                .contributions()
                .last()
                .is_some_and(|item| item.delegated_expansion),
            "expansion must be marked delegated"
        );
    }

    #[test]
    fn exact_effective_delegation_from_higher_layer_resolves() {
        // Abstaining installation grants exactly 95 within its inherited 100.
        // System Owner explicitly carries that delegation across its 80
        // boundary, so the task expansion to exactly 95 resolves delegated.
        let inputs = vec![
            LayerInput {
                layer: ConfigLayer::CompiledDefaults,
                limit: Some(100),
                delegation_ceiling: None,
            },
            LayerInput {
                layer: ConfigLayer::InstallationConfig,
                limit: None,
                delegation_ceiling: Some(95),
            },
            LayerInput {
                layer: ConfigLayer::SystemOwnerPolicy,
                limit: Some(80),
                delegation_ceiling: Some(95),
            },
            LayerInput {
                layer: ConfigLayer::TaskPolicy,
                limit: Some(95),
                delegation_ceiling: None,
            },
        ];
        let chain = resolve_canonical_chain(CANONICAL_SETTING_KEY, &inputs)
            .expect("exact effective delegation must resolve");
        assert_eq!(chain.winning_value(), 95);
        assert!(
            chain
                .contributions()
                .last()
                .is_some_and(|item| item.delegated_expansion),
            "expansion must be marked delegated"
        );
    }

    #[test]
    fn repeated_json_fields_reject_as_ambiguous() {
        let repeated =
            br#"{"layer":"task_policy","key":"task.budget.per_job","limit":40,"limit":90}"#;
        let error = parse_canonical_layer_json(repeated).expect_err("repeated field must fail");
        assert!(
            error.to_string().contains("duplicate"),
            "unexpected: {error}"
        );
    }

    #[test]
    fn script_and_untyped_input_rejected_with_schema_error() {
        let script = b"#!/bin/sh\nexport LIMIT=999\n";
        let error = parse_canonical_layer_json(script).expect_err("script must be refused");
        assert!(error.to_string().contains("script"), "unexpected: {error}");

        let powershell = b"Invoke-Expression \"Set-Limit 999\"\n{\"layer\":\"task_policy\"}";
        let error = parse_canonical_layer_json(powershell).expect_err("script must be refused");
        assert!(error.to_string().contains("script"), "unexpected: {error}");

        let untyped =
            br#"{"layer":"task_policy","key":"task.budget.per_job","limit":40,"extra":true}"#;
        let error = parse_canonical_layer_json(untyped).expect_err("unknown field must fail");
        assert!(
            error.to_string().contains("schema rejected"),
            "unexpected: {error}"
        );

        let toml_script = "#!/usr/bin/env python3\nlayer = \"task_policy\"\n";
        let error =
            parse_canonical_layer_toml(toml_script).expect_err("toml script must be refused");
        assert!(error.to_string().contains("script"), "unexpected: {error}");

        let schema = canonical_layer_json_schema();
        assert_eq!(
            schema["additionalProperties"],
            serde_json::json!(false),
            "schema must forbid unknown properties"
        );
        assert!(
            schema["properties"]["layer"]["enum"]
                .as_array()
                .is_some_and(|names| names.len() == 7),
            "schema must enumerate all seven layers"
        );
        assert!(
            schema["properties"]["key"]["enum"]
                .as_array()
                .is_some_and(|keys| keys.len() == 2),
            "schema must enumerate both proven setting chains"
        );
    }

    // Declared retention policy set (I3.11 `retention_and_backup_policy`).
    //
    // The declared ref is read through the owner constant so this test cannot
    // drift from the declaration it proves.

    fn declared_ref(index: usize) -> String {
        eliot_config::COMPILED_SAFE_DEFAULT_RETENTION_POLICY_REFS[index].to_owned()
    }

    fn retention_inputs(
        seed: Option<Vec<String>>,
        lower: &[(ConfigLayer, Option<Vec<String>>)],
    ) -> Vec<RetentionLayerInput> {
        let mut inputs = vec![RetentionLayerInput {
            layer: ConfigLayer::CompiledDefaults,
            policy_refs: seed,
        }];
        inputs.extend(
            lower
                .iter()
                .map(|(layer, policy_refs)| RetentionLayerInput {
                    layer: *layer,
                    policy_refs: policy_refs.clone(),
                }),
        );
        inputs
    }

    #[test]
    fn declared_set_resolves_from_the_compiled_default_and_narrows() {
        // Positive: with no document the compiled declared vocabulary is the
        // effective set, so the schedule owner is never empty.
        let expected = eliot_config::compiled_default_retention_policy_refs();
        let effective = resolve_effective_retention_set(&[]).expect("compiled default resolves");
        assert_eq!(effective.key(), RETENTION_POLICY_SETTING_KEY);
        assert_eq!(effective.policy_refs(), expected);

        // A narrower layer restating the compiled ref narrows to the same set.
        let narrowed = resolve_canonical_retention_set(
            RETENTION_POLICY_SETTING_KEY,
            &retention_inputs(
                Some(vec![declared_ref(0)]),
                &[(ConfigLayer::WorkScopeProfile, Some(vec![declared_ref(0)]))],
            ),
        )
        .expect("a narrower restatement resolves");
        assert_eq!(narrowed.policy_refs(), expected);
        assert!(
            narrowed
                .contributions()
                .last()
                .is_some_and(|item| item.order == ConfigLayer::WorkScopeProfile.order()),
            "the narrowing layer must be recorded in canonical order"
        );
    }

    #[test]
    fn declared_set_refuses_expansion_empty_and_missing_defaults() {
        let expanded = resolve_canonical_retention_set(
            RETENTION_POLICY_SETTING_KEY,
            &retention_inputs(
                Some(vec![declared_ref(0)]),
                &[(
                    ConfigLayer::SystemOwnerPolicy,
                    Some(vec!["eliot.governor.retention.forever:1.0.0".to_owned()]),
                )],
            ),
        )
        .expect_err("I3.9:15 permits narrowing only");
        assert!(
            expanded.to_string().contains("does not name"),
            "unexpected: {expanded}"
        );

        let emptied = resolve_canonical_retention_set(
            RETENTION_POLICY_SETTING_KEY,
            &retention_inputs(
                Some(vec![declared_ref(0)]),
                &[(ConfigLayer::SystemOwnerPolicy, Some(Vec::new()))],
            ),
        )
        .expect_err("an always-refusing issuer must be refused");
        assert!(
            emptied
                .to_string()
                .contains("no declared retention policy ref"),
            "unexpected: {emptied}"
        );

        let unseeded = resolve_canonical_retention_set(
            RETENTION_POLICY_SETTING_KEY,
            &retention_inputs(None, &[]),
        )
        .expect_err("the broadest layer must seed the chain");
        assert!(
            unseeded.to_string().contains("compiled safe defaults"),
            "unexpected: {unseeded}"
        );

        let repeated = resolve_canonical_retention_set(
            RETENTION_POLICY_SETTING_KEY,
            &retention_inputs(
                Some(vec![declared_ref(0)]),
                &[(
                    ConfigLayer::ExactHumanApproval,
                    Some(vec![declared_ref(0), declared_ref(0)]),
                )],
            ),
        )
        .expect_err("a repeated ref is ambiguous");
        assert!(
            repeated.to_string().contains("duplicate"),
            "unexpected: {repeated}"
        );
    }

    #[test]
    fn declared_set_documents_decode_by_key_and_do_not_cross_chains() {
        let standard = declared_ref(0);
        let toml = format!(
            "layer = \"system_owner_policy\"\nkey = \"{RETENTION_POLICY_SETTING_KEY}\"\npolicy_refs = [\"{standard}\"]\n"
        );
        let decoded = parse_canonical_layer_toml(&toml).expect("retention document must decode");
        match decoded {
            DecodedLayerInput::Retention(RetentionLayerInput {
                layer,
                policy_refs: Some(decoded_refs),
            }) => {
                assert_eq!(layer, ConfigLayer::SystemOwnerPolicy);
                assert_eq!(decoded_refs, vec![standard.clone()]);
            }
            other => panic!("retention document decoded as the wrong chain: {other:?}"),
        }
        // The retention document contributes to the retention chain only; the
        // numeric chain must not read it, and vice versa.
        let documents = [PolicyDocument {
            file_name: "policy.toml",
            bytes: toml.as_bytes(),
        }];
        assert_eq!(
            resolve_effective_configuration(&documents)
                .expect("numeric chain unaffected")
                .winning_value(),
            COMPILED_SAFE_DEFAULT_PER_JOB_BUDGET
        );
        assert_eq!(
            resolve_effective_retention_set(&documents)
                .expect("retention chain resolves")
                .policy_refs(),
            eliot_config::compiled_default_retention_policy_refs()
        );

        // A budget field inside a retention document, or a retention field inside
        // a budget document, is a schema rejection rather than a defaulted value.
        let crossed = format!(
            "layer = \"task_policy\"\nkey = \"{RETENTION_POLICY_SETTING_KEY}\"\nlimit = 10\n"
        );
        assert!(
            parse_canonical_layer_toml(&crossed)
                .expect_err("a numeric field cannot cross into the retention chain")
                .to_string()
                .contains("schema rejected")
        );
        let crossed_other = format!(
            "layer = \"task_policy\"\nkey = \"{CANONICAL_SETTING_KEY}\"\npolicy_refs = [\"{standard}\"]\n"
        );
        assert!(
            parse_canonical_layer_toml(&crossed_other)
                .expect_err("a ref array cannot cross into the numeric chain")
                .to_string()
                .contains("schema rejected")
        );

        // A duplicated ref list is refused at decode rather than collapsed, so
        // a document cannot mean either a set or a scalar.
        let repeated = format!(
            "layer = \"system_owner_policy\"\nkey = \"{RETENTION_POLICY_SETTING_KEY}\"\npolicy_refs = [{standard},{standard}]\n"
        );
        assert!(
            parse_canonical_layer_toml(&repeated)
                .expect_err("a repeated ref is ambiguous")
                .to_string()
                .contains("duplicate")
        );
        let blank = format!(
            "layer = \"system_owner_policy\"\nkey = \"{RETENTION_POLICY_SETTING_KEY}\"\npolicy_refs = [\"\"]\n"
        );
        assert!(
            parse_canonical_layer_toml(&blank)
                .expect_err("a blank ref is not a declaration")
                .to_string()
                .contains("blank")
        );
    }
}
