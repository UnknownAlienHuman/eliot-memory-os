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
//! Proven setting chain: [`CANONICAL_SETTING_KEY`] (`task.budget.per_job`),
//! a per-job budget limit where a smaller value narrows authority/cost.
//! Lower layers may narrow this limit; they may not expand it unless a higher
//! layer's `delegation_ceiling` covers the exact requested value.
//!
//! The legacy `governor.toml` surface (`bins/eliot`, #1687) adopts nothing:
//! a present legacy file still fails closed through the legacy rejector,
//! which now names this canonical surface as the sole typed replacement.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The single proven setting chain for issue #1966.
///
/// A per-job budget limit: smaller narrows cost/authority, larger expands it.
pub const CANONICAL_SETTING_KEY: &str = "task.budget.per_job";

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

/// Typed layer document shared by the JSON and TOML decoders.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalLayerDocument {
    layer: String,
    key: String,
    limit: Option<u64>,
    delegation_ceiling: Option<u64>,
}

impl CanonicalLayerDocument {
    fn into_input(self) -> Result<LayerInput, PrecedenceError> {
        if self.key.trim().is_empty() || self.key != CANONICAL_SETTING_KEY {
            return Err(PrecedenceError::InvalidKey(self.key));
        }
        Ok(LayerInput {
            layer: ConfigLayer::from_name(self.layer.trim())?,
            limit: self.limit,
            delegation_ceiling: self.delegation_ceiling,
        })
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
/// before decoding; only [`CANONICAL_SETTING_KEY`] is admitted.
///
/// # Errors
/// Returns [`PrecedenceError`] for script, schema, layer, or key failures.
pub fn parse_canonical_layer_json(bytes: &[u8]) -> Result<LayerInput, PrecedenceError> {
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
/// `layer` and `key` are required double-quoted strings; `limit` and
/// `delegation_ceiling` are optional bare integers; any other field,
/// duplicate field, missing required field, or unquoted value is a schema
/// rejection. Unknown TOML features (tables, arrays, inline documents) are
/// rejected as untyped input. Scripts are refused before decoding.
///
/// # Errors
/// Returns [`PrecedenceError`] for script, schema, layer, or key failures.
pub fn parse_canonical_layer_toml(text: &str) -> Result<LayerInput, PrecedenceError> {
    classify_policy_input("layer.toml", text.as_bytes())?;
    let mut layer: Option<String> = None;
    let mut key: Option<String> = None;
    let mut limit: Option<u64> = None;
    let mut delegation_ceiling: Option<u64> = None;
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
    }
    .into_input()
}

/// Published JSON Schema for the canonical layer document.
///
/// This is the generated schema for the supported TOML/JSON layer files:
/// `layer` is the seven-name enum, `key` is the proven setting chain,
/// `limit`/`delegation_ceiling` are optional non-negative integers, and
/// unknown properties are forbidden.
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
                "const": CANONICAL_SETTING_KEY
            },
            "limit": { "type": "integer", "minimum": 0 },
            "delegation_ceiling": { "type": "integer", "minimum": 0 }
        }
    })
}

/// Pretty-printed rendering of [`canonical_layer_json_schema`] for publishing.
#[must_use]
pub fn canonical_layer_json_schema_pretty() -> String {
    serde_json::to_string_pretty(&canonical_layer_json_schema()).unwrap_or_else(|_| "{}".to_owned())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "precedence unit tests assert exact fail-closed shapes with real inputs"
)]
mod tests {
    use super::{
        CANONICAL_SETTING_KEY, ConfigLayer, LayerInput, canonical_layer_json_schema,
        parse_canonical_layer_json, parse_canonical_layer_toml, resolve_canonical_chain,
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
    }
}
