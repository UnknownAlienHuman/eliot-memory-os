//! Task-relative tool-surface budget and dispatch binding contracts (I7.24).
//!
//! This module is the shared, store-neutral contract for the tool surface
//! economy. It owns no transport, execution, policy decision, or persistence.
//! It binds the **actually advertised** surface to a generated
//! [`ToolSurfaceBudget`] measured from the final rendered bytes, and it
//! carries surface/method/profile/task/grant revisions into call admission
//! through [`SurfaceDispatchBinding`].
//!
//! Byte observations and token observations stay distinct: an unmeasured cost
//! is never zero or actual tokens. Fields whose observation owner is not
//! joined at the compiling seam are explicitly unresolved (`None`,
//! [`TokenCountObservation::Unavailable`], or [`BudgetCoverage::Incomplete`])
//! rather than omitted or invented.

#![forbid(unsafe_code)]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::sha256_hex;
use crate::tool_exposure::{TokenCountObservation, ToolExposureError, digest, text};
use crate::{GrantClosureReceipt, GrantClosureState};

/// Stable contract revision shared by the surface decision, budget, and
/// dispatch binding. All three must agree on this value; a mismatch fails
/// closed.
pub const TOOL_SURFACE_CONTRACT_VERSION: u16 = 1;

/// Maximum number of tools carried by one surface budget.
pub const MAX_BUDGET_TOOLS: usize = 128;
/// Maximum UTF-8 bytes of one budget text field.
pub const MAX_BUDGET_TEXT_BYTES: usize = 4_096;

fn bounded_text(value: &str, field: &'static str) -> Result<(), ToolExposureError> {
    text(value, field)?;
    if value.len() > MAX_BUDGET_TEXT_BYTES {
        return Err(ToolExposureError::InvalidField {
            field,
            reason: "exceeds the bounded text length",
        });
    }
    Ok(())
}

fn optional_text(value: Option<&str>, field: &'static str) -> Result<(), ToolExposureError> {
    if let Some(text_value) = value {
        bounded_text(text_value, field)?;
    }
    Ok(())
}

/// Coverage of non-ELIOT tools and provider rewrites behind one budget.
///
/// The compiling seam observes only the surface it renders. Host-added
/// provider tools or provider-side rewrites that are not observable are
/// recorded as [`BudgetCoverage::Incomplete`], never claimed as complete.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "state",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum BudgetCoverage {
    /// Every tool behind the first prompt was observed by this budget.
    Complete,
    /// Tools or rewrites beyond the rendered projection were not observed.
    Incomplete {
        /// Why coverage is incomplete.
        reason: String,
    },
}

impl BudgetCoverage {
    fn validate(&self) -> Result<(), ToolExposureError> {
        if let Self::Incomplete { reason } = self {
            bounded_text(reason, "budget.non_eliot_coverage.reason")?;
        }
        Ok(())
    }
}

/// Protected context reserves recorded with their owning attestation.
///
/// Reserve figures come from the Context-budget owner. This contract records
/// them verbatim; it never derives them from rendered bytes.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProtectedReserves {
    /// Protected reasoning reserve in tokens.
    pub reasoning_reserve: u64,
    /// Protected review reserve in tokens.
    pub review_reserve: u64,
    /// Protected evidence reserve in tokens.
    pub evidence_reserve: u64,
    /// Reference to the owner attestation for these figures.
    pub owner_ref: String,
}

impl ProtectedReserves {
    fn validate(&self) -> Result<(), ToolExposureError> {
        bounded_text(&self.owner_ref, "budget.protected_reserves.owner_ref")?;
        Ok(())
    }
}

/// Measured cost of one advertised tool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PerToolCost {
    /// Exact canonical tool name.
    pub tool: String,
    /// Measured rendered description bytes.
    pub description_bytes: u64,
}

/// Overflow and quality disposition for one budget.
///
/// Overflow is not an automatic rejection, but a justified overflow needs an
/// explicit measured justification and an alternative. Protected reserves are
/// never silently consumed: this contract has no path that spends them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OverflowDisposition {
    /// Rendered cost fits the applicable bound.
    WithinBudget,
    /// Overflow with explicit measured justification and alternative.
    OverflowJustified,
    /// Overflow state could not be resolved by its owner.
    OverflowUnresolved,
}

/// Overflow record bound to one budget.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetOverflow {
    /// Overflow disposition.
    pub disposition: OverflowDisposition,
    /// Measured justification; required when justified.
    pub justification: Option<String>,
    /// Cheaper or safer alternative; required when justified.
    pub alternative: Option<String>,
}

impl BudgetOverflow {
    fn validate(&self) -> Result<(), ToolExposureError> {
        optional_text(
            self.justification.as_deref(),
            "budget.overflow.justification",
        )?;
        optional_text(self.alternative.as_deref(), "budget.overflow.alternative")?;
        if matches!(self.disposition, OverflowDisposition::OverflowJustified)
            && (self.justification.is_none() || self.alternative.is_none())
        {
            return Err(ToolExposureError::InvalidField {
                field: "budget.overflow",
                reason: "a justified overflow requires both justification and alternative",
            });
        }
        Ok(())
    }
}

/// Generated budget over the actually advertised surface (I7.24).
///
/// Every count and byte figure is measured from the final rendered
/// serialization supplied by the publishing seam, never from source
/// docstrings or schema hashes alone. Token figures require the actual
/// tokenizer and exact bytes; anything else stays
/// [`TokenCountObservation::Unavailable`].
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ToolSurfaceBudget {
    /// Wire contract revision. Must equal [`TOOL_SURFACE_CONTRACT_VERSION`].
    pub schema_version: u16,
    /// Role the surface was compiled for; `None` means explicitly unresolved.
    pub role: Option<String>,
    /// Route fingerprint; `None` means explicitly unresolved.
    pub route_fingerprint: Option<String>,
    /// Semantic-profile revision the budget was compiled against.
    pub profile_revision: String,
    /// Lowercase SHA-256 over the exact rendered surface bytes.
    pub actual_fingerprint: String,
    /// Observed host-builtin tools alongside the MCP surface.
    pub builtin_tool_count: u64,
    /// Tools rendered visibly in this projection.
    pub visible_tool_count: u64,
    /// MCP tools withheld from this projection.
    pub hidden_tool_count: u64,
    /// Total MCP tools covered by this budget.
    pub mcp_tool_count: u64,
    /// Advertised tools owned by an ELIOT semantic profile.
    pub eliot_tool_count: u64,
    /// Advertised tools without an ELIOT semantic owner.
    pub non_eliot_tool_count: u64,
    /// Coverage of non-ELIOT tools and provider rewrites.
    pub non_eliot_coverage: BudgetCoverage,
    /// Measured rendered description bytes.
    pub description_bytes: u64,
    /// Measured rendered schema bytes.
    pub schema_bytes: u64,
    /// Measured rendered example bytes.
    pub example_bytes: u64,
    /// Measured rendered permission-text bytes.
    pub permission_bytes: u64,
    /// First-prompt token observation bound to the actual fingerprint.
    pub first_prompt_tokens: TokenCountObservation,
    /// Protected reserves; `None` means explicitly unresolved.
    pub protected_reserves: Option<ProtectedReserves>,
    /// Measured per-tool description costs.
    pub per_tool_costs: Vec<PerToolCost>,
    /// First-line task shape named by the publishing seam.
    pub first_line_task_shape: String,
    /// Lazy reference handles rendered by this projection.
    pub lazy_reference_handles: Vec<String>,
    /// Overflow and quality disposition.
    pub overflow: BudgetOverflow,
    /// Owner that compiled this budget.
    pub change_owner: String,
    /// Delta identity of this rendering, derived from its fingerprint.
    pub change_delta: String,
    /// Validity scope; `None` means explicitly unresolved.
    pub validity_scope: Option<String>,
    /// Expiry reference; `None` means explicitly unresolved.
    pub expires_at: Option<String>,
}

impl ToolSurfaceBudget {
    /// Validates identities, count coherence, byte coherence, token binding,
    /// and overflow justification without measuring anything itself.
    ///
    /// An `Observed` token figure must bind the budget's own actual
    /// fingerprint: only the exact rendered bytes may be claimed as counted.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported schema version, malformed digest,
    /// blank or oversized text, incoherent counts or byte sums, a token
    /// observation that does not bind this budget's bytes, or an unjustified
    /// justified-overflow claim.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        if self.schema_version != TOOL_SURFACE_CONTRACT_VERSION {
            return Err(ToolExposureError::InvalidField {
                field: "budget.schema_version",
                reason: "unsupported tool surface contract version",
            });
        }
        optional_text(self.role.as_deref(), "budget.role")?;
        optional_text(
            self.route_fingerprint.as_deref(),
            "budget.route_fingerprint",
        )?;
        bounded_text(&self.profile_revision, "budget.profile_revision")?;
        digest(&self.actual_fingerprint, "budget.actual_fingerprint")?;
        if self.visible_tool_count + self.hidden_tool_count != self.mcp_tool_count {
            return Err(ToolExposureError::InvalidField {
                field: "budget.mcp_tool_count",
                reason: "visible and hidden tools must partition the MCP tools",
            });
        }
        if self.eliot_tool_count + self.non_eliot_tool_count != self.mcp_tool_count {
            return Err(ToolExposureError::InvalidField {
                field: "budget.mcp_tool_count",
                reason: "ELIOT and non-ELIOT tools must partition the MCP tools",
            });
        }
        self.non_eliot_coverage.validate()?;
        self.validate_token_binding()?;
        if let Some(reserves) = &self.protected_reserves {
            reserves.validate()?;
        }
        self.validate_per_tool_costs()?;
        bounded_text(&self.first_line_task_shape, "budget.first_line_task_shape")?;
        if self.lazy_reference_handles.len() > MAX_BUDGET_TOOLS {
            return Err(ToolExposureError::InvalidField {
                field: "budget.lazy_reference_handles",
                reason: "exceeds the bounded handle count",
            });
        }
        for handle in &self.lazy_reference_handles {
            bounded_text(handle, "budget.lazy_reference_handles")?;
        }
        self.overflow.validate()?;
        bounded_text(&self.change_owner, "budget.change_owner")?;
        bounded_text(&self.change_delta, "budget.change_delta")?;
        optional_text(self.validity_scope.as_deref(), "budget.validity_scope")?;
        optional_text(self.expires_at.as_deref(), "budget.expires_at")?;
        Ok(())
    }

    fn validate_token_binding(&self) -> Result<(), ToolExposureError> {
        if let TokenCountObservation::Observed {
            representation_digest,
            tokenizer_evidence_ref,
            ..
        } = &self.first_prompt_tokens
        {
            digest(
                representation_digest,
                "budget.first_prompt_tokens.representation_digest",
            )?;
            if representation_digest != &self.actual_fingerprint {
                return Err(ToolExposureError::InvalidField {
                    field: "budget.first_prompt_tokens.representation_digest",
                    reason: "token observation must bind this budget's actual bytes",
                });
            }
            bounded_text(
                tokenizer_evidence_ref,
                "budget.first_prompt_tokens.tokenizer_evidence_ref",
            )?;
        }
        Ok(())
    }

    fn validate_per_tool_costs(&self) -> Result<(), ToolExposureError> {
        if self.per_tool_costs.len() > MAX_BUDGET_TOOLS {
            return Err(ToolExposureError::InvalidField {
                field: "budget.per_tool_costs",
                reason: "exceeds the bounded tool count",
            });
        }
        let mut described: u64 = 0;
        let mut seen_names = std::collections::BTreeSet::new();
        for cost in &self.per_tool_costs {
            bounded_text(&cost.tool, "budget.per_tool_costs.tool")?;
            if !seen_names.insert(cost.tool.as_str()) {
                return Err(ToolExposureError::InvalidField {
                    field: "budget.per_tool_costs.tool",
                    reason: "must not contain duplicate tools",
                });
            }
            described = described.saturating_add(cost.description_bytes);
        }
        if described != self.description_bytes {
            return Err(ToolExposureError::InvalidField {
                field: "budget.description_bytes",
                reason: "must equal the sum of per-tool description bytes",
            });
        }
        Ok(())
    }
}

/// Measured rendering cost of one advertised tool, supplied by the
/// publishing seam from the final host serialization.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenderedToolCost {
    /// Exact canonical tool name.
    pub tool: String,
    /// Whether an ELIOT semantic profile owns this tool. Derived from the
    /// live profile owner by the publishing seam, never from the name text.
    pub is_eliot_owned: bool,
    /// Measured rendered description bytes.
    pub description_bytes: u64,
    /// Measured rendered input/output schema bytes.
    pub schema_bytes: u64,
    /// Measured rendered example bytes.
    pub example_bytes: u64,
    /// Measured rendered permission-text bytes.
    pub permission_bytes: u64,
    /// Lazy reference handle rendered for this tool, when any.
    pub lazy_handle: Option<String>,
}

impl RenderedToolCost {
    fn validate(&self) -> Result<(), ToolExposureError> {
        bounded_text(&self.tool, "budget_input.tools.tool")?;
        optional_text(
            self.lazy_handle.as_deref(),
            "budget_input.tools.lazy_handle",
        )?;
        Ok(())
    }
}

/// Owner-supplied input for one surface budget compilation.
///
/// Counts, byte sums, and the actual fingerprint are derived by
/// [`compile_surface_budget`]; every other field is recorded verbatim from
/// its observation owner and validated for shape only.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurfaceBudgetInput {
    /// Role the surface was compiled for, when known.
    pub role: Option<String>,
    /// Route fingerprint, when the route owner supplied one.
    pub route_fingerprint: Option<String>,
    /// Semantic-profile revision the surface was compiled against.
    pub profile_revision: String,
    /// Exact final rendered surface bytes covered by the fingerprint.
    pub rendered_surface_bytes: Vec<u8>,
    /// Measured per-tool costs in stable rendering order.
    pub tools: Vec<RenderedToolCost>,
    /// Observed host-builtin tools alongside the MCP surface.
    pub builtin_tool_count: u64,
    /// MCP tools withheld from this projection.
    pub hidden_tool_count: u64,
    /// Withheld tools owned by an ELIOT semantic profile.
    pub hidden_eliot_tool_count: u64,
    /// Coverage of non-ELIOT tools and provider rewrites.
    pub non_eliot_coverage: BudgetCoverage,
    /// First-prompt token observation from the tokenizer owner.
    pub first_prompt_tokens: TokenCountObservation,
    /// Protected reserves from the Context-budget owner, when joined.
    pub protected_reserves: Option<ProtectedReserves>,
    /// First-line task shape named by the publishing seam.
    pub first_line_task_shape: String,
    /// Overflow disposition from the budget owner.
    pub overflow: BudgetOverflow,
    /// Owner compiling this budget.
    pub change_owner: String,
    /// Validity scope, when the owner supplied one.
    pub validity_scope: Option<String>,
    /// Expiry reference, when the owner supplied one.
    pub expires_at: Option<String>,
}

/// Compiles a [`ToolSurfaceBudget`] from owner-measured rendering input.
///
/// The compiler counts tools, sums measured bytes, and binds the actual
/// fingerprint over the exact rendered bytes. It invents no token figures:
/// the token observation passes through untouched, so an unmeasured cost
/// stays [`TokenCountObservation::Unavailable`].
///
/// # Errors
///
/// Returns an error when any input is malformed or when the compiled budget
/// fails [`ToolSurfaceBudget::validate`].
pub fn compile_surface_budget(
    input: &SurfaceBudgetInput,
) -> Result<ToolSurfaceBudget, ToolExposureError> {
    validate_budget_input(input)?;

    let mut description_bytes: u64 = 0;
    let mut schema_bytes: u64 = 0;
    let mut example_bytes: u64 = 0;
    let mut permission_bytes: u64 = 0;
    let mut eliot_tool_count: u64 = 0;
    let mut per_tool_costs = Vec::with_capacity(input.tools.len());
    let mut lazy_reference_handles = Vec::new();
    for tool in &input.tools {
        description_bytes = description_bytes.saturating_add(tool.description_bytes);
        schema_bytes = schema_bytes.saturating_add(tool.schema_bytes);
        example_bytes = example_bytes.saturating_add(tool.example_bytes);
        permission_bytes = permission_bytes.saturating_add(tool.permission_bytes);
        if tool.is_eliot_owned {
            eliot_tool_count = eliot_tool_count.saturating_add(1);
        }
        per_tool_costs.push(PerToolCost {
            tool: tool.tool.clone(),
            description_bytes: tool.description_bytes,
        });
        if let Some(handle) = &tool.lazy_handle {
            lazy_reference_handles.push(handle.clone());
        }
    }
    let visible_tool_count =
        u64::try_from(input.tools.len()).map_err(|_| ToolExposureError::InvalidField {
            field: "budget_input.tools",
            reason: "tool count exceeds the representable range",
        })?;
    if input.hidden_eliot_tool_count > input.hidden_tool_count {
        return Err(ToolExposureError::InvalidField {
            field: "budget_input.hidden_eliot_tool_count",
            reason: "withheld ELIOT tools cannot exceed withheld tools",
        });
    }
    let mcp_tool_count = visible_tool_count.saturating_add(input.hidden_tool_count);
    eliot_tool_count = eliot_tool_count.saturating_add(input.hidden_eliot_tool_count);
    if eliot_tool_count > mcp_tool_count {
        return Err(ToolExposureError::InvalidField {
            field: "budget_input.hidden_eliot_tool_count",
            reason: "ELIOT tools cannot exceed the MCP tools",
        });
    }
    let actual_fingerprint = sha256_hex(&input.rendered_surface_bytes);
    let budget = ToolSurfaceBudget {
        schema_version: TOOL_SURFACE_CONTRACT_VERSION,
        role: input.role.clone(),
        route_fingerprint: input.route_fingerprint.clone(),
        profile_revision: input.profile_revision.clone(),
        actual_fingerprint: actual_fingerprint.clone(),
        builtin_tool_count: input.builtin_tool_count,
        visible_tool_count,
        hidden_tool_count: input.hidden_tool_count,
        mcp_tool_count,
        eliot_tool_count,
        non_eliot_tool_count: mcp_tool_count.saturating_sub(eliot_tool_count),
        non_eliot_coverage: input.non_eliot_coverage.clone(),
        description_bytes,
        schema_bytes,
        example_bytes,
        permission_bytes,
        first_prompt_tokens: input.first_prompt_tokens.clone(),
        protected_reserves: input.protected_reserves.clone(),
        per_tool_costs,
        first_line_task_shape: input.first_line_task_shape.clone(),
        lazy_reference_handles,
        overflow: input.overflow.clone(),
        change_owner: input.change_owner.clone(),
        change_delta: format!("surface-sha256:{actual_fingerprint}"),
        validity_scope: input.validity_scope.clone(),
        expires_at: input.expires_at.clone(),
    };
    budget.validate()?;
    Ok(budget)
}

fn validate_budget_input(input: &SurfaceBudgetInput) -> Result<(), ToolExposureError> {
    optional_text(input.role.as_deref(), "budget_input.role")?;
    optional_text(
        input.route_fingerprint.as_deref(),
        "budget_input.route_fingerprint",
    )?;
    bounded_text(&input.profile_revision, "budget_input.profile_revision")?;
    if input.tools.len() > MAX_BUDGET_TOOLS {
        return Err(ToolExposureError::InvalidField {
            field: "budget_input.tools",
            reason: "exceeds the bounded tool count",
        });
    }
    let mut seen_names = std::collections::BTreeSet::new();
    for tool in &input.tools {
        tool.validate()?;
        if !seen_names.insert(tool.tool.as_str()) {
            return Err(ToolExposureError::InvalidField {
                field: "budget_input.tools.tool",
                reason: "must not contain duplicate tools",
            });
        }
    }
    bounded_text(
        &input.first_line_task_shape,
        "budget_input.first_line_task_shape",
    )?;
    input.non_eliot_coverage.validate()?;
    input.overflow.validate()?;
    if let Some(reserves) = &input.protected_reserves {
        reserves.validate()?;
    }
    bounded_text(&input.change_owner, "budget_input.change_owner")?;
    optional_text(
        input.validity_scope.as_deref(),
        "budget_input.validity_scope",
    )?;
    optional_text(input.expires_at.as_deref(), "budget_input.expires_at")?;
    Ok(())
}

/// Current grant standing from the authority owner for one task/route.
///
/// Resolved by the admitting seam from its live grant owner — the Governor
/// grant-closure verdict at surface advertisement, the admitted task binding
/// at Kernel dispatch — never minted by the caller. A missing standing cannot
/// enable Material dispatch; a revoked standing withholds it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MaterialGrantStanding {
    /// Grant revision the standing authorizes.
    pub grant_revision: String,
    /// Whether the authority owner revoked the grant.
    pub revoked: bool,
}

impl MaterialGrantStanding {
    /// Validates the standing shape without consulting any owner.
    ///
    /// # Errors
    ///
    /// Returns an error when the grant revision is blank or oversized.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        bounded_text(&self.grant_revision, "grant.grant_revision")?;
        Ok(())
    }

    /// Authorizes Material use under this standing.
    ///
    /// # Errors
    ///
    /// Returns [`ToolExposureError::GrantRevoked`] when the authority owner
    /// revoked the grant, or an error when the standing is malformed.
    pub fn authorize_material_use(&self) -> Result<(), ToolExposureError> {
        self.validate()?;
        if self.revoked {
            return Err(ToolExposureError::GrantRevoked);
        }
        Ok(())
    }
}

/// Requires a live grant standing for Material dispatch.
///
/// A missing standing fails closed with
/// [`ToolExposureError::GrantRequired`]; a revoked one fails with
/// [`ToolExposureError::GrantRevoked`]. There is no silent or default grant.
pub fn authorize_material_grant(
    standing: Option<&MaterialGrantStanding>,
) -> Result<(), ToolExposureError> {
    let Some(standing) = standing else {
        return Err(ToolExposureError::GrantRequired);
    };
    standing.authorize_material_use()
}

/// Resolves the Material standing for one claimed grant revision from the
/// live grant-closure verdict.
///
/// The closure is the Governor's complete parent-before-child declaration
/// consumed by the Kernel as an immutable projection: it is the single
/// grant/revocation owner, so no second catalogue or authorization service is
/// consulted. A missing verdict, a revoked closure, or a revision the live
/// closure does not cover fails closed; only an `Active` closure covering
/// the claimed revision yields a live standing.
///
/// # Errors
///
/// Returns [`ToolExposureError::GrantRequired`] when no verdict is joined or
/// the claimed revision is not covered, [`ToolExposureError::GrantRevoked`]
/// when the live closure revoked it, or an error for a malformed revision.
pub fn resolve_material_grant(
    closure: Option<&GrantClosureReceipt>,
    grant_revision: &str,
) -> Result<MaterialGrantStanding, ToolExposureError> {
    bounded_text(grant_revision, "grant.grant_revision")?;
    let Some(closure) = closure else {
        return Err(ToolExposureError::GrantRequired);
    };
    if matches!(closure.state, GrantClosureState::Revoked) {
        return Err(ToolExposureError::GrantRevoked);
    }
    let covered = closure.declaration.target_grant_id == grant_revision
        || closure
            .declaration
            .members
            .iter()
            .any(|member| member.grant_id == grant_revision);
    if !covered {
        return Err(ToolExposureError::GrantRequired);
    }
    let standing = MaterialGrantStanding {
        grant_revision: grant_revision.to_owned(),
        revoked: false,
    };
    standing.validate()?;
    Ok(standing)
}

/// Surface, method, profile, task, and grant revisions carried into call
/// admission (I7.24).
///
/// The binding is resolved by canonical method name from the live generated
/// descriptors and the live semantic owner on every admission. Visibility is
/// never consulted: a hidden method invoked by name faces the identical
/// check, because advertisement is neither a capability grant nor a security
/// boundary. Task and grant revisions are bound only when the admitting seam
/// owns them; a seam that never mints task or grant identity binds `None`
/// rather than inventing a value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SurfaceDispatchBinding {
    /// Surface contract revision. Must equal [`TOOL_SURFACE_CONTRACT_VERSION`].
    pub surface_revision: u16,
    /// Exact canonical method name invoked.
    pub method: String,
    /// Tool Definition version agreed by descriptor and owner.
    pub definition_version: String,
    /// Semantic-profile version of the live owner.
    pub profile_version: String,
    /// Task identity/revision from the admitting owner, when task-bound.
    pub task_ref: Option<String>,
    /// Grant revision from the authority owner, when supplied.
    pub grant_revision: Option<String>,
}

impl SurfaceDispatchBinding {
    /// Validates revision shape and contract agreement.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported surface revision, blank identity
    /// or version text, or blank task/grant references.
    pub fn validate(&self) -> Result<(), ToolExposureError> {
        if self.surface_revision != TOOL_SURFACE_CONTRACT_VERSION {
            return Err(ToolExposureError::InvalidField {
                field: "binding.surface_revision",
                reason: "unsupported tool surface contract version",
            });
        }
        bounded_text(&self.method, "binding.method")?;
        bounded_text(&self.definition_version, "binding.definition_version")?;
        bounded_text(&self.profile_version, "binding.profile_version")?;
        optional_text(self.task_ref.as_deref(), "binding.task_ref")?;
        optional_text(self.grant_revision.as_deref(), "binding.grant_revision")?;
        Ok(())
    }
}

/// Admits one dispatch surface binding from live owner facts.
///
/// The caller resolves the generated descriptor and the semantic owner
/// afresh for the invoked method name; this gate requires the two to agree
/// on the Tool Definition version, binds the live profile version plus any
/// owned task/grant revisions, and validates the result. There is no
/// visibility input: hidden and visible methods admit identically.
///
/// # Errors
///
/// Returns an error when the descriptor and owner disagree on the definition
/// version or when the bound revisions are malformed.
pub fn admit_dispatch_surface(
    method: &str,
    descriptor_definition_version: &str,
    owner_definition_version: &str,
    owner_profile_version: &str,
    task_ref: Option<&str>,
    grant_revision: Option<&str>,
) -> Result<SurfaceDispatchBinding, ToolExposureError> {
    if descriptor_definition_version != owner_definition_version {
        return Err(ToolExposureError::InvalidField {
            field: "binding.definition_version",
            reason: "generated descriptor and semantic owner disagree",
        });
    }
    let binding = SurfaceDispatchBinding {
        surface_revision: TOOL_SURFACE_CONTRACT_VERSION,
        method: method.to_owned(),
        definition_version: owner_definition_version.to_owned(),
        profile_version: owner_profile_version.to_owned(),
        task_ref: task_ref.map(str::to_owned),
        grant_revision: grant_revision.map(str::to_owned),
    };
    binding.validate()?;
    Ok(binding)
}

/// Replay disposition for two recorded surface budgets on one compilation
/// scope.
///
/// Returned by [`detect_budget_replay`]: evidence for the publishing seam to
/// reconcile, never permission to execute — `tools/list` publication executes
/// nothing, so an [`BudgetReplaySignal::IdempotentReplay`] retains the prior
/// revision, while a [`BudgetReplaySignal::SuccessorRevision`] persists
/// alongside it through the existing observation/receipt path. The recorded
/// original is never rewritten.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BudgetReplaySignal {
    /// Identical recorded fingerprint with identical recorded evidence: a
    /// replayed publication, not new work.
    IdempotentReplay,
    /// Different recorded bytes on the same recorded compilation scope: a new
    /// revision that persists alongside the retained prior.
    SuccessorRevision,
}

/// Classifies a repeated surface publication against the recorded prior budget.
///
/// Both budgets validate as recorded first:
/// [`ToolSurfaceBudget::validate`] checks the original recorded digest values
/// and never recomputes them. The recorded actual fingerprints then decide,
/// compared with this operation: identical fingerprints with identical
/// recorded bytes and counts are an idempotent publication replay; identical
/// fingerprints with divergent recorded evidence are a typed conflict, so a
/// replay can never validate as a quiet rewrite. Different fingerprints on
/// the same recorded compilation scope (role, route, profile revision) are a
/// successor revision, never an overwrite. Different scopes return `Ok(None)`:
/// not a replay pair, routed to their owners.
///
/// # Errors
///
/// Returns an error when either budget is inconsistent, or when one recorded
/// fingerprint carries conflicting recorded evidence.
pub fn detect_budget_replay(
    previous: &ToolSurfaceBudget,
    current: &ToolSurfaceBudget,
) -> Result<Option<BudgetReplaySignal>, ToolExposureError> {
    previous.validate()?;
    current.validate()?;
    if previous.actual_fingerprint == current.actual_fingerprint {
        if previous == current {
            return Ok(Some(BudgetReplaySignal::IdempotentReplay));
        }
        return Err(ToolExposureError::InvalidField {
            field: "budget.actual_fingerprint",
            reason: "replayed surface fingerprint carries conflicting recorded evidence; persist a successor revision instead of rewriting",
        });
    }
    if previous.role == current.role
        && previous.route_fingerprint == current.route_fingerprint
        && previous.profile_revision == current.profile_revision
    {
        return Ok(Some(BudgetReplaySignal::SuccessorRevision));
    }
    Ok(None)
}
