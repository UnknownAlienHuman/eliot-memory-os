## I7.24. Tool surface economy and cognitive exposure

Tool descriptions, schemas, defaults, examples and permission text are versioned cognitive inputs. They consume context, shape the model's action ontology and may carry injection or stale-capability risk. The bridge therefore compiles a task-relative surface instead of exposing the whole catalog.

`ToolSurfaceDecision` records:

```text
task/role/route/Governance Profile and State Fence;
considered Tool Definitions and capability evidence;
always-visible, lazy-visible, hidden and forbidden sets;
schema/context cost and expected decision/proof delta;
side effects, authority and privacy boundary;
cheaper or safer alternative;
selection/suppression reason, expansion path and invalidation dependencies.
```


Tool schema is not enough to govern behavior. Every introduced tool version is joined to one ELIOT-owned semantic profile:

```yaml
ToolSemanticProfile:
  tool_definition_and_version:
  operation_class: OBSERVE | NAVIGATE | PROPOSE | MUTATE | VERIFY | PROGRESS | COMPLETE_CANDIDATE
  effect_class:
  authority_and_introduction_requirements:
  idempotency_class:
  reversibility_or_compensation_class:
  expected_result_semantics:
  repetition_polling_pagination_and_terminal_semantics:
  evidence_and_completion_ceiling:
  timeout_resource_and_privacy_profile:
  compatibility_and_invalidation_set:
```

`ToolSemanticProfile` is the method-level operational projection of the owning `Tool Definition` and, where the tool is introduced as a resource facet, of the owning `FacetManifest`. It is not a second tool catalogue or authority source. One versioned method identity has one operational semantics owner; generated MCP/WIT/EBP views must agree with it.

Tool names, descriptions and shell substrings never define these semantics. A router or Stage classifier may consume `ToolSemanticProfile`; it may not infer “test passed”, “task complete”, “safe to retry” or “read-only” from a vendor tool name. A missing profile limits the tool to the narrowest observable capability or removes it from the Material surface.

Rules:

```text
the eight logical ELIOT operations remain the stable hot surface;
provider/native tools are exposed only for the current task and role;
large schemas are handles-first and loaded lazily;
README/handshake claims do not make a tool available without capability evidence;
Tool Definition changes invalidate dependent Skills, profiles, packets and competence evidence;
repeated calls without new evidence, state transition or effect create a tool-loop signal;
tool-count reduction is not a goal if it removes a load-bearing capability;
an unavailable or forbidden capability is absent from the advertised surface, not merely discouraged in prose;
no model-authored tool choice creates authority to execute the tool.
```


`ToolSurfaceBudget` is a generated CI/profile contract over the **actually advertised** surface:

```yaml
ToolSurfaceBudget:
  role_route_profile_and_actual_fingerprint:
  builtin_visible_hidden_and_MCP_tool_counts:
  ELIOT_and_non_ELIOT_tool_counts:
  schema_description_example_and_permission_tokens:
  first_prompt_total_tokens_by_actual_tokenizer:
  protected_reasoning_review_and_evidence_reserve:
  per_tool_description_tokens:
  first_line_task_shape:
  lazy_reference_handles:
  overflow_and_quality_disposition:
  change_delta_and_owner:
  validity_scope_and_expiry:
```

A new capability requires budget-delta review. Reference detail moves to lazy resources; the first line names the task shape. Budget overflow is not an automatic rejection if the capability is load-bearing, but it requires a measured context/decision justification and an explicit alternative. Source-file docstring size is not the metric; the rendered schema delivered to the route is.

For ordinary exact operations the decision may be compiled mechanically and need not create a separate user-visible ceremony. A material expansion of the tool surface, a new effect class or a high-cost route is receipted.

Expensive, model-backed, swarm, network, broad-search or effect-capable calls carry a lightweight `ToolCallIntent` naming the expected evidence/decision/artifact/proof delta, why a cheaper cached/exact route is insufficient, budget/stop/retry conditions and operation identity when durable work/effects are possible. Cheap exact reads are exempt. Repeating materially the same call on the same inputs without a new expected delta produces a loop/no-progress signal, not progress.

Tool-result delivery is measured separately from transport completion. A result receipt carries exact digest, admissible source handle, rendered bytes/tokens under the actual tokenizer and `FULL | PARTIAL | TRUNCATED | MISSING`. Large evidence is handle-first; a completed tool call with a truncated result cannot satisfy a complete-evidence or verifier requirement.


Tool availability and tool use are orthogonal observations. Each evaluated turn/run stores a `ToolExposureReceipt`:

```yaml
ToolExposureReceipt:
  tool_definition_and_route_fingerprint:
  registered:
  advertised_to_route:
  eligible_under_scope_policy_and_grant:
  selected_by_planner_or_model:
  called:
  transport_completed:
  result_delivery: FULL | PARTIAL | TRUNCATED | MISSING
  result_digest_and_exact_token_cost:
  expanded_or_retried:
  observably_used_in_decision_action_or_verifier:
  terminal_task_or_product_outcome_ref:
```

The fields are not one success ladder: an advertised tool may never be eligible; a completed call may deliver a truncated result; a delivered result may be ignored; a gold tool appearing in the surface is not a correct-tool decision. Surface and result experiments therefore report advertisement cost, selection, execution, delivery and downstream use separately.

