## I11.11. Project launcher, environment manager and ordinary-user workflow

The Human does not need to open a terminal or understand agent runtimes. The native UI presents:

```text
Projects
  discovered and registered WorkScopes, similar-repository conflicts, cold-start readiness;

Agents
  installed runtime families, exact current capability/health, routes, quotas and preview status;

Start work
  goal/task, project, assurance/cost/privacy preset, selected or automatic agent plan;

Maintenance
  backup, curation, reindex, route/tool requalification, updates and repair;

Settings
  direct forms and Dreamer-assisted natural-language changes with impact/rollback preview;

Research
  local Dreamer query and optional ELIOT Research federation jobs.
```

The UI can start Codex, Claude Code, OpenCode, Gemini CLI, ACP agents, local-model workers or later admitted routes through `AgentLaunchRequest`; it can also attach to work initiated by an external agent and bind its Session/WorkScope/task after verification. `Start work` first exposes the `WorkScopeCandidateSet`, ScopeBindingGuard and `OnboardingReadinessReceipt`; it cannot hide an ambiguous clone, missing task or conflicting governing document behind an automatic agent launch. It never assumes the newest executable is healthy merely because it was discovered.

Attaching an already-running external agent does not retroactively make its earlier activity observed or authorized. ELIOT creates an `ExternalAttachReconciliationReceipt`:

```yaml
ExternalAttachReconciliationReceipt:
  external_process_session_route_and_actual_identity:
  attach_time_and_pre_attach_blind_interval:
  observed_workspace_instance_scope_and_task_candidates:
  last_known_base_and_current_workspace_artifact_delta:
  imported_transcript_event_and_tool_coverage:
  known_unknown_or_unattributed_external_effects:
  scope_authority_privacy_and_credential_disposition:
  required_verification_cleanup_or_human_decision:
  continuation_kind_and_new_attempt_identity:
```

Pre-attach changes are candidate artifacts/observations and cannot become proof, task completion or agent-attributed experience until reconciled. If exact process/session or workspace ownership cannot be established, the route attaches read-only or as a new bounded attempt with an explicit blind interval. Any request to continue Material work before that disposition returns `EXTERNAL_ATTACH_RECONCILIATION_REQUIRED`.

A first-run “recommended integrations” page is generated from the discovery catalogue and current evidence. It may offer installation/registration plans for supported tools, SurrealDB or a code-intelligence pilot, but nothing is installed, updated or granted credentials without the applicable Human policy and visible transaction.

