---
name: eliot-governor
description: Use ELIOT Governor automatically for project continuity, memory recall and handoff, current-state checks, bounded second opinions, risk reviews, and verifier suggestions. Activate at the start and end of every nontrivial project task, especially when the user says continue, remember, resume, status, audit, or review.
---

# ELIOT Governor Memory Workflow

Use Eliot without waiting for the user to name it or a specific tool.

1. Use the `eliot-governor` MCP server proactively. Antigravity connects through `--host antigravity`; the host identity grants no task role.
2. Choose one stable project key, normally the lower-case repository name such as `eliot-governor`, and reuse it for the whole project. If the user names a repository or project, that exact normalized name wins over the active Antigravity project, playground name, or current directory.
3. Call `eliot_project_identity` directly from its live MCP definition. The same stable key is accepted in every `project_id` field; do not hunt for a UUID or read generated MCP JSON schema files.
4. Before local exploration, call `eliot_recall_l0` with the task subject. Fetch relevant handles with `eliot_fetch_l2`; use `eliot_current_state` when epistemic status matters.
5. Treat recalled memory as routed evidence, never as current repository truth. Cite recovered handles and state freshness or uncertainty.
6. A recall-only or status-only task needs no handoff write. Never copy an existing recalled claim into a new candidate. Before ending material work, call `eliot_agent_candidate_submit` only for a novel reusable finding, decision, failure, or handoff state created by the current task.
7. Submit once with `project_id`, one valid retry-stable UUID `write_id`, `topic`, `statement`, all three arrays `where_applicable`, `where_not_applicable`, `negative_constraints` (use `[]` when empty), non-empty `provenance_refs`, and `freshness_rule`. Retry at most once after correcting the exact validation error, without changing `write_id`.
8. Do not submit noise, conversational filler, secrets, duplicate claims, or unverified completion claims.
9. For ordinary recall, do not call CodeCortex, Antigravity connector reports, live smoke, or generated report/output files. Use those only when the task explicitly requires that subsystem.
10. Call `eliot_host_session_status` before role-sensitive work. Only its active `TaskRoleLease` entries are current role evidence; never infer your role from the Antigravity host name, visibility/provider reports, old invocation receipts, or memory history. You may act as Controller, Implementer, Reviewer, Auditor, or Verifier only when Governor grants that role for the current task. A `ControllerLease` coordinates that task; it does not grant admin, truth-promotion, patch, credential, provider-control, or completion authority.
11. Never invoke Antigravity or `agy` recursively through Eliot. Repository or service mutation requires the matching current work/action lease and must remain inside its scope. Never inspect credentials or bypass a denied Governor gate.
12. Never claim `DONE_VERIFIED`; only Governor reconciliation plus current verifier evidence can close work. Every model result and memory write remains candidate-only until disposition.

Do not inspect `~/.gemini/antigravity/mcp`, `.eliot-governor`, generated schema/report/output files, or database files to discover memory identity when the MCP server is available. A missing project UUID is not a blocker: use the stable project key.

candidate_only; requires Governor reconciliation and verifier evidence before activation
