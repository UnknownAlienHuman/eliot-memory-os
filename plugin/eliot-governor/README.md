# ELIOT Governor for Codex

This native Codex package contributes one ELIOT MCP server, four on-demand
skills, and secondary lifecycle hooks. The Governor remains the authority
boundary; hooks do not manufacture model reasoning, candidates, influence
claims, or completion.

## ELIOT memory (read once)

Context arrives by itself: `ul_boot` on your first call, `ul_fired` on
responses, hook injections. Trust it. Never re-fetch what was injected; expand
handles only when your next action depends on them.

Work loop for material changes:

1. `eliot_compile_packet_l3 {goal}` -> read packet; edit `frame_stub` (intent,
   expected_observable, next step) and include it.
2. Do the change. On any error/test failure: check `ul_fired` for a matching
   episode before debugging from scratch.
3. Verify with the packet's `verifier`.
4. Save non-obvious lessons: `eliot_agent_candidate_submit {statement, kind,
   expected_reuse_note}` — bindings are automatic.
5. Ack memory you used: `eliot_memory_influence_trace {memory_handle,
   influence_class}` (+ `downstream_outcome_ref` if it changed your action).

Cost rules: omit optional fields; unsure about a form -> same call with
`dry_run:true`; on a validation error copy `minimal_valid_example`, fix the
listed fields, retry once; never invent `NO_USEFUL_MEMORY` — echo the server's
`memory_confidence`.
