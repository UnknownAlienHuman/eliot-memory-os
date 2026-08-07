You are the senior architecture/debugging reviewer for ELIOT Memory OS. Give one decisive,
bounded diagnosis and minimal repair plan. Do not write code, do not ask questions, and do not
suggest another unchanged retry.

Repository:
`C:\Users\kleym\OneDrive\Documents\Rust\projects\eliot-memory-os`

Branch: `codex/cognitive-completion-v2`

Current source base commit: `29acb8646d5500ffc0618fa953a33067e00725dc`, with uncommitted
P009 and OpenCode parser/prompt repairs.

## Goal context

HOST-CLI-01 must prove a production headless OpenCode smoke before run006 may resume. The user
explicitly requires the free OpenCode model `opencode/mimo-v2.5-free`, not GPT. Claude and
Antigravity production smokes already pass canonical HostBroker closeout. We must remain
fail-closed, avoid provider redispatch, and keep model calls bounded.

## First free MiMo smoke

- Smoke: `external-agent-smoke-opencode-019fb5e1-d2f0-78c3-bc9a-ea42d691abf0`.
- Provider session: `ses_04a1de748ffeJrQy5tFDgKNVE5`; provider `16.084 s`; cost `0`.
- MiMo first called `eliot_current_state` with invented project/task IDs, received
  `PROJECT_SCOPE_MISMATCH`, then self-corrected and called with only
  `scope=memory_free_control`.
- It returned the exact bound project/task/revision and correct result, but enclosed the JSON in
  one bare `json` Markdown fence.
- Parser reported zero structured outputs.
- Bounded repair now accepts only direct JSON or exactly one bare `json` fence with no
  surrounding prose; prompt now mandates the sole argument
  `{"scope":"memory_free_control"}` and no project/task IDs.
- Three parser tests pass.

## Daemon recovery

- Old PID `158740` left instance-default `daemon.lock`, `daemon.pid`, publication and
  `stop.requested`.
- Global `startup-recovery scan` was clean because it targets global runtime, not instance
  runtime.
- Governed host-launch instance recovery correctly double-checked PID liveness and unchanged
  lock/PID snapshots, removed only the stale pair and started new daemon PID `151892`.
- New runtime ID: `019fb5f1-b409-75f2-97ae-9e094b6fda61`; publication ready;
  `stop_requested=false`; authenticated IPC doctor ready.
- Release SHA-256:
  `6443043901b9ee88f4196496dd7515851e23d67e0701a1dcd890fb61c852e98f`.

## Second post-repair smoke

- Smoke root: `external-agent-smoke-opencode-019fb5f1-b0dc-7822-8e69-2c609b11cabe`.
- Outer process survived beyond the `180 s` shell bound.
- Only the empty workspace directory existed.
- No provider attempt journal, spool, provider config or `opencode-cli.exe` process appeared.
- Therefore zero provider/model calls were dispatched.
- Controller PID `55240` remained alive after the outer shell timeout and was explicitly
  terminated.
- No child/provider orphan remained; daemon PID `151892` stayed healthy.

## Relevant code

1. `crates/eliot-app/src/host_runtime/external_agent.rs`, `run_mcp_smoke`:
   - creates `smoke_root/workspace`;
   - `mcp_reference_exchange(profile=codex_controller, tool=eliot_project_identity)`;
   - `mcp_reference_exchange(profile=codex_controller, tool=eliot_task_contract_create)`;
   - `prepare_ul_auditor_scope(...)`;
   - `mcp_reference_exchange(profile=default, host=OpenCode, scope,
     tool=eliot_current_state)`;
   - only after those does it build the schema/prompt, launch contract and provider
     execution/journal.
2. `mcp_reference_exchange`:
   - spawns current executable as
     `mcp stdio [--host] [--profile] --instance default`;
   - writes initialize, tools/list, optional tools/call and notifications/initialized;
   - closes stdin;
   - only `child.wait_with_output` is wrapped in `tokio::time::timeout(20 s)`;
   - spawn, stdin writes/shutdown, response parsing and callers around it have no enclosing phase
     deadline or durable phase receipt.
3. Governed host launch itself calls
   `runtime_bootstrap::ensure_default_daemon_ready` before provider process dispatch, but this
   second smoke never reached provider dispatch.
4. No durable stage marker exists between workspace creation and provider journal creation, so
   current evidence cannot tell whether identity, task creation, scope preparation or
   current-state preflight hung.
5. The CLI outer shell timeout killed its shell parent but not the Rust smoke controller. That
   controller had no whole-smoke cancellation/cleanup guard at this pre-provider stage.

## Constraints

- Do not recommend an unchanged third smoke.
- Do not spend another model call until zero-model phases are isolated and bounded.
- Preserve canonical task/role/session writes and HostBroker authority.
- Do not bypass MCP, fabricate receipts, widen authority or weaken exact tool/schema checks.
- Prove no orphan controller/process after timeout.
- Prefer the smallest source repair and focused zero-model tests.

## Deliver

A. Most likely causal chain, clearly separating known facts from inference.

B. The smallest repair design with exact function boundaries and ordering.

C. Focused tests, including how to simulate a stuck phase without a real provider/model.

D. Evidence that must pass before exactly one free MiMo retry is permitted.

E. Any important hazard in the current P009/OpenCode uncommitted change interaction.
