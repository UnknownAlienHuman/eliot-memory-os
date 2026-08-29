# Agent runtime route profiles

These profiles keep four different concerns separate:

1. **Host surface** — plugin, hooks, Skills, MCP registration, and host instruction files.
2. **Executable route** — the exact CLI, local server, or SDK sidecar that performs one bounded attempt.
3. **ELIOT control** — task, authority, budget, durable attempt state, cancellation, evidence, and finish.
4. **Provider-native state** — useful for native resume/fork, but never canonical task state or authority.

Installing a plugin does not prove that an executable route is ready. A documented CLI flag or handshake does not prove current-account capability. Every production route still requires an exact runtime/adapter fingerprint, active probes, event coverage, cancellation reconciliation, and an `ActualRouteReceipt`.

## Current route map

| Host | Candidate route | Passive host surface | Current profile status |
|---|---|---|---|
| Codex | App Server over stdio JSONL | plugin, hooks, MCP, Skills | target |
| OpenCode | local HTTP/OpenAPI + SSE server | sequential plugin hooks, MCP, Skills | target; plugin dispatch hardened |
| Claude | local Agent SDK sidecar | Claude Code plugin/hooks/MCP/Skills | target |
| Antigravity | persistent headless NDJSON stream; Python SDK alternative | plugin/hooks/MCP/Skills | target; conservative read-only fallback retained |

No profile is production-admitted merely because this table exists.

## Model selection

Models are discovered from the active host/runtime and selected per attempt. Profiles therefore record a discovery method and selection surface but deliberately keep `fixed_model_id` null. Provider, model, auth, billing, serializer, tool surface, and behavior-affecting options belong to the route fingerprint and attempt receipt.

## Skills, MCP, and tool economy

The canonical Skill bodies remain in `integrations/agent-skills`. Hosts receive only the Skill index by default, load a body on activation, and load references/scripts/assets only when used. MCP exposes the stable ELIOT semantic operations, never raw canonical storage. Provider-native tools remain task- and role-relative; installing a host must not advertise every available tool to every worker.

## Swarm and agent meetings

A runtime may execute a worker, but it does not own the swarm. ELIOT creates bounded `AgentAttempt`s, issues minimum decision-sufficient packets, and exchanges messages through a durable mailbox. A meeting is a Concilium over sealed observations, rival models, objections, and discriminative tests. Whole sibling transcripts and free-form group chat are not the control plane. The Task Controller or Human decides; worker and synthesis outputs remain candidates.

## Verification

Install the pinned schema-validator dependency before running the verifier outside CI:

```text
python -m pip install --disable-pip-version-check --no-input -r scripts/requirements-verification.txt
```

Then run:

```text
python scripts/verify-agent-route-bundles.py --self-test
python scripts/verify-agent-route-bundles.py
```

A missing Draft 2020-12 validator is a hard verifier failure; profiles are never accepted by falling back to partial manual checks. The verifier proves profile shape and selected static safety properties. It does not prove a current account, provider route, hook delivery, sidecar implementation, or end-to-end swarm outcome.
