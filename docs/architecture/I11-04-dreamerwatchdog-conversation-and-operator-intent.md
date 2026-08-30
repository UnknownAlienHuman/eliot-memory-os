## I11.4. Dreamer/Watchdog conversation and operator intent

The native UI exposes a persistent Dreamer chat and a narrower “Ask Watchdog” diagnostic surface. Both are typed job/operator-intent interfaces:

```text
user question or requested action;
resolved WorkScope/task and onboarding state;
source/evidence handles;
proposed agents/tools/maintenance/configuration delta;
route, cumulative context and budget;
risk, approvals, effects and rollback;
result status: candidate/advisory/verified portion;
follow-up, edit, confirm, pause, cancel or escalate actions.
```

Examples:

```text
“Explain what ELIOT knows about this project.”
“Clean up this scope’s memory and show what would change.”
“Start Codex on task X and use Claude for a blind audit.”
“Run maintenance now, but do not call paid external models.”
“Switch the default Dreamer route to a local model.”
“Install or update the admitted SurrealDB generation.”
“Pilot Codebase Memory MCP for this repository.”
```

Natural language creates an `OperatorIntentCandidate` and visible plan. Direct read-only questions may execute immediately inside authority. Effects, software/configuration changes and agent launches follow their owners and approval policy. This is not direct chat with database, package manager, shell or daemon internals.

The durable conversation surface is a privacy-scoped `SessionEpisode` plus Dreamer job/request/result records. Provider-bound `RouteContinuationState` is stored separately and never becomes the chat’s authority or knowledge. After UI or route restart, the conversation is reconstructed from public messages, exact source/result handles and terminal job state; hidden reasoning, stale continuation or a cached UI transcript cannot authorize or prove an action.

