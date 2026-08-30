## A10.1. Agent Interaction Loop

This is a logical control loop, not a synchronous checklist. The Harness performs routine capture, state synchronization, and admission automatically; the agent is interrupted only at a boundary of material uncertainty, conflict, missing authority or verifier, or failure.

```text
1. Attach the session and WorkScope.
2. Restore task, commitments, and Active View.
3. Select an inquiry or action.
4. Record the expected observable for a Material causal decision.
5. Obtain applicable authority.
6. Execute the action through the Harness.
7. Record observations and effects.
8. Run the verifier or preserve the unknown.
9. Update task, memory, and Theory Portfolio.
10. End in one honest finish state.
```

On a host with hooks, this loop is reactive. On a tool-only host, ELIOT uses available boundaries, obligations, and finish discipline without pretending to have full control. A model, tool, or swarm call is justified when it is expected to produce new evidence, change a decision, create an artifact, or provide proof; otherwise it is unnecessary load. A rejected write or action attempt does not disappear silently: the response states the reason, what was preserved, whether retry is possible, which repair, probe, or authority is required, and what action is allowed next.

