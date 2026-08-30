## I8.4. Interaction heartbeat

For active Material work Watchdog expects observable progress envelope:

```text
session attach;
WorkScope/task sync;
packet/action boundary;
material tool/action observation;
verification or explicit unknown;
checkpoint/finish.
```

Rules are contextual, not a fixed “write every N seconds” dogma.

Examples:

```text
workspace changes while no PostTool/observe events arrive
  → integration gap signal;

observed cwd/worktree/root differs from the bound WorkspaceInstance
  → WatchdogSignal `scope_drift`; freeze dependent context/effects and request rebind;

many material tool calls without packet/state refresh after invalidation
  → stale-context warning or require refresh;

same failed action signature repeated without new evidence
  → repeated-failure attention;

native/external child appears without an admitted AgentAttempt or parent lineage
  → orphan-descendant signal and no proof/effect admission;

child context, token, tool or descendant usage approaches/exceeds its envelope
  → narrow/cancel/escalate the subtree; unrelated attempts continue;

active agent and changing files, but no ELIOT observations for configured window
  → ask agent for resync; persistent gap lowers Governance Profile;

agent idle with no external change
  → no violation.
```

Cadence defaults are Empirical Profiles per harness/task family.

