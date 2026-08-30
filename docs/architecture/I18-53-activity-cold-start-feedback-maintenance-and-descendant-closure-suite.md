## I18.53. Activity, cold-start, feedback, maintenance and descendant closure suite

The following focused scenarios are mandatory before the corresponding capability can be reported supported:

```text
ACT-1  no Sessions/jobs/effects/policy → RuntimeLease and SupervisionLease expire → Watchdog/Host stop cleanly;
ACT-2  first UI/MCP/agent use from STOPPED → one coalesced activation → Kernel and independent Watchdog ready before admitted Material work;
ACT-3  wake during pre-commit drain cancels drain; wake after DrainCommit creates a new fenced generation;
ACT-4  suspend/hibernate/logoff/resume cannot reuse stale PID, pipe, epoch, UserBroker or lease and records the coverage gap;
ACT-5  registered but dormant WorkScope/repository does not keep Watchdog alive;
ACT-6  files/config changed while ELIOT was fully stopped are detected on next activation, stale dependent state and remain actor/intent-unknown;

COLD-1 two same-name clones with shared remote but different workspace identity remain separate candidates and memories;
COLD-2 copied marker or partial Git metadata cannot authenticate a WorkScope;
COLD-3 two simultaneous attaches single-flight through one OnboardingLease and cannot create duplicate current tasks/scopes;
COLD-4 empty corpus plus missing governing documents yields explicit readiness gaps and safe bounded work, not invented project knowledge;
COLD-5 governing-source change invalidates the old receipt before Material effects;

OBS-1  every claimed event class has a predeclared denominator/coverage profile;
OBS-2  absent event under incomplete coverage remains UNKNOWN;
OBS-3  journal admission does not recursively generate ordinary self-events;
OBS-4  protected journal failure blocks only the exact Hard-Boundary transition; ordinary Meta-import failure degrades observability only;

FDBK-1 wrong-scope feedback is accepted in self-scope and triggers ScopeBindingGuard rather than rejection by the wrong scope;
FDBK-2 route without feedback support is UNKNOWN, not satisfied;
FDBK-3 feedback receives a visible disposition and can repair the current packet without rewriting global policy;
FDBK-4 repeated supported feedback opens one deduplicated Problem/ImprovementCandidate;

CHILD-1 every visible child is registered before launch and appears in DescendantClosureReceipt;
CHILD-2 cancellation/restart cannot orphan process/session/effect descendants;
CHILD-3 opaque native subagents are treated as one parent attempt and never receive false child-level control/independence credit;

MAINT-1 release of the last active obligation deterministically runs EndOfActivityMaintenanceAssessment;
MAINT-2 assessment with no admitted work does not keep ELIOT alive;
MAINT-3 user-session-required maintenance defers/suggests instead of retaining desktop credentials or faking execution;
MAINT-4 Dreamer/maintenance outcome changes the system only through candidate → owner decision → verifier → rollback/retain loop;

RSH-1 unavailable/stale ELIOT Research returns explicit coverage gap and cannot silently substitute an old summary;
RSH-2 Research exchange preserves disclosure lineage and requires governed import before local influence.
```

Each scenario records exact Product/Activation/WorkScope identities, relevant rule and contract revisions, deterministic events, fault points, expected disposition, real evidence and proof ceiling. A document-only fixture does not satisfy a Windows/process/provider scenario.

