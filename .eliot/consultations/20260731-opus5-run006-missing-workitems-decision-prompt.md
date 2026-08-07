You are reviewing one narrow recovery decision for ELIOT RUNTIME-SUPERVISION-01.
Do not audit the whole patch. Do not use tools. Return a compact engineering decision with:
1) safe interpretation,
2) required code/record changes,
3) whether APPLY may proceed,
4) the exact postconditions/tests needed.

Contract intent:
- current run cq-core-20260730-006 is a failed pre-provider transactional seal;
- expected incident inventory says 4 execution requests, 4 provider runtimes, 4 AgentSessions,
  4 TaskRoleLeases, 4 WorkItems, no provider dispatch evidence;
- recover-seal dry-run must inventory exact partial state;
- apply must revoke leases, retire sessions, abandon matching jobs/work items, quarantine the
  eight immutable files, write a typed AbandonedSealAttemptRecord, and prove no active authority;
- never invent a fake cross-file atomic claim.

Verified current truth:
- the four exact execution request files exist and bind four distinct call IDs, sessions,
  leases, invocation IDs, and WorkItem IDs;
- the four exact provider runtime files exist;
- current HostBroker state contains exactly those four sessions and four leases;
- those legacy rows have no state/generation/seal_attempt_id fields on disk (new loader defaults
  them to legacy Active/generation 0);
- current WorkState has 19 WorkItems but none of the four request-bound WorkItem IDs;
- WorkState state.json mtime is 2026-07-21, before run006;
- current HostBroker has no OperationJob matching any of the four invocation IDs;
- recursive search of Eliot reports/control finds none of the four WorkItem IDs outside the
  private run request files;
- provider-plan is absent; provider reservations/results/raw outputs/artifacts are absent.

Current implementation blocks APPLY because its exact_partial_shape requires four matching
WorkItems. Proposed correction:
- make recovery inventory distinguish `referenced_work_item_ids` from
  `present_work_item_ids` and similarly for jobs;
- classify the exact legacy partial shape as safe if present WorkItems/Jobs count is either 0 or
  exact expected 4, but reject any unexpected/foreign match;
- APPLY revokes/retires/abandons only records that are actually present;
- typed abandonment record lists request-referenced IDs separately from records actually found
  and records actually transitioned, explicitly recording missing legacy authority projections;
- postcondition requires all four leases revoked, sessions retired, and no active matching
  WorkItem/OperationJob (absence satisfies this), plus eight hashed files quarantined.

Question: Is that safe and faithful, or must recovery remain blocked? Identify any stronger
minimal safeguard. No provider calls are allowed.
