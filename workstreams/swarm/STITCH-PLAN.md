# Integration seams and PR dispositions

Use only the row applicable to the selected assignment. This is coordination evidence,
not product authority. Canonical sections are linked from PLAN.md. Source observations
below bind main b7e9e334569639a6290baeacf82bf44941def506; refresh changed inputs before
dispatch. No entry proves that an external writer has stopped.

## Current selected work

| Issue | Existing owner-to-consumer path | Shared-file rule |
|---|---|---|
| #3980 | SurrealServerConfig validator -> GovernorConfig loader / supervisor admission / RPC connect, before effects. | Four legacy files only; preserve reserved Store isolation. No modern Store or legacy-retirement dependency. |
| #2691 | S-03 lifetime -> narrow adapter method -> existing bounded snapshot expiry/retirement -> diagnostics. | Five PLAN files; preserve #2688/#2689 state and receipts. PR disposition below. |
| #2643 | Fresh get_context nonce -> current identity guard -> actual client -> owner fence -> business request. | Two DTO/client files; #2644/#1137 cannot write them concurrently. MainViewModel/journal/Rust stay read-only. |
| #2701 | #929 check(Path) -> strict result validation -> CheckedInventory -> closure report. | Two scripts; root alone refreshes the global inventory on combined source. No second scanner. |

The four selected sets are mutually disjoint. The prior complete PR filename screen
contains no contact with #3980's four files, #2643's two files or #2701's two scripts.
That screen is an input observation, not a current runner claim or a semantic review
of every PR. Refresh new/changed heads and the actual controller claims.

## #2691: exact-file reconciliation, not whole-PR waiting

The former two-subtree reservation is replaced by the five files in PLAN.tsv.
#3811/#3812 change apply/*, not those five files. They are not snapshot prerequisites.

#3869 at bce9207b52a29cfa0b2439d69c4235a49fe27fd4 contacts three selected files.
Each complete per-file patch was compared with the main source above:

| Shared bin file | Relevant #3869 hunks already present in main |
|---|---|
| bins/eliot-store-surreal/src/lib.rs | install_compatibility_decision re-export. |
| bins/eliot-store-surreal/src/main.rs | Imports, three compatibility input constants, typed health projection, installation/path helpers and the early run branch. |
| bins/eliot-store-surreal/src/diagnostics.rs | CompatibilityVerdict import, CompatibilityDecision/CompatibilityHealth and project_compatibility_health. |

**Disposition: PRESERVE_MAIN for those hunks only.** No merge of #3869 is needed
before writing snapshot maintenance. PLAN retains [3869] as the observed file contact,
with CLAIM_AFTER_PREFLIGHT. A live external writer still needs explicit transfer:
different lines of one physical file are not independent write claims.
Preserve compatibility behavior; never restore old whole-file bytes or reapply the
whole branch. The other 41 paths, whole-file equality, runtime correctness and
whole-PR supersession are not established. #3869 remains open and unaccepted.

## Next Kernel work: no provisional subsystem lock

#1943 is RECHECK, not a write reservation. Under I7.21, trace the authenticated policy
supplier -> existing ApplicationSession admission/transition -> prior-context
revocation -> enforcement. Start at ApplicationSession construction in
bins/eliot-kernel/src/agent_bridge.rs and the existing role_lease/session_lifecycle
methods. Return exact caller/consumer files under I2.17 before issuing a claim.
Do not build a second capability engine or let role labels mint authority.

#1678 already has the async coordinator. #1701's production eliotd admission,
activation and dispatch ports still refuse unconditionally; bind the actual existing
owner operations and retained results. Daemon-launch reservation gating is not proof
of this native-worker attempt join. Include the actual eliotd/worker consumers when
the scope is established. No second saga or whole-parent test wait.
Neither task currently reserves all Kernel/protocol files.

#1884/#1888 must reuse main's CPU-rate implementation, not the mixed archived CB
branch. One platform-file writer owns any actual remaining manifest/Job cleanup join.

## Retained PR decisions

- #4999 @ d4dfbbe4870a: draft, REQUEST_CHANGES
  [5398877744](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/4999#pullrequestreview-5398877744).
  Reject the missing-evidence synthesizer and fixture-prose exceptions. Final-byte
  recomputation cannot attest premutation reading. Genuine producer evidence and
  I18.27 oracle review are required; other documentation corrections are separate.
- #3058 @ f93239dec051: draft, COMMENTED hold
  [5398880483](https://github.com/UnknownAlienHuman/eliot-memory-os/pull/3058#pullrequestreview-5398880483).
  Port unmatched #686 work to current V2 commit-fence/namespace/bounds/coverage/digest
  producers; preserve #2966 recovery decisions. Do not restore V1 or default evidence.
- #2707 was closed without merge because its sole script registration was already
  in main. No source or branch deletion, no parent acceptance.

The prior 26-PR filename screen and obsolete broad-scope counts remain in
[the inspected revision](https://github.com/UnknownAlienHuman/eliot-memory-os/blob/3aa7cc157fee31ffc0c64531b00013a62dc6babf/workstreams/swarm/STITCH-PLAN.md).
They are not today's locks: #1943 has no claim and #2691 is narrowed above.
Titles are not scopes (#3869 had 44 paths; #4845 had three Kernel Rust paths despite
their descriptions). Compare merge-base/candidate/main before adopting unmatched
work; do not attribute inherited hunks to an author merely from the PR diff.

## Pending historical dependency groups — review, not a launch order

| Group | Boundary to resolve from current canonical contracts and code |
|---|---|
| #8 / #1746 | Existing bootstrap response versus real owner-source assembly/delivery. One writer for the shared Bootstrap/Bridge join. |
| #1229 / #3004 | Dependency-policy preparation supplies declared inputs; compile profile consumes them. Preparation is not a policy verdict; execution proof remains separate. |
| #1767 / #2893 | Portfolio/denominator owner consumes exact no-match/source-record/evaluator evidence. #1762 supplies live composition; #1765 retains final release authority. Serialize evidence_portfolio.rs and the actual adapter. |
| #18 / #2892 / #2968 | Host wiring versus packaging/disposition versus later assembled-product proof. |
| #1126 / #1699 / #2567 / #2866 | Exact execution/admission output and consumer-specific handoff. |
| #1762 / #1769 | Inquiry/source-admission producer and restricted consumer. |
| #1789 / #1791 | Authoritative transition versus plan/context projection. |
| #1934 / #2561 / #2731 / #2732; #2729 / #2730 | Privacy, retained event/projection, stream authority, bounded handoff, sequencing, acknowledgement and recovery. |

The first three partitions were body-reviewed; their full current source/thread
joins, and the remaining groups, are not certified. Do not remove an unverified edge
to manufacture a DAG. For the coverage group, no local fabricated evaluation receipt,
I/O inside the pure assessor or package-verdict promotion to release authority.
Missing vetted records, complete predicates or a real empty-scope contract stay Unproven.

Decision leads also remain: #332 layout; #1968 pair/Blob identity; #1844 R2 vocabulary;
#2882 part 5; #238 Context-cell owner; #956 purge/publication ports. Check the actual
canonical section and producer before declaring a missing contract. An omitted
assignment owner is not automatically an Architecture decision.

## Release rule

A real wait names the consumer item, producer output, exact type/operation and
observable release condition. Internal item order, a related link and final parent
acceptance are not interchangeable prerequisites. Record the disposition in the
existing controller ledger; transfer physical files explicitly. After integration,
refresh affected consumers/findings only. Independent cleared work continues.
