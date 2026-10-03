# Shared seams and release conditions

These are integration boundaries, not a second product specification. Keep all
requirements in their existing owning issues and canonical docs. A missing caller
under an existing contract is source work; a genuinely unspecified contract gets
one precise proposal in its owning issue, not a fabricated implementation.

## Initial assignments and their shared boundaries

**#1943, M-KERNEL:** authenticated admission / explicit role transition → existing
ApplicationSession role-capability compilation → issued context/token + revocation of
old context + independence update → existing operation authorisation. All source
sides are in the single Kernel/IPC assignment. No other manager changes these protocol
or composition files concurrently. Acceptance remains Controller→Worker restriction
and explicit Verifier downgrade; declarations alone do not release this seam.

**#2691, M-STORE:** S-03 StoreComposition lifetime → narrow adapter maintenance method
→ snapshot_owner_maintenance_tick → existing expiry/retirement accounting → bounded
diagnostics. The same owner starts/stops the no-client wake. #2688/#2689 identity,
incarnation, interruption and retained receipt semantics are preserved. Shared snapshot
files are not assigned to those issues simultaneously. No new Store API is needed
merely to expose an internal maintenance method; any discovered cross-owner need is
recorded before expanding the scope.

**#1678 → #1701:** reservation owner → exact active owner-verifiable evidence → launch
consumers. #1678 already contains an asynchronous coordinator, canonical receipt
readback and recovery module on this baseline; recheck its missing producer/application
join instead of recreating it. Release #1701 when its actual required evidence/API and
current caller contract are present in main, not when all product tests for #1678 close.
The Kernel manager owns the shared source turns sequentially. #1679 capacity and #1680
attempt history retain their own semantics; no second scheduler/state machine.

**#1884 → #1888:** use the main process_job.rs CPU-rate implementation from #5019.
The old CB branch is not a clean #1888 delivery. Compare per-issue residuals before
carrying code; do not reintroduce a second CPU-rate mechanism. Launch/manifest and
Job cleanup changes must share one platform-file writer when this work is selected.

## Historical cycle review groups

The published stop graph contained the groups below. These are NOT approved hard
dependencies or executable issue orders. Root gives each group one read-only review;
source changes wait for explicit item-level ownership and a scope claim. Even separate
groups may share Kernel/ORS/protocol files, so group separation is not write isolation.

| Group | Issues | Required output before source scheduling |
|---|---|---|
| bootstrap | #8, #1746 | Separate bootstrap contract/response from real owner producer/transport; identify exact release output. |
| front door | #18, #2892, #2968 | Separate host wiring, release packaging/disposition and post-assembly host proof. |
| execution | #1126, #1699, #2567, #2866 | Name the one execution/admission owner and consumer-specific result; preserve identity, no mutual whole-issue wait. |
| dependency preparation | #1229, #3004 | Distinguish preparation entrypoint from compile-gate consumer and runtime proof; no waiting on repeated issue closure. |
| source admission | #1762, #1769 | Identify admission producer and restricted proposal consumer; determine real contract decision separately. |
| coverage | #1767, #2893 | Identify the denominator/receipt producer versus verification; no self-issued complete coverage. |
| scope/plan transition | #1789, #1791 | Distinguish transition-owner output from downstream projection and parent acceptance. |
| host events | #1934, #2561, #2731, #2732; related #2729/#2730 | Map privacy admission, immutable source+normalisation/disposition, bounded handoff, acknowledgement and replay. One writer for shared Kernel/ORS/protocol turns; no second event database. |

Review output is one exact relation: consumer issue/item → producer issue/item and
output → existing type/operation → owning paths → release observation. If an edge is
only a reference, internal step, old proof or stale state, record that classification
and do not import it as an implementation dependency. If a genuine cycle remains,
resolve the existing contract ownership first; no arbitrary topological ordering.

## Single decision list

Unresolved candidates (not approved design changes): #332 non-Windows install layout;
#1968 external pair/generation identity boundary; #1844 R2 event vocabulary; #2882
part 5; #238 Context-cell ownership; #956 concrete publication/purge ports. Confirm
silence in their actual governing sections before escalating. A code owner missing
from an issue is an assignment repair, not automatically an Architecture decision.
None of these candidates blocks the two selected source assignments.
