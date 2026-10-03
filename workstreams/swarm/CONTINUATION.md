# Continuation of #5018

## Authority and entry

Canonical Architecture/Implementation govern the product. In particular,
[A0.2](../../docs/architecture/A00-02-hierarchy-of-architectural-decisions.md#a02-hierarchy-of-architectural-decisions)
distinguishes hard boundaries from defaults/examples; an old Issue, audit comment or
map cannot silently replace them.
[I2.17](../../docs/architecture/I02-17-parallel-agent-development-contract.md#i217-parallel-agent-development-contract)
requires bounded owner/caller work, not whole-subsystem reservations or one-line
deliveries detached from the product. Use PLAN.tsv and the matching PLAN.md card.

## Controller preflight, once per actual assignment

Read current main and current Issue/PR identities. Refresh the complete PR-ID set
and changed heads/paths, including rename sources; do not rely on an author-filtered
search, title or count. Resolve only overlaps applicable to the selected exact files.
An already-absorbed hunk is not an implementation wait; its disposition is recorded
in STITCH-PLAN. Recheck it when either candidate, selected scope or main changes.

Check selected-but-unstarted work as well as running writers, relevant old FIN
checkpoints and external writers. Stop/transfer an intersecting writer explicitly;
do not require a global stop of unrelated runners. Record the current claim in the
existing controller ledger: Issue, manager/session/worktree/branch, base and exact
files. No empty PR, new ledger service or repository-wide lock is required.
PLAN's conflicting_prs retains observed candidate-path contacts; STITCH-PLAN records
their actual remaining disposition. A listed PR need not be merged when its relevant
hunks already exist in main. [] does not prove there is no local writer.
CLAIM_AFTER_PREFLIGHT is not a running-session receipt.

One manager uses one worktree and a fresh Issue branch per coherent delivery.
Root owns synchronization and main integration; workers never race to land or
self-rebase. Subagents receive disjoint files within that manager's claim.
A claim lasts until integration, explicit transfer or abort, not a wave boundary.
A wider implementation need is a scoped amendment before editing, not a silent
directory claim. The existing controller concurrency/resource limits still apply.

## Executor loop

Read your full current Issue/discussion and nearest AGENTS, then route all actual
mutable path families together with scripts/docs_read.py and read every required
verified item before code mutation. The card's canonical links aid navigation;
they do not replace the bundle. Required reading and causal source must fit I2.16.
The full historical map, every other Issue and unrelated PR discussions are not
each worker's compulsory context.

Implement the existing owner and its real caller/consumer path first. An absent
caller is WIRING, not TEST-PHASE or automatically a missing normative contract.
A genuine semantic conflict gets one bounded ContractChallenge naming the canonical
section, producer output and affected consumer; preserve its checkpoint and take
independent cleared work. After two same-cause failures, audit the cause and change
approach rather than repeating the report. Never invent authority or success.

## Integration and continued review

Deliver exact changed files, requirement residual, entry-to-consumer path, actual
scoped checks and remaining acceptance to root. Use scoped Rust formatting/minimal
Clippy, the existing locked Operator build for C#, and applicable Python checks.
Broad behavioral campaigns follow product assembly; skipped proof remains skipped.
Root revalidates the combined candidate and affected reverse consumers, integrates
one coherent delivery, then releases its files and exact supplied outputs. A consumer
need not wait for the producer Issue's later acceptance/closure when its required
contract/output is already available. Do not close a whole Issue from a helper fix.

Root alone updates planning and refreshes shared generated inventories on combined
source. Recheck findings affected by source/contract/Issue changes, not the whole
backlog after every merge. Continue the full review over retained plus current open
Issue IDs; closed prerequisites still need actual output evidence. Keep raw paginated
captures/content identities outside Git; counts and labels do not establish coverage.
Read-only R0-R3 partitions (Issue number modulo four) reserve no code or planning files.

#818's existing oracle has unresolved input/scope/readiness defects: its Valid/READY
cannot substitute for this preflight. Repair that owner, not a second checker.
Independent proven assignments need not wait for its entire acceptance campaign.

Use genuine versioned documentation evidence through the existing delivery gate.
The rejected #4999 synthesizer is not an emitter fix; byte recomputation cannot
attest earlier reading. Apply I18.27 independent oracle review. Local Make-PR2.sh,
runner state, full Issue coverage and product execution were not established by this
metadata revision. Do not report a merge, launch or passing gate until observed.
