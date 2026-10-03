# Selected source work

Use your PLAN.tsv row and the matching card below. Its write_paths are exact files,
not permission to edit their directories. Read your live Issue/discussion, nearest
AGENTS and the complete verified changed-path bundle; the links below identify the
load-bearing canonical sections, not a smaller substitute bundle. Root owns integration.
Wave 1 is an eligible pool, not a barrier or an instruction to launch every manager.
The controller's existing resource/concurrency limits still apply.

## M-LEGACY — #3980

Canonical: [I15.4 secrets](../../docs/architecture/I15-04-secrets.md#i154-secrets);
[Appendix P boundaries](../../docs/architecture/APPENDIX-P-rust-public-boundary-interfaces.md#appendix-p-rust-public-boundary-interfaces).
**Residual:** current GovernorConfig accepts loopback-looking prefixes, while the
supervisor checks only Store collision and the RPC client performs no local-only check.
**Implement:** one full-grammar validator on SurrealServerConfig; call it from
GovernorConfig::validate, SurrealServerSupervisor::validate_admission and
SurrealRpcTransport::connect before credentials, paths, process or socket effects.
Consume the whole existing literal-loopback/bind/port/rpc grammar, not a prefix.
**Preserve:** reserved Store collision, existing accepted encoding/case policy and
typed bounded failures. Reject userinfo/path/query/fragment tricks without logging
the rejected URI. No new dependency, Store daemon, credential owner or legacy revival.
**Handoff:** all three real entrypoints use that predicate; scoped eliot-types /
eliot-store formatting and minimal Clippy. Original negative/valid-route acceptance
stays in #3980 after assembly. eliot-app's loader is read-only unless scope is amended.

## M-STORE — #2691

Canonical: [I14.3 reserve](../../docs/architecture/I14-03-control-reserve.md#i143-control-reserve);
[I5.16 evidence](../../docs/architecture/I05-16-common-durable-fields.md#i516-common-durable-fields);
[I5.13 backup](../../docs/architecture/I05-13-backup-and-restore.md#i513-backup-and-restore);
[I5.27 identity](../../docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md#i527-canonical-operation-identity-and-effect-identity).
**Residual:** private snapshot_owner_maintenance_tick has no external caller;
budget diagnostics still lack the requested high-water/remaining accounting.
**Implement:** S-03 run/StoreComposition lifetime -> narrow adapter method -> existing
bounded expiry/retirement -> existing diagnostics. Drive it during idle pipe waits,
not only after requests; preserve in-flight framing/cancellation and clock rules.
Every exit must stop/join the driver before its owner is dropped.
**Preserve:** #2688/#2689 incarnation, exact replay, charge transfer, interruption and
terminal receipts; no second registry/service, detached task, silent eviction or
reset-to-zero recovery. Existing global state is not durable restart evidence.
**Handoff:** complete W5/W7 and A6's source obligations in the five named files;
scoped adapter/S-03 checks, then the original bounded acceptance after assembly.
No apply/*, Store API, compatibility policy, manifests or Cargo changes are assigned.
The old PR waits are resolved for these files only; see STITCH-PLAN's #2691 entry.

## M-OPERATOR — #2643

Canonical: [I11.12 UserAutomation](../../docs/architecture/I11-12-userautomation.md#i1112-userautomation);
[I7.20 failure identity](../../docs/architecture/I07-20-agent-facing-error-contract.md#i720-agent-facing-error-contract);
[I5.27 identity](../../docs/architecture/I05-27-canonical-operation-identity-and-effect-identity.md#i527-canonical-operation-identity-and-effect-identity).
**Residual:** CreateContext's fresh nonce is compared with the business-operation
hash by ValidateCurrentIdentity before GovernorPipeClient sends it.
**Implement:** distinguish only the existing closed UserAutomationGetContextOperation
at that validation boundary. Keep nonce/key syntax and absent-fence checks; correct
the adjacent client contract comment without removing its validation call.
**Preserve:** every business request's digest and original expected_state_fence,
one prepared journal/send identity, exact withheld legacy bytes and strict decoding.
Do not replace the nonce with a constant digest or exempt all read operations.
**Handoff:** both UI read/effect paths can obtain context without the incompatible
local guard. MainViewModel, pending journal and Rust owner are read-only consumers.
Use the existing locked Operator build profile, not Clippy or a new harness.
Original cross-language/recovery acceptance remains pending; this repair does not
certify the full UserAutomation runtime or replace its current wire with the old table.

## M-TOOLS — #2701

Canonical: [I18.27 oracle ownership](../../docs/architecture/I18-27-oracle-ownership-and-test-change-governance.md#i1827-oracle-ownership-and-test-change-governance).
Read existing audit 5908785311 and recheck 5963910318; #929 owns check(Path)'s contract.
**Implement:** its full repair 1-7, preserving item 9, in the existing validator.
The second file is only for a genuinely needed accepted-API change, not a new scanner.
**Preserve:** one check(Path), no normal-check sync/fallback, separate inventory and
closure digests, valid unknown/needs-repair findings and original failure causes.
**Handoff:** syntax/scoped CLI checks on the named scripts; item-8 regressions remain
later acceptance. Root alone refreshes global generated inventories after integration.
No Rust, workflow, generated TOML or evidence-attestation fallback is assigned.

## Next root review — #1943, not a broad write reservation

[I7.21](../../docs/architecture/I07-21-default-agent-role-capability-profiles.md#i721-default-agent-role-capability-profiles)
requires actual role issuance/revocation, not labels. Follow ApplicationSession
construction in bins/eliot-kernel/src/agent_bridge.rs into the existing role_lease.rs /
session_lifecycle.rs methods; identify the authenticated policy supplier, transition
entry and direct enforcement consumers. Return exact files and the required owner
output. Do not rebuild the role engine or claim four subtrees while choosing a caller.
#1943 stays visible in REVIEWED.tsv as RECHECK. It does not hold unrelated work.
