# Hook: operator board-inbox runtime serving (issue #1780)

Owner: board-inbox runtime worker (Muse Spark 1.3), tree
`luna-1780-notification-inbox-20260921`, branch
`codex/1780-notification-inbox-runtime`.
Readers: Beauvoir (central Kernel composition), B2 (notify declaration
producer), B3 (daemon consumer), root (merge).

## Frozen source

- Freeze commit: `98bfeaf056c9b9dd7f6509ca84dcef98b546f204` (12 source
  files, no build output, no trailer per authorization).
- Parent: `a4598a6d` (operator inbox consumer + stdin dispatch arm).
- Docs routing: route `sha256:c06465de…`, read `sha256:082b1d27…`,
  bundle `sha256:cc20118a…` (49 required items, routes
  `generic-source`, `host-kernel`, `human-surfaces`); normative reads
  I11.2/I11.5/I11.7 full text plus I01.8 read path. Bundle + receipt
  live in `.eliot/` (local state, never committed).

## What the freeze delivers

- `eliot-protocol::board_inbox`: `BOARD_INBOX_OPERATION =
  "controlboard.inbox"`, contract `eliot.foundation.board-inbox` v1.0.0.
  Closed empty request; reply reuses the notify `ReadInbox` envelope
  shape with `service`/`protocol` naming this producer.
- Catalogue: `CommandId::BoardInbox` (`controlboard-inbox`),
  `CommandArguments::ControlboardInbox`, read-only PlanGap row (work
  `1780`) with forwarded-provider acceptance; `cli_contract` count
  26 → 27.
- Kernel: `KernelFrameAction::BoardInbox` + `dispatch_board_inbox_frame`
  (Ready / peer / correlation / exact-operation / empty-payload gates)
  + `execute_board_inbox_request` (binds `AuthenticatedNotificationSession`
  under the admitted peer principal, serves the fixed closed read through
  the retained `KernelStoreGateway`, frames the correlated inbox
  envelope). Driver serves it on the front-door loop; bridge transports
  fence it. Byte-compare serve proof in-module (served rows re-encode
  byte-equal to canonical payload records).
- CLI: `AuthenticatedKernelPort` dispatches `BoardInbox` as
  `transact_json(BOARD_INBOX_OPERATION, {})`, forwarding kernel bytes
  verbatim.
- Meta: contour `ControlBoardEntryKind::Notification` + `notification_count`,
  rows keyed by record dedup key (1:1, no role/privacy/quiet-hours
  filtering, duplicates fail closed); denominator render coverage.

## Beauvoir: tiny central hook (exact)

No new central code is required beyond merging the freeze. The only
composition-owned fact the execute path depends on is the already-owned
retained gateway slot:

- Callable: the existing store-bootstrap connect path
  (`bins/eliot-kernel/src/canonical_store_runtime.rs`,
  `connect_canonical_store*` installing `canonical_store_gateway`).
- Contract: `execute_board_inbox_request` clones the gateway under a
  scoped lock and fails closed (`SessionFenced`) while it is `None`;
  service bind happens under a scoped lock that ends before any await
  (no self-deadlock). Nothing to register, admit, or name centrally:
  the `controlboard.inbox` arm lives in the closed native-operation
  gateway matrix (`frame_dispatch.rs`), already gated like its
  neighbours.

## Wire-field contract (both producers, one consumer)

- Request frame: `Request`/`Execute`, payload exactly
  `{"operation": "controlboard.inbox"}` (single key; anything else
  fences).
- Reply frame: `Response`/`Result`, same `request_id`, payload
  `{"status": "inbox", "service": <producer>, "protocol": <producer
  protocol>, "read": {"records": [...], "metrics": {...},
  "state_fence": {...}, "revision": N}}` with `N != 0`, per-record
  fence equality, and record count within `MAX_NOTIFICATION_PAGE_LIMIT`.
- Kernel producer marks `service: "eliot-kernel"`, `protocol:
  "eliot.kernel.v1"` (correlation-only). `bins/eliot/src/
  controlboard_status.rs::decode_inbox_response` decodes both.

## B2 coordination (consume, don't collide)

- B2 owns the installer/materializer Notify declaration producer.
  Frozen B2 APIs (`01a85e7a`): `VerifiedNotifyLaunch::
  installation_identity()` (validated record identity, not paths/labels)
  and `bind_notify_launch_grant` (+ `NotifyGrantInputs` /
  `NotifyLaunchAuthorization`) per
  `control-20260921/1780-notify-beauvoir-handoff.md`.
- Board-inbox call sites use only those two APIs against real
  declaration bytes / retained session bindings. No synthetic
  identities, no second notify record, no broker/scheduler changes.
- No collisions: this lane touches no `notify_fallback_setup`, no
  installer CLI args, no grant module, no `ApprovedLaunch` mapping.

## Pipe-proof status (honest)

- Done: serve-layer byte proof (fake store → rows re-encode byte-equal);
  closed-query selectors; foreign-fence/shape negatives; catalogue +
  consumer + projection suites green (see delivery report for counts).
- Next: real front-door pipe proof — admitted `Request`/`Execute`
  bytes → `BoardInbox` action → retained-store read → wire `read.rows`
  bytes compared against canonical record bytes. Harness precedent:
  `bins/eliot-kernel/tests/kernel_front_door_diagnostics.rs`
  (`test_kernel_with_pipe` + manual `Session` + `dispatch_frame`) and
  the in-crate `ready_kernel` driver (`dreamer_job_dispatch.rs`
  tests). Seeded-store leg still open; no synthetic store bytes in the
  final proof.
