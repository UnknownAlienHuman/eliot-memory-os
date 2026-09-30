# Report: issue #1934 — privacy verdict through the retained WorkScope owner binding

Branch `fix/1934-privacy-authorization-MC1`, rebased cleanly onto `origin/main`
(`0738d7ef`). HEAD `8d369f153` (writer `1e2b0a3ea` + two manager gate commits).

## What changed

The bridge-event privacy verdict is no longer derived from an echoable scope
plus a presenter-minted revision. The Kernel route resolves the verdict over
the retained Governor-resolved `work_scope_id`, the provider identity, and the
closed retention term, bound to the exact owner decision refs (activation
ticket + result digest). The ORS stage entry re-derives the scope and the
owner-decision revision from its own durable activation row and fails closed
on any disagreement. The fencing generation is never recorded as a policy
revision again.

Files: `bins/eliot-kernel/src/host_request_route.rs`,
`crates/kernel/eliot-ors/src/store.rs`. No new dependencies, no new binaries,
no test files (product code only, per lane order).

## Item coverage

All 6 Work items and 4 Acceptance items are met; see `CHECKLIST.json` for the
per-item evidence map. W1–W4/A3–A4 rest on the pre-existing ingest/cursor/
replay pipeline on main, which this branch preserves (duplicate/conflict legs
intact, gap/reconcile paths untouched); W5/W6/A1/A2 are implemented by this
branch's verdict binding and re-verification.

## Production chain (stitched, no dead code)

`AGENT_BRIDGE_EVENT_FORWARD` → `admit_bridge_event_envelope` (:6016) →
`bridge_event_privacy_authorization` (:6224) + `stage_bridge_event_durable`
(:6403) → `stage_bridge_event_document` (:6329) →
`stage_bridge_event_checked` (store.rs:16737) → `parse_bridge_stage_checked`
(:16917) → `bridge_event_privacy_owner` (:11773, via pre-existing
`load_activation_result` :9425) + `bridge_event_privacy_scope` (:11173) →
`bridge_event_privacy_staging` (:11568) → `check_grant_binds_owner` (:11531).

## Gates (observed)

- `clippy -p eliot-ors --lib --no-deps -- -D warnings`: clean.
- `clippy -p eliot-kernel --bins --no-deps -- -D warnings`: exactly the 7
  pre-existing `main` errors (control_plane, testd_terminal_completion_route,
  daemon_request_dispatch x4, dispatch_launch), 0 new.
- `rustfmt --check` on both touched files: clean.
- `docs_read --changed-from origin/main`: PASS, 43 required items.

## Docs attestation

Route `sha256:f55e2c5c…`, read receipt `sha256:ed0ae36d…`, bundle
`08ff3303…`, routes generic-source/host-kernel/security-privacy. Manager read
the verified bundle sections governing this change (kernel owners/boundaries,
I1.8, I5.5, I5.26, I6.15, I14.14, I15, I16.17, I18) plus the standing lane
docs. No optional fragments crossed. Full receipt in
`docs-read-receipt.json`.

## Risks

- `eliot-kernel` on `main` is clippy-red (7 pre-existing); CI `ci.yml` is
  compile-only so the merge check is unaffected.
- `admitted_policy_revision` now stores the owner-decision revision; old rows
  keep validating, but consumers must read it under its honest name
  (`owner_revision` on the outcome object).
