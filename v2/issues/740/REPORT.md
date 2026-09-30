# Report: issue #740 (MC1 slice) — handshake/readiness diagnostic records

Branch `fix/740-handshake-readiness-emit-MC1`, rebased cleanly onto
`origin/main` (`0738d7ef`). HEAD `f0f82a3fc` (writer `6fd7557a6` + manager
fmt commit).

## What changed (product slice)

- `DaemonKernelClient::connect` emits the handshake record only after the
  snapshot reply passes wire correlation plus snapshot/admission validation
  (`validated` is observed), and one owning error record per failed connect.
- `report_ready` emits one owning error record per failed report; the success
  leg stays record-free because the runtime emits the daemon-readiness
  record. Distinct `eliotd.daemon_readiness` span preserved.
- `daemon_runtime::pre_loop_failure` names the `DaemonRuntime`-owned error
  record on the two pre-loop `String` failure legs (connect, report_ready);
  terminal output bytes unchanged.

Files: `bins/eliotd/src/daemon_kernel_client.rs`,
`bins/eliotd/src/daemon_runtime.rs` — both inside the issue's exclusive
mutable scope. No dependency, lockfile, workflow, or normative edits.

## Coverage

Product-side of matrix cases 2 and 14 for the handshake/readiness/pre-loop
legs; sink/redaction behavior preserved via `ScreenedValue`. The remaining
18 cases need follow-up product slices plus the executable 21-case matrix in
`tests/daemon_diagnostics.rs`, which this lane does not author
(product-code-only lane order). See `CHECKLIST.json`.

## Gates (observed)

- `clippy -p eliotd --lib --bins --no-deps -- -D warnings`: 16 errors,
  byte-identical file/line set to the `main` baseline — 0 new.
- `rustfmt --check` on both touched files: clean.
- `docs_read --changed-from origin/main`: PASS, 23 required items.

## Docs attestation

Route `sha256:6e102707…`, read receipt `sha256:6e699b74…`, bundle
`7892dd68…`, route generic-source. Manager read the verified bundle
(standing docs, hashes match session reads) and the four issue-mandated
shards I1.10, I13.11, I14.25, I15.4 directly. Conformant: handshake and
readiness stay distinct states (I1.10), records carry owner/code/bounded
detail (I13.11), no Doctor/repair semantics (I14.25), no secret values in
any sink (I15.4). Full receipt in `docs-read-receipt.json`.
