# status.md — lane MGR-B, issue #957 (E2)

- Branch: `work/957-ors-restore-journal`
- State: port complete, gate run, ready to push.
- Scope: `crates/kernel/eliot-ors` restore journal only
  (`src/restore_journal.rs`, `src/store/restore_journal.rs`, lib/store
  registration, `tests/restore_journal.rs`, 2 fixtures).
- Tests: 16/16 `WORK_UNIT_CASE: 957/1..16` executed PASS.
- Pre-existing (not mine): fmt drift + clippy lints elsewhere in
  `eliot-ors`; left untouched.
- Out of scope (not ported): #958 host prep, platform-windows seam,
  #1751 lease census, introduction scan.
- Next: commit `feat(#957)`, push `-u origin`, report back.
