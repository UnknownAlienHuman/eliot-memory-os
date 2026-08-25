# W0 watchdog protected-root fixture decision

Status: `ACCEPTED_FOR_ONE_QUIESCENT_AGGREGATE_RERUN`

Decision owner: Root integration authority

## Decision

Accept the fixture-only watchdog correction that replaces direct test writes to
`C:\ProgramData\Eliot\installations\...` with a unique disposable protected-root
override for the lifetime of `RegistryFixture`.

This decision authorizes one new quiescent `scripts/verify.ps1` aggregate run
after the focused watchdog verifier remains green.

## Accepted mechanism

- `eliot-platform-windows/test-support` is enabled only for the watchdog test
  fixture.
- `RegistryFixture` owns the `ProtectedRootOverride` guard for its complete
  lifetime.
- The disposable root is prepared with the same protected-directory helper used
  by the production contour.
- Registry paths and v14 Phase-B selectors remain production-shaped beneath the
  disposable root.
- Fixture teardown removes only its exact temporary artifact and root paths.

## Authority and effect boundary

This is test-fixture authority only. It does not authorize:

- changing the production protected-root resolver;
- weakening ACL, owner, reparse-point, or descriptor validation;
- writing to or deleting the real `C:\ProgramData\Eliot` contour;
- treating focused tests as an aggregate or hosted-CI receipt;
- activation, cutover, installation, commit, or push.

## Evidence required before the aggregate rerun

```text
cargo test -p eliot-watchdog --lib protected_redb_registry_ --locked -- --nocapture
cargo test -p eliot-watchdog --lib --locked
cargo clippy -p eliot-watchdog --lib --locked -- -D warnings
git diff --check
```

The focused discriminator is the three-test `protected_redb_registry_` set. It
failed before the fixture correction at protected ProgramData creation and now
must pass without touching the real protected root.

## Rollback

If any focused test fails, if the fixture resolves under real ProgramData, or if
the aggregate exposes a production-path regression, stop the aggregate claim,
retain the failing receipt, revert only this fixture mechanism, and open a new
ContractChallenge. Do not broaden permissions or bypass protected-root checks.

