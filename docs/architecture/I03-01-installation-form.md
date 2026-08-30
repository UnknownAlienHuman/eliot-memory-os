## I3.1. Installation form

Installation profile determines both process supervision and writable roots.

```text
system_service — DEFAULT; one elevated installation, SCM demand-start and strongest recovery;
user_mode      — no admin: per-user binaries, launcher + Task Scheduler/current-user supervision;
portable_dev   — repository-local binaries/state, development and tests only.
```

Profile paths:

| Profile | Immutable binaries | Durable/service data | User config/cache |
|---|---|---|---|
| `system_service` | `%ProgramFiles%\Eliot\<component>\<version>` | `%ProgramData%\Eliot` | `%LocalAppData%\Eliot` |
| `user_mode` | `%LocalAppData%\Programs\Eliot\<component>\<version>` | `%LocalAppData%\Eliot\data` | `%LocalAppData%\Eliot\config\|cache` |
| `portable_dev` | repository `target/eliot-dev/<generation>` | repository `.eliot-dev/state` | repository `.eliot-dev/config\|cache` |

Mutable data is never stored beside immutable versioned binaries, except inside the explicitly disposable `portable_dev` profile. CLI/agent bridges are added to the current user's PATH or registered through the selected host integration.

`user_mode` preserves EBP, Kernel and module contracts, but its Governance Profile honestly reports weaker restart, independent-Watchdog and OS-level isolation guarantees. Code may not assume `%ProgramData%` or administrative service rights merely because the Windows production profile supports them.

For `system_service`, installer configures a narrow service DACL: authorized local users may query and demand-start Eliot Host, but cannot change the binary path, service account, recovery policy or protected configuration. Normal stop/drain is requested through authenticated ELIOT control so receipts and shutdown manifests are preserved; administrative SCM stop remains recovery-only. This allows ordinary-user startup without granting service reconfiguration rights.

### Installation owner and user-session binding

`system_service` has a primary System Owner SID and an explicit list of authorized interactive-user brokers. The service account does not inherit their subscriptions or desktop credentials. Adding another user is a visible registration/consent transition with a distinct broker identity; private WorkScopes and memory are not merged automatically.

