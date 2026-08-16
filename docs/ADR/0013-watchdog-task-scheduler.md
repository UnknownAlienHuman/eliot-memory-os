# ADR-0013: bounded Watchdog Task Scheduler boundary

## Decision

The X-01 fallback registration and activation boundary uses the Windows Task
Scheduler COM API through `windows` 0.61.3 with `default-features = false` and
only `Win32_System_Com`, `Win32_System_Ole`, `Win32_System_TaskScheduler`, and
`Win32_System_Variant`. The crate is MIT licensed and follows the workspace
MSRV. No shell, PowerShell, service-manufactured logon token, password, or
user-writable command is used.

Registration is limited to the installer-pinned `\\Eliot\\WatchdogFallback`
task, `InteractiveToken`, `LeastPrivilege`, the exact live SID/session, and a
fixed no-stdin `--watchdog-fallback` action. The implementation creates or
reopens the `\\Eliot` folder, reads back the task path and XML, validates the
single trigger/principal/action and all bounded settings, and returns a receipt
digest over the observed XML. Run requests perform the same readback before
`RunEx`; API failure remains unknown and is reconciled by the caller.

## Consequences

The dependency adds a small Windows COM projection but keeps the hot path
native and avoids a second scheduler or notification authority. Development
verification uses structural/unit tests only; it never registers or runs a
machine task.

The normal `NotificationPort` deliberately does not project a Shell balloon as
a general toast. Normal delivery remains the existing User Broker/
`AppNotificationManager` contract and returns a typed unavailable result until
that owner supplies authenticated OS-acceptance evidence. The native
`Shell_NotifyIcon` implementation is exposed only to X-01 as a bounded recovery
banner after `NIN_BALLOONSHOW`; it is not a second normal notification owner.
