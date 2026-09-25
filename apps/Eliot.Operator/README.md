# ELIOT Operator

Native WinUI 3 operator client for the existing ELIOT Governor. It is a thin
renderer/controller over the authenticated named-pipe contract; it has no
database credentials, HTTP listener, browser surface, shell, scheduler, or
independent authoritative cache.

## Toolchain

The pinned identity below is stated only where a checked-in source file, the
NuGet lock, or a publish receipt carries it. Each claim names the file and the
property that carries it.

- Target framework `net10.0-windows10.0.19041.0`, minimum platform
  `10.0.17763.0`, `Platforms`/`PlatformTarget` `x64` and
  `RuntimeIdentifier` `win-x64` — the `PropertyGroup` in
  `Eliot.Operator.csproj`;
- unpackaged (`WindowsPackageType=None`), `UseWinUI=true`,
  `SelfContained=true` and `WindowsAppSDKSelfContained=true` — the same
  `PropertyGroup`;
- `Microsoft.WindowsAppSDK` `2.3.1` requested — the `PackageReference` in
  `Eliot.Operator.csproj`;
- `Microsoft.WindowsAppSDK` `2.3.1` resolved — the `resolved` entry of
  `Microsoft.WindowsAppSDK` under `dependencies` in `packages.lock.json`, whose
  sibling `requested` is `[2.3.1, )`. That lock is the NuGet lock required by
  `docs/DEPENDENCY_POLICY.md`, kept in place by
  `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` in
  `Eliot.Operator.csproj`;
- the same framework, runtime identifier, platform, configuration and Windows
  App SDK version, re-read from a successful locked publish —
  `OPERATOR_BUILD_RECEIPT.json`, schema `eliot-operator-build-receipt-v2`;
- .NET 10 SDK — the project pins no SDK patch release and the repository has no
  `global.json`. The observed toolchain is recorded per publish as
  `sdk.dotnet_path`, `sdk.dotnet_sha256`, `sdk.dotnet_sdk` and
  `sdk.msbuild_version`; no README claim substitutes for `dotnet --version`.

Build and publish with an installed x64 .NET 10 SDK, for developer iteration
only:

```powershell
dotnet restore apps/Eliot.Operator/Eliot.Operator.csproj --locked-mode
dotnet publish apps/Eliot.Operator/Eliot.Operator.csproj -c Release -r win-x64 --self-contained true -o dist/windows-x64/Eliot.Operator
```

### Publish evidence

`Eliot.Operator.csproj` produces publish evidence from one MSBuild target,
`WriteOperatorBuildReceipt` (`AfterTargets="Publish"`), and that target is
conditional: its `Condition` is `'$(OperatorBuildReceiptPath)' != ''`. A publish
that does not pass `-p:OperatorBuildReceiptPath=…` never runs the target and
never writes `OPERATOR_BUILD_RECEIPT.json`. The two commands above are local
build commands; they are not publish evidence and nothing may claim they are.

The receipt-producing path is the release builder, as
`docs/release/WINDOWS_X64_RELEASE.md` states:
`scripts/build-eliot-windows-x64-release.ps1 -BuildOperator` runs the pinned
project through locked `dotnet publish` — passing `-p:RestoreLockedMode=true`
and the receipt properties, and publishing outside the source tree under
`%LOCALAPPDATA%\Eliot\build\operator-publish\` — and the project's
`AfterTargets=Publish` target writes `OPERATOR_BUILD_RECEIPT.json` into that
publish directory. The producer is `scripts/write-operator-build-receipt.ps1`.
It refuses to write a receipt unless the source commit is a full 40-hex SHA
equal to `HEAD`, the tracked tree is clean, the observed publish properties
equal the pinned project properties with `Configuration=Release` and a locked
restore, and the output directory holds exactly one nonempty Windows x64
`Eliot.Operator.exe`, with no reparse point and no unapproved file type.

The receipt's identity fields, and the single consumer that re-derives every one
of them from the current source, are
`scripts/build-eliot-windows-x64-release.ps1::Get-VerifiedOperatorBuildReceipt`:

- `schema` `eliot-operator-build-receipt-v2`, `created_at_utc`, and the pinned
  build identity — `source_commit` (the observed `HEAD`), `invocation_id` (a
  canonical `D` GUID), `target_framework`, `runtime_identifier`, `platform`,
  `configuration` (`Release`), `windows_app_sdk_version` and
  `restore_locked_mode` (`true`);
- the exact inputs — `packages_lock_sha256`, `csproj_sha256`, `source_inputs`
  (each bound file's `path`, git blob SHA-1, SHA-256 and byte count, for the
  project, the lock and `Protocol/OperatorContracts.cs`) and `producer` (the
  receipt writer's own `path` and `sha256`);
- `contracts` — `path`, `sha256`, `schema_version`, `ipc_protocol_version` and
  `contract_hash`, re-read from `Protocol/OperatorContracts.cs`;
- `sdk` — `dotnet_path`, `dotnet_sha256`, `dotnet_sdk`, `msbuild_version`;
- `build` — `target` (`Publish`), `result` (`succeeded`), the same
  `invocation_id`, framework, runtime identifier, platform, configuration and
  locked restore, plus `self_contained`, `windows_app_sdk_self_contained`,
  `use_winui` and `windows_package_type`;
- `artifact` — the one `Eliot.Operator.exe` with `path`, `sha256`, `bytes` and
  PE machine `8664` — and `artifacts.files`, the per-file `path`, `sha256` and
  `bytes` inventory of the whole publish output, covering every file except
  `.pdb` and the receipt itself.

That consumer re-reads the project, the lock, the protocol contract and the
receipt writer from the source commit, re-derives every value above, and refuses
a receipt that differs from any of them, from the builder's own `dotnet`
executable identity, or from the payload it claims. A staged release therefore
cannot carry a receipt that has drifted from the sources the receipt names.

One agreement is not value-checked, and this section does not claim it is:
**no script in this repository reads a version value out of
`packages.lock.json`.** The receipt's `windows_app_sdk_version` is read from
`Eliot.Operator.csproj`, and the verifier compares it only to
`Eliot.Operator.csproj`. The lock enters the receipt as the digest
`packages_lock_sha256` and is separately bound to the source commit by git blob
identity, so the lock that was restored is provably the lock in that commit —
but a lock whose `resolved` Windows App SDK version disagreed with the project's
requested version would still pass both scripts. What keeps the two in step is
NuGet's locked restore, which both scripts require (`RestoreLockedMode` must be
`true` when the receipt is written and when it is verified) and which fails the
restore when the project reference and the lock would need to change; that is
tool behaviour, not a comparison any script in this repository performs. The
two values do agree today, `2.3.1` in both files. Closing the gap means editing
`scripts/write-operator-build-receipt.ps1` and
`scripts/build-eliot-windows-x64-release.ps1`, which are outside this surface's
scope.

## One-shot handoff and reconnect

The app consumes exactly one owner-issued handoff. `RuntimeDiscoveryService`
reads the inherited `ELIOT_OPERATOR_ENDPOINT` once, clears it immediately,
closed-decodes the six owner fields, and binds them through `OperatorHandoff`
to:

- the installation root of this process;
- the authenticated Windows user SID and the interactive logon Session,
  checked against the owner-issued `interactive_session_id`;
- the broker registration epoch, which is also the Governor endpoint
  generation;
- a bounded Operator artifact fingerprint (image length, last-write instant and
  a SHA-256 over the leading 1 MiB) and the Operator process generation
  (process id plus start instant);
- the role and the exact `controlboard.read` / `operator.command` capability
  set;
- the handoff nonce, which is never stored, logged or displayed; and
- the owner's own handoff lifetime, so the connect deadline can never outlive
  the handoff it consumes.

The handoff is consumed *before* the pipe is opened, so a failed connect can
never present the same nonce twice. After consumption, expiry, invalidation or
refusal there is no in-process continuity: `OperatorHandoffRefusedException`
carries the typed restart-required disposition and the exact owner obligation.
The app never re-reads the consumed environment value and never infers
continuity from a PID, a user, a pipe name or a cached endpoint.

## Wire ownership

The `eliot_operator_*` tools are served by `crates/eliot-app` and conflict with
current ControlBoard/runtime-status ownership. They are therefore isolated
behind exactly one versioned compatibility adapter, `LegacyOperatorAdapter`:
one schema, one pinned contract hash, one admitted tool set
(`IsAdmittedTool` refuses anything else before it is written), one current
consumer (`Eliot.Operator.Services.GovernorPipeClient`), a proof ceiling, and an
expiry/removal condition. No new feature is added to `crates/eliot-app`.
Reads stay on the current ControlBoard/runtime-status contract and mutations on
the current typed Operator-intent route; the adapter is the only remaining
legacy path and its removal condition is stated on the type itself.

## Operation identity and reconciliation

Both mutation routes retain exactly one operation identity:

- task-scoped operator commands mint the identity once per user action in
  `OperatorIntentEnvelope`, and the exact canonical envelope bytes are written
  to the user-local `OperatorPendingOperationJournal` **before** the first
  send;
- typed UserAutomation effects derive a retry-stable identity from the exact
  canonical operation bytes, so a lost response, a reconnect or an operator
  resubmission of the same typed operation carries the same identity.

Durable phases stay distinct: `Submitted`, `PossiblyExecuted` (transport loss
after the request was written), `UnknownReconciling` (the owner answered
without proving a terminal disposition), `Receipted`, `Rejected`,
`StaleFence` and `Cancelled`. A retained operation is compacted only after its
terminal owner-bound phase has been journalled, and `accepted && executed`
without a canonical receipt is never treated as success. Restart promotes any
surviving non-terminal record to `UnknownReconciling`, so a restart cannot
create a second logical mutation.

## Bounded surfaces

Encoded line, decoded body, response member/depth/token/string/array-item,
local JSON parameter, page, cursor, retained-input, retained-result, request
timeout and diagnostic limits are enforced before the offending data can be
trusted. Oversized input fails closed and is never truncated into a
valid-looking object. Protected control shapes reject unknown and duplicate
fields; the serializer refuses unmapped members instead of ignoring them.
A bounded opaque result payload stays untrusted data.

## Diagnostics

Startup diagnostics are bounded and redacted: stage, exception type and
HRESULT only, plus one record naming the loaded wire adapter's schema, hash,
consumer, proof ceiling and removal condition. Messages, stack traces, pipe
names, nonces, endpoints, credentials and command/query bodies never enter the
log, and transport faults surface as closed `OperatorFaultReason` codes rather
than framework message text.

The publish target explicitly copies generated `.pri` and `.xbf` resources
because plain `dotnet publish` otherwise produced an executable that failed
during XAML activation. Current UI debt is presentation-only: several
projections are raw JSON-first, and contour reassignment/approvals/incidents
were not exercised in the bounded L8 run.
