# ELIOT Operator

Native WinUI 3 operator client for the existing ELIOT Governor. It is a thin
renderer/controller over the authenticated named-pipe contract; it has no
database credentials, HTTP listener, browser surface, shell, scheduler, or
independent authoritative cache.

## Toolchain

Pinned toolchain, taken from the four sources the identity is compared across
and not from memory:

- **Project metadata** — `Eliot.Operator.csproj`: `TargetFramework`
  `net10.0-windows10.0.19041.0`, `TargetPlatformMinVersion` `10.0.17763.0`,
  `Platforms`/`PlatformTarget` `x64`, `RuntimeIdentifier` `win-x64`,
  `WindowsPackageType` `None`, `SelfContained` `true`,
  `WindowsAppSDKSelfContained` `true`, `UseWinUI` `true`, and the single
  `PackageReference` `Microsoft.WindowsAppSDK` `Version` `2.3.1`.
- **Dependency lock** — `packages.lock.json`, under
  `dependencies."net10.0-windows10.0.19041"."Microsoft.WindowsAppSDK"`:
  `"type": "Direct"`, `"requested": "[2.3.1, )"`, `"resolved": "2.3.1"`.
- **Publish evidence** — `OPERATOR_BUILD_RECEIPT.json`, schema
  `eliot-operator-build-receipt-v2`, written into the publish directory by the
  `WriteOperatorBuildReceipt` MSBuild target
  (`Eliot.Operator.csproj`, `AfterTargets="Publish"`) which shells out to
  `scripts/write-operator-build-receipt.ps1`. The identity fields are
  `target_framework`, `runtime_identifier`, `platform`, `configuration`,
  `windows_app_sdk_version`, `restore_locked_mode`, `packages_lock_sha256`,
  `csproj_sha256`, `source_inputs[]`, `producer`, `contracts`, `sdk`, `build`,
  `artifact` and `artifacts`.
- **.NET SDK** — the resolved SDK is whatever `dotnet --version` reports for the
  machine; the project pins no SDK patch release and no README claim
  substitutes for `dotnet --version`. The publish receipt records the observed
  `sdk.dotnet_sdk` and `sdk.msbuild_version` instead of asserting one here.

Build and publish with an installed x64 .NET 10 SDK:

```powershell
dotnet restore apps/Eliot.Operator/Eliot.Operator.csproj --locked-mode
dotnet publish apps/Eliot.Operator/Eliot.Operator.csproj -c Release -r win-x64 --self-contained true -o dist/windows-x64/Eliot.Operator
```

**That publish command emits no publish evidence.** The
`WriteOperatorBuildReceipt` target is guarded by
`Condition="'$(OperatorBuildReceiptPath)' != ''"`, and the command above passes
no `OperatorBuildReceiptPath`, so the receipt is not produced and
`Get-VerifiedOperatorBuildReceipt`
(`scripts/build-eliot-windows-x64-release.ps1`) refuses the directory. The
evidence-producing path is the release builder, which owns the publish
directory, passes `-p:RestoreLockedMode=true` and
`-p:OperatorBuildReceiptPath=...`, and then verifies the result:

```powershell
pwsh -NoProfile -File scripts/build-eliot-windows-x64-release.ps1 -BuildOperator
```

### What is enforced about this identity, and what is not

Stated precisely, because a README that implies more enforcement than exists
is worse than one that states the gap:

- **Enforced.** `dotnet restore --locked-mode` fails with `NU1004` when the
  csproj `PackageReference` range stops matching the lock's `requested` range,
  so project-metadata-to-lock drift on the *requested* range cannot reach a
  build. The receipt is bound to the source commit by SHA-256 over the csproj,
  the lock and the protocol contract, and
  `Get-VerifiedOperatorBuildReceipt` re-derives those digests and compares
  `receipt.windows_app_sdk_version` against the csproj `PackageReference`
  before the publish directory is consumed.
- **Not enforced anywhere in this repository.** Nothing value-compares the
  lock's `resolved` version against the csproj `requested` version. Measured on
  the committed bytes: editing `resolved` to `2.2.0` while leaving
  `requested` as `[2.3.1, )` still restores with `--locked-mode` at exit 0,
  and the receipt binds the lock by digest alone, so the digest agrees with
  whatever the lock says. Closing that needs a value comparison in
  `scripts/write-operator-build-receipt.ps1` or in
  `Get-VerifiedOperatorBuildReceipt`; `scripts/**` is outside this project's
  mutable scope, so the gap is recorded here rather than papered over.

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
