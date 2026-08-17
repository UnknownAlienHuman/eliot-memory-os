# ELIOT Operator

Native WinUI 3 operator client for the existing ELIOT Governor. It is a thin renderer/controller over the authenticated named-pipe contract; it has no database credentials, HTTP listener, browser surface, shell, or independent authoritative cache.

Pinned toolchain:

- .NET 10 SDK, x64
- `Microsoft.WindowsAppSDK` `2.2.0` stable
- unpackaged, self-contained `win-x64`

Build and verify with the installed x64 .NET SDK `10.0.302`:

```powershell
dotnet publish apps/Eliot.Operator/Eliot.Operator.csproj -c Release -r win-x64 --self-contained true -o dist/windows-x64/Eliot.Operator
```

The app consumes only the inherited one-shot `ELIOT_OPERATOR_ENDPOINT`, clears it immediately after parsing, validates the exact `human_operator` capability set, and connects with `NamedPipeClientStream`. It does not discover publication, authentication-reference, token, or Governor files and does not replay a consumed nonce.

The L8 live smoke loaded canonical task cognition, displayed exactly one autonomy
run, and drove `DRAFT -> RUNNING -> PAUSED_BY_OPERATOR -> RUNNING` through typed
Governor commands. A later daemon/auth rotation reconnected through one
`Connect / Refresh` and preserved `RUNNING @ revision 4`; a stale token/generation
was rejected.

The publish target explicitly copies generated `.pri` and `.xbf` resources because
plain `dotnet publish` otherwise produced an executable that failed during XAML
activation. Current UI debt is presentation-only: several projections are raw
JSON-first, and contour reassignment/approvals/incidents were not exercised in the
bounded L8 run.
