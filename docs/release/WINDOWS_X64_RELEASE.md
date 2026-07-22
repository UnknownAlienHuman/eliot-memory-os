# Windows x64 Release

`scripts/build-eliot-windows-x64-release.ps1` stages an intentionally unsigned bundle containing the release governor, required Eliot.Operator publish output, config templates, integrations, plugins/skills, migrations, and operations/release runbooks. Its default output root is `%LOCALAPPDATA%\Eliot\packages`; `-OutputRoot` accepts an explicit absolute path or a repository-relative override.

Use `-PlanOnly` to inspect paths and contents without building or writing a bundle. Every real staging run requires `-OperatorSource <published-directory>` containing `Eliot.Operator.exe`; the script refuses a Governor-only package and refuses to overwrite an existing versioned bundle.

```powershell
$operatorPublish = Join-Path $env:LOCALAPPDATA 'Eliot\build\operator-publish'
$releaseRoot = Join-Path $env:LOCALAPPDATA 'Eliot\packages'
dotnet publish apps/Eliot.Operator/Eliot.Operator.csproj -c Release -r win-x64 `
  --self-contained false -o $operatorPublish
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/build-eliot-windows-x64-release.ps1 `
  -Version 0.1.0-rc1 -OutputRoot $releaseRoot -OperatorSource $operatorPublish
```

Verify an existing staged bundle without rebuilding or changing it:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File scripts/build-eliot-windows-x64-release.ps1 `
  -VerifyBundle (Join-Path $releaseRoot 'eliot-windows-x64-0.1.0-rc1-unsigned')
```

Staging requires a clean tracked source tree. Repository resources are enumerated from the pinned commit tree, and each file is filter-hashed against that commit both before and after copying; staged deletions, ignored, untracked, dirty-tracked, or concurrently changed content cannot enter the bundle under a false source attestation. Real staging always rebuilds the Governor from the unchanged pinned tree; `-SkipBuild` is rejected. The Governor executable is admitted only from the release directory reported by `cargo metadata`, which is normally outside OneDrive; Operator publish output is restricted to its runtime extension allowlist and excludes PDBs. Reparse points, secret-like filenames, private-key/provider/AWS/JWT signatures, Basic authorization, and credential assignments in text payloads are rejected before checksum generation and again during verification. Run `tests/release-security/run-tests.ps1` for the provider-free negative smoke.

`RELEASE.json` pins the exact Git source commit plus the Operator schema/protocol/hash and marks the bundle unsigned and unavailable for public distribution. `SHA256SUMS.json` repeats the source commit and inventories every staged file with SHA-256 and byte length; verification rejects a source-binding mismatch, missing file, changed file, duplicate/unsafe path, unmanifested payload, or secret-scan finding. The bundle is not suitable for public distribution until Authenticode signing and RFC3161 timestamping are complete. After signing, regenerate the hash manifest and verify every shipped PE file with `Get-AuthenticodeSignature`.

Upgrade is backup-gated: take and verify a fresh logical backup, complete the isolated restore/MCP drill, generate the production cutover manifest, and preserve the prior signed bundle, service command, config, and data root until the new release passes doctor and Operator smoke. Roll back with the exact commands in the reviewed cutover manifest; never delete either data root during the cutover window.
