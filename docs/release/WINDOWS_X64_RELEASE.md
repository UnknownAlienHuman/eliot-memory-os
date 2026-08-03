# Windows x64 Release

`scripts/build-eliot-windows-x64-release.ps1` stages an intentionally unsigned bundle containing the release governor, required Eliot.Operator publish output, config templates, canonical host integration packages, shared skills, migrations, and operations/release runbooks. Host plugins live under their owning `integrations/<host>` tree; the bundle does not create a second top-level plugin copy. The Codex surface is a self-contained local marketplace at `integrations/codex/marketplace.json` with its plugin at `integrations/codex/plugins/eliot-governor` and the release Governor copied into that plugin's `bin` directory. Its default output root is `%LOCALAPPDATA%\Eliot\packages`; `-OutputRoot` accepts an explicit absolute path or a repository-relative override.

Use `-PlanOnly` to inspect paths and contents without building or writing a bundle. Every real staging run requires `-OperatorSource <published-directory>` containing `Eliot.Operator.exe`; the script refuses a Governor-only package and refuses to overwrite an existing versioned bundle.

The Codex marketplace declares `eliot-governor` as `INSTALLED_BY_DEFAULT`. Its sole MCP server is `eliot`, resolves `bin/eliot-governor.exe` relative to the plugin root, and starts the `codex_controller` profile for every project. The plugin command deliberately omits `--host`; live session binding remains the authority for host identity. Codex discovers `hooks/hooks.json` by convention, so the plugin manifest does not carry the unsupported `hooks` field.

The tracked and released `plugin.json` is cache-neutral: its version is the base SemVer, currently `0.1.0`, with no `+codex` build metadata. `PlanOnly` reports this as `codex_plugin_base_version`, and `RELEASE.json` records the same value. The installer must not rewrite either source or release payload. It materializes only its ELIOT-owned personal-plugin copy as `<base-version>+codex.<deterministic-content-token>` before invoking the Codex plugin lifecycle. The token is stable for the complete Codex cache contract and changes when the bundled Governor, MCP, hooks, skills, or plugin metadata change. Codex executes the SHA-256-verified Governor inside that immutable cache, so a binary-only update receives a new add-only version. A timestamp-only token is reserved for manual local-development iteration.

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

Staging requires a clean tracked source tree. Repository resources are enumerated from the pinned commit tree, and each file is filter-hashed against that commit both before and after copying; staged deletions, ignored, untracked, dirty-tracked, or concurrently changed content cannot enter the bundle under a false source attestation. Real staging always rebuilds the Governor from the unchanged pinned tree; `-SkipBuild` is rejected. The Governor executable is admitted only from the release directory reported by `cargo metadata`, which is normally outside OneDrive; Operator publish output is restricted to its runtime extension allowlist and excludes PDBs. A pinned OneDrive source file is accepted only when it is resident and exposes neither a link target nor offline/unpinned/recall attributes. Every copied bundle entry must still be a regular non-reparse file. Secret-like filenames, private-key/provider/AWS/JWT signatures, Basic authorization, and credential assignments in text payloads are rejected before checksum generation and again during verification. Run `tests/release-security/run-tests.ps1` for the provider-free negative smoke.

`RELEASE.json` pins the exact Git source commit, the cache-neutral `codex_plugin_base_version`, and the Operator schema/protocol/hash, and marks the bundle unsigned and unavailable for public distribution. `SHA256SUMS.json` repeats the source commit and inventories every staged file with SHA-256 and byte length; verification rejects a source-binding mismatch, missing file, changed file, duplicate/unsafe path, unmanifested payload, secret-scan finding, malformed Codex marketplace/plugin metadata, a release plugin version containing `+codex` metadata or differing from `RELEASE.json`, a non-controller MCP profile, or a plugin binary whose hash differs from the root Governor. The bundle is not suitable for public distribution until Authenticode signing and RFC3161 timestamping are complete. After signing, regenerate the hash manifest and verify every shipped PE file with `Get-AuthenticodeSignature`.

Upgrade is backup-gated: take and verify a fresh logical backup, complete the isolated restore/MCP drill, generate the production cutover manifest, and preserve the prior signed bundle, service command, config, and data root until the new release passes doctor and Operator smoke. Roll back with the exact commands in the reviewed cutover manifest; never delete either data root during the cutover window.
