[CmdletBinding()]
param(
    # NOTE: $Profile intentionally shadows the automatic PowerShell home-path
    # variable inside this script scope. Here it selects the closed
    # verification profile (issues #750, #3004). No other profile/command/ref
    # input exists; ValidateSet rejects arbitrary profile text.
    [ValidateSet('Quick', 'Review', 'MergeCompile')]
    [string] $Profile = 'Quick',
    [switch] $List,
    [switch] $SkipCargoCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Retired skip switch (issue #750): -SkipCargoCheck is explicitly rejected.
# No invocation carrying a skip may emit a passing result under any profile.
if ($SkipCargoCheck) {
    [Console]::Error.WriteLine('VERIFY_REJECTED: -SkipCargoCheck is retired and cannot yield a passing result. Run -Profile Quick, -Profile Review or -Profile MergeCompile without skips.')
    exit 1
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$architectureAudit = Join-Path $PSScriptRoot 'audit-architecture-boundaries.py'
$guardrailVerifier = Join-Path $PSScriptRoot 'verify-agent-guardrails.py'
$runtimeHygieneAudit = Join-Path $PSScriptRoot 'audit-runtime-source-hygiene.py'
$agentBridgeProtocolVerifier = Join-Path $PSScriptRoot 'verify-agent-bridge-protocol.py'
$agentRouteBundleVerifier = Join-Path $PSScriptRoot 'verify-agent-route-bundles.py'
$coreDaemonInventoryVerifier = Join-Path $PSScriptRoot 'verify-core-daemon-inventory.py'
$docsShardVerifier = Join-Path $PSScriptRoot 'docs_shards.py'
$docsRouter = Join-Path $PSScriptRoot 'docs_router.py'
$docsReader = Join-Path $PSScriptRoot 'docs_read.py'
$docCodeConformanceVerifier = Join-Path $PSScriptRoot 'verify-doc-code-conformance.py'
$docsEvidenceCheck = Join-Path $PSScriptRoot 'documentation_evidence_check.py'
$codeNavigation = Join-Path $PSScriptRoot 'code_navigation.py'
$docsClosureAudit = Join-Path $PSScriptRoot 'docs_closure_audit.py'
$standaloneCrates = Join-Path $PSScriptRoot 'verify-standalone-crates.py'
$dependencyPolicyVerifier = Join-Path $PSScriptRoot 'verify-dependency-policy.py'
$dependencyPolicyReceiptPath = Join-Path $repoRoot (
    Join-Path '.eliot' ('dependency-policy-run-{0}.json' -f [Guid]::NewGuid().ToString('N'))
)

# Sole ordered gate-definition owner (issues #750, #3004). Wrappers
# (Justfile, CI) select a closed profile only; they must not duplicate these
# commands. Quick = every gate this script ran on base, in base order.
# Review = the same oracle block, then the locked cargo tail in the exact
# issue order: metadata, fmt, check, clippy, test, deny. MergeCompile = the
# shared oracle block (with the standalone verifier in compile-only mode),
# then metadata, fmt, check, denominator, test-compile (no-run), bounded
# changed-package clippy with normal warning semantics, standalone compile,
# and locked Operator restore/build with zero test execution. Quick and Review
# behavior is unchanged. Each gate runs once per invocation.
$allGates = @(
    [pscustomobject]@{ Name = 'documentation-shards-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $docsShardVerifier self-test } },
    [pscustomobject]@{ Name = 'documentation-shards'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $docsShardVerifier verify --root $repoRoot } },
    [pscustomobject]@{ Name = 'documentation-routes-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $docsRouter self-test } },
    [pscustomobject]@{ Name = 'documentation-routes'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $docsRouter check --root $repoRoot } },
    [pscustomobject]@{ Name = 'documentation-read-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $docsReader self-test } },
    [pscustomobject]@{ Name = 'documentation-code-conformance-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $docCodeConformanceVerifier --self-test } },
    [pscustomobject]@{ Name = 'documentation-code-conformance'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $docCodeConformanceVerifier --root $repoRoot } },
    [pscustomobject]@{ Name = 'code-navigation-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $codeNavigation self-test } },
    [pscustomobject]@{ Name = 'code-navigation'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $codeNavigation check --root $repoRoot } },
    [pscustomobject]@{ Name = 'documentation-closure-audit'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $docsClosureAudit --root $repoRoot } },
    [pscustomobject]@{ Name = 'documentation-evidence-check-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $docsEvidenceCheck --self-test } },
    [pscustomobject]@{ Name = 'standalone-crates'; Profiles = @('Quick', 'Review'); Command = { python $standaloneCrates --root $repoRoot } },
    [pscustomobject]@{ Name = 'core-daemon-inventory-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $coreDaemonInventoryVerifier --self-test } },
    [pscustomobject]@{ Name = 'core-daemon-inventory'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $coreDaemonInventoryVerifier --root $repoRoot } },
    [pscustomobject]@{ Name = 'normative-pair'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { pwsh -NoProfile -File (Join-Path $PSScriptRoot 'verify-normative.ps1') } },
    [pscustomobject]@{ Name = 'dependency-policy-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $dependencyPolicyVerifier --self-test } },
    [pscustomobject]@{ Name = 'dependency-policy-offline'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $dependencyPolicyVerifier --root $repoRoot --profile offline-source --receipt-out $dependencyPolicyReceiptPath } },
    [pscustomobject]@{ Name = 'architecture-boundaries-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $architectureAudit --self-test } },
    [pscustomobject]@{ Name = 'architecture-boundaries'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $architectureAudit --root $repoRoot } },
    [pscustomobject]@{ Name = 'agent-guardrails-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $guardrailVerifier --self-test } },
    [pscustomobject]@{ Name = 'agent-guardrails'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $guardrailVerifier --root $repoRoot } },
    [pscustomobject]@{ Name = 'agent-route-bundles-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $agentRouteBundleVerifier --self-test } },
    [pscustomobject]@{ Name = 'agent-route-bundles'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $agentRouteBundleVerifier --root $repoRoot } },
    [pscustomobject]@{ Name = 'runtime-source-hygiene-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $runtimeHygieneAudit --self-test } },
    [pscustomobject]@{ Name = 'runtime-source-hygiene'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $runtimeHygieneAudit --root $repoRoot } },
    [pscustomobject]@{ Name = 'agent-bridge-protocol-self-test'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $agentBridgeProtocolVerifier --self-test } },
    [pscustomobject]@{ Name = 'agent-bridge-protocol'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $agentBridgeProtocolVerifier --root $repoRoot } },
    # Deviation note vs issue #750 text (which lists `cargo metadata --locked
    # --format-version 1` without --no-deps): this gate retains the base oracle
    # `cargo metadata --locked --no-deps --format-version 1`, identical to the
    # base script gate and the Justfile `metadata` recipe. Evidence: pinned
    # cargo 1.97.1 `cargo metadata --help` documents --locked, --no-deps and
    # --format-version 1 as supported stable flags (case 17: only proven flags),
    # and I18-27 forbids silently changing an owned oracle definition. Full
    # locked dependency resolution is still enforced by the --locked cargo
    # check/clippy/test gates plus the dependency-policy offline-source gate.
    [pscustomobject]@{ Name = 'cargo-metadata'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { $script:verifyMetadataJson = (cargo metadata --locked --no-deps --format-version 1 | Out-String) } },
    # To prevent Windows command-line limit failures (os error 206) when
    # cargo fmt passes all workspace files to rustfmt on deep worktree paths,
    # workspace packages are formatted in bounded batches with -p.
    [pscustomobject]@{
        Name = 'cargo-fmt'
        Profiles = @('Quick', 'Review', 'MergeCompile')
        Command = {
            if ([string]::IsNullOrWhiteSpace($script:verifyMetadataJson)) {
                $script:verifyMetadataJson = (cargo metadata --locked --no-deps --format-version 1 | Out-String)
            }
            $metadata = $script:verifyMetadataJson | ConvertFrom-Json
            $packages = @($metadata.packages | ForEach-Object { $_.name })
            if ($packages.Count -eq 0) {
                cargo fmt --check
                return
            }
            $batchSize = 16
            $fmtExit = 0
            for ($i = 0; $i -lt $packages.Count; $i += $batchSize) {
                $end = [Math]::Min($i + $batchSize - 1, $packages.Count - 1)
                $batch = @($packages[$i..$end])
                $pkgArgs = @()
                foreach ($p in $batch) {
                    $pkgArgs += '-p'
                    $pkgArgs += $p
                }
                cargo fmt --check @pkgArgs
                if ($LASTEXITCODE -ne 0) {
                    $fmtExit = $LASTEXITCODE
                }
            }
            if ($fmtExit -ne 0) {
                $global:LASTEXITCODE = $fmtExit
            }
        }
    },
    [pscustomobject]@{ Name = 'cargo-check-workspace'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { cargo check --locked --workspace --all-targets } },
    [pscustomobject]@{ Name = 'cargo-clippy-workspace'; Profiles = @('Review'); Command = { cargo clippy --locked --workspace --all-targets -- -D warnings } },
    [pscustomobject]@{ Name = 'cargo-test-workspace'; Profiles = @('Review'); Command = { cargo test --locked --workspace } },
    [pscustomobject]@{ Name = 'cargo-deny'; Profiles = @('Review'); Command = {
        # Review's "cargo deny check" contract is executed by the pinned private-copy runner.
        python $dependencyPolicyVerifier --root $repoRoot --profile current-advisories --receipt-out $dependencyPolicyReceiptPath
    } },
    # MergeCompile-only tail (accepted issue #3004). Review order above is
    # unchanged; these gates run only under -Profile MergeCompile.
    [pscustomobject]@{
        Name = 'cargo-denominator'
        Profiles = @('MergeCompile')
        Command = {
            # Deterministic denominator receipt derived at runtime from locked
            # cargo metadata plus the standalone/excluded discovery owner. No
            # hand-maintained package, target, binary, or standalone counts.
            if ([string]::IsNullOrWhiteSpace($script:verifyMetadataJson)) {
                $script:verifyMetadataJson = (cargo metadata --locked --no-deps --format-version 1 | Out-String)
            }
            $denominatorMetadata = $script:verifyMetadataJson | ConvertFrom-Json
            $denominatorPackages = @($denominatorMetadata.packages | Sort-Object -Property id)
            Write-Host "VERIFY_DENOMINATOR: workspace_packages=$($denominatorPackages.Count)"
            foreach ($denominatorPackage in $denominatorPackages) {
                $denominatorTargets = @($denominatorPackage.targets | Sort-Object -Property name | ForEach-Object { "$($_.kind -join '+'):$($_.name)" })
                Write-Host "VERIFY_DENOMINATOR_PACKAGE: $($denominatorPackage.id) manifest=$($denominatorPackage.manifest_path) targets=$($denominatorTargets -join ',')"
            }
            $denominatorStandalone = (python $standaloneCrates --root $repoRoot --list | Out-String)
            $denominatorListExit = $LASTEXITCODE
            if ($denominatorListExit -ne 0) {
                throw "standalone discovery list failed with exit $denominatorListExit"
            }
            foreach ($denominatorLine in ($denominatorStandalone -split "`n")) {
                $denominatorTrimmed = $denominatorLine.Trim()
                if (-not [string]::IsNullOrWhiteSpace($denominatorTrimmed)) {
                    Write-Host "VERIFY_DENOMINATOR_STANDALONE: $denominatorTrimmed"
                }
            }
        }
    },
    [pscustomobject]@{ Name = 'cargo-test-compile'; Profiles = @('MergeCompile'); Command = { cargo test --locked --workspace --all-targets --no-run } },
    [pscustomobject]@{
        Name = 'cargo-clippy-changed'
        Profiles = @('MergeCompile')
        Command = {
            # Bounded Clippy over directly changed workspace packages with
            # normal warning semantics: compilation errors block, existing
            # warnings are reported, and this profile claims no workspace lint
            # cleanliness and uses no `-D warnings` oracle. Changed files map
            # to packages by longest manifest-directory prefix from locked
            # metadata; root-wide inputs (workspace manifest/lock, toolchain,
            # workflows, scripts, config) or an unmappable candidate widen the
            # scope to the full workspace, which still covers every changed
            # package. Every selection carries its path-to-package reason.
            if ([string]::IsNullOrWhiteSpace($script:verifyMetadataJson)) {
                $script:verifyMetadataJson = (cargo metadata --locked --no-deps --format-version 1 | Out-String)
            }
            $clippyMetadata = $script:verifyMetadataJson | ConvertFrom-Json
            $clippyPackageByDir = @{}
            foreach ($clippyPackage in @($clippyMetadata.packages)) {
                $clippyPackageByDir[[IO.Path]::GetDirectoryName($clippyPackage.manifest_path)] = $clippyPackage.name
            }
            $clippyBase = ''
            if (-not [string]::IsNullOrWhiteSpace($env:MERGE_COMPILE_BASE_SHA) -and $env:MERGE_COMPILE_BASE_SHA -match '^[0-9a-fA-F]{40}$') {
                $clippyBase = $env:MERGE_COMPILE_BASE_SHA.Trim()
            } else {
                try {
                    $clippyBase = ((git merge-base HEAD origin/main) | Out-String).Trim()
                } catch {
                    $clippyBase = ''
                }
            }
            $clippyRootWide = @()
            $clippySelected = @{}
            if ([string]::IsNullOrWhiteSpace($clippyBase)) {
                $clippyRootWide += 'no base revision for changed-package mapping'
            } else {
                $clippyDiffRaw = (git diff --name-only $clippyBase HEAD | Out-String)
                $clippyDiffExit = $LASTEXITCODE
                if ($clippyDiffExit -ne 0) {
                    $clippyRootWide += 'change-set command failed; widened to workspace'
                } else {
                    $clippyChanged = @($clippyDiffRaw -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                    if ($clippyChanged.Count -eq 0) {
                        $clippyRootWide += 'empty change set against base; selection unprovable'
                    }
                    foreach ($clippyFile in $clippyChanged) {
                        $clippyAbsolute = Join-Path $repoRoot $clippyFile
                        $clippyMatched = $null
                        $clippyBest = -1
                        foreach ($clippyDir in $clippyPackageByDir.Keys) {
                            if ($clippyAbsolute.StartsWith($clippyDir + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase) -and $clippyDir.Length -gt $clippyBest) {
                                $clippyBest = $clippyDir.Length
                                $clippyMatched = $clippyDir
                            }
                        }
                        if ($null -eq $clippyMatched) {
                            $clippyRootWide += "root-wide input: $clippyFile"
                        } else {
                            $clippyName = $clippyPackageByDir[$clippyMatched]
                            if (-not $clippySelected.ContainsKey($clippyName)) {
                                $clippySelected[$clippyName] = @()
                            }
                            $clippySelected[$clippyName] += $clippyFile
                        }
                    }
                }
            }
            if ($clippyRootWide.Count -gt 0 -or $clippySelected.Count -eq 0) {
                foreach ($clippyReason in $clippyRootWide) {
                    Write-Host "VERIFY_CLIPPY_SELECTION: scope=workspace reason=$clippyReason"
                }
                if ($clippySelected.Count -eq 0) {
                    Write-Host 'VERIFY_CLIPPY_SELECTION: scope=workspace reason=no changed workspace package mapped'
                }
                cargo clippy --locked --workspace --all-targets --no-deps
            } else {
                $clippyOrdered = @($clippySelected.Keys | Sort-Object)
                foreach ($clippyName in $clippyOrdered) {
                    Write-Host "VERIFY_CLIPPY_SELECTION: scope=changed package=$clippyName reasons=$($clippySelected[$clippyName] -join ';')"
                }
                $clippyPackageArgs = @()
                foreach ($clippyName in $clippyOrdered) {
                    $clippyPackageArgs += '-p'
                    $clippyPackageArgs += $clippyName
                }
                cargo clippy --locked @clippyPackageArgs --all-targets --no-deps
            }
        }
    },
    [pscustomobject]@{ Name = 'standalone-crates-compile'; Profiles = @('MergeCompile'); Command = { python $standaloneCrates --root $repoRoot --mode compile } },
    [pscustomobject]@{
        Name = 'dotnet-restore-operator'
        Profiles = @('MergeCompile')
        Command = {
            dotnet restore apps/Eliot.Operator/Eliot.Operator.csproj --locked-mode
            if ($LASTEXITCODE -ne 0) {
                throw 'dotnet restore Eliot.Operator failed'
            }
            dotnet restore tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj --locked-mode
            if ($LASTEXITCODE -ne 0) {
                throw 'dotnet restore Eliot.Operator.Tests failed'
            }
        }
    },
    [pscustomobject]@{
        Name = 'dotnet-build-operator'
        Profiles = @('MergeCompile')
        Command = {
            dotnet build apps/Eliot.Operator/Eliot.Operator.csproj -c Release --no-restore
            if ($LASTEXITCODE -ne 0) {
                throw 'dotnet build Eliot.Operator failed'
            }
            dotnet build tests/Eliot.Operator.Tests/Eliot.Operator.Tests.csproj -c Release --no-restore
            if ($LASTEXITCODE -ne 0) {
                throw 'dotnet build Eliot.Operator.Tests failed'
            }
        }
    }
)

$profileExplicit = $PSBoundParameters.ContainsKey('Profile')

# List/configuration mode is read-only: it prints gate definitions and never
# claims execution. Bare -List covers all closed profiles.
if ($List) {
    $listProfiles = if ($profileExplicit) { @($Profile) } else { @('Quick', 'Review', 'MergeCompile') }
    Write-Host 'VERIFY_PROFILES: Quick, Review, MergeCompile'
    foreach ($listed in $listProfiles) {
        $names = @($allGates | Where-Object { $_.Profiles -contains $listed } | ForEach-Object { $_.Name })
        Write-Host "VERIFY_PROFILE: $listed ($($names.Count) gates)"
        foreach ($gateName in $names) {
            Write-Host "VERIFY_GATE_DEF: $listed $gateName"
        }
    }
    Write-Host 'VERIFY_LIST_READONLY: configuration only; no gate was executed and no result is claimed.'
    exit 0
}

# Structural self-guard: duplicate gate names would silently double-run.
$duplicateNames = @($allGates | Group-Object -Property Name | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name })
if ($duplicateNames.Count -gt 0) {
    [Console]::Error.WriteLine("VERIFY_DEFINITION_FAILURE: duplicate gate names: $($duplicateNames -join ', ')")
    exit 1
}

$selectedGates = @($allGates | Where-Object { $_.Profiles -contains $Profile })
if ($selectedGates.Count -eq 0) {
    [Console]::Error.WriteLine("VERIFY_DEFINITION_FAILURE: profile '$Profile' selects no gates.")
    exit 1
}

# Exact already-produced run evidence reused for the summary denominator.
$script:verifyMetadataJson = ''
$workspaceMembers = 'unproven'

# Source/tool identities bound into the summary. Git, cargo and Python
# best-effort probes never fabricate an identity; cargo-deny comes from the
# digest-pinned verifier receipt below.
$sourceSha = 'unknown'
try {
    $sourceSha = ((git rev-parse HEAD) | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($sourceSha)) { $sourceSha = 'unknown' }
} catch {
    $sourceSha = 'unknown'
}
$cargoIdentity = 'unavailable'
try {
    $cargoIdentity = ((cargo --version) | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($cargoIdentity)) { $cargoIdentity = 'unavailable' }
} catch {
    $cargoIdentity = 'unavailable'
}
$pythonIdentity = 'unavailable'
try {
    $pythonIdentity = ((python --version) | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($pythonIdentity)) { $pythonIdentity = 'unavailable' }
} catch {
    $pythonIdentity = 'unavailable'
}
$denyIdentity = 'unverified-by-pinned-policy-runner'

$results = @()
$harnessState = 'pass'
$harnessError = ''

Push-Location $repoRoot
try {
    $position = 0
    foreach ($gate in $selectedGates) {
        $position++
        Write-Host "VERIFY_STEP: [$position/$($selectedGates.Count)] $($gate.Name)"
        # Reset per gate: a stale LASTEXITCODE must never mask the next gate,
        # and a gate that raises must never be read as success.
        $LASTEXITCODE = 0
        $gateWatch = [System.Diagnostics.Stopwatch]::StartNew()
        $state = 'pass'
        $exitCode = 0
        $gateError = ''
        try {
            if ($null -eq $gate.Command) {
                $state = 'skipped-undefined'
                $exitCode = -1
            } else {
                & $gate.Command
                $exitCode = $LASTEXITCODE
                if ($exitCode -ne 0) {
                    $state = 'fail-exit'
                }
            }
        } catch [System.Management.Automation.PipelineStoppedException] {
            $state = 'cancelled'
            $exitCode = -1
            $gateError = $_.Exception.Message
        } catch {
            # Missing tool, failing assertion, or any other PowerShell
            # exception: distinct nonpassing state, never green.
            $state = 'fail-exception'
            $exitCode = -1
            $gateError = $_.Exception.Message
        }
        $gateWatch.Stop()
        $results += [pscustomobject]@{
            Name       = $gate.Name
            State      = $state
            ExitCode   = $exitCode
            DurationMs = $gateWatch.ElapsedMilliseconds
        }
        Write-Host "VERIFY_GATE: $($gate.Name) $state exit=$exitCode ms=$($gateWatch.ElapsedMilliseconds)"
        if ($state -eq 'fail-exception' -or $state -eq 'cancelled') {
            Write-Host "VERIFY_GATE_ERROR: $($gate.Name) $gateError"
        }
        if ($gate.Name -eq 'cargo-metadata' -and $state -eq 'pass') {
            try {
                $metadata = $script:verifyMetadataJson | ConvertFrom-Json
                $workspaceMembers = "$($metadata.packages.Count)"
            } catch {
                $workspaceMembers = 'unproven'
            }
        }
        if ($state -ne 'pass') {
            for ($rest = $position; $rest -lt $selectedGates.Count; $rest++) {
                $results += [pscustomobject]@{
                    Name       = $selectedGates[$rest].Name
                    State      = 'not-run'
                    ExitCode   = -1
                    DurationMs = 0
                }
            }
            break
        }
    }
} catch {
    $harnessState = 'harness-error'
    $harnessError = $_.Exception.Message
    foreach ($gate in $selectedGates) {
        if (@($results | Where-Object { $_.Name -eq $gate.Name }).Count -eq 0) {
            $results += [pscustomobject]@{
                Name       = $gate.Name
                State      = 'not-run'
                ExitCode   = -1
                DurationMs = 0
            }
        }
    }
} finally {
    Pop-Location
}

# Report scanner identity only from the policy verifier's checked receipt.
# This script does not choose trust from PATH. The verifier may use PATH to
# locate a candidate, but executes only digest-pinned bytes after identity
# checks, through a private verified copy.
$receiptCleanupState = 'pass'
try {
    if (Test-Path -LiteralPath $dependencyPolicyReceiptPath -PathType Leaf) {
        $dependencyReceipt = Get-Content -LiteralPath $dependencyPolicyReceiptPath -Raw | ConvertFrom-Json
        $receiptProperties = @($dependencyReceipt.PSObject.Properties.Name)
        $scannerReceipt = if ($receiptProperties -contains 'scanner') { $dependencyReceipt.scanner } else { $null }
        $scannerProperties = if ($null -ne $scannerReceipt) { @($scannerReceipt.PSObject.Properties.Name) } else { @() }
        $expectedReceiptProfile = if ($Profile -eq 'Review') { 'current-advisories' } else { 'offline-source' }
        $observedDenyVersion = if ($scannerProperties -contains 'observed_version') { [string]$scannerReceipt.observed_version } else { '' }
        $observedDenyDigest = if ($scannerProperties -contains 'observed_executable_sha256') { [string]$scannerReceipt.observed_executable_sha256 } else { '' }
        $receiptSource = if ($receiptProperties -contains 'source_sha') { [string]$dependencyReceipt.source_sha } else { '' }
        if (
            $receiptSource -eq $sourceSha -and
            $dependencyReceipt.profile -eq $expectedReceiptProfile -and
            $scannerProperties -contains 'identity_verified' -and
            $scannerReceipt.identity_verified -eq $true -and
            -not [string]::IsNullOrWhiteSpace($observedDenyVersion) -and
            $observedDenyDigest -match '^[0-9a-fA-F]{64}$'
        ) {
            $denyIdentity = "$observedDenyVersion sha256:$observedDenyDigest"
        }
    }
} catch {
    $denyIdentity = 'unverified-by-pinned-policy-runner'
} finally {
    try {
        if (Test-Path -LiteralPath $dependencyPolicyReceiptPath) {
            if (-not (Test-Path -LiteralPath $dependencyPolicyReceiptPath -PathType Leaf)) {
                throw 'dependency-policy temporary receipt path is not a file'
            }
            Remove-Item -LiteralPath $dependencyPolicyReceiptPath -Force -ErrorAction Stop
        }
    } catch {
        $receiptCleanupState = 'fail'
        $harnessState = 'harness-error'
        if ([string]::IsNullOrWhiteSpace($harnessError)) {
            $harnessError = 'dependency-policy temporary receipt cleanup failed'
        } else {
            $harnessError += '; dependency-policy temporary receipt cleanup failed'
        }
    }
}

$passedCount = @($results | Where-Object { $_.State -eq 'pass' }).Count
$failedCount = @($results | Where-Object { $_.State -ne 'pass' -and $_.State -ne 'not-run' }).Count
$notRunCount = @($results | Where-Object { $_.State -eq 'not-run' }).Count
$overall = if ($failedCount -eq 0 -and $harnessState -eq 'pass') { 'PASS' } else { 'FAIL' }

if ($Profile -eq 'Quick') {
    $proofCeiling = 'QUICK_ONLY: bounded repository/document/source oracle check. Not Review, not release, not Product-Pulse proof.'
} elseif ($Profile -eq 'MergeCompile') {
    $proofCeiling = 'MERGE_COMPILE_SOURCE_ONLY: locked compile-only merge check on this candidate only. Zero test execution, no lint-cleanliness claim. Not Review, not release/source-candidate, not installed-runtime/store/Product-Pulse proof.'
} else {
    $proofCeiling = 'REVIEW_SOURCE_ONLY: complete locked Review on this candidate only. Not release/source-candidate, not installed-runtime/store/Product-Pulse proof.'
}

# Bounded, redacted summary: identities, gate states, ceilings. No command
# output, no environment content, never credentials.
$summaryLines = @(
    "VERIFY_RESULT: $overall profile=$Profile source=$sourceSha gates=$($selectedGates.Count) passed=$passedCount failed=$failedCount not-run=$notRunCount",
    "VERIFY_WORKSPACE_MEMBERS: $workspaceMembers (cargo metadata --locked --no-deps)",
    "VERIFY_TOOLCHAIN: $cargoIdentity / $pythonIdentity / deny=$denyIdentity",
    "VERIFY_POLICY_RECEIPT_CLEANUP: $receiptCleanupState",
    'VERIFY_CACHE: workflow-owned only; this script implements no gate cache, so a cache hit cannot skip a gate or supply a pass receipt',
    "VERIFY_PROOF_CEILING: $proofCeiling",
    'VERIFY_DINT_CEILING: ignored/stateful/live-provider tests are outside the normal Quick/Review/MergeCompile profiles (D-INT family issues 905/907/909/911/913/915); this result covers none of them',
    'VERIFY_QUARANTINE: cargo/dotnet gates (cargo-fmt/cargo-check-workspace/cargo-clippy-workspace/cargo-test-workspace/cargo-denominator/cargo-test-compile/cargo-clippy-changed/standalone-crates-compile/dotnet-restore-operator/dotnet-build-operator) execute the quarantined legacy lane with no governed profile receipt (issue #1813 W6); thin-invoker migration awaits W4 stage-execution provisions'
)
if ($harnessState -ne 'pass') {
    $summaryLines += "VERIFY_HARNESS: $harnessState $harnessError"
}
$nonPassing = @($results | Where-Object { $_.State -ne 'pass' } | ForEach-Object { "$($_.Name)=$($_.State)" })
if ($nonPassing.Count -gt 0) {
    $summaryLines += "VERIFY_NONPASSING: $($nonPassing -join ', ')"
}
foreach ($line in $summaryLines) {
    Write-Host $line
}
try {
    $stepSummaryPath = $env:GITHUB_STEP_SUMMARY
    if (-not [string]::IsNullOrWhiteSpace($stepSummaryPath) -and (Test-Path -LiteralPath $stepSummaryPath -PathType Leaf)) {
        Add-Content -LiteralPath $stepSummaryPath -Value ($summaryLines -join "`n")
    }
} catch {
    Write-Host "VERIFY_SUMMARY_MIRROR_UNAVAILABLE: $($_.Exception.Message)"
}

if ($overall -eq 'PASS') {
    exit 0
} else {
    exit 1
}
