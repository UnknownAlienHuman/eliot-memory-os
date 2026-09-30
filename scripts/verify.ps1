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
$donorDispositions = Join-Path $PSScriptRoot 'verify-cognitive-donor-dispositions-816.py'
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
    [pscustomobject]@{ Name = 'cognitive-donor-dispositions'; Profiles = @('Quick', 'Review'); Command = { python $donorDispositions --root $repoRoot } },
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
            # Reuse the exact locked metadata and standalone/excluded discovery
            # producers. Counts and manifest paths are always derived at runtime.
            if ([string]::IsNullOrWhiteSpace($script:verifyMetadataJson)) {
                $script:verifyMetadataJson = (cargo metadata --locked --no-deps --format-version 1 | Out-String)
            }
            try {
                $denominatorMetadata = $script:verifyMetadataJson | ConvertFrom-Json
            } catch {
                throw "cargo metadata output could not be parsed: $($_.Exception.Message)"
            }
            if ($null -eq $denominatorMetadata -or $null -eq $denominatorMetadata.packages) {
                throw 'cargo metadata package denominator is unavailable'
            }
            $denominatorPackages = @($denominatorMetadata.packages | Sort-Object -Property id)
            $script:verifyDenominatorWorkspacePackages = @(
                foreach ($denominatorPackage in $denominatorPackages) {
                    if ([string]::IsNullOrWhiteSpace([string]$denominatorPackage.id) -or [string]::IsNullOrWhiteSpace([string]$denominatorPackage.manifest_path) -or $null -eq $denominatorPackage.targets) {
                        throw 'cargo metadata package omitted its ID, manifest path, or targets'
                    }
                    $relativeManifestPath = [System.IO.Path]::GetRelativePath($repoRoot, [string]$denominatorPackage.manifest_path).Replace('\', '/')
                    $targetRecords = @(
                        foreach ($target in @($denominatorPackage.targets | Sort-Object -Property name)) {
                            if ([string]::IsNullOrWhiteSpace([string]$target.name) -or $null -eq $target.kind -or @($target.kind).Count -eq 0) {
                                throw "cargo metadata target omitted its kind or name for package $($denominatorPackage.id)"
                            }
                            $targetKinds = @($target.kind | Sort-Object)
                            [pscustomobject][ordered]@{ kind = $targetKinds; name = [string]$target.name }
                        }
                    )
                    [pscustomobject][ordered]@{
                        package_id = [string]$denominatorPackage.id
                        package_name = [string]$denominatorPackage.name
                        manifest_path = $relativeManifestPath
                        targets = $targetRecords
                    }
                }
            )
            $denominatorStandaloneOutput = @(& python $standaloneCrates --root $repoRoot --list 2>&1)
            $denominatorListExit = $LASTEXITCODE
            if ($denominatorListExit -ne 0) {
                throw "standalone discovery list failed with exit $denominatorListExit"
            }
            $standaloneManifestPaths = @()
            $excludedManifestPaths = @()
            $discoveredManifestPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($denominatorLine in $denominatorStandaloneOutput) {
                $denominatorTrimmed = ([string]$denominatorLine).Trim()
                if ([string]::IsNullOrWhiteSpace($denominatorTrimmed)) { continue }
                $isExcluded = $denominatorTrimmed.StartsWith('exclude: ', [StringComparison]::Ordinal)
                if ($denominatorTrimmed.StartsWith('exclude:', [StringComparison]::Ordinal) -and -not $isExcluded) {
                    throw "standalone discovery emitted a malformed excluded row: $denominatorTrimmed"
                }
                $relativeDirectory = if ($isExcluded) { $denominatorTrimmed.Substring(9) } else { $denominatorTrimmed }
                if ([string]::IsNullOrWhiteSpace($relativeDirectory) -or [System.IO.Path]::IsPathRooted($relativeDirectory) -or $relativeDirectory.Contains('\') -or $relativeDirectory -match '(^|/)\.\.?(/|$)') {
                    throw "standalone discovery emitted a malformed repository-relative path: $denominatorTrimmed"
                }
                $manifestPath = "$relativeDirectory/Cargo.toml"
                if (-not $discoveredManifestPaths.Add($manifestPath)) {
                    throw "standalone discovery repeated a manifest path: $manifestPath"
                }
                if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $manifestPath) -PathType Leaf)) {
                    throw "standalone discovery manifest is unavailable: $manifestPath"
                }
                if ($isExcluded) {
                    $excludedManifestPaths += $manifestPath
                } else {
                    $standaloneManifestPaths += $manifestPath
                }
                Write-Host "VERIFY_DENOMINATOR_STANDALONE: $denominatorTrimmed"
            }
            $script:verifyDenominatorStandaloneManifests = @($standaloneManifestPaths | Sort-Object -CaseSensitive)
            $script:verifyDenominatorExcludedManifests = @($excludedManifestPaths | Sort-Object -CaseSensitive)
            Write-Host "VERIFY_DENOMINATOR: workspace_packages=$($script:verifyDenominatorWorkspacePackages.Count)"
            foreach ($denominatorPackage in $script:verifyDenominatorWorkspacePackages) {
                $denominatorTargets = @($denominatorPackage.targets | ForEach-Object { "$($_.kind -join '+'):$($_.name)" })
                Write-Host "VERIFY_DENOMINATOR_PACKAGE: $($denominatorPackage.package_id) manifest=$($denominatorPackage.manifest_path) targets=$($denominatorTargets -join ',')"
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
            # metadata; root-wide inputs or an unmappable candidate widen the
            # scope to the full workspace. The receipt records this same mapping.
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
            $clippyRootWideInputs = @()
            $clippySelected = @{}
            $clippySelectionReasons = @{}
            if ([string]::IsNullOrWhiteSpace($clippyBase)) {
                $clippyRootWide += 'no base revision for changed-package mapping'
                $clippyRootWideInputs += [pscustomobject][ordered]@{ path = $null; reason = 'no base revision for changed-package mapping' }
            } else {
                $clippyDiffRaw = (git diff --name-only $clippyBase HEAD | Out-String)
                $clippyDiffExit = $LASTEXITCODE
                if ($clippyDiffExit -ne 0) {
                    $clippyRootWide += 'change-set command failed; widened to workspace'
                    $clippyRootWideInputs += [pscustomobject][ordered]@{ path = $null; reason = 'change-set command failed; widened to workspace' }
                } else {
                    $clippyChanged = @($clippyDiffRaw -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' })
                    if ($clippyChanged.Count -eq 0) {
                        $clippyRootWide += 'empty change set against base; selection unprovable'
                        $clippyRootWideInputs += [pscustomobject][ordered]@{ path = $null; reason = 'empty change set against base; selection unprovable' }
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
                            $clippyRootWideInputs += [pscustomobject][ordered]@{ path = $clippyFile; reason = 'no workspace manifest-directory prefix matched; widened to workspace' }
                        } else {
                            $clippyName = $clippyPackageByDir[$clippyMatched]
                            if (-not $clippySelected.ContainsKey($clippyName)) {
                                $clippySelected[$clippyName] = @()
                                $clippySelectionReasons[$clippyName] = @()
                            }
                            $clippySelected[$clippyName] += $clippyFile
                            $matchedManifestDirectory = [IO.Path]::GetRelativePath($repoRoot, $clippyMatched).Replace('\', '/')
                            $clippySelectionReasons[$clippyName] += [pscustomobject][ordered]@{
                                path = $clippyFile
                                reason = "longest workspace manifest-directory prefix matched $matchedManifestDirectory"
                            }
                        }
                    }
                }
            }

            $clippyOrdered = @($clippySelected.Keys | Sort-Object)
            $changedPackageSelection = @(
                foreach ($clippyName in $clippyOrdered) {
                    $packageIds = @($clippyMetadata.packages | Where-Object { $_.name -eq $clippyName } | ForEach-Object { [string]$_.id } | Sort-Object)
                    if ($packageIds.Count -ne 1) {
                        $fallbackReason = "selected package name '$clippyName' matched $($packageIds.Count) cargo metadata package IDs; widened to workspace"
                        $clippyRootWide += $fallbackReason
                        $clippyRootWideInputs += [pscustomobject][ordered]@{ path = $null; reason = $fallbackReason }
                        continue
                    }
                    [pscustomobject][ordered]@{
                        package_name = $clippyName
                        package_ids = $packageIds
                        changed_paths = @($clippySelectionReasons[$clippyName])
                    }
                }
            )
            $clippyScope = if ($clippyRootWide.Count -gt 0 -or $clippySelected.Count -eq 0) { 'workspace' } else { 'changed' }
            if ($clippySelected.Count -eq 0) {
                $clippyRootWideInputs += [pscustomobject][ordered]@{ path = $null; reason = 'no changed workspace package mapped; widened to workspace' }
            }
            $denominatorReceipt = [pscustomobject][ordered]@{
                workspace_packages = @($script:verifyDenominatorWorkspacePackages)
                standalone_manifests = @($script:verifyDenominatorStandaloneManifests)
                excluded_manifests = @($script:verifyDenominatorExcludedManifests)
                base_revision = if ([string]::IsNullOrWhiteSpace($clippyBase)) { $null } else { $clippyBase }
                clippy_scope = $clippyScope
                changed_package_selection = $changedPackageSelection
                root_wide_inputs = $clippyRootWideInputs
            }
            $receiptJson = $denominatorReceipt | ConvertTo-Json -Depth 8 -Compress
            [Console]::Out.WriteLine("VERIFY_DENOMINATOR_RECEIPT: $receiptJson")

            if ($clippyRootWide.Count -gt 0 -or $clippySelected.Count -eq 0) {
                foreach ($clippyReason in $clippyRootWide) {
                    Write-Host "VERIFY_CLIPPY_SELECTION: scope=workspace reason=$clippyReason"
                }
                if ($clippySelected.Count -eq 0) {
                    Write-Host 'VERIFY_CLIPPY_SELECTION: scope=workspace reason=no changed workspace package mapped'
                }
                cargo clippy --locked --workspace --all-targets --no-deps
            } else {
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

# Versioned profile admission (issue #1914 W2/W4, I18.21:3). This script stays
# the ONE ordered gate-definition owner: the table above is still the only place
# a gate command is written down, and nothing below selects or reorders a gate.
# What this seam adds is the one thing the table cannot express: the profile
# ADMISSION decision, which the shared Rust resolver owns.
#
# The resolver named here is `eliot-profile-resolver`, the production entry of
# `eliot-instrument-runner`. It resolves the closed profile ALIAS below through
# `resolve_verification_route` — the same function the CI step calls with the
# same alias — and issues the shared `VerificationProfileReceipt`. So "local
# profile revision == CI profile revision" has a computed value on both sides
# rather than being asserted in prose, and a refusal here (an unadmitted alias,
# a missing executable identity, or an absent provenance receipt) stops the run
# before a single gate executes rather than after.
#
# The three PowerShell profiles map onto the two admitted verification routes:
# Quick and Review are package-scoped source verification, MergeCompile is
# package-scoped compile-only verification. The mapping is declared here, once,
# as data — not as a command list — and the resolver refuses any alias outside
# the closed table it owns.
$verificationRouteAliases = @{
    'Quick'        = 'package-verification'
    'Review'       = 'package-verification'
    'MergeCompile' = 'package-verification'
}
$verificationRouteAlias = $verificationRouteAliases[$Profile]
$profileResolver = 'eliot-profile-resolver'
$profileResolverSource = 'crates/instrument/eliot-instrument-runner/src/bin/eliot-profile-resolver.rs'
$profileReceiptPath = Join-Path $repoRoot (Join-Path '.eliot' ('verification-profile-{0}.json' -f [Guid]::NewGuid().ToString('N')))

# Admit the profile through the shared resolver. A missing or unbuildable
# resolver is a fail-closed outcome: without it this run has no versioned
# profile revision to report, and reporting one it did not resolve would be
# exactly the hidden-command-list divergence I18.21:11 forbids.
$resolverCommand = Get-Command $profileResolver -CommandType Application -ErrorAction SilentlyContinue
if ($null -eq $resolverCommand) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: the shared profile resolver '$profileResolver' ($profileResolverSource) is not on PATH; build the ELIOT verifier/runner bootstrap first (I18.21:14).")
    exit 1
}
$resolverTargetRoot = Join-Path $repoRoot '.eliot'
if (-not (Test-Path -LiteralPath $resolverTargetRoot -PathType Container)) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: the resolver needs an existing target root at '$resolverTargetRoot' for its admitted layout.")
    exit 1
}
$resolverArgs = @(
    '--alias', $verificationRouteAlias,
    '--source-root', $repoRoot,
    '--target-root', $resolverTargetRoot,
    '--cache-root', (Join-Path $repoRoot '.cargo'),
    '--declared-environment', "eliot-verify-profile-$Profile",
    '--receipt-out', $profileReceiptPath
)
$resolverOutput = @(& $resolverCommand.Source @resolverArgs 2>&1)
$resolverExit = $LASTEXITCODE
foreach ($resolverLine in $resolverOutput) { Write-Host "VERIFY_PROFILE_RESOLVER: $resolverLine" }
Write-Host "VERIFY_PROFILE_ALIAS: $verificationRouteAlias exit=$resolverExit"
if ($resolverExit -ne 0) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: the shared resolver refused alias '$verificationRouteAlias' for profile '$Profile' (exit $resolverExit); no gate ran under an unadmitted profile revision.")
    exit 1
}
if (-not (Test-Path -LiteralPath $profileReceiptPath -PathType Leaf)) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: the shared resolver issued no VerificationProfileReceipt at '$profileReceiptPath'; a missing receipt is incomplete evidence, never a pass.")
    exit 1
}
$profileReceipt = $null
try {
    $profileReceipt = Get-Content -LiteralPath $profileReceiptPath -Raw | ConvertFrom-Json
} catch {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: the issued receipt at '$profileReceiptPath' is not canonical JSON ($($_.Exception.Message)).")
    exit 1
}
# The receipt must name the route the alias pins, at the revision the resolver
# admitted. Anything else means the receipt this run would report does not
# describe the profile it selected, so it is refused here instead of being
# printed into the summary as if it did.
$expectedRoute = if ($verificationRouteAlias -eq 'bundle-verification') { 'bundle-verification' } else { 'package-verification' }
if ($profileReceipt.profile -ne $expectedRoute) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: alias '$verificationRouteAlias' issued a receipt for route '$($profileReceipt.profile)', not '$expectedRoute'.")
    exit 1
}
Write-Host "VERIFY_PROFILE_REVISION: $($profileReceipt.profile)@$($profileReceipt.profile_revision) schema=$($profileReceipt.schema.schema)@$($profileReceipt.schema.version) outcome=$($profileReceipt.outcome)"
foreach ($identity in @($profileReceipt.tool_identities)) {
    Write-Host "VERIFY_PROFILE_TOOL: $($identity.stage_id) instrument=$($identity.instrument) executable=$($identity.executable) sha256=$($identity.executable_digest)"
}
foreach ($dependency in @($profileReceipt.environment_dependencies)) {
    Write-Host "VERIFY_PROFILE_ENVIRONMENT: $($dependency.name) expected=$($dependency.expected_class) observed=$($dependency.observed_class)"
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

# MergeCompile collects independent failures without turning them into PASS.
# Prerequisites are execution dependencies, not policy waivers: a failed
# restore/metadata producer cannot leave a consumer running on stale output.
# Quick and Review retain their existing fail-fast contract.
$mergeCompilePrerequisites = @{
    'cargo-fmt' = @('cargo-metadata')
    'cargo-check-workspace' = @('cargo-metadata')
    'cargo-denominator' = @('cargo-metadata')
    'cargo-test-compile' = @('cargo-metadata')
    'cargo-clippy-changed' = @('cargo-metadata', 'cargo-denominator')
    'dotnet-build-operator' = @('dotnet-restore-operator')
}
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
            $unmetPrerequisites = @()
            if ($Profile -eq 'MergeCompile' -and $mergeCompilePrerequisites.ContainsKey($gate.Name)) {
                $unmetPrerequisites = @(
                    foreach ($required in $mergeCompilePrerequisites[$gate.Name]) {
                        $producer = @($results | Where-Object { $_.Name -eq $required })
                        if ($producer.Count -ne 1 -or $producer[0].State -ne 'pass') {
                            $required
                        }
                    }
                )
            }
            if ($unmetPrerequisites.Count -gt 0) {
                $state = 'not-run'
                $exitCode = -1
                $gateError = "prerequisite did not pass: $($unmetPrerequisites -join ', ')"
            } elseif ($null -eq $gate.Command) {
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
        if ($state -eq 'fail-exception' -or $state -eq 'cancelled' -or $state -eq 'not-run') {
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
        if ($state -ne 'pass' -and ($Profile -ne 'MergeCompile' -or $state -eq 'cancelled')) {
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
$overall = if ($passedCount -eq $selectedGates.Count -and $results.Count -eq $selectedGates.Count -and $harnessState -eq 'pass') { 'PASS' } else { 'FAIL' }

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
    "VERIFY_FAILURE_POLICY: $(if ($Profile -eq 'MergeCompile') { 'collect independent results; unmet prerequisites not-run; any nonpass fails' } else { 'fail-fast' })",
    'VERIFY_CACHE: workflow-owned only; this script implements no gate cache, so a cache hit cannot skip a gate or supply a pass receipt',
    "VERIFY_PROFILE_ALIAS: $verificationRouteAlias",
    "VERIFY_PROFILE_REVISION: $($profileReceipt.profile)@$($profileReceipt.profile_revision) schema=$($profileReceipt.schema.schema)@$($profileReceipt.schema.version) profile_digest=$($profileReceipt.profile_digest) dag_digest=$($profileReceipt.dag_digest) outcome=$($profileReceipt.outcome)",
    "VERIFY_PROFILE_RECEIPT: shared owner crates/instrument/eliot-instrument-runner/src/bin/eliot-profile-resolver.rs issued this run's VerificationProfileReceipt through resolve_verification_route/build_verification_profile_receipt; the same alias is invoked by the local Justfile and by ci.yml, so this revision is the one CI resolves",
    "VERIFY_PROFILE_ENVIRONMENT: $((@($profileReceipt.environment_dependencies) | ForEach-Object { "$($_.name)=$($_.expected_class)/$($_.observed_class)" }) -join ', ')",
    "VERIFY_PROFILE_PROOF_CEILING: $($profileReceipt.proof_ceiling)",
    "VERIFY_PROOF_CEILING: $proofCeiling",
    'VERIFY_DINT_CEILING: ignored/stateful/live-provider tests are outside the normal Quick/Review/MergeCompile profiles (D-INT family issues 905/907/909/911/913/915); this result covers none of them',
    'VERIFY_QUARANTINE: the individual cargo/dotnet gates (cargo-fmt/cargo-check-workspace/cargo-clippy-workspace/cargo-test-workspace/cargo-denominator/cargo-test-compile/cargo-clippy-changed/standalone-crates-compile/dotnet-restore-operator/dotnet-build-operator) still execute the quarantined legacy lane with no PER-GATE receipt (issue #1813 W6); what is now governed is the profile ADMISSION above, not each gate in this table'
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

# The issued receipt is summarized above; the GUID-named file is working state,
# not an artifact, so it is removed here exactly like the dependency-policy
# receipt. A cleanup failure is reported and fails the run rather than leaving
# undeclared working state behind.
$profileReceiptCleanupState = 'removed'
try {
    if (Test-Path -LiteralPath $profileReceiptPath -PathType Leaf) {
        Remove-Item -LiteralPath $profileReceiptPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $profileReceiptPath) {
        throw "profile receipt path is not a file: $profileReceiptPath"
    }
} catch {
    $profileReceiptCleanupState = 'fail'
    Write-Host "VERIFY_PROFILE_RECEIPT_CLEANUP: fail $($_.Exception.Message)"
    $overall = 'FAIL'
}

if ($overall -eq 'PASS') {
    exit 0
} else {
    exit 1
}
