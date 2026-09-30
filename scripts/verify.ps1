[CmdletBinding()]
param(
    # NOTE: $Profile intentionally shadows the automatic PowerShell home-path
    # variable inside this script scope. Here it selects the closed
    # verification profile (issues #750, #3004). No other profile/command/ref
    # input exists; ValidateSet rejects arbitrary profile text.
    [ValidateSet('Quick', 'Review', 'MergeCompile')]
    [string] $Profile = 'Quick',
    [switch] $List,
    [switch] $SkipCargoCheck,
    # Counterpart `VerificationProfileReceipt` (issue #1914 A3, I18.21). When
    # supplied, the resolver compares this run's receipt against it through the
    # one shared `verify_profile_parity` owner and a non-PASS parity outcome
    # refuses this run before any gate executes. The path is optional: this
    # script adds no default and never invents a counterpart receipt, because
    # a locally produced one is this run's OWN receipt and comparing it with
    # itself would be a check that can never fire.
    [string] $CompareProfileReceipt = ''
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
# and locked Operator restore/build with zero test execution. Review's tail
# additionally carries the manual source/release lane stages that
# .github/workflows/source-candidate.yml used to run as its own private command
# list (issue #1914 W4): all-target test execution under the nonzero-execution
# safeguard, all-target build, and locked Operator restore/build. Quick
# behavior is unchanged, and MergeCompile keeps zero test execution. Each gate
# runs once per invocation.
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
    # The dependency-policy artifacts are generated here, by the one shared
    # offline-source owner, into the same `.eliot/dependency-policy-artifacts/`
    # paths `just dependency-policy-artifacts` and the release builder use. This
    # is a change in WHERE the artifacts are written, not in WHAT is checked:
    # every profile that ran this gate before still runs the same verifier with
    # the same profile and the same receipt path, and the three extra flags only
    # select the caller-chosen output files the verifier documents. The manual
    # source/release lane binds those artifacts' bytes by digest, so producing
    # them here is what lets that workflow stop invoking the verifier itself.
    [pscustomobject]@{ Name = 'dependency-policy-offline'; Profiles = @('Quick', 'Review', 'MergeCompile'); Command = { python $dependencyPolicyVerifier --root $repoRoot --profile offline-source --receipt-out $dependencyPolicyReceiptPath --sbom-out .eliot/dependency-policy-artifacts/sbom.json --license-report-out .eliot/dependency-policy-artifacts/licenses.json --advisory-report-out .eliot/dependency-policy-artifacts/advisories.json } },
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
    },
    # Manual source/release lane tail (issue #1914 W4). Before this, the
    # manual release-candidate workflow (.github/workflows/source-candidate.yml)
    # carried these stages as its OWN private cargo/dotnet command list, so the
    # I18.21 line "no CI-only hidden verifier command list" was violated in the
    # literal sense: a `workflow_dispatch` of that file executed a command set no
    # versioned profile revision covered and emitted no shared-schema evidence.
    # The commands below are the SAME commands that workflow executed, moved
    # here to the one ordered gate-definition owner and reached by that workflow
    # through a single `-Profile Review` invocation. The workflow no longer names
    # a verifier command, a stage, or an order; it selects one closed profile
    # exactly as ci.yml and integration.yml already do, so the run that workflow
    # reports is a run of the same profile revision a local `verify.ps1 -Profile
    # Review` reports. Nothing below is a new or weakened check: every command and
    # every failure condition is the one the workflow already ran on its own
    # `run:` lines, and it joins the existing Review tail rather than replacing
    # any Review stage.
    #
    # These stages are in `Review` because `Review` IS the repository's
    # documented manual source/release profile: docs/DEPENDENCY_POLICY.md names
    # `current-advisories` "a manual source/release workflow profile", and
    # integration.yml already dispatches `Review` for the other manual source
    # lane. A separate fourth profile would have been a second name for the same
    # work, and .github/workflows/repository-policy.yml:399-401 pins the closed
    # Quick/Review/MergeCompile profile set in this file, so a new name there is
    # not available without editing a checker this issue does not own.
    [pscustomobject]@{
        Name = 'cargo-test-workspace-all-targets'
        Profiles = @('Review')
        Command = {
            # The manual release lane compiles and runs every target, not only
            # the default lib/bin/test targets `cargo-test-workspace` covers, and
            # it refuses a run in which no test was listed or none executed. The
            # all-targets test run and the nonzero-execution safeguard are the
            # exact commands and the exact refusal the release workflow ran on
            # its own `run:` lines; `cargo-test-workspace` above is unchanged, so
            # this adds coverage rather than replacing it.
            $testListOutput = @(& cargo test --workspace --all-targets --locked -- --list 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "TEST_LIST_FAILURE: cargo test -- --list exited $LASTEXITCODE"
            }

            $testOutput = @(& cargo test --workspace --all-targets --locked 2>&1)
            if ($LASTEXITCODE -ne 0) {
                throw "TEST_EXECUTION_FAILURE: cargo test exited $LASTEXITCODE"
            }

            $listedTests = @(
                $testListOutput |
                    ForEach-Object { "$_" } |
                    Where-Object { $_ -match '^\s*.+:\s+test\s*$' }
            ).Count
            $executedTests = 0
            foreach ($line in $testOutput) {
                $text = "$line"
                if ($text -match 'test result: .*?(\d+) passed;\s+(\d+) failed;\s+(\d+) ignored;\s+(\d+) measured;') {
                    $executedTests += [int]$Matches[1] + [int]$Matches[2]
                }
            }

            Write-Host "TEST_EVIDENCE: listed=$listedTests executed=$executedTests"
            if ($listedTests -eq 0 -or $executedTests -eq 0) {
                throw "TEST_CONTRACT_FAILURE: expected nonzero listed and executed tests"
            }
        }
    },
    [pscustomobject]@{
        Name = 'cargo-build-workspace-all-targets'
        Profiles = @('Review')
        Command = { cargo build --workspace --all-targets --locked }
    },
    [pscustomobject]@{
        Name = 'dotnet-restore-operator-release'
        Profiles = @('Review')
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
        Name = 'dotnet-build-operator-release'
        Profiles = @('Review')
        Command = {
            dotnet build apps/Eliot.Operator/Eliot.Operator.csproj -c Release --no-restore
            if ($LASTEXITCODE -ne 0) {
                throw 'dotnet build Eliot.Operator failed'
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

# Versioned profile admission (issue #1914 W2/W4, I18.21:3, I18.21:14). This
# script stays the ONE ordered gate-definition owner: the table above is still
# the only place a gate command is written down, and nothing below selects or
# reorders a gate. What this seam adds is the one thing the table cannot
# express: the profile ADMISSION decision, which the shared Rust resolver owns.
#
# The resolver named here is `eliot-profile-resolver`, the production entry of
# `eliot-instrument-runner`. It resolves the closed profile ALIAS below through
# `resolve_verification_route` — the same function, the same alias, and the same
# binary that CI resolves, because CI enters this same script — and issues the
# shared `VerificationProfileReceipt`. So "local profile revision == CI profile
# revision" has a computed value on both sides rather than being asserted in
# prose, and a refusal here (an unadmitted alias, a missing executable identity,
# or an absent provenance receipt) stops the run before a single gate executes
# rather than after.
#
# Reaching the resolver is this script's own responsibility. I18.21:14 says the
# minimal bootstrap build is the only unavoidable pre-run exception, so the
# admission below PERFORMS that build itself — exactly one crate, exactly one
# binary, into a target root it names — and then executes the built file by
# absolute path. No caller has to put the resolver on PATH, no PATH entry has to
# survive between steps, and there is no branch that proceeds without the
# resolver: if the bootstrap build fails or issues no receipt, the run is
# refused. That is the difference between a governed entrypoint and a gate that
# only consults a resolver somebody remembered to install.
#
# The PowerShell profiles map onto the admitted verification route:
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
if ([string]::IsNullOrWhiteSpace($verificationRouteAlias)) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: PowerShell profile '$Profile' names no admitted verification route alias.")
    exit 1
}

# Declared CI-only environment dependencies (I18.21:10, "CI-specific
# environment differences are explicit profile dependencies"). Every
# environment difference this profile's stage set has over the same profile run
# elsewhere is named here, once, and handed to the shared resolver so the run's
# `VerificationProfileReceipt` records it as a declared dependency instead of
# leaving it implicit. The list is deliberately NOT derived from the same table
# it validates: a dependency a run invents from its own gate list would always
# agree with itself, and a CI-only difference it forgot to invent would then be
# invisible. This list is the independent record of what a hosted lane needs
# that a developer's machine does not.
#
# `Review` is the only profile that declares any. It is the repository's manual
# source/release profile, so it is the profile both manual hosted lanes reach
# (integration.yml and source-candidate.yml), and its Operator stages need a
# .NET SDK that no other profile's stage set touches. The other two profiles
# declare none today because they have no CI-only environment difference left;
# an empty list is the honest record, and the receipt still reports it as such.
$declaredProfileEnvironmentDependencies = @{
    'Quick'        = @()
    'Review'       = @(
        # The Operator gates (locked restore and Release build) need a .NET SDK
        # that this profile's admitted route has no stage for, so the
        # toolchain's presence is a declared environment dependency of the run
        # rather than an ambient fact. It is named, not probed: the resolver
        # records the dependency and its admitted class, and a run whose
        # attested class differs fails closed in
        # check_declared_environment_dependencies.
        'eliot-manual-source-lane-dotnet-sdk'
        # Both manual hosted lanes run on a shared GitHub-hosted runner, which
        # establishes no filesystem, network or ACL boundary. That runner class
        # is a CI-only environment difference and is declared as one, so the
        # receipt shows the run's proof ceiling was reached on a shared host
        # rather than leaving the reader to infer it.
        'eliot-manual-source-lane-github-hosted-runner'
    )
    'MergeCompile' = @()
}
$profileDeclaredEnvironmentDependencies = @($declaredProfileEnvironmentDependencies[$Profile])
$profileResolver = 'eliot-profile-resolver'
$profileResolverSource = 'crates/instrument/eliot-instrument-runner/src/bin/eliot-profile-resolver.rs'
$profileResolverPackage = 'eliot-instrument-runner'
$eliotStateRoot = Join-Path $repoRoot '.eliot'
# The receipt is run-local working state, so the directory that holds it is
# created on demand and removed again below when this run created it. A
# checkout that already has `.eliot` keeps it untouched.
$eliotStateRootCreated = $false
if (-not (Test-Path -LiteralPath $eliotStateRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $eliotStateRoot -Force | Out-Null
    $eliotStateRootCreated = $true
}
$profileReceiptPath = Join-Path $eliotStateRoot ('verification-profile-{0}.json' -f [Guid]::NewGuid().ToString('N'))

# Minimal bootstrap build (I18.21:14). The target root is the one cargo is
# already configured to use, so the resolver's own build output is the file it
# runs and the cache root is the real cargo home rather than a stand-in.
$resolverTargetRoot = if ([string]::IsNullOrWhiteSpace($env:CARGO_TARGET_DIR)) { Join-Path $repoRoot 'target' } else { $env:CARGO_TARGET_DIR }
$resolverCacheRoot = if ([string]::IsNullOrWhiteSpace($env:CARGO_HOME)) { Join-Path $env:USERPROFILE '.cargo' } else { $env:CARGO_HOME }
foreach ($resolverRoot in @(@{ Name = 'target'; Value = $resolverTargetRoot }, @{ Name = 'cache'; Value = $resolverCacheRoot })) {
    if ([string]::IsNullOrWhiteSpace($resolverRoot.Value) -or -not [IO.Path]::IsPathFullyQualified($resolverRoot.Value)) {
        [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: the resolver's $($resolverRoot.Name) root '$($resolverRoot.Value)' is not an absolute path, so no admitted layout can be bound to it.")
        exit 1
    }
}
if (-not (Test-Path -LiteralPath $resolverCacheRoot -PathType Container)) {
    New-Item -ItemType Directory -Path $resolverCacheRoot -Force | Out-Null
}
$bootstrapExit = 0
try {
    $bootstrapOutput = @(& cargo build --locked --target-dir $resolverTargetRoot -p $profileResolverPackage --bin $profileResolver 2>&1)
    $bootstrapExit = $LASTEXITCODE
    foreach ($bootstrapLine in $bootstrapOutput) { Write-Host "VERIFY_PROFILE_BOOTSTRAP: $bootstrapLine" }
} catch {
    $bootstrapExit = -1
    Write-Host "VERIFY_PROFILE_BOOTSTRAP: raised $($_.Exception.Message)"
}
if ($bootstrapExit -ne 0) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: the minimal bootstrap build of $profileResolverPackage/$profileResolver ($profileResolverSource) failed (exit $bootstrapExit); this run has no versioned profile revision to report and no gate ran under one.")
    exit 1
}
$resolverExecutable = ''
foreach ($resolverCandidate in @("$profileResolver.exe", $profileResolver)) {
    $resolverCandidatePath = Join-Path (Join-Path $resolverTargetRoot 'debug') $resolverCandidate
    if (Test-Path -LiteralPath $resolverCandidatePath -PathType Leaf) {
        $resolverExecutable = $resolverCandidatePath
        break
    }
}
if ([string]::IsNullOrWhiteSpace($resolverExecutable)) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: the bootstrap build reported success but no $profileResolver executable exists under '$resolverTargetRoot\debug'.")
    exit 1
}
Write-Host "VERIFY_PROFILE_RESOLVER_EXECUTABLE: $resolverExecutable"

# Admit the profile through the shared resolver. A nonzero exit reports the
# admitted route's own normalized outcome, not an admission failure, so it is
# recorded rather than treated as a refusal: the receipt is the admission
# evidence, and a run that could not admit the route issues none.
$resolverExit = 0
try {
    $resolverArgs = @(
        '--alias', $verificationRouteAlias,
        '--source-root', $repoRoot,
        '--target-root', $resolverTargetRoot,
        '--cache-root', $resolverCacheRoot,
        '--declared-environment', "eliot-verify-profile-$Profile"
    )
    # Every declared CI-only environment dependency this profile has travels into
    # the same receipt, as its own `--declared-environment` pair. The resolver
    # validates each one against the admitted environment class in
    # check_declared_environment_dependencies and refuses the receipt on a
    # mismatch, so declaring a difference is a claim CI's receipt carries and
    # not a comment beside it. A dependency this run did not declare is
    # invisible to the receipt; that is why the list above is the independent
    # record rather than something derived from the gate table.
    foreach ($declaredEnvironmentDependency in $profileDeclaredEnvironmentDependencies) {
        $resolverArgs += @('--declared-environment', $declaredEnvironmentDependency)
    }
    # Local/CI parity (issue #1914 A3, I18.21 "local profile revision == CI
    # profile revision"). When the caller supplied a counterpart receipt, the
    # SAME binary compares this run's receipt against it through the one shared
    # `verify_profile_parity` owner and prints `PARITY_PASS` or
    # `PARITY_NON_PASS reason=...` on its own stdout. This script adds no
    # comparison of its own: the decision is the library's, and a non-PASS
    # verdict leaves the resolver with a nonzero exit that the guard below
    # turns into a refusal before a single gate executes, rather than a
    # warning printed beside a run that continued.
    if (-not [string]::IsNullOrWhiteSpace($CompareProfileReceipt)) {
        $resolverArgs += @('--compare-against', $CompareProfileReceipt)
    }
    $resolverArgs += @('--receipt-out', $profileReceiptPath)
    $resolverOutput = @(& $resolverExecutable @resolverArgs 2>&1)
    $resolverExit = $LASTEXITCODE
    foreach ($resolverLine in $resolverOutput) { Write-Host "VERIFY_PROFILE_RESOLVER: $resolverLine" }
} catch {
    $resolverExit = -1
    Write-Host "VERIFY_PROFILE_RESOLVER: raised $($_.Exception.Message)"
}
Write-Host "VERIFY_PROFILE_ALIAS: $verificationRouteAlias exit=$resolverExit"
# A missing receipt is the admission refusal, and it is the ONLY thing that is.
# A route that could not be admitted (unknown alias, absent tool identity,
# missing provenance, unreadable artifact) issues no receipt, and a receipt that
# was never issued is incomplete evidence rather than a pass — so a missing
# receipt refuses the run whatever the exit code was. A route that WAS admitted
# keeps its receipt even when its own aggregate outcome is non-PASS, and that
# non-PASS is this run's real outcome: it is reported through the profile's
# nonpass policy below, and the receipt stays the admission evidence. The exit
# code is deliberately NOT the discriminator here — see the parity guard below,
# which is why the two refusals are separated by the receipt's existence rather
# than by exit status.
if (-not (Test-Path -LiteralPath $profileReceiptPath -PathType Leaf)) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_ADMISSION_REFUSED: the shared resolver issued no VerificationProfileReceipt at '$profileReceiptPath' (exit $resolverExit); a missing receipt is incomplete evidence, never a pass, and no gate ran under an unadmitted profile revision.")
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
# A receipt the shared owner issued is trusted as admission evidence; nothing
# here recomputes or second-guesses it. The resolver's exit code and the
# receipt's normalized outcome are the SAME decision over the SAME receipt
# value: `eliot-profile-resolver` returns exit 0 if and only if
# `receipt.outcome.is_pass()` (src/bin/eliot-profile-resolver.rs run()), and it
# writes that exact receipt to `--receipt-out` before choosing the exit. A
# non-PASS outcome with a zero exit is therefore impossible by construction, so
# there is no "disagreement" branch to warn on here: adding one would be a check
# that can never fire. A genuinely non-PASS outcome arrives as a nonzero
# resolver exit, is surfaced verbatim in the VERIFY_PROFILE_ALIAS and
# VERIFY_PROFILE_REVISION lines below, and fails the run through the profile's
# own nonpass policy; a route that could not be admitted at all issues no
# receipt and is refused above.
Write-Host "VERIFY_PROFILE_REVISION: $($profileReceipt.profile)@$($profileReceipt.profile_revision) schema=$($profileReceipt.schema.schema)@$($profileReceipt.schema.version) outcome=$($profileReceipt.outcome)"
foreach ($identity in @($profileReceipt.tool_identities)) {
    Write-Host "VERIFY_PROFILE_TOOL: $($identity.stage_id) instrument=$($identity.instrument) executable=$($identity.executable) sha256=$($identity.executable_digest)"
}
foreach ($dependency in @($profileReceipt.environment_dependencies)) {
    Write-Host "VERIFY_PROFILE_ENVIRONMENT: $($dependency.name) expected=$($dependency.expected_class) observed=$($dependency.observed_class)"
}

# What the local/CI comparison actually did this run, stated in the summary
# rather than left to a reader who has to notice whether a counterpart receipt
# was supplied at all. The verdict itself is the resolver's `PARITY_PASS` /
# `PARITY_NON_PASS` line and nothing here recomputes it.
#
# A supplied comparison that did NOT pass is a refusal, and it is refused HERE,
# before any gate executes. The discriminator MUST be the resolver's own parity
# verdict, not the exit code: `EXIT_REFUSED` is 1 for BOTH a parity refusal
# (run()/require_receipt_parity) and an ordinary non-PASS aggregate
# (run(), `receipt.outcome.is_pass()`), so keying on the exit would report a
# normal non-PASS run as a parity divergence that never happened. The resolver
# prints exactly one `PARITY_PASS`/`PARITY_NON_PASS` line when — and only when —
# a comparison ran, so that line states which of the two nonzero refusals this
# is. An unreadable or malformed counterpart artifact produces no verdict line
# and is refused above as a run that could not be admitted, which is what it is.
$profileParityVerdict = if ($resolverOutput) {
    @($resolverOutput | Where-Object { "$_" -match '^\s*PARITY_(PASS|NON_PASS)\b' })
} else {
    @()
}
$profileParitySummary = if ([string]::IsNullOrWhiteSpace($CompareProfileReceipt)) {
    'not compared; no -CompareProfileReceipt was supplied, so this run reports its own profile revision without a counterpart verdict'
} elseif ($profileParityVerdict.Count -eq 0) {
    "compared against $CompareProfileReceipt; the shared verify_profile_parity owner produced no verdict line, so this run was refused as a comparison it could not decide"
} else {
    "compared against $CompareProfileReceipt through the shared verify_profile_parity owner: $($profileParityVerdict[0])"
}
Write-Host "VERIFY_PROFILE_PARITY: $profileParitySummary"
if (-not [string]::IsNullOrWhiteSpace($CompareProfileReceipt) -and -not ($profileParityVerdict -match '^PARITY_PASS\b')) {
    [Console]::Error.WriteLine("VERIFY_PROFILE_PARITY_REFUSED: the local/CI parity comparison against '$CompareProfileReceipt' reported non-PASS (resolver exit $resolverExit); the VERIFY_PROFILE_PARITY line above names the comparison and the resolver's own line names the divergence, and no gate ran under a refused parity verdict.")
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

# The issued receipt is summarized below from the parsed value, so the
# GUID-named file and, when this run had to create it, the `.eliot` directory
# are working state, not artifacts: both are removed here, exactly like the
# dependency-policy receipt, BEFORE the summary reports their cleanup state. A
# cleanup failure is a harness failure rather than a silent leftover.
$profileReceiptCleanupState = 'removed'
try {
    if (Test-Path -LiteralPath $profileReceiptPath -PathType Leaf) {
        Remove-Item -LiteralPath $profileReceiptPath -Force -ErrorAction Stop
    }
    if (Test-Path -LiteralPath $profileReceiptPath) {
        throw "profile receipt path is not a file: $profileReceiptPath"
    }
    if ($eliotStateRootCreated) {
        Remove-Item -LiteralPath $eliotStateRoot -Force -Recurse -ErrorAction Stop
    }
    if ($eliotStateRootCreated -and (Test-Path -LiteralPath $eliotStateRoot)) {
        throw "run-created state root still exists: $eliotStateRoot"
    }
} catch {
    $profileReceiptCleanupState = 'fail'
    $harnessState = 'harness-error'
    if ([string]::IsNullOrWhiteSpace($harnessError)) {
        $harnessError = 'verification-profile receipt cleanup failed'
    } else {
        $harnessError += '; verification-profile receipt cleanup failed'
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
    $proofCeiling = 'REVIEW_SOURCE_ONLY: complete locked Review on this candidate only, including the manual source/release lane stages. No installed-runtime/store/Product-Pulse proof, and no filesystem, network or ACL isolation is claimed on a shared hosted runner.'
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
    "VERIFY_PROFILE_RESOLVER: $profileResolver built at $resolverExecutable and invoked with alias $verificationRouteAlias (exit $resolverExit); the shared receipt, not a PATH lookup, is the admission evidence",
    "VERIFY_PROFILE_PARITY: $profileParitySummary",
    "VERIFY_PROFILE_RECEIPT_CLEANUP: $profileReceiptCleanupState",
    "VERIFY_PROFILE_REVISION: $($profileReceipt.profile)@$($profileReceipt.profile_revision) schema=$($profileReceipt.schema.schema)@$($profileReceipt.schema.version) profile_digest=$($profileReceipt.profile_digest) dag_digest=$($profileReceipt.dag_digest) outcome=$($profileReceipt.outcome)",
    "VERIFY_PROFILE_RECEIPT: shared owner crates/instrument/eliot-instrument-runner/src/bin/eliot-profile-resolver.rs issued this run's VerificationProfileReceipt through resolve_verification_route/build_verification_profile_receipt; this script performs the minimal bootstrap build (I18.21:14) and then invokes it, and ci.yml, integration.yml and source-candidate.yml all enter this same script, so the revision resolved here is the revision every CI lane resolves",
    "VERIFY_PROFILE_DECLARED_ENVIRONMENT: $((@($profileDeclaredEnvironmentDependencies) | ForEach-Object { "$_" }) -join ', ') declared by profile $Profile and carried in the receipt above as $(if ($profileDeclaredEnvironmentDependencies.Count -gt 0) { 'declared dependencies' } else { 'no declared dependencies' })",
    "VERIFY_PROFILE_ENVIRONMENT: $((@($profileReceipt.environment_dependencies) | ForEach-Object { "$($_.name)=$($_.expected_class)/$($_.observed_class)" }) -join ', ')",
    "VERIFY_PROFILE_PROOF_CEILING: $($profileReceipt.proof_ceiling)",
    "VERIFY_PROOF_CEILING: $proofCeiling",
    'VERIFY_DINT_CEILING: ignored/stateful/live-provider tests are outside the normal Quick/Review/MergeCompile profiles (D-INT family issues 905/907/909/911/913/915); this result covers none of them',
    'VERIFY_QUARANTINE: the individual cargo/dotnet gates (cargo-fmt/cargo-check-workspace/cargo-clippy-workspace/cargo-test-workspace/cargo-denominator/cargo-test-compile/cargo-clippy-changed/standalone-crates-compile/dotnet-restore-operator/dotnet-build-operator/cargo-test-workspace-all-targets/cargo-build-workspace-all-targets/dotnet-restore-operator-release/dotnet-build-operator-release) still execute the quarantined legacy lane with no PER-GATE receipt (issue #1813 W6); what is now governed is the profile ADMISSION above, not each gate in this table'
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
