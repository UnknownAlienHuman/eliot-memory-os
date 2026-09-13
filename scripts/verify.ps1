[CmdletBinding()]
param(
    # NOTE: $Profile intentionally shadows the automatic PowerShell home-path
    # variable inside this script scope. Here it selects the closed
    # verification profile (issue #750). No other profile/command/ref input
    # exists; ValidateSet rejects arbitrary profile text.
    [ValidateSet('Quick', 'Review')]
    [string] $Profile = 'Quick',
    [switch] $List,
    [switch] $SkipCargoCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Retired skip switch (issue #750): -SkipCargoCheck is explicitly rejected.
# No invocation carrying a skip may emit a passing result under any profile.
if ($SkipCargoCheck) {
    [Console]::Error.WriteLine('VERIFY_REJECTED: -SkipCargoCheck is retired and cannot yield a passing result. Run -Profile Quick or -Profile Review without skips.')
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
$codeNavigation = Join-Path $PSScriptRoot 'code_navigation.py'
$docsClosureAudit = Join-Path $PSScriptRoot 'docs_closure_audit.py'
$standaloneCrates = Join-Path $PSScriptRoot 'verify-standalone-crates.py'
$dependencyPolicyVerifier = Join-Path $PSScriptRoot 'verify-dependency-policy.py'

# Sole ordered gate-definition owner (issue #750). Wrappers (Justfile, CI)
# select a closed profile only; they must not duplicate these commands.
# Quick = every gate this script ran on base, in base order. Review = the same
# oracle block, then the locked cargo tail in the exact issue order:
# metadata, fmt, check, clippy, test, deny. Each gate runs once per invocation.
$allGates = @(
    [pscustomobject]@{ Name = 'documentation-shards-self-test'; Profiles = @('Quick', 'Review'); Command = { python $docsShardVerifier self-test } },
    [pscustomobject]@{ Name = 'documentation-shards'; Profiles = @('Quick', 'Review'); Command = { python $docsShardVerifier verify --root $repoRoot } },
    [pscustomobject]@{ Name = 'documentation-routes-self-test'; Profiles = @('Quick', 'Review'); Command = { python $docsRouter self-test } },
    [pscustomobject]@{ Name = 'documentation-routes'; Profiles = @('Quick', 'Review'); Command = { python $docsRouter check --root $repoRoot } },
    [pscustomobject]@{ Name = 'documentation-read-self-test'; Profiles = @('Quick', 'Review'); Command = { python $docsReader self-test } },
    [pscustomobject]@{ Name = 'documentation-code-conformance-self-test'; Profiles = @('Quick', 'Review'); Command = { python $docCodeConformanceVerifier --self-test } },
    [pscustomobject]@{ Name = 'documentation-code-conformance'; Profiles = @('Quick', 'Review'); Command = { python $docCodeConformanceVerifier --root $repoRoot } },
    [pscustomobject]@{ Name = 'code-navigation-self-test'; Profiles = @('Quick', 'Review'); Command = { python $codeNavigation self-test } },
    [pscustomobject]@{ Name = 'code-navigation'; Profiles = @('Quick', 'Review'); Command = { python $codeNavigation check --root $repoRoot } },
    [pscustomobject]@{ Name = 'documentation-closure-audit'; Profiles = @('Quick', 'Review'); Command = { python $docsClosureAudit --root $repoRoot } },
    [pscustomobject]@{ Name = 'standalone-crates'; Profiles = @('Quick', 'Review'); Command = { python $standaloneCrates --root $repoRoot } },
    [pscustomobject]@{ Name = 'core-daemon-inventory-self-test'; Profiles = @('Quick', 'Review'); Command = { python $coreDaemonInventoryVerifier --self-test } },
    [pscustomobject]@{ Name = 'core-daemon-inventory'; Profiles = @('Quick', 'Review'); Command = { python $coreDaemonInventoryVerifier --root $repoRoot } },
    [pscustomobject]@{ Name = 'normative-pair'; Profiles = @('Quick', 'Review'); Command = { pwsh -NoProfile -File (Join-Path $PSScriptRoot 'verify-normative.ps1') } },
    [pscustomobject]@{ Name = 'dependency-policy-self-test'; Profiles = @('Quick', 'Review'); Command = { python $dependencyPolicyVerifier --self-test } },
    [pscustomobject]@{ Name = 'dependency-policy-offline'; Profiles = @('Quick', 'Review'); Command = { python $dependencyPolicyVerifier --root $repoRoot --profile offline-source } },
    [pscustomobject]@{ Name = 'architecture-boundaries-self-test'; Profiles = @('Quick', 'Review'); Command = { python $architectureAudit --self-test } },
    [pscustomobject]@{ Name = 'architecture-boundaries'; Profiles = @('Quick', 'Review'); Command = { python $architectureAudit --root $repoRoot } },
    [pscustomobject]@{ Name = 'agent-guardrails-self-test'; Profiles = @('Quick', 'Review'); Command = { python $guardrailVerifier --self-test } },
    [pscustomobject]@{ Name = 'agent-guardrails'; Profiles = @('Quick', 'Review'); Command = { python $guardrailVerifier --root $repoRoot } },
    [pscustomobject]@{ Name = 'agent-route-bundles-self-test'; Profiles = @('Quick', 'Review'); Command = { python $agentRouteBundleVerifier --self-test } },
    [pscustomobject]@{ Name = 'agent-route-bundles'; Profiles = @('Quick', 'Review'); Command = { python $agentRouteBundleVerifier --root $repoRoot } },
    [pscustomobject]@{ Name = 'runtime-source-hygiene-self-test'; Profiles = @('Quick', 'Review'); Command = { python $runtimeHygieneAudit --self-test } },
    [pscustomobject]@{ Name = 'runtime-source-hygiene'; Profiles = @('Quick', 'Review'); Command = { python $runtimeHygieneAudit --root $repoRoot } },
    [pscustomobject]@{ Name = 'agent-bridge-protocol-self-test'; Profiles = @('Quick', 'Review'); Command = { python $agentBridgeProtocolVerifier --self-test } },
    [pscustomobject]@{ Name = 'agent-bridge-protocol'; Profiles = @('Quick', 'Review'); Command = { python $agentBridgeProtocolVerifier --root $repoRoot } },
    # Deviation note vs issue #750 text (which lists `cargo metadata --locked
    # --format-version 1` without --no-deps): this gate retains the base oracle
    # `cargo metadata --locked --no-deps --format-version 1`, identical to the
    # base script gate and the Justfile `metadata` recipe. Evidence: pinned
    # cargo 1.97.1 `cargo metadata --help` documents --locked, --no-deps and
    # --format-version 1 as supported stable flags (case 17: only proven flags),
    # and I18-27 forbids silently changing an owned oracle definition. Full
    # locked dependency resolution is still enforced by the --locked cargo
    # check/clippy/test gates plus the dependency-policy offline-source gate.
    [pscustomobject]@{ Name = 'cargo-metadata'; Profiles = @('Quick', 'Review'); Command = { $script:verifyMetadataJson = (cargo metadata --locked --no-deps --format-version 1 | Out-String) } },
    [pscustomobject]@{ Name = 'cargo-fmt'; Profiles = @('Quick', 'Review'); Command = { cargo fmt --all -- --check } },
    [pscustomobject]@{ Name = 'cargo-check-workspace'; Profiles = @('Quick', 'Review'); Command = { cargo check --locked --workspace --all-targets } },
    [pscustomobject]@{ Name = 'cargo-clippy-workspace'; Profiles = @('Review'); Command = { cargo clippy --locked --workspace --all-targets -- -D warnings } },
    [pscustomobject]@{ Name = 'cargo-test-workspace'; Profiles = @('Review'); Command = { cargo test --locked --workspace } },
    [pscustomobject]@{ Name = 'cargo-deny'; Profiles = @('Review'); Command = { cargo deny check } }
)

$profileExplicit = $PSBoundParameters.ContainsKey('Profile')

# List/configuration mode is read-only: it prints gate definitions and never
# claims execution. Bare -List covers both closed profiles.
if ($List) {
    $listProfiles = if ($profileExplicit) { @($Profile) } else { @('Quick', 'Review') }
    Write-Host 'VERIFY_PROFILES: Quick, Review'
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

# Source/tool identities bound into the summary. Best-effort probes: an
# unavailable probe is recorded as such and never fabricates an identity.
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
$denyIdentity = 'unavailable'
try {
    $denyIdentity = ((cargo deny --version) | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($denyIdentity)) { $denyIdentity = 'unavailable' }
} catch {
    $denyIdentity = 'unavailable'
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

$passedCount = @($results | Where-Object { $_.State -eq 'pass' }).Count
$failedCount = @($results | Where-Object { $_.State -ne 'pass' -and $_.State -ne 'not-run' }).Count
$notRunCount = @($results | Where-Object { $_.State -eq 'not-run' }).Count
$overall = if ($failedCount -eq 0 -and $harnessState -eq 'pass') { 'PASS' } else { 'FAIL' }

if ($Profile -eq 'Quick') {
    $proofCeiling = 'QUICK_ONLY: bounded repository/document/source oracle check. Not Review, not release, not Product-Pulse proof.'
} else {
    $proofCeiling = 'REVIEW_SOURCE_ONLY: complete locked Review on this candidate only. Not release/source-candidate, not installed-runtime/store/Product-Pulse proof.'
}

# Bounded, redacted summary: identities, gate states, ceilings. No command
# output, no environment content, never credentials.
$summaryLines = @(
    "VERIFY_RESULT: $overall profile=$Profile source=$sourceSha gates=$($selectedGates.Count) passed=$passedCount failed=$failedCount not-run=$notRunCount",
    "VERIFY_WORKSPACE_MEMBERS: $workspaceMembers (cargo metadata --locked --no-deps)",
    "VERIFY_TOOLCHAIN: $cargoIdentity / $pythonIdentity / deny=$denyIdentity",
    'VERIFY_CACHE: workflow-owned only; this script implements no gate cache, so a cache hit cannot skip a gate or supply a pass receipt',
    "VERIFY_PROOF_CEILING: $proofCeiling",
    'VERIFY_DINT_CEILING: ignored/stateful/live-provider tests are outside the normal Quick/Review profiles (D-INT family issues 905/907/909/911/913/915); this result covers none of them'
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
