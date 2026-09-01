[CmdletBinding()]
param(
    [switch] $List,
    [switch] $SkipCargoCheck
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

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

$steps = @(
    [pscustomobject]@{
        Name = 'documentation-shards-self-test'
        Command = { python $docsShardVerifier self-test }
    },
    [pscustomobject]@{
        Name = 'documentation-shards'
        Command = { python $docsShardVerifier verify --root $repoRoot }
    },
    [pscustomobject]@{
        Name = 'documentation-routes-self-test'
        Command = { python $docsRouter self-test }
    },
    [pscustomobject]@{
        Name = 'documentation-routes'
        Command = { python $docsRouter check --root $repoRoot }
    },
    [pscustomobject]@{
        Name = 'documentation-read-self-test'
        Command = { python $docsReader self-test }
    },
    [pscustomobject]@{
        Name = 'core-daemon-inventory-self-test'
        Command = { python $coreDaemonInventoryVerifier --self-test }
    },
    [pscustomobject]@{
        Name = 'core-daemon-inventory'
        Command = { python $coreDaemonInventoryVerifier --root $repoRoot }
    },
    [pscustomobject]@{
        Name = 'normative-pair'
        Command = { pwsh -NoProfile -File (Join-Path $PSScriptRoot 'verify-normative.ps1') }
    },
    [pscustomobject]@{
        Name = 'architecture-boundaries-self-test'
        Command = { python $architectureAudit --self-test }
    },
    [pscustomobject]@{
        Name = 'architecture-boundaries'
        Command = { python $architectureAudit --root $repoRoot }
    },
    [pscustomobject]@{
        Name = 'agent-guardrails-self-test'
        Command = { python $guardrailVerifier --self-test }
    },
    [pscustomobject]@{
        Name = 'agent-guardrails'
        Command = { python $guardrailVerifier --root $repoRoot }
    },
    [pscustomobject]@{
        Name = 'agent-route-bundles-self-test'
        Command = { python $agentRouteBundleVerifier --self-test }
    },
    [pscustomobject]@{
        Name = 'agent-route-bundles'
        Command = { python $agentRouteBundleVerifier --root $repoRoot }
    },
    [pscustomobject]@{
        Name = 'runtime-source-hygiene-self-test'
        Command = { python $runtimeHygieneAudit --self-test }
    },
    [pscustomobject]@{
        Name = 'runtime-source-hygiene'
        Command = { python $runtimeHygieneAudit --root $repoRoot }
    },
    [pscustomobject]@{
        Name = 'agent-bridge-protocol-self-test'
        Command = { python $agentBridgeProtocolVerifier --self-test }
    },
    [pscustomobject]@{
        Name = 'agent-bridge-protocol'
        Command = { python $agentBridgeProtocolVerifier --root $repoRoot }
    },
    [pscustomobject]@{
        Name = 'cargo-metadata'
        Command = { cargo metadata --locked --no-deps --format-version 1 | Out-Null }
    },
    [pscustomobject]@{
        Name = 'cargo-fmt'
        Command = { cargo fmt --all -- --check }
    }
)

if (-not $SkipCargoCheck) {
    $steps += [pscustomobject]@{
        Name = 'cargo-check-workspace'
        Command = { cargo check --locked --workspace --all-targets }
    }
}

if ($List) {
    $steps | ForEach-Object { $_.Name }
    exit 0
}

Push-Location $repoRoot
try {
    foreach ($step in $steps) {
        Write-Host "VERIFY_STEP: $($step.Name)"
        & $step.Command
        if ($LASTEXITCODE -ne 0) {
            throw "Verification step failed: $($step.Name) (exit $LASTEXITCODE)"
        }
    }

    Write-Host "VERIFY: PASS steps=$($steps.Count)"
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
finally {
    Pop-Location
}
