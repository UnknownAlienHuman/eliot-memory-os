[CmdletBinding()]
param(
    [switch] $List
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ProfileVersion = 'eliot-verify-v1'

function Fail([string] $Message) {
    throw "VERIFY_FAIL: $Message"
}

function Invoke-NativeStep(
    [string] $StepId,
    [string] $FilePath,
    [string[]] $Arguments,
    [switch] $SuppressOutput
) {
    Write-Output "VERIFY_STEP_START id=$StepId"
    if ($SuppressOutput) {
        & $FilePath @Arguments | Out-Null
    }
    else {
        & $FilePath @Arguments
    }
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        Fail "step=$StepId exit=$exitCode"
    }
    Write-Output "VERIFY_STEP_PASS id=$StepId"
}

try {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $normativeVerifier = Join-Path $repoRoot 'scripts/verify-normative.ps1'
    if (-not (Test-Path -LiteralPath $normativeVerifier -PathType Leaf)) {
        Fail 'normative verifier is missing'
    }
    $stuMeasure = Join-Path $repoRoot 'scripts/measure-stu.ps1'
    if (-not (Test-Path -LiteralPath $stuMeasure -PathType Leaf)) {
        Fail 'STU measurement script is missing'
    }

    $pwsh = (Get-Command pwsh -ErrorAction Stop).Source
    $steps = @(
        [pscustomobject]@{ Id = 'metadata'; Description = 'cargo metadata --locked --no-deps --format-version 1'; FilePath = 'cargo'; Arguments = @('metadata', '--locked', '--no-deps', '--format-version', '1'); SuppressOutput = $true },
        [pscustomobject]@{ Id = 'fmt'; Description = 'cargo fmt --all -- --check'; FilePath = 'cargo'; Arguments = @('fmt', '--all', '--', '--check'); SuppressOutput = $false },
        [pscustomobject]@{ Id = 'normative'; Description = 'scripts/verify-normative.ps1'; FilePath = $pwsh; Arguments = @('-NoProfile', '-File', $normativeVerifier); SuppressOutput = $false },
        [pscustomobject]@{ Id = 'stu-evidence'; Description = 'provisional non-blocking STU observations for tracked Rust source'; FilePath = $pwsh; Arguments = @('-NoProfile', '-File', $stuMeasure); SuppressOutput = $false },
        [pscustomobject]@{ Id = 'workspace-check'; Description = 'cargo check --locked --workspace --all-targets'; FilePath = 'cargo'; Arguments = @('check', '--locked', '--workspace', '--all-targets'); SuppressOutput = $false },
        [pscustomobject]@{ Id = 'workspace-clippy'; Description = 'cargo clippy --locked --workspace --all-targets -- -D warnings'; FilePath = 'cargo'; Arguments = @('clippy', '--locked', '--workspace', '--all-targets', '--', '-D', 'warnings'); SuppressOutput = $false },
        [pscustomobject]@{ Id = 'workspace-tests'; Description = 'cargo test --locked --workspace'; FilePath = 'cargo'; Arguments = @('test', '--locked', '--workspace'); SuppressOutput = $false },
        [pscustomobject]@{ Id = 'cargo-deny'; Description = 'cargo deny check'; FilePath = 'cargo'; Arguments = @('deny', 'check'); SuppressOutput = $false }
    )

    if ($List) {
        Write-Output "ELIOT_VERIFY_PROFILE=$ProfileVersion"
        for ($index = 0; $index -lt $steps.Count; $index++) {
            $step = $steps[$index]
            Write-Output ('{0:D2} {1} | {2}' -f ($index + 1), $step.Id, $step.Description)
        }
        exit 0
    }

    Write-Output "ELIOT_VERIFY_PROFILE=$ProfileVersion"
    Write-Output "VERIFY_ROOT=$repoRoot"
    foreach ($step in $steps) {
        Invoke-NativeStep -StepId $step.Id -FilePath $step.FilePath -Arguments $step.Arguments -SuppressOutput:$step.SuppressOutput
    }
    Write-Output 'VERIFY_RESULT=PASS'
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
