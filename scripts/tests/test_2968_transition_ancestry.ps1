$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '..' 'lib' 'governor-retirement-approval.ps1')

$work = Join-Path ([System.IO.Path]::GetTempPath()) ('t2968-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work
try {
    git init -q $work
    git -C $work config user.email 'probe@example.invalid'
    git -C $work config user.name 'probe'
    Set-Content -Path (Join-Path $work 'f.txt') -Value 'c'
    git -C $work add .
    git -C $work commit -qm c
    $C = (git -C $work rev-parse HEAD).Trim()
    Set-Content -Path (Join-Path $work 'f.txt') -Value 'd'
    git -C $work commit -qam d
    $D = (git -C $work rev-parse HEAD).Trim()
    git -C $work checkout -q --orphan off
    Set-Content -Path (Join-Path $work 'g.txt') -Value 'e'
    git -C $work add .
    git -C $work commit -qm e
    $E = (git -C $work rev-parse HEAD).Trim()

    $idAbsent = [pscustomobject]@{ status = 'absent' }
    $closureComplete = [pscustomobject]@{ status = 'COMPLETE' }

    $r1 = Test-GovernorRetirementCandidateTransition $work $E $C $C $idAbsent $null $closureComplete @()
    if (-not ($r1.admitted -eq $false -and $r1.reason -ceq 'APPROVAL_OWNER_SOURCE_NOT_ANCESTOR')) {
        throw "case 1 expected APPROVAL_OWNER_SOURCE_NOT_ANCESTOR, got admitted=$($r1.admitted) reason=$($r1.reason)"
    }

    $r2 = Test-GovernorRetirementCandidateTransition $work $D $C $E $idAbsent $null $closureComplete @()
    if (-not ($r2.admitted -eq $false -and $r2.reason -ceq 'APPROVAL_TRUST_ROOT_NOT_ANCESTOR')) {
        throw "case 2 expected APPROVAL_TRUST_ROOT_NOT_ANCESTOR, got admitted=$($r2.admitted) reason=$($r2.reason)"
    }

    $r3 = Test-GovernorRetirementCandidateTransition $work $D $C $C $idAbsent $null $closureComplete @()
    if (-not ($r3.admitted -eq $false -and ($r3.reason -notin @('APPROVAL_OWNER_SOURCE_NOT_ANCESTOR', 'APPROVAL_TRUST_ROOT_NOT_ANCESTOR')))) {
        throw "control expected a later gate than the two ancestry gates, got admitted=$($r3.admitted) reason=$($r3.reason)"
    }

    Write-Output 'ANCESTRY-PROBE-OK'
}
finally {
    Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
}
