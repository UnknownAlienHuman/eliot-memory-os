[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
    throw "VERIFY_NORMATIVE_FAIL: $Message"
}

function Read-Receipt([string] $Path) {
    $values = @{}
    foreach ($line in (Get-Content -LiteralPath $Path)) {
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) {
            continue
        }
        $match = [regex]::Match(
            $trimmed,
            '^(?<key>[A-Za-z0-9_]+)\s*=\s*"(?<value>[^"]*)"\s*$'
        )
        if (-not $match.Success) {
            Fail "unsupported normative-pair TOML record: $trimmed"
        }
        $key = $match.Groups['key'].Value
        if ($values.ContainsKey($key)) {
            Fail "duplicate normative-pair key: $key"
        }
        $values[$key] = $match.Groups['value'].Value
    }
    return $values
}

function Sha256([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Require-LowerHexDigest(
    [string] $FieldName,
    [string] $Value
) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        Fail "$FieldName must be exactly 64 lowercase hexadecimal characters"
    }
}

function Require-PairKeyFormat([string] $Value) {
    if ($Value -cnotmatch '^sha256:[0-9a-f]{64}$') {
        Fail 'pair_key must be sha256: followed by exactly 64 lowercase hexadecimal characters'
    }
}

function Require-ExactDigest(
    [string] $Name,
    [string] $ReceiptValue,
    [string] $ActualValue
) {
    Require-LowerHexDigest "${Name}_sha256" $ReceiptValue
    if ($ReceiptValue -cne $ActualValue) {
        Fail "$Name digest mismatch: expected $ReceiptValue, actual $ActualValue"
    }
}

function Get-PairKey(
    [string] $ArchitectureHash,
    [string] $ImplementationHash
) {
    $pairInput =
        'eliot-normative-pair-v1' + [char]0 +
        $ArchitectureHash + [char]0 +
        $ImplementationHash + [char]0
    $pairBytes = [Text.Encoding]::UTF8.GetBytes($pairInput)
    $pairDigest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($pairBytes)
    ).ToLowerInvariant()
    return "sha256:$pairDigest"
}

function Require-ExactPairKey(
    [string] $ReceiptValue,
    [string] $ExpectedValue
) {
    Require-PairKeyFormat $ReceiptValue
    if ($ReceiptValue -cne $ExpectedValue) {
        Fail "pair key mismatch: expected $ExpectedValue, receipt $ReceiptValue"
    }
}

function Assert-SelfTestFailure(
    [scriptblock] $Action,
    [string] $ExpectedPattern,
    [string] $CaseName
) {
    $failed = $false
    try {
        & $Action | Out-Null
    }
    catch {
        $failed = $true
        if ($_.Exception.Message -notmatch $ExpectedPattern) {
            throw
        }
    }
    if (-not $failed) {
        Fail "normative self-test case did not fail: $CaseName"
    }
}

function Invoke-NormativeSelfTest {
    $validDigest = [string]::new([char]'a', 64)
    foreach ($invalidLength in @(62, 63, 65)) {
        $invalidDigest = if ($invalidLength -lt 64) {
            $validDigest.Substring(0, $invalidLength)
        }
        else {
            $validDigest + 'a'
        }
        Assert-SelfTestFailure {
            Require-LowerHexDigest 'architecture_sha256' $invalidDigest
        } 'architecture_sha256 must be exactly 64 lowercase hexadecimal characters' "architecture digest length $invalidLength"
    }

    $differentDigest = [string]::new([char]'b', 64)
    Assert-SelfTestFailure {
        Require-ExactDigest 'Architecture' $validDigest $differentDigest
    } 'Architecture digest mismatch' 'wrong well-formed Architecture digest'

    $receiptPairKey = 'sha256:' + $validDigest
    $expectedPairKey = 'sha256:' + $differentDigest
    Assert-SelfTestFailure {
        Require-ExactPairKey $receiptPairKey $expectedPairKey
    } 'pair key mismatch' 'wrong well-formed pair key'

    Write-Output 'NORMATIVE_SELF_TEST: PASS cases=5'
}

try {
    Invoke-NormativeSelfTest

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $receiptPath = Join-Path $repoRoot 'docs/normative-pair.toml'
    $contractPath = Join-Path $repoRoot 'docs/ARCHITECTURE_CONTRACT.md'

    foreach ($requiredPath in @($receiptPath, $contractPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
            Fail "required file is missing: $requiredPath"
        }
    }

    $receipt = Read-Receipt $receiptPath
    $requiredKeys = @(
        'schema_version',
        'status',
        'repository_authority_branch',
        'pair_key_algorithm',
        'pair_key',
        'architecture_path',
        'architecture_sha256',
        'implementation_path',
        'implementation_sha256'
    )
    foreach ($key in $requiredKeys) {
        if (-not $receipt.ContainsKey($key) -or [string]::IsNullOrWhiteSpace($receipt[$key])) {
            Fail "normative-pair receipt is missing: $key"
        }
    }

    if ($receipt['schema_version'] -ne 'eliot-normative-pair-v1') {
        Fail 'unsupported normative-pair schema'
    }
    if ($receipt['status'] -ne 'accepted') {
        Fail 'normative pair is not accepted'
    }
    if ($receipt['repository_authority_branch'] -ne 'main') {
        Fail 'main is not the declared authority branch'
    }
    if ($receipt['pair_key_algorithm'] -ne 'sha256-domain-separated-v1') {
        Fail 'unsupported pair-key algorithm'
    }

    Require-LowerHexDigest 'architecture_sha256' $receipt['architecture_sha256']
    Require-LowerHexDigest 'implementation_sha256' $receipt['implementation_sha256']
    Require-PairKeyFormat $receipt['pair_key']

    $expectedArchitecturePath = 'docs/architecture/ELIOT_ARCHITECTURE.md'
    $expectedImplementationPath = 'docs/architecture/ELIOT_IMPLEMENTATION.md'
    if ($receipt['architecture_path'] -ne $expectedArchitecturePath -or
        $receipt['implementation_path'] -ne $expectedImplementationPath) {
        Fail 'normative paths are not the stable canonical repository paths'
    }

    $architecturePath = Join-Path $repoRoot $receipt['architecture_path']
    $implementationPath = Join-Path $repoRoot $receipt['implementation_path']
    foreach ($path in @($architecturePath, $implementationPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Fail "canonical normative file is missing: $path"
        }
    }

    $architectureHash = Sha256 $architecturePath
    $implementationHash = Sha256 $implementationPath
    Require-ExactDigest 'Architecture' $receipt['architecture_sha256'] $architectureHash
    Require-ExactDigest 'Implementation' $receipt['implementation_sha256'] $implementationHash

    $expectedPairKey = Get-PairKey $architectureHash $implementationHash
    Require-ExactPairKey $receipt['pair_key'] $expectedPairKey

    $contractText = Get-Content -Raw -LiteralPath $contractPath
    foreach ($requiredText in @(
        $expectedArchitecturePath,
        $expectedImplementationPath,
        $architectureHash.ToUpperInvariant(),
        $implementationHash.ToUpperInvariant(),
        $expectedPairKey
    )) {
        if (-not $contractText.Contains($requiredText)) {
            Fail "architecture contract is missing current identity: $requiredText"
        }
    }

    $retiredPaths = @(
        'docs/normative',
        'docs/architecture/ELIOT_ARCHITECTURE_ENGLISH_FINAL_2026-08-28.md',
        'docs/architecture/ELIOT_IMPLEMENTATION_ENGLISH_FINAL_2026-08-28.md'
    )
    foreach ($relativePath in $retiredPaths) {
        $path = Join-Path $repoRoot $relativePath
        if (Test-Path -LiteralPath $path) {
            Fail "retired normative authority surface is present: $relativePath"
        }
    }

    Write-Output "NORMATIVE_VERIFY: PASS pair=$expectedPairKey authority=main"
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
