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

function Require-LowerHexDigest(
    [string] $FieldName,
    [string] $Value
) {
    if ($Value -cnotmatch '^[0-9a-f]{64}$') {
        Fail "$FieldName must be exactly 64 lowercase hexadecimal characters"
    }
}

function Require-PairKey([string] $Value) {
    if ($Value -cnotmatch '^sha256:[0-9a-f]{64}$') {
        Fail 'pair_key must be sha256: followed by exactly 64 lowercase hexadecimal characters'
    }
}

function Invoke-NormativeVerification([string] $RepoRoot) {
    $receiptPath = Join-Path $RepoRoot 'docs/normative-pair.toml'
    $contractPath = Join-Path $RepoRoot 'docs/ARCHITECTURE_CONTRACT.md'

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
    Require-PairKey $receipt['pair_key']

    $expectedArchitecturePath = 'docs/architecture/ELIOT_ARCHITECTURE.md'
    $expectedImplementationPath = 'docs/architecture/ELIOT_IMPLEMENTATION.md'
    if ($receipt['architecture_path'] -ne $expectedArchitecturePath -or
        $receipt['implementation_path'] -ne $expectedImplementationPath) {
        Fail 'normative paths are not the stable canonical repository paths'
    }

    $architecturePath = Join-Path $RepoRoot $receipt['architecture_path']
    $implementationPath = Join-Path $RepoRoot $receipt['implementation_path']
    foreach ($path in @($architecturePath, $implementationPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Fail "canonical normative file is missing: $path"
        }
    }

    $architectureHash = Sha256 $architecturePath
    $implementationHash = Sha256 $implementationPath
    if ($architectureHash -cne $receipt['architecture_sha256']) {
        Fail "Architecture digest mismatch: expected $($receipt['architecture_sha256']), actual $architectureHash"
    }
    if ($implementationHash -cne $receipt['implementation_sha256']) {
        Fail "Implementation digest mismatch: expected $($receipt['implementation_sha256']), actual $implementationHash"
    }

    $expectedPairKey = Get-PairKey $architectureHash $implementationHash
    if ($receipt['pair_key'] -cne $expectedPairKey) {
        Fail "pair key mismatch: expected $expectedPairKey, receipt $($receipt['pair_key'])"
    }

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
        $path = Join-Path $RepoRoot $relativePath
        if (Test-Path -LiteralPath $path) {
            Fail "retired normative authority surface is present: $relativePath"
        }
    }

    return $expectedPairKey
}

function Set-ReceiptValue(
    [string] $Path,
    [string] $Key,
    [string] $Value
) {
    $text = Get-Content -Raw -LiteralPath $Path
    $pattern = '(?m)^' + [regex]::Escape($Key) + '\s*=\s*"[^"]*"\s*$'
    $matches = [regex]::Matches($text, $pattern)
    if ($matches.Count -ne 1) {
        Fail "self-test could not resolve exactly one receipt key: $Key"
    }
    $replacement = "$Key = `"$Value`""
    $updated = [regex]::Replace($text, $pattern, $replacement)
    Set-Content -LiteralPath $Path -Value $updated -NoNewline -Encoding utf8NoBOM
}

function Assert-VerificationFailure(
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
    $tempRoot = Join-Path (
        [IO.Path]::GetTempPath()
    ) ("eliot-normative-self-test-" + [Guid]::NewGuid().ToString('N'))
    $tempDocs = Join-Path $tempRoot 'docs'
    $tempArchitecture = Join-Path $tempDocs 'architecture'
    $architecturePath = Join-Path $tempArchitecture 'ELIOT_ARCHITECTURE.md'
    $implementationPath = Join-Path $tempArchitecture 'ELIOT_IMPLEMENTATION.md'
    $receiptPath = Join-Path $tempDocs 'normative-pair.toml'
    $contractPath = Join-Path $tempDocs 'ARCHITECTURE_CONTRACT.md'

    try {
        New-Item -ItemType Directory -Path $tempArchitecture -Force | Out-Null
        Set-Content -LiteralPath $architecturePath -Value "architecture fixture`n" -NoNewline -Encoding utf8NoBOM
        Set-Content -LiteralPath $implementationPath -Value "implementation fixture`n" -NoNewline -Encoding utf8NoBOM

        $architectureHash = Sha256 $architecturePath
        $implementationHash = Sha256 $implementationPath
        $pairKey = Get-PairKey $architectureHash $implementationHash
        $receipt = @"
schema_version = "eliot-normative-pair-v1"
status = "accepted"
repository_authority_branch = "main"
pair_key_algorithm = "sha256-domain-separated-v1"
pair_key = "$pairKey"
architecture_path = "docs/architecture/ELIOT_ARCHITECTURE.md"
architecture_sha256 = "$architectureHash"
implementation_path = "docs/architecture/ELIOT_IMPLEMENTATION.md"
implementation_sha256 = "$implementationHash"
"@
        Set-Content -LiteralPath $receiptPath -Value $receipt -NoNewline -Encoding utf8NoBOM
        $contract = @"
docs/architecture/ELIOT_ARCHITECTURE.md
docs/architecture/ELIOT_IMPLEMENTATION.md
$($architectureHash.ToUpperInvariant())
$($implementationHash.ToUpperInvariant())
$pairKey
"@
        Set-Content -LiteralPath $contractPath -Value $contract -NoNewline -Encoding utf8NoBOM

        Invoke-NormativeVerification $tempRoot | Out-Null
        $validReceipt = Get-Content -Raw -LiteralPath $receiptPath

        foreach ($invalidLength in @(62, 63, 65)) {
            Set-Content -LiteralPath $receiptPath -Value $validReceipt -NoNewline -Encoding utf8NoBOM
            $invalidDigest = if ($invalidLength -le 64) {
                $architectureHash.Substring(0, $invalidLength)
            }
            else {
                $architectureHash + '0'
            }
            Set-ReceiptValue $receiptPath 'architecture_sha256' $invalidDigest
            Assert-VerificationFailure {
                Invoke-NormativeVerification $tempRoot
            } 'architecture_sha256 must be exactly 64 lowercase hexadecimal characters' "architecture digest length $invalidLength"
        }

        Set-Content -LiteralPath $receiptPath -Value $validReceipt -NoNewline -Encoding utf8NoBOM
        Set-ReceiptValue $receiptPath 'architecture_sha256' ([string]::new('0', 64))
        Assert-VerificationFailure {
            Invoke-NormativeVerification $tempRoot
        } 'Architecture digest mismatch' 'wrong well-formed Architecture digest'

        Set-Content -LiteralPath $receiptPath -Value $validReceipt -NoNewline -Encoding utf8NoBOM
        Set-ReceiptValue $receiptPath 'pair_key' ('sha256:' + [string]::new('0', 64))
        Assert-VerificationFailure {
            Invoke-NormativeVerification $tempRoot
        } 'pair key mismatch' 'wrong well-formed pair key'
    }
    finally {
        if (Test-Path -LiteralPath $tempRoot) {
            Remove-Item -LiteralPath $tempRoot -Recurse -Force
        }
    }

    Write-Output 'NORMATIVE_SELF_TEST: PASS cases=5'
}

try {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    Invoke-NormativeSelfTest
    $expectedPairKey = Invoke-NormativeVerification $repoRoot
    Write-Output "NORMATIVE_VERIFY: PASS pair=$expectedPairKey authority=main"
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
