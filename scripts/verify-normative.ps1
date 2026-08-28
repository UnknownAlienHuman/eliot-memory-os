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

try {
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
    if ($architectureHash -ne $receipt['architecture_sha256'].ToLowerInvariant()) {
        Fail "Architecture digest mismatch: expected $($receipt['architecture_sha256']), actual $architectureHash"
    }
    if ($implementationHash -ne $receipt['implementation_sha256'].ToLowerInvariant()) {
        Fail "Implementation digest mismatch: expected $($receipt['implementation_sha256']), actual $implementationHash"
    }

    $pairInput =
        'eliot-normative-pair-v1' + [char]0 +
        $architectureHash + [char]0 +
        $implementationHash + [char]0
    $pairBytes = [Text.Encoding]::UTF8.GetBytes($pairInput)
    $pairDigest = [Convert]::ToHexString(
        [Security.Cryptography.SHA256]::HashData($pairBytes)
    ).ToLowerInvariant()
    $expectedPairKey = "sha256:$pairDigest"
    if ($receipt['pair_key'].ToLowerInvariant() -ne $expectedPairKey) {
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
