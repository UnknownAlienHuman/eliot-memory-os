[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
    throw "VERIFY_NORMATIVE_FAIL: $Message"
}

try {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $projectionRoot = Join-Path $repoRoot 'docs/normative'
    $manifestPath = Join-Path $projectionRoot 'projection-manifest.tsv'
    $contractPath = Join-Path $repoRoot 'docs/ARCHITECTURE_CONTRACT.md'

    foreach ($requiredPath in @($projectionRoot, $manifestPath, $contractPath)) {
        if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf) -and
            -not (Test-Path -LiteralPath $requiredPath -PathType Container)) {
            Fail "required path is missing: $requiredPath"
        }
    }

    $expectedFiles = @(
        'ELIOT_ARCHITECTURE.md',
        'ELIOT_IMPLEMENTATION.md',
        'INDEX.md',
        'README.md'
    )
    $expectedSet = @{}
    foreach ($fileName in $expectedFiles) {
        $expectedSet[$fileName.ToLowerInvariant()] = $fileName
    }

    $metaSeen = @{}
    $manifestFiles = @{}
    foreach ($line in (Get-Content -LiteralPath $manifestPath)) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.TrimStart().StartsWith('#')) {
            continue
        }
        $parts = $line.Split([char]9, [System.StringSplitOptions]::None)
        $kind = $parts[0]
        if ($kind -eq 'projection_file') {
            if ($parts.Count -ne 3) {
                Fail "projection_file record must have exactly 3 TSV fields"
            }
            $fileName = $parts[1]
            $hash = $parts[2].ToUpperInvariant()
            $key = $fileName.ToLowerInvariant()
            if (-not $expectedSet.ContainsKey($key)) {
                Fail "manifest contains an unexpected projection file: $fileName"
            }
            if ($manifestFiles.ContainsKey($key)) {
                Fail "manifest contains a duplicate projection file: $fileName"
            }
            if ($hash -notmatch '^[0-9A-F]{64}$') {
                Fail "manifest contains an invalid SHA-256 for $fileName"
            }
            $manifestFiles[$key] = [pscustomobject]@{ Name = $expectedSet[$key]; Hash = $hash }
            continue
        }
        if ($parts.Count -ne 2 -or [string]::IsNullOrWhiteSpace($kind) -or
            [string]::IsNullOrWhiteSpace($parts[1])) {
            Fail "invalid manifest record: $line"
        }
        if ($metaSeen.ContainsKey($kind)) {
            Fail "manifest contains a duplicate metadata key: $kind"
        }
        $metaSeen[$kind] = $parts[1]
    }

    foreach ($requiredMeta in @('schema_version', 'kind', 'authority_status')) {
        if (-not $metaSeen.ContainsKey($requiredMeta)) {
            Fail "manifest metadata is missing: $requiredMeta"
        }
    }
    if ($metaSeen['schema_version'] -ne 'eliot-normative-projection-v1') {
        Fail 'unsupported projection manifest schema'
    }
    if ($metaSeen['kind'] -ne 'non_authority_projection' -or
        $metaSeen['authority_status'] -ne 'NOT_AUTHORITY') {
        Fail 'projection is not explicitly marked NOT_AUTHORITY'
    }
    if ($manifestFiles.Count -ne $expectedFiles.Count) {
        Fail "manifest must contain exactly $($expectedFiles.Count) projection files"
    }

    $contractText = Get-Content -Raw -LiteralPath $contractPath
    function Get-ContractHash([string] $FileName) {
        $needle = '`' + $FileName + '`'
        $rows = @($contractText -split "`r?`n" | Where-Object {
            $_.Contains('|') -and $_.Contains($needle)
        })
        if ($rows.Count -ne 1) {
            Fail "contract must contain exactly one hash row for $FileName"
        }
        $hashes = @([regex]::Matches($rows[0], '(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])'))
        if ($hashes.Count -ne 1) {
            Fail "contract hash row is missing or ambiguous for $FileName"
        }
        return $hashes[0].Value.ToUpperInvariant()
    }

    foreach ($fileName in $expectedFiles) {
        $key = $fileName.ToLowerInvariant()
        $path = Join-Path $projectionRoot $fileName
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Fail "projection file is missing: $fileName"
        }
        $matches = @(Get-ChildItem -LiteralPath $projectionRoot -Recurse -File |
            Where-Object { $_.Name -ieq $fileName })
        if ($matches.Count -ne 1 -or $matches[0].FullName -ne (Resolve-Path -LiteralPath $path).Path) {
            Fail "projection file is duplicated or moved: $fileName"
        }
        $actualHash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToUpperInvariant()
        $manifestHash = $manifestFiles[$key].Hash
        if ($actualHash -ne $manifestHash) {
            Fail "manifest hash mismatch for ${fileName}: expected $manifestHash, actual $actualHash"
        }
        if ($fileName -in @('ELIOT_ARCHITECTURE.md', 'ELIOT_IMPLEMENTATION.md')) {
            $contractHash = Get-ContractHash $fileName
            if ($actualHash -ne $contractHash) {
                Fail "contract hash mismatch for ${fileName}: expected $contractHash, actual $actualHash"
            }
        }
    }

    Write-Output "NORMATIVE_VERIFY: PASS projection=docs/normative files=$($expectedFiles.Count) authority=NOT_AUTHORITY"
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
