[CmdletBinding()]
param(
    [switch] $Check,
    [string] $OutputPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
    throw "UNIMPLEMENTED_GENERATE_FAIL: $Message"
}

function Get-LineSha256([string] $Line) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($Line)
    return [Convert]::ToHexString(
        [System.Security.Cryptography.SHA256]::HashData($bytes)
    ).ToLowerInvariant()
}

function Get-NormativeAnchors([string] $Text) {
    $anchors = @{}
    $fenceCharacter = $null
    $fenceLength = 0

    foreach ($line in [regex]::Split($Text, "\r\n|\n|\r")) {
        if ($null -ne $fenceCharacter) {
            $closingPattern =
                '^[ \t]*' + [regex]::Escape([string] $fenceCharacter) +
                '{' + $fenceLength + ',}[ \t]*$'
            if ($line -match $closingPattern) {
                $fenceCharacter = $null
                $fenceLength = 0
            }
            continue
        }

        $fence = [regex]::Match($line, '^[ \t]*(?<fence>`{3,}|~{3,})')
        if ($fence.Success) {
            $fenceCharacter = $fence.Groups['fence'].Value[0]
            $fenceLength = $fence.Groups['fence'].Value.Length
            continue
        }

        $heading = [regex]::Match(
            $line,
            '^[ \t]*#{1,6}[ \t]+(?<anchor>[AI][0-9]+(?:\.[0-9]+)+)\.[ \t]'
        )
        if ($heading.Success) {
            $anchors[$heading.Groups['anchor'].Value] = $true
        }
    }

    return $anchors
}

try {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    if ($Check -and $PSBoundParameters.ContainsKey('OutputPath')) {
        Fail '-Check validates only the canonical docs/UNIMPLEMENTED.md output'
    }
    if ([string]::IsNullOrWhiteSpace($OutputPath)) {
        $OutputPath = Join-Path $repoRoot 'docs/UNIMPLEMENTED.md'
    }
    elseif (-not [System.IO.Path]::IsPathRooted($OutputPath)) {
        $OutputPath = Join-Path $repoRoot $OutputPath
    }

    $architecturePath = Join-Path $repoRoot 'docs/normative/ELIOT_ARCHITECTURE.md'
    $implementationPath = Join-Path $repoRoot 'docs/normative/ELIOT_IMPLEMENTATION.md'
    foreach ($path in @($architecturePath, $implementationPath)) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            Fail "normative source is missing: $path"
        }
    }
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $normativeText =
        [System.IO.File]::ReadAllText($architecturePath, $strictUtf8) + "`n" +
        [System.IO.File]::ReadAllText($implementationPath, $strictUtf8)
    $normativeAnchors = Get-NormativeAnchors $normativeText

    $trackedFiles = @(& git -C $repoRoot ls-files -- '*.[rR][sS]')
    if ($LASTEXITCODE -ne 0) {
        Fail "git ls-files exited $LASTEXITCODE"
    }
    $trackedFiles = [string[]] $trackedFiles
    [Array]::Sort($trackedFiles, [StringComparer]::Ordinal)

    $tokenPattern = '(?<![A-Za-z0-9_])(?<kind>todo|unimplemented)![ \t]*\('
    $structuredPattern =
        '(?<![A-Za-z0-9_])todo![ \t]*\([ \t]*"(?<anchor>[AI][0-9]+(?:\.[0-9]+)+): (?<what>[^"\r\n|`]+)"[ \t]*\)'
    $entries = [System.Collections.Generic.List[object]]::new()

    foreach ($relativePath in $trackedFiles) {
        $absolutePath = Join-Path $repoRoot $relativePath
        $source = [System.IO.File]::ReadAllText($absolutePath, $strictUtf8)
        $sourceLines = [regex]::Split($source, "\r\n|\n|\r")
        for ($index = 0; $index -lt $sourceLines.Count; $index++) {
            $line = $sourceLines[$index]
            $tokens = @([regex]::Matches($line, $tokenPattern))
            if ($tokens.Count -eq 0) {
                continue
            }
            if (@($tokens | Where-Object { $_.Groups['kind'].Value -eq 'unimplemented' }).Count) {
                Fail "unimplemented! is forbidden; use structured todo!: $($relativePath):$($index + 1)"
            }
            $markers = @([regex]::Matches($line, $structuredPattern))
            if ($markers.Count -ne $tokens.Count) {
                Fail "marker must use todo with an A/I anchor and description: $($relativePath):$($index + 1)"
            }
            foreach ($marker in $markers) {
                $anchor = $marker.Groups['anchor'].Value
                $what = $marker.Groups['what'].Value.Trim()
                if ([string]::IsNullOrWhiteSpace($what)) {
                    Fail "marker description is empty: $($relativePath):$($index + 1)"
                }
                if (-not $normativeAnchors.ContainsKey($anchor)) {
                    Fail "unknown normative anchor $($anchor): $($relativePath):$($index + 1)"
                }
                $entries.Add([pscustomobject]@{
                    File = $relativePath.Replace('\', '/')
                    Line = $index + 1
                    LineSha256 = Get-LineSha256 $line
                    Anchor = $anchor
                    What = $what
                })
            }
        }
    }

    $entries = @($entries | Sort-Object File, Line, Anchor, What)
    $status = if ($entries.Count -eq 0) { 'HONEST_EMPTY' } else { 'ENTRIES_PRESENT' }
    $document = [System.Collections.Generic.List[string]]::new()
    $document.Add('# Unimplemented registry')
    $document.Add('')
    $document.Add('> Generated by `scripts/gen-unimplemented.ps1`. Do not edit by hand.')
    $document.Add('')
    $document.Add('- Schema: `eliot-unimplemented-registry-v1`')
    $document.Add('- Source scope: all Git-tracked Rust source files')
    $document.Add(('- Row count: `{0}`' -f $entries.Count))
    $document.Add(('- Status: `{0}`' -f $status))
    $document.Add('')
    $document.Add('| File | Line | Line SHA-256 | Architecture anchor | Work |')
    $document.Add('|---|---:|---|---|---|')
    foreach ($entry in $entries) {
        $document.Add((
            '| `{0}` | {1} | `{2}` | `{3}` | {4} |' -f
                $entry.File,
                $entry.Line,
                $entry.LineSha256,
                $entry.Anchor,
                $entry.What
        ))
    }
    if ($entries.Count -eq 0) {
        $document.Add('')
        $document.Add('No tracked Rust source contains a structured unimplemented marker.')
    }
    $expected = ($document -join "`n") + "`n"

    if ($Check) {
        if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) {
            Fail "generated registry is missing: $OutputPath"
        }
        $actual = [System.IO.File]::ReadAllText($OutputPath, $strictUtf8)
        if ($actual -ne $expected) {
            Fail 'docs/UNIMPLEMENTED.md is stale; run scripts/gen-unimplemented.ps1'
        }
        Write-Output "UNIMPLEMENTED_GENERATE_CHECK: PASS rows=$($entries.Count) status=$status"
        exit 0
    }

    $parent = Split-Path -Parent $OutputPath
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        Fail "output parent is missing: $parent"
    }
    [System.IO.File]::WriteAllText($OutputPath, $expected, [System.Text.UTF8Encoding]::new($false))
    Write-Output "UNIMPLEMENTED_GENERATE: PASS rows=$($entries.Count) status=$status output=$OutputPath"
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
