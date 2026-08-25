[CmdletBinding()]
param(
    [switch] $SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
    throw "UNIMPLEMENTED_VERIFY_FAIL: $Message"
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

function Get-StructuredMarkers(
    [string] $Path,
    [int] $LineNumber,
    [string] $Line
) {
    $tokenPattern = '(?<![A-Za-z0-9_])(?<kind>todo|unimplemented)![ \t]*\('
    $structuredPattern =
        '(?<![A-Za-z0-9_])todo![ \t]*\([ \t]*"(?<anchor>[AI][0-9]+(?:\.[0-9]+)+): (?<what>[^"\r\n|`]+)"[ \t]*\)'
    $tokens = @([regex]::Matches($Line, $tokenPattern))
    if ($tokens.Count -eq 0) {
        return
    }
    if (@($tokens | Where-Object { $_.Groups['kind'].Value -eq 'unimplemented' }).Count) {
        Fail "unimplemented! is forbidden: $($Path):$LineNumber"
    }
    $markers = @([regex]::Matches($Line, $structuredPattern))
    if ($markers.Count -ne $tokens.Count) {
        Fail "unstructured todo marker: $($Path):$LineNumber"
    }
    foreach ($marker in $markers) {
        $what = $marker.Groups['what'].Value.Trim()
        if ([string]::IsNullOrWhiteSpace($what)) {
            Fail "empty marker description: $($Path):$LineNumber"
        }
        [pscustomobject]@{
            File = $Path.Replace('\', '/')
            Line = $LineNumber
            LineSha256 = Get-LineSha256 $Line
            Anchor = $marker.Groups['anchor'].Value
            What = $what
        }
    }
}

function Assert-ParserSelfTest {
    $valid = @(Get-StructuredMarkers 'valid.rs' 7 'todo!("A0.8: connect one useful path")')
    if ($valid.Count -ne 1 -or $valid[0].Anchor -ne 'A0.8') {
        Fail 'self-test did not accept the canonical marker'
    }
    foreach ($invalid in @(
        'todo!("missing anchor")',
        'unimplemented!("A0.8: wrong macro")',
        'todo!("A0.8: ")',
        'todo!('
    )) {
        $rejected = $false
        try {
            $null = @(Get-StructuredMarkers 'invalid.rs' 9 $invalid)
        }
        catch {
            $rejected = $true
        }
        if (-not $rejected) {
            Fail "self-test accepted invalid marker: $invalid"
        }
    }

    $normativeFixture = @'
```text
## A9.9. A fenced example is not a normative heading
```
## A0.8. Progressive conformance
'@
    $anchors = Get-NormativeAnchors $normativeFixture
    if (-not $anchors.ContainsKey('A0.8')) {
        Fail 'self-test did not discover a real normative heading'
    }
    if ($anchors.ContainsKey('A9.9')) {
        Fail 'self-test accepted a fenced example as a normative heading'
    }
    Write-Output 'UNIMPLEMENTED_VERIFY_SELF_TEST: PASS'
}

try {
    if ($SelfTest) {
        Assert-ParserSelfTest
        exit 0
    }

    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $registryPath = Join-Path $repoRoot 'docs/UNIMPLEMENTED.md'
    if (-not (Test-Path -LiteralPath $registryPath -PathType Leaf)) {
        Fail 'docs/UNIMPLEMENTED.md is missing'
    }
    $strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $registryText = [System.IO.File]::ReadAllText($registryPath, $strictUtf8)
    if (-not $registryText.Contains('- Schema: `eliot-unimplemented-registry-v1`')) {
        Fail 'registry schema marker is missing'
    }

    $countMatch = [regex]::Match($registryText, '(?m)^- Row count: `(?<count>[0-9]+)`$')
    if (-not $countMatch.Success) {
        Fail 'registry row count is missing'
    }
    $declaredCount = [int] $countMatch.Groups['count'].Value

    $grepOutput = @(
        & git -C $repoRoot grep -n -E '(todo|unimplemented)![[:blank:]]*\(' -- '*.[rR][sS]' 2>$null
    )
    $grepExit = $LASTEXITCODE
    if ($grepExit -notin @(0, 1)) {
        Fail "git grep exited $grepExit"
    }

    $sourceEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($hit in $grepOutput) {
        $parsed = [regex]::Match("$hit", '^(?<path>.+?):(?<line>[0-9]+):(?<text>.*)$')
        if (-not $parsed.Success) {
            Fail "cannot parse git grep result: $hit"
        }
        $path = $parsed.Groups['path'].Value
        $lineNumber = [int] $parsed.Groups['line'].Value
        $line = $parsed.Groups['text'].Value.TrimEnd([char] 13)
        foreach ($marker in @(Get-StructuredMarkers $path $lineNumber $line)) {
            $sourceEntries.Add($marker)
        }
    }

    $architecturePath = Join-Path $repoRoot 'docs/normative/ELIOT_ARCHITECTURE.md'
    $implementationPath = Join-Path $repoRoot 'docs/normative/ELIOT_IMPLEMENTATION.md'
    $normativeText =
        [System.IO.File]::ReadAllText($architecturePath, $strictUtf8) + "`n" +
        [System.IO.File]::ReadAllText($implementationPath, $strictUtf8)
    $normativeAnchors = Get-NormativeAnchors $normativeText
    foreach ($entry in $sourceEntries) {
        if (-not $normativeAnchors.ContainsKey($entry.Anchor)) {
            Fail "unknown normative anchor $($entry.Anchor): $($entry.File):$($entry.Line)"
        }
    }

    $rowPattern =
        '^\| `(?<file>[^`]+)` \| (?<line>[0-9]+) \| `(?<hash>[0-9a-f]{64})` \| `(?<anchor>[AI][0-9]+(?:\.[0-9]+)+)` \| (?<what>[^|]+) \|$'
    $registryEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($line in [regex]::Split($registryText, '\r\n|\n|\r')) {
        $row = [regex]::Match($line, $rowPattern)
        if ($row.Success) {
            $registryEntries.Add([pscustomobject]@{
                File = $row.Groups['file'].Value
                Line = [int] $row.Groups['line'].Value
                LineSha256 = $row.Groups['hash'].Value
                Anchor = $row.Groups['anchor'].Value
                What = $row.Groups['what'].Value.Trim()
            })
        }
    }

    if ($declaredCount -ne $registryEntries.Count) {
        Fail "declared row count $declaredCount differs from parsed rows $($registryEntries.Count)"
    }
    if ($sourceEntries.Count -ne $registryEntries.Count) {
        Fail "source marker count $($sourceEntries.Count) differs from registry rows $($registryEntries.Count)"
    }

    function EntryKey($Entry) {
        return @(
            $Entry.File,
            $Entry.Line,
            $Entry.LineSha256,
            $Entry.Anchor,
            $Entry.What
        ) -join "`0"
    }
    $sourceKeys = @($sourceEntries | ForEach-Object { EntryKey $_ } | Sort-Object)
    $registryKeys = @($registryEntries | ForEach-Object { EntryKey $_ } | Sort-Object)
    if (($sourceKeys -join "`n") -cne ($registryKeys -join "`n")) {
        Fail 'source markers and registry rows are not bijective'
    }

    $expectedStatus = if ($sourceEntries.Count -eq 0) { 'HONEST_EMPTY' } else { 'ENTRIES_PRESENT' }
    if (-not $registryText.Contains(('- Status: `{0}`' -f $expectedStatus))) {
        Fail "registry status must be $expectedStatus"
    }

    Write-Output "UNIMPLEMENTED_VERIFY: PASS rows=$($sourceEntries.Count) status=$expectedStatus"
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
