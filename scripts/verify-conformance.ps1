[CmdletBinding()]
param(
    [switch]$Check,
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ArchitecturePath = Join-Path $RepoRoot 'docs/normative/ELIOT_ARCHITECTURE.md'
$ImplementationPath = Join-Path $RepoRoot 'docs/normative/ELIOT_IMPLEMENTATION.md'
$DecisionPath = Join-Path $RepoRoot 'swarm/challenges/W1-RESULT-ENVELOPE-CONTRACT.md'
$BindingDecisionPath = Join-Path $RepoRoot 'swarm/challenges/W1-04-ANCHOR-SYMBOL-INDEX.md'
$GeneratorPath = Join-Path $RepoRoot 'scripts/gen-conformance.ps1'
$VerifierPath = Join-Path $RepoRoot 'scripts/verify-conformance.ps1'
$ConformancePath = Join-Path $RepoRoot 'docs/conformance.toml'
$ResultPath = Join-Path $RepoRoot 'swarm/results/W1-04.json'
$SupportingResultPath = Join-Path $RepoRoot 'swarm/results/W1-04-implementation.json'
$ModulesPath = Join-Path $RepoRoot 'swarm/inventory/modules.json'
$RefusalsPath = Join-Path $RepoRoot 'swarm/inventory/refusals.csv'
$GraphArtifactPath = Join-Path $RepoRoot '.codebase-memory/artifact.json'
$GraphDatabasePath = Join-Path $RepoRoot '.codebase-memory/graph.db.zst'
$ExpectedAnchorCount = 58
$MarkerToken = 'ELIOT_ARCH_OWNER'

function Rel([string]$Path) {
    return ([IO.Path]::GetRelativePath($RepoRoot, $Path)).Replace('\', '/')
}

function Sha([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToUpperInvariant()
}

function TextSha([string]$Text) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text))
        )).Replace('-', '').ToUpperInvariant()
    }
    finally {
        $hash.Dispose()
    }
}

function Read-Utf8([string]$Path) {
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    return [IO.File]::ReadAllText($Path, $encoding)
}

function Norm([string]$Value) {
    if ($null -eq $Value) { return '' }
    return [regex]::Replace($Value.Trim(), '[\t\r\n ]+', ' ')
}

function Toml([string]$Value) {
    $text = if ($null -eq $Value) { '' } else { [string]$Value }
    return '"' + $text.Replace('\', '\\').Replace('"', '\"').Replace("`r", '\r').Replace("`n", '\n').Replace("`t", '\t') + '"'
}

function TomlArray($Values) {
    if ($null -eq $Values -or @($Values).Count -eq 0) { return '[]' }
    return '[' + ((@($Values) | ForEach-Object { Toml ([string]$_) }) -join ', ') + ']'
}

function Rows(
    [string]$Text,
    [string]$Start,
    [string]$End,
    [string]$Header,
    [string]$Kind
) {
    $inside = $false
    $fenced = $false
    $headerSeen = $false
    $separatorSeen = $false
    $rows = [Collections.Generic.List[object]]::new()

    foreach ($line in ($Text -split "`r?`n")) {
        if ($line -match '^\s*```') {
            $fenced = -not $fenced
            continue
        }
        if ($fenced) { continue }

        if (-not $inside) {
            if ($line -match $Start) { $inside = $true }
            continue
        }
        if ($line -match $End) { break }

        if (-not $headerSeen) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }
            if ($line -notmatch $Header) { continue }
            $headerSeen = $true
            continue
        }

        if (-not $separatorSeen) {
            if ($line -match '^\|\s*:?-{3,}:?\s*\|\s*:?-{3,}:?\s*\|\s*:?-{3,}:?\s*\|\s*$') {
                $separatorSeen = $true
                continue
            }
            if (-not [string]::IsNullOrWhiteSpace($line)) {
                throw "$Kind table separator is malformed"
            }
            continue
        }

        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($Kind -eq 'architecture' -and $line -match '^\|\s*`(ARCH-[A-Z]+-[0-9]+)`\s*\|\s*(Invariant|Contract)\s*\|\s*(.*?)\s*\|\s*$') {
            $rows.Add([pscustomobject]@{
                Id = $Matches[1]
                Class = $Matches[2]
                Decision = $Matches[3].Trim()
            })
            continue
        }
        if ($Kind -eq 'implementation' -and $line -match '^\|\s*`(ARCH-[A-Z]+-[0-9]+)`\s*\|\s*(.*?)\s*\|\s*(.*?)\s*\|\s*$') {
            $rows.Add([pscustomobject]@{
                Id = $Matches[1]
                ScopeOwner = $Matches[2].Trim()
                Proof = $Matches[3].Trim()
            })
            continue
        }
        if ($line -match '^\|') {
            throw "$Kind table contains an invalid row: $line"
        }
    }

    if (-not $inside -or -not $headerSeen -or -not $separatorSeen) {
        throw "$Kind table headings/header were not found"
    }
    return $rows.ToArray()
}

function AssertPair($Architecture, $Implementation) {
    if (@($Architecture).Count -ne $ExpectedAnchorCount -or @($Implementation).Count -ne $ExpectedAnchorCount) {
        throw "A16.1 and Appendix H must each contain exactly $ExpectedAnchorCount rows"
    }

    $architectureIds = @($Architecture | ForEach-Object { $_.Id })
    $implementationIds = @($Implementation | ForEach-Object { $_.Id })
    if (@($architectureIds | Sort-Object -Unique).Count -ne $ExpectedAnchorCount) {
        throw 'A16.1 contains duplicate architecture IDs'
    }
    if (@($implementationIds | Sort-Object -Unique).Count -ne $ExpectedAnchorCount) {
        throw 'Appendix H contains duplicate architecture IDs'
    }
    $missing = @($architectureIds | Where-Object { $_ -notin $implementationIds })
    $extra = @($implementationIds | Where-Object { $_ -notin $architectureIds })
    if ($missing.Count -gt 0 -or $extra.Count -gt 0) {
        throw "A16.1/Appendix H anchor sets differ: missing=$($missing -join ',') extra=$($extra -join ',')"
    }
}

function Scope([string]$Value) {
    $normalized = Norm $Value
    $handles = $normalized
    if ($normalized -match '^(.*?);\s*[^;]+$') {
        $handles = $Matches[1].Trim()
    }
    return [pscustomobject]@{
        Handles = @($handles -split '\s*,\s*' | ForEach-Object { $_.Trim().Trim('`') } | Where-Object { $_ })
    }
}

function Mask-Range($Ranges, [int]$Start, [int]$End) {
    if ($End -gt $Start) { $Ranges.Add([pscustomobject]@{ Start = $Start; End = $End }) }
}

function RustLex([string]$InputText, [string]$RelativePath) {
    $text = $InputText.Replace("`r`n", "`n").Replace("`r", "`n")
    $maskRanges = [Collections.Generic.List[object]]::new()
    $length = $text.Length
    $markers = [Collections.Generic.List[object]]::new()
    $outerDocs = [Collections.Generic.List[object]]::new()
    $line = 1
    $index = 0

    while ($index -lt $length) {
        $current = $text[$index]
        $next = if ($index + 1 -lt $length) { $text[$index + 1] } else { [char]0 }

        if ($current -eq '/' -and $next -eq '/') {
            $end = $text.IndexOf("`n", $index)
            if ($end -lt 0) { $end = $length }
            $comment = $text.Substring($index, $end - $index)
            if ($comment -match '^///(?!/)') {
                $outerDocs.Add([pscustomobject]@{ Start = $index; End = $end })
            }
            if ($comment.Contains($MarkerToken)) {
                $lineStart = $text.LastIndexOf("`n", [Math]::Max(0, $index - 1)) + 1
                $prefix = $text.Substring($lineStart, $index - $lineStart)
                $markerMatch = [regex]::Match($comment, '^///\s*ELIOT_ARCH_OWNER:\s*(ARCH-[A-Z]+-[0-9]+)\s*$')
                if ($prefix -notmatch '^\s*$' -or -not $markerMatch.Success) {
                    throw "invalid marker syntax outside genuine outer rustdoc: ${RelativePath}:$line"
                }
                $markers.Add([pscustomobject]@{
                    Anchor = $markerMatch.Groups[1].Value
                    Offset = $index
                    Line = $line
                })
            }
            Mask-Range $maskRanges $index $end
            $index = $end
            continue
        }

        if ($current -eq '/' -and $next -eq '*') {
            $depth = 1
            $start = $index
            $outerDoc = $index + 2 -lt $length -and $text[$index + 2] -eq '*' -and
                ($index + 3 -ge $length -or $text[$index + 3] -ne '*')
            $index += 2
            while ($index -lt $length -and $depth -gt 0) {
                if ($text[$index] -eq '/' -and $index + 1 -lt $length -and $text[$index + 1] -eq '*') {
                    $depth++
                    $index += 2
                    continue
                }
                if ($text[$index] -eq '*' -and $index + 1 -lt $length -and $text[$index + 1] -eq '/') {
                    $depth--
                    $index += 2
                    continue
                }
                if ($text[$index] -eq 'E' -and $index + $MarkerToken.Length -le $length -and
                    [string]::Compare($text, $index, $MarkerToken, 0, $MarkerToken.Length, [StringComparison]::Ordinal) -eq 0) {
                    throw "reserved marker token in block comment: ${RelativePath}:$line"
                }
                if ($text[$index] -eq "`n") { $line++ }
                $index++
            }
            if ($depth -ne 0) { throw "unterminated block comment: $RelativePath" }
            Mask-Range $maskRanges $start $index
            if ($outerDoc) { $outerDocs.Add([pscustomobject]@{ Start = $start; End = $index }) }
            continue
        }

        $rawStart = -1
        $hashCount = 0
        $quoteIndex = -1
        if ($current -eq 'r') {
            $quoteIndex = $index + 1
        } elseif ($current -eq 'b' -and $next -eq 'r') {
            $quoteIndex = $index + 2
        }
        if ($quoteIndex -ge 0) {
            $cursor = $quoteIndex
            while ($cursor -lt $length -and $text[$cursor] -eq '#') {
                $hashCount++
                $cursor++
            }
            if ($cursor -lt $length -and $text[$cursor] -eq '"') {
                $rawStart = $index
                $quoteIndex = $cursor
            }
        }
        if ($rawStart -ge 0) {
            $closing = '"' + ('#' * $hashCount)
            $contentStart = $quoteIndex + 1
            $closeIndex = $text.IndexOf($closing, $contentStart, [StringComparison]::Ordinal)
            if ($closeIndex -lt 0) { throw "unterminated raw string: $RelativePath" }
            if ($text.Substring($contentStart, $closeIndex - $contentStart).Contains($MarkerToken)) {
                throw "reserved marker token in raw string: ${RelativePath}:$line"
            }
            $end = $closeIndex + $closing.Length
            for ($cursor = $index; $cursor -lt $end; $cursor++) {
                if ($text[$cursor] -eq "`n") { $line++ }
            }
            Mask-Range $maskRanges $index $end
            $index = $end
            continue
        }

        if ($current -eq '"' -or ($current -eq 'b' -and $next -eq '"')) {
            $start = $index
            if ($current -eq 'b') { $index++ }
            $index++
            $closed = $false
            while ($index -lt $length) {
                if ($text[$index] -eq 'E' -and $index + $MarkerToken.Length -le $length -and
                    [string]::Compare($text, $index, $MarkerToken, 0, $MarkerToken.Length, [StringComparison]::Ordinal) -eq 0) {
                    throw "reserved marker token in string: ${RelativePath}:$line"
                }
                if ($text[$index] -eq '\' -and $index + 1 -lt $length) {
                    $index += 2
                    continue
                }
                if ($text[$index] -eq '"') {
                    $index++
                    $closed = $true
                    break
                }
                if ($text[$index] -eq "`n") { $line++ }
                $index++
            }
            if (-not $closed) { throw "unterminated string: $RelativePath" }
            Mask-Range $maskRanges $start $index
            continue
        }

        $charQuote = -1
        if ($current -eq "'") { $charQuote = $index }
        elseif ($current -eq 'b' -and $next -eq "'") { $charQuote = $index + 1 }
        if ($charQuote -ge 0) {
            $cursor = $charQuote + 1
            if ($cursor -lt $length -and $text[$cursor] -eq '\' -and $cursor + 1 -lt $length) {
                $cursor += 2
            } elseif ($cursor -lt $length -and $text[$cursor] -ne "`n" -and $text[$cursor] -ne "'") {
                $cursor++
            }
            if ($cursor -lt $length -and $text[$cursor] -eq "'") {
                $end = $cursor + 1
                $literal = $text.Substring($index, $end - $index)
                if ($literal.Contains($MarkerToken)) {
                    throw "reserved marker token in character literal: ${RelativePath}:$line"
                }
                Mask-Range $maskRanges $index $end
                $index = $end
                continue
            }
        }

        if ($current -eq 'E' -and $index + $MarkerToken.Length -le $length -and
            [string]::Compare($text, $index, $MarkerToken, 0, $MarkerToken.Length, [StringComparison]::Ordinal) -eq 0) {
            throw "reserved marker token outside genuine outer rustdoc: ${RelativePath}:$line"
        }
        if ($current -eq "`n") { $line++ }
        $index++
    }

    $maskedBuilder = [Text.StringBuilder]::new($length)
    $cursor = 0
    foreach ($range in $maskRanges) {
        if ($range.Start -gt $cursor) { [void]$maskedBuilder.Append($text.Substring($cursor, $range.Start - $cursor)) }
        $segment = $text.Substring($range.Start, $range.End - $range.Start)
        [void]$maskedBuilder.Append([regex]::Replace($segment, '[^\r\n]', ' '))
        $cursor = $range.End
    }
    if ($cursor -lt $length) { [void]$maskedBuilder.Append($text.Substring($cursor)) }
    return [pscustomobject]@{
        Text = $text
        Masked = $maskedBuilder.ToString()
        Markers = $markers.ToArray()
        OuterDocs = $outerDocs.ToArray()
    }
}

function CfgArgs([string]$Body) {
    $parts = [Collections.Generic.List[string]]::new()
    $depth = 0
    $quoted = $false
    $escaped = $false
    $start = 0
    for ($index = 0; $index -lt $Body.Length; $index++) {
        $character = $Body[$index]
        if ($quoted) {
            if ($escaped) { $escaped = $false; continue }
            if ($character -eq '\') { $escaped = $true; continue }
            if ($character -eq '"') { $quoted = $false }
            continue
        }
        if ($character -eq '"') { $quoted = $true; continue }
        if ($character -eq '(') { $depth++ }
        elseif ($character -eq ')') { $depth-- }
        elseif ($character -eq ',' -and $depth -eq 0) {
            $parts.Add($Body.Substring($start, $index - $start).Trim())
            $start = $index + 1
        }
    }
    $tail = $Body.Substring($start).Trim()
    if ($tail.Length -gt 0) { $parts.Add($tail) }
    return $parts.ToArray()
}

function ParseCfgFormula([string]$Expression) {
    $expression = $Expression.Trim()
    if ($expression -ceq 'test') {
        return [pscustomobject]@{ Kind = 'atom'; Value = 'test'; Args = @() }
    }
    $call = [regex]::Match($expression, '(?s)^(?<op>all|any|not)\s*\((?<body>.*)\)$')
    if (-not $call.Success) {
        throw "unsupported cfg atom: $Expression"
    }
    $arguments = @(CfgArgs $call.Groups['body'].Value | ForEach-Object { ParseCfgFormula $_ })
    if ($call.Groups['op'].Value -eq 'not' -and $arguments.Count -ne 1) {
        throw "malformed cfg not() expression: $Expression"
    }
    return [pscustomobject]@{ Kind = $call.Groups['op'].Value; Value = ''; Args = $arguments }
}

function CollectCfgAtoms($Formula, $Atoms) {
    if ($Formula.Kind -eq 'atom') {
        if ($Formula.Value -cne 'test') { [void]$Atoms.Add($Formula.Value) }
        return
    }
    foreach ($argument in @($Formula.Args)) { [void](CollectCfgAtoms $argument $Atoms) }
}

function EvalCfgFormula($Formula, $Assignment) {
    if ($Formula.Kind -eq 'atom') {
        if ($Formula.Value -ceq 'test') { return $false }
        return [bool]$Assignment[$Formula.Value]
    }
    if ($Formula.Kind -eq 'not') { return -not (EvalCfgFormula $Formula.Args[0] $Assignment) }
    if ($Formula.Kind -eq 'all') {
        foreach ($argument in @($Formula.Args)) { if (-not (EvalCfgFormula $argument $Assignment)) { return $false } }
        return $true
    }
    foreach ($argument in @($Formula.Args)) { if (EvalCfgFormula $argument $Assignment) { return $true } }
    return $false
}

function CfgPossibility([string]$Expression) {
    $formula = ParseCfgFormula $Expression
    $atoms = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    [void](CollectCfgAtoms $formula $atoms)
    if ($atoms.Count -gt 12) { throw "cfg expression has too many opaque atoms: $Expression" }
    $names = @($atoms)
    $canTrue = $false
    $canFalse = $false
    $assignments = [int]1 -shl $names.Count
    for ($mask = 0; $mask -lt $assignments; $mask++) {
        $assignment = @{}
        for ($index = 0; $index -lt $names.Count; $index++) {
            $assignment[$names[$index]] = (($mask -band ([int]1 -shl $index)) -ne 0)
        }
        if (EvalCfgFormula $formula $assignment) { $canTrue = $true } else { $canFalse = $true }
        if ($canTrue -and $canFalse) { break }
    }
    return [pscustomobject]@{ CanTrue = $canTrue; CanFalse = $canFalse }
}

function CfgAttributes([string]$MaskedText, [string]$OriginalText = $MaskedText) {
    $attributes = [Collections.Generic.List[object]]::new()
    foreach ($match in [regex]::Matches($MaskedText, '#\s*(?<inner>!)?\[\s*(?<kind>cfg|cfg_attr)\s*\(')) {
        $open = $MaskedText.IndexOf('(', $match.Index)
        $depth = 0
        $close = -1
        for ($index = $open; $index -lt $MaskedText.Length; $index++) {
            if ($MaskedText[$index] -eq '(') { $depth++ }
            elseif ($MaskedText[$index] -eq ')') {
                $depth--
                if ($depth -eq 0) { $close = $index; break }
            }
        }
        if ($close -lt 0) { throw 'unterminated cfg attribute' }
        $cursor = $close + 1
        while ($cursor -lt $MaskedText.Length -and [char]::IsWhiteSpace($MaskedText[$cursor])) { $cursor++ }
        if ($cursor -ge $MaskedText.Length -or $MaskedText[$cursor] -ne ']') { throw 'malformed cfg attribute' }
        $body = $OriginalText.Substring($open + 1, $close - $open - 1)
        $testOnly = $false
        $formula = $null
        if ($match.Groups['kind'].Value -eq 'cfg') {
            $formula = $body.Trim()
            $testOnly = -not (CfgPossibility $formula).CanTrue
        } else {
            $arguments = @(CfgArgs $body)
            if ($arguments.Count -lt 1) { throw 'malformed cfg_attr attribute' }
            [void](CfgPossibility $arguments[0])
            $gates = [Collections.Generic.List[string]]::new()
            $nestedTestAttribute = $false
            for ($argumentIndex = 1; $argumentIndex -lt $arguments.Count; $argumentIndex++) {
                if ($arguments[$argumentIndex] -match '^\s*(?:test|bench)\s*$') {
                    $nestedTestAttribute = $true
                    continue
                }
                if ($arguments[$argumentIndex] -match '(?s)^\s*cfg_attr\s*\(') {
                    throw 'nested cfg_attr presence gating is not admitted'
                }
                $nested = [regex]::Match($arguments[$argumentIndex], '(?s)^cfg\s*\((.*)\)$')
                if ($nested.Success) {
                    $gates.Add($nested.Groups[1].Value)
                }
            }
            if ($gates.Count -gt 0) {
                $gateExpression = 'all(' + ($gates -join ',') + ')'
                $combinedExpression = 'any(not(' + $arguments[0] + '),' + $gateExpression + ')'
                $formula = $combinedExpression
                $testOnly = -not (CfgPossibility $formula).CanTrue
            }
            if ($nestedTestAttribute) { $testOnly = $true }
        }
        $attributes.Add([pscustomobject]@{
            Start = $match.Index
            End = $cursor + 1
            Inner = $match.Groups['inner'].Success
            TestOnly = $testOnly
            Formula = $formula
        })
    }
    return $attributes.ToArray()
}

function CfgAttributeSetTestOnly($Attributes) {
    if (@($Attributes | Where-Object { $_.TestOnly }).Count -gt 0) { return $true }
    $formulas = @($Attributes | ForEach-Object { $_.Formula } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
    if ($formulas.Count -eq 0) { return $false }
    $combined = if ($formulas.Count -eq 1) { [string]$formulas[0] } else { 'all(' + ($formulas -join ',') + ')' }
    return -not (CfgPossibility $combined).CanTrue
}

function TestPath([string]$RelativePath) {
    $path = $RelativePath.Replace('\', '/')
    return $path -match '(?i)(^|/)(test|tests|fixture|fixtures)(/|$)' -or
        $path -match '(?i)(^|/)[^/]*_tests?\.rs$'
}

function PrecedingAttributes([string]$Text, [int]$Offset) {
    # RustLex has already converted comments to whitespace, so trim every
    # trailing masked whitespace line before collecting the attached attr.
    $prefix = $Text.Substring(0, $Offset).TrimEnd()
    $lines = @($prefix -split "`n")
    $index = $lines.Count - 1
    $contiguous = [Collections.Generic.List[string]]::new()
    while ($index -ge 0) {
        $line = [string]$lines[$index]
        if ([string]::IsNullOrWhiteSpace($line)) { break }
        $contiguous.Insert(0, $line)
        $index--
    }
    $firstAttribute = -1
    for ($lineIndex = 0; $lineIndex -lt $contiguous.Count; $lineIndex++) {
        if ($contiguous[$lineIndex] -match '^\s*#\s*\[') { $firstAttribute = $lineIndex; break }
    }
    if ($firstAttribute -lt 0) { return $null }
    $depth = 0
    for ($lineIndex = $firstAttribute; $lineIndex -lt $contiguous.Count; $lineIndex++) {
        $line = [string]$contiguous[$lineIndex]
        if ($depth -eq 0 -and $line -notmatch '^\s*#\s*\[') { return $null }
        $depth += BracketDelta $line
        if ($depth -lt 0) { return $null }
    }
    if ($depth -ne 0) { return $null }
    return ($contiguous | Select-Object -Skip $firstAttribute) -join "`n"
}

function HasPrecedingOuterAttribute([string]$Text, [int]$Offset) {
    return $null -ne (PrecedingAttributes $Text $Offset)
}

function HasPrecedingTestAttribute([string]$Text, [int]$Offset) {
    $attributeText = PrecedingAttributes $Text $Offset
    if ($null -eq $attributeText) { return $false }
    return CfgAttributeSetTestOnly @(CfgAttributes $attributeText $attributeText)
}

function BracketDelta([string]$Text) {
    $depth = 0
    $quoted = $false
    $escaped = $false
    foreach ($character in $Text.ToCharArray()) {
        if ($quoted) {
            if ($escaped) { $escaped = $false; continue }
            if ($character -eq '\') { $escaped = $true; continue }
            if ($character -eq '"') { $quoted = $false }
            continue
        }
        if ($character -eq '"') { $quoted = $true; continue }
        if ($character -eq '[') { $depth++ }
        elseif ($character -eq ']') { $depth-- }
    }
    return $depth
}

function AssertOuterAttributeRemainder([string]$MaskedText, [string]$Context) {
    $close = $MaskedText.LastIndexOf(']')
    if ($close -lt 0) { throw "incomplete outer attribute after source marker at $Context" }
    $sameLineRemainder = ($MaskedText.Substring($close + 1) -split "`n", 2)[0]
    if (-not [string]::IsNullOrWhiteSpace($sameLineRemainder)) {
        throw "outer attribute has non-whitespace same-line remainder outside grammar at $Context"
    }
}

function PublicItem($Lines, $MaskedLines, [int]$MarkerLine, [string]$RelativePath) {
    $index = $MarkerLine + 1
    while ($index -lt $Lines.Count -and ([string]$Lines[$index]) -match '^\s*///(?!/)' -and
        ([string]$MaskedLines[$index]) -match '^\s*$') {
        $index++
    }

    $attributes = [Collections.Generic.List[object]]::new()
    while ($index -lt $Lines.Count -and ([string]$MaskedLines[$index]) -match '^\s*#\[') {
        $attributeSource = [string]$Lines[$index]
        $attributeMasked = [string]$MaskedLines[$index]
        $depth = BracketDelta $attributeMasked
        if ($depth -lt 0) { throw "incomplete outer attribute after source marker at line $($MarkerLine + 1)" }
        while ($depth -gt 0) {
            $index++
            if ($index -ge $Lines.Count) {
                throw "incomplete outer attribute after source marker at line $($MarkerLine + 1)"
            }
            $sourcePart = [string]$Lines[$index]
            $maskedPart = [string]$MaskedLines[$index]
            $attributeSource += "`n$sourcePart"
            $attributeMasked += "`n$maskedPart"
            $depth += BracketDelta $maskedPart
        }
        AssertOuterAttributeRemainder $attributeMasked "line $($MarkerLine + 1)"
        $attributes.Add([pscustomobject]@{ Source = $attributeSource; Masked = $attributeMasked })
        $index++
    }

    $attributeText = ($attributes | ForEach-Object { $_.Source }) -join "`n"
    $attributeMaskedText = ($attributes | ForEach-Object { $_.Masked }) -join "`n"
    if ($attributes.Count -gt 0 -and (CfgAttributeSetTestOnly @(CfgAttributes $attributeMaskedText $attributeText))) {
        throw "source marker target is test-only through cfg/cfg_attr at line $($MarkerLine + 1)"
    }
    foreach ($attribute in $attributes) {
        if ($attribute.Masked -match '(?im)^\s*#\[\s*(?:test|bench)\s*\]') {
            throw "source marker target is test-only through test/bench at line $($MarkerLine + 1)"
        }
    }

    if ($index -ge $Lines.Count) {
        throw "source marker has no following public defining item at line $($MarkerLine + 1)"
    }
    $sourceLine = [string]$Lines[$index]
    $line = [string]$MaskedLines[$index]
    if ([string]::IsNullOrWhiteSpace($line)) {
        throw "source marker is detached from its public Rust item at line $($MarkerLine + 1)"
    }
    if ($line -match '^\s*pub\s*\(') {
        throw "source marker target has restricted visibility at line $($index + 1)"
    }
    if ($line -match '^\s*pub\s+use\b') {
        throw "source marker does not bind a public defining item at line $($index + 1)"
    }
    if ($line -match '^\s*pub\s+(?:(?:async|unsafe|const|extern(?:\s+"[^"]+")?)\s+)*(?<kind>fn|struct|enum|union|trait|type|const|static|mod)\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)') {
        return [pscustomobject]@{
            Name = $Matches['name']
            Kind = $Matches['kind']
            Line = $index + 1
            Text = $sourceLine.Trim()
        }
    }
    throw "source marker is not immediately followed by a public defining Rust item at line $($index + 1)"
}

function PackageFor([string]$RelativePath, $Inventory) {
    $path = $RelativePath.Replace('\', '/')
    $exact = [Collections.Generic.List[string]]::new()
    $containing = [Collections.Generic.List[object]]::new()

    foreach ($manifest in @($Inventory.manifests)) {
        if ($null -eq $manifest.package_name -or $null -eq $manifest.manifest_path) {
            throw 'modules inventory contains an incomplete manifest entry'
        }
        $manifestPath = ([string]$manifest.manifest_path).Replace('/', [IO.Path]::DirectorySeparatorChar)
        $root = [IO.Path]::GetDirectoryName($manifestPath)
        if ($null -eq $root) { $root = '' }
        $root = $root.Replace('\', '/').TrimEnd('/')
        $package = [string]$manifest.package_name
        $targets = @($manifest.source_modules_and_crates.targets)
        foreach ($target in $targets) {
            if ($path -eq ([string]$target.src_path).Replace('\', '/')) {
                $exact.Add($package)
                break
            }
        }
        if ([string]::IsNullOrEmpty($root) -or $path.StartsWith("$root/", [StringComparison]::OrdinalIgnoreCase)) {
            $containing.Add([pscustomobject]@{ Package = $package; Root = $root })
        }
    }

    $exactPackages = @($exact | Sort-Object -Unique)
    if ($exactPackages.Count -gt 1) {
        throw "ambiguous package owner for ${RelativePath}: $($exactPackages -join ', ')"
    }
    if ($exactPackages.Count -eq 1) { return $exactPackages[0] }

    if ($containing.Count -eq 0) { throw "package owner is unresolved for $RelativePath" }
    $deepestLength = (@($containing | ForEach-Object { $_.Root.Length } | Measure-Object -Maximum).Maximum)
    $deepestPackages = @($containing | Where-Object { $_.Root.Length -eq $deepestLength } | ForEach-Object { $_.Package } | Sort-Object -Unique)
    if ($deepestPackages.Count -ne 1) {
        throw "ambiguous package owner for ${RelativePath}: $($deepestPackages -join ', ')"
    }
    return $deepestPackages[0]
}

function ModuleCandidates([string]$Root, [string]$ParentRelative, [string]$Name) {
    $parent = $ParentRelative.Replace('\', '/')
    $directory = [IO.Path]::GetDirectoryName($parent)
    if ($null -eq $directory) { $directory = '' }
    $directory = $directory.Replace('\', '/')
    $fileName = [IO.Path]::GetFileNameWithoutExtension($parent)
    $base = if ($fileName -in @('lib', 'main', 'mod')) { $directory } elseif ([string]::IsNullOrEmpty($directory)) { $fileName } else { "$directory/$fileName" }
    return @("$base/$Name.rs", "$base/$Name/mod.rs") | ForEach-Object { $_.TrimStart('/') }
}

function ExternalProductionModules($Lexed) {
    $modules = [Collections.Generic.List[string]]::new()
    $pattern = '(?m)^[ \t]*(?:pub(?:\s*\([^)]*\))?\s+)?mod\s+(?<name>[A-Za-z_][A-Za-z0-9_]*)\s*;'
    foreach ($match in [regex]::Matches($Lexed.Masked, $pattern)) {
        if (-not (IsLexicalTopLevel $Lexed.Masked $match.Index)) { continue }
        if (AttachedOuterDecoration $Lexed $match.Index) { continue }
        $modules.Add($match.Groups['name'].Value)
    }
    return $modules.ToArray()
}

function IsLexicalTopLevel([string]$Text, [int]$Offset) {
    $round = 0
    $square = 0
    $curly = 0
    for ($index = 0; $index -lt $Offset; $index++) {
        switch ($Text[$index]) {
            '(' { $round++ }
            ')' { $round-- }
            '[' { $square++ }
            ']' { $square-- }
            '{' { $curly++ }
            '}' { $curly-- }
        }
    }
    return $round -eq 0 -and $square -eq 0 -and $curly -eq 0
}

function AttachedOuterAttribute([string]$Text, [int]$Offset) {
    $prefix = $Text.Substring(0, $Offset).TrimEnd()
    if (-not $prefix.EndsWith(']', [StringComparison]::Ordinal)) { return $false }
    $hash = $prefix.LastIndexOf('#')
    if ($hash -lt 0) { return $false }
    return $prefix.Substring($hash) -match '^#\s*\['
}

function AttachedOuterDecoration($Lexed, [int]$Offset) {
    if (AttachedOuterAttribute $Lexed.Masked $Offset) { return $true }
    foreach ($doc in @($Lexed.OuterDocs)) {
        if ($doc.End -le $Offset -and
            $Lexed.Masked.Substring([int]$doc.End, $Offset - [int]$doc.End) -match '^\s*$') {
            return $true
        }
    }
    return $false
}

function ProductionFileSet([string]$Root, $Inventory, [string[]]$CandidatePaths = @()) {
    $reachable = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $queue = [Collections.Generic.Queue[string]]::new()
    $candidatePackages = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($candidatePath in @($CandidatePaths)) {
        [void]$candidatePackages.Add((PackageFor $candidatePath $Inventory))
    }
    foreach ($manifest in @($Inventory.manifests)) {
        if ($candidatePackages.Count -gt 0 -and -not $candidatePackages.Contains([string]$manifest.package_name)) { continue }
        foreach ($target in @($manifest.source_modules_and_crates.targets)) {
            $kinds = if ($target.PSObject.Properties.Name -contains 'kind') {
                @($target.kind | ForEach-Object { [string]$_ })
            } else { @() }
            if (@($kinds | Where-Object { $_ -in @('test', 'bench', 'example', 'custom-build') }).Count -gt 0) { continue }
            $relative = ([string]$target.src_path).Replace('\', '/')
            if (-not [string]::IsNullOrWhiteSpace($relative)) { $queue.Enqueue($relative) }
        }
    }
    while ($queue.Count -gt 0) {
        $relative = $queue.Dequeue()
        if ($reachable.Contains($relative)) { continue }
        $full = Join-Path $Root $relative
        if (-not (Test-Path -LiteralPath $full -PathType Leaf)) {
            throw "production Cargo target/module is missing: $relative"
        }
        $lexed = RustLex (Read-Utf8 $full) $relative
        $rootInner = @(CfgAttributes $lexed.Masked $lexed.Text | Where-Object {
            $_.Inner -and (IsLexicalTopLevel $lexed.Masked $_.Start)
        })
        $crateOnlyTest = CfgAttributeSetTestOnly $rootInner
        if ($crateOnlyTest) { continue }
        [void]$reachable.Add($relative)
        foreach ($name in @(ExternalProductionModules $lexed)) {
            $candidates = @(ModuleCandidates $Root $relative $name | Where-Object {
                Test-Path -LiteralPath (Join-Path $Root $_) -PathType Leaf
            })
            if ($candidates.Count -gt 1) { throw "ambiguous Rust module file for ${relative}::${name}" }
            if ($candidates.Count -eq 1) { $queue.Enqueue($candidates[0]) }
        }
    }
    return $reachable
}

function AssertBindingRelations($Bindings) {
    $duplicatePair = @($Bindings | Group-Object { "$($_.Anchor)|$($_.Symbol)" } | Where-Object Count -gt 1)
    if ($duplicatePair.Count -gt 0) { throw "duplicate anchor-symbol pair: $($duplicatePair[0].Name)" }
    $ambiguousAnchor = @($Bindings | Group-Object Anchor | Where-Object Count -gt 1)
    if ($ambiguousAnchor.Count -gt 0) { throw "anchor has multiple source symbols: $($ambiguousAnchor[0].Name)" }
    $reusedSymbol = @($Bindings | Group-Object Symbol | Where-Object Count -gt 1)
    if ($reusedSymbol.Count -gt 0) { throw "symbol has multiple architecture anchors: $($reusedSymbol[0].Name)" }
}

function CodeBindings([string]$Root, $Anchors, $Inventory) {
    $known = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($anchor in $Anchors) { [void]$known.Add([string]$anchor.Id) }
    $files = @(Get-ChildItem -LiteralPath $Root -Recurse -File -Filter '*.rs' |
        Where-Object {
            $_.FullName -notmatch '[\\/]\.git[\\/]' -and
            $_.FullName -notmatch '[\\/]target[\\/]' -and
            $_.FullName -notmatch '[\\/]\.codebase-memory[\\/]'
        } | Sort-Object FullName)
    $candidates = [Collections.Generic.List[object]]::new()
    foreach ($file in $files) {
        $text = Read-Utf8 $file.FullName
        if ($text.IndexOf($MarkerToken, 0, [StringComparison]::Ordinal) -ge 0) {
            $relative = [IO.Path]::GetRelativePath($Root, $file.FullName).Replace('\', '/')
            $candidates.Add([pscustomobject]@{ File = $file; Text = $text; Relative = $relative })
        }
    }
    $productionFiles = ProductionFileSet $Root $Inventory @($candidates | ForEach-Object { $_.Relative })
    $bindings = [Collections.Generic.List[object]]::new()

    foreach ($candidate in $candidates) {
        $file = $candidate.File
        $relative = $candidate.Relative
        $lexed = RustLex $candidate.Text $relative
        $lines = @($lexed.Text -split "`n")
        $maskedLines = @($lexed.Masked -split "`n")
        $rootInner = @(CfgAttributes $lexed.Masked $lexed.Text | Where-Object {
            $_.Inner -and (IsLexicalTopLevel $lexed.Masked $_.Start)
        })
        $rootInnerTestOnly = CfgAttributeSetTestOnly $rootInner
        foreach ($marker in @($lexed.Markers)) {
            $anchor = [string]$marker.Anchor
            if ((TestPath $relative) -or
                $rootInnerTestOnly -or
                (HasPrecedingTestAttribute $lexed.Masked ([int]$marker.Offset))) {
                throw "source marker is test-only: ${relative}:$($marker.Line)"
            }
            if (HasPrecedingOuterAttribute $lexed.Masked ([int]$marker.Offset)) {
                throw "source marker must precede every outer attribute on its target: ${relative}:$($marker.Line)"
            }
            if (-not (IsLexicalTopLevel $lexed.Masked ([int]$marker.Offset))) {
                throw "source marker is not a top-level production item: ${relative}:$($marker.Line)"
            }
            if (-not $productionFiles.Contains($relative)) {
                throw "source marker is not reachable from a production Cargo target: ${relative}:$($marker.Line)"
            }
            if (-not $known.Contains($anchor)) {
                throw "unknown architecture anchor in source marker: $anchor"
            }
            $item = PublicItem $lines $maskedLines ([int]$marker.Line - 1) $relative
            $bindings.Add([pscustomobject]@{
                Anchor = $anchor
                Symbol = "$relative::$($item.Name)"
                Path = $relative
                MarkerLine = [int]$marker.Line
                SourceLine = [int]$item.Line
                SourceSha256 = Sha $file.FullName
                Item = $item.Name
                Kind = $item.Kind
                Owner = PackageFor $relative $Inventory
            })
        }
    }
    AssertBindingRelations $bindings
    return $bindings.ToArray()
}

function RefusalSites([string]$Root, [string]$Path, $Anchors) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "missing refusals inventory: $Path"
    }
    $known = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($anchor in $Anchors) { [void]$known.Add([string]$anchor.Id) }
    $byAnchor = @{}
    $digestCache = @{}
    foreach ($row in @(Import-Csv -LiteralPath $Path)) {
        foreach ($field in @('stable_id', 'file', 'line', 'end_line', 'normative_anchor', 'source_sha256')) {
            if ([string]::IsNullOrWhiteSpace([string]$row.$field)) {
                throw "refusals inventory row is missing $field"
            }
        }
        $line = 0
        $endLine = 0
        if (-not [int]::TryParse([string]$row.line, [ref]$line) -or
            -not [int]::TryParse([string]$row.end_line, [ref]$endLine) -or
            $line -lt 1 -or $endLine -lt $line) {
            throw "refusals inventory has invalid line range: $($row.stable_id)"
        }
        $source = Join-Path $Root ([string]$row.file)
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "refusal site source missing: $($row.stable_id)"
        }
        $key = [IO.Path]::GetFullPath($source)
        if (-not $digestCache.ContainsKey($key)) { $digestCache[$key] = Sha $source }
        if (-not $digestCache[$key].Equals([string]$row.source_sha256, [StringComparison]::OrdinalIgnoreCase)) {
            throw "refusal site source digest stale: $($row.stable_id)"
        }
        $anchor = [string]$row.normative_anchor
        if ($known.Contains($anchor)) {
            if (-not $byAnchor.ContainsKey($anchor)) {
                $byAnchor[$anchor] = [Collections.Generic.List[string]]::new()
            }
            $byAnchor[$anchor].Add("$($row.stable_id)@$($row.file):$line-$endLine")
        }
    }
    foreach ($key in @($byAnchor.Keys)) {
        $byAnchor[$key] = @($byAnchor[$key] | Sort-Object -Culture '')
    }
    return $byAnchor
}

function Graph([string]$ArtifactPath, [string]$DatabasePath) {
    if (-not (Test-Path -LiteralPath $ArtifactPath -PathType Leaf) -or
        -not (Test-Path -LiteralPath $DatabasePath -PathType Leaf)) {
        throw 'missing code graph artifact or database'
    }
    $artifact = Read-Utf8 $ArtifactPath | ConvertFrom-Json
    foreach ($field in @('schema_version', 'project', 'commit', 'nodes', 'edges')) {
        if ($null -eq $artifact.$field -or [string]::IsNullOrWhiteSpace([string]$artifact.$field)) {
            throw "graph artifact lacks $field"
        }
    }
    $nodes = 0L
    $edges = 0L
    if (-not [int64]::TryParse([string]$artifact.nodes, [ref]$nodes) -or $nodes -lt 0 -or
        -not [int64]::TryParse([string]$artifact.edges, [ref]$edges) -or $edges -lt 0) {
        throw 'graph artifact has invalid node/edge counts'
    }
    $databaseSize = [int64](Get-Item -LiteralPath $DatabasePath).Length
    if ($databaseSize -le 0) { throw 'graph database is empty' }
    return [ordered]@{
        artifact_path = Rel $ArtifactPath
        artifact_sha256 = Sha $ArtifactPath
        database_path = Rel $DatabasePath
        database_sha256 = Sha $DatabasePath
        nodes = $nodes
        edges = $edges
        artifact_schema_version = [int]$artifact.schema_version
        graph_project = [string]$artifact.project
        graph_commit = [string]$artifact.commit
        database_size = $databaseSize
    }
}

function Model {
    $architecture = Rows (Read-Utf8 $ArchitecturePath) '^## A16\.1\. Decision anchors\s*$' '^## A16\.2\.' '^[|]\s*ID\s*[|]\s*Класс\s*[|]\s*Решение\s*[|]\s*$' 'architecture'
    $implementation = Rows (Read-Utf8 $ImplementationPath) '^# Appendix H\. Full Architecture conformance map\s*$' '^# Appendix I\.' '^[|]\s*Architecture ID\s*[|]\s*Primary implementation sections / owner\s*[|]\s*Observable proof family\s*[|]\s*$' 'implementation'
    AssertPair $architecture $implementation

    $inventory = Read-Utf8 $ModulesPath | ConvertFrom-Json
    if ($null -eq $inventory.manifests) { throw 'modules inventory has no manifests' }
    $bindings = @(CodeBindings $RepoRoot $architecture $inventory)
    $refusals = RefusalSites $RepoRoot $RefusalsPath $architecture
    $implementationById = @{}
    foreach ($row in $implementation) { $implementationById[$row.Id] = $row }

    $architectureProjection = (($architecture | ForEach-Object { "$($_.Id)|$($_.Class)|$(Norm $_.Decision)" }) -join "`n") + "`n"
    $implementationProjection = (($architecture | ForEach-Object {
        $row = $implementationById[$_.Id]
        "$($_.Id)|$(Norm $row.ScopeOwner)|$(Norm $row.Proof)"
    }) -join "`n") + "`n"

    return [pscustomobject]@{
        Architecture = $architecture
        Implementation = $implementation
        ImplementationById = $implementationById
        Bindings = $bindings
        Refusals = $refusals
        Graph = Graph $GraphArtifactPath $GraphDatabasePath
        ArchitectureHash = Sha $ArchitecturePath
        ImplementationHash = Sha $ImplementationPath
        PairHash = TextSha ($architectureProjection + "---`n" + $implementationProjection)
        GeneratorHash = Sha $GeneratorPath
        VerifierHash = Sha $VerifierPath
        DecisionHash = Sha $DecisionPath
        BindingDecisionHash = Sha $BindingDecisionPath
        ModulesHash = Sha $ModulesPath
        RefusalsHash = Sha $RefusalsPath
    }
}

function BindingsFor($Model, [string]$Anchor) {
    return @($Model.Bindings | Where-Object { $_.Anchor -eq $Anchor })
}

function Conformance($Model) {
    $lines = [Collections.Generic.List[string]]::new()
    $lines.Add('# GENERATED FILE - DO NOT EDIT. Content-bound projection of A16.1, Appendix H, and code-side joins.')
    $lines.Add('schema_version = "eliot-conformance-v3"')
    $lines.Add('authority_status = "GENERATED_PROJECTION"')
    $lines.Add('provenance_mode = "CONTENT_BOUND"')
    $lines.Add("architecture_source_path = $(Toml (Rel $ArchitecturePath))")
    $lines.Add("implementation_source_path = $(Toml (Rel $ImplementationPath))")
    $lines.Add("generator_path = $(Toml (Rel $GeneratorPath))")
    $lines.Add("verifier_path = $(Toml (Rel $VerifierPath))")
    $lines.Add("result_envelope_contract_path = $(Toml (Rel $DecisionPath))")
    $lines.Add("binding_contract_path = $(Toml (Rel $BindingDecisionPath))")
    $lines.Add("modules_inventory_path = $(Toml (Rel $ModulesPath))")
    $lines.Add("refusals_inventory_path = $(Toml (Rel $RefusalsPath))")
    $lines.Add("architecture_source_sha256 = $(Toml $Model.ArchitectureHash)")
    $lines.Add("implementation_source_sha256 = $(Toml $Model.ImplementationHash)")
    $lines.Add("normalized_pair_sha256 = $(Toml $Model.PairHash)")
    $lines.Add("generator_source_sha256 = $(Toml $Model.GeneratorHash)")
    $lines.Add("verifier_source_sha256 = $(Toml $Model.VerifierHash)")
    $lines.Add("result_envelope_contract_sha256 = $(Toml $Model.DecisionHash)")
    $lines.Add("binding_contract_sha256 = $(Toml $Model.BindingDecisionHash)")
    $lines.Add("modules_inventory_sha256 = $(Toml $Model.ModulesHash)")
    $lines.Add("refusals_inventory_sha256 = $(Toml $Model.RefusalsHash)")
    $lines.Add("graph_artifact_path = $(Toml $Model.Graph.artifact_path)")
    $lines.Add("graph_artifact_sha256 = $(Toml $Model.Graph.artifact_sha256)")
    $lines.Add("graph_database_path = $(Toml $Model.Graph.database_path)")
    $lines.Add("graph_database_sha256 = $(Toml $Model.Graph.database_sha256)")
    $lines.Add("graph_schema_version = $($Model.Graph.artifact_schema_version)")
    $lines.Add("graph_project = $(Toml $Model.Graph.graph_project)")
    $lines.Add("graph_commit = $(Toml $Model.Graph.graph_commit)")
    $lines.Add("graph_nodes = $($Model.Graph.nodes)")
    $lines.Add("graph_edges = $($Model.Graph.edges)")
    $lines.Add("graph_database_size = $($Model.Graph.database_size)")
    $lines.Add("anchor_count = $ExpectedAnchorCount")
    $lines.Add("code_binding_count = $(@($Model.Bindings).Count)")
    $lines.Add("unknown_owner_count = $(@($Model.Architecture | Where-Object { @(BindingsFor $Model $_.Id).Count -eq 0 }).Count)")
    $lines.Add('')

    foreach ($anchor in $Model.Architecture) {
        $implementation = $Model.ImplementationById[$anchor.Id]
        $scope = Scope $implementation.ScopeOwner
        $bindings = @(BindingsFor $Model $anchor.Id)
        $owner = if ($bindings.Count -eq 1) { $bindings[0].Owner } else { 'UNKNOWN' }
        $symbols = @($bindings | ForEach-Object { $_.Symbol } | Sort-Object -Culture '')
        $sites = @($bindings | ForEach-Object { "$($_.Path):$($_.SourceLine)" } | Sort-Object -Culture '')
        $refusalSites = if ($Model.Refusals.ContainsKey($anchor.Id)) { @($Model.Refusals[$anchor.Id]) } else { @() }
        $lines.Add('[[requirement]]')
        $lines.Add("id = $(Toml $anchor.Id)")
        $lines.Add("class = $(Toml $anchor.Class)")
        $lines.Add("decision = $(Toml (Norm $anchor.Decision))")
        $lines.Add("owner = $(Toml $owner)")
        $lines.Add("source_handles = $(TomlArray $scope.Handles)")
        $lines.Add("symbols = $(TomlArray $symbols)")
        $lines.Add("symbol_sites = $(TomlArray $sites)")
        $lines.Add("refusal_sites = $(TomlArray $refusalSites)")
        $lines.Add('support = "UNKNOWN"')
        $lines.Add('invalidation = []')
        $lines.Add("observable_proof = $(Toml (Norm $implementation.Proof))")
        $lines.Add('')
    }

    foreach ($binding in @($Model.Bindings | Sort-Object Symbol, Anchor -Culture '')) {
        $lines.Add('[[symbol_anchor]]')
        $lines.Add("symbol = $(Toml $binding.Symbol)")
        $lines.Add("anchor = $(Toml $binding.Anchor)")
        $lines.Add("owner = $(Toml $binding.Owner)")
        $lines.Add("source_path = $(Toml $binding.Path)")
        $lines.Add("marker_line = $($binding.MarkerLine)")
        $lines.Add("source_line = $($binding.SourceLine)")
        $lines.Add("source_sha256 = $(Toml $binding.SourceSha256)")
        $lines.Add("item = $(Toml $binding.Item)")
        $lines.Add("item_kind = $(Toml $binding.Kind)")
        $lines.Add('')
    }
    return (($lines -join "`n") + "`n")
}

function Json($Value) {
    return ($Value | ConvertTo-Json -Depth 30)
}

function Envelope($Model, [string]$ConformanceHash) {
    $sources = @(
        [ordered]@{ path = Rel $ArchitecturePath; role = 'current repository normative projection'; sha256 = $Model.ArchitectureHash },
        [ordered]@{ path = Rel $ImplementationPath; role = 'current repository normative projection'; sha256 = $Model.ImplementationHash },
        [ordered]@{ path = Rel $DecisionPath; role = 'resolved result-envelope contract'; sha256 = $Model.DecisionHash },
        [ordered]@{ path = Rel $BindingDecisionPath; role = 'Root-accepted anchor-symbol binding contract'; sha256 = $Model.BindingDecisionHash },
        [ordered]@{ path = Rel $ModulesPath; role = 'current module ownership inventory'; sha256 = $Model.ModulesHash },
        [ordered]@{ path = Rel $RefusalsPath; role = 'current refusal-site inventory'; sha256 = $Model.RefusalsHash },
        [ordered]@{ path = $Model.Graph.artifact_path; role = 'code graph identity and counts'; sha256 = $Model.Graph.artifact_sha256 },
        [ordered]@{ path = $Model.Graph.database_path; role = 'persisted code graph database'; sha256 = $Model.Graph.database_sha256 },
        [ordered]@{ path = Rel $GeneratorPath; role = 'projection generator'; sha256 = $Model.GeneratorHash },
        [ordered]@{ path = Rel $VerifierPath; role = 'independent projection verifier'; sha256 = $Model.VerifierHash }
    )
    $bindingCount = @($Model.Bindings).Count
    $unknownCount = @($Model.Architecture | Where-Object { @(BindingsFor $Model $_.Id).Count -eq 0 }).Count
    $structured = [ordered]@{
        disposition = 'completed'
        artifacts = @(
            [ordered]@{ path = 'docs/conformance.toml'; role = 'generated projection'; sha256 = $ConformanceHash },
            [ordered]@{ path = 'swarm/results/W1-04-implementation.json'; role = 'supporting implementation evidence'; sha256 = 'supporting-file-not-authority' }
        )
        evidence = @("58 A16.1 anchors are projected in canonical order; $bindingCount exact production bindings have code-derived owners and $unknownCount owners remain UNKNOWN.", 'Every support value remains UNKNOWN and every invalidation list remains empty.')
        discriminator_before = [ordered]@{ name = 'code-owned-anchor-bindings'; value = 'zero explicit production anchor-owner bindings; owner inference from Appendix H or names was forbidden'; status = 'observed' }
        discriminator_after = [ordered]@{ name = 'code-owned-anchor-bindings'; value = "$bindingCount exact code bindings and $unknownCount UNKNOWN owners with symmetric reverse index"; status = 'verified' }
        uncertainty = @('No support or invalidation evidence is inferred from a navigation binding.', 'The persisted graph corroborates project provenance but source markers remain the ownership authority.', 'Digest and semantic evidence assumes writer quiescence; it is not an atomic snapshot proof and does not claim TOCTOU is fixed.')
        unresolved_questions = @('The remaining UNKNOWN owners require later exact production bindings.', 'Per-anchor support and invalidation semantics require separately admitted evidence.')
        proposed_effects = @('Future implementation lanes may add an exact production marker when they can preserve the one-to-one binding contract.')
        evidence_lineage = @($sources | ForEach-Object { [ordered]@{ path = $_.path; sha256 = $_.sha256; role = $_.role } })
        schema_version = 'eliot-w1-04-implementation-v3'
        authority_status = 'EVIDENCE_ONLY'
        work_item_id = 'W1-04'
        provenance_mode = 'CONTENT_BOUND'
        source_documents = $sources
        normalized_pair_sha256 = $Model.PairHash
        generator_path = Rel $GeneratorPath
        generator_source_sha256 = $Model.GeneratorHash
        verifier_path = Rel $VerifierPath
        verifier_source_sha256 = $Model.VerifierHash
        result = [ordered]@{
            disposition = 'EVIDENCE_ONLY'
            anchors = $ExpectedAnchorCount
            code_bindings = $bindingCount
            unknown_owners = $unknownCount
            bijection = '58x58 exact ID bijection'
            support_default = 'UNKNOWN'
            invalidation_default = @()
            ordering = 'Architecture A16.1 canonical order'
            authority = 'site-local production rustdoc binding plus current module ownership; no Appendix H owner inference'
            graph = [ordered]@{
                schema_version = $Model.Graph.artifact_schema_version
                project = $Model.Graph.graph_project
                commit = $Model.Graph.graph_commit
                nodes = $Model.Graph.nodes
                edges = $Model.Graph.edges
            }
        }
        result_envelope_contract_path = Rel $DecisionPath
        binding_contract_path = Rel $BindingDecisionPath
        verification = @('generator self-test and deterministic generation', 'generator check of conformance and both result envelopes', 'independent verifier self-test and normal verification')
        residuals = @("$unknownCount anchor owners remain UNKNOWN.", 'No generated support or invalidation evidence exists.', 'Result remains EVIDENCE_ONLY; no terminal attempt is claimed.', 'Digest and semantic evidence assumes writer quiescence; it is not an atomic snapshot proof and does not claim TOCTOU is fixed.')
        authority_ceiling = 'EVIDENCE_ONLY; no terminal completion, release WIP, activation, or wave authorization.'
    }
    return [ordered]@{ schema_version = 'eliot.bootstrap-work-result.v1'; authority_status = 'EVIDENCE_ONLY'; work_item_id = 'W1-04'; structured_result = $structured }
}

function AssertStable([string]$Expected, [string]$Actual) {
    if ($Actual -cne $Expected) { throw 'generated conformance bytes are stale, tampered, or non-deterministic' }
}

function AssertEnvelope($Actual, $Expected, [string]$Path) {
    if ($null -eq $Actual) { throw "result envelope is null: $Path" }
    $actualJson = Json $Actual
    $expectedJson = Json $Expected
    if ($actualJson -cne $expectedJson) { throw "result envelope is stale, tampered, or structurally invalid: $Path" }
}

function ExpectFailure([string]$Name, [scriptblock]$Action, [string]$Pattern) {
    $caught = $null
    try { & $Action } catch { $caught = $_.Exception.Message }
    if ($null -eq $caught) { throw "SelfTest expected $Name failure" }
    if ($caught -notmatch $Pattern) { throw "SelfTest $Name error class mismatch: $caught" }
}

function NewFixture([string]$Root, [string]$Name, [string]$RelativePath, [string]$Text) {
    $fixtureRoot = Join-Path $Root $Name
    $sourcePath = Join-Path $fixtureRoot $RelativePath
    $parent = Split-Path -Parent $sourcePath
    New-Item -ItemType Directory -Path $parent -Force | Out-Null
    [IO.File]::WriteAllText($sourcePath, $Text, [Text.UTF8Encoding]::new($false))
    return $fixtureRoot
}

function FixtureInventory([string]$ManifestPath, [string]$Package, [string]$TargetPath) {
    return [pscustomobject]@{
        manifests = @([pscustomobject]@{
            package_name = $Package
            manifest_path = $ManifestPath
            source_modules_and_crates = [pscustomobject]@{
                targets = @([pscustomobject]@{ src_path = $TargetPath })
            }
        })
    }
}

function SelfTest {
    $model = Model
    if (@($model.Architecture).Count -ne $ExpectedAnchorCount -or @($model.Implementation).Count -ne $ExpectedAnchorCount) {
        throw 'SelfTest model count failed'
    }
    if (@($model.Bindings).Count -ne 4) { throw 'SelfTest expected four current bindings' }
    if (@($model.Architecture | Where-Object { @(BindingsFor $model $_.Id).Count -eq 0 }).Count -ne 54) {
        throw 'SelfTest expected 54 current UNKNOWN owners'
    }
    $first = Conformance $model
    $second = Conformance $model
    if ($first -cne $second) { throw 'SelfTest determinism failed' }
    if ($first -notmatch 'schema_version = "eliot-conformance-v3"') { throw 'SelfTest schema v3 failed' }
    if ($first -match '(?i)timestamp|indexed_at|worktree|source_revision') { throw 'SelfTest volatile provenance leaked' }
    $tampered = $first.Replace('source_line = ', 'source_line = 999 # tampered; source_line = ')
    ExpectFailure 'reverse/conformance tamper' { AssertStable $first $tampered } 'stale|tampered|non-deterministic'

    $tempRoot = Join-Path ([IO.Path]::GetTempPath()) ('eliot-conformance-selftest-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tempRoot | Out-Null
    try {
        $anchor = [pscustomobject]@{ Id = 'ARCH-TEST-01' }
        $inventory = FixtureInventory 'Cargo.toml' 'fixture' 'src/lib.rs'
        $valid = "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n/// Fixture docs.`n#[derive(Debug)]`npub struct Good {}`n"
        $validRoot = NewFixture $tempRoot 'valid' 'src/lib.rs' $valid
        $validBindings = @(CodeBindings $validRoot @($anchor) $inventory)
        if ($validBindings.Count -ne 1 -or $validBindings[0].Kind -ne 'struct') { throw 'SelfTest valid marker binding failed' }

        $rawRoot = NewFixture $tempRoot 'raw-string' 'src/lib.rs' @"
pub const SPOOF: &str = r#"ELIOT_ARCH_OWNER: ARCH-TEST-01"#;
"@
        ExpectFailure 'raw-string spoof' { CodeBindings $rawRoot @($anchor) $inventory } 'raw string'

        $normalRoot = NewFixture $tempRoot 'normal-string' 'src/lib.rs' @"
pub const SPOOF: &str = "ELIOT_ARCH_OWNER: ARCH-TEST-01";
"@
        ExpectFailure 'normal-string spoof' { CodeBindings $normalRoot @($anchor) $inventory } 'string'

        $blockRoot = NewFixture $tempRoot 'block-comment' 'src/lib.rs' "/* ELIOT_ARCH_OWNER: ARCH-TEST-01 */`npub struct Hidden;`n"
        ExpectFailure 'block-comment spoof' { CodeBindings $blockRoot @($anchor) $inventory } 'block comment'

        $cfgRoot = NewFixture $tempRoot 'cfg-test' 'src/lib.rs' @"
#[cfg(test)]
mod hidden {
    /// ELIOT_ARCH_OWNER: ARCH-TEST-01
    pub fn hidden() {}
}
"@
        ExpectFailure 'direct cfg(test)' { CodeBindings $cfgRoot @($anchor) $inventory } 'test-only|top-level'

        $lifetimeCfgRoot = NewFixture $tempRoot 'nested-cfg-lifetime' 'src/lib.rs' @"
#[cfg(test)]
mod hidden {
    fn helper<'a>() { let _: &'a str = ""; }
    /// ELIOT_ARCH_OWNER: ARCH-TEST-01
    pub struct LifetimeCfg;
}
"@
        ExpectFailure 'nested cfg(test) with lifetime syntax' { CodeBindings $lifetimeCfgRoot @($anchor) $inventory } 'test-only|top-level'

        $directCfgRoot = NewFixture $tempRoot 'direct-cfg-test' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg(test)]
pub struct DirectCfg;
"@
        ExpectFailure 'direct cfg(test) attribute' { CodeBindings $directCfgRoot @($anchor) $inventory } 'test-only'

        $cfgAttrRoot = NewFixture $tempRoot 'cfg-attr-test' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg_attr(test, derive(Debug))]
pub struct CfgAttr;
"@
        $cfgAttrBindings = @(CodeBindings $cfgAttrRoot @($anchor) $inventory)
        if ($cfgAttrBindings.Count -ne 1 -or $cfgAttrBindings[0].Item -ne 'CfgAttr') {
            throw 'cfg_attr(test, derive(...)) was incorrectly rejected'
        }

        $cfgAttrGateRoot = NewFixture $tempRoot 'cfg-attr-test-gate' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg_attr(not(test), cfg(test))]
pub struct CfgAttrGate;
"@
        ExpectFailure 'cfg_attr(not(test), cfg(test))' { CodeBindings $cfgAttrGateRoot @($anchor) $inventory } 'test-only'

        $cfgAttrUnsupportedBaseRoot = NewFixture $tempRoot 'cfg-attr-unsupported-base' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg_attr(unix, derive(Clone))]
pub struct CfgAttrUnsupportedBase;
"@
        ExpectFailure 'cfg_attr(unix, derive(Clone))' { CodeBindings $cfgAttrUnsupportedBaseRoot @($anchor) $inventory } 'unsupported cfg atom'

        $cfgAttrNestedRoot = NewFixture $tempRoot 'cfg-attr-nested-cfg-attr' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg_attr(not(test), cfg_attr(not(test), cfg(test)))]
pub struct NeverProduction;
"@
        ExpectFailure 'nested cfg_attr presence gating' { CodeBindings $cfgAttrNestedRoot @($anchor) $inventory } 'nested cfg_attr presence gating is not admitted'

        $cfgAttrNestedTestRoot = NewFixture $tempRoot 'cfg-attr-nested-test' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg_attr(not(test), test)]
pub fn CfgAttrNestedTest() {}
"@
        ExpectFailure 'cfg_attr(not(test), test)' { CodeBindings $cfgAttrNestedTestRoot @($anchor) $inventory } 'test-only'

        $cfgAttrNestedBenchRoot = NewFixture $tempRoot 'cfg-attr-nested-bench' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg_attr(not(test), bench)]
pub fn CfgAttrNestedBench() {}
"@
        ExpectFailure 'cfg_attr(not(test), bench)' { CodeBindings $cfgAttrNestedBenchRoot @($anchor) $inventory } 'test-only'

        $correlatedCfgAttrRoot = NewFixture $tempRoot 'cfg-attr-correlated-test' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg_attr(not(test), cfg(feature = "fixture"), cfg(not(feature = "fixture")))]
pub struct CorrelatedCfgAttr;
"@
        ExpectFailure 'correlated cfg_attr test expression' { CodeBindings $correlatedCfgAttrRoot @($anchor) $inventory } 'unsupported cfg atom'

        $cfgDeclRoot = NewFixture $tempRoot 'cfg-test-declaration' 'src/lib.rs' @"
#[cfg(test)]
mod tests;
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
pub struct AfterDeclaration;
"@
        $declarationBindings = @(CodeBindings $cfgDeclRoot @($anchor) $inventory)
        if ($declarationBindings.Count -ne 1 -or $declarationBindings[0].Item -ne 'AfterDeclaration') {
            throw 'cfg(test) semicolon declaration incorrectly masked following marker'
        }

        $innerCfgRoot = NewFixture $tempRoot 'inner-cfg-test' 'src/lib.rs' @"
#![cfg(test)]
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
pub struct InnerCfg;
"@
        ExpectFailure 'inner cfg(test)' { CodeBindings $innerCfgRoot @($anchor) $inventory } 'test-only'

        $notCfgRoot = NewFixture $tempRoot 'cfg-not-test' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg(not(test))]
pub struct NotCfg;
"@
        $notCfgBindings = @(CodeBindings $notCfgRoot @($anchor) $inventory)
        if ($notCfgBindings.Count -ne 1 -or $notCfgBindings[0].Item -ne 'NotCfg') {
            throw 'cfg(not(test)) was incorrectly rejected'
        }

        $anyCfgRoot = NewFixture $tempRoot 'cfg-any-feature' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg(any(test, feature = "fixture"))]
pub struct AnyCfg;
"@
        ExpectFailure 'cfg(any(test, feature=...))' { CodeBindings $anyCfgRoot @($anchor) $inventory } 'unsupported cfg atom'

        $featureCfgRoot = NewFixture $tempRoot 'cfg-feature-only' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg(feature = "fixture")]
pub struct FeatureCfg;
"@
        ExpectFailure 'cfg(feature = "...")' { CodeBindings $featureCfgRoot @($anchor) $inventory } 'unsupported cfg atom'

        $impossibleTargetOsRoot = NewFixture $tempRoot 'cfg-impossible-target-os-pair' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg(all(target_os = "windows", target_os = "linux"))]
pub struct ImpossibleTargetOs;
"@
        ExpectFailure 'impossible target_os pair' { CodeBindings $impossibleTargetOsRoot @($anchor) $inventory } 'unsupported cfg atom'

        $unixWindowsRoot = NewFixture $tempRoot 'cfg-unix-windows' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg(any(unix, windows))]
pub struct UnixWindows;
"@
        ExpectFailure 'unix/windows cfg pair' { CodeBindings $unixWindowsRoot @($anchor) $inventory } 'unsupported cfg atom'

        $correlatedCfgRoot = NewFixture $tempRoot 'cfg-correlated-test' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg(any(test, all(feature = "fixture", not(feature = "fixture"))))]
pub struct CorrelatedCfg;
"@
        ExpectFailure 'correlated cfg(test) expression' { CodeBindings $correlatedCfgRoot @($anchor) $inventory } 'unsupported cfg atom'

        $stackedCfgRoot = NewFixture $tempRoot 'cfg-stacked-test' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[cfg(any(test, feature = "fixture"))]
#[cfg(any(test, not(feature = "fixture")))]
pub struct StackedCfg;
"@
        ExpectFailure 'stacked cfg(test) expressions' { CodeBindings $stackedCfgRoot @($anchor) $inventory } 'unsupported cfg atom'

        $stackedInnerCfgRoot = NewFixture $tempRoot 'inner-cfg-stacked-test' 'src/lib.rs' @"
#![cfg(any(test, feature = "fixture"))]
#![cfg(any(test, not(feature = "fixture")))]
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
pub struct StackedInnerCfg;
"@
        ExpectFailure 'stacked inner cfg(test) expressions' { CodeBindings $stackedInnerCfgRoot @($anchor) $inventory } 'unsupported cfg atom|top-level'

        $fieldCfgRoot = NewFixture $tempRoot 'cfg-field-not-item' 'src/lib.rs' @"
struct Holder {
    #[cfg(test)]
    field: u8,
}
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
pub struct Real {}
"@
        $fieldCfgBindings = @(CodeBindings $fieldCfgRoot @($anchor) $inventory)
        if ($fieldCfgBindings.Count -ne 1 -or $fieldCfgBindings[0].Item -ne 'Real') {
            throw 'cfg field incorrectly masked a following top-level item'
        }

        $rawAttributeRoot = NewFixture $tempRoot 'raw-attribute' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[doc = r#"
]
pub struct Phantom;
"#]
pub struct Real;
"@
        $rawAttributeBindings = @(CodeBindings $rawAttributeRoot @($anchor) $inventory)
        if ($rawAttributeBindings.Count -ne 1 -or $rawAttributeBindings[0].Item -ne 'Real') {
            throw 'raw-string attribute content was mistaken for a public Rust item'
        }

        $stringAttributeRoot = NewFixture $tempRoot 'string-attribute' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[doc = "opens [ here"]
pub struct Real;
pub fn pad() { let s = "]"; }
pub struct Impostor;
"@
        $stringAttributeBindings = @(CodeBindings $stringAttributeRoot @($anchor) $inventory)
        if ($stringAttributeBindings.Count -ne 1 -or $stringAttributeBindings[0].Item -ne 'Real') {
            throw 'string attribute brackets absorbed a non-adjacent Rust item'
        }

        $sameLineAttributeRoot = NewFixture $tempRoot 'same-line-attribute-item' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[derive(Clone)] pub struct Impostor;
pub struct Victim;
"@
        ExpectFailure 'same-line attribute plus item' { CodeBindings $sameLineAttributeRoot @($anchor) $inventory } 'same-line remainder outside grammar'

        $reversedAttrRoot = NewFixture $tempRoot 'reversed-test-attribute' 'src/lib.rs' @"
#[cfg(test)]
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
pub struct ReversedAttr;
"@
        ExpectFailure 'test cfg attribute preceding marker' { CodeBindings $reversedAttrRoot @($anchor) $inventory } 'test-only'

        $blankGapAttrRoot = NewFixture $tempRoot 'blank-gap-test-attribute' 'src/lib.rs' @"
#[cfg(test)]

/// ELIOT_ARCH_OWNER: ARCH-TEST-01
pub struct Bad;
"@
        ExpectFailure 'test cfg attribute across blank gap' { CodeBindings $blankGapAttrRoot @($anchor) $inventory } 'test-only|must precede'

        $commentGapAttrRoot = NewFixture $tempRoot 'comment-gap-test-attribute' 'src/lib.rs' @"
#[cfg(test)]
// ordinary comment does not detach an outer attribute
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
pub struct Bad;
"@
        ExpectFailure 'test cfg attribute across ordinary comment gap' { CodeBindings $commentGapAttrRoot @($anchor) $inventory } 'test-only|must precede'

        $orphanRoot = NewFixture $tempRoot 'orphan-module' 'src/lib.rs' "pub struct Root;`n"
        NewFixture $tempRoot 'orphan-module' 'src/orphan.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Orphan;`n" | Out-Null
        ExpectFailure 'orphan production file' { CodeBindings $orphanRoot @($anchor) $inventory } 'not reachable'

        $inlineOrphanRoot = NewFixture $tempRoot 'inline-orphan-module' 'src/lib.rs' "pub mod inline { mod orphan; }`n"
        NewFixture $tempRoot 'inline-orphan-module' 'src/inline/orphan.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct InlineOrphan;`n" | Out-Null
        ExpectFailure 'inline orphan production file' { CodeBindings $inlineOrphanRoot @($anchor) $inventory } 'not reachable'

        $cfgExternalRoot = NewFixture $tempRoot 'cfg-external-helper' 'src/lib.rs' @"
#[cfg(test)]
mod helpers;
"@
        NewFixture $tempRoot 'cfg-external-helper' 'src/helpers.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct Helper;`n" | Out-Null
        ExpectFailure 'cfg(test) external helper' { CodeBindings $cfgExternalRoot @($anchor) $inventory } 'not reachable'

        $docExternalRoot = NewFixture $tempRoot 'doc-external-helper' 'src/lib.rs' "/// helper documentation`n// ordinary explanation remains trivia`nmod helpers;`n"
        NewFixture $tempRoot 'doc-external-helper' 'src/helpers.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct DocHelper;`n" | Out-Null
        ExpectFailure 'rustdoc external helper' { CodeBindings $docExternalRoot @($anchor) $inventory } 'not reachable'

        $blockDocExternalRoot = NewFixture $tempRoot 'block-doc-external-helper' 'src/lib.rs' "/** helper documentation */`n// ordinary explanation remains trivia`nmod helpers;`n"
        NewFixture $tempRoot 'block-doc-external-helper' 'src/helpers.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct BlockDocHelper;`n" | Out-Null
        ExpectFailure 'block rustdoc external helper' { CodeBindings $blockDocExternalRoot @($anchor) $inventory } 'not reachable'

        $multilineCfgExternalRoot = NewFixture $tempRoot 'multiline-cfg-external-helper' 'src/lib.rs' @"
#[cfg(
    all(test, feature = "fixture")
)]
mod helpers;
"@
        NewFixture $tempRoot 'multiline-cfg-external-helper' 'src/helpers.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub struct MultiHelper;`n" | Out-Null
        ExpectFailure 'multiline cfg(test) external helper' { CodeBindings $multilineCfgExternalRoot @($anchor) $inventory } 'unsupported cfg atom|not reachable'

        $pathRoot = NewFixture $tempRoot 'test-path' 'tests/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub fn hidden() {}`n"
        $pathInventory = FixtureInventory 'Cargo.toml' 'fixture' 'tests/lib.rs'
        ExpectFailure 'test path' { CodeBindings $pathRoot @($anchor) $pathInventory } 'test-only'

        $blankRoot = NewFixture $tempRoot 'blank-detachment' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n`npub fn detached() {}`n"
        ExpectFailure 'blank detachment' { CodeBindings $blankRoot @($anchor) $inventory } 'detached'

        $commentRoot = NewFixture $tempRoot 'plain-comment-detachment' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`n// plain comment`npub fn detached() {}`n"
        ExpectFailure 'plain comment detachment' { CodeBindings $commentRoot @($anchor) $inventory } 'detached'

        $testAttrRoot = NewFixture $tempRoot 'test-attribute' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[test]
pub fn test_item() {}
"@
        ExpectFailure 'test attribute' { CodeBindings $testAttrRoot @($anchor) $inventory } 'test-only'

        $benchAttrRoot = NewFixture $tempRoot 'bench-attribute' 'src/lib.rs' @"
/// ELIOT_ARCH_OWNER: ARCH-TEST-01
#[bench]
pub fn bench_item() {}
"@
        ExpectFailure 'bench attribute' { CodeBindings $benchAttrRoot @($anchor) $inventory } 'test-only'

        $useRoot = NewFixture $tempRoot 'pub-use' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub use crate::Thing as ThingAlias;`n"
        ExpectFailure 'pub use' { CodeBindings $useRoot @($anchor) $inventory } 'defining item'

        $unknownRoot = NewFixture $tempRoot 'unknown-anchor' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-NOT-01`npub fn nope() {}`n"
        ExpectFailure 'unknown anchor' { CodeBindings $unknownRoot @($anchor) $inventory } 'unknown architecture anchor'

        $unresolvedRoot = NewFixture $tempRoot 'unresolved-package' 'src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub fn nope() {}`n"
        $unresolvedInventory = FixtureInventory 'pkg/Cargo.toml' 'fixture' 'pkg/src/lib.rs'
        ExpectFailure 'unresolved package' { CodeBindings $unresolvedRoot @($anchor) $unresolvedInventory } 'unresolved'

        $ambiguousRoot = NewFixture $tempRoot 'ambiguous-package' 'pkg/src/lib.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub fn nope() {}`n"
        $ambiguousInventory = [pscustomobject]@{ manifests = @(
            (FixtureInventory 'pkg/Cargo.toml' 'one' 'pkg/src/lib.rs').manifests[0],
            (FixtureInventory 'pkg/Cargo.toml' 'two' 'pkg/src/lib.rs').manifests[0]
        ) }
        ExpectFailure 'ambiguous package' { CodeBindings $ambiguousRoot @($anchor) $ambiguousInventory } 'ambiguous package'

        $exactOwnerInventory = [pscustomobject]@{ manifests = @(
            (FixtureInventory 'Cargo.toml' 'exact-owner' 'src/lib.rs').manifests[0],
            (FixtureInventory 'src/Cargo.toml' 'deeper-containment' 'src/other.rs').manifests[0]
        ) }
        if ((PackageFor 'src/lib.rs' $exactOwnerInventory) -ne 'exact-owner') {
            throw 'exact Cargo target did not dominate deeper containment'
        }
        $deepOwnerInventory = [pscustomobject]@{ manifests = @(
            (FixtureInventory 'Cargo.toml' 'broad-owner' 'other.rs').manifests[0],
            (FixtureInventory 'src/nested/Cargo.toml' 'deep-owner' 'src/nested/other.rs').manifests[0]
        ) }
        if ((PackageFor 'src/nested/file.rs' $deepOwnerInventory) -ne 'deep-owner') {
            throw 'deepest unique containment was not selected'
        }

        $duplicateRoot = NewFixture $tempRoot 'duplicate-anchor' 'src/lib.rs' "mod other;`n/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub fn one() {}`n"
        NewFixture $tempRoot 'duplicate-anchor' 'src/other.rs' "/// ELIOT_ARCH_OWNER: ARCH-TEST-01`npub fn two() {}`n" | Out-Null
        ExpectFailure 'duplicate anchor' { CodeBindings $duplicateRoot @($anchor) $inventory } 'multiple source symbols'

        $syntheticDuplicate = @(
            [pscustomobject]@{ Anchor = 'ARCH-TEST-01'; Symbol = 'src/lib.rs::one' },
            [pscustomobject]@{ Anchor = 'ARCH-TEST-01'; Symbol = 'src/lib.rs::one' }
        )
        ExpectFailure 'duplicate anchor-symbol pair' { AssertBindingRelations $syntheticDuplicate } 'duplicate anchor-symbol pair'
        $syntheticReuse = @(
            [pscustomobject]@{ Anchor = 'ARCH-TEST-01'; Symbol = 'src/lib.rs::one' },
            [pscustomobject]@{ Anchor = 'ARCH-TEST-02'; Symbol = 'src/lib.rs::one' }
        )
        ExpectFailure 'symbol reuse' { AssertBindingRelations $syntheticReuse } 'symbol has multiple architecture anchors'
    }
    finally {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    $expectedEnvelope = Envelope $model (TextSha $first)
    if ($expectedEnvelope.schema_version -ne 'eliot.bootstrap-work-result.v1' -or
        $expectedEnvelope.authority_status -ne 'EVIDENCE_ONLY' -or
        $expectedEnvelope.PSObject.Properties.Name -contains 'terminal_update' -or
        @($expectedEnvelope.structured_result.source_documents).Count -ne 10) {
        throw 'SelfTest envelope contract failed'
    }
    Write-Output 'SELFTEST PASS: v3 model, strict lexical marker fixtures, package/refusal/graph provenance, exact reverse symmetry, tamper check, and evidence-only envelopes'
}

if ($SelfTest) {
    if ($Check) { throw '-SelfTest cannot be combined with -Check' }
    SelfTest
    exit 0
}

$model = Model
$bindingCount = @($model.Bindings).Count
$unknownCount = @($model.Architecture | Where-Object { @(BindingsFor $model $_.Id).Count -eq 0 }).Count
if ($bindingCount -ne 4 -or $unknownCount -ne 54) {
    throw "current source binding discriminator failed: bindings=$bindingCount UNKNOWN=$unknownCount; expected 4/54"
}

$expected = Conformance $model
if (-not (Test-Path -LiteralPath $ConformancePath -PathType Leaf)) {
    throw "missing conformance artifact: $ConformancePath"
}
AssertStable $expected (Read-Utf8 $ConformancePath)
$conformanceHash = Sha $ConformancePath
$expectedEnvelope = Envelope $model $conformanceHash
foreach ($resultPath in @($ResultPath, $SupportingResultPath)) {
    if (-not (Test-Path -LiteralPath $resultPath -PathType Leaf)) {
        throw "missing result artifact: $resultPath"
    }
    $actualEnvelope = Read-Utf8 $resultPath | ConvertFrom-Json -Depth 30
    AssertEnvelope $actualEnvelope $expectedEnvelope $resultPath
}

Write-Output "VERIFY PASS: $ExpectedAnchorCount anchors, 4 bindings/54 UNKNOWN, independent v3 projection, refusal and graph provenance, exact reverse symmetry, and both evidence-only envelopes"
