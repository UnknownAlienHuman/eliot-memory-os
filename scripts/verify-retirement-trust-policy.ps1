<#
.SYNOPSIS
    Regression probe for the owner-pinned Governor retirement trust policy of
    issue #2968. READ-ONLY: it asserts and prints, it never repairs.

.DESCRIPTION
    A green PowerShell parse is not evidence that the retirement trust contract
    works. This probe is what lets the NEXT attempt tell a real fix from a
    green parse. It answers one question per assertion:

      A1  the declared policy digest equals the observed digest of the EXACT
          bytes of the policy file
      A2  the declared verifier digest equals the observed digest of the
          verifier file
      A3  the policy declares the owner-pinned anchor the resolver demands
      A4  a forged / substituted / empty policy FAILS

    It deliberately computes digests with its OWN local implementation rather
    than by calling into scripts/lib, so a defect in the contract cannot hide
    behind the contract's own helpers. The byte digest is SHA-256 over the raw
    file bytes; the `content_sha256` canonical preimage digest is a DIFFERENT
    domain and is reported separately. Substituting one for the other is
    falsification and this probe reports it as such rather than passing.

    It NEVER populates admitted_issuers, never writes an issuer, never signs
    and never runs the release builder. It relaxes no guard in
    scripts/lib/governor-retirement-approval.ps1 or
    scripts/lib/governor-retirement-trust-root.ps1.

.PARAMETER Policy
    Repository-relative path to the trust policy. Defaults to the tracked
    scripts/lib/governor-retirement-approval-trust.json.

.PARAMETER Repo
    Repository root used for `git hash-object`. Defaults to this file's repo.

.PARAMETER Verifier
    Repository-relative path to the closure verifier / approval contract.

.EXAMPLE
    pwsh -NoProfile -File scripts/verify-retirement-trust-policy.ps1
    Exits nonzero on the current tree; the reason is printed.

.EXAMPLE
    pwsh -NoProfile -File scripts/verify-retirement-trust-policy.ps1 `
        -Policy scripts/lib/governor-retirement-approval-trust.json `
        -Repo C:\path\to\repo
#>
[CmdletBinding()]
param(
    [string]$Policy = 'scripts/lib/governor-retirement-approval-trust.json',
    [string]$Verifier = 'scripts/lib/governor-retirement-approval.ps1',
    [string]$Repo
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

if ([string]::IsNullOrWhiteSpace($Repo)) {
    $Repo = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
}

# The identities the contract itself demands, restated here so this probe
# fails closed if the contract ever stops demanding them.
$script:AnchorSchema = 'eliot-governor-retirement-approval-anchor-v1'
$script:PolicySchemas = @(
    'eliot-governor-retirement-approval-trust-v1',
    'eliot-governor-retirement-approval-trust-v2',
    'eliot-governor-retirement-approval-trust-v3'
)
$script:LegacyRepository = 'UnknownAlienHuman/eliot-memory-os'
$script:Product = 'eliot'
$script:VerifierRelPath = 'scripts/lib/governor-retirement-approval.ps1'
$script:PolicyRelPath = 'scripts/lib/governor-retirement-approval-trust.json'
$script:ClosureVerifier = 'Get-GovernorRetirementConsumerClosure'
$script:ClosureRuleSet = 'tracked-legacy-reference-closure-v2'

$script:Results = [System.Collections.Generic.List[object]]::new()
$script:FailureCount = 0

function Add-Result {
    param([string]$Id, [bool]$Ok, [string]$Detail)
    $script:Results.Add([pscustomobject]@{ id = $Id; ok = $Ok; detail = $Detail })
    if (-not $Ok) { $script:FailureCount++ }
    $mark = if ($Ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("[{0}] {1} {2}" -f $mark, $Id, $Detail)
}

function Get-ObservedByteDigest {
    param([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally { $sha.Dispose() }
}

function Get-ObservedGitBlob {
    param([string]$Repo, [string]$Path)
    $blob = (& git -C $Repo hash-object "--path=$Path" $Path 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $blob -notmatch '^[0-9a-f]{40,64}$') { return $null }
    return $blob
}

function Get-PolicyField {
    param([object]$Policy, [string]$Name)
    if ($null -eq $Policy) { return $null }
    $property = $Policy.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-FailureCount {
    # StrictMode 2.0 refuses `.Count` on a scalar, and `@(...)` around a null
    # or a single string yields different shapes. One accessor keeps every call
    # site type-stable.
    param([object]$Verdict)
    if ($null -eq $Verdict) { return 0 }
    $fails = $Verdict.PSObject.Properties['fails']
    if ($null -eq $fails -or $null -eq $fails.Value) { return 0 }
    return @($fails.Value).Count
}

function Test-FailureMentions {
    param([object]$Verdict, [string]$Token, [int]$Minimum = 1)
    return (Get-FailureCount $Verdict) -ge $Minimum -and
        (@($Verdict.fails | Where-Object { ([string]$_).Contains($Token) }).Count -ge $Minimum)
}

function Test-PolicyFile {
    # Returns a verdict object for one candidate policy: which assertions
    # hold. Used both for the repository's own policy and for the adversarial
    # policies A4 builds, so the adversarial cases run through exactly the
    # same code the real case does.
    param([string]$Label, [string]$PolicyPath, [string]$VerifierPath, [string]$RepoRoot)

    $verdict = [ordered]@{
        label = $Label
        parsed = $false
        declared_policy_sha256 = $null
        declared_policy_blob = $null
        declared_verifier_sha256 = $null
        declared_verifier_blob = $null
        declared_anchor = $null
        declared_content_sha256 = $null
        observed_policy_sha256 = $null
        observed_policy_blob = $null
        observed_verifier_sha256 = $null
        observed_verifier_blob = $null
        fails = [System.Collections.Generic.List[string]]::new()
    }

    if (-not (Test-Path -LiteralPath $PolicyPath -PathType Leaf)) {
        $verdict.fails.Add("policy file is absent: $PolicyPath")
        return [pscustomobject]$verdict
    }

    # A1 -- declared policy digest vs the observed digest of the exact bytes.
    $verdict.observed_policy_sha256 = Get-ObservedByteDigest $PolicyPath
    $verdict.observed_policy_blob = Get-ObservedGitBlob $RepoRoot $PolicyPath

    $raw = (Get-Content -LiteralPath $PolicyPath -Raw -ErrorAction SilentlyContinue)
    if ([string]::IsNullOrWhiteSpace($raw)) {
        $verdict.fails.Add('policy file is empty')
        return [pscustomobject]$verdict
    }
    try { $parsed = $raw | ConvertFrom-Json }
    catch {
        $verdict.fails.Add("policy is not parseable JSON: $($_.Exception.Message)")
        return [pscustomobject]$verdict
    }
    $verdict.parsed = $true

    $verdict.declared_policy_sha256 = [string](Get-PolicyField $parsed 'trust_policy_sha256')
    $verdict.declared_policy_blob = [string](Get-PolicyField $parsed 'trust_policy_git_blob')
    $verdict.declared_verifier_sha256 = [string](Get-PolicyField $parsed 'verifier_sha256')
    $verdict.declared_verifier_blob = [string](Get-PolicyField $parsed 'verifier_git_blob')
    $verdict.declared_anchor = [string](Get-PolicyField $parsed 'owner_pinned_trust_anchor')
    $verdict.declared_content_sha256 = [string](Get-PolicyField $parsed 'content_sha256')

    # A1. An absent declared identity is a FAIL, never a skip: the resolver
    # demands it, so the absence is the defect being probed.
    if ([string]::IsNullOrWhiteSpace($verdict.declared_policy_sha256)) {
        $verdict.fails.Add('policy declares no trust_policy_sha256 (binding 1 has nothing to compare)')
    }
    elseif ($verdict.declared_policy_sha256 -cnotmatch '^[0-9a-f]{64}$') {
        $verdict.fails.Add("trust_policy_sha256 is malformed: $($verdict.declared_policy_sha256)")
    }
    elseif ($verdict.declared_policy_sha256 -cne $verdict.observed_policy_sha256) {
        $verdict.fails.Add("declared trust_policy_sha256 does not equal the observed digest of the exact bytes (declared=$($verdict.declared_policy_sha256) observed=$($verdict.observed_policy_sha256))")
    }
    if ([string]::IsNullOrWhiteSpace($verdict.declared_policy_blob)) {
        $verdict.fails.Add('policy declares no trust_policy_git_blob')
    }
    elseif ($verdict.declared_policy_blob -cne $verdict.observed_policy_blob) {
        $verdict.fails.Add("declared trust_policy_git_blob does not equal the observed blob of the exact bytes (declared=$($verdict.declared_policy_blob) observed=$($verdict.observed_policy_blob))")
    }

    # A2 -- declared verifier digest vs the observed digest of the verifier.
    if (-not (Test-Path -LiteralPath $VerifierPath -PathType Leaf)) {
        $verdict.fails.Add("verifier file is absent: $VerifierPath")
    }
    else {
        $verdict.observed_verifier_sha256 = Get-ObservedByteDigest $VerifierPath
        $verdict.observed_verifier_blob = Get-ObservedGitBlob $RepoRoot $VerifierPath
        if ([string]::IsNullOrWhiteSpace($verdict.declared_verifier_sha256)) {
            $verdict.fails.Add('policy declares no verifier_sha256 (binding 2 has nothing to compare)')
        }
        elseif ($verdict.declared_verifier_sha256 -cne $verdict.observed_verifier_sha256) {
            $verdict.fails.Add("declared verifier_sha256 does not equal the observed digest of the verifier file (declared=$($verdict.declared_verifier_sha256) observed=$($verdict.observed_verifier_sha256))")
        }
        if (-not [string]::IsNullOrWhiteSpace($verdict.declared_verifier_blob) -and
            $verdict.declared_verifier_blob -cne $verdict.observed_verifier_blob) {
            $verdict.fails.Add("declared verifier_git_blob does not equal the observed blob of the verifier file (declared=$($verdict.declared_verifier_blob) observed=$($verdict.observed_verifier_blob)")
        }
    }

    # A3 -- the owner-pinned anchor the resolver demands must be declared.
    $schema = [string](Get-PolicyField $parsed 'schema')
    if ($script:PolicySchemas -cnotcontains $schema) {
        $verdict.fails.Add("unsupported trust policy schema: $schema")
    }
    if ($verdict.declared_anchor -cne $script:AnchorSchema) {
        $verdict.fails.Add("policy does not declare the owner-pinned trust anchor $($script:AnchorSchema) the resolver demands (declared='$($verdict.declared_anchor)')")
    }

    # Domain separation: the canonical `content_sha256` is NOT the byte digest.
    # Reporting it as a match would be falsification, so it is checked and
    # reported on its own terms.
    if (-not [string]::IsNullOrWhiteSpace($verdict.declared_content_sha256) -and
        $verdict.declared_content_sha256 -ceq $verdict.observed_policy_sha256) {
        $verdict.fails.Add('policy substitutes content_sha256 (canonical preimage domain) for the byte digest; the two are different domains and substituting one for the other is falsification')
    }

    # The policy may never declare an issuer we did not record. This probe does
    # not populate admitted_issuers, and it must not be made to pass by one.
    $issuers = @(Get-PolicyField $parsed 'admitted_issuers')
    if ($issuers.Count -gt 0) {
        $verdict.fails.Add("policy admits $($issuers.Count) issuer(s); no production retirement issuer exists and this probe does not admit one")
    }

    return [pscustomobject]$verdict
}

Write-Host '=== #2968 owner-pinned retirement trust policy probe (read-only) ==='
Write-Host "repo    : $Repo"
Write-Host "policy  : $Policy"
Write-Host "verifier: $Verifier"
Write-Host ''

$policyFull = if ([System.IO.Path]::IsPathRooted($Policy)) { $Policy } else { Join-Path $Repo $Policy }
$verifierFull = if ([System.IO.Path]::IsPathRooted($Verifier)) { $Verifier } else { Join-Path $Repo $Verifier }

# --- A1/A2/A3 against the repository's own policy -----------------------------
$real = Test-PolicyFile -Label 'repository policy' -PolicyPath $policyFull -VerifierPath $verifierFull -RepoRoot $Repo

Add-Result 'A1' ((Get-FailureCount $real) -eq 0) `
    ("policy digest: declared='{0}' observed={1} blob declared='{2}' observed={3}" -f `
        $real.declared_policy_sha256, $real.observed_policy_sha256, $real.declared_policy_blob, $real.observed_policy_blob)
foreach ($failure in $real.fails) { Write-Host "       - $failure" }

$declaredVerifier = if ([string]::IsNullOrWhiteSpace($real.declared_verifier_sha256)) { '<absent>' } else { $real.declared_verifier_sha256 }
Add-Result 'A2' ((Get-FailureCount $real) -eq 0 -and $real.declared_verifier_sha256 -ceq $real.observed_verifier_sha256) `
    ("verifier digest: declared='{0}' observed='{1}'" -f $declaredVerifier, $real.observed_verifier_sha256)

Add-Result 'A3' ($real.declared_anchor -ceq $script:AnchorSchema) `
    ("owner-pinned anchor: declared='{0}' required='{1}'" -f $real.declared_anchor, $script:AnchorSchema)

# --- A4 adversarial policies ---------------------------------------------------
# Each adversarial policy is written to a temp path, run through the SAME
# Test-PolicyFile code as the real policy, and MUST be rejected. A probe that
# cannot reject these is not evidence.
#
# The adversarial fixtures are built on a COMPLETE, HONEST v3 policy -- the
# schema the resolver actually demands -- rather than on the repository's v2
# file. That matters: if the fixtures inherited v2's own missing identities,
# every forgery would be rejected for the wrong reason and the probe would
# prove nothing. Here the honest fixture is accepted and each forgery differs
# from it by exactly one thing, so each rejection is attributable.
$scratch = Join-Path ([System.IO.Path]::GetTempPath()) "eliot-2968-probe-$([guid]::NewGuid().ToString('n'))"
New-Item -ItemType Directory -Path $scratch -Force | Out-Null
$probeRepo = $scratch

function New-HonestV3Fixture {
    param([string]$PolicySha256, [string]$PolicyBlob, [string]$VerifierSha256, [string]$VerifierBlob)
    # Every field the v3 closed contract demands, with NO issuer admitted and
    # the honest unavailable issuer state preserved.
    return [pscustomobject]([ordered]@{
            schema = 'eliot-governor-retirement-approval-trust-v3'
            release_policy = $script:LegacyRepository
            release_product = $script:Product
            release_policy_revision = '1.2.0'
            owner_pinned_trust_anchor = $script:AnchorSchema
            owner_pinned_trust_root = 'refs/heads/main'
            owner_decision_file = 'GOVERNOR_RETIREMENT_OWNER_DECISION.json'
            owner_decision_schema = 'eliot-governor-retirement-owner-decision-v1'
            trust_policy_relpath = 'scripts/lib/governor-retirement-approval-trust.json'
            trust_policy_sha256 = $PolicySha256
            trust_policy_git_blob = $PolicyBlob
            verifier_relpath = $script:VerifierRelPath
            verifier_sha256 = $VerifierSha256
            verifier_git_blob = $VerifierBlob
            closure_verifier = 'Get-GovernorRetirementConsumerClosure'
            closure_rule_set = 'tracked-legacy-reference-closure-v2'
            closure_policies = @(
                [pscustomobject]@{ owner_source_rule_set = 'tracked-legacy-reference-closure-v1'; release_candidate_rule_set = 'tracked-legacy-reference-closure-v1'; approval_release_policy_revision = '1.0.0' },
                [pscustomobject]@{ owner_source_rule_set = 'tracked-legacy-reference-closure-v2'; release_candidate_rule_set = 'tracked-legacy-reference-closure-v2'; approval_release_policy_revision = '1.2.0' })
            revocation_source = 'root-owned release policy; an issuer is admitted here only after the owner records the exact issuer identity for the semantic retirement-approval role'
            admitted_issuers = @()
            issuer_state = 'ISSUER_UNAVAILABLE'
            issuer_state_reason = 'No production release-retirement approval issuer exists on current main. Issue #2968 authorizes the narrow issuer seam and this explicit fail-closed state; it does not authorize inventing a semantic retirement authority.'
            authenticode_code_signing_policy = 'Authenticode Code Signing signers are NOT admitted for the semantic retirement-approval role.'
            content_sha256 = ('0' * 64)
        })
}

function Write-Fixture {
    param([string]$Name, [object]$Object)
    $path = Join-Path $scratch $Name
    # `-Depth 12` plus a stable key order keeps the serialised bytes a pure
    # function of the object, which is what makes the fixed-point iteration
    # below meaningful.
    ($Object | ConvertTo-Json -Depth 12) | Set-Content -LiteralPath $path -Encoding utf8
    return $path
}

try {
    # --- A4.0 CONTROL: the honest v3 fixture MUST be accepted -------------
    # If the honest fixture is rejected, every rejection below is meaningless,
    # so this is asserted first and it is also the isolation assertion: the
    # honest fixture satisfies A1-A3 EXCEPT for trust_policy_sha256 /
    # trust_policy_git_blob, which is the one requirement with no solution.
    $v3Sha = '0' * 64
    $v3Blob = '0' * 40
    $converged = $false
    $passes = 0
    $fixturePath = Join-Path $scratch 'honest-v3.json'
    for ($i = 1; $i -le 6; $i++) {
        $fixture = New-HonestV3Fixture -PolicySha256 $v3Sha -PolicyBlob $v3Blob `
            -VerifierSha256 ([string]$real.observed_verifier_sha256) -VerifierBlob ([string]$real.observed_verifier_blob)
        $fixturePath = [string](Write-Fixture -Name 'honest-v3.json' -Object $fixture)
        $obsSha = Get-ObservedByteDigest $fixturePath
        $obsBlob = Get-ObservedGitBlob $scratch $fixturePath
        $passes++
        if ($obsSha -ceq $v3Sha -and $obsBlob -ceq $v3Blob) { $converged = $true; break }
        $v3Sha = $obsSha
        $v3Blob = [string]$obsBlob
    }
    $honestVerdict = Test-PolicyFile -Label 'honest v3 fixture' -PolicyPath $fixturePath -VerifierPath $verifierFull -RepoRoot $probeRepo
    $honestFails = @($honestVerdict.fails)

    # The honest fixture must fail for EXACTLY the self-referential identity and
    # nothing else. Anything else failing means the fixture is not isolating the
    # defect, and every adversarial verdict below is reported as unreliable.
    $expectedHonestFails = @(
        'trust_policy_sha256'
        'trust_policy_git_blob'
    )
    $isolationHonest = $true
    foreach ($failure in $honestFails) {
        $matched = $false
        foreach ($token in $expectedHonestFails) {
            if ($failure.Contains($token)) { $matched = $true; break }
        }
        if (-not $matched) { $isolationHonest = $false }
    }
    $isolationHonest = $isolationHonest -and
        @($honestFails | Where-Object { $_.Contains('trust_policy_sha256') }).Count -eq 1 -and
        @($honestFails | Where-Object { $_.Contains('trust_policy_git_blob') }).Count -eq 1

    Add-Result 'A4.0' $isolationHonest `
        ("honest v3 fixture fails ONLY on the self-referential identity after {0} fixed-point iteration(s), converged={1} :: {2}" -f $passes, $converged, $(if (@($honestFails).Count -gt 0) { $honestFails -join '; ' } else { '<none>' }))

    # A5 -- the fixed point itself: the identity the policy must carry cannot
    # be the identity of the bytes that carry it.
    Add-Result 'A5' (-not $converged) `
        "declared policy identity converges to its own byte digest in $passes iteration(s): no fixed point found (sha $($v3Sha.Substring(0, 12)).. / blob $($v3Blob.Substring(0, 12))..)"

    # --- A4.1 EMPTY policy ----------------------------------------------------
    $emptyPath = Join-Path $scratch 'empty.json'
    Set-Content -LiteralPath $emptyPath -Value '' -NoNewline -Encoding utf8
    $emptyVerdict = Test-PolicyFile -Label 'empty policy' -PolicyPath $emptyPath -VerifierPath $verifierFull -RepoRoot $probeRepo
    Add-Result 'A4.1' ((Get-FailureCount $emptyVerdict) -gt 0) "empty policy rejected: $($emptyVerdict.fails -join '; ')"

    # --- A4.2 FORGED policy: the honest v3 fixture plus an invented issuer ---
    $forged = New-HonestV3Fixture -PolicySha256 $v3Sha -PolicyBlob $v3Blob `
        -VerifierSha256 $real.observed_verifier_sha256 -VerifierBlob $real.observed_verifier_blob
    $forged.admitted_issuers = @(
        [pscustomobject]@{
            issuer = 'probe-forged-issuer'
            role = 'retirement-approval'
            authority = 'probe-forged-authority'
            receipt_kind = 'detached-cms-sha256'
            receipt_certificate_thumbprint = 'A'.PadRight(40, 'A')
            owner_decision_sha256 = 'b'.PadRight(64, 'b')
            owner_decision_operation_id = 'probe-forged-operation'
            authenticode_code_signing_thumbprint = $null
        })
    $forgedVerdict = Test-PolicyFile -Label 'forged policy' -PolicyPath ([string](Write-Fixture -Name 'forged.json' -Object $forged)) -VerifierPath $verifierFull -RepoRoot $probeRepo
    Add-Result 'A4.2' ((Test-FailureMentions $forgedVerdict 'issuer')) `
        "forged policy (invented issuer on an otherwise honest v3 fixture) rejected: $($forgedVerdict.fails -join '; ')"

    # --- A4.3 SUBSTITUTED policy: claims an identity it does not have --------
    $substituted = New-HonestV3Fixture -PolicySha256 ('c' * 64) -PolicyBlob ('d' * 40) `
        -VerifierSha256 ([string]$real.observed_verifier_sha256) -VerifierBlob ([string]$real.observed_verifier_blob)
    $substitutedVerdict = Test-PolicyFile -Label 'substituted policy' -PolicyPath ([string](Write-Fixture -Name 'substituted.json' -Object $substituted)) -VerifierPath $verifierFull -RepoRoot $probeRepo
    Add-Result 'A4.3' ((Test-FailureMentions $substitutedVerdict 'does not equal the observed' 2)) `
        "substituted policy (declared sha/blob it does not have) rejected: $($substitutedVerdict.fails -join '; ')"

    # --- A4.4 ANCHOR-STRIPPED policy: every identity honest, anchor removed --
    $anchorStripped = New-HonestV3Fixture -PolicySha256 $v3Sha -PolicyBlob $v3Blob `
        -VerifierSha256 ([string]$real.observed_verifier_sha256) -VerifierBlob ([string]$real.observed_verifier_blob)
    $anchorStripped | Add-Member -MemberType NoteProperty -Name owner_pinned_trust_anchor -Value $null -Force
    $anchorVerdict = Test-PolicyFile -Label 'anchor-stripped policy' -PolicyPath ([string](Write-Fixture -Name 'anchor-stripped.json' -Object $anchorStripped)) -VerifierPath $verifierFull -RepoRoot $probeRepo
    Add-Result 'A4.4' ((Test-FailureMentions $anchorVerdict 'owner-pinned trust anchor')) `
        "anchor-stripped policy rejected: $($anchorVerdict.fails -join '; ')"

    # --- A4.5 VERIFIER-SWAPPED policy: binds a verifier that is not this one -
    # The binding a candidate cannot forge is the policy naming its VERIFIER.
    # This asserts the probe actually detects a wrong verifier identity.
    $verifierSwapped = New-HonestV3Fixture -PolicySha256 $v3Sha -PolicyBlob $v3Blob `
        -VerifierSha256 ('e' * 64) -VerifierBlob ('f' * 40)
    $swapVerdict = Test-PolicyFile -Label 'verifier-swapped policy' -PolicyPath ([string](Write-Fixture -Name 'verifier-swapped.json' -Object $verifierSwapped)) -VerifierPath $verifierFull -RepoRoot $probeRepo
    Add-Result 'A4.5' ((Test-FailureMentions $swapVerdict 'verifier' 2)) `
        "verifier-swapped policy rejected: $($swapVerdict.fails -join '; ')"
}
finally {
    Remove-Item -LiteralPath $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

Write-Host ''
Write-Host "--- summary ---"
foreach ($result in $script:Results) {
    $mark = if ($result.ok) { 'PASS' } else { 'FAIL' }
    Write-Host ("{0,-6} {1,-4} {2}" -f $mark, $result.id, $result.detail)
}

if ($script:FailureCount -ne 0) {
    Write-Host ''
    Write-Host "RESULT: FAIL ($($script:FailureCount) of $($script:Results.Count) assertions failed)."
    Write-Host 'This is the expected verdict for the current tree: the trust policy cannot bind its own byte identity without a self-referential fixed point, and the resolver therefore cannot reach a resolved root.'
    exit 1
}

Write-Host ''
Write-Host 'RESULT: PASS (every declared identity matches the observed bytes and every adversarial policy was rejected).'
exit 0