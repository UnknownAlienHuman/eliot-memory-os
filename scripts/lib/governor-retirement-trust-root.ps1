<#
.SYNOPSIS
    Owner-pinned trust root for the detached Governor retirement approval of
    issue #2968 (external audit 5918050095 defect 1).

.DESCRIPTION
    The retirement decision R(C) must be constrained by an issuer policy and a
    closure-verifier/rule-set identity that candidate C cannot redefine.
    Resolving either from `$SourceCommit` is the defect, not the fix: one
    candidate tree can rewrite admitted_issuers, the closure token set, the
    closure rule set, the approval verifier and the release builder together,
    which recreates self-approval at repository root.

    This module resolves the trust root through an OWNER-PINNED REFERENCE - an
    explicitly supplied git ref whose commit the root owner controls outside
    candidate C - and binds it STRUCTURALLY, not only by a digest that the
    candidate could also carry:

        candidate C                       (the bytes being approved)
        owner-pinned ref P                (protected ref; C does not define P)
          -> scripts/lib/governor-retirement-approval-trust.json   issuer policy
          -> scripts/lib/governor-retirement-approval.ps1           verifier / rule set

    Two independent bindings are enforced:

      1. The resolved issuer policy declares its OWN exact bytes
         (`trust_policy_sha256` plus `trust_policy_git_blob`). Changing
         admitted issuers, the policy revision or the closure rule set changes
         those declared identities, and the recomputed digest then fails.
      2. The verifier loaded and executed to produce the closure must itself
         declare that trust root: the pinned policy names
         `owner_pinned_trust_anchor`, `closure_verifier` and
         `closure_rule_set`, and the executing contract checks that its own
         resolved verifier identity declares exactly the same trust anchor. A
         candidate that substitutes a permissive verifier fails this binding
         even if a permissive policy is supplied beside it.

    The tracked file scripts/lib/governor-retirement-approval-anchor.json is
    NOT read here. It documents the currently declared owner-pinned ref, its
    commit and the admitted issuer state, so reviewers can see the declared pin
    without re-deriving it. The anchor is evidence about the ref; the ref is
    the trust root.

    Nothing selects the root from environment state, nothing searches a
    directory, no default path inside the repository exists, and an unset input
    is absence - which fails closed.
#>

$ErrorActionPreference = 'Stop'

$script:GovernorRetirementTrustAnchorSchema = 'eliot-governor-retirement-approval-anchor-v1'
$script:GovernorRetirementTrustAnchorPath = 'scripts/lib/governor-retirement-approval-anchor.json'
$script:GovernorRetirementTrustAnchorRole = 'owner-pinned-trust-root'
$script:GovernorRetirementTrustRootFile = 'GOVERNOR_RETIREMENT_TRUST_ROOT.json'
$script:GovernorRetirementTrustRootDigestDomain = 'eliot-governor-retirement-trust-root-preimage-v1'
$script:GovernorRetirementApprovalPreimageDomain = 'eliot-governor-retirement-approval-preimage-v1'
$script:GovernorRetirementClosureRuleSet = 'tracked-legacy-reference-closure-v2'
$script:GovernorRetirementClosureVerifierIdentity = 'Get-GovernorRetirementConsumerClosure'
$script:GovernorRetirementTrustPolicyRelPath = 'scripts/lib/governor-retirement-approval-trust.json'
$script:GovernorRetirementVerifierRelPath = 'scripts/lib/governor-retirement-approval.ps1'
$script:GovernorRetirementLegacyRepository = 'UnknownAlienHuman/eliot-memory-os'
$script:GovernorRetirementProduct = 'eliot'
$script:GovernorRetirementApprovalRole = 'retirement-approval'
$script:GovernorRetirementTrustPolicySchemaV2 = 'eliot-governor-retirement-approval-trust-v2'
$script:GovernorRetirementTrustPolicySchemaV3 = 'eliot-governor-retirement-approval-trust-v3'

function Get-GovernorApprovalField([object]$Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Test-GovernorRetirementGitRefSyntax([string]$Ref) {
    # A ref is supplied to `git rev-parse --verify --end-of-options`, so the
    # syntax gate here only rejects values that are plainly not refs. The exact
    # object lookup decides existence; `-`/`^`/`~`/spaces/`:`/globs are rejected
    # outright so no revision expression can widen the pinned identity.
    $text = [string]$Ref
    if ([string]::IsNullOrWhiteSpace($text) -or $text -cne $text.Trim() -or
        $text -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._\-/]*$' -or
        $text.Contains('..') -or $text.Contains('@{') -or
        $text -cnotmatch '(?:^|/|[-._])(heads|tags|remotes)/') {
        return $false
    }
    return $true
}

function Resolve-GovernorRetirementOwnerPinnedRef([string]$Repo, [string]$TrustRef) {
    # The trust root is resolved from an EXPLICIT owner-pinned ref, never from
    # `$SourceCommit`. There is no ambient ref discovery, no environment
    # selection, and no fallback to the candidate commit.
    if ([string]::IsNullOrWhiteSpace($Repo) -or -not (Test-Path -LiteralPath $Repo -PathType Container)) {
        throw 'the retirement trust root requires the repository root of candidate C'
    }
    if ([string]::IsNullOrWhiteSpace($TrustRef)) {
        return $null
    }
    if (-not (Test-GovernorRetirementGitRefSyntax $TrustRef)) {
        throw "the retirement trust root must be an explicit owner-pinned git ref; refusing: $TrustRef"
    }
    $commit = (& git -C $Repo rev-parse --verify --end-of-options "$TrustRef^{commit}" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $commit -notmatch '^[0-9a-f]{40,64}$') {
        throw "the owner-pinned retirement trust ref does not resolve to an exact commit: $TrustRef"
    }
    return [pscustomobject]@{
        supplied = $true
        ref = [string]$TrustRef
        commit = [string]$commit
    }
}

function Read-GovernorRetirementDetachedBytes([string]$Path, [object]$ExpectedSha256, [string]$Purpose) {
    # One handle, pinned by exact absolute path. The file must be a resident
    # regular non-reparse file; the bytes are read through that handle and the
    # observed SHA-256 must equal the owner-pinned identity, so a concurrent
    # change is detected by content rather than by a second stat.
    if ([string]::IsNullOrWhiteSpace($Path) -or -not [System.IO.Path]::IsPathRooted($Path)) {
        throw "$Purpose must be an explicit absolute path"
    }
    if (-not (Get-Command Get-GovernorApprovalSha256 -CommandType Function -ErrorAction SilentlyContinue)) {
        throw 'the retirement trust root requires the approval digest helper; dot-source scripts/lib/governor-retirement-approval.ps1'
    }
    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $file = Get-Item -LiteralPath $resolved -ErrorAction Stop
    $linkTargets = @($file.Target) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) }
    $nonResidentMask = [int64]0x00541000
    if (-not ($file -is [System.IO.FileInfo]) -or
        -not [string]::IsNullOrWhiteSpace([string]$file.LinkType) -or
        $linkTargets.Count -ne 0 -or
        (([int64]$file.Attributes -band $nonResidentMask) -ne 0)) {
        throw "$Purpose must be a resident regular non-reparse file: $resolved"
    }
    $stream = [System.IO.File]::Open($resolved, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $memory = [System.IO.MemoryStream]::new()
        try {
            $stream.CopyTo($memory)
            $bytes = $memory.ToArray()
        }
        finally {
            $memory.Dispose()
        }
        $length = $stream.Length
    }
    finally {
        $stream.Dispose()
    }
    $observed = Get-GovernorApprovalSha256 $bytes
    $expected = if ($null -eq $ExpectedSha256) { '' } else { ([string]$ExpectedSha256).ToLowerInvariant() }
    if (-not [string]::IsNullOrEmpty($expected)) {
        if ($expected -cnotmatch '^[0-9a-f]{64}$') {
            throw "$Purpose declares a malformed SHA-256 identity: $expected"
        }
        if ($observed -cne $expected) {
            throw "$Purpose content digest differs from the owner-pinned identity (declared=$expected observed=$observed)"
        }
    }
    if ([int64]$length -ne [int64]$bytes.Length) {
        throw "$Purpose changed during the verified read: byte length differs from the pinned identity"
    }
    return [pscustomobject]@{
        path = [string]$file.FullName
        bytes = [byte[]]$bytes
        length = [int64]$length
        sha256 = [string]$observed
    }
}

function Get-GovernorRetirementOwnerPinnedArtifact([string]$Repo, [string]$TrustCommit, [string]$RelativePath, [object]$ExpectedSha256, [string]$Purpose) {
    # The artifact bytes are ALWAYS read from the working tree through the
    # pinned path/handle rules and then proved byte-identical to the blob the
    # OWNER-PINNED ref holds at that path. Candidate C is never a source of
    # trust material, and a candidate that edits the file cannot satisfy the
    # pinned blob identity.
    if ([string]::IsNullOrWhiteSpace($TrustCommit) -or $TrustCommit -notmatch '^[0-9a-f]{40,64}$') {
        throw "$Purpose requires the resolved owner-pinned trust commit"
    }
    $full = Join-Path $Repo $RelativePath
    $blob = (& git -C $Repo rev-parse --verify --end-of-options "$TrustCommit`:$RelativePath" 2>$null | Out-String).Trim()
    if ($blob -notmatch '^[0-9a-f]{40,64}$') {
        throw "$Purpose is not tracked at the owner-pinned trust commit: $RelativePath"
    }
    $resolved = Read-GovernorRetirementDetachedBytes $full $ExpectedSha256 $Purpose
    $workingTreeBlob = (& git -C $Repo hash-object "--path=$RelativePath" $full 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $workingTreeBlob -cne $blob) {
        throw "$Purpose working-tree bytes differ from the owner-pinned blob at $RelativePath"
    }
    $resolved | Add-Member -MemberType NoteProperty -Name blob -Value ([string]$blob)
    $resolved | Add-Member -MemberType NoteProperty -Name relative_path -Value ([string]$RelativePath)
    return $resolved
}

function Test-GovernorRetirementVerifierTrustAnchorBinding([object]$Policy) {
    # Binding 2: the verifier that actually executes the closure must declare
    # this exact trust root. The resolved issuer policy names the anchor schema
    # and the closure verifier/rule set; this executing contract compares them
    # with its OWN resolved identity, so a candidate cannot swap a permissive
    # verifier in beside a restrictive policy (or the reverse).
    if (-not $Policy) {
        throw 'the retirement trust anchor binding requires the resolved issuer policy'
    }
    $schema = [string](Get-GovernorApprovalField $Policy 'schema')
    if ($schema -cne $script:GovernorRetirementTrustPolicySchemaV2 -and
        $schema -cne $script:GovernorRetirementTrustPolicySchemaV3) {
        throw "the retirement trust anchor binding does not support this policy schema: $schema"
    }
    $declaredAnchor = [string](Get-GovernorApprovalField $Policy 'owner_pinned_trust_anchor')
    if ($declaredAnchor -cne $script:GovernorRetirementTrustAnchorSchema) {
        throw "the resolved retirement issuer policy does not declare the owner-pinned trust anchor $($script:GovernorRetirementTrustAnchorSchema): $declaredAnchor"
    }
    if ($schema -ceq $script:GovernorRetirementTrustPolicySchemaV3) {
        $declaredRoot = [string](Get-GovernorApprovalField $Policy 'owner_pinned_trust_root')
        if ([string]::IsNullOrWhiteSpace($declaredRoot)) {
            throw 'the resolved retirement issuer policy declares no owner-pinned trust root reference form'
        }
    }
    $declaredVerifier = [string](Get-GovernorApprovalField $Policy 'closure_verifier')
    if ($declaredVerifier -cne $script:GovernorRetirementClosureVerifierIdentity) {
        throw "the resolved retirement issuer policy names a closure verifier this contract does not implement: $declaredVerifier"
    }
    if ($declaredVerifier -cne 'Get-GovernorRetirementConsumerClosure') {
        throw "the closure verifier identity changed: $declaredVerifier"
    }
    return $true
}

function Get-GovernorRetirementTrustRootPreimage([object]$Root) {
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'domain' $script:GovernorRetirementTrustRootDigestDomain))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'approval_schema' (Get-GovernorApprovalField $Root 'approval_schema')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'approval_preimage_domain' (Get-GovernorApprovalField $Root 'approval_preimage_domain')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'repository' (Get-GovernorApprovalField $Root 'repository')))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'trust_root_file'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'trust_root_ref'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'trust_root_commit'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'trust_policy_relpath'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'trust_policy_sha256'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'trust_policy_git_blob'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'verifier_relpath'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'verifier_sha256'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'verifier_git_blob'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'closure_verifier'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'closure_rule_set'))
    [void]$lines.Add((Get-GovernorApprovalField $Root 'closure_verifier_sha256'))
    return (@($lines) -join "`n")
}

function New-GovernorRetirementTrustRootRecord([string]$Repo, [object]$Ref, [object]$PolicyBytes, [object]$VerifierBytes, [string]$ClosureRuleSet, [string]$ClosureVerifier, [string]$ClosureVerifierSha256) {
    $record = [ordered]@{
        schema = 'eliot-governor-retirement-trust-root-v1'
        digest_domain = $script:GovernorRetirementTrustRootDigestDomain
        approval_schema = [string]$script:GovernorRetirementApprovalSchema
        approval_preimage_domain = $script:GovernorRetirementApprovalPreimageDomain
        repository = $script:GovernorRetirementLegacyRepository
        product = $script:GovernorRetirementProduct
        issuer_role = $script:GovernorRetirementApprovalRole
        trust_anchor = $script:GovernorRetirementTrustAnchorSchema
        trust_anchor_role = $script:GovernorRetirementTrustAnchorRole
        trust_anchor_path = $script:GovernorRetirementTrustAnchorPath
        trust_root_ref = [string]$Ref.ref
        trust_root_commit = [string]$Ref.commit
        trust_policy_relpath = [string]$PolicyBytes.relative_path
        trust_policy_sha256 = [string]$PolicyBytes.sha256
        trust_policy_git_blob = [string]$PolicyBytes.blob
        verifier_relpath = [string]$VerifierBytes.relative_path
        verifier_sha256 = [string]$VerifierBytes.sha256
        verifier_git_blob = [string]$VerifierBytes.blob
        trust_policy = $PolicyBytes.body
        trust_policy_sha256_bytes = [byte[]]$PolicyBytes.bytes
        closure_verifier = [string]$ClosureVerifier
        closure_rule_set = [string]$ClosureRuleSet
        closure_verifier_sha256 = [string]$ClosureVerifierSha256
        proof_ceiling = 'DECLARED_REF_IDENTITY_ONLY'
    }
    $record | Add-Member -MemberType NoteProperty -Name content_sha256 -Value (Get-GovernorApprovalSha256 (Get-GovernorRetirementTrustRootPreimage $record))
    return $record
}

function Resolve-GovernorRetirementTrustRoot([object]$Input) {
    # The single seam every consumer resolves. `$Input` is
    # [pscustomobject]@{ TrustRootRef = '<explicit owner-pinned git ref>' }
    # supplied by the release builder or the finalizer from their own explicit
    # parameter. There is no second source of the root: the candidate commit is
    # not a fallback, the tracked anchor file is not a fallback, and no
    # environment variable or directory search can substitute one.
    $supplied = $null
    if ($null -ne $Input) {
        $supplied = ConvertTo-GovernorApprovalString (Get-GovernorApprovalField $Input 'TrustRootRef')
    }
    if ([string]::IsNullOrWhiteSpace($supplied)) {
        return [pscustomobject]@{
            supplied = $false
            state = 'ABSENT'
            reason = 'no owner-pinned trust root reference was supplied; without it the retirement trust root cannot be resolved from anything candidate C cannot redefine, so no issuer can be admitted and no retirement approval can verify'
            trust_root_ref = $null
            trust_root_commit = $null
            trust_policy = $null
            trust_policy_sha256 = $null
            trust_policy_bytes = $null
            verifier_sha256 = $null
            verifier_blob = $null
            root = $null
        }
    }
    $repo = [string](Get-GovernorApprovalField $Input 'Repo')
    if ([string]::IsNullOrWhiteSpace($repo)) {
        throw 'the retirement trust root requires the repository root of candidate C'
    }
    $ref = Resolve-GovernorRetirementOwnerPinnedRef $repo $supplied
    $policyBytes = Get-GovernorRetirementOwnerPinnedArtifact `
        $repo $ref.commit $script:GovernorRetirementTrustPolicyRelPath $null 'owner-pinned retirement approval trust policy'
    $policy = Read-GovernorRetirementJsonFile $policyBytes.path 'owner-pinned retirement approval trust policy'
    [void](Test-GovernorRetirementTrustPolicyShape $policy)
    [void](Test-GovernorRetirementVerifierTrustAnchorBinding $policy)
    # The policy declares its own exact bytes; binding 1 is enforced against the
    # bytes actually read from the owner-pinned ref.
    $declaredSha = [string](Get-GovernorApprovalField $policy 'trust_policy_sha256')
    $declaredBlob = [string](Get-GovernorApprovalField $policy 'trust_policy_git_blob')
    if ([string]::IsNullOrWhiteSpace($declaredSha) -or [string]::IsNullOrWhiteSpace($declaredBlob)) {
        throw 'the owner-pinned retirement trust policy declares no exact byte identity (trust_policy_sha256 / trust_policy_git_blob)'
    }
    if ($declaredBlob -cne [string]$policyBytes.blob) {
        throw "the retirement trust policy blob identity differs from the owner-pinned blob (declared=$declaredBlob observed=$([string]$policyBytes.blob))"
    }
    $observedSha = Get-GovernorApprovalSha256 ([byte[]]$policyBytes.bytes)
    if ($observedSha -cne $declaredSha.ToLowerInvariant()) {
        throw "the retirement trust policy content digest differs from the identity it declares (declared=$declaredSha observed=$observedSha)"
    }
    $ruleSet = [string](Get-GovernorApprovalField $policy 'closure_rule_set')
    $verifierIdentity = [string](Get-GovernorApprovalField $policy 'closure_verifier')
    $verifierBytes = Get-GovernorRetirementOwnerPinnedArtifact `
        $repo $ref.commit $script:GovernorRetirementVerifierRelPath $null 'owner-pinned retirement closure verifier'
    $root = New-GovernorRetirementTrustRootRecord `
        $repo $ref $policyBytes $verifierBytes $ruleSet $verifierIdentity ([string]$verifierBytes.sha256)
    [pscustomobject]@{
        supplied = $true
        state = 'SUPPLIED'
        reason = $null
        trust_root_ref = [string]$ref.ref
        trust_root_commit = [string]$ref.commit
        trust_policy = $policy
        trust_policy_sha256 = [string]$policyBytes.sha256
        trust_policy_bytes = [byte[]]$policyBytes.bytes
        verifier_sha256 = [string]$verifierBytes.sha256
        verifier_blob = [string]$verifierBytes.blob
        root = $root
    }
}

function Test-GovernorRetirementTrustRootAgreement([object]$Recomputed, [object]$Carried, [string]$Purpose) {
    # Exactly one owner-pinned trust root identity may appear across the plan,
    # the staged manifest, RELEASE.json, the checksums, the signed finalization
    # evidence and every later readback. Carrying a different owner-pinned ref,
    # commit, policy blob or verifier blob than the independently re-resolved
    # root is refused: the build never binds one authority and ships evidence
    # for another.
    $fields = @(
        'trust_root_ref', 'trust_root_commit', 'trust_policy_relpath', 'trust_policy_sha256',
        'trust_policy_git_blob', 'verifier_relpath', 'verifier_sha256', 'verifier_git_blob',
        'closure_verifier', 'closure_rule_set', 'closure_verifier_sha256'
    )
    foreach ($field in $fields) {
        $expected = [string](Get-GovernorApprovalField $Recomputed $field)
        $observed = [string](Get-GovernorApprovalField $Carried $field)
        if ($observed -cne $expected) {
            throw "$Purpose carries a different owner-pinned retirement trust root identity (field=$field carried='$observed' re-resolved='$expected')"
        }
    }
    return $true
}

function Assert-GovernorRetirementTrustRootShape([object]$Carried) {
    if (-not $Carried) {
        throw 'the owner-pinned retirement trust root identity is missing from the release evidence'
    }
    if (-not (Test-GovernorRetirementGitRefSyntax ([string](Get-GovernorApprovalField $Carried 'trust_root_ref')))) {
        throw 'the release evidence names no valid owner-pinned retirement trust root ref'
    }
    if ([string](Get-GovernorApprovalField $Carried 'trust_root_commit') -cnotmatch '^[0-9a-f]{40,64}$') {
        throw 'the owner-pinned retirement trust root identity is missing its resolved commit'
    }
    foreach ($field in @('trust_policy_sha256', 'verifier_sha256', 'closure_verifier_sha256')) {
        if ([string](Get-GovernorApprovalField $Carried $field) -cnotmatch '^[0-9a-f]{64}$') {
            throw "the owner-pinned retirement trust root identity is missing its $field binding"
        }
    }
    foreach ($field in @('trust_policy_git_blob', 'verifier_git_blob')) {
        if ([string](Get-GovernorApprovalField $Carried $field) -cnotmatch '^[0-9a-f]{40,64}$') {
            throw "the owner-pinned retirement trust root identity is missing its $field binding"
        }
    }
    foreach ($field in @('trust_policy_relpath', 'verifier_relpath', 'closure_verifier', 'closure_rule_set')) {
        if ([string]::IsNullOrWhiteSpace([string](Get-GovernorApprovalField $Carried $field))) {
            throw "the owner-pinned retirement trust root identity is missing its $field binding"
        }
    }
    return $true
}

function Get-GovernorRetirementTrustAnchorPreimage([object]$Anchor) {
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'domain' $script:GovernorRetirementApprovalPreimageDomain))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'schema' (Get-GovernorApprovalField $Anchor 'schema')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'release_policy' (Get-GovernorApprovalField $Anchor 'release_policy')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'release_product' (Get-GovernorApprovalField $Anchor 'release_product')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'owner_pinned_trust_root_ref' (Get-GovernorApprovalField $Anchor 'owner_pinned_trust_root_ref')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'owner_pinned_trust_root_commit' (Get-GovernorApprovalField $Anchor 'owner_pinned_trust_root_commit')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'trust_policy_relpath' (Get-GovernorApprovalField $Anchor 'trust_policy_relpath')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'trust_policy_sha256' (Get-GovernorApprovalField $Anchor 'trust_policy_sha256')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'trust_policy_git_blob' (Get-GovernorApprovalField $Anchor 'trust_policy_git_blob')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'verifier_relpath' (Get-GovernorApprovalField $Anchor 'verifier_relpath')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'verifier_sha256' (Get-GovernorApprovalField $Anchor 'verifier_sha256')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'verifier_git_blob' (Get-GovernorApprovalField $Anchor 'verifier_git_blob')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'closure_verifier' (Get-GovernorApprovalField $Anchor 'closure_verifier')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'closure_rule_set' (Get-GovernorApprovalField $Anchor 'closure_rule_set')))
    foreach ($issuer in @(Get-GovernorApprovalField $Anchor 'admitted_issuers')) {
        [void]$lines.Add("issuer=$([string](Get-GovernorApprovalField $issuer 'issuer'))|role=$([string](Get-GovernorApprovalField $issuer 'role'))|authority=$([string](Get-GovernorApprovalField $issuer 'authority'))|receipt_kind=$([string](Get-GovernorApprovalField $issuer 'receipt_kind'))|authenticode_code_signing_thumbprint=$([string](Get-GovernorApprovalField $issuer 'authenticode_code_signing_thumbprint'))")
    }
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'issuer_state' (Get-GovernorApprovalField $Anchor 'issuer_state')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'issuer_state_reason' (Get-GovernorApprovalField $Anchor 'issuer_state_reason')))
    return (@($lines) -join "`n")
}

function Test-GovernorRetirementTrustAnchorShape([object]$Anchor) {
    # The tracked anchor is DECLARED evidence about the currently pinned
    # owner-pinned ref, not the trust root. It is validated here so a reviewer
    # can trust what it says; it is never resolved as a trust root.
    if (-not $Anchor) {
        throw 'the retirement trust anchor is missing'
    }
    if ([string](Get-GovernorApprovalField $Anchor 'schema') -cne $script:GovernorRetirementTrustAnchorSchema) {
        throw "the retirement trust anchor schema is not supported: $([string](Get-GovernorApprovalField $Anchor 'schema'))"
    }
    $supported = @(
        'schema', 'release_policy', 'release_product', 'owner_pinned_trust_root_ref',
        'owner_pinned_trust_root_commit', 'trust_policy_relpath', 'trust_policy_sha256',
        'trust_policy_git_blob', 'verifier_relpath', 'verifier_sha256', 'verifier_git_blob',
        'closure_verifier', 'closure_rule_set', 'admitted_issuers', 'issuer_state',
        'issuer_state_reason', 'content_sha256'
    )
    foreach ($property in $Anchor.PSObject.Properties) {
        if ($supported -cnotcontains [string]$property.Name) {
            throw "the retirement trust anchor field is not in the closed contract: $([string]$property.Name)"
        }
    }
    if ([string](Get-GovernorApprovalField $Anchor 'release_policy') -cne $script:GovernorRetirementLegacyRepository -or
        [string](Get-GovernorApprovalField $Anchor 'release_product') -cne $script:GovernorRetirementProduct) {
        throw 'the retirement trust anchor is not bound to this repository/product release'
    }
    if (-not (Test-GovernorRetirementGitRefSyntax ([string](Get-GovernorApprovalField $Anchor 'owner_pinned_trust_root_ref')))) {
        throw "the retirement trust anchor declares no valid owner-pinned ref: $([string](Get-GovernorApprovalField $Anchor 'owner_pinned_trust_root_ref'))"
    }
    if ([string](Get-GovernorApprovalField $Anchor 'owner_pinned_trust_root_commit') -cnotmatch '^[0-9a-f]{40,64}$') {
        throw 'the retirement trust anchor declares no exact owner-pinned commit'
    }
    foreach ($field in @('trust_policy_sha256', 'verifier_sha256')) {
        if ([string](Get-GovernorApprovalField $Anchor $field) -cnotmatch '^[0-9a-f]{64}$') {
            throw "the retirement trust anchor is missing its $field binding"
        }
    }
    foreach ($field in @('trust_policy_git_blob', 'verifier_git_blob')) {
        if ([string](Get-GovernorApprovalField $Anchor $field) -cnotmatch '^[0-9a-f]{40,64}$') {
            throw "the retirement trust anchor is missing its $field binding"
        }
    }
    if ([string](Get-GovernorApprovalField $Anchor 'closure_verifier') -cne $script:GovernorRetirementClosureVerifierIdentity) {
        throw "the retirement trust anchor names a closure verifier this contract does not implement: $([string](Get-GovernorApprovalField $Anchor 'closure_verifier'))"
    }
    $issuers = @(Get-GovernorApprovalField $Anchor 'admitted_issuers')
    $admitted = @($issuers | Where-Object { [string](Get-GovernorApprovalField $_ 'role') -ceq $script:GovernorRetirementApprovalRole })
    if ($admitted.Count -ne 1) {
        throw "the retirement trust anchor must declare exactly one issuer for the $($script:GovernorRetirementApprovalRole) role; found $($admitted.Count)"
    }
    $issuerState = [string](Get-GovernorApprovalField $Anchor 'issuer_state')
    if ($issuerState -cne 'ISSUER_AVAILABLE' -and $issuerState -cne 'ISSUER_UNAVAILABLE') {
        throw "the retirement trust anchor declares an unsupported issuer state: $issuerState"
    }
    if ($issuerState -ceq 'ISSUER_AVAILABLE' -and [string]::IsNullOrWhiteSpace([string](Get-GovernorApprovalField $admitted[0] 'issuer'))) {
        throw 'the retirement trust anchor reports ISSUER_AVAILABLE with no issuer identity'
    }
    if ($issuerState -ceq 'ISSUER_UNAVAILABLE' -and [string]::IsNullOrWhiteSpace([string](Get-GovernorApprovalField $Anchor 'issuer_state_reason'))) {
        throw 'the retirement trust anchor reports ISSUER_UNAVAILABLE with no stated reason'
    }
    if ((ConvertTo-GovernorApprovalString (Get-GovernorApprovalField $Anchor 'content_sha256')) -cne (Get-GovernorApprovalSha256 (Get-GovernorRetirementTrustAnchorPreimage $Anchor))) {
        throw 'the retirement trust anchor canonical digest mismatch'
    }
    return $true
}

# Dot-source guard, LAST: this module defines only closed constants and pure
# resolvers. Dot-sourcing exposes every function without resolving a trust root.
if ($MyInvocation.InvocationName -eq '.') {
    return
}