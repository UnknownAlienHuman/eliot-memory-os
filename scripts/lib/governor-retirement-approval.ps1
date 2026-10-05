<#
.SYNOPSIS
    Detached Governor retirement approval contract, independent consumer-closure
    verifier, issuer seam, and offline trust admission for issue #2968.

.DESCRIPTION
    This module is the neutral owner-side of the two-time release transition:

        freeze candidate C
        -> run the independent consumer/replacement closure over C
        -> the owner reviews and adopts that exact result
        -> the owner issues the detached approval R(C) OUTSIDE C
        -> the release builder verifies R(C) before omitting any artifact
        -> the staged bundle carries the approval reference and digest
        -> the finalizer independently re-verifies R(C)
        -> install/readback verifies the original source approval and separately bound release candidate

    Four defects are corrected here.

    1. No tracked file is ever the approval instance. The pre-image digest of
       `GovernorRetirementApprovalV1` covers historical source C and its tree; the later release candidate D is
       separately bound in release evidence. The detached approval is outside
       C, so no commit-fixed-point search is required. A tracked source
       file may describe the expected contract, but a tracked approval whose
       digest cannot match the tree it lives in is a shape error.

    2. Shape is not authority. `Test-GovernorRetirementApprovalShape` establishes
       SHAPE ONLY. Actionability additionally requires (a) an issuer admitted by
       the OWNER-PINNED trust policy and an executed issuer readback that
       authenticates the detached owner receipt, and (b) an independently
       recomputed consumer closure produced by the owner-pinned verifier that
       matches the owner-adopted closure declaration. No parameter, environment
       variable, or repository path can widen the trust policy: it is resolved
       from an explicitly supplied owner-pinned git ref that candidate C neither
       contains nor defines (see scripts/lib/governor-retirement-trust-root.ps1,
       external audit 5918050095 defect 1), and the approval body and the signed
       owner receipt always come from outside the candidate tree.

    3. The candidate inventory cannot certify its own completeness. The closure
       verifier is implemented HERE (outside the candidate source) and scans the
       tracked tree of C with a fixed rule set. The owner pins the verifier
       identity and the closure rule-set version, and any unclassified tracked
       reference to the retiring surface blocks approval.
    #
    #    4. Exact replay/conflict semantics (I5.27) are enforced, not merely
    #    named. The replay record carries the canonical request digest (owner
    #    evidence excluded), identical to the approval's admitted hash, so an
    #    exact replay returns the same receipt; reusing one
    #    (idempotency_namespace, operation_id) key with a different request
    #    hash is APPROVAL_IDENTITY_CONFLICT and performs no transition.

The issuer. Current `main` has no production release-retirement approval
    issuer, and the release retirement role is a semantic owner decision that
    this issue is not authorized to invent. The seam below therefore exposes
    exactly three issuer states and only one of them is actionable:
    `ISSUER_AVAILABLE` (an owner-pinned trust policy admits exactly one issuer
    identity for the `retirement-approval` role AND an executed issuer readback
    authenticates the detached owner receipt), `ISSUER_UNAVAILABLE` (no issuer is
    admitted by the owner-pinned root - the documented fail-closed state), and a
    rejected approval. Neither the Authenticode Code Signing EKU nor any
    binary-signing signer is admitted for the semantic `retirement-approval`
    role by this module.

    The owner/authority PATH is implemented, not stubbed, and it has three real
    parts:

      * `Resolve-GovernorRetirementTrustRoot` (scripts/lib/
        governor-retirement-trust-root.ps1) resolves the issuer policy and the
        closure-verifier identity from an explicitly supplied OWNER-PINNED GIT
        REF that candidate C cannot define. Candidate C is never a source of
        trust material.
      * `Resolve-GovernorRetirementIssuerReadback` is the EXECUTED verification
        path for `issuer_readback_ref`: it pins, reads back and executes the
        pinned owner-decision record over the exact operation, candidate and
        policy, and proves the detached owner receipt's detached CMS signature
        against the admitted issuer certificate (issuer identity, role,
        operation, candidate, window, revocation and exact content).
      * `Resolve-GovernorRetirementIssuanceInputs` / `New-GovernorRetirementApproval`
        freeze candidate C, read the owner readback first, then issue the
        detached approval R(C) outside C. `Resolve-GovernorRetirementIssuanceInputs`
        is the real issuer entry point: given the owner-pinned ref, the signed
        owner decision and the detached owner receipt it produces the exact
        inputs issuance consumes, or it refuses.

    Because no production issuer identity is admitted by an owner-pinned
    release-policy ref today, issuance still fails closed. That is an external
    organizational decision (which principal owns semantic retirement authority),
    not missing code: absent stays absent, and no issuer, certificate, signature
    or receipt is invented here.

    Control-flow contract for callers: this file defines only closed constants
    and pure functions, and its dot-source guard sits at the BOTTOM, exactly
    like the release builder's. An early return would abort the script before a
    single function was defined, so the builder and finalizer would see none of
    this contract. Dot-sourcing this file therefore exposes every function here
    without running a build.
#>

$ErrorActionPreference = 'Stop'

# Neutral closed constants. The approval contract is deliberately defined
# outside crates/eliot-app so retiring the facade package cannot remove or edit
# the contract that governs its retirement.
$script:GovernorRetirementApprovalSchema = 'eliot-governor-retirement-approval-v1'
$script:GovernorRetirementApprovalDomain = 'eliot-governor-retirement-approval-preimage-v1'
# Retained-slice evidence keeps the exact pre-#2968 digest domain: a retained
# bundle stages byte-identically, so its evidence digest must too.
$script:GovernorRetirementRetainedEvidenceDomain = 'eliot-governor-disposition-v1'
$script:GovernorRetirementClosureDomain = 'eliot-governor-retirement-closure-v1'
$script:GovernorRetirementClosureSchema = 'eliot-governor-retirement-closure-v1'
$script:GovernorRetirementTrustSchema = 'eliot-governor-retirement-approval-trust-v2'
$script:GovernorRetirementFreezeSchema = 'eliot-governor-retirement-receipt-v1'
$script:GovernorRetirementFreezeKind = 'detached-approval-pointer'
# AUD-5847600066-1: the certified candidate C must never track its own receipt.
# The freeze record above is valid only as a detached artifact outside C; the
# legacy in-tree path below is refused by the shape gate whenever it is still
# tracked at the certified commit, so no commit/amend workflow can produce an
# exact accepted receipt inside the tree it certifies.
$script:GovernorRetirementForbiddenSelfReceiptPath = 'crates/eliot-app/retirement-receipt.json'
$script:GovernorRetirementBundleTrustFile = 'GOVERNOR_RETIREMENT_APPROVAL_TRUST.json'
$script:GovernorRetirementBundleApprovalFile = 'GOVERNOR_RETIREMENT_APPROVAL.json'
$script:GovernorRetirementBundleReceiptFile = 'GOVERNOR_RETIREMENT_OWNER_RECEIPT.p7s'
$script:GovernorRetirementTrustPolicyPath = 'scripts/lib/governor-retirement-approval-trust.json'
$script:GovernorRetirementTrustSchemaV3 = 'eliot-governor-retirement-approval-trust-v3'
$script:GovernorRetirementApprovalRole = 'retirement-approval'
$script:GovernorRetirementOwnerDecisionSchema = 'eliot-governor-retirement-owner-decision-v1'
$script:GovernorRetirementOwnerDecisionFile = 'GOVERNOR_RETIREMENT_OWNER_DECISION.json'
$script:GovernorRetirementOwnerDecisionDigestDomain = 'eliot-governor-retirement-owner-decision-preimage-v1'
$script:GovernorRetirementOwnerReceiptKind = 'detached-cms-sha256'
$script:GovernorRetirementReceiptContentOid = '1.3.6.1.4.1.57264.296.1.9'
# Issue #2968 (external audit 5918050095 defect 1). This file no longer
# asserts by prose that it is the trust root. It DECLARES which owner-pinned
# trust anchor it binds to, and `Resolve-GovernorRetirementTrustRoot` executes
# the closure through this contract and refuses any issuer policy that names a
# different anchor, closure verifier or rule set. That makes this contract the
# owner-pinned closure-verifier identity: a candidate cannot supply a permissive
# verifier beside a restrictive policy, and `Resolve-GovernorRetirementTrustRoot`
# independently compares its own resolved SHA-256 and git blob id against the
# values the owner-pinned issuer policy declares for it.
$script:GovernorRetirementOwnerPinnedTrustAnchor = 'eliot-governor-retirement-approval-anchor-v1'
$script:GovernorRetirementVerifierRelPath = 'scripts/lib/governor-retirement-approval.ps1'
$script:GovernorRetirementClosureVerifier = 'Get-GovernorRetirementConsumerClosure'
$script:GovernorRetirementClosureRuleSetV1 = 'tracked-legacy-reference-closure-v1'
$script:GovernorRetirementClosureRuleSetV2 = 'tracked-legacy-reference-closure-v2'
$script:GovernorRetirementClosureRuleSet = $script:GovernorRetirementClosureRuleSetV2
$script:GovernorRetirementClosureRuleSets = @(
    $script:GovernorRetirementClosureRuleSetV1
    $script:GovernorRetirementClosureRuleSetV2
)
$script:GovernorRetirementLegacyRepository = 'UnknownAlienHuman/eliot-memory-os'
$script:GovernorRetirementProduct = 'eliot'
$script:GovernorRetirementProductContract = 'eliot-wicket'
$script:GovernorRetirementPackage = 'eliot-app'
$script:GovernorRetirementBinary = 'eliot-governor'
$script:GovernorRetirementReleaseRole = 'codex-eliot-governor-plugin-legacy-entrypoint'
$script:GovernorRetirementPlugin = 'plugin/eliot-governor'
$script:GovernorRetirementWorkspaceManifestPath = 'Cargo.toml'
$script:GovernorRetirementFacadeManifestPath = 'crates/eliot-app/Cargo.toml'
$script:GovernorRetirementDispositionInventoryPath = 'crates/eliot-app/src/disposition.rs'
$script:GovernorRetirementProofCeiling = 'DETACHED_RELEASE_CANDIDATE_OMISSION_ONLY (no installed migration, no live Product behavior, no safe data deletion evidence)'
$script:GovernorRetirementDispositionAdmitted = @('migrated', 'fixture-removed', 'removed')
$script:GovernorRetirementNonAdmissionReasons = @(
    'APPROVAL_INPUT_ABSENT'
    'APPROVAL_SHAPE_REJECTED'
    'APPROVAL_IDENTITY_CONFLICT'
    'APPROVAL_CANDIDATE_MISMATCH'
    'APPROVAL_TRUST_UNAVAILABLE'
    'APPROVAL_ISSUER_UNAVAILABLE'
    'APPROVAL_CLOSURE_MISMATCH'
    'APPROVAL_CLOSURE_INCOMPLETE'
    'APPROVAL_EXPIRED_OR_FUTURE'
    'APPROVAL_REVOKED'
    'APPROVAL_SIMULATED_NOT_ADMITTED'
)
# The exact tracked reference tokens the independent closure scanner must
# classify for the retiring surface. This list is the verifier: it lives outside
# the candidate source, so a candidate cannot shrink the detector and the table
# at the same time.
# The bare binary name also catches command lines, documentation prose and
# plugin-relative paths (for example 'plugin/eliot-governor/' and
# 'eliot-governor --config') that name the retiring surface without one of the
# qualified spellings, and the environment-variable spelling catches launch
# references such as '{env:ELIOT_GOVERNOR_EXE}'. The bare facade package name
# catches references through the package ('cargo run -p eliot-app',
# 'crates/eliot-app/...') without a governor spelling. The uninstall flag
# spelling catches references to the retiring 'host uninstall' CLI through a
# launcher variable such as '$governor' without any governor spelling. Detection
# stays purely
# content-based, so candidate shrinkage of CONSUMER_SURFACES can never remove
# a reference from the denominator.
$script:GovernorRetirementClosureTokens = @(
    'eliot-governor.exe'
    'bin/eliot-governor'
    'plugins/eliot-governor'
    'codex_controller'
    'eliot-governor'
    'ELIOT_GOVERNOR'
    'eliot-app'
    'uninstall --host'
)


$script:GovernorRetirementClosurePathFamilies = @(
    'source_and_automation'
    'retiring_plugin_tree'
    'host_integration_manifest'
    'desktop_surface'
    'documentation_and_workstream'
)
$script:GovernorRetirementApprovalContract = [ordered]@{
    schema = $script:GovernorRetirementApprovalSchema
    digest_domain = $script:GovernorRetirementApprovalDomain
    closure_schema = $script:GovernorRetirementClosureSchema
    closure_digest_domain = $script:GovernorRetirementClosureDomain
    trust_schema = $script:GovernorRetirementTrustSchema
    bundle_approval_file = $script:GovernorRetirementBundleApprovalFile
    bundle_trust_file = $script:GovernorRetirementBundleTrustFile
    issuer_role = $script:GovernorRetirementApprovalRole
    closure_rule_set = $script:GovernorRetirementClosureRuleSet
    repository = $script:GovernorRetirementLegacyRepository
    product = $script:GovernorRetirementProduct
    product_contract = $script:GovernorRetirementProductContract
    legacy_package = $script:GovernorRetirementPackage
    legacy_binary = $script:GovernorRetirementBinary
    legacy_release_role = $script:GovernorRetirementReleaseRole
    legacy_plugin_path = $script:GovernorRetirementPlugin
    proof_ceiling = $script:GovernorRetirementProofCeiling
}

function ConvertTo-GovernorApprovalString([object]$Value) {
    if ($null -eq $Value) { return '' }
    return [string]$Value
}

function Get-GovernorApprovalDomainSeparatedLine([string]$Key, [object]$Value) {
    # Canonical one-line encoding. Null and the empty string collapse to the
    # empty scalar so a missing binding is a shape error rather than a
    # silently different canonical preimage.
    $text = ConvertTo-GovernorApprovalString $Value
    if ([string]::IsNullOrEmpty($text)) {
        return "$Key="
    }
    return "$Key=$text"
}

function Get-GovernorApprovalCanonicalPreimage([object]$Approval) {
    # Canonical digest domain separation (I5.27): a deterministic, versioned,
    # ordered preimage over every field that affects authority, scope, ordering,
    # privacy or effect. No field may be omitted or defaulted silently, and the
    # consumer disposition set is sorted by canonical operation identity so a
    # reordering is not a new content identity while an added/removed/changed
    # consumer is.
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'domain' $script:GovernorRetirementApprovalDomain))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'schema' (Read-GovernorApprovalField $Approval 'schema')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'repository' (Read-GovernorApprovalField $Approval 'repository')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'product' (Read-GovernorApprovalField $Approval 'product')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'product_contract' (Read-GovernorApprovalField $Approval 'product_contract')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'normative_pair_revision' (Read-GovernorApprovalField $Approval 'normative_pair_revision')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'normative_pair_sha256' (Read-GovernorApprovalField $Approval 'normative_pair_sha256')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'config_policy_revision' (Read-GovernorApprovalField $Approval 'config_policy_revision')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'release_policy_revision' (Read-GovernorApprovalField $Approval 'release_policy_revision')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'candidate_commit' (Read-GovernorApprovalField $Approval 'candidate_commit')))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'candidate_tree' (Read-GovernorApprovalField $Approval 'candidate_tree')))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'legacy_package'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'legacy_binary'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'legacy_release_role'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'legacy_plugin_path'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'closure_rule_set'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'closure_verifier'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'closure_digest'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'closure_count'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'closure_declaration_path'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'closure_declaration_sha256'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'replacement_owner'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'replacement_product_contract'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'product_removal_decision'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issue_refs'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'work_refs'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'review_refs'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'operation_id'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'idempotency_namespace'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'canonical_request_hash'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'idempotency_retention_hours'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'approver_principal'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'approver_role'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issuer'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issuer_receipt_kind'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issuer_evidence_sha256'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issuer_readback_ref'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issuer_readback_sha256'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issuer_readback_blob'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issuer_certificate_thumbprint'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issuer_signing_time_utc'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'issued_at_utc'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'expires_at_utc'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'revocation_state'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'reopen_condition'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'rollback_condition'))
    [void]$lines.Add((Get-GovernorApprovalFieldEx $Approval 'proof_ceiling'))
    foreach ($consumer in @(Sort-GovernorApprovalConsumers (Read-GovernorApprovalField $Approval 'consumers'))) {
        [void]$lines.Add("consumer=$([string]$consumer.consumer)|proof=$([string]$consumer.proof_path)|reference=$([string]$consumer.live_reference)|disposition=$([string]$consumer.disposition)|replacement_owner=$([string]$consumer.replacement_owner)|product_contract=$([string]$consumer.product_contract)|removal_decision=$([string]$consumer.removal_decision)|expiry=$([string]$consumer.expiry)")
    }
    return (@($lines) -join "`n")
}

function Read-GovernorApprovalField([object]$Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $null }
    return $property.Value
}

function Get-GovernorApprovalFieldEx([object]$Object, [string]$Name) {
    return Get-GovernorApprovalDomainSeparatedLine $Name (Read-GovernorApprovalField $Object $Name)
}

function Sort-GovernorApprovalConsumers([object]$Consumers) {
    $sorted = @($Consumers) | Sort-Object -Property `
    @{ Expression = { ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'consumer') } }, `
    @{ Expression = { ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'proof_path') } }, `
    @{ Expression = { ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'live_reference') } }
    return @($sorted)
}

function Get-GovernorApprovalSha256([string]$Canonical) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Canonical)) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}

function Get-GovernorApprovalContentDigest([object]$Approval) {
    return Get-GovernorApprovalSha256 (Get-GovernorApprovalCanonicalPreimage $Approval)
}

function New-GovernorApprovalRequestDigestInput([object]$Approval) {
    # The canonical request hash deliberately excludes the owner evidence: it
    # identifies the requested ACTION, so a re-issued owner receipt over the
    # identical action keeps one idempotency identity, while any change of
    # candidate, denominator or dispositions conflicts under the same operation.
    $shadow = [ordered]@{}
    foreach ($property in $Approval.PSObject.Properties) { $shadow[$property.Name] = $property.Value }
    # The hash itself is excluded together with the owner evidence: a digest
    # that covered its own value would demand a cryptographic fixed-point
    # search from every issuer (the exact failure mode issue #2968 removes)
    # instead of one deterministic pass. Changed action/content under one
    # operation still conflicts, because every action field stays covered.
    foreach ($name in @('issuer', 'issuer_receipt_kind', 'issuer_evidence_sha256', 'issuer_readback_ref',
            'issuer_readback_sha256', 'issuer_readback_blob', 'issuer_certificate_thumbprint',
            'issuer_signing_time_utc', 'issued_at_utc', 'approver_principal', 'content_sha256',
            'canonical_request_hash')) {
        $shadow[$name] = $null
    }
    return [pscustomobject]$shadow
}

function Get-GovernorApprovalRequestDigest([object]$Approval) {
    return Get-GovernorApprovalContentDigest (New-GovernorApprovalRequestDigestInput $Approval)
}

function Test-GovernorApprovalUtcInstant([object]$Value, [string]$Field, [string]$Purpose) {
    $text = ConvertTo-GovernorApprovalString $Value
    if ($text -cnotmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$') {
        throw "$Purpose $Field must be an exact UTC instant of the form yyyy-MM-ddTHH:mm:ssZ: $text"
    }
    $parsed = [DateTimeOffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal
    if (-not [DateTimeOffset]::TryParseExact($text, "yyyy-MM-dd'T'HH:mm:ss'Z'", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        throw "$Purpose $Field is not a resolvable UTC instant: $text"
    }
    return $parsed
}

function Test-GovernorApprovalSha256Field([object]$Value, [string]$Field, [string]$Purpose) {
    $text = (ConvertTo-GovernorApprovalString $Value).ToLowerInvariant()
    if ($text -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Purpose $Field must be a lowercase 64-hex SHA-256: $text"
    }
    return $text
}

function Test-GovernorApprovalGitObjectId([object]$Value, [string]$Field, [string]$Purpose) {
    $text = (ConvertTo-GovernorApprovalString $Value).ToLowerInvariant()
    if ($text -cnotmatch '^[0-9a-f]{40}$' -and $text -cnotmatch '^[0-9a-f]{64}$') {
        throw "$Purpose $Field must be an exact lowercase Git object id: $text"
    }
    return $text
}

function Get-GovernorRetirementCandidateTree([string]$Repo, [string]$SourceCommit) {
    $tree = (& git -C $Repo rev-parse "$SourceCommit^{tree}" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $tree -notmatch '^[0-9a-f]{40}$') {
        throw "failed to resolve the candidate tree object for $SourceCommit"
    }
    return $tree
}

function Get-GovernorRetirementNormativePairRevision([string]$Repo, [string]$SourceCommit) {
    $relativePath = 'docs/normative-pair.toml'
    $blob = Get-GovernorRetirementTrackedPathDigest $Repo $SourceCommit $relativePath
    if (-not $blob) {
        throw "tracked normative pair receipt is missing at $SourceCommit`: $relativePath"
    }
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'git'
    $psi.Arguments = "-C `"$Repo`" cat-file blob $blob"
    $psi.RedirectStandardOutput = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    $memory = [System.IO.MemoryStream]::new()
    try {
        $process.StandardOutput.BaseStream.CopyTo($memory)
        $process.WaitForExit()
        if ($process.ExitCode -ne 0) {
            throw "failed to read the pinned normative pair blob $blob at $SourceCommit"
        }
        $bytes = $memory.ToArray()
    }
    finally {
        $process.StandardOutput.Close()
        $memory.Dispose()
        $process.Dispose()
    }
    try {
        $text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes).TrimStart([char]0xFEFF)
    }
    catch {
        throw "pinned normative pair receipt at $SourceCommit is not valid UTF-8: $([string]$_.Exception.Message)"
    }
    $revision = $null
    $pairKey = $null
    foreach ($line in ($text -split "`r?`n")) {
        if ($line -match '^architecture_revision\s*=\s*"([^"]+)"') { $revision = $Matches[1] }
        if ($line -match '^pair_key\s*=\s*"sha256:([0-9a-f]{64})"') { $pairKey = $Matches[1] }
    }
    if ([string]::IsNullOrWhiteSpace($revision) -or [string]::IsNullOrWhiteSpace($pairKey)) {
        throw 'tracked normative pair receipt is missing its architecture revision or pair key'
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $digest = (($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
    [pscustomobject]@{ revision = [string]$revision; pair_key = [string]$pairKey; sha256 = [string]$digest }
}

function Get-GovernorRetirementTrackedPathDigest([string]$Repo, [string]$SourceCommit, [string]$RelativePath) {
    $blob = (& git -C $Repo rev-parse "$SourceCommit`:$RelativePath" 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $blob -notmatch '^[0-9a-f]{40,64}$') {
        return $null
    }
    return [string]$blob
}

function Get-GovernorRetirementTrackedBlobMap([string]$Repo, [string]$SourceCommit, [string[]]$RelativePaths) {
    # One `git ls-tree` call for the whole denominator instead of one
    # subprocess per tracked file. The repository is large (thousands of
    # tracked paths), and spawning a process per path made the independent
    # closure scan unusably slow. This returns exactly the same
    # path -> blob-id map, read from the pinned commit's tree, with no
    # working-tree access.
    $map = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
    if (@($RelativePaths).Count -eq 0) {
        return $map
    }
    $rows = @(& git -C $Repo ls-tree -r $SourceCommit 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "failed to enumerate the tracked tree at $SourceCommit"
    }
    $wanted = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($relative in @($RelativePaths)) { [void]$wanted.Add(([string]$relative).Replace('\', '/')) }
    foreach ($row in $rows) {
        # "<mode> SP <type> <oid>\t<path>"
        $tab = ([string]$row).IndexOf("`t")
        if ($tab -lt 0) { continue }
        $meta = ([string]$row).Substring(0, $tab)
        $path = ([string]$row).Substring($tab + 1)
        if (-not $wanted.Contains($path)) { continue }
        $fields = @($meta -split ' ')
        if ($fields.Count -lt 3 -or $fields[1] -cne 'blob') { continue }
        $map[$path] = [string]$fields[2]
    }
    $missingPaths = @($wanted | Where-Object { -not $map.ContainsKey([string]$_) })
    if ($missingPaths.Count -gt 0) {
        throw "tracked retirement input is missing or is not a blob in the pinned tree: $([string]::Join(',', $missingPaths))"
    }
    return $map
}

function Get-GovernorRetirementTrackedBlobsText([string]$Repo, [string]$SourceCommit, [string[]]$RelativePaths) {
    # One `git cat-file --batch` process for the whole denominator. Every
    # requested path's object id and content are read from the pinned commit's
    # objects; nothing is read from the working tree. The wire format is
    # "<oid> <type> <size>\n<content>\n" per object, so content is taken by
    # exact byte length rather than by line scanning.
    $blobs = Get-GovernorRetirementTrackedBlobMap $Repo $SourceCommit $RelativePaths
    $result = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    if ($blobs.Count -eq 0) {
        return $result
    }
    $requestedOids = @($blobs.Values | Sort-Object -Unique)
    $input = (($requestedOids -join "`n") + "`n")
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = 'git'
    $psi.Arguments = "-C `"$Repo`" cat-file --batch"
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $process = [System.Diagnostics.Process]::Start($psi)
    try {
        # Feed requests asynchronously while draining stdout. cat-file emits
        # one potentially large object per request; writing the entire batch
        # first can deadlock when stdout fills before stdin has been consumed.
        $writer = $process.StandardInput.WriteAsync($input)
        $standardOutput = $process.StandardOutput.BaseStream
        $byOid = [System.Collections.Generic.Dictionary[string, System.Collections.Generic.List[string]]]::new([System.StringComparer]::Ordinal)
        foreach ($pair in $blobs.GetEnumerator()) {
            $oid = [string]$pair.Value
            if (-not $byOid.ContainsKey($oid)) {
                $byOid[$oid] = [System.Collections.Generic.List[string]]::new()
            }
            [void]$byOid[$oid].Add([string]$pair.Key)
        }
        $buffer = [byte[]]::new(65536)
        $pending = [System.Collections.Generic.List[byte]]::new()
        $header = [System.Text.StringBuilder]::new()
        $stage = 'header'
        $currentOid = $null
        $remaining = 0
        $responses = 0
        $readFailures = [System.Collections.Generic.List[string]]::new()
        $seenOids = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $inputClosed = $false
        while ($true) {
            $readTask = $standardOutput.ReadAsync($buffer, 0, $buffer.Length)
            $null = [System.Threading.Tasks.Task]::WhenAny($writer, $readTask).GetAwaiter().GetResult()
            if ($writer.IsCompleted -and -not $inputClosed) {
                [void]$writer.GetAwaiter().GetResult()
                $process.StandardInput.Close()
                $inputClosed = $true
            }
            $read = $readTask.GetAwaiter().GetResult()
            if ($read -le 0) { break }
            $offset = 0
            while ($offset -lt $read) {
                if ($stage -eq 'header') {
                    while ($offset -lt $read) {
                        $byte = $buffer[$offset]
                        $offset++
                        if ($byte -eq 0x0A) {
                            $line = $header.ToString()
                            [void]$header.Clear()
                            $fields = @($line -split ' ')
                            if ($fields.Count -eq 2 -and $fields[1] -ceq 'missing') {
                                $responses++
                                [void]$readFailures.Add("tracked object is missing: $([string]$fields[0])")
                                $stage = 'header'
                            }
                            elseif ($fields.Count -ge 3 -and $fields[2] -match '^\d+$') {
                                $currentOid = [string]$fields[0]
                                $remaining = [int64]$fields[2]
                                $responses++
                                if ($fields[1] -cne 'blob') {
                                    [void]$readFailures.Add("tracked object is not a blob: $currentOid ($([string]$fields[1]))")
                                    $stage = if ($remaining -eq 0) { 'trailing' } else { 'skipcontent' }
                                }
                                elseif (-not $byOid.ContainsKey($currentOid)) {
                                    [void]$readFailures.Add("cat-file returned an unrequested object: $currentOid")
                                    $stage = if ($remaining -eq 0) { 'trailing' } else { 'skipcontent' }
                                }
                                elseif (-not $seenOids.Add($currentOid)) {
                                    [void]$readFailures.Add("cat-file returned a duplicate object: $currentOid")
                                    $stage = if ($remaining -eq 0) { 'trailing' } else { 'skipcontent' }
                                }
                                else {
                                    $pending.Clear()
                                    $stage = if ($remaining -eq 0) { 'content' } else { 'content' }
                                }
                            }
                            else {
                                $responses++
                                [void]$readFailures.Add("cat-file returned a malformed response header: $line")
                                $stage = 'skipheader'
                            }
                            break
                        }
                        [void]$header.Append([char]$byte)
                    }
                }
                elseif ($stage -eq 'content') {
                    $take = [int][Math]::Min($remaining, [int64]($read - $offset))
                    for ($i = 0; $i -lt $take; $i++) { $pending.Add($buffer[$offset + $i]) }
                    $offset += $take
                    $remaining -= $take
                    if ($remaining -eq 0) {
                        $bytes = $pending.ToArray()
                        if ($byOid.ContainsKey($currentOid)) {
                            foreach ($path in $byOid[$currentOid]) {
                                $result[[string]$path] = [pscustomobject]@{
                                    blob = [string]$currentOid
                                    text = [System.Text.Encoding]::UTF8.GetString($bytes)
                                }
                            }
                        }
                        $pending.Clear()
                        $currentOid = $null
                        $stage = 'trailing'
                    }
                }
                elseif ($stage -eq 'skipcontent') {
                    $take = [int][Math]::Min($remaining, [int64]($read - $offset))
                    $offset += $take
                    $remaining -= $take
                    if ($remaining -eq 0) { $stage = 'trailing' }
                }
                elseif ($stage -eq 'trailing') {
                    # exactly one LF after the object content
                    while ($offset -lt $read) {
                        $byte = $buffer[$offset]
                        $offset++
                        if ($byte -eq 0x0A) { $stage = 'header'; break }
                        [void]$readFailures.Add('cat-file object response is missing its trailing LF')
                    }
                }
                else {
                    $offset = $read
                }
            }
        }
        if (-not $inputClosed) {
            [void]$writer.GetAwaiter().GetResult()
            $process.StandardInput.Close()
            $inputClosed = $true
        }
        $process.WaitForExit()
        if ($process.ExitCode -ne 0 -or $responses -ne $requestedOids.Count -or $result.Count -ne $blobs.Count -or $readFailures.Count -gt 0) {
            $failureDetails = [string]::Join('; ', @($readFailures | Select-Object -First 8))
            throw "tracked retirement blob read was incomplete (exit=$($process.ExitCode) expected=$($requestedOids.Count) responses=$responses read=$($result.Count) paths=$($blobs.Count) failures=$failureDetails)"
        }
    }
    finally {
        $process.StandardOutput.Close()
        $process.StandardError.Close()
        if (-not $process.HasExited) { $process.Kill() }
        $process.Dispose()
    }
    return $result
}

function Get-GovernorRetirementTrackedPathText([string]$Repo, [string]$SourceCommit, [string]$RelativePath) {
    $blob = Get-GovernorRetirementTrackedPathDigest $Repo $SourceCommit $RelativePath
    if (-not $blob) { return $null }
    $text = (& git -C $Repo cat-file -p $blob 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0 -or $null -eq $text) {
        return $null
    }
    return [pscustomobject]@{ blob = $blob; text = $text }
}

function Get-GovernorRetirementPinnedLegacyIdentity([string]$Repo, [string]$SourceCommit) {
    # Recomputes the retiring package/target/plugin identity from the pinned
    # manifests and the owner-pinned release-role registration, never from
    # cargo metadata. Returns present/absent with the exact blob bindings.
    $workspace = Get-GovernorRetirementTrackedPathText $Repo $SourceCommit $script:GovernorRetirementWorkspaceManifestPath
    $facade = Get-GovernorRetirementTrackedPathText $Repo $SourceCommit $script:GovernorRetirementFacadeManifestPath
    if (-not $workspace) {
        return [pscustomobject]@{ status = 'absent'; reason = 'workspace manifest is not tracked at this candidate'; workspace_blob = $null; facade_blob = $null; plugin_blob = $null }
    }
    $memberListed = $false
    $inMembers = $false
    foreach ($line in @(([string]$workspace.text) -split "`r?`n")) {
        if (-not $inMembers -and $line -match '^\s*members\s*=\s*\[') { $inMembers = $true }
        if ($inMembers) {
            if ($line -match '"crates/eliot-app"') { $memberListed = $true }
            if ($line -match '\]') { break }
        }
    }
    if (-not $memberListed) {
        return [pscustomobject]@{ status = 'absent'; reason = 'crates/eliot-app is not a workspace member at this candidate'; workspace_blob = [string]$workspace.blob; facade_blob = $null; plugin_blob = $null }
    }
    if (-not $facade) {
        return [pscustomobject]@{ status = 'absent'; reason = 'facade manifest is not tracked at this candidate'; workspace_blob = [string]$workspace.blob; facade_blob = $null; plugin_blob = $null }
    }
    $packageName = $null
    $binNames = @()
    $section = ''
    foreach ($line in @(([string]$facade.text) -split "`r?`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[\[(.+)\]\]$') { $section = '[[' + $Matches[1] + ']]'; continue }
        if ($trimmed -match '^\[(.+)\]$') { $section = '[' + $Matches[1] + ']'; continue }
        if ($trimmed -match '^name\s*=\s*"([^"]+)"') {
            if ($section -ceq '[package]' -and -not $packageName) { $packageName = $Matches[1] }
            elseif ($section -ceq '[[bin]]') { $binNames += @($Matches[1]) }
        }
    }
    $pluginBlob = Get-GovernorRetirementTrackedPathDigest $Repo $SourceCommit "$($script:GovernorRetirementPlugin)/.codex-plugin/plugin.json"
    $binFound = @($binNames | Where-Object { $_ -ceq $script:GovernorRetirementBinary }).Count -ge 1
    if ($packageName -cne $script:GovernorRetirementPackage -or -not $binFound -or -not $pluginBlob) {
        return [pscustomobject]@{ status = 'absent'; reason = 'the candidate no longer binds the exact retiring package/target/plugin identity'; workspace_blob = [string]$workspace.blob; facade_blob = [string]$facade.blob; plugin_blob = $pluginBlob }
    }
    return [pscustomobject]@{ status = 'present'; reason = $null; workspace_blob = [string]$workspace.blob; facade_blob = [string]$facade.blob; plugin_blob = [string]$pluginBlob }
}

function Get-GovernorRetirementCandidateInventorySurfaces([string]$Repo, [string]$SourceCommit) {
    # The candidate's reviewed migration declaration (#18 CONSUMER_SURFACES).
    # It is migration evidence, never completeness evidence: the closure below is
    # computed independently from the tracked tree of C.
    $inventory = Get-GovernorRetirementTrackedPathText $Repo $SourceCommit $script:GovernorRetirementDispositionInventoryPath
    if (-not $inventory) {
        return [pscustomobject]@{ blob = $null; surfaces = @() }
    }
    $surfaces = @()
    $matches = [regex]::Matches([string]$inventory.text, 'path:\s*"([^"]+)"\s*,\s*live_reference:\s*"((?:[^"\\]|\\.)*)"')
    foreach ($match in $matches) {
        $reference = ([string]$match.Groups[2].Value).Replace('\\', '\').Replace('\"', '"')
        $surfaces += @([pscustomobject]@{ path = [string]$match.Groups[1].Value; live_reference = $reference })
    }
    return [pscustomobject]@{ blob = [string]$inventory.blob; surfaces = @($surfaces) }
}

function Get-GovernorRetirementCandidateMigratedEdgeProofPaths([string]$Repo, [string]$SourceCommit) {
    # Exact owner evidence for already-migrated consumer edges. These paths are
    # not live CONSUMER_SURFACES, but their independent owner guard pins the old
    # invocation as absent and the replacement route as present.
    $inventory = Get-GovernorRetirementTrackedPathText $Repo $SourceCommit $script:GovernorRetirementDispositionInventoryPath
    if (-not $inventory) { return @() }
    $table = [regex]::Match([string]$inventory.text, 'pub const MIGRATED_CONSUMER_EDGES:\s*&\[MigratedConsumerEdge\]\s*=\s*&\[\s*(?<body>.*?)\r?\n\];', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $table.Success) { return @() }
    $paths = [System.Collections.Generic.List[string]]::new()
    foreach ($match in [regex]::Matches([string]$table.Groups['body'].Value, 'proof:\s*"([^"]+)"')) {
        $path = ([string]$match.Groups[1].Value).Replace('\', '/')
        if (-not [string]::IsNullOrWhiteSpace($path)) { [void]$paths.Add($path) }
    }
    return @($paths | Sort-Object -Unique)
}

function Get-GovernorRetirementCandidateClosedReferenceRoles([string]$Repo, [string]$SourceCommit) {
    # Exact path roles are declared by the #18 semantic inventory. They close
    # references that name history, generated projections, migration/audit
    # evidence, or the separate current Governor-config contract without
    # pretending those strings launch the retiring executable. The source
    # inventory blob is part of the tracked closure and the declaration is
    # parsed from that pinned blob, never from the mutable worktree.
    $inventory = Get-GovernorRetirementTrackedPathText $Repo $SourceCommit $script:GovernorRetirementDispositionInventoryPath
    if (-not $inventory) { return @() }
    $table = [regex]::Match([string]$inventory.text, 'pub const CLOSED_REFERENCE_ROLES:\s*&\[ClosedReferenceRole\]\s*=\s*&\[\s*(?<body>.*?)\r?\n\];', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    if (-not $table.Success) { return @() }
    $allowedRoles = @(
        'live_consumer:build', 'live_consumer:test', 'live_consumer:workspace_lock',
        'reference_only:historical_record', 'reference_only:decision_record', 'reference_only:policy_history',
        'reference_only:project_map', 'reference_only:architecture_history', 'reference_only:migration_policy',
        'reference_only:navigation', 'reference_only:documentation_configuration', 'reference_only:security_guidance',
        'reference_only:migration_inventory', 'reference_only:operator_history', 'reference_only:workstream_record',
        'reference_only:owner_instruction', 'reference_only:owner_registry', 'reference_only:generated_projection',
        'reference_only:current_configuration', 'reference_only:repository_hygiene', 'reference_only:audit_fixture',
        'reference_only:navigation_configuration', 'reference_only:measurement_inventory',
        'reference_only:migration_verifier', 'reference_only:test_data', 'reference_only:migration_compiler_input',
        'reference_only:skill_manifest', 'reference_only:skill_guidance'
    )
    $roles = [System.Collections.Generic.List[object]]::new()
    foreach ($match in [regex]::Matches([string]$table.Groups['body'].Value, 'path:\s*"([^"]+)"\s*,\s*role:\s*"([^"]+)"\s*,\s*basis:\s*"([^"]+)"')) {
        $path = ([string]$match.Groups[1].Value).Replace('\', '/')
        $role = [string]$match.Groups[2].Value
        $basis = [string]$match.Groups[3].Value
        if ([string]::IsNullOrWhiteSpace($path) -or $path.Contains('*') -or $path.Contains('?') -or
            $path.StartsWith('/', [System.StringComparison]::Ordinal) -or $path.Split('/') -contains '..' -or
            [string]::IsNullOrWhiteSpace($basis) -or $allowedRoles -cnotcontains $role) {
            throw "closed reference role declaration is malformed at $path ($role)"
        }
        [void]$roles.Add([pscustomobject]@{ path = $path; role = $role; basis = $basis })
    }
    if ($roles.Count -eq 0) { throw 'closed reference role table is empty or malformed' }
    $duplicates = @($roles | Group-Object -Property path | Where-Object Count -ne 1)
    if ($duplicates.Count -gt 0) { throw "closed reference role table repeats path(s): $([string]::Join(',', @($duplicates | ForEach-Object Name)))" }
    return @($roles | Sort-Object -Property path)
}

function Get-GovernorRetirementClosureClass([string]$RelativePath) {
    # Path-family classification. The five families are the closure's
    # denominator contract: an owner closure that never classified a family is
    # incomplete and blocks approval.
    $path = ([string]$RelativePath).Replace('\', '/')
    if ($path -eq $script:GovernorRetirementPlugin -or $path.StartsWith("$($script:GovernorRetirementPlugin)/", [System.StringComparison]::Ordinal)) {
        return 'retiring_plugin_tree'
    }
    if ($path.StartsWith('integrations/', [System.StringComparison]::Ordinal)) {
        return 'host_integration_manifest'
    }
    if ($path.StartsWith('apps/', [System.StringComparison]::Ordinal)) {
        return 'desktop_surface'
    }
    if ($path.StartsWith('docs/', [System.StringComparison]::Ordinal) -or
        $path.StartsWith('workstreams/', [System.StringComparison]::Ordinal)) {
        return 'documentation_and_workstream'
    }
    return 'source_and_automation'
}

function Get-GovernorRetirementClosureClassification(
    [string]$RelativePath,
    [string[]]$Tokens,
    [string]$RuleSet = $script:GovernorRetirementClosureRuleSetV1,
    [System.Collections.Generic.HashSet[string]]$ConsumerSurfacePaths = $null,
    [System.Collections.Generic.HashSet[string]]$MigratedConsumerProofPaths = $null,
    [System.Collections.Generic.Dictionary[string, string]]$ClosedReferenceRoles = $null) {
    # Evidence-class classification for one tracked reference. Returns the
    # verifier rules that cover this path, or the single real class 'unknown'
    # when no rule covers it. 'unknown' is a class, not an absence: the caller
    # records unknown references explicitly, binds them into the closure
    # digest, reports the closure INCOMPLETE, and approval stays blocked. The
    # path family is reported separately by the caller; it partitions the
    # denominator but never stands in for a covering verifier rule.
    $path = ([string]$RelativePath).Replace('\', '/')
    $classes = [System.Collections.Generic.List[string]]::new()
    if ($script:GovernorRetirementClosureRuleSets -cnotcontains $RuleSet) {
        throw "unsupported Governor retirement closure rule set: $RuleSet"
    }
    foreach ($token in @($Tokens)) {
        if ($path -ceq $token -or $path.EndsWith("/$token", [System.StringComparison]::Ordinal) -or
            $path.StartsWith("$token/", [System.StringComparison]::Ordinal)) {
            [void]$classes.Add('retiring_surface_identity')
        }
    }
    if ($path -ceq $script:GovernorRetirementWorkspaceManifestPath -or
        $path -ceq $script:GovernorRetirementFacadeManifestPath -or
        $path -ceq $script:GovernorRetirementDispositionInventoryPath) {
        [void]$classes.Add('release_role_registry')
    }
    if ($path.StartsWith('crates/', [System.StringComparison]::Ordinal) -or
        $path.StartsWith('bins/', [System.StringComparison]::Ordinal) -or
        $path.StartsWith('migrations/', [System.StringComparison]::Ordinal) -or
        $path.StartsWith('config/', [System.StringComparison]::Ordinal)) {
        [void]$classes.Add('source_graph')
    }
    if ($path.StartsWith('.github/workflows/', [System.StringComparison]::Ordinal)) {
        [void]$classes.Add('continuous_integration')
    }
    if ($RuleSet -ceq $script:GovernorRetirementClosureRuleSetV2) {
        # Closed semantic owner declarations. CONSUMER_SURFACES remains
        # evidence for only its exact proof paths; it does not define the
        # tracked-file/token denominator below, so undeclared references stay
        # unknown.
        if ($ConsumerSurfacePaths -and $ConsumerSurfacePaths.Contains($path)) {
            [void]$classes.Add('owner_declared_consumer_surface')
        }
        if ($MigratedConsumerProofPaths -and $MigratedConsumerProofPaths.Contains($path)) {
            [void]$classes.Add('owner_declared_migrated_consumer_edge')
        }
        if ($ClosedReferenceRoles -and $ClosedReferenceRoles.ContainsKey($path)) {
            [void]$classes.Add("owner_declared_$($ClosedReferenceRoles[$path].Replace(':', '_'))")
        }
        # The release guide and owner inventory describe active build edges.
        # These exact roles are grounded by the production finalizer/readback
        # contract and the builder's dot-source/call chain; no path-wide
        # documentation or script class is inferred.
        if ($path -ceq 'scripts/finalize-eliot-windows-x64-release.ps1' -or
            $path -ceq 'scripts/lib/governor-retirement-approval.ps1') {
            [void]$classes.Add('release_retirement_verifier')
        }
        if ($path -ceq 'scripts/lib/governor-retirement-approval-trust.json') {
            [void]$classes.Add('release_authority_policy')
        }
        if ($path -ceq 'scripts/lib/entrypoint-inventory.ps1') {
            [void]$classes.Add('release_entrypoint_inventory')
        }
        if ($path -ceq 'scripts/invoke-eliot-windows-x64-production.ps1') {
            [void]$classes.Add('release_workflow_coordinator')
        }
    }
    if ($classes.Count -eq 0) {
        return @('unknown')
    }
    return @($classes | Sort-Object -Unique)
}

function Get-GovernorRetirementConsumerClosure(
    [string]$Repo,
    [string]$SourceCommit,
    [switch]$AllowMissingFamilies,
    [string]$RuleSet = $script:GovernorRetirementClosureRuleSetV1,
    [string]$ReferenceDeclarationCommit = $SourceCommit) {
    # Independent closure over the tracked tree of C (issue #2968 section D).
    # Enumerates every tracked file and records every file that names the
    # retiring surface: files covered by a verifier rule are classified, and
    # files matching no rule are classified 'unknown', bound into the digest,
    # and reported explicitly. The result is independent of the candidate's
    # own disposition table, so a candidate can neither shrink the table and
    # the verifier together, nor make an unclassified reference disappear:
    # any 'unknown' reference makes the closure INCOMPLETE and blocks approval.
    if ($script:GovernorRetirementClosureRuleSets -cnotcontains $RuleSet) {
        throw "unsupported Governor retirement closure rule set: $RuleSet"
    }
    $tokens = @($script:GovernorRetirementClosureTokens)
    $consumerSurfacePaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $migratedConsumerProofPaths = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $closedReferenceRoles = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
    if ($RuleSet -ceq $script:GovernorRetirementClosureRuleSetV2) {
        $ownerSurfaces = Get-GovernorRetirementCandidateInventorySurfaces $Repo $ReferenceDeclarationCommit
        foreach ($surface in @($ownerSurfaces.surfaces)) {
            $ownerPath = ([string]$surface.path).Replace('\', '/')
            if (-not [string]::IsNullOrWhiteSpace($ownerPath)) {
                [void]$consumerSurfacePaths.Add($ownerPath)
            }
        }
        foreach ($ownerPath in @(Get-GovernorRetirementCandidateMigratedEdgeProofPaths $Repo $ReferenceDeclarationCommit)) {
            [void]$migratedConsumerProofPaths.Add([string]$ownerPath)
        }
        foreach ($role in @(Get-GovernorRetirementCandidateClosedReferenceRoles $Repo $ReferenceDeclarationCommit)) {
            $ownerPath = [string]$role.path
            if ($consumerSurfacePaths.Contains($ownerPath) -or $migratedConsumerProofPaths.Contains($ownerPath)) {
                throw "closed reference role overlaps a declared live or migrated consumer proof: $ownerPath"
            }
            $closedReferenceRoles.Add($ownerPath, [string]$role.role)
        }
    }
    $tracked = @(& git -C $Repo ls-tree -r --name-only $SourceCommit)
    if ($LASTEXITCODE -ne 0) {
        throw "failed to enumerate the tracked closure denominator at $SourceCommit"
    }
    if ($tracked.Count -eq 0) {
        throw 'the tracked closure denominator is empty at this candidate'
    }
    $sortedPaths = @($tracked | ForEach-Object { ([string]$_).Replace('\', '/') } | Sort-Object)
    # One batched read of the whole denominator. The per-path subprocess form
    # of this scan took many minutes on a repository of this size, which is
    # not an acceptable cost for a release gate; the batched form reads exactly
    # the same pinned objects and produces the same classification.
    $contents = Get-GovernorRetirementTrackedBlobsText $Repo $SourceCommit $sortedPaths
    $classified = [System.Collections.Generic.List[object]]::new()
    $families = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $unclassified = [System.Collections.Generic.List[string]]::new()
    $unknownEntries = [System.Collections.Generic.List[object]]::new()
    foreach ($relative in $sortedPaths) {
        if (-not $contents.ContainsKey([string]$relative)) { continue }
        $text = $contents[[string]$relative]
        $family = Get-GovernorRetirementClosureClass $relative
        [void]$families.Add($family)
        $classes = Get-GovernorRetirementClosureClassification ([string]$relative) $tokens $RuleSet $consumerSurfacePaths $migratedConsumerProofPaths $closedReferenceRoles
        $hits = @($tokens | Where-Object { ([string]$text.text).Contains($_) } | Sort-Object -Unique)
        if ($hits.Count -eq 0 -and -not ($classes -contains 'release_role_registry')) {
            continue
        }
        if ($classes -contains 'unknown') {
            # A tracked reference the verifier cannot place under any rule.
            # Recorded explicitly and bound into the digest below, so it can
            # never disappear from the denominator; the closure below reports
            # INCOMPLETE and the approval binding refuses it.
            [void]$unclassified.Add([string]$relative)
            [void]$unknownEntries.Add([pscustomobject]@{
                    path = [string]$relative
                    blob = [string]$text.blob
                    family = [string]$family
                    tokens = @($hits)
                })
            continue
        }
        $proofRequired = $hits.Count -gt 0
        if ($closedReferenceRoles.ContainsKey([string]$relative) -and $closedReferenceRoles[[string]$relative].StartsWith('reference_only:', [System.StringComparison]::Ordinal)) {
            $proofRequired = $false
        }
        if ($consumerSurfacePaths.Contains([string]$relative) -or $migratedConsumerProofPaths.Contains([string]$relative)) {
            $proofRequired = $true
        }
        [void]$classified.Add([pscustomobject]@{
                path = [string]$relative
                blob = [string]$text.blob
                classes = @((@($classes) + "family:$family") | Sort-Object -Unique)
                tokens = @($hits)
                consumer_proof_required = [bool]$proofRequired
            })
    }
    $sorted = @($classified | Sort-Object -Property path)
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'domain' $script:GovernorRetirementClosureDomain))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'rule_set' $RuleSet))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'candidate_commit' $SourceCommit))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'candidate_tree' (Get-GovernorRetirementCandidateTree $Repo $SourceCommit)))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'tracked_file_count' $tracked.Count))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'path_family' $script:GovernorRetirementClosurePathFamilies))
    if ($AllowMissingFamilies) {
        # The historical owner receipt still requires every source family. A
        # post-deletion candidate may intentionally remove the legacy plugin
        # family, so that mode binds a distinct candidate-only closure digest.
        [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'candidate_closure_mode' 'post-deletion-cleanliness-v1'))
    }
    foreach ($entry in $sorted) {
        if ($RuleSet -ceq $script:GovernorRetirementClosureRuleSetV2) {
            [void]$lines.Add("closure=$([string]$entry.path)|blob=$([string]$entry.blob)|classes=$([string]::Join(',', @($entry.classes)))|tokens=$([string]::Join(',', @($entry.tokens)))|consumer_proof_required=$([int][bool]$entry.consumer_proof_required)")
        }
        else {
            # Historical v1 canonical bytes remain immutable: no new role or
            # denominator field is serialized into its original digest.
            [void]$lines.Add("closure=$([string]$entry.path)|blob=$([string]$entry.blob)|classes=$([string]::Join(',', @($entry.classes)))|tokens=$([string]::Join(',', @($entry.tokens)))")
        }
    }
    foreach ($entry in @($unknownEntries | Sort-Object -Property path)) {
        [void]$lines.Add("unclassified=$([string]$entry.path)|blob=$([string]$entry.blob)|family=$([string]$entry.family)|tokens=$([string]::Join(',', @($entry.tokens)))")
    }
    $canonical = (@($lines) -join "`n")
    $familyList = @($families | Sort-Object)
    $missingFamilies = @($script:GovernorRetirementClosurePathFamilies | Where-Object { -not $families.Contains($_) })
    $blockingMissingFamilies = if ($AllowMissingFamilies) {
        @($missingFamilies | Where-Object { $_ -cne 'retiring_plugin_tree' })
    }
    else {
        @($missingFamilies)
    }
    $status = if ($unclassified.Count -gt 0) { 'INCOMPLETE' }
    elseif ($blockingMissingFamilies.Count -gt 0) { 'INCOMPLETE' }
    else { 'COMPLETE' }
    [pscustomobject]@{
        schema = $script:GovernorRetirementClosureSchema
        status = $status
        rule_set = $RuleSet
        verifier = $MyInvocation.MyCommand.Name  # unqualified: the computing function in every session (matches the trust policy's pinned verifier); the $script: form would name the hosting script per session and break issuance-to-binding agreement
        candidate_commit = $SourceCommit
        candidate_tree = (Get-GovernorRetirementCandidateTree $Repo $SourceCommit)
        tracked_file_count = $tracked.Count
        classified_count = $sorted.Count
        path_families = @($familyList)
        unclassified_path_families = @($missingFamilies)
        unclassified_paths = @($unclassified)
        entries = @($sorted)
        digest_sha256 = Get-GovernorApprovalSha256 $canonical
    }
}

function Get-GovernorRetirementExpectedConsumerProofs([object]$Closure) {
    # The independent scanner, not the owner-authored approval list or the
    # legacy crate's CONSUMER_SURFACES table, defines which tracked proof files
    # need an owner disposition. The returned token set is closed per path so
    # an owner proof for one string cannot silently leave a second tracked
    # Governor reference in that same file outside the approved denominator.
    $proofs = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in @($Closure.entries)) {
        $path = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $entry 'path')
        $tokens = @((Read-GovernorApprovalField $entry 'tokens') | ForEach-Object { [string]$_ } | Sort-Object -Unique)
        $proofRequired = Read-GovernorApprovalField $entry 'consumer_proof_required'
        $ruleSet = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Closure 'rule_set')
        $includeProof = if ($ruleSet -ceq $script:GovernorRetirementClosureRuleSetV1) { $tokens.Count -gt 0 }
        else { $tokens.Count -gt 0 -and $proofRequired -is [bool] -and $proofRequired }
        if ($includeProof) {
            if ([string]::IsNullOrWhiteSpace($path) -or $proofs.ContainsKey($path)) {
                throw "independent retirement closure contains an empty or duplicate proof path: $path"
            }
            $proofs[$path] = [pscustomobject]@{ path = $path; tokens = @($tokens) }
        }
    }
    return @($proofs.Values | Sort-Object -Property path)
}


function Get-GovernorRetirementPolicyRevision([object]$TrustPolicy) {
    return ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'release_policy_revision')
}

function Get-GovernorRetirementClosurePolicyRevision([object]$TrustPolicy, [string]$RuleSet) {
    $schema = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'schema')
    if ($script:GovernorRetirementClosureRuleSets -cnotcontains $RuleSet) {
        throw "approval closure rule set is not supported by this verifier: $RuleSet"
    }
    if ($schema -ceq 'eliot-governor-retirement-approval-trust-v1') {
        if ($RuleSet -cne $script:GovernorRetirementClosureRuleSetV1 -or
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'closure_rule_set')) -cne $RuleSet) {
            throw 'historical trust-v1 only admits the original v1 source and candidate closure rule'
        }
        return Get-GovernorRetirementPolicyRevision $TrustPolicy
    }
    if ($schema -cne $script:GovernorRetirementTrustSchema) {
        throw "retirement trust policy schema cannot bind closure policy: $schema"
    }
    $matches = @(@(Read-GovernorApprovalField $TrustPolicy 'closure_policies') | Where-Object {
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'owner_source_rule_set')) -ceq $RuleSet -and
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'release_candidate_rule_set')) -ceq $RuleSet
        })
    if ($matches.Count -ne 1) {
        throw "retirement trust policy does not bind one matching source/C and candidate/D rule pair for $RuleSet"
    }
    return ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $matches[0] 'approval_release_policy_revision')
}

function Test-GovernorRetirementApprovalShape(
    [object]$Approval,
    [string]$SourceCommit,
    [string]$CandidateTree,
    [object]$Closure,
    [string]$Repo,
    [string]$ReleasePolicyRevision,
    [object]$IssuerReadback = $null,
    [object]$ReceiptVerification = $null) {
    # Decoding plus schema validation. SHAPE ONLY: returns a result whose
    # `admissible` bit is true when the body is a well-formed GovernorRetirement
    # ApprovalV1 bound to historical source C, its closure and policy. It grants
    # nothing; only verified issuer evidence - an EXECUTED issuer readback and a
    # cryptographically authenticated detached owner receipt - makes the
    # approval actionable.
    $rejected = {
        param([string]$Reason)
        [pscustomobject]@{
            admitted = $false
            reason = $Reason
            content_sha256 = $null
            canonical_request_hash = $null
            operation_id = $null
            approver_principal = $null
            consumers = @()
        }
    }
    if (-not $Approval) {
        return (& $rejected 'APPROVAL_BODY_MISSING')
    }
    if ([string](Read-GovernorApprovalField $Approval 'schema') -cne $script:GovernorRetirementApprovalSchema) {
        return (& $rejected "APPROVAL_SCHEMA_NOT_ADMITTED (expected $($script:GovernorRetirementApprovalSchema))")
    }
    $supportedFields = @(
        'schema', 'domain', 'repository', 'product', 'product_contract',
        'normative_pair_revision', 'normative_pair_sha256', 'config_policy_revision',
        'release_policy_revision', 'candidate_commit', 'candidate_tree',
        'legacy_package', 'legacy_binary', 'legacy_release_role', 'legacy_plugin_path',
        'closure_rule_set', 'closure_verifier', 'closure_digest', 'closure_count',
        'closure_declaration_path', 'closure_declaration_sha256',
        'replacement_owner', 'replacement_product_contract', 'product_removal_decision',
        'issue_refs', 'work_refs', 'review_refs',
        'operation_id', 'idempotency_namespace', 'canonical_request_hash', 'idempotency_retention_hours',
        'approver_principal', 'approver_role', 'issuer', 'issuer_receipt_kind',
        'issuer_evidence_sha256', 'issuer_readback_ref', 'issuer_readback_sha256',
        'issuer_readback_blob', 'issuer_certificate_thumbprint', 'issuer_signing_time_utc',
        'issued_at_utc', 'expires_at_utc', 'revocation_state', 'reopen_condition',
        'rollback_condition', 'proof_ceiling', 'consumers', 'content_sha256'
    )
    foreach ($property in $Approval.PSObject.Properties) {
        if ($supportedFields -cnotcontains [string]$property.Name) {
            return (& $rejected "APPROVAL_FIELD_NOT_IN_CLOSED_CONTRACT (field=$([string]$property.Name))")
        }
    }
    if ([string](Read-GovernorApprovalField $Approval 'domain') -cne $script:GovernorRetirementApprovalDomain) {
        return (& $rejected "APPROVAL_DIGEST_DOMAIN_NOT_ADMITTED (expected $($script:GovernorRetirementApprovalDomain))")
    }
    try {
        $boundRepository = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'repository')).ToLowerInvariant()
        $boundProduct = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'product')
        $boundContract = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'product_contract')
        # Like-for-like: the bound value is lowercased above, so the admitted
        # identity must be lowercased too, or no approval could ever match.
        if ($boundRepository -cne $script:GovernorRetirementLegacyRepository.ToLowerInvariant()) {
            return (& $rejected "APPROVAL_REPOSITORY_MISMATCH (expected $($script:GovernorRetirementLegacyRepository))")
        }
        if ($boundProduct -cne $script:GovernorRetirementProduct -or $boundContract -cne $script:GovernorRetirementProductContract) {
            return (& $rejected "APPROVAL_PRODUCT_MISMATCH (expected $($script:GovernorRetirementProduct)/$($script:GovernorRetirementProductContract))")
        }
        $boundCommit = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'candidate_commit')).ToLowerInvariant()
        $boundTree = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'candidate_tree')).ToLowerInvariant()
        if ($boundCommit -cne $SourceCommit) {
            return (& $rejected "APPROVAL_CANDIDATE_COMMIT_MISMATCH (approved=$boundCommit candidate=$SourceCommit)")
        }
        if ($boundTree -cne $CandidateTree) {
            return (& $rejected "APPROVAL_CANDIDATE_TREE_MISMATCH (approved=$boundTree candidate=$CandidateTree)")
        }
        $selfReceiptBlob = Get-GovernorRetirementTrackedPathDigest $Repo $SourceCommit $script:GovernorRetirementForbiddenSelfReceiptPath
        if ($selfReceiptBlob) {
            return (& $rejected "APPROVAL_CANDIDATE_CARRIES_SELF_RECEIPT (candidate=$SourceCommit still tracks $($script:GovernorRetirementForbiddenSelfReceiptPath); freeze a receipt-free candidate first, then issue R(C) detached)")
        }
        $normativeRevision = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'normative_pair_revision')
        $normativeDigest = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'normative_pair_sha256')).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normativeRevision) -or $normativeRevision -cnotmatch '^\d+\.\d+-(draft|adopted)$') {
            return (& $rejected "APPROVAL_NORMATIVE_PAIR_REVISION_MALFORMED (value=$normativeRevision)")
        }
        if ($normativeDigest -cnotmatch '^[0-9a-f]{64}$') {
            return (& $rejected "APPROVAL_NORMATIVE_PAIR_DIGEST_MALFORMED (value=$normativeDigest)")
        }
        $sourceNormativePair = Get-GovernorRetirementNormativePairRevision $Repo $SourceCommit
        if ($normativeRevision -cne [string]$sourceNormativePair.revision -or
            $normativeDigest -cne [string]$sourceNormativePair.sha256) {
            return (& $rejected "APPROVAL_NORMATIVE_PAIR_MISMATCH (approved=$normativeRevision/$normativeDigest source=$([string]$sourceNormativePair.revision)/$([string]$sourceNormativePair.sha256))")
        }
        $configPolicy = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'config_policy_revision')
        if ([string]::IsNullOrWhiteSpace($configPolicy)) {
            return (& $rejected 'APPROVAL_CONFIG_POLICY_REVISION_MISSING')
        }
        $boundPolicy = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'release_policy_revision')
        if ($boundPolicy -cne $ReleasePolicyRevision) {
            return (& $rejected "APPROVAL_RELEASE_POLICY_REVISION_MISMATCH (approved=$boundPolicy current=$ReleasePolicyRevision)")
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'legacy_package')) -cne $script:GovernorRetirementPackage -or
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'legacy_binary')) -cne $script:GovernorRetirementBinary -or
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'legacy_release_role')) -cne $script:GovernorRetirementReleaseRole -or
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'legacy_plugin_path')) -cne $script:GovernorRetirementPlugin) {
            return (& $rejected 'APPROVAL_LEGACY_TARGET_IDENTITY_MISMATCH')
        }
        $approvedClosureRuleSet = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'closure_rule_set')
        if ($script:GovernorRetirementClosureRuleSets -cnotcontains $approvedClosureRuleSet) {
            return (& $rejected "APPROVAL_CLOSURE_RULE_SET_NOT_ADMITTED (approved=$approvedClosureRuleSet)")
        }
        if ($approvedClosureRuleSet -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Closure 'rule_set'))) {
            return (& $rejected "APPROVAL_CLOSURE_RULE_SET_MISMATCH (approved=$approvedClosureRuleSet recomputed=$(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Closure 'rule_set')))")
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'closure_verifier')) -cne [string]$Closure.verifier) {
            return (& $rejected "APPROVAL_CLOSURE_VERIFIER_MISMATCH (approved=$(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'closure_verifier')) current=$([string]$Closure.verifier))")
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'closure_digest')).ToLowerInvariant() -cne [string]$Closure.digest_sha256) {
            return (& $rejected 'APPROVAL_CLOSURE_DIGEST_MISMATCH')
        }
        $closureCount = Read-GovernorApprovalField $Approval 'closure_count'
        if ($closureCount -is [bool] -or [string]$closureCount -notmatch '^[0-9]+$' -or [int64]$closureCount -ne [int64]$Closure.classified_count) {
            return (& $rejected "APPROVAL_CLOSURE_COUNT_MISMATCH (approved=$(ConvertTo-GovernorApprovalString $closureCount) current=$([int64]$Closure.classified_count))")
        }
        $declarationPath = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'closure_declaration_path')
        if ($declarationPath -ne $Closure.declaration_path) {
            return (& $rejected "APPROVAL_CLOSURE_DECLARATION_MISMATCH (approved=$declarationPath current=$([string]$Closure.declaration_path))")
        }
        $declarationBlob = Get-GovernorRetirementTrackedPathDigest $Repo $SourceCommit $declarationPath
        if (-not $declarationBlob) {
            return (& $rejected "APPROVAL_CLOSURE_DECLARATION_NOT_TRACKED (path=$declarationPath)")
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'closure_declaration_sha256')).ToLowerInvariant() -cne $declarationBlob) {
            return (& $rejected 'APPROVAL_CLOSURE_DECLARATION_DIGEST_MISMATCH')
        }
        foreach ($reference in @('issue_refs', 'work_refs', 'review_refs')) {
            $value = Read-GovernorApprovalField $Approval $reference
            if ($null -eq $value -or @($value).Count -eq 0) {
                return (& $rejected "APPROVAL_SUPPORTING_IDENTITY_MISSING (field=$reference)")
            }
            foreach ($item in @($value)) {
                if ([string]::IsNullOrWhiteSpace([string]$item)) {
                    return (& $rejected "APPROVAL_SUPPORTING_IDENTITY_BLANK (field=$reference)")
                }
            }
        }
        foreach ($field in @('operation_id', 'idempotency_namespace', 'approver_principal', 'approver_role',
                'issuer', 'issuer_receipt_kind', 'issuer_readback_ref', 'reopen_condition', 'rollback_condition')) {
            if ([string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval $field)))) {
                return (& $rejected "APPROVAL_IDENTITY_FIELD_MISSING (field=$field)")
            }
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'approver_role')) -cne $script:GovernorRetirementApprovalRole) {
            return (& $rejected "APPROVAL_ROLE_NOT_ADMITTED (approved=$(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'approver_role')) admitted=$($script:GovernorRetirementApprovalRole))")
        }
        $retention = Read-GovernorApprovalField $Approval 'idempotency_retention_hours'
        if ($retention -is [bool] -or [string]$retention -notmatch '^[1-9][0-9]*$') {
            return (& $rejected "APPROVAL_IDEMPOTENCY_RETENTION_MALFORMED (value=$(ConvertTo-GovernorApprovalString $retention))")
        }
        $issuerEvidence = Read-GovernorApprovalField $Approval 'issuer_evidence_sha256'
        if ($issuerEvidence -is [bool] -or [string]$issuerEvidence -notmatch '^[0-9a-f]{64}$') {
            return (& $rejected "APPROVAL_OWNER_EVIDENCE_MISSING (issuer_evidence_sha256 must be a 64-hex content digest of the detached owner receipt)")
        }
        # Issuer evidence is never "shaped right" or "a file exists": the
        # issuer_readback_ref must have been EXECUTED against this exact
        # operation and candidate, the signed receipt's content digest must be
        # this approval's content digest, and the authenticated receipt must
        # carry the approval's issuer and approving principal.
        if (-not $IssuerReadback -or [string]$IssuerReadback.state -cne 'SUPPLIED') {
            return (& $rejected "APPROVAL_ISSUER_READBACK_NOT_EXECUTED ($(if ($IssuerReadback) { [string]$IssuerReadback.reason } else { 'no issuer readback was executed for this approval' }))")
        }
        $readbackRef = [string]$IssuerReadback.trust_root_ref
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_readback_ref')) -cne $readbackRef) {
            $approvalRef = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_readback_ref')
            return (& $rejected "APPROVAL_ISSUER_READBACK_REF_MISMATCH (approval='$approvalRef' executed='$readbackRef')")
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'operation_id')) -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $IssuerReadback.decision 'operation_id'))) {
            return (& $rejected 'APPROVAL_ISSUER_READBACK_OPERATION_MISMATCH (the executed owner-decision readback attests a different operation)'
            )
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer')) -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $IssuerReadback.decision 'issuer'))) {
            return (& $rejected 'APPROVAL_ISSUER_READBACK_ISSUER_MISMATCH (the executed owner-decision readback attests a different issuer)')
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'approver_principal')) -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $IssuerReadback.decision 'approver_principal'))) {
            return (& $rejected 'APPROVAL_ISSUER_READBACK_PRINCIPAL_MISMATCH (the executed owner-decision readback attests a different approving principal)')
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'idempotency_namespace')) -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $IssuerReadback.decision 'idempotency_namespace'))) {
            return (& $rejected 'APPROVAL_ISSUER_READBACK_NAMESPACE_MISMATCH (the executed owner-decision readback attests a different idempotency namespace)')
        }
        if (-not $ReceiptVerification -or (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ReceiptVerification 'verified')) -cne 'true') {
            return (& $rejected "APPROVAL_OWNER_RECEIPT_NOT_AUTHENTICATED ($(if ($ReceiptVerification) { [string]$ReceiptVerification.reason } else { 'no detached owner receipt was authenticated' }))")
        }
        if ([string]$ReceiptVerification.signature_status -cne 'VALID') {
            return (& $rejected "APPROVAL_OWNER_RECEIPT_SIGNATURE_NOT_VALID (status=$([string]$ReceiptVerification.signature_status))")
        }
        if ([string]$ReceiptVerification.certificate_chain_trusted -cne 'true') {
            return (& $rejected 'APPROVAL_OWNER_RECEIPT_ISSUER_UNTRUSTED (the admitted issuer certificate does not chain to a trusted root)')
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_evidence_sha256')).ToLowerInvariant() -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ReceiptVerification 'receipt_sha256')).ToLowerInvariant()) {
            return (& $rejected 'APPROVAL_OWNER_RECEIPT_DIGEST_MISMATCH (issuer_evidence_sha256 is not the digest of the authenticated detached owner receipt)')
        }
        $approvalReceiptKind = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_receipt_kind')
        $authenticatedReceiptKind = [string]$ReceiptVerification.receipt_kind
        if ($approvalReceiptKind -cne $authenticatedReceiptKind) {
            return (& $rejected "APPROVAL_ISSUER_RECEIPT_KIND_MISMATCH (approval='$approvalReceiptKind' authenticated='$authenticatedReceiptKind')")
        }
        foreach ($pair in @(
                @{ field = 'issuer_readback_sha256'; observed = [string]$IssuerReadback.sha256 },
                @{ field = 'issuer_readback_blob'; observed = [string]$IssuerReadback.blob },
                @{ field = 'issuer_certificate_thumbprint'; observed = [string]$ReceiptVerification.signer_thumbprint },
                @{ field = 'issuer_signing_time_utc'; observed = [string]$ReceiptVerification.signing_time_utc })) {
            $declared = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval $pair.field)
            if ([string]::IsNullOrWhiteSpace($declared) -or $declared -cne [string]$pair.observed) {
                return (& $rejected "APPROVAL_ISSUER_EVIDENCE_FIELD_MISMATCH ($($pair.field): approval='$declared' authenticated='$([string]$pair.observed)')")
            }
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'revocation_state')) -cne 'not-revoked') {
            return (& $rejected "APPROVAL_REVOKED (state=$(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'revocation_state')))")
        }
        $issued = Test-GovernorApprovalUtcInstant (Read-GovernorApprovalField $Approval 'issued_at_utc') 'issued_at_utc' 'retirement approval'
        $expires = Test-GovernorApprovalUtcInstant (Read-GovernorApprovalField $Approval 'expires_at_utc') 'expires_at_utc' 'retirement approval'
        if ($expires -le $issued) {
            return (& $rejected 'APPROVAL_WINDOW_INVALID (expires_at_utc must be after issued_at_utc)')
        }
        $now = [DateTimeOffset]::UtcNow
        if ($now -lt $issued) {
            return (& $rejected 'APPROVAL_NOT_YET_CURRENT (issued_at_utc is in the future)')
        }
        if ($now -ge $expires) {
            return (& $rejected 'APPROVAL_EXPIRED (expires_at_utc is in the past)')
        }
        $replacementOwner = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'replacement_owner')
        $replacementContract = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'replacement_product_contract')
        $removalDecision = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'product_removal_decision')
        if ([string]::IsNullOrWhiteSpace($replacementOwner) -and [string]::IsNullOrWhiteSpace($removalDecision)) {
            return (& $rejected 'APPROVAL_REPLACEMENT_OR_REMOVAL_DECISION_MISSING')
        }
        if (-not [string]::IsNullOrWhiteSpace($replacementOwner) -and $replacementContract -cne $script:GovernorRetirementProductContract) {
            return (& $rejected "APPROVAL_REPLACEMENT_PRODUCT_CONTRACT_MISMATCH (approved=$replacementContract expected=$($script:GovernorRetirementProductContract))")
        }
        $consumers = @(Read-GovernorApprovalField $Approval 'consumers')
        if ($consumers.Count -eq 0) {
            return (& $rejected 'APPROVAL_NAMES_NO_CONSUMER_DISPOSITION')
        }
        $expectedProofs = @(Get-GovernorRetirementExpectedConsumerProofs $Closure)
        if ($expectedProofs.Count -eq 0) {
            return (& $rejected 'APPROVAL_CONSUMER_DENOMINATOR_EMPTY')
        }
        $expectedPathSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $expectedTokensByPath = [System.Collections.Generic.Dictionary[string, string[]]]::new([System.StringComparer]::Ordinal)
        $expectedProofPairs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        foreach ($proof in $expectedProofs) {
            $proofPath = [string]$proof.path
            [void]$expectedPathSet.Add($proofPath)
            $expectedTokensByPath[$proofPath] = [string[]]@($proof.tokens)
            foreach ($token in @($proof.tokens)) {
                $tokenText = [string]$token
                [void]$expectedProofPairs.Add("$($proofPath.Length):$proofPath|$($tokenText.Length):$tokenText")
            }
        }
        $seen = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $seenProofReferences = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $approvedProofPairs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        # One batched read of every consumer proof path. The per-consumer
        # per-path subprocess form was the remaining hot spot in this gate.
        $proofPaths = @(@($consumers) | ForEach-Object {
                ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'proof_path')
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
        $proofContents = Get-GovernorRetirementTrackedBlobsText $Repo $SourceCommit $proofPaths
        foreach ($consumer in $consumers) {
            $name = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'consumer')
            $proofPath = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'proof_path')
            $reference = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'live_reference')
            $disposition = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'disposition')
            if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($proofPath) -or [string]::IsNullOrWhiteSpace($reference)) {
                return (& $rejected "APPROVAL_CONSUMER_ENTRY_INCOMPLETE (consumer=$name)")
            }
            if (-not $seen.Add("$name|$proofPath|$reference")) {
                return (& $rejected "APPROVAL_CONSUMER_ENTRY_DUPLICATED (consumer=$name)")
            }
            $proofReferenceKey = "$($proofPath.Length):$proofPath|$($reference.Length):$reference"
            if (-not $seenProofReferences.Add($proofReferenceKey)) {
                return (& $rejected "APPROVAL_CONSUMER_PROOF_DUPLICATED (consumer=$name proof=$proofPath)")
            }
            if (-not $expectedPathSet.Contains($proofPath)) {
                return (& $rejected "APPROVAL_CONSUMER_PROOF_OUTSIDE_INDEPENDENT_DENOMINATOR (consumer=$name proof=$proofPath)")
            }
            $matchesClosureToken = $false
            foreach ($token in $expectedTokensByPath[$proofPath]) {
                $tokenText = [string]$token
                if ($reference.Contains($tokenText)) {
                    $matchesClosureToken = $true
                    [void]$approvedProofPairs.Add("$($proofPath.Length):$proofPath|$($tokenText.Length):$tokenText")
                }
            }
            if (-not $matchesClosureToken) {
                return (& $rejected "APPROVAL_CONSUMER_REFERENCE_NOT_IN_INDEPENDENT_DENOMINATOR (consumer=$name proof=$proofPath)")
            }
            if ($script:GovernorRetirementDispositionAdmitted -cnotcontains $disposition) {
                return (& $rejected "APPROVAL_CONSUMER_DISPOSITION_NOT_ADMITTED (consumer=$name disposition=$disposition)")
            }
            if (-not $proofContents.ContainsKey($proofPath)) {
                return (& $rejected "APPROVAL_CONSUMER_PROOF_NOT_TRACKED (consumer=$name proof=$proofPath)")
            }
            $proofText = $proofContents[$proofPath]
            if (-not $proofText -or -not ([string]$proofText.text).Contains($reference)) {
                return (& $rejected "APPROVAL_CONSUMER_LIVE_REFERENCE_NOT_PRESENT (consumer=$name proof=$proofPath)")
            }
            if ($disposition -ceq 'migrated') {
                if ([string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'replacement_owner'))) -or
                    (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'product_contract')) -cne $script:GovernorRetirementProductContract) {
                    return (& $rejected "APPROVAL_CONSUMER_REPLACEMENT_OWNER_MISSING (consumer=$name)")
                }
            }
            elseif ([string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'removal_decision')))) {
                return (& $rejected "APPROVAL_CONSUMER_REMOVAL_DECISION_MISSING (consumer=$name)")
            }
        }
        if ($approvedProofPairs.Count -ne $expectedProofPairs.Count) {
            $missing = @($expectedProofPairs | Where-Object { -not $approvedProofPairs.Contains([string]$_) } | Sort-Object)
            return (& $rejected "APPROVAL_CONSUMER_DENOMINATOR_MISMATCH (approved=$($approvedProofPairs.Count) expected=$($expectedProofPairs.Count) missing=$([string]::Join(',', $missing)))")
        }
        $declared = Get-GovernorApprovalSha256 (Get-GovernorApprovalCanonicalPreimage $Approval)
        $admitted = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'content_sha256')
        if ($declared -cne $admitted) {
            return (& $rejected "APPROVAL_CANONICAL_PREIMAGE_DIGEST_MISMATCH (declared=$admitted recomputed=$declared)")
        }
        $requestHash = Get-GovernorApprovalRequestDigest $Approval
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'canonical_request_hash')) -cne $requestHash) {
            return (& $rejected 'APPROVAL_CANONICAL_REQUEST_HASH_MISMATCH')
        }
        [pscustomobject]@{
            admitted = $true
            reason = $null
            content_sha256 = $declared
            canonical_request_hash = $requestHash
            operation_id = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'operation_id'))
            approver_principal = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'approver_principal'))
            consumers = @($consumers)
        }
    }
    catch {
        return (& $rejected "APPROVAL_SHAPE_REJECTED ($([string]$_.Exception.Message))")
    }
}

function Read-GovernorRetirementJsonFile([string]$Path, [string]$Purpose) {
    # Reads a JSON document that is already outside the candidate tree (the
    # detached approval, the owner trust policy, or the bundle copy) through the
    # caller's pinned path/handle rules. Throws for unreadable or malformed
    # bytes: that is infrastructure, not a disposition outcome.
    $text = [System.Text.Encoding]::UTF8.GetString([System.IO.File]::ReadAllBytes($Path)).TrimStart([char]0xFEFF)
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "$Purpose is empty: $Path"
    }
    $decoded = $null
    try {
        $decoded = $text | ConvertFrom-Json
    }
    catch {
        throw "$Purpose is not well-formed JSON: $([string]$_.Exception.Message)"
    }
    if (-not $decoded) {
        throw "$Purpose decoded to no object: $Path"
    }
    return $decoded
}

function Get-GovernorRetirementOwnerDecisionPreimage([object]$Decision) {
    # Canonical digest domain separation for the owner-decision record. Every
    # authority-bearing field is covered, so a changed issuer, role, operation,
    # candidate, window, revocation state, policy or receipt digest is a
    # different decision identity.
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($field in @('schema', 'domain', 'decision_id', 'operation_id', 'idempotency_namespace',
            'repository', 'product', 'approver_principal', 'approver_role', 'issuer', 'issuer_role',
            'candidate_commit', 'candidate_tree', 'release_policy_revision', 'closure_rule_set',
            'closure_digest', 'receipt_sha256', 'issued_at_utc', 'expires_at_utc', 'revocation_state',
            'reopen_condition', 'rollback_condition')) {
        [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine $field (Read-GovernorApprovalField $Decision $field)))
    }
    return (@($lines) -join "`n")
}

function Test-GovernorRetirementOwnerDecisionShape([object]$Decision, [string]$Purpose) {
    # Shape only. The record becomes authority solely after
    # `Resolve-GovernorRetirementIssuerReadback` has read it back through the
    # owner-pinned ref, executed it against the admitted issuer, the exact
    # candidate, the exact policy revision and the exact receipt digest.
    if (-not $Decision) {
        throw "$Purpose is missing"
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'schema')) -cne $script:GovernorRetirementOwnerDecisionSchema) {
        throw "$Purpose schema is not supported: $(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'schema'))"
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'domain')) -cne $script:GovernorRetirementOwnerDecisionDigestDomain) {
        throw "$Purpose digest domain is not supported: $(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'domain'))"
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'repository')) -cne $script:GovernorRetirementLegacyRepository -or
        (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'product')) -cne $script:GovernorRetirementProduct) {
        throw "$Purpose is not bound to this repository/product release"
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'approver_role')) -cne $script:GovernorRetirementApprovalRole -or
        (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'issuer_role')) -cne $script:GovernorRetirementApprovalRole) {
        throw "$Purpose does not carry the semantic $($script:GovernorRetirementApprovalRole) role"
    }
    foreach ($field in @('decision_id', 'operation_id', 'idempotency_namespace', 'approver_principal', 'issuer')) {
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision $field)) -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$') {
            throw "$Purpose has a malformed $field identity"
        }
    }
    foreach ($field in @('candidate_commit', 'candidate_tree')) {
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision $field)) -cnotmatch '^[0-9a-f]{40,64}$') {
            throw "$Purpose has a malformed $field identity"
        }
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'release_policy_revision')) -cnotmatch '^[0-9]+\.[0-9]+\.[0-9]+$') {
        throw "$Purpose has a malformed release policy revision"
    }
    foreach ($field in @('closure_digest', 'receipt_sha256')) {
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision $field)) -cnotmatch '^[0-9a-f]{64}$') {
            throw "$Purpose has a malformed $field digest"
        }
    }
    $issued = Test-GovernorApprovalUtcInstant (Read-GovernorApprovalField $Decision 'issued_at_utc') 'issued_at_utc' $Purpose
    $expires = Test-GovernorApprovalUtcInstant (Read-GovernorApprovalField $Decision 'expires_at_utc') 'expires_at_utc' $Purpose
    if ($expires -le $issued) {
        throw "$Purpose expires_at_utc must be after issued_at_utc"
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'revocation_state')) -cne 'not-revoked') {
        throw "$Purpose is revoked: $(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'revocation_state'))"
    }
    foreach ($field in @('reopen_condition', 'rollback_condition')) {
        if ([string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision $field)))) {
            throw "$Purpose is missing its $field"
        }
    }
    $declared = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Decision 'content_sha256')
    $recomputed = Get-GovernorApprovalSha256 (Get-GovernorRetirementOwnerDecisionPreimage $Decision)
    if ($declared -cne $recomputed) {
        throw "$Purpose canonical digest mismatch (declared=$declared recomputed=$recomputed)"
    }
    return $true
}

function Resolve-GovernorRetirementOwnerDecisionReadback(
    [string]$Repo,
    [string]$SourceCommit,
    [object]$TrustRoot,
    [string]$OperationId,
    [string]$OwnerReceiptPath) {
    # EXECUTED `issuer_readback_ref`. The approval's `issuer_readback_ref`
    # names the owner-pinned ref's owner-decision record; this resolves that
    # exact record at that exact ref, proves its bytes are the bytes the
    # owner-pinned ref holds (blob identity) and are the bytes the
    # owner-pinned trust policy pins by SHA-256, executes it against the exact
    # operation, candidate C, policy revision, closure digest and detached
    # owner-receipt digest, and refuses on any mismatch. A nonblank ref string,
    # a caller-supplied principal or a "file exists" check is never sufficient.
    $absent = {
        param([string]$Reason)
        [pscustomobject]@{ supplied = $false; state = 'ABSENT'; reason = $Reason; trust_root_ref = $null; decision = $null; sha256 = $null; blob = $null; issuer = $null; approver_principal = $null; receipt_content_sha256 = $null }
    }
    if (-not $TrustRoot -or -not [bool]$TrustRoot.supplied) {
        return (& $absent 'no owner-pinned retirement trust root was supplied, so issuer_readback_ref cannot be resolved or executed')
    }
    if ([string]::IsNullOrWhiteSpace($OperationId) -or $OperationId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$') {
        return (& $absent 'issuer_readback_ref requires an exact approval operation identity to read back')
    }
    $policy = $TrustRoot.trust_policy
    $decisionFile = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $policy 'owner_decision_file')
    $admitted = @(@(Read-GovernorApprovalField $policy 'admitted_issuers') | Where-Object {
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'role')) -ceq $script:GovernorRetirementApprovalRole
        })
    if ($admitted.Count -ne 1 -or [string]::IsNullOrWhiteSpace($decisionFile)) {
        return (& $absent 'the owner-pinned trust policy admits no single retirement-approval issuer, so no owner-decision readback exists to execute')
    }
    $expectedDecisionSha = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $admitted[0] 'owner_decision_sha256')).ToLowerInvariant()
    $decisionBytes = $null
    try {
        $decisionBytes = Get-GovernorRetirementOwnerPinnedArtifact `
            $Repo ([string]$TrustRoot.trust_root_commit) $decisionFile $expectedDecisionSha 'owner-pinned retirement owner decision record'
    }
    catch {
        return (& $absent "the owner-pinned owner-decision record could not be read back: $([string]$_.Exception.Message)")
    }
    $decision = $null
    try {
        $decision = Read-GovernorRetirementJsonFile $decisionBytes.path 'owner-pinned retirement owner decision record'
    }
    catch {
        return (& $absent "the owner-pinned owner-decision record is unreadable: $([string]$_.Exception.Message)")
    }
    try {
        [void](Test-GovernorRetirementOwnerDecisionShape $decision 'owner-pinned retirement owner decision record')
    }
    catch {
        return (& $absent "the owner-pinned owner-decision record is malformed: $([string]$_.Exception.Message)")
    }
    if ([string]$SourceCommit -cnotmatch '^[0-9a-f]{40,64}$') {
        return (& $absent 'the owner-decision readback requires the exact candidate commit being approved')
    }
    $checks = @(
        @{ name = 'operation'; expected = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $admitted[0] 'owner_decision_operation_id')); observed = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'operation_id')) }
        @{ name = 'operation-identity'; expected = $OperationId; observed = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'operation_id')) }
        @{ name = 'issuer'; expected = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $admitted[0] 'issuer')).ToUpperInvariant(); observed = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'issuer')).ToUpperInvariant() }
        @{ name = 'release_policy_revision'; expected = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $policy 'release_policy_revision')); observed = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'release_policy_revision')) }
        @{ name = 'candidate_commit'; expected = ([string]$SourceCommit).ToLowerInvariant(); observed = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'candidate_commit')).ToLowerInvariant() }
    )
    foreach ($check in $checks) {
        if ($check.expected -cne $check.observed) {
            return (& $absent "the executed owner-decision readback disagrees on $($check.name) (pinned='$($check.expected)' decision='$($check.observed)')")
        }
    }
    $decisionTree = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'candidate_tree')).ToLowerInvariant()
    $observedTree = (Get-GovernorRetirementCandidateTree $Repo $SourceCommit).ToLowerInvariant()
    if ($decisionTree -cne $observedTree) {
        return (& $absent "the executed owner-decision readback names a different candidate tree (decision='$decisionTree' candidate='$observedTree')")
    }
    $ruleSet = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'closure_rule_set')
    if ($script:GovernorRetirementClosureRuleSets -cnotcontains $ruleSet) {
        return (& $absent "the executed owner-decision readback names an unsupported closure rule set: $ruleSet"
        )
    }
    $expectedPolicyRevision = Get-GovernorRetirementClosurePolicyRevision $policy $ruleSet
    if ($expectedPolicyRevision -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'release_policy_revision'))) {
        return (& $absent "the executed owner-decision readback names a release policy revision its own closure rule pair does not bind")
    }
    if ([string]::IsNullOrWhiteSpace($OwnerReceiptPath)) {
        return (& $absent 'the executed owner-decision readback requires the detached owner receipt it attests to')
    }
    $receiptBytes = $null
    try {
        $receiptBytes = Read-GovernorRetirementDetachedBytes $OwnerReceiptPath $null 'detached owner retirement receipt'
    }
    catch {
        return (& $absent "the detached owner receipt named by the approval could not be read: $([string]$_.Exception.Message)")
    }
    $receiptContentSha = (Get-GovernorApprovalSha256 ([byte[]]$receiptBytes.bytes)).ToLowerInvariant()
    $attestedReceiptSha = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'receipt_sha256')).ToLowerInvariant()
    if ($receiptContentSha -cne $attestedReceiptSha) {
        return (& $absent "the detached owner receipt digest differs from the one the owner-decision readback attests (decision='$attestedReceiptSha' observed='$receiptContentSha')")
    }
    # The cryptographic authentication of the receipt (including its signed
    # content attribute) is `Test-GovernorRetirementOwnerReceiptSignature`'s
    # job; this readback only proves the OWNER DECISION attests these exact
    # detached bytes for this exact operation and candidate.
    [pscustomobject]@{
        supplied = $true
        state = 'SUPPLIED'
        reason = $null
        trust_root_ref = [string]$TrustRoot.trust_root_ref
        trust_root_commit = [string]$TrustRoot.trust_root_commit
        decision = $decision
        sha256 = [string]$decisionBytes.sha256
        blob = [string]$decisionBytes.blob
        issuer = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'issuer'))
        approver_principal = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'approver_principal'))
        receipt_sha256 = $receiptContentSha
        receipt_content_sha256 = $receiptContent
    }
}

function Get-GovernorRetirementReceiptContent([byte[]]$CmsBytes) {
    # The detached owner receipt carries the approval's canonical content
    # digest as a CMS encapsulated signed attribute. Signing that digest binds
    # the signature to exactly one approval content identity; no embedded
    # signature is accepted instead.
    if ($null -eq $CmsBytes -or $CmsBytes.Length -eq 0) {
        throw 'the detached owner receipt is empty'
    }
    if (-not ('System.Security.Cryptography.Pkcs.SignedCms' -as [type])) {
        throw 'the detached owner receipt cannot be decoded: this PowerShell host has no CMS/PKCS#7 provider'
    }
    $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
    try {
        $cms.Decode([byte[]]$CmsBytes)
    }
    catch {
        throw "the detached owner receipt is not a well-formed detached CMS signature: $([string]$_.Exception.Message)"
    }
    foreach ($attribute in @($cms.SignerInfos[0].SignedAttributes)) {
        if ([string]$attribute.Type.Value -ceq $script:GovernorRetirementReceiptContentOid) {
            $values = @($attribute.Values)
            if ($values.Count -ne 1) {
                throw 'the detached owner receipt carries multiple owner-receipt content attributes'
            }
            $text = [System.Text.Encoding]::UTF8.GetString([byte[]]$values[0].RawData).Trim()
            if ($text -cnotmatch '^[0-9a-f]{64}$') {
                throw 'the detached owner receipt content attribute is not one lowercase 64-hex SHA-256'
            }
            return $text
        }
    }
    throw 'the detached owner receipt carries no owner-receipt content attribute; a detached CMS signature without it proves nothing about this approval'
}

function Test-GovernorRetirementOwnerReceiptSignature(
    [byte[]]$ReceiptBytes,
    [object]$Readback,
    [object]$Policy,
    [object]$Approval = $null) {
    # Cryptographic authentication of the detached owner receipt, plus its
    # semantic read-back against THIS operation. Any failure is data (a refusal
    # result), never a throw, so the caller reports ISSUER_UNAVAILABLE instead of
    # crashing on unverified bytes.
    $refused = {
        param([string]$Reason)
        [pscustomobject]@{ verified = $false; reason = $Reason; receipt_kind = $script:GovernorRetirementOwnerReceiptKind; signature_status = 'UNVERIFIED'; signature_algorithm = $null; signer_thumbprint = $null; signer_subject = $null; certificate_chain_trusted = $null; certificate_not_before_utc = $null; certificate_not_after_utc = $null; signing_time_utc = $null; receipt_sha256 = $null; receipt_content_sha256 = $null }
    }
    try {
        if (-not $Readback -or [string]$Readback.state -cne 'SUPPLIED') {
            return (& $refused 'no executed owner-decision readback: the owner receipt cannot be authenticated without one')
        }
        $admitted = @(@(Read-GovernorApprovalField $Policy 'admitted_issuers') | Where-Object {
                (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'role')) -ceq $script:GovernorRetirementApprovalRole
            })
        if ($admitted.Count -ne 1) {
            return (& $refused 'the owner-pinned trust policy admits no single retirement-approval issuer')
        }
        $pinnedThumbprint = ([string](Read-GovernorApprovalField $admitted[0] 'receipt_certificate_thumbprint')).Replace(' ', '').ToUpperInvariant()
        if ($pinnedThumbprint -cnotmatch '^[0-9A-F]{40}$') {
            return (& $refused 'the owner-pinned trust policy admits no exact receipt certificate thumbprint')
        }
        if ($null -eq $ReceiptBytes -or $ReceiptBytes.Length -eq 0) {
            return (& $refused 'no detached owner receipt bytes were supplied')
        }
        $receiptSha = (Get-GovernorApprovalSha256 ([byte[]]$ReceiptBytes)).ToLowerInvariant()
        $receiptContent = Get-GovernorRetirementReceiptContent $ReceiptBytes
        $cms = [System.Security.Cryptography.Pkcs.SignedCms]::new()
        $cms.Decode([byte[]]$ReceiptBytes)
        $signerInfos = @($cms.SignerInfos)
        if ($signerInfos.Count -ne 1) {
            return (& $refused "the detached owner receipt must carry exactly one CMS signer; found $($signerInfos.Count)")
        }
        $signer = $signerInfos[0]
        $signingTime = $null
        foreach ($attribute in @($signer.SignedAttributes)) {
            if ([string]$attribute.Type.Value -ceq '1.2.840.113549.1.9.5') {
                $signingTime = [DateTimeOffset]::ParseExact(
                    [System.Text.Encoding]::UTF8.GetString([byte[]]@($attribute.Values)[0].RawData).Trim(),
                    "yyyy-MM-dd'T'HH:mm:ss'Z'",
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal)
            }
        }
        if ($null -eq $signingTime) {
            return (& $refused 'the detached owner receipt carries no CMS signing-time attribute; an unsigned-time receipt cannot prove currentness')
        }
        if ($signingTime -lt (Test-GovernorApprovalUtcInstant (Read-GovernorApprovalField $Readback.decision 'issued_at_utc') 'issued_at_utc' 'owner decision')) {
            return (& $refused 'the detached owner receipt was signed before the owner decision it attests')
        }
        if ($signingTime -ge (Test-GovernorApprovalUtcInstant (Read-GovernorApprovalField $Readback.decision 'expires_at_utc') 'expires_at_utc' 'owner decision')) {
            return (& $refused 'the detached owner receipt was signed at or after the expiry of the owner decision it attests')
        }
        $now = [DateTimeOffset]::UtcNow
        if ($now -lt $signingTime) {
            return (& $refused 'the detached owner receipt carries a signing time in the future')
        }
        $signerCertificate = $signer.Certificate
        if ($null -eq $signerCertificate) {
            return (& $refused 'the detached owner receipt carries no signer certificate')
        }
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($signerCertificate)
        try {
            $sha1 = [System.Security.Cryptography.SHA1]::Create()
            try {
                $observedThumbprint = (($sha1.ComputeHash([byte[]]$certificate.RawData) | ForEach-Object { $_.ToString('X2') }) -join '')
            }
            finally {
                $sha1.Dispose()
            }
            if ($observedThumbprint -cne $pinnedThumbprint) {
                return (& $refused "the detached owner receipt was signed by an unadmitted certificate (pinned=$pinnedThumbprint observed=$observedThumbprint)")
            }
            # Revocation is checked before trust and before signature
            # verification: an expired or revoked issuer certificate can never
            # authenticate an approval.
            if ($now -lt [DateTimeOffset]::new($certificate.NotBefore.ToUniversalTime()) -or
                $now -ge [DateTimeOffset]::new($certificate.NotAfter.ToUniversalTime())) {
                return (& $refused "the admitted issuer certificate is outside its validity window ($($certificate.NotBefore.ToUniversalTime().ToString('o')) .. $($certificate.NotAfter.ToUniversalTime().ToString('o')))")
            }
            $revocationStatus = 'NOT_CHECKED'
            try {
                $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new()
                try {
                    $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
                    $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::EntireChain
                    $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
                    if (-not $chain.Build($certificate)) {
                        return (& $refused "the admitted issuer certificate does not chain to a trusted root: $([string]::Join('; ', @($chain.ChainStatus | ForEach-Object { [string]$_.Status })))")
                    }
                    foreach ($element in @($chain.ChainElements)) {
                        $status = [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NoError
                        if (@($element.ChainElementStatus).Count -gt 0) {
                            $status = [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags](@($element.ChainElementStatus)[0].Status)
                        }
                        if (($status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::RevocationStatusUnknown) -ne 0) {
                            return (& $refused "the admitted issuer certificate chain revocation could not be established offline; an unverifiable issuer stays blocked (status=$([string]$status))")
                        }
                        if (($status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::Revoked) -ne 0) {
                            return (& $refused "the admitted issuer certificate is revoked (status=$([string]$status))")
                        }
                        if (($status -band [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]::NotTimeValid) -ne 0) {
                            return (& $refused 'the admitted issuer certificate chain is not time valid')
                        }
                    }
                    $revocationStatus = 'CHECKED'
                }
                finally {
                    $chain.Dispose()
                }
            }
            catch {
                return (& $refused "the admitted issuer certificate chain could not be verified: $([string]$_.Exception.Message)")
            }
            # Verify the detached signature. The receipt is a DETACHED CMS
            # signature: the signed content (the approval content digest) is not
            # embedded, so the signature is checked over the DER-encoded
            # SignedAttributes, which is what the signer actually signed, and
            # the signed attribute set must additionally carry exactly the
            # owner-receipt content digest read above.
            $signatureStatus = 'UNVERIFIED'
            $algorithm = $null
            $digest = $null
            $signedAttributeBytes = [System.Text.Encoding]::ASCII.GetBytes($signer.SignedAttrs)
            # The receipt names its OWN algorithms. A detached CMS SignerInfo
            # declares both the signature algorithm and the message-digest
            # algorithm, and both are read from the parsed receipt rather than
            # from any caller-supplied claim, so a caller cannot talk this gate
            # into accepting a weaker algorithm. Only the two algorithms this
            # contract admits are dispatched; an unknown or absent algorithm is
            # a refusal and NEVER a default (no "assume RSA", no fallback).
            $signatureOid = $null
            $digestOid = $null
            try {
                $signatureOid = [string]$signer.SignatureAlgorithm.Value
                $digestOid = [string]$signer.DigestAlgorithm.Value
            }
            catch {
                return (& $refused "the detached owner receipt declares no readable CMS signature/digest algorithm: $([string]$_.Exception.Message)")
            }
            if ([string]::IsNullOrWhiteSpace($signatureOid) -or [string]::IsNullOrWhiteSpace($digestOid)) {
                return (& $refused 'the detached owner receipt declares no CMS signature/digest algorithm; an unnamed algorithm is refused, not assumed')
            }
            switch ($signatureOid) {
                '1.2.840.113549.1.1.1' { $algorithm = 'RSA' }
                '1.2.840.113549.1.1.11' { $algorithm = 'RSA' }
                '1.2.840.10045.4.1' { $algorithm = 'ECDSA' }
                '1.2.840.10045.4.3.2' { $algorithm = 'ECDSA' }
                default {
                    return (& $refused "the detached owner receipt signature algorithm is not admitted: $signatureOid")
                }
            }
            switch ($digestOid) {
                '2.16.840.1.101.3.4.2.1' { $digest = [System.Security.Cryptography.HashAlgorithmName]::SHA256 }
                default {
                    return (& $refused "the detached owner receipt digest algorithm is not admitted: $digestOid")
                }
            }
            switch ($algorithm) {
                'RSA' {
                    $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($certificate)
                    if ($null -eq $rsa) { return (& $refused 'the admitted issuer certificate exposes no RSA public key') }
                    try {
                        $verified = $rsa.VerifyHash([byte[]]$signer.Signature, $signedAttributeBytes, $digest, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
                    }
                    finally {
                        $rsa.Dispose()
                    }
                    $signatureStatus = if ($verified) { 'VALID' } else { 'INVALID' }
                    break
                }
                'ECDSA' {
                    $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($certificate)
                    if ($null -eq $ecdsa) { return (& $refused 'the admitted issuer certificate exposes no ECDSA public key') }
                    try {
                        $verified = $ecdsa.VerifyHash([byte[]]$signer.Signature, $signedAttributeBytes, $digest)
                    }
                    finally {
                        $ecdsa.Dispose()
                    }
                    $signatureStatus = if ($verified) { 'VALID' } else { 'INVALID' }
                    break
                }
                default {
                    return (& $refused "the detached owner receipt signature algorithm is not admitted: $signatureOid")
                }
            }
            if ($signatureStatus -cne 'VALID') {
                return (& $refused 'the detached owner receipt signature does not verify against the admitted issuer certificate'
                )
            }
            $subject = [string]$certificate.Subject
            $chainTrusted = $true
        }
        finally {
            $certificate.Dispose()
        }
        if ($Approval) {
            # Semantic read-back against THIS operation: the signed receipt must
            # carry the exact content digest of the approval that claims it.
            $approvalDigest = (Get-GovernorApprovalContentDigest $Approval).ToLowerInvariant()
            if ($receiptContent -cne $approvalDigest) {
                return (& $refused "the signed owner receipt content differs from the approval content digest (receipt='$receiptContent' approval='$approvalDigest')")
            }
            if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'operation_id')) -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Readback.decision 'operation_id'))) {
                return (& $refused 'the signed owner receipt attests a different approval operation than the approval carries'
                )
            }
            if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer')) -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Readback.decision 'issuer'))) {
                return (& $refused 'the signed owner receipt attests a different issuer than the approval carries')
            }
            if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'approver_principal')) -cne (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Readback.decision 'approver_principal'))) {
                return (& $refused 'the signed owner receipt attests a different approving principal than the approval carries')
            }
        }
        [pscustomobject]@{
            verified = $true
            reason = $null
            receipt_kind = $script:GovernorRetirementOwnerReceiptKind
            signature_status = $signatureStatus
            signature_algorithm = ([string]$algorithm + '/' + [string]$digestOid)
            signer_thumbprint = $observedThumbprint
            signer_subject = $subject
            certificate_chain_trusted = $chainTrusted
            certificate_not_before_utc = $certificate.NotBefore.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            certificate_not_after_utc = $certificate.NotAfter.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            signing_time_utc = $signingTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
            receipt_sha256 = $receiptSha
            receipt_content_sha256 = $receiptContent
            revocation = $revocationStatus
        }
    }
    catch {
        return (& $refused "the detached owner receipt could not be authenticated: $([string]$_.Exception.Message)")
    }
}

function Resolve-GovernorRetirementDetachedInput([string]$Path, [string]$Purpose) {
    # The explicit build input seam. There is no environment-variable selection,
    # no default path inside the repository, and no directory search: an
    # unset/blank input is absence, and a supplied input must be an explicit
    # absolute resident regular non-reparse file outside the candidate tree.
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return [pscustomobject]@{
            supplied = $false
            state = 'ABSENT'
            reason = "$Purpose was not supplied; absence is not implicit retirement"
            path = $null
            bytes = $null
            sha256 = $null
            body = $null
        }
    }
    $evidence = $null
    if (Get-Command Read-VerifiedResidentFile -CommandType Function -ErrorAction SilentlyContinue) {
        $evidence = Read-VerifiedResidentFile $Path $Purpose
    }
    else {
        throw "the retirement approval input requires the release safe path/handle reader: $Purpose"
    }
    [pscustomobject]@{
        supplied = $true
        state = 'SUPPLIED'
        reason = $null
        path = [string]$evidence.path
        bytes = [byte[]]$evidence.bytes
        sha256 = [string]$evidence.sha256
        body = (Read-GovernorRetirementJsonFile ([string]$evidence.path) $Purpose)
    }
}

function Resolve-GovernorRetirementBundleTrustMaterial(
    [string]$ApprovalReference,
    [string]$ApprovalPath,
    [string]$TrustPath,
    [string]$Purpose) {
    # Offline readback (issue #2968 implementation step 10). The issued
    # immutable approval and the required trust material travel beside the
    # bundle; verification never needs the network. A missing or stale trust
    # file refuses retirement instead of degrading to shape-only.
    $bundleTrust = Resolve-GovernorRetirementDetachedInput $TrustPath "$Purpose trust material"
    if (-not [bool]$bundleTrust.supplied) {
        return [pscustomobject]@{
            trust_state = 'ABSENT'
            reason = "$Purpose trust material is absent; missing or stale trust refuses retirement"
            trust_file = $null
            trust_file_sha256 = $null
            approval_file = $null
            approval_file_sha256 = $null
            approval_body = $null
        }
    }
    [void](Test-GovernorRetirementTrustPolicyShape $bundleTrust.body)
    $approval = Resolve-GovernorRetirementDetachedInput $ApprovalPath "$Purpose detached approval"
    if (-not [bool]$approval.supplied) {
        return [pscustomobject]@{
            trust_state = 'ABSENT'
            reason = "$Purpose detached approval is absent; missing or stale trust refuses retirement"
            trust_file = [string]$bundleTrust.path
            trust_file_sha256 = [string]$bundleTrust.sha256
            approval_file = $null
            approval_file_sha256 = $null
            approval_body = $null
        }
    }
    $expectedTrustFile = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ApprovalReference 'trust_file')
    $expectedTrustDigest = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ApprovalReference 'trust_file_sha256')).ToLowerInvariant()
    $expectedApprovalFile = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ApprovalReference 'approval_file')
    $expectedApprovalDigest = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ApprovalReference 'approval_file_sha256')).ToLowerInvariant()
    if ($expectedTrustDigest -cnotmatch '^[0-9a-f]{64}$' -or $expectedApprovalDigest -cnotmatch '^[0-9a-f]{64}$' -or
        [string]::IsNullOrWhiteSpace($expectedTrustFile) -or [string]::IsNullOrWhiteSpace($expectedApprovalFile)) {
        throw "$Purpose release manifest does not bind the detached approval reference and its trust material"
    }
    if ([string]$bundleTrust.sha256 -cne $expectedTrustDigest) {
        throw "$Purpose trust material digest differs from the bound release manifest (stale trust refuses retirement)"
    }
    if ([string]$approval.sha256 -cne $expectedApprovalDigest) {
        throw "$Purpose detached approval digest differs from the bound release manifest (stale approval refuses retirement)"
    }
    [pscustomobject]@{
        trust_state = 'SUPPLIED'
        reason = $null
        trust_file = [string]$bundleTrust.path
        trust_file_sha256 = [string]$bundleTrust.sha256
        approval_file = [string]$approval.path
        approval_file_sha256 = [string]$approval.sha256
        approval_body = $approval.body
    }
}


function Resolve-GovernorRetirementIssuer([object]$TrustPolicy, [object]$OwnerDecision = $null, [object]$ReceiptVerification = $null) {
    # The narrow issuer seam. `ISSUER_UNAVAILABLE` is the documented fail-closed
    # state until an OWNER-PINNED trust policy admits one issuer identity for the
    # semantic retirement-approval role; Authenticode Code Signing signers and any
    # binary-signing identity are never admitted for this role by this module.
    # Actionable additionally requires an EXECUTED issuer readback and a verified
    # detached owner receipt: a name in a policy file is not authority.
    $issuers = @(Read-GovernorApprovalField $TrustPolicy 'admitted_issuers')
    if ($issuers.Count -eq 0) {
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = 'no owner-admitted retirement-approval issuer is configured in the owner-pinned trust policy'
            issuer_identity = $null
            policy_digest = $null
        }
    }
    $matching = @($issuers | Where-Object {
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'role')) -ceq $script:GovernorRetirementApprovalRole -and
            -not [string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'issuer')))
        })
    if ($matching.Count -ne 1) {
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = "the owner-pinned trust policy must admit exactly one issuer for the $($script:GovernorRetirementApprovalRole) role; found $($matching.Count)"
            issuer_identity = $null
            policy_digest = $null
        }
    }
    $admitted = $matching[0]
    if (-not [string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $admitted 'authenticode_code_signing_thumbprint')))) {
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = 'an Authenticode Code Signing signer is not a semantic retirement-approval issuer; the owner-pinned trust policy claim is refused'
            issuer_identity = $null
            policy_digest = $null
        }
    }
    if (-not $OwnerDecision) {
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = 'the admitted issuer was not read back: no executed owner-decision record verified this approval operation, so the issuer name alone is not authority'
            issuer_identity = $null
            policy_digest = $null
        }
    }
    $decisionAdmission = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $OwnerDecision 'issuer')).ToUpperInvariant()
    $policyAdmission = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $admitted 'issuer')).ToUpperInvariant()
    if ($decisionAdmission -cne $policyAdmission) {
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = "the executed owner decision admits '$decisionAdmission' but the owner-pinned trust policy admits '$policyAdmission'"
            issuer_identity = $null
            policy_digest = $null
        }
    }
    if (-not $ReceiptVerification -or [string](Read-GovernorApprovalField $ReceiptVerification 'verified') -cne 'true') {
        $receiptReason = if ($ReceiptVerification) { [string](Read-GovernorApprovalField $ReceiptVerification 'reason') } else { 'no detached owner receipt was verified against the admitted issuer certificate' }
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = "the admitted issuer's detached owner receipt does not verify: $receiptReason"
            issuer_identity = $null
            policy_digest = $null
        }
    }
    [pscustomobject]@{
        state = 'ISSUER_AVAILABLE'
        reason = $null
        issuer_identity = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $admitted 'issuer'))
        policy_digest = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'content_sha256'))
    }
}

function Test-GovernorRetirementCandidateTransition(
    [string]$Repo,
    [string]$CandidateCommit,
    [string]$OwnerSourceCommit,
    [string]$TrustRootCommit,
    [object]$CandidateIdentity,
    [object]$SourceClosure,
    [object]$CandidateClosure,
    [object[]]$ApprovedConsumers) {
    # The detached owner approval remains bound to its original source C. The
    # release candidate D is checked independently: it must descend from C,
    # remove the legacy crate, add no independently scanned path/token pair,
    # and remove every owner-approved live_reference string from its proof
    # path. Existing scanned pairs remain bound by D's closure, but only the
    # exact owner-approved consumer references are required to disappear. The
    # independent scan is the fixed closed-rule contract; no filename-only or
    # inferred live-edge classifier is added.
    $null = & git -C $Repo merge-base --is-ancestor $OwnerSourceCommit $CandidateCommit 2>$null
    if ($LASTEXITCODE -ne 0) {
        return [pscustomobject]@{ admitted = $false; reason = 'APPROVAL_OWNER_SOURCE_NOT_ANCESTOR' }
    }

    if (-not [string]::IsNullOrWhiteSpace($TrustRootCommit)) {
        $null = & git -C $Repo merge-base --is-ancestor $TrustRootCommit $OwnerSourceCommit 2>$null
        if ($LASTEXITCODE -ne 0) {
            return [pscustomobject]@{ admitted = $false; reason = 'APPROVAL_TRUST_ROOT_NOT_ANCESTOR' }
        }
    }
    if ([string]$CandidateClosure.status -cne 'COMPLETE') {
        return [pscustomobject]@{ admitted = $false; reason = "APPROVAL_CANDIDATE_CLOSURE_INCOMPLETE (status=$([string]$CandidateClosure.status))" }
    }
    if ([string]$CandidateIdentity.status -cne 'absent') {
        return [pscustomobject]@{ admitted = $false; reason = "APPROVAL_CURRENT_LEGACY_IDENTITY_NOT_ABSENT (status=$([string]$CandidateIdentity.status))" }
    }
    $workspace = Get-GovernorRetirementTrackedPathText $Repo $CandidateCommit $script:GovernorRetirementWorkspaceManifestPath
    if (-not $workspace) {
        return [pscustomobject]@{ admitted = $false; reason = 'APPROVAL_CURRENT_WORKSPACE_MANIFEST_MISSING' }
    }
    $memberListed = $false
    $inMembers = $false
    foreach ($line in @(([string]$workspace.text) -split '\r?\n')) {
        if (-not $inMembers -and $line -match '^\s*members\s*=\s*\[') { $inMembers = $true }
        if ($inMembers) {
            if ($line -match '"crates/eliot-app"') { $memberListed = $true }
            if ($line -match '\]') { break }
        }
    }
    if ($memberListed) {
        return [pscustomobject]@{ admitted = $false; reason = 'APPROVAL_CURRENT_WORKSPACE_STILL_LISTS_LEGACY_PACKAGE' }
    }
    $legacyPaths = @(& git -C $Repo ls-tree -r --name-only $CandidateCommit -- 'crates/eliot-app' 2>$null)
    if ($LASTEXITCODE -ne 0) {
        return [pscustomobject]@{ admitted = $false; reason = 'APPROVAL_CURRENT_LEGACY_PACKAGE_TREE_UNREADABLE' }
    }
    if ($legacyPaths.Count -gt 0) {
        return [pscustomobject]@{ admitted = $false; reason = 'APPROVAL_CURRENT_LEGACY_PACKAGE_TREE_STILL_TRACKED' }
    }

    $sourcePairs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in @($SourceClosure.entries)) {
        $path = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $entry 'path')
        foreach ($token in @(Read-GovernorApprovalField $entry 'tokens')) {
            $tokenText = [string]$token
            [void]$sourcePairs.Add("$($path.Length):$path|$($tokenText.Length):$tokenText")
        }
    }
    foreach ($entry in @($CandidateClosure.entries)) {
        $path = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $entry 'path')
        foreach ($token in @(Read-GovernorApprovalField $entry 'tokens')) {
            $tokenText = [string]$token
            $pair = "$($path.Length):$path|$($tokenText.Length):$tokenText"
            if (-not $sourcePairs.Contains($pair)) {
                return [pscustomobject]@{ admitted = $false; reason = "APPROVAL_CANDIDATE_REFERENCE_NOT_IN_SOURCE_CLOSURE (path=$path token=$tokenText)" }
            }
        }
    }
    $proofPaths = @($ApprovedConsumers | ForEach-Object {
            ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'proof_path')
        } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
    $candidateProofContents = Get-GovernorRetirementTrackedBlobsText $Repo $CandidateCommit $proofPaths
    foreach ($consumer in @($ApprovedConsumers)) {
        $name = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'consumer')
        $proofPath = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'proof_path')
        $reference = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'live_reference')
        if ($candidateProofContents.ContainsKey($proofPath) -and
            ([string]$candidateProofContents[$proofPath].text).Contains($reference)) {
            return [pscustomobject]@{ admitted = $false; reason = "APPROVAL_CONSUMER_REFERENCE_STILL_LIVE_IN_CANDIDATE (consumer=$name proof=$proofPath)" }
        }
    }
    [pscustomobject]@{ admitted = $true; reason = $null }
}

function Test-GovernorRetirementTrustPolicyShape([object]$TrustPolicy) {
    # The owner-pinned trust policy is the ONLY thing that can admit a
    # retirement approval issuer. It is a shape gate only: the issuer decision
    # is made by Resolve-GovernorRetirementIssuer plus the executed issuer
    # readback, and no caller parameter can widen it. The policy resolved here
    # is the one held at the OWNER-PINNED ref, never one read out of candidate
    # C: `Resolve-GovernorRetirementTrustRoot` additionally binds its declared
    # byte identity (binding 1) and this contract's own trust-anchor declaration
    # (binding 2).
    if (-not $TrustPolicy) {
        throw 'retirement approval trust policy is missing'
    }
    $trustSchema = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'schema')
    if ($trustSchema -cne $script:GovernorRetirementTrustSchema -and
        $trustSchema -cne $script:GovernorRetirementTrustSchemaV3 -and
        $trustSchema -cne 'eliot-governor-retirement-approval-trust-v1') {
        throw "retirement approval trust policy schema is not supported: $trustSchema"
    }
    if ($trustSchema -ceq $script:GovernorRetirementTrustSchemaV3) {
        # v3 closes the external audit 5918050095 defects: the issuer entry
        # must pin the certificate thumbprint that signs the detached owner
        # receipt, name the exact owner-decision record the issuer read back,
        # and the policy must declare its own byte identity.
        $supportedV3 = @(
            'schema', 'release_policy', 'release_product', 'release_policy_revision',
            'owner_pinned_trust_anchor', 'owner_pinned_trust_root',
            'owner_decision_file', 'owner_decision_schema',
            'trust_policy_relpath', 'trust_policy_sha256', 'trust_policy_git_blob',
            'verifier_relpath', 'verifier_sha256', 'verifier_git_blob',
            'closure_verifier', 'closure_rule_set', 'closure_policies', 'revocation_source',
            'admitted_issuers', 'issuer_state', 'issuer_state_reason',
            'authenticode_code_signing_policy', 'content_sha256'
        )
        foreach ($property in $TrustPolicy.PSObject.Properties) {
            if ($supportedV3 -cnotcontains [string]$property.Name) {
                throw "retirement approval trust policy field is not in the closed v3 contract: $([string]$property.Name)"
            }
        }
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'owner_pinned_trust_anchor')) -cne $script:GovernorRetirementOwnerPinnedTrustAnchor) {
            throw "retirement approval trust policy declares an unsupported owner-pinned trust anchor: $(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'owner_pinned_trust_anchor'))"
        }
        if ([string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'owner_pinned_trust_root')))) {
            throw 'retirement approval trust policy declares no owner-pinned trust root reference form'
        }
        foreach ($pair in @(
                @{ field = 'trust_policy_relpath'; expected = $script:GovernorRetirementTrustPolicyPath },
                @{ field = 'verifier_relpath'; expected = $script:GovernorRetirementVerifierRelPath },
                @{ field = 'owner_decision_file'; expected = $script:GovernorRetirementOwnerDecisionFile },
                @{ field = 'owner_decision_schema'; expected = $script:GovernorRetirementOwnerDecisionSchema })) {
            if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy $pair.field)) -cne $pair.expected) {
                throw "retirement approval trust policy names an unsupported $($pair.field): $(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy $pair.field))"
            }
        }
        foreach ($field in @('trust_policy_sha256', 'verifier_sha256')) {
            if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy $field)) -cnotmatch '^[0-9a-f]{64}$') {
                throw "retirement approval trust policy is missing its exact $field identity"
            }
        }
        foreach ($field in @('trust_policy_git_blob', 'verifier_git_blob')) {
            if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy $field)) -cnotmatch '^[0-9a-f]{40,64}$') {
                throw "retirement approval trust policy is missing its exact $field identity"
            }
        }
        $v3Issuers = @(Read-GovernorApprovalField $TrustPolicy 'admitted_issuers')
        foreach ($issuer in $v3Issuers) {
            $issuerFields = @('issuer', 'role', 'authority', 'receipt_kind',
                'receipt_certificate_thumbprint', 'owner_decision_sha256',
                'owner_decision_operation_id', 'authenticode_code_signing_thumbprint')
            foreach ($property in $issuer.PSObject.Properties) {
                if ($issuerFields -cnotcontains [string]$property.Name) {
                    throw "retirement approval trust policy issuer entry has an unsupported field: $([string]$property.Name)"
                }
            }
            if (@($issuer.PSObject.Properties).Count -ne $issuerFields.Count) {
                throw 'retirement approval trust policy issuer entry is incomplete'
            }
            if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $issuer 'role')) -ceq $script:GovernorRetirementApprovalRole) {
                foreach ($field in @('issuer', 'authority', 'receipt_kind', 'receipt_certificate_thumbprint')) {
                    if ([string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $issuer $field)))) {
                        throw "retirement approval trust policy admits a $($script:GovernorRetirementApprovalRole) issuer with no $field"
                    }
                }
                if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $issuer 'receipt_kind')) -cne $script:GovernorRetirementOwnerReceiptKind) {
                    throw "retirement approval trust policy admits an unsupported owner receipt kind: $(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $issuer 'receipt_kind'))"
                }
                if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $issuer 'receipt_certificate_thumbprint')) -cnotmatch '^[0-9A-Fa-f]{40}$') {
                    throw 'retirement approval trust policy admits an issuer without an exact receipt certificate thumbprint'
                }
                if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $issuer 'owner_decision_sha256')) -cnotmatch '^[0-9a-f]{64}$') {
                    throw 'retirement approval trust policy admits an issuer without the exact owner-decision readback digest'
                }
                if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $issuer 'owner_decision_operation_id')) -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$') {
                    throw 'retirement approval trust policy admits an issuer without an exact owner-decision operation identity'
                }
            }
            elseif (-not [string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $issuer 'receipt_certificate_thumbprint')))) {
                throw "an issuer admitted for a role other than $($script:GovernorRetirementApprovalRole) declares a retirement receipt certificate thumbprint"
            }
        }
    }
    if ($trustSchema -ceq $script:GovernorRetirementTrustSchema) {
        $supportedFields = @(
            'schema', 'release_policy', 'release_product', 'release_policy_revision',
            'closure_verifier', 'closure_rule_set', 'closure_policies', 'revocation_source',
            'admitted_issuers', 'issuer_state', 'issuer_state_reason',
            'authenticode_code_signing_policy', 'content_sha256'
        )
        foreach ($property in $TrustPolicy.PSObject.Properties) {
            if ($supportedFields -cnotcontains [string]$property.Name) {
                throw "retirement approval trust policy field is not in the closed v2 contract: $([string]$property.Name)"
            }
        }
    }
    $policy = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'release_policy')
    if ($policy -cne $script:GovernorRetirementLegacyRepository -or
        (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'release_product')) -cne $script:GovernorRetirementProduct) {
        throw 'retirement approval trust policy is not bound to this repository/product release'
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'closure_verifier')) -cne $script:GovernorRetirementClosureVerifier) {
        throw "retirement approval trust policy names a closure verifier this release does not implement: $(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'closure_verifier'))"
    }
    $trustRuleSet = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'closure_rule_set')
    if ($trustSchema -ceq 'eliot-governor-retirement-approval-trust-v1') {
        if ($trustRuleSet -cne $script:GovernorRetirementClosureRuleSetV1) {
            throw "historical v1 trust policy must retain its original closure rule set: $trustRuleSet"
        }
    }
    else {
        if ($trustRuleSet -cne $script:GovernorRetirementClosureRuleSetV2) {
            throw "current trust policy must select the current closure rule set $($script:GovernorRetirementClosureRuleSetV2): $trustRuleSet"
        }
        $policyRevision = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'release_policy_revision')
        $policies = @(Read-GovernorApprovalField $TrustPolicy 'closure_policies')
        if ($policies.Count -ne $script:GovernorRetirementClosureRuleSets.Count) {
            throw 'current retirement trust policy must record exactly the v1 and v2 closure compatibility pairs'
        }
        $expectedPolicies = @(
            [pscustomobject]@{
                owner_source_rule_set = $script:GovernorRetirementClosureRuleSetV1
                release_candidate_rule_set = $script:GovernorRetirementClosureRuleSetV1
                approval_release_policy_revision = '1.0.0'
            },
            [pscustomobject]@{
                owner_source_rule_set = $script:GovernorRetirementClosureRuleSetV2
                release_candidate_rule_set = $script:GovernorRetirementClosureRuleSetV2
                approval_release_policy_revision = $policyRevision
            }
        )
        for ($i = 0; $i -lt $expectedPolicies.Count; $i++) {
            $policyFields = @('owner_source_rule_set', 'release_candidate_rule_set', 'approval_release_policy_revision')
            foreach ($property in $policies[$i].PSObject.Properties) {
                if ($policyFields -cnotcontains [string]$property.Name) {
                    throw "current retirement trust policy closure pair has an unsupported field: $([string]$property.Name)"
                }
            }
            if (@($policies[$i].PSObject.Properties).Count -ne $policyFields.Count) {
                throw "current retirement trust policy closure pair at index $i is incomplete"
            }
            foreach ($field in $policyFields) {
                if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $policies[$i] $field)) -cne
                    (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $expectedPolicies[$i] $field))) {
                    throw "current retirement trust policy has invalid v1/v2 continuity pair at index $i field $field"
                }
            }
        }
    }
    foreach ($field in @('release_policy_revision', 'content_sha256')) {
        if ([string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy $field)))) {
            throw "retirement approval trust policy is missing its $field"
        }
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'content_sha256')) -cne (Get-GovernorApprovalSha256 (Get-GovernorRetirementTrustPolicyPreimage $TrustPolicy))) {
        throw 'retirement approval trust policy canonical digest mismatch'
    }
    return $true
}

function Get-GovernorRetirementTrustPolicyPreimage([object]$TrustPolicy) {
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($field in @('schema', 'release_policy', 'release_product', 'release_policy_revision',
            'closure_verifier', 'closure_rule_set', 'revocation_source')) {
        [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine $field (Read-GovernorApprovalField $TrustPolicy $field)))
    }
    $trustSchema = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'schema')
    if ($trustSchema -ceq $script:GovernorRetirementTrustSchemaV3) {
        # v3 binds the owner-pinned root form, the declared byte identity of this
        # policy and of the closure verifier, and the exact owner-decision record
        # the admitted issuer read back. A historical v1/v2 policy keeps its
        # original immutable preimage so a previously issued approval still
        # verifies under the policy it was admitted with.
        foreach ($field in @('owner_pinned_trust_anchor', 'owner_pinned_trust_root',
                'owner_decision_file', 'owner_decision_schema',
                'trust_policy_relpath', 'trust_policy_sha256', 'trust_policy_git_blob',
                'verifier_relpath', 'verifier_sha256', 'verifier_git_blob')) {
            [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine $field (Read-GovernorApprovalField $TrustPolicy $field)))
        }
    }
    if ($trustSchema -ceq $script:GovernorRetirementTrustSchema -or $trustSchema -ceq $script:GovernorRetirementTrustSchemaV3) {
        foreach ($policy in @(Read-GovernorApprovalField $TrustPolicy 'closure_policies')) {
            [void]$lines.Add("closure_policy=$([string](Read-GovernorApprovalField $policy 'owner_source_rule_set'))|candidate=$([string](Read-GovernorApprovalField $policy 'release_candidate_rule_set'))|approval_release_policy_revision=$([string](Read-GovernorApprovalField $policy 'approval_release_policy_revision'))")
        }
    }
    foreach ($issuer in @(Read-GovernorApprovalField $TrustPolicy 'admitted_issuers')) {
        $issuerLine = "issuer=$([string](Read-GovernorApprovalField $issuer 'issuer'))|role=$([string](Read-GovernorApprovalField $issuer 'role'))|authority=$([string](Read-GovernorApprovalField $issuer 'authority'))|receipt_kind=$([string](Read-GovernorApprovalField $issuer 'receipt_kind'))|authenticode_code_signing_thumbprint=$([string](Read-GovernorApprovalField $issuer 'authenticode_code_signing_thumbprint'))"
        if ($trustSchema -ceq $script:GovernorRetirementTrustSchemaV3) {
            $issuerLine += "|receipt_certificate_thumbprint=$([string](Read-GovernorApprovalField $issuer 'receipt_certificate_thumbprint'))|owner_decision_sha256=$([string](Read-GovernorApprovalField $issuer 'owner_decision_sha256'))|owner_decision_operation_id=$([string](Read-GovernorApprovalField $issuer 'owner_decision_operation_id'))"
        }
        [void]$lines.Add($issuerLine)
    }
    return (@($lines) -join "`n")
}

function New-GovernorRetirementCandidateFreeze(
    # #18-side freeze of candidate C (issue #18 AUD-5847600066-1/2, two-time workflow step 1).
    [string]$Repo,
    [string]$SourceCommit,
    [string]$OutputPath) {
    $repoFull = [System.IO.Path]::GetFullPath($Repo)
    $candidateTree = Get-GovernorRetirementCandidateTree $Repo $SourceCommit
    $closure = Get-GovernorRetirementConsumerClosure $Repo $SourceCommit -RuleSet $script:GovernorRetirementClosureRuleSet
    if ([string]$closure.status -cne 'COMPLETE') {
        throw "retirement freeze refused: the independent consumer closure over $SourceCommit is $($closure.status), unclassified=$([string]::Join(',', @($closure.unclassified_paths)))"
    }
    $consumerProofs = @(Get-GovernorRetirementExpectedConsumerProofs $closure)
    $consumerProofCount = 0
    foreach ($proof in $consumerProofs) { $consumerProofCount += @($proof.tokens).Count }
    if ([string]::IsNullOrWhiteSpace($OutputPath) -or -not [System.IO.Path]::IsPathRooted($OutputPath)) {
        throw 'retirement freeze requires the detached freeze record path as an explicit absolute path outside the candidate tree'
    }
    $outputFull = [System.IO.Path]::GetFullPath($OutputPath)
    if ($outputFull.StartsWith("$repoFull$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase) -or [string]::Equals($outputFull, $repoFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'the detached freeze record must remain outside the candidate tree C'
    }
    $parent = Split-Path -Parent $outputFull
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "the detached freeze parent directory does not exist: $parent"
    }
    $record = [ordered]@{
        schema = [string]$script:GovernorRetirementFreezeSchema
        receipt_kind = [string]$script:GovernorRetirementFreezeKind
        candidate_commit = [string]$SourceCommit
        candidate_tree = [string]$candidateTree
        closure_rule_set = [string]$script:GovernorRetirementClosureRuleSet
        closure_verifier = 'Get-GovernorRetirementConsumerClosure'
        closure_digest_sha256 = [string]$closure.digest_sha256
        trust_policy = [string]$script:GovernorRetirementTrustPolicyPath
        consumer_count = $consumerProofCount
        approval = $null
        replay_conflict = 'EXACT_REPLAY_SAME_DECISION; CHANGED_SAME_OPERATION_CONTENT_CONFLICTS'
        self_certification = 'FORBIDDEN: this receipt never asserts identity with its own HEAD; the candidate is frozen first and the approval R(C) is issued afterwards outside the certified commit'
    }
    $json = ([pscustomobject]$record) | ConvertTo-Json -Depth 6
    $stream = [System.IO.File]::Open($outputFull, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $payload = [System.Text.Encoding]::UTF8.GetBytes($json)
        $stream.Write($payload, 0, $payload.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $roundtrip = Read-GovernorRetirementJsonFile $outputFull 'frozen retirement candidate record'
    if ([string](Read-GovernorApprovalField $roundtrip 'candidate_commit') -cne [string]$SourceCommit -or [string](Read-GovernorApprovalField $roundtrip 'closure_digest_sha256') -cne [string]$closure.digest_sha256 -or [string](Read-GovernorApprovalField $roundtrip 'schema') -cne [string]$script:GovernorRetirementFreezeSchema -or [string](Read-GovernorApprovalField $roundtrip 'receipt_kind') -cne [string]$script:GovernorRetirementFreezeKind) {
        throw 'the frozen candidate record does not read back its own schema, kind, candidate and closure identity; freeze refused'
    }
    [pscustomobject]@{
        path = $outputFull
        candidate_commit = [string]$SourceCommit
        candidate_tree = [string]$candidateTree
        closure_digest_sha256 = [string]$closure.digest_sha256
        consumer_count = $consumerProofCount
    }
}

function Resolve-GovernorRetirementIssuerCertificate([object]$AdmittedIssuer, [string]$IssuerCertificatePath) {
    # Explicit issuer-certificate resolution for retirement approval
    # issuance (issue #2968 CCV1/W2). The owner-pinned trust policy
    # admits exactly one issuer and pins its receipt certificate
    # thumbprint; the caller supplies the explicit thumbprint or the
    # absolute certificate path. Nothing is invented here: no identity
    # is derived from the certificate, no receipt is signed, and every
    # mismatch refuses before issuance runs.
    if ([string]::IsNullOrWhiteSpace($IssuerCertificatePath)) {
        throw 'retirement approval issuance requires the admitted owner release controller certificate as an explicit thumbprint or absolute certificate path'
    }
    $pinnedThumbprint = ([string](Read-GovernorApprovalField $AdmittedIssuer 'receipt_certificate_thumbprint')).Replace(' ', '').ToUpperInvariant()
    if ($pinnedThumbprint -cnotmatch '^[0-9A-F]{40}$') {
        throw 'the owner-pinned trust policy admits no exact receipt certificate thumbprint'
    }
    $certificate = $null
    if ($IssuerCertificatePath -cmatch '^[0-9a-fA-F]{40}$') {
        # An explicit 40-hex thumbprint resolves against the owner
        # host's personal stores only; there is no other search path.
        $wantedThumbprint = $IssuerCertificatePath.Replace(' ', '').ToUpperInvariant()
        foreach ($store in @('Cert:\CurrentUser\My', 'Cert:\LocalMachine\My')) {
            $found = @(Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue |
                Where-Object { ([string]$_.Thumbprint).Replace(' ', '').ToUpperInvariant() -ceq $wantedThumbprint })
            if ($found.Count -gt 0) {
                $certificate = $found[0]
                break
            }
        }
        if ($null -eq $certificate) {
            throw "no certificate with thumbprint $IssuerCertificatePath was found for the owner release controller"
        }
    }
    else {
        if (-not [System.IO.Path]::IsPathRooted($IssuerCertificatePath)) {
            throw 'the owner release controller certificate must be an explicit thumbprint or an explicit absolute path'
        }
        if (-not (Test-Path -LiteralPath $IssuerCertificatePath -PathType Leaf)) {
            throw "the owner release controller certificate file was not found: $IssuerCertificatePath"
        }
        $full = [System.IO.Path]::GetFullPath($IssuerCertificatePath)
        # No password is ever supplied: a password-protected PFX throws
        # out of the constructor, so issuance fails closed instead of
        # accepting a key it cannot read.
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($full)
    }
    $loadedThumbprint = ([string]$certificate.Thumbprint).Replace(' ', '').ToUpperInvariant()
    if ($loadedThumbprint -cne $pinnedThumbprint) {
        throw 'the supplied issuer certificate does not match the admitted receipt certificate thumbprint'
    }
    if (-not $certificate.HasPrivateKey) {
        throw 'the owner release controller certificate carries no accessible private key; issuance runs on the owner host so the issuer never signs with a transported key'
    }
    return $certificate
}

function New-GovernorRetirementApproval(
    [string]$Repo,
    [string]$SourceCommit,
    [object]$TrustRoot,
    [object]$OwnerDecisionReadback,
    [string]$OwnerReceiptPath,
    [object]$ReceiptVerification,
    [string]$OperationId,
    [string]$ConfigPolicyRevision,
    [string[]]$IssueRefs,
    [string[]]$WorkRefs,
    [string[]]$ReviewRefs,
    [object[]]$Consumers,
    [string]$ReplacementOwner,
    [string]$ProductRemovalDecision,
    [string]$OutputPath) {
    # Owner-side issuance of the detached GovernorRetirementApprovalV1 artifact
    # R(C) (issue #2968 Required design B, two-time workflow step 4). The issuer
    # observes the frozen candidate C first and issues afterwards; the approval
    # body and the signed owner receipt remain outside C.
    #
    # Every authority-bearing value - principal, operation identity, validity
    # window, refs, dispositions, conditions - now arrives ONLY through the
    # EXECUTED owner-decision readback of the owner-pinned trust root and the
    # CRYPTOGRAPHICALLY AUTHENTICATED detached owner receipt. They are no longer
    # caller-supplied strings, so the same caller cannot assert an approval
    # principal, operation or issuer identity it did not prove. Every
    # candidate-bound value (commit, tree, closure, declaration, normative pair,
    # policy revision, issuer identity) is recomputed from the repository and the
    # owner-pinned trust root - never from the commit being approved.
    #
    # Issuance refuses, fail closed, while no issuer is admitted by the
    # owner-pinned root, while the owner-decision readback was not executed, while
    # the detached owner receipt does not authenticate against the admitted issuer
    # certificate, while the independent closure is incomplete, or while the
    # constructed body does not verify through the same shape gate the builder
    # enforces; nothing unverifiable is ever emitted. The emitted artifact is
    # consumed through the builder's explicit -GovernorRetirementApproval input.
    # No new PKI is introduced: the detached CMS receipt is a detached
    # SignedData structure verified with the admitted issuer certificate's public
    # key, and the trust anchor is the owner-pinned ref whose issuer policy admits
    # exactly one issuer identity, certificate thumbprint and owner-decision
    # digest for the retirement-approval role.
    if ([string]::IsNullOrWhiteSpace($Repo) -or -not (Test-Path -LiteralPath $Repo -PathType Container)) {
        throw 'retirement approval issuance requires the repository root of candidate C'
    }
    if ([string]::IsNullOrWhiteSpace($SourceCommit) -or $SourceCommit -cnotmatch '^[0-9a-f]{40}$') {
        throw 'retirement approval issuance requires the exact 40-hex candidate commit C'
    }
    $head = (& git -C $Repo rev-parse HEAD 2>$null | Out-String).Trim()
    if ($LASTEXITCODE -ne 0 -or $head -cne $SourceCommit) {
        throw "the issuer must observe candidate C first: check out $SourceCommit (repository HEAD is '$head') so every issuance read binds C"
    }
    if (-not (Get-Command Resolve-GovernorRetirementTrustRoot -CommandType Function -ErrorAction SilentlyContinue) -or
        -not (Get-Command Get-GovernorRetirementOwnerPinnedArtifact -CommandType Function -ErrorAction SilentlyContinue)) {
        throw 'retirement approval issuance requires the owner-pinned trust root contract; dot-source scripts/lib/governor-retirement-trust-root.ps1 beside this contract before issuing'
    }
    # The trust root is re-resolved here from the owner-pinned ref only. The
    # candidate commit is never consulted for issuer policy or verifier identity.
    $root = Resolve-GovernorRetirementTrustRoot ([pscustomobject]@{ Repo = $Repo; TrustRootRef = [string]$TrustRoot.trust_root_ref })
    if (-not [bool]$root.supplied) {
        throw "retirement approval issuance is unavailable for candidate ${SourceCommit}: $([string]$root.reason)"
    }
    $issuer = Resolve-GovernorRetirementIssuer $root.trust_policy $OwnerDecisionReadback.decision $ReceiptVerification
    if ([string]$issuer.state -cne 'ISSUER_AVAILABLE') {
        throw "retirement approval issuance is unavailable for candidate ${SourceCommit}: $([string]$issuer.reason)"
    }
    if (-not $OwnerDecisionReadback -or [string]$OwnerDecisionReadback.state -cne 'SUPPLIED') {
        throw "retirement approval issuance requires an EXECUTED owner-decision readback: $(if ($OwnerDecisionReadback) { [string]$OwnerDecisionReadback.reason } else { 'none was executed' })"
    }
    $admitted = @(@(Read-GovernorApprovalField $root.trust_policy 'admitted_issuers') | Where-Object {
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'role')) -ceq $script:GovernorRetirementApprovalRole -and
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'issuer')) -ceq [string]$issuer.issuer_identity
        })
    if ($admitted.Count -ne 1) {
        throw 'the owner-pinned trust policy admits no single retirement-approval issuer entry for this issuance'
    }
    $issuerReceiptKind = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $admitted[0] 'receipt_kind')
    if ([string]::IsNullOrWhiteSpace($issuerReceiptKind)) {
        throw 'the admitted retirement-approval issuer entry names no receipt_kind'
    }
    # The readback and the receipt verification must both be non-null and
    # SUPPLIED/verified before anything is constructed.
    if (-not $ReceiptVerification -or (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ReceiptVerification 'verified')) -cne 'true') {
        throw "retirement approval issuance requires an AUTHENTICATED detached owner receipt: $(if ($ReceiptVerification) { [string]$ReceiptVerification.reason } else { 'none was verified' })"
    }
    if ([string]$ReceiptVerification.signature_status -cne 'VALID') {
        throw "retirement approval issuance requires a VALID detached owner receipt signature: status=$([string]$ReceiptVerification.signature_status)"
    }
    if ([string]$ReceiptVerification.certificate_chain_trusted -cne 'true') {
        throw 'retirement approval issuance requires a trusted admitted issuer certificate chain'
    }
    $decision = $OwnerDecisionReadback.decision
    $ApproverPrincipal = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'approver_principal')
    $IssuerReadbackRef = [string]$root.trust_root_ref
    $IdempotencyNamespace = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'idempotency_namespace')
    $IssuedAtUtc = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'issued_at_utc')
    $ExpiresAtUtc = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'expires_at_utc')
    $ReopenCondition = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'reopen_condition')
    $RollbackCondition = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'rollback_condition')
    $IdempotencyRetentionHours = '72'
    # The readback already proved that this decision attests exactly this
    # candidate, operation, issuer, policy revision and receipt digest. Re-check
    # the operation and candidate here so issuance cannot diverge from the
    # executed readback even if the caller's arguments drift.
    if ([string]$OwnerDecisionReadback.decision.operation_id -cne $OperationId) {
        throw "retirement approval issuance operation identity differs from the executed owner-decision readback (requested='$OperationId' readback='$([string]$OwnerDecisionReadback.decision.operation_id)')"
    }
    if (([string]$OwnerDecisionReadback.decision.candidate_commit).ToLowerInvariant() -cne $SourceCommit.ToLowerInvariant()) {
        throw "retirement approval issuance candidate commit differs from the executed owner-decision readback (requested='$SourceCommit' readback='$([string]$OwnerDecisionReadback.decision.candidate_commit)')"
    }
    $closureRuleSet = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $root.trust_policy 'closure_rule_set')
    $releasePolicyRevision = Get-GovernorRetirementClosurePolicyRevision $root.trust_policy $closureRuleSet
    $closure = Get-GovernorRetirementConsumerClosure $Repo $SourceCommit -RuleSet $closureRuleSet
    if ([string]$closure.status -cne 'COMPLETE') {
        $blocking = @(@($closure.unclassified_path_families) + @($closure.unclassified_paths) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        throw "retirement approval issuance refuses an incomplete independent closure: $([string]::Join(', ', $blocking))"
    }
    # The owner-decision readback attests this exact closure digest: the owner
    # adopted the closure result for this candidate before issuing.
    $adoptedClosure = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'closure_digest')).ToLowerInvariant()
    $recomputedClosure = ([string]$closure.digest_sha256).ToLowerInvariant()
    if ($adoptedClosure -cne $recomputedClosure) {
        throw "retirement approval issuance refuses a candidate whose independent closure differs from the closure the owner adopted (adopted=$adoptedClosure recomputed=$recomputedClosure)"
    }
    $attestedPolicyRevision = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $decision 'release_policy_revision')
    if ($attestedPolicyRevision -cne $releasePolicyRevision) {
        throw "retirement approval issuance refuses a policy revision the owner decision did not attest (attested=$attestedPolicyRevision current=$releasePolicyRevision)"
    }
    $candidateTree = Get-GovernorRetirementCandidateTree $Repo $SourceCommit
    $normativePair = Get-GovernorRetirementNormativePairRevision $Repo $SourceCommit
    $declarationBlob = Get-GovernorRetirementTrackedPathDigest $Repo $SourceCommit $script:GovernorRetirementDispositionInventoryPath
    if (-not $declarationBlob) {
        throw "the closure declaration inventory is not tracked at candidate ${SourceCommit}: $($script:GovernorRetirementDispositionInventoryPath)"
    }
    $repoFull = (Resolve-Path -LiteralPath $Repo).Path.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    $approvalOutputFull = $null
    if ([string]::IsNullOrWhiteSpace($OwnerReceiptPath) -or -not [System.IO.Path]::IsPathRooted($OwnerReceiptPath)) {
        throw 'retirement approval issuance requires the owner receipt as an explicit absolute path outside the candidate tree'
    }
    $receiptFull = [System.IO.Path]::GetFullPath($OwnerReceiptPath)
    if ($receiptFull.StartsWith("$repoFull$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($receiptFull, $repoFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'the owner receipt must remain outside the candidate tree C'
    }
    if ([string]$IdempotencyRetentionHours -notmatch '^[1-9][0-9]*$') {
        throw "retirement approval issuance requires a positive idempotency retention in hours: $IdempotencyRetentionHours"
    }
    $issued = Test-GovernorApprovalUtcInstant $IssuedAtUtc 'issued_at_utc' 'retirement approval issuance'
    $expires = Test-GovernorApprovalUtcInstant $ExpiresAtUtc 'expires_at_utc' 'retirement approval issuance'
    if ($expires -le $issued) {
        throw 'retirement approval issuance requires expires_at_utc after issued_at_utc'
    }
    foreach ($refSet in @(@{ name = 'IssueRefs'; value = $IssueRefs }, @{ name = 'WorkRefs'; value = $WorkRefs }, @{ name = 'ReviewRefs'; value = $ReviewRefs })) {
        if (@($refSet.value).Count -eq 0) {
            throw "retirement approval issuance requires at least one owner -$($refSet.name) identity"
        }
        foreach ($item in @($refSet.value)) {
            if ([string]::IsNullOrWhiteSpace([string]$item)) {
                throw "retirement approval issuance requires nonblank -$($refSet.name) identities"
            }
        }
    }
    if ([string]::IsNullOrWhiteSpace($ReplacementOwner) -and [string]::IsNullOrWhiteSpace($ProductRemovalDecision)) {
        throw 'retirement approval issuance requires a replacement owner or an explicit product-removal decision'
    }
    $consumerEntries = @($Consumers)
    if ($consumerEntries.Count -eq 0) {
        throw 'retirement approval issuance requires at least one consumer disposition'
    }
    $seenConsumers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    $normalizedConsumers = @()
    foreach ($consumer in $consumerEntries) {
        $name = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'consumer')
        $proofPath = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'proof_path')
        $reference = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'live_reference')
        $disposition = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'disposition')
        if ([string]::IsNullOrWhiteSpace($name) -or [string]::IsNullOrWhiteSpace($proofPath) -or [string]::IsNullOrWhiteSpace($reference)) {
            throw "retirement approval issuance requires a complete consumer entry (consumer/proof_path/live_reference): $name"
        }
        if (-not $seenConsumers.Add("$name|$proofPath|$reference")) {
            throw "retirement approval issuance refuses a duplicated consumer entry: $name"
        }
        if ($script:GovernorRetirementDispositionAdmitted -cnotcontains $disposition) {
            throw "retirement approval issuance refuses a non-admitted consumer disposition (consumer=$name disposition=$disposition)"
        }
        $consumerReplacement = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'replacement_owner')
        $consumerRemoval = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'removal_decision')
        $consumerExpiry = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'expiry')
        if ($disposition -ceq 'migrated') {
            $declaredContract = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'product_contract')
            if ([string]::IsNullOrWhiteSpace($consumerReplacement) -or
                (-not [string]::IsNullOrWhiteSpace($declaredContract) -and $declaredContract -cne $script:GovernorRetirementProductContract)) {
                throw "retirement approval issuance requires a replacement owner bound to $($script:GovernorRetirementProductContract) for a migrated consumer: $name"
            }
            $consumerProductContract = $script:GovernorRetirementProductContract
        }
        else {
            if ([string]::IsNullOrWhiteSpace($consumerRemoval)) {
                throw "retirement approval issuance requires a removal decision for a non-migrated consumer: $name"
            }
            $consumerProductContract = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $consumer 'product_contract')
        }
        $normalizedConsumers += @([ordered]@{
                consumer = $name
                proof_path = $proofPath
                live_reference = $reference
                disposition = $disposition
                replacement_owner = $consumerReplacement
                product_contract = $consumerProductContract
                removal_decision = $consumerRemoval
                expiry = $consumerExpiry
            })
    }
    $approval = [ordered]@{
        schema = $script:GovernorRetirementApprovalSchema
        domain = $script:GovernorRetirementApprovalDomain
        repository = $script:GovernorRetirementLegacyRepository
        product = $script:GovernorRetirementProduct
        product_contract = $script:GovernorRetirementProductContract
        normative_pair_revision = [string]$normativePair.revision
        normative_pair_sha256 = [string]$normativePair.sha256
        config_policy_revision = $ConfigPolicyRevision
        release_policy_revision = $releasePolicyRevision
        candidate_commit = $SourceCommit
        candidate_tree = $candidateTree
        legacy_package = $script:GovernorRetirementPackage
        legacy_binary = $script:GovernorRetirementBinary
        legacy_release_role = $script:GovernorRetirementReleaseRole
        legacy_plugin_path = $script:GovernorRetirementPlugin
        closure_rule_set = [string]$closure.rule_set
        closure_verifier = [string]$closure.verifier
        closure_digest = [string]$closure.digest_sha256
        closure_count = [int]$closure.classified_count
        closure_declaration_path = $script:GovernorRetirementDispositionInventoryPath
        closure_declaration_sha256 = [string]$declarationBlob
        replacement_owner = $ReplacementOwner
        replacement_product_contract = if ([string]::IsNullOrWhiteSpace($ReplacementOwner)) { '' } else { $script:GovernorRetirementProductContract }
        product_removal_decision = $ProductRemovalDecision
        issue_refs = @($IssueRefs | ForEach-Object { [string]$_ })
        work_refs = @($WorkRefs | ForEach-Object { [string]$_ })
        review_refs = @($ReviewRefs | ForEach-Object { [string]$_ })
        operation_id = $OperationId
        idempotency_namespace = $IdempotencyNamespace
        canonical_request_hash = $null
        idempotency_retention_hours = [string]$IdempotencyRetentionHours
        approver_principal = $ApproverPrincipal
        approver_role = $script:GovernorRetirementApprovalRole
        issuer = [string]$issuer.issuer_identity
        issuer_receipt_kind = $issuerReceiptKind
        issuer_evidence_sha256 = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ReceiptVerification 'receipt_sha256')).ToLowerInvariant()
        issuer_readback_ref = $IssuerReadbackRef
        issuer_readback_sha256 = [string]$OwnerDecisionReadback.sha256
        issuer_readback_blob = [string]$OwnerDecisionReadback.blob
        issuer_certificate_thumbprint = [string]$ReceiptVerification.signer_thumbprint
        issuer_signing_time_utc = [string]$ReceiptVerification.signing_time_utc
        issued_at_utc = $IssuedAtUtc
        expires_at_utc = $ExpiresAtUtc
        revocation_state = 'not-revoked'
        reopen_condition = $ReopenCondition
        rollback_condition = $RollbackCondition
        proof_ceiling = $script:GovernorRetirementProofCeiling
        consumers = @($normalizedConsumers)
        content_sha256 = $null
    }
    $body = [pscustomobject]$approval
    $requestHash = Get-GovernorApprovalRequestDigest $body
    $body.canonical_request_hash = $requestHash
    $contentDigest = Get-GovernorApprovalContentDigest $body
    $body.content_sha256 = $contentDigest
    $closure | Add-Member -MemberType NoteProperty -Name declaration_path -Value $script:GovernorRetirementDispositionInventoryPath
    $closure | Add-Member -MemberType NoteProperty -Name declaration_blob -Value $declarationBlob
    $shape = Test-GovernorRetirementApprovalShape $body $SourceCommit $candidateTree $closure $Repo $releasePolicyRevision $OwnerDecisionReadback $ReceiptVerification
    if (-not [bool]$shape.admitted) {
        throw "the issuer refuses to emit an unverifiable approval: $([string]$shape.reason)"
    }
    if ([string]::IsNullOrWhiteSpace($OutputPath) -or -not [System.IO.Path]::IsPathRooted($OutputPath)) {
        throw 'retirement approval issuance requires the detached artifact path as an explicit absolute path outside the candidate tree'
    }
    $outputFull = [System.IO.Path]::GetFullPath($OutputPath)
    if ($outputFull.StartsWith("$repoFull$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($outputFull, $repoFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'the detached approval artifact must remain outside the candidate tree C'
    }
    if ([string]::Equals($outputFull, $receiptFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'the detached approval artifact and the signed owner receipt must be separate files'
    }
    $parent = Split-Path -Parent $outputFull
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -LiteralPath $parent -PathType Container)) {
        throw "the detached approval parent directory does not exist: $parent"
    }
    $json = $body | ConvertTo-Json -Depth 6
    $stream = [System.IO.File]::Open($outputFull, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    try {
        $payload = [System.Text.Encoding]::UTF8.GetBytes($json)
        $stream.Write($payload, 0, $payload.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $roundtrip = Read-GovernorRetirementJsonFile $outputFull 'issued detached Governor retirement approval'
    if ((Get-GovernorApprovalContentDigest $roundtrip) -cne $contentDigest) {
        throw 'the issued detached approval does not read back its own content digest; issuance refused'
    }
    # The artifact as written must verify through the same shape gate with the
    # SAME executed issuer readback and the SAME authenticated receipt: a
    # re-read, re-decoded and re-verified body, never the in-memory one.
    $closure | Add-Member -MemberType NoteProperty -Name declaration_path -Value $script:GovernorRetirementDispositionInventoryPath -Force
    $closure | Add-Member -MemberType NoteProperty -Name declaration_blob -Value $declarationBlob -Force
    $reverified = Test-GovernorRetirementApprovalShape $roundtrip $SourceCommit $candidateTree $closure $Repo $releasePolicyRevision $OwnerDecisionReadback $ReceiptVerification
    if (-not [bool]$reverified.admitted) {
        throw "the issued detached approval does not re-verify after its round trip: $([string]$reverified.reason)"
    }
    [pscustomobject]@{
        path = $outputFull
        sha256 = Get-GovernorApprovalSha256 $json
        content_sha256 = $contentDigest
        canonical_request_hash = $requestHash
        operation_id = $OperationId
        candidate_commit = $SourceCommit
        candidate_tree = $candidateTree
        closure_digest_sha256 = [string]$closure.digest_sha256
        closure_count = [int]$closure.classified_count
        issuer = [string]$issuer.issuer_identity
        issuer_receipt_sha256 = [string]$ReceiptVerification.receipt_sha256
        issuer_certificate_thumbprint = [string]$ReceiptVerification.signer_thumbprint
        issuer_readback_ref = [string]$IssuerReadbackRef
        issuer_readback_sha256 = [string]$OwnerDecisionReadback.sha256
        issued_at_utc = $IssuedAtUtc
        expires_at_utc = $ExpiresAtUtc
    }
}

function Resolve-GovernorRetirementIssuanceInputs(
    [string]$Repo,
    [string]$SourceCommit,
    [string]$TrustRootRef,
    [string]$OperationId,
    [string]$OwnerReceiptPath) {
    # The real production issuer entry point for issue #2968 (external audit
    # 5918050095 defect 2). Given the OWNER-PINNED trust root reference, the
    # approval operation identity and the detached signed owner receipt, this
    # performs the two-time sequence in the correct order:
    #
    #     resolve the owner-pinned root (never from C)
    #     -> execute issuer_readback_ref over the exact operation and candidate
    #     -> authenticate the detached owner receipt against the admitted issuer
    #     -> hand the verified evidence to New-GovernorRetirementApproval
    #
    # It returns the resolved trust root, the executed owner-decision readback
    # and the authenticated receipt. When no production issuer is admitted by
    # the owner-pinned root - the current, honest state - it refuses with
    # ISSUER_UNAVAILABLE and invents nothing. No issuer identity, certificate,
    # signature or receipt is ever fabricated to make the path reachable.
    if ([string]::IsNullOrWhiteSpace($Repo) -or -not (Test-Path -LiteralPath $Repo -PathType Container)) {
        throw 'retirement issuance requires the repository root of candidate C'
    }
    $trustRoot = Resolve-GovernorRetirementTrustRoot ([pscustomobject]@{ Repo = $Repo; TrustRootRef = $TrustRootRef })
    if (-not [bool]$trustRoot.supplied) {
        # No owner-pinned root means no admitted issuer exists at all; there is
        # nothing to probe and nothing to read back, so the seam is reported
        # unavailable with the resolver's own reason.
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = [string]$trustRoot.reason
            trust_root = $trustRoot
            issuer_readback = $null
            receipt_verification = $null
            issuer = $null
        }
    }
    $readback = Resolve-GovernorRetirementOwnerDecisionReadback $Repo $SourceCommit $trustRoot $OperationId $OwnerReceiptPath
    if ([string]$readback.state -cne 'SUPPLIED') {
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = [string]$readback.reason
            trust_root = $trustRoot
            issuer_readback = $readback
            receipt_verification = $null
            issuer = (Resolve-GovernorRetirementIssuer $trustRoot.trust_policy $null $null)
        }
    }
    $receiptBytes = Read-GovernorRetirementDetachedBytes $OwnerReceiptPath ([string]$readback.receipt_sha256) 'detached owner retirement receipt'
    $verification = Test-GovernorRetirementOwnerReceiptSignature `
        ([byte[]]$receiptBytes.bytes) $readback $trustRoot.trust_policy $null
    $issuer = Resolve-GovernorRetirementIssuer $trustRoot.trust_policy $readback.decision $verification
    if ([string]$issuer.state -cne 'ISSUER_AVAILABLE') {
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = [string]$issuer.reason
            trust_root = $trustRoot
            issuer_readback = $readback
            receipt_verification = $verification
            issuer = $issuer
        }
    }
    [pscustomobject]@{
        state = 'ISSUER_AVAILABLE'
        reason = $null
        trust_root = $trustRoot
        issuer_readback = $readback
        receipt_verification = $verification
        issuer = $issuer
    }
}

function Resolve-GovernorRetirementApprovalBinding(
    [string]$Repo,
    [string]$SourceCommit,
    [object]$Approval,
    [object]$TrustPolicy,
    [object]$Issuer,
    [object]$IssuerReadback = $null,
    [object]$ReceiptVerification = $null) {
    # R(C) remains the original owner-issued approval for historical source C.
    # D is the release candidate. Select the closure version recorded in R(C),
    # recompute C under that exact historical/current rule, and select the
    # trust-policy pair that independently binds D under the same rule. No
    # field in R(C) is rewritten or re-digested to make it name D.
    $candidateTree = Get-GovernorRetirementCandidateTree $Repo $SourceCommit
    $normativePair = Get-GovernorRetirementNormativePairRevision $Repo $SourceCommit
    $candidateIdentity = Get-GovernorRetirementPinnedLegacyIdentity $Repo $SourceCommit
    $approvedClosureRuleSet = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'closure_rule_set')
    $selectedClosureRuleSet = if ($script:GovernorRetirementClosureRuleSets -ccontains $approvedClosureRuleSet) {
        $approvedClosureRuleSet
    }
    else {
        $script:GovernorRetirementClosureRuleSet
    }
    $ownerSourceCommit = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'candidate_commit')).ToLowerInvariant()
    # v2 role/inventory declarations are owned by the approved source C. Keep
    # using those exact declarations when scanning D after the facade subtree
    # (and its Rust inventory) has been deleted. D's token denominator remains
    # independently scanned from D itself.
    $candidateClosure = Get-GovernorRetirementConsumerClosure $Repo $SourceCommit -AllowMissingFamilies -RuleSet $selectedClosureRuleSet -ReferenceDeclarationCommit $ownerSourceCommit
    $ownerSourceTree = $null
    $ownerIdentity = [pscustomobject]@{ status = 'absent'; reason = 'owner approval source commit is missing or malformed'; workspace_blob = $null; facade_blob = $null; plugin_blob = $null }
    $ownerClosure = $null
    $ownerDeclarationBlob = $null
    $ownerSourceError = $null
    if ($ownerSourceCommit -cmatch '^[0-9a-f]{40}$') {
        try {
            $ownerSourceTree = Get-GovernorRetirementCandidateTree $Repo $ownerSourceCommit
            $ownerIdentity = Get-GovernorRetirementPinnedLegacyIdentity $Repo $ownerSourceCommit
            $ownerClosure = Get-GovernorRetirementConsumerClosure $Repo $ownerSourceCommit -RuleSet $selectedClosureRuleSet
            $ownerDeclarationBlob = Get-GovernorRetirementTrackedPathDigest $Repo $ownerSourceCommit $script:GovernorRetirementDispositionInventoryPath
            $ownerClosure | Add-Member -MemberType NoteProperty -Name declaration_path -Value $script:GovernorRetirementDispositionInventoryPath
            $ownerClosure | Add-Member -MemberType NoteProperty -Name declaration_blob -Value $ownerDeclarationBlob
        }
        catch {
            $ownerSourceError = [string]$_.Exception.Message
        }
    }
    # The revision lives in the pinned policy BODY (path/blob/sha256/bytes/body
    # wrapper); reading the wrapper would bind the empty string instead of the
    # admitted revision the plan reports.
    $releasePolicyRevision = Get-GovernorRetirementClosurePolicyRevision $TrustPolicy.body $selectedClosureRuleSet
    $shape = $null
    if ($ownerClosure -and $ownerSourceTree) {
        $shape = Test-GovernorRetirementApprovalShape $Approval $ownerSourceCommit $ownerSourceTree $ownerClosure $Repo $releasePolicyRevision $IssuerReadback $ReceiptVerification
    }
    $closureForDiagnostics = if ($ownerClosure) { $ownerClosure } else { $candidateClosure }
    $rejected = {
        param([string]$NonAdmission, [string]$Reason, [string]$State = 'REJECTED')
        [pscustomobject]@{
            kind = 'RetirementCandidate'
            state = $State
            reason = $Reason
            non_admission_reason = $NonAdmission
            candidate_commit = $SourceCommit
            candidate_tree = $candidateTree
            owner_candidate_commit = $ownerSourceCommit
            owner_candidate_tree = [string]$ownerSourceTree
            candidate_closure_digest_sha256 = [string]$candidateClosure.digest_sha256
            candidate_closure_count = [int]$candidateClosure.classified_count
            candidate_closure_status = [string]$candidateClosure.status
            closure_rule_set = [string]$closureForDiagnostics.rule_set
            closure_verifier = [string]$closureForDiagnostics.verifier
            closure_digest_sha256 = if ($ownerClosure) { [string]$ownerClosure.digest_sha256 } else { $null }
            closure_count = if ($ownerClosure) { [int]$ownerClosure.classified_count } else { 0 }
            closure_status = [string]$closureForDiagnostics.status
            closure_declaration_path = $script:GovernorRetirementDispositionInventoryPath
            closure_declaration_blob = $ownerDeclarationBlob
            legacy_identity = [string]$candidateIdentity.status
            legacy_package_manifest_blob = [string]$candidateIdentity.workspace_blob
            legacy_facade_manifest_blob = [string]$candidateIdentity.facade_blob
            legacy_plugin_manifest_blob = [string]$candidateIdentity.plugin_blob
            normative_pair_revision = [string]$normativePair.revision
            release_policy_revision = $releasePolicyRevision
            content_sha256 = $null
            canonical_request_hash = $null
            operation_id = $null
            live_references = @()
            consumers = @()
            proof_ceiling = $script:GovernorRetirementProofCeiling
        }
    }
    if ($ownerSourceCommit -cnotmatch '^[0-9a-f]{40}$') {
        return (& $rejected 'APPROVAL_OWNER_SOURCE_IDENTITY_MISSING' 'the detached approval does not name an exact historical 40-hex candidate commit C')
    }
    if ($ownerSourceError) {
        return (& $rejected 'APPROVAL_OWNER_SOURCE_UNAVAILABLE' "the approval's historical source C cannot be independently scanned: $ownerSourceError")
    }
    if (-not [bool]$shape.admitted) {
        return (& $rejected 'APPROVAL_SHAPE_REJECTED' ([string]$shape.reason))
    }
    if ([string]$ownerIdentity.status -cne 'present') {
        return (& $rejected 'APPROVAL_OWNER_SOURCE_MISMATCH' "the owner approval's historical source C does not bind the legacy package/target/plugin identity ($([string]$ownerIdentity.reason))")
    }
    if ([string]$ownerClosure.status -cne 'COMPLETE') {
        return (& $rejected 'APPROVAL_CLOSURE_INCOMPLETE' "the independent historical consumer closure over C is incomplete: $([string]::Join(', ', @($ownerClosure.unclassified_path_families + @($ownerClosure.unclassified_paths) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })))")
    }
    if ([string]$candidateClosure.status -cne 'COMPLETE') {
        return (& $rejected 'APPROVAL_CANDIDATE_CLOSURE_INCOMPLETE' "the independent release-candidate closure over D is incomplete: $([string]::Join(', ', @($candidateClosure.unclassified_path_families + @($candidateClosure.unclassified_paths) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })))")
    }
    if ([string]$candidateClosure.rule_set -cne [string]$ownerClosure.rule_set) {
        return (& $rejected 'APPROVAL_CLOSURE_RULE_CONTINUITY_REJECTED' "R(C) source rule $([string]$ownerClosure.rule_set) differs from release candidate D rule $([string]$candidateClosure.rule_set)")
    }
    $transition = Test-GovernorRetirementCandidateTransition `
        $Repo `
        $SourceCommit `
        $ownerSourceCommit `
        $candidateIdentity `
        $ownerClosure `
        $candidateClosure `
        @($shape.consumers) `
        ([string]$TrustPolicy.commit)
    if (-not [bool]$transition.admitted) {
        return (& $rejected 'APPROVAL_CANDIDATE_TRANSITION_REJECTED' ([string]$transition.reason))
    }
    if ([string]$Issuer.state -cne 'ISSUER_AVAILABLE') {
        return (& $rejected 'APPROVAL_ISSUER_UNAVAILABLE' "the detached approval R(C) cannot be admitted for release candidate D=${SourceCommit}: $([string]$Issuer.reason)" 'ISSUER_UNAVAILABLE')
    }
    $boundIssuer = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer')
    if ($boundIssuer -cne [string]$Issuer.issuer_identity) {
        return (& $rejected 'APPROVAL_TRUST_UNAVAILABLE' "the detached approval names issuer '$boundIssuer' but the root-owned trust policy admits only '$([string]$Issuer.issuer_identity)'")
    }
    [pscustomobject]@{
        kind = 'Retired'
        state = 'ADMITTED'
        reason = $null
        non_admission_reason = $null
        candidate_commit = $SourceCommit
        candidate_tree = $candidateTree
        owner_candidate_commit = $ownerSourceCommit
        owner_candidate_tree = [string]$ownerSourceTree
        candidate_closure_digest_sha256 = [string]$candidateClosure.digest_sha256
        candidate_closure_count = [int]$candidateClosure.classified_count
        candidate_closure_status = [string]$candidateClosure.status
        closure_rule_set = [string]$ownerClosure.rule_set
        closure_verifier = [string]$ownerClosure.verifier
        closure_digest_sha256 = [string]$ownerClosure.digest_sha256
        closure_count = [int]$ownerClosure.classified_count
        closure_status = [string]$ownerClosure.status
        closure_declaration_path = $script:GovernorRetirementDispositionInventoryPath
        closure_declaration_blob = $ownerDeclarationBlob
        legacy_identity = [string]$candidateIdentity.status
        legacy_package_manifest_blob = [string]$ownerIdentity.workspace_blob
        legacy_facade_manifest_blob = [string]$ownerIdentity.facade_blob
        legacy_plugin_manifest_blob = [string]$ownerIdentity.plugin_blob
        normative_pair_revision = [string]$normativePair.revision
        release_policy_revision = $releasePolicyRevision
        issuer = $boundIssuer
        issuer_state = [string]$Issuer.state
        issuer_policy_digest = [string]$Issuer.policy_digest
        issuer_evidence_sha256 = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_evidence_sha256')).ToLowerInvariant()
        issuer_receipt_kind = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_receipt_kind')
        issuer_readback_ref = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_readback_ref')
        issuer_readback_sha256 = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_readback_sha256')
        issuer_readback_blob = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_readback_blob')
        issuer_certificate_thumbprint = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_certificate_thumbprint')
        issuer_signing_time_utc = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'issuer_signing_time_utc')
        issuer_receipt_signature_status = if ($ReceiptVerification) { [string]$ReceiptVerification.signature_status } else { 'UNVERIFIED' }
        issuer_receipt_chain_trusted = if ($ReceiptVerification) { [string]$ReceiptVerification.certificate_chain_trusted } else { 'false' }
        issuer_receipt_revocation = if ($ReceiptVerification) { [string]$ReceiptVerification.revocation } else { 'NOT_CHECKED' }
        approver_principal = [string]$shape.approver_principal
        trust_root_ref = [string]$TrustPolicy.ref
        trust_root_commit = [string]$TrustPolicy.commit
        trust_policy_sha256 = [string]$TrustPolicy.trust_policy_sha256
        verifier_sha256 = [string]$TrustPolicy.verifier_sha256
        verifier_blob = [string]$TrustPolicy.verifier_blob
        owner_receipt_file_sha256 = if ($ReceiptVerification) { [string]$ReceiptVerification.receipt_sha256 } else { '' }
        operation_id = [string]$shape.operation_id
        canonical_request_hash = [string]$shape.canonical_request_hash
        content_sha256 = [string]$shape.content_sha256
        consumers = @($shape.consumers)
        live_references = @(@($shape.consumers) | ForEach-Object { ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'live_reference') })
        proof_ceiling = $script:GovernorRetirementProofCeiling
    }
}

function New-GovernorRetirementApprovalReference([object]$Binding, [string]$ApprovalFileSha256, [string]$TrustFileSha256) {
    # The single approval identity carried by the plan, the staged payload
    # manifest, RELEASE.json, SHA256SUMS.json and the signed finalization
    # evidence. The original v1 owner approval remains bound to C; this release
    # reference separately binds the independently checked D candidate.
    [ordered]@{
        schema = $script:GovernorRetirementApprovalSchema
        state = [string]$Binding.state
        content_sha256 = [string]$Binding.content_sha256
        canonical_request_hash = [string]$Binding.canonical_request_hash
        operation_id = [string]$Binding.operation_id
        candidate_commit = [string]$Binding.candidate_commit
        candidate_tree = [string]$Binding.candidate_tree
        owner_candidate_commit = [string]$Binding.owner_candidate_commit
        owner_candidate_tree = [string]$Binding.owner_candidate_tree
        candidate_closure_digest_sha256 = [string]$Binding.candidate_closure_digest_sha256
        candidate_closure_count = [int]$Binding.candidate_closure_count
        repository = $script:GovernorRetirementLegacyRepository
        product = $script:GovernorRetirementProduct
        product_contract = $script:GovernorRetirementProductContract
        release_policy_revision = [string]$Binding.release_policy_revision
        normative_pair_revision = [string]$Binding.normative_pair_revision
        closure_rule_set = [string]$Binding.closure_rule_set
        closure_verifier = [string]$Binding.closure_verifier
        closure_digest_sha256 = [string]$Binding.closure_digest_sha256
        closure_count = [int]$Binding.closure_count
        closure_declaration_path = [string]$Binding.closure_declaration_path
        closure_declaration_blob = [string]$Binding.closure_declaration_blob
        legacy_package = $script:GovernorRetirementPackage
        legacy_binary = $script:GovernorRetirementBinary
        legacy_release_role = $script:GovernorRetirementReleaseRole
        legacy_package_manifest_blob = [string]$Binding.legacy_package_manifest_blob
        legacy_facade_manifest_blob = [string]$Binding.legacy_facade_manifest_blob
        legacy_plugin_manifest_blob = [string]$Binding.legacy_plugin_manifest_blob
        issuer = [string]$Binding.issuer
        issuer_state = [string]$Binding.issuer_state
        issuer_receipt_kind = [string]$Binding.issuer_receipt_kind
        issuer_evidence_sha256 = [string]$Binding.issuer_evidence_sha256
        issuer_readback_ref = [string]$Binding.issuer_readback_ref
        issuer_readback_sha256 = [string]$Binding.issuer_readback_sha256
        issuer_readback_blob = [string]$Binding.issuer_readback_blob
        issuer_certificate_thumbprint = [string]$Binding.issuer_certificate_thumbprint
        issuer_signing_time_utc = [string]$Binding.issuer_signing_time_utc
        issuer_receipt_signature_status = [string]$Binding.issuer_receipt_signature_status
        issuer_receipt_chain_trusted = [string]$Binding.issuer_receipt_chain_trusted
        issuer_receipt_revocation = [string]$Binding.issuer_receipt_revocation
        approver_principal = [string]$Binding.approver_principal
        # The owner-pinned trust root identity travels with the approval
        # identity, so plan, staged manifest, RELEASE.json, checksums, the
        # signed finalization evidence and every readback all name the ONE
        # owner-pinned ref/commit whose policy and verifier constrained R(C).
        trust_root_ref = [string]$Binding.trust_root_ref
        trust_root_commit = [string]$Binding.trust_root_commit
        trust_policy_sha256 = [string]$Binding.trust_policy_sha256
        verifier_sha256 = [string]$Binding.verifier_sha256
        verifier_blob = [string]$Binding.verifier_blob
        approval_file = $script:GovernorRetirementBundleApprovalFile
        approval_file_sha256 = $ApprovalFileSha256
        trust_file = $script:GovernorRetirementBundleTrustFile
        trust_file_sha256 = $TrustFileSha256
        owner_receipt_file = $script:GovernorRetirementBundleReceiptFile
        owner_receipt_file_sha256 = [string]$Binding.owner_receipt_file_sha256
        proof_ceiling = $script:GovernorRetirementProofCeiling
    }
}

function New-GovernorRetirementReplayRecord([object]$Reference, [object]$ApprovalBody, [object]$ExistingReplayRecord = $null) {
    # Exact owner-decision replay under one operation (issue #2968 step 11).
    # The unchanged v1 request hash covers historical source C and its approved
    # denominator, dispositions, target identity, policy revisions and
    # rollback/reopen conditions. It excludes owner evidence as before. The
    # later release candidate D is separately recorded in the release binding;
    # moving D changes that binding without re-issuing or re-digesting R(C).
    # Exact I5.27 semantics: the same (idempotency_namespace, operation_id)
    # with the same request hash replays the same receipt; the same key with a
    # different request hash is APPROVAL_IDENTITY_CONFLICT and performs no
    # transition. Issuance stays fail-closed until the root owner admits
    # exactly one issuer identity in the trust policy; the existing
    # Authenticode/RFC3161 finalizer is a cryptographic primitive only and
    # confers no semantic retirement authority. No second signing, MAC,
    # digest or nonce scheme is defined here.
    $namespace = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ApprovalBody 'idempotency_namespace'))
    $operation = [string]$Reference.operation_id
    $requestHash = Get-GovernorApprovalRequestDigest $ApprovalBody
    if ($null -ne $ExistingReplayRecord) {
        $existingNamespace = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ExistingReplayRecord 'idempotency_namespace'))
        $existingOperation = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ExistingReplayRecord 'operation_id'))
        $existingHash = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ExistingReplayRecord 'canonical_request_hash')).ToLowerInvariant()
        if ($existingNamespace -ceq $namespace -and $existingOperation -ceq $operation) {
            if ($existingHash -cne $requestHash.ToLowerInvariant()) {
                throw "APPROVAL_IDENTITY_CONFLICT (idempotency key $namespace/$operation is reused with a different canonical request hash; no transition is performed)"
            }
            if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ExistingReplayRecord 'release_candidate_commit')) -ceq [string]$Reference.candidate_commit -and
                (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ExistingReplayRecord 'release_candidate_tree')) -ceq [string]$Reference.candidate_tree) {
                return $ExistingReplayRecord
            }
        }
    }
    [ordered]@{
        operation_id = $operation
        idempotency_namespace = $namespace
        idempotency_retention_hours = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ApprovalBody 'idempotency_retention_hours'))
        canonical_request_hash = $requestHash
        approved_owner_candidate_commit = [string]$Reference.owner_candidate_commit
        approved_owner_candidate_tree = [string]$Reference.owner_candidate_tree
        release_candidate_commit = [string]$Reference.candidate_commit
        release_candidate_tree = [string]$Reference.candidate_tree
        approved_denominator = [int]$Reference.closure_count
        release_candidate_denominator = [int]$Reference.candidate_closure_count
        approved_content_sha256 = [string]$Reference.content_sha256
        replay_semantics = 'EXACT_REPLAY_SAME_OWNER_DECISION; RELEASE_CANDIDATE_D_IS_SEPARATELY_BOUND'
    }
}

function Get-GovernorRetirementEvidenceDigest([string]$Canonical) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return (($sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Canonical)) | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $sha.Dispose()
    }
}
function New-GovernorRetiredGovernorEvidence([string]$SourceCommit, [object]$Reference) {
    # The evidence names both time points: the owner digest remains the v1
    # approval for historical C, while the release binding identifies exact D
    # and its independently recomputed candidate closure.
    $canonical = "$($script:GovernorRetirementApprovalDomain)|retired|$SourceCommit|$([string]$Reference.candidate_tree)|$([string]$Reference.owner_candidate_commit)|$([string]$Reference.owner_candidate_tree)|$([string]$Reference.content_sha256)|$([string]$Reference.closure_digest_sha256)|$([string]$Reference.candidate_closure_digest_sha256)|$([string]$Reference.candidate_closure_count)|$([string]$Reference.canonical_request_hash)|$([string]$Reference.issuer_evidence_sha256)|$([string]$Reference.release_policy_revision)"
    [ordered]@{
        kind = 'retired'
        source_commit = $SourceCommit
        candidate_tree = [string]$Reference.candidate_tree
        owner_candidate_commit = [string]$Reference.owner_candidate_commit
        owner_candidate_tree = [string]$Reference.owner_candidate_tree
        approval_content_sha256 = [string]$Reference.content_sha256
        approval_canonical_request_hash = [string]$Reference.canonical_request_hash
        approval_operation_id = [string]$Reference.operation_id
        approval_file_sha256 = [string]$Reference.approval_file_sha256
        trust_file_sha256 = [string]$Reference.trust_file_sha256
        issuer = [string]$Reference.issuer
        issuer_evidence_sha256 = [string]$Reference.issuer_evidence_sha256
        release_policy_revision = [string]$Reference.release_policy_revision
        closure_rule_set = [string]$Reference.closure_rule_set
        closure_digest_sha256 = [string]$Reference.closure_digest_sha256
        denominator_consumers = [int]$Reference.closure_count
        candidate_closure_digest_sha256 = [string]$Reference.candidate_closure_digest_sha256
        candidate_closure_count = [int]$Reference.candidate_closure_count
        evidence_sha256 = Get-GovernorRetirementEvidenceDigest $canonical
    }
}

function New-RetainedGovernorEvidence([string]$SourceCommit, [object]$Pinned, [object]$Cargo) {
    # Retained evidence binds the exact pinned manifests; the digest covers only
    # pinned content (never machine-local cargo paths), so builder and verifier
    # recompute the identical identity. Shape, field order, domain and canonical
    # preimage are exactly the pre-#2968 retained form: when no approved
    # retirement is supplied the retained slice stages byte-identically, so no
    # retirement-approval field may appear here. Absence is reported in the
    # plan, never in staged bytes.
    $packageId = $null
    $manifestPath = $null
    $targetName = $null
    $targetSrc = $null
    if ($Cargo) {
        $packageId = [string]$Cargo.package_id
        $manifestPath = [string]$Cargo.manifest_path
        $targetName = [string]$Cargo.target_name
        $targetSrc = [string]$Cargo.target_src
    }
    $canonical = "$($script:GovernorRetirementRetainedEvidenceDomain)|retained|$SourceCommit|$([string]$Pinned.workspace_blob)|$([string]$Pinned.facade_blob)"
    [ordered]@{
        kind = 'retained'
        source_commit = $SourceCommit
        workspace_manifest_blob = [string]$Pinned.workspace_blob
        facade_manifest_blob = [string]$Pinned.facade_blob
        package_id = $packageId
        manifest_path = $manifestPath
        target_name = $targetName
        target_src = $targetSrc
        evidence_sha256 = Get-GovernorRetirementEvidenceDigest $canonical
    }
}

function New-GovernorRetirementAbsentApprovalEvidence([string]$SourceCommit, [object]$Pinned) {
    # Why today's retained slice was not retired, recorded explicitly so an
    # absent approval is never mistaken for an accepted one.
    [ordered]@{
        non_admission_reason = 'APPROVAL_INPUT_ABSENT'
        non_admission_reasons = @($script:GovernorRetirementNonAdmissionReasons)
        state = 'RETAINED_WITHOUT_DETACHED_APPROVAL'
        source_commit = $SourceCommit
        workspace_manifest_blob = [string]$Pinned.workspace_blob
        facade_manifest_blob = [string]$Pinned.facade_blob
        plugin_manifest_blob = [string]$Pinned.plugin_blob
        proof_ceiling = $script:GovernorRetirementProofCeiling
    }
}

function New-GovernorRetirementCandidateEvidence([object]$Binding) {
    # The blocked/partial state: the owner has not (or cannot yet) admit an R(C)
    # for this candidate. The independent closure result is still recorded,
    # because it is the exact input the owner must adopt before issuing.
    [ordered]@{
        kind = 'retirement-candidate'
        state = [string]$Binding.state
        non_admission_reason = [string]$Binding.non_admission_reason
        source_commit = [string]$Binding.candidate_commit
        candidate_tree = [string]$Binding.candidate_tree
        reason = [string]$Binding.reason
        closure_rule_set = [string]$Binding.closure_rule_set
        closure_verifier = [string]$Binding.closure_verifier
        closure_digest_sha256 = [string]$Binding.closure_digest_sha256
        closure_count = [int]$Binding.closure_count
        closure_status = [string]$Binding.closure_status
        closure_declaration_path = [string]$Binding.closure_declaration_path
        closure_declaration_blob = [string]$Binding.closure_declaration_blob
        issuer_role = $script:GovernorRetirementApprovalRole
        issuer_state = [string]$Binding.state
        release_policy_revision = [string]$Binding.release_policy_revision
        normative_pair_revision = [string]$Binding.normative_pair_revision
        proof_ceiling = $script:GovernorRetirementProofCeiling
    }
}

# Dot-source guard, deliberately LAST so every constant and function above is
# defined for the release builder and the Authenticode finalizer that dot-source
# this contract. This module performs no staging, no signing and no build; it
# only exposes the closed approval contract and its pure resolvers.
if ($MyInvocation.InvocationName -eq '.') {
    return
}
