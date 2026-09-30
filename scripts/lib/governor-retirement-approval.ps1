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

    Three defects are corrected here.

    1. No tracked file is ever the approval instance. The pre-image digest of
       `GovernorRetirementApprovalV1` covers historical source C and its tree; the later release candidate D is
       separately bound in release evidence. The detached approval is outside
       C, so no commit-fixed-point search is required. A tracked source
       file may describe the expected contract, but a tracked approval whose
       digest cannot match the tree it lives in is a shape error.

    2. Shape is not authority. `Test-GovernorRetirementApprovalShape` establishes
       SHAPE ONLY. Actionability additionally requires (a) issuer evidence
       admitted by a root-owned trust policy file, and (b) an independently
       recomputed consumer closure that matches the owner-pinned closure
       declaration. No parameter, environment variable, or repository path can
       widen the trust policy: the trust policy is one explicit, owner-selected
       tracked file, and the approval body and issuer receipt always come from
       outside the candidate tree.

    3. The candidate inventory cannot certify its own completeness. The closure
       verifier is implemented HERE (outside the candidate source) and scans the
       tracked tree of C with a fixed rule set. The owner pins the verifier
       identity and the closure rule-set version, and any unclassified tracked
       reference to the retiring surface blocks approval.

    The issuer. Current `main` has no production release-retirement approval
    issuer, and the release retirement role is a semantic owner decision that
    this issue is not authorized to invent. The seam below therefore exposes
    exactly three issuer states and only one of them is actionable:
    `ISSUER_AVAILABLE` (an admitted issuer identity is configured and the owner
    adopts the recomputed closure), `ISSUER_UNAVAILABLE` (no issuer is
    configured - the documented fail-closed state), and a rejected approval.
    Neither the Authenticode Code Signing EKU nor any binary-signing signer is
    admitted for the semantic `retirement-approval` role by this module.
    Issuance itself is implemented below by `New-GovernorRetirementApproval`:
    the owner observes C first, and the function constructs, self-verifies and
    emits the detached R(C) outside C - refusing while no issuer is admitted
    or the closure is incomplete.

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
$script:GovernorRetirementTrustSchema = 'eliot-governor-retirement-approval-trust-v1'
$script:GovernorRetirementFreezeSchema = 'eliot-governor-retirement-receipt-v1'
$script:GovernorRetirementFreezeKind = 'detached-approval-pointer'
$script:GovernorRetirementBundleTrustFile = 'GOVERNOR_RETIREMENT_APPROVAL_TRUST.json'
$script:GovernorRetirementBundleApprovalFile = 'GOVERNOR_RETIREMENT_APPROVAL.json'
$script:GovernorRetirementTrustPolicyPath = 'scripts/lib/governor-retirement-approval-trust.json'
$script:GovernorRetirementApprovalRole = 'retirement-approval'
$script:GovernorRetirementClosureRuleSet = 'tracked-legacy-reference-closure-v1'
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

function Read-GovernorApprovalFieldEx([object]$Object, [string]$Name) {
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
    foreach ($name in @('issuer', 'issuer_receipt_kind', 'issuer_evidence_sha256', 'issuer_readback_ref', 'issued_at_utc', 'approver_principal', 'content_sha256', 'canonical_request_hash')) {
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

function Get-GovernorRetirementNormativePairRevision([string]$Repo) {
    $path = Join-Path $Repo 'docs/normative-pair.toml'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw 'tracked normative pair receipt is missing: docs/normative-pair.toml'
    }
    $bytes = [System.IO.File]::ReadAllBytes($path)
    $text = [System.Text.Encoding]::UTF8.GetString($bytes).TrimStart([char]0xFEFF)
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
        if ($fields.Count -lt 3) { continue }
        $map[$path] = [string]$fields[2]
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
    $input = (@($blobs.GetEnumerator() | ForEach-Object { $_.Value }) -join "`n")
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
        $process.StandardInput.Write($input)
        $process.StandardInput.Write("`n")
        $process.StandardInput.Close()
        $standardOutput = $process.StandardOutput.BaseStream
        $byOid = [System.Collections.Generic.Dictionary[string, string]]::new([System.StringComparer]::Ordinal)
        foreach ($pair in $blobs.GetEnumerator()) { $byOid[[string]$pair.Value] = [string]$pair.Key }
        $buffer = [byte[]]::new(65536)
        $pending = [System.Collections.Generic.List[byte]]::new()
        $header = [System.Text.StringBuilder]::new()
        $stage = 'header'
        $currentOid = $null
        $remaining = 0
        while ($true) {
            $read = $standardOutput.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $offset = 0
            while ($offset -lt $read) {
                if ($stage -eq 'header') {
                    while ($offset -lt $read) {
                        $byte = $buffer[$offset]
                        $offset++
                        if ($byte -eq 0x0A) {
                            $line = $header.ToString()
                            $header.Clear()
                            $fields = @($line -split ' ')
                            if ($fields.Count -ge 3 -and $fields[1] -ceq 'blob') {
                                $currentOid = [string]$fields[0]
                                $remaining = [int]$fields[2]
                                $pending.Clear()
                                $stage = 'content'
                            }
                            else {
                                # "<oid> missing" or a non-blob object: skip it.
                                $stage = 'skipheader'
                            }
                            break
                        }
                        [void]$header.Append([char]$byte)
                    }
                }
                elseif ($stage -eq 'content') {
                    $take = [Math]::Min($remaining, $read - $offset)
                    for ($i = 0; $i -lt $take; $i++) { $pending.Add($buffer[$offset + $i]) }
                    $offset += $take
                    $remaining -= $take
                    if ($remaining -eq 0) {
                        $bytes = $pending.ToArray()
                        if ($byOid.ContainsKey($currentOid)) {
                            $result[[string]$byOid[$currentOid]] = [pscustomobject]@{
                                blob = [string]$currentOid
                                text = [System.Text.Encoding]::UTF8.GetString($bytes)
                            }
                        }
                        $pending.Clear()
                        $currentOid = $null
                        $stage = 'trailing'
                    }
                }
                elseif ($stage -eq 'trailing') {
                    # exactly one LF after the object content
                    while ($offset -lt $read) {
                        $byte = $buffer[$offset]
                        $offset++
                        if ($byte -eq 0x0A) { $stage = 'header'; break }
                    }
                }
                else {
                    $offset = $read
                }
            }
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

function Get-GovernorRetirementClosureClassification([string]$RelativePath, [string[]]$Tokens) {
    # Evidence-class classification for one tracked reference. Returns the
    # verifier rules that cover this path, or the single real class 'unknown'
    # when no rule covers it. 'unknown' is a class, not an absence: the caller
    # records unknown references explicitly, binds them into the closure
    # digest, reports the closure INCOMPLETE, and approval stays blocked. The
    # path family is reported separately by the caller; it partitions the
    # denominator but never stands in for a covering verifier rule.
    $path = ([string]$RelativePath).Replace('\', '/')
    $classes = [System.Collections.Generic.List[string]]::new()
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
    if ($classes.Count -eq 0) {
        return @('unknown')
    }
    return @($classes | Sort-Object -Unique)
}

function Get-GovernorRetirementConsumerClosure([string]$Repo, [string]$SourceCommit, [switch]$AllowMissingFamilies) {
    # Independent closure over the tracked tree of C (issue #2968 section D).
    # Enumerates every tracked file and records every file that names the
    # retiring surface: files covered by a verifier rule are classified, and
    # files matching no rule are classified 'unknown', bound into the digest,
    # and reported explicitly. The result is independent of the candidate's
    # own disposition table, so a candidate can neither shrink the table and
    # the verifier together, nor make an unclassified reference disappear:
    # any 'unknown' reference makes the closure INCOMPLETE and blocks approval.
    $tokens = @($script:GovernorRetirementClosureTokens)
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
        $classes = Get-GovernorRetirementClosureClassification ([string]$relative) $tokens
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
        [void]$classified.Add([pscustomobject]@{
                path = [string]$relative
                blob = [string]$text.blob
                classes = @((@($classes) + "family:$family") | Sort-Object -Unique)
                tokens = @($hits)
            })
    }
    $sorted = @($classified | Sort-Object -Property path)
    $lines = [System.Collections.Generic.List[string]]::new()
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'domain' $script:GovernorRetirementClosureDomain))
    [void]$lines.Add((Get-GovernorApprovalDomainSeparatedLine 'rule_set' $script:GovernorRetirementClosureRuleSet))
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
        [void]$lines.Add("closure=$([string]$entry.path)|blob=$([string]$entry.blob)|classes=$([string]::Join(',', @($entry.classes)))|tokens=$([string]::Join(',', @($entry.tokens)))")
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
        rule_set = $script:GovernorRetirementClosureRuleSet
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
        if ($tokens.Count -gt 0) {
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

function Test-GovernorRetirementApprovalShape(
    [object]$Approval,
    [string]$SourceCommit,
    [string]$CandidateTree,
    [object]$Closure,
    [string]$Repo,
    [string]$ReleasePolicyRevision) {
    # Decoding plus schema validation. SHAPE ONLY: returns a result whose
    # `admissible` bit is true when the body is a well-formed GovernorRetirement
    # ApprovalV1 bound to historical source C, its closure and policy. It grants
    # nothing; only verified issuer evidence makes the approval actionable.
    $rejected = {
        param([string]$Reason)
        [pscustomobject]@{
            admitted = $false
            reason = $Reason
            content_sha256 = $null
            canonical_request_hash = $null
            operation_id = $null
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
        'issuer_evidence_sha256', 'issuer_readback_ref',
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
        $normativeRevision = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'normative_pair_revision')
        $normativeDigest = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'normative_pair_sha256')).ToLowerInvariant()
        if ([string]::IsNullOrWhiteSpace($normativeRevision) -or $normativeRevision -cnotmatch '^\d+\.\d+-(draft|adopted)$') {
            return (& $rejected "APPROVAL_NORMATIVE_PAIR_REVISION_MALFORMED (value=$normativeRevision)")
        }
        if ($normativeDigest -cnotmatch '^[0-9a-f]{64}$') {
            return (& $rejected "APPROVAL_NORMATIVE_PAIR_DIGEST_MALFORMED (value=$normativeDigest)")
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
        if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'closure_rule_set')) -cne $script:GovernorRetirementClosureRuleSet) {
            return (& $rejected "APPROVAL_CLOSURE_RULE_SET_MISMATCH (approved=$(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'closure_rule_set')) current=$($script:GovernorRetirementClosureRuleSet))")
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


function Resolve-GovernorRetirementIssuer([object]$TrustPolicy) {
    # The narrow issuer seam. `ISSUER_UNAVAILABLE` is the documented fail-closed
    # state for every current tree; the state is only actionable when a
    # root-owned trust policy admits one issuer identity for the semantic
    # retirement-approval role. Authenticode Code Signing signers and any
    # binary-signing identity are never admitted for this role by this module.
    $issuers = @(Read-GovernorApprovalField $TrustPolicy 'admitted_issuers')
    if ($issuers.Count -eq 0) {
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = 'no owner-admitted retirement-approval issuer is configured in the root-owned trust policy'
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
            reason = "the root-owned trust policy must admit exactly one issuer for the $($script:GovernorRetirementApprovalRole) role; found $($matching.Count)"
            issuer_identity = $null
            policy_digest = $null
        }
    }
    $admitted = $matching[0]
    if (-not [string]::IsNullOrWhiteSpace((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $admitted 'authenticode_code_signing_thumbprint')))) {
        return [pscustomobject]@{
            state = 'ISSUER_UNAVAILABLE'
            reason = 'an Authenticode Code Signing signer is not a semantic retirement-approval issuer; the trust policy claim is refused'
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
    [object]$CandidateIdentity,
    [object]$SourceClosure,
    [object]$CandidateClosure,
    [object[]]$ApprovedConsumers) {
    # The detached owner approval remains bound to its original source C. The
    # release candidate D is checked independently: it must descend from C,
    # remove the legacy crate and every C-scanned path/token reference, add no
    # new reference, and remove every owner-approved live_reference string from
    # its proof path. The independent scan is the fixed closed-rule contract;
    # no filename-only or inferred live-edge classifier is added.
    $null = & git -C $Repo merge-base --is-ancestor $OwnerSourceCommit $CandidateCommit 2>$null
    if ($LASTEXITCODE -ne 0) {
        return [pscustomobject]@{ admitted = $false; reason = 'APPROVAL_OWNER_SOURCE_NOT_ANCESTOR' }
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
    $candidatePairs = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
    foreach ($entry in @($CandidateClosure.entries)) {
        $path = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $entry 'path')
        foreach ($token in @(Read-GovernorApprovalField $entry 'tokens')) {
            $tokenText = [string]$token
            $pair = "$($path.Length):$path|$($tokenText.Length):$tokenText"
            if (-not $sourcePairs.Contains($pair)) {
                return [pscustomobject]@{ admitted = $false; reason = "APPROVAL_CANDIDATE_REFERENCE_NOT_IN_SOURCE_CLOSURE (path=$path token=$tokenText)" }
            }
            [void]$candidatePairs.Add($pair)
        }
    }
    foreach ($entry in @($SourceClosure.entries)) {
        $path = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $entry 'path')
        foreach ($token in @(Read-GovernorApprovalField $entry 'tokens')) {
            $tokenText = [string]$token
            $pair = "$($path.Length):$path|$($tokenText.Length):$tokenText"
            if ($candidatePairs.Contains($pair)) {
                return [pscustomobject]@{ admitted = $false; reason = "APPROVAL_CANDIDATE_REFERENCE_STILL_IN_CLOSURE (path=$path token=$tokenText)" }
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
    # The root-owned trust policy is the ONLY thing that can admit a retirement
    # approval issuer. It is a shape gate only: the issuer decision is made by
    # Resolve-GovernorRetirementIssuer, and no caller parameter can widen it.
    if (-not $TrustPolicy) {
        throw 'retirement approval trust policy is missing'
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'schema')) -cne $script:GovernorRetirementTrustSchema) {
        throw "retirement approval trust policy schema must be $($script:GovernorRetirementTrustSchema)"
    }
    $policy = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'release_policy')
    if ($policy -cne $script:GovernorRetirementLegacyRepository -or
        (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'release_product')) -cne $script:GovernorRetirementProduct) {
        throw 'retirement approval trust policy is not bound to this repository/product release'
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'closure_verifier')) -cne 'Get-GovernorRetirementConsumerClosure') {
        throw "retirement approval trust policy names a closure verifier this release does not implement: $(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'closure_verifier'))"
    }
    if ((ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'closure_rule_set')) -cne $script:GovernorRetirementClosureRuleSet) {
        throw "retirement approval trust policy names a closure rule set this release does not implement: $(ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $TrustPolicy 'closure_rule_set'))"
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
    foreach ($issuer in @(Read-GovernorApprovalField $TrustPolicy 'admitted_issuers')) {
        [void]$lines.Add("issuer=$([string](Read-GovernorApprovalField $issuer 'issuer'))|role=$([string](Read-GovernorApprovalField $issuer 'role'))|authority=$([string](Read-GovernorApprovalField $issuer 'authority'))|receipt_kind=$([string](Read-GovernorApprovalField $issuer 'receipt_kind'))|authenticode_code_signing_thumbprint=$([string](Read-GovernorApprovalField $issuer 'authenticode_code_signing_thumbprint'))")
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
    $closure = Get-GovernorRetirementConsumerClosure $Repo $SourceCommit
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

function New-GovernorRetirementApproval(
    [string]$Repo,
    [string]$SourceCommit,
    [string]$OwnerReceiptPath,
    [string]$ApproverPrincipal,
    [string]$IssuerReadbackRef,
    [string]$OperationId,
    [string]$IdempotencyNamespace,
    [string]$IdempotencyRetentionHours,
    [string]$IssuedAtUtc,
    [string]$ExpiresAtUtc,
    [string]$ConfigPolicyRevision,
    [string[]]$IssueRefs,
    [string[]]$WorkRefs,
    [string[]]$ReviewRefs,
    [object[]]$Consumers,
    [string]$ReplacementOwner,
    [string]$ProductRemovalDecision,
    [string]$ReopenCondition,
    [string]$RollbackCondition,
    [string]$OutputPath) {
    # Owner-side issuance of the detached GovernorRetirementApprovalV1 artifact
    # R(C) (issue #2968 Required design B, two-time workflow step 4). The issuer
    # observes the frozen candidate C first and issues afterwards; the approval
    # body and the owner receipt remain outside C. Every candidate-bound value
    # (commit, tree, closure, declaration, normative pair, policy revision,
    # issuer identity) is recomputed from the repository and the pinned
    # root-owned trust policy - never taken from a caller string - while the
    # owner decision itself (principal, operation, validity window, refs,
    # dispositions, conditions) arrives only through these explicit parameters:
    # no environment selection, no repository default, no directory search.
    # Issuance refuses, fail closed, while no issuer is admitted, while the
    # independent closure is incomplete, or while the constructed body does not
    # verify through the same shape gate the builder enforces; nothing
    # unverifiable is ever emitted. The emitted artifact is consumed through
    # the builder's explicit -GovernorRetirementApproval input. No new PKI is
    # introduced: the owner receipt is owner-produced bytes bound here by
    # content digest, and the trust anchor is the root-owned policy admitting
    # exactly one issuer identity for the retirement-approval role.
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
    if (-not (Get-Command Resolve-GovernorRetirementTrustPolicy -CommandType Function -ErrorAction SilentlyContinue) -or
        -not (Get-Command Read-VerifiedResidentFile -CommandType Function -ErrorAction SilentlyContinue)) {
        throw 'retirement approval issuance requires the release safe path/handle rules; dot-source scripts/build-eliot-windows-x64-release.ps1 (which loads this contract) before issuing'
    }
    $trustPolicy = Resolve-GovernorRetirementTrustPolicy $Repo $SourceCommit
    $issuer = Resolve-GovernorRetirementIssuer $trustPolicy.body
    if ([string]$issuer.state -cne 'ISSUER_AVAILABLE') {
        throw "retirement approval issuance is unavailable for candidate ${SourceCommit}: $([string]$issuer.reason)"
    }
    $admitted = @(@(Read-GovernorApprovalField $trustPolicy.body 'admitted_issuers') | Where-Object {
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'role')) -ceq $script:GovernorRetirementApprovalRole -and
            (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $_ 'issuer')) -ceq [string]$issuer.issuer_identity
        })
    if ($admitted.Count -ne 1) {
        throw 'the root-owned trust policy admits no single retirement-approval issuer entry for this issuance'
    }
    $issuerReceiptKind = ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $admitted[0] 'receipt_kind')
    if ([string]::IsNullOrWhiteSpace($issuerReceiptKind)) {
        throw 'the admitted retirement-approval issuer entry names no receipt_kind'
    }
    $closure = Get-GovernorRetirementConsumerClosure $Repo $SourceCommit
    if ([string]$closure.status -cne 'COMPLETE') {
        $blocking = @(@($closure.unclassified_path_families) + @($closure.unclassified_paths) | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) })
        throw "retirement approval issuance refuses an incomplete independent closure: $([string]::Join(', ', $blocking))"
    }
    $candidateTree = Get-GovernorRetirementCandidateTree $Repo $SourceCommit
    $normativePair = Get-GovernorRetirementNormativePairRevision $Repo
    $declarationBlob = Get-GovernorRetirementTrackedPathDigest $Repo $SourceCommit $script:GovernorRetirementDispositionInventoryPath
    if (-not $declarationBlob) {
        throw "the closure declaration inventory is not tracked at candidate ${SourceCommit}: $($script:GovernorRetirementDispositionInventoryPath)"
    }
    $releasePolicyRevision = Get-GovernorRetirementPolicyRevision $trustPolicy.body
    $repoFull = (Resolve-Path -LiteralPath $Repo).Path.TrimEnd([System.IO.Path]::DirectorySeparatorChar, [System.IO.Path]::AltDirectorySeparatorChar)
    if ([string]::IsNullOrWhiteSpace($OwnerReceiptPath) -or -not [System.IO.Path]::IsPathRooted($OwnerReceiptPath)) {
        throw 'retirement approval issuance requires the owner receipt as an explicit absolute path outside the candidate tree'
    }
    $receiptFull = [System.IO.Path]::GetFullPath($OwnerReceiptPath)
    if ($receiptFull.StartsWith("$repoFull$([System.IO.Path]::DirectorySeparatorChar)", [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]::Equals($receiptFull, $repoFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'the owner receipt must remain outside the candidate tree C'
    }
    $receipt = Read-VerifiedResidentFile $OwnerReceiptPath 'detached owner retirement receipt'
    $ownerScalars = [ordered]@{
        ApproverPrincipal = $ApproverPrincipal
        IssuerReadbackRef = $IssuerReadbackRef
        OperationId = $OperationId
        IdempotencyNamespace = $IdempotencyNamespace
        ConfigPolicyRevision = $ConfigPolicyRevision
        ReopenCondition = $ReopenCondition
        RollbackCondition = $RollbackCondition
    }
    foreach ($entry in $ownerScalars.GetEnumerator()) {
        if ([string]::IsNullOrWhiteSpace([string]$entry.Value)) {
            throw "retirement approval issuance requires a nonblank owner decision: -$($entry.Key)"
        }
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
        issuer_evidence_sha256 = [string]$receipt.sha256
        issuer_readback_ref = $IssuerReadbackRef
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
    $shape = Test-GovernorRetirementApprovalShape $body $SourceCommit $candidateTree $closure $Repo $releasePolicyRevision
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
        issued_at_utc = $IssuedAtUtc
        expires_at_utc = $ExpiresAtUtc
    }
}

function Resolve-GovernorRetirementApprovalBinding(
    [string]$Repo,
    [string]$SourceCommit,
    [object]$Approval,
    [object]$TrustPolicy,
    [object]$Issuer) {
    # R(C) remains the original owner-issued approval for historical source C.
    # D is the release candidate. Verify the immutable v1 body against C with
    # the existing owner validator, then independently bind D and its scanned
    # closure in the release reference. No field in R(C) is rewritten or
    # re-digested to make it name D.
    $candidateTree = Get-GovernorRetirementCandidateTree $Repo $SourceCommit
    $normativePair = Get-GovernorRetirementNormativePairRevision $Repo
    $candidateIdentity = Get-GovernorRetirementPinnedLegacyIdentity $Repo $SourceCommit
    $candidateClosure = Get-GovernorRetirementConsumerClosure $Repo $SourceCommit -AllowMissingFamilies
    $ownerSourceCommit = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $Approval 'candidate_commit')).ToLowerInvariant()
    $ownerSourceTree = $null
    $ownerIdentity = [pscustomobject]@{ status = 'absent'; reason = 'owner approval source commit is missing or malformed'; workspace_blob = $null; facade_blob = $null; plugin_blob = $null }
    $ownerClosure = $null
    $ownerDeclarationBlob = $null
    $ownerSourceError = $null
    if ($ownerSourceCommit -cmatch '^[0-9a-f]{40}$') {
        try {
            $ownerSourceTree = Get-GovernorRetirementCandidateTree $Repo $ownerSourceCommit
            $ownerIdentity = Get-GovernorRetirementPinnedLegacyIdentity $Repo $ownerSourceCommit
            $ownerClosure = Get-GovernorRetirementConsumerClosure $Repo $ownerSourceCommit
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
    $releasePolicyRevision = Get-GovernorRetirementPolicyRevision $TrustPolicy.body
    $shape = $null
    if ($ownerClosure -and $ownerSourceTree) {
        $shape = Test-GovernorRetirementApprovalShape $Approval $ownerSourceCommit $ownerSourceTree $ownerClosure $Repo $releasePolicyRevision
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
    $transition = Test-GovernorRetirementCandidateTransition `
        $Repo `
        $SourceCommit `
        $ownerSourceCommit `
        $candidateIdentity `
        $ownerClosure `
        $candidateClosure `
        @($shape.consumers)
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
        approval_file = $script:GovernorRetirementBundleApprovalFile
        approval_file_sha256 = $ApprovalFileSha256
        trust_file = $script:GovernorRetirementBundleTrustFile
        trust_file_sha256 = $TrustFileSha256
        proof_ceiling = $script:GovernorRetirementProofCeiling
    }
}

function New-GovernorRetirementReplayRecord([object]$Reference, [object]$ApprovalBody) {
    # Exact owner-decision replay under one operation (issue #2968 step 11).
    # The unchanged v1 request hash covers historical source C and its approved
    # denominator, dispositions, target identity, policy revisions and
    # rollback/reopen conditions. It excludes owner evidence as before. The
    # later release candidate D is separately recorded in the release binding;
    # moving D changes that binding without re-issuing or re-digesting R(C).
    $canonical = Get-GovernorApprovalCanonicalPreimage $ApprovalBody
    [ordered]@{
        operation_id = [string]$Reference.operation_id
        idempotency_namespace = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ApprovalBody 'idempotency_namespace'))
        idempotency_retention_hours = (ConvertTo-GovernorApprovalString (Read-GovernorApprovalField $ApprovalBody 'idempotency_retention_hours'))
        canonical_request_hash = (Get-GovernorApprovalSha256 $canonical)
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
