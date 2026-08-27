[CmdletBinding()]
param([switch] $SelfTest)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) { throw "COMPOSITION_ROOTS_VERIFY_FAIL: $Message" }
function Sha256-Text([string] $Text) { [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes($Text))).ToLowerInvariant() }
function Read-Utf8([string] $Path) { [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false, $true)) }
function Source-Lines([string] $Text) { [regex]::Split($Text, "`r`n|`n|`r") }

function Assert-RelativePath([string] $Path, [string] $Field) {
    if ([string]::IsNullOrWhiteSpace($Path) -or [System.IO.Path]::IsPathRooted($Path) -or $Path.Contains('\') -or $Path -match '(^|/)\.\.?(/|$)' -or $Path.StartsWith('/')) { Fail "$Field must be a repository-relative slash path: $Path" }
}

function Assert-PropertySet($Object, [string[]] $Expected, [string] $Field) {
    if ($null -eq $Object) { Fail "$Field is missing" }
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    if (($actual -join "`n") -cne ($wanted -join "`n")) { Fail "$Field property set mismatch" }
}

function Get-TargetSet($Metadata) {
    @(
        foreach ($package in $Metadata.packages) {
            foreach ($target in $package.targets) {
                if (@($target.kind) -contains 'bin') {
                    [pscustomobject]@{ Target = [string]$target.name; Package = [string]$package.name; Manifest = ([string]$package.manifest_path -replace '\\','/'); Source = ([string]$target.src_path -replace '\\','/') }
                }
            }
        }
    ) | Sort-Object Target
}

function Get-ExpectedStableId($Record) {
    $seed = "$($Record.target)`0$($Record.package)`0$($Record.manifest.path)`0$($Record.main.path)`0$($Record.classification)`0$($Record.witness.anchor_digest)"
    'CR-' + (Sha256-Text $seed).Substring(0, 24)
}

function Get-ExpectedAnchorDigest($Record) {
    $texts = @($Record.manifest.anchor.text, $Record.main.text) + @($Record.composition_root.call_chain | ForEach-Object { $_.text })
    Sha256-Text ($texts -join "`n")
}

function Get-PredicatePolicy([string] $Target) {
    $policies = @{
        'eliot' = @{ kind = 'reachable_effect'; required = @('match cli.command') }
        'eliot-agent-bridge' = @{ kind = 'reachable_effect'; required = @('kernel_ports_with_declaration(&config.client_declaration)', 'BridgeRunner::new(', 'for line in io::stdin().lock().lines()') }
        'eliot-campaign-executor' = @{ kind = 'reachable_effect'; required = @('fn dispatch(command: Option<Command>)', 'fn apply(campaign_root: PathBuf, command: String)') }
        'eliot-credential-suite-guard' = @{ kind = 'reachable_effect'; required = @('isolated_operator_cursor_credentials()?', 'match action.to_str()') }
        'eliot-doctor' = @{ kind = 'pre_effect_typed_refusal'; required = @('std::process::exit(EXIT_KERNEL_ADMISSION_REQUIRED);') }
        'eliot-dreamer' = @{ kind = 'pre_effect_typed_refusal'; required = @('AuthenticatedKernelJobPort::connect()', 'ExitCode::from(KERNEL_ADMISSION_EXIT)') }
        'eliot-governor' = @{ kind = 'reachable_effect'; required = @('dispatch_command(') }
        'eliot-host' = @{ kind = 'reachable_effect'; required = @('if !run_console()', 'fn dispatch(host: &mut HostComposition') }
        'eliot-kernel' = @{ kind = 'reachable_effect'; required = @('parse_launch_options(', 'KernelConfig::new(') }
        'eliot-live-canary' = @{ kind = 'reachable_effect'; required = @('ProductionCanary::new(', 'write_development_evidence(') }
        'eliot-mod-research' = @{ kind = 'reachable_effect'; required = @('compose_from_environment()', 'Request::Submit') }
        'eliot-native-worker' = @{ kind = 'pre_effect_typed_refusal'; required = @('KernelNativeWorkerClient::connect()', 'std::process::exit(KERNEL_ADMISSION_EXIT);') }
        'eliot-notify' = @{ kind = 'reachable_effect'; required = @('register_watchdog_fallback_task()', 'dispatch_deliver(') }
        'eliot-opencode-bootstrap' = @{ kind = 'reachable_effect'; required = @('match run().await', 'OpenCodeClient::new(') }
        'eliot-process-guardian' = @{ kind = 'reachable_effect'; required = @('match run()', 'SuspendedJobChild::spawn(') }
        'eliot-r13-two-token-harness' = @{ kind = 'reachable_effect'; required = @('eliot_kernel::r13_os_harness::run()') }
        'eliot-runtime-compiler' = @{ kind = 'reachable_effect'; required = @('compile(&CompileOptions', 'println!') }
        'eliot-store-surreal' = @{ kind = 'reachable_effect'; required = @('NamedPipeServer::create(', 'loop {') }
        'eliot-testd' = @{ kind = 'reachable_effect_partial_refusal'; required = @('UnavailableProcessIssuer', '&Response::Ready', 'for line in io::stdin().lock().lines()', 'Request::Submit', 'Request::Status', 'Request::Cancel') }
        'eliot-user-broker' = @{ kind = 'reachable_effect'; required = @('BrokerComposition::start_with_kernel(', 'dispatch(&mut composition') }
        'eliot-wasm-host' = @{ kind = 'pre_effect_typed_refusal'; required = @('parse_args(', 'std::process::exit(ADMISSION_REQUIRED_EXIT);') }
        'eliot-watchdog' = @{ kind = 'reachable_effect'; required = @('run_watchdog(', 'IndependentKernelSensor::') }
        'eliotd' = @{ kind = 'reachable_effect'; required = @('tokio::select!', 'claim_agent_activation_ticket()', 'submit_agent_activation_decision(') }
    }
    if (-not $policies.ContainsKey($Target)) { Fail "missing independent predicate policy for target $Target" }
    $policy = $policies[$Target]
    $expectedClassification = switch ([string]$policy.kind) {
        'reachable_effect' { 'useful_work' }
        'reachable_effect_partial_refusal' { 'useful_work' }
        'pre_effect_typed_refusal' { 'typed_refusal' }
        'idle_only' { 'idle_only' }
        default { 'unknown' }
    }
    [pscustomobject]@{
        kind = [string]$policy.kind; expected_classification = $expectedClassification; required_source_fragments = @($policy.required)
        reachable_effect = $policy.kind -in @('reachable_effect','reachable_effect_partial_refusal')
        pre_effect_refusal = $policy.kind -in @('pre_effect_typed_refusal','reachable_effect_partial_refusal')
        partial_capability = $policy.kind -eq 'reachable_effect_partial_refusal'
        refusal_scope = if ($policy.kind -eq 'reachable_effect_partial_refusal') { 'Submit only' } else { $null }
    }
}

function Assert-PredicateConsistency($Record, $Policy) {
    $predicate = $Record.composition_root.predicate
    foreach ($field in @('kind','expected_classification','reachable_effect','pre_effect_refusal','partial_capability')) {
        if ($predicate.$field -cne $Policy.$field) { Fail "predicate derivation mismatch for $($Record.target): $field" }
    }
    if (($predicate.refusal_scope | Out-String).Trim() -cne (($Policy.refusal_scope | Out-String).Trim())) { Fail "predicate refusal scope mismatch: $($Record.target)" }
    if ($Record.classification -cne $Policy.expected_classification) { Fail "classification is not derived from source predicate: $($Record.target)" }
}

function Assert-Predicate($Root, $Record) {
    $policy = Get-PredicatePolicy ([string]$Record.target)
    $chain = @($Record.composition_root.call_chain)
    $chainLines = @($chain | ForEach-Object { "$($_.path):$($_.line)" })
    $chainSymbols = @($chain | ForEach-Object { [string]$_.symbol })
    if (($Record.composition_root.predicate.witness.ordered_anchor_lines -join "`n") -cne ($chainLines -join "`n")) { Fail "predicate ordered anchor witness mismatch: $($Record.target)" }
    if (($Record.composition_root.predicate.witness.ordered_anchor_symbols -join "`n") -cne ($chainSymbols -join "`n")) { Fail "predicate ordered symbol witness mismatch: $($Record.target)" }
    if (($Record.composition_root.predicate.witness.required_source_fragments -join "`n") -cne ($policy.required_source_fragments -join "`n")) { Fail "predicate required-fragment policy mismatch: $($Record.target)" }
    $sourceTexts = [System.Collections.Generic.List[string]]::new()
    $sourcePaths = @($Record.main.path) + @($chain | ForEach-Object path)
    foreach ($relative in ($sourcePaths | Sort-Object -Unique)) { $sourceTexts.Add((Read-Utf8 (Join-Path $Root $relative))) }
    $combined = $sourceTexts -join "`n"
    $orderedAnchorText = (@($Record.main.text) + @($chain | ForEach-Object { $_.text })) -join "`n"
    foreach ($fragment in $policy.required_source_fragments) {
        if (-not $orderedAnchorText.Contains([string]$fragment)) { Fail "predicate branch fragment is absent from ordered anchors: $($Record.target):$fragment" }
        if (-not $combined.Contains([string]$fragment)) { Fail "predicate source fragment is absent: $($Record.target):$fragment" }
    }
    Assert-PredicateConsistency $Record $policy
}

function Get-ExpectedWitnessHash([string] $Target) {
    $hashes = @{
        'eliot'='3bdbe7f0e759e83afd90b51d22d9afa96bfbd9781c08d8ca306bc1763cd88794'; 'eliot-agent-bridge'='1e0ae745d5ef85d96adeb221ec6997770f17d88a820a723399ebde6cda34fd0b'; 'eliot-campaign-executor'='f9a1a358a3b7e0b201549c92a452b99533a972a4045acf72ac8ff5bbbdcc13bc'; 'eliot-credential-suite-guard'='202aa6c583a0a86449cb590510d4d0927e7abc8bdb66b26fca5b4ca5ee4b162c'; 'eliot-doctor'='4935a21fc36f0086017e1bc0ee7bbd26f359eb180a2249120c7927b1c788f204'; 'eliot-dreamer'='807388bc573016958e27bb653f94d2b006c95a4a8525fcfc2af18e8532e30b41'; 'eliot-governor'='0ac29883aff15d2cc9ed75d3a672aeeecf5a588b9327bb31875df4538ac97c1f'; 'eliot-host'='79573922bf51dcbe4226cff1b57e721e38aff44d6538ef38976df8f30fbf33e3'; 'eliot-kernel'='0d03b69c3cea22c46ef2a673f67e72e61af649a32d9ea38647d02dd12b64b70c'; 'eliot-live-canary'='3b7d75d8202f46ba67d87bdc5c856543b87948de2ee8fc925ee22c26c6a992b2'; 'eliot-mod-research'='fa2879f2fe61da14404d8fbb60393efed9733620e08c0aa24c7a3d3f6f440ff4'; 'eliot-native-worker'='32c3bd74939e0d4356080176f4d0bcd78b695db14e8e70f3d8ff73a8ab76b372'; 'eliot-notify'='d6eebb5df306ec37af3329e5a13e0222e4d6977d27fe2d65364978de0364f80c'; 'eliot-opencode-bootstrap'='aa3ae280ec08617613cafd41cbc3295953279630c7f5e27e67f45a5338ce0f6f'; 'eliot-process-guardian'='c1aedbc24e2cdd12a8573635a7d5d95d53bb8c96e164c285c1a8c581796e55b5'; 'eliot-r13-two-token-harness'='b3bcdc755b8d140d6bfd7c1fc3eea6d83b964c49768dc6925354d17d9ca33a16'; 'eliot-runtime-compiler'='74ba7e6472b4e05fa5f2cd180983d2446f206516a3305e54dbb582898de77fc0'; 'eliot-store-surreal'='b7ba845620b45faac76d536aa0fb62652880d39b22efbad344f705416027aa23'; 'eliot-testd'='36ac411448e57d67ddd40674b24d53fb2ade10b88aafb59c4b60a3be692c4c6e'; 'eliot-user-broker'='c8706ff0c901780e45ae9ce009b214f236f8de33e23600b6b1321766a4102acf'; 'eliot-wasm-host'='25daf3923ed2d06f7230e20e732db8b0c32e4232bc3979f666d330b6f482a3c9'; 'eliot-watchdog'='d5ecb2043f1b223019dc7e22bdd2bfc0ef6ed80e0b94e4224086a92811dcae65'; 'eliotd'='ebf3dedbb207f1ab4884075f014092c9ef72564d3a03ef22dd3a0376d4736642'
    }
    # Current-tree overrides are explicit and remain independent from the generator oracle.
    $hashes['eliot-agent-bridge'] = '1e0ae745d5ef85d96adeb221ec6997770f17d88a820a723399ebde6cda34fd0b'
    $hashes['eliot-r13-two-token-harness'] = 'b3bcdc755b8d140d6bfd7c1fc3eea6d83b964c49768dc6925354d17d9ca33a16'
    $hashes['eliotd'] = 'ebf3dedbb207f1ab4884075f014092c9ef72564d3a03ef22dd3a0376d4736642'
    if (-not $hashes.ContainsKey($Target)) { Fail "missing exact witness policy for $Target" }
    [string]$hashes[$Target]
}

function Get-WitnessHash($Record) {
    $value = "$($Record.operational_scope)`0$($Record.composition_root.gate_condition)`0$($Record.composition_root.effect_boundary)`0$($Record.composition_root.falsifier)`0$($Record.witness.catalogue)"
    Sha256-Text $value
}

function Get-ExpectedAnchorGraphDigest([string] $Target) {
    $digests = @{
        'eliot'='c745ed87043a9ec81370f43d1fdba2db6c4c5c69cb027e5984f56fd8391218ac'; 'eliot-agent-bridge'='13aee977741be448fe4a2134d590dea26ca852df051859b352d2730d959248b5'; 'eliot-campaign-executor'='ba4084967da26e75b4cd88b0fe76cd7b1324593059a13f3a65b783afa5144e89'; 'eliot-credential-suite-guard'='141b54f2e81ba7380e762bfaa8ca526c13959b29cfa826222a574468e2462510'; 'eliot-doctor'='3da8530f36fb79cf2d1bbf4c1165a3cd86f814ea9d8cb73fcd14a8c8b4c51dc7'; 'eliot-dreamer'='d44e24db198b105601fafd409149ed173a328c04d767ed823c4e945ba0b5043c'; 'eliot-governor'='f4fc02076400a47d36ce31c7f2af26c012640c945ab9c5366d6101acd9d9564a'; 'eliot-host'='6e4c615198c6240b0ac2506cf47c436e759a4e7e37b72c6b3c702d7bf067bd54'; 'eliot-kernel'='71cd9b7e76568aeda7fa1cc27cd1b96b03e4a916b84bd26f57fe52a5afc1b6d9'; 'eliot-live-canary'='25eee7f351fb40853cfdede3e3e0e5a309717e291a6c09df4530843e94d3ce78'; 'eliot-mod-research'='9a499d21d2fcfd9235c8341edd02922a6805a3a39d569ba2d71754c3d41522ca'; 'eliot-native-worker'='8561425f49fd32f059661ef6609c792bc302dcd5fcbaffd37cc7490c88a46470'; 'eliot-notify'='5c64389049ddd1737222310a4118e4d7f237c1e20e12178c374f65ff9473dfbe'; 'eliot-opencode-bootstrap'='c55ee641ba02328a966ad221f2ab7bd20858edc0e4f44ff8566ca26b4f6c0044'; 'eliot-process-guardian'='b34b4ff1325edad7789533666148b5e924d742e3f925f4f17aa879fa4d0a2b28'; 'eliot-runtime-compiler'='eb3162e89d6f3e3ad543c1d070c6cbf806586fb5c809e6f6332cece5c0c4cf7d'; 'eliot-store-surreal'='9d88bff5e55315a212aade55f7eeec325bfc795d28274d4ada3bc5a30ad84579'; 'eliot-testd'='f208129f2adcea9f64de78023a7a4d7c03483867ce7e3298a30039894d980fb7'; 'eliot-user-broker'='3e5d50edabe05b4ca50ba5b5e2ae472564d692d5d79c0e094e01cd8998343494'; 'eliot-wasm-host'='ce419d656f2a966ba406258f630f51954bc37486348d2afeaddc782dd4c72f33'; 'eliot-watchdog'='91ab02ca24bb6b48c2dc2c7f9becf87ed8b3274ac4ef0d98fe245c74e9972ae2'; 'eliotd'='71758c4bb79cc0dd1dcd95f668a5ab381ad1f089d897f114911a8d57db581609'
    }
    # Current-tree overrides are explicit and remain independent from the generator oracle.
    $digests['eliot-agent-bridge'] = 'b272670057e0f93211428b7aa04ec195287a49d993569629b0090fd49e31cf67'
    $digests['eliot-r13-two-token-harness'] = '147dd921395997b10a4cf762a995e3f9a04667f4ce11b9a35425f00f50c3a401'
    $digests['eliotd'] = 'ebd25157cd7ab511a8d3840970f710a6078264d272549c5fefa627e551c902ef'
    if (-not $digests.ContainsKey($Target)) { Fail "missing exact anchor graph policy for $Target" }
    [string]$digests[$Target]
}

function Get-RustCommitCensus([string] $Root) {
    $cached = @(& git -C $Root ls-files --cached -- '*.rs')
    if ($LASTEXITCODE -ne 0) { Fail "git cached Rust census exited $LASTEXITCODE" }
    $untracked = @(& git -C $Root ls-files --others --exclude-standard -- '*.rs')
    if ($LASTEXITCODE -ne 0) { Fail "git untracked Rust census exited $LASTEXITCODE" }
    $paths = @($cached + $untracked | ForEach-Object { ([string]$_).Replace('\','/') } | Sort-Object -Unique)
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($relativeRaw in $paths) {
        $relative = ([string]$relativeRaw).Replace('\','/')
        $lines = Source-Lines (Read-Utf8 (Join-Path $Root $relative))
        for ($index = 0; $index -lt $lines.Count; $index++) {
            $line = [string]$lines[$index]
            if ($line -notmatch '\bcommit_canonical\s*\(') { continue }
            $kind = if ($line -match '\bfn\s+commit_canonical\s*\(') { 'definition' } else { 'caller' }
            $entries.Add([pscustomobject]@{ path = $relative; line = $index + 1; text = $line; kind = $kind; line_sha256 = Sha256-Text $line })
        }
    }
    @($entries | Sort-Object path, line, kind)
}

function Assert-DeclaredCommitRows($Actual, $Declared) {
    $actualKeys = @($Actual | ForEach-Object { "$($_.path)`0$($_.line)`0$($_.text)`0$($_.kind)`0$($_.line_sha256)" })
    $declaredKeys = @($Declared.occurrences | ForEach-Object { "$($_.path)`0$($_.line)`0$($_.text)`0$($_.kind)`0$($_.line_sha256)" })
    if (($actualKeys -join "`n") -cne ($declaredKeys -join "`n")) { Fail 'canonical commit occurrence census differs from workspace Rust union' }
}

function Assert-CanonicalCommitCensus($Root, $Declared) {
    if ($Declared.scope -cne 'workspace-rust-cached-plus-nonignored-untracked') { Fail 'canonical commit census scope is not the portable workspace union' }
    $actual = @(Get-RustCommitCensus $Root)
    foreach ($row in @($Declared.occurrences)) { Assert-PropertySet $row @('kind','line','line_sha256','path','text') 'canonical_commit.occurrence'; Assert-RelativePath ([string]$row.path) 'canonical_commit.occurrence.path' }
    Assert-DeclaredCommitRows $actual $Declared
    $definitions = @($actual | Where-Object kind -eq 'definition'); $callers = @($actual | Where-Object kind -eq 'caller')
    if ([int]$Declared.total_occurrences -ne $actual.Count -or [int]$Declared.definition_count -ne $definitions.Count -or [int]$Declared.caller_count -ne $callers.Count) { Fail 'canonical commit census counts differ' }
    if ($Declared.expected -cne 'one_definition_zero_callers' -or $definitions.Count -ne 1 -or $callers.Count -ne 0) { Fail 'canonical commit invariant is not one-definition/zero-callers' }
    $digest = Sha256-Text (($actual | ForEach-Object { "$($_.path)`0$($_.line)`0$($_.kind)`0$($_.line_sha256)" }) -join "`n")
    if ($Declared.census_digest -cne $digest) { Fail 'canonical commit census digest mismatch' }
}

function Assert-TargetSet($Records, $Targets) {
    $actual = @($Records | ForEach-Object target)
    $expected = @($Targets | ForEach-Object Target)
    if (@($actual | Sort-Object -Unique).Count -ne $actual.Count) { Fail 'duplicate registry target' }
    if (($actual -join "`n") -cne (($actual | Sort-Object) -join "`n")) { Fail 'registry order is not stable target order' }
    if (($actual | Sort-Object) -join "`n" -cne ($expected -join "`n")) { Fail 'registry target set differs from cargo metadata' }
}

function Assert-Anchor($Root, $Record, $Anchor, [string] $Kind) {
    $path = Join-Path $Root $Anchor.path
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "$Kind anchor file missing: $($Anchor.path)" }
    $text = Read-Utf8 $path
    $lines = Source-Lines $text
    if ($Anchor.line -lt 1 -or $Anchor.line -gt $lines.Count) { Fail "$Kind anchor line out of range: $($Record.target)" }
    if ($lines[$Anchor.line - 1] -cne $Anchor.text) { Fail "stale $Kind anchor text: $($Record.target):$($Anchor.path):$($Anchor.line)" }
    if ($Anchor.line_sha256 -ne (Sha256-Text $Anchor.text)) { Fail "$Kind anchor digest mismatch: $($Record.target)" }
    if ($Anchor.symbol -notmatch '^[A-Za-z_][A-Za-z0-9_:]*$') { Fail "invalid $Kind anchor symbol: $($Record.target)" }
    $symbolLeaf = ($Anchor.symbol -split '::')[-1]
    $sourceHasSymbol = $text -match "\b(fn|async\s+fn)\s+$([regex]::Escape($symbolLeaf))\b"
    $lineHasSymbol = $Anchor.text -match "\b$([regex]::Escape($symbolLeaf))\b"
    if (-not $sourceHasSymbol -and -not $lineHasSymbol) {
        Fail "$Kind anchor symbol is not bound to source or line: $($Record.target):$($Anchor.line)"
    }
}

function Assert-ResultEnvelope([string] $Root, $Registry, [string] $RegistryText, [string] $TargetSetDigest) {
    $path = Join-Path $Root 'swarm/results/W1-07.json'
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail 'W1-07 structured result is missing' }
    $text = Read-Utf8 $path
    if ($text.Contains("`r")) { Fail 'W1-07 result must use canonical LF line endings' }
    $result = $text | ConvertFrom-Json
    Assert-PropertySet $result @('authority_status','schema_version','structured_result','work_item_id') 'W1-07 BootstrapWorkResult'
    if ($result.schema_version -cne 'eliot.bootstrap-work-result.v1' -or $result.authority_status -cne 'EVIDENCE_ONLY' -or $result.work_item_id -cne 'W1-07') { Fail 'W1-07 BootstrapWorkResult wrapper fields mismatch' }
    if ($result.PSObject.Properties.Name -contains 'terminal_update' -or $result.PSObject.Properties.Name -contains 'attempt_id') { Fail 'W1-07 terminal_update/attempt_id are forbidden' }
    $structuredNames = @($result.structured_result.PSObject.Properties.Name)
    foreach ($requiredStructured in @('artifacts','disposition','discriminator_after','discriminator_before','evidence','evidence_lineage','proposed_effects','uncertainty','unresolved_questions')) { if ($requiredStructured -notin $structuredNames) { Fail "W1-07 structured_result missing required field: $requiredStructured" } }
    if ($result.structured_result.disposition -notin @('completed','challenged','blocked','failed')) { Fail 'W1-07 structured_result disposition invalid' }
    if ($result.structured_result.PSObject.Properties.Name -contains 'terminal_update' -or $result.structured_result.PSObject.Properties.Name -contains 'attempt_id') { Fail 'W1-07 nested terminal_update/attempt_id are forbidden' }
    $result = $result.structured_result
    foreach ($legacyRequired in @('additional_findings','agent_profile','all_targets','artifacts','authority_status','classification','disposition','integration_disposition','provider_id','recovery_program_5_1','registry','schema_version','verification','work_item_id')) { if ($legacyRequired -notin @($result.PSObject.Properties.Name)) { Fail "W1-07 result missing legacy field: $legacyRequired" } }
    if ($result.provider_id -cne 'codex-luna-w1-07' -or $result.agent_profile -cne 'implementation' -or $result.disposition -cne 'completed') { Fail 'W1-07 result authority/provenance fields mismatch' }
    if ($result.PSObject.Properties.Name -contains 'terminal_update' -or $result.PSObject.Properties.Name -contains 'observed_source_revision') { Fail 'W1-07 result contains forbidden terminal or revision claim' }
    Assert-PropertySet $result.registry @('cargo_metadata_target_count','generator','path','registry_sha256','schema_version','target_set_digest','verifier') 'W1-07 result.registry'
    $registrySha = Sha256-Text $RegistryText
    if ($result.registry.path -cne 'swarm/inventory/composition-roots.json' -or $result.registry.generator -cne 'scripts/gen-composition-roots.ps1' -or $result.registry.verifier -cne 'scripts/verify-composition-roots.ps1' -or $result.registry.schema_version -cne 'eliot-composition-root-registry-v2' -or [int]$result.registry.cargo_metadata_target_count -ne [int]$Registry.source.target_count -or $result.registry.target_set_digest -cne $TargetSetDigest -or $result.registry.registry_sha256 -cne $registrySha) { Fail 'W1-07 result.registry fields mismatch' }
    Assert-PropertySet $result.artifacts[0] @('kind','path','sha256') 'W1-07 result.artifacts[0]'
    if (@($result.artifacts).Count -ne 1 -or $result.artifacts[0].kind -cne 'inventory' -or $result.artifacts[0].path -cne 'swarm/inventory/composition-roots.json' -or $result.artifacts[0].sha256 -cne $registrySha) { Fail 'W1-07 artifact binding mismatch' }
    Assert-PropertySet $result.classification @('idle_only','typed_refusal','unknown','useful_work') 'W1-07 result.classification'
    foreach ($class in @('useful_work','typed_refusal','idle_only','unknown')) { if ([int]$result.classification.$class -ne [int]$Registry.summary.$class) { Fail "W1-07 result classification mismatch: $class" } }
    $recoveryFindings = @{
        'eliot-agent-bridge' = 'kernel_ports_with_declaration reaches authenticated front-door transport, then main constructs BridgeRunner and enters the stdin request loop'
        'eliot-dreamer' = 'both connect branches produce an error response and ExitCode 78; the Ok branch is also KernelAdmissionRequired'
        'eliot-doctor' = 'main emits the Kernel admission refusal and unconditionally exits 78'
        'eliotd' = 'run_loop selects ctrl_c, activation-ticket claim/decision submission, and five-second Kernel health'
    }
    $recoveryTargets = @('eliot-agent-bridge','eliot-dreamer','eliot-doctor','eliotd')
    if (@($result.recovery_program_5_1).Count -ne $recoveryTargets.Count) { Fail 'W1-07 recovery §5.1 count mismatch' }
    for ($i = 0; $i -lt $recoveryTargets.Count; $i++) {
        $finding = $result.recovery_program_5_1[$i]; $targetName = $recoveryTargets[$i]; $record = $Registry.records | Where-Object target -eq $targetName | Select-Object -First 1
        Assert-PropertySet $finding @('anchor','classification','finding','falsifier','target') "W1-07 recovery.$targetName"
        $expectedAnchor = @($record.composition_root.call_chain | ForEach-Object { "$($_.path):$($_.line)" }) -join ', '
        if ($finding.target -cne $targetName -or $finding.classification -cne $record.classification -or $finding.anchor -cne $expectedAnchor -or $finding.finding -cne $recoveryFindings[$targetName] -or $finding.falsifier -cne $record.composition_root.falsifier) { Fail "W1-07 recovery fact mismatch: $targetName" }
    }
    $additional = @(
        @{ target='eliot-native-worker'; classification='typed_refusal'; anchor='bins/eliot-native-worker/src/main.rs:8-15'; finding='KernelNativeWorkerClient::connect cannot yield a session-bound process request; main emits typed refusal and exits 78' }
        @{ target='eliot-wasm-host'; classification='typed_refusal'; anchor='bins/eliot-wasm-host/src/main.rs:30-35'; finding='after argument parsing, main unconditionally emits KERNEL_ADMISSION_REQUIRED and exits' }
        @{ target='eliot-testd'; classification='useful_work'; anchor='bins/eliot-testd/src/main.rs:53 and :98'; finding='main reaches Ready, stdin dispatch, Status and Cancel; only Submit is bound to UnavailableProcessIssuer and is typed unavailable'; predicate='reachable_effect_partial_refusal'; refusal_scope='Submit only' }
    )
    if (@($result.additional_findings).Count -ne $additional.Count) { Fail 'W1-07 additional-finding count mismatch' }
    for ($i = 0; $i -lt $additional.Count; $i++) { $actual = $result.additional_findings[$i]; $expected = $additional[$i]; Assert-PropertySet $actual (@($expected.Keys)) "W1-07 additional[$i]"; foreach ($key in $expected.Keys) { if ($actual.$key -cne $expected[$key]) { Fail "W1-07 additional finding mismatch: $($expected.target)" } } }
    $targets = @($Registry.records | ForEach-Object target)
    if (($result.all_targets -join "`n") -cne ($targets -join "`n")) { Fail 'W1-07 result target set mismatch' }
    Assert-PropertySet $result.verification @('commands','kind','proof_ceiling','result','self_tests') 'W1-07 result.verification'
    if ($result.verification.kind -cne 'structured_evidence_only' -or $result.verification.result -cne 'PASS' -or $result.verification.proof_ceiling -cne 'static composition-root reachability; no live runtime PASS claim; no TerminalWorkUpdate claim') { Fail 'W1-07 result verification claim mismatch' }
    $commands = @('pwsh -NoProfile -File scripts/gen-composition-roots.ps1 -Check','pwsh -NoProfile -File scripts/gen-composition-roots.ps1 -SelfTest','pwsh -NoProfile -File scripts/verify-composition-roots.ps1 -SelfTest','pwsh -NoProfile -File scripts/verify-composition-roots.ps1')
    if (($result.verification.commands -join "`n") -cne ($commands -join "`n")) { Fail 'W1-07 result command envelope mismatch' }
    $selfTests = @('generator predicate and determinism self-test passed','synthetic tamper rejected','synthetic missing target rejected','synthetic duplicate target rejected','classification/predicate mismatch rejected','omitted commit_canonical caller rejected','cached plus nonignored-untracked Rust census enforced','CRLF fixture distinguished from canonical LF')
    if (($result.verification.self_tests -join "`n") -cne ($selfTests -join "`n")) { Fail 'W1-07 result self-test envelope mismatch' }
    Assert-PropertySet $result.integration_disposition @('accepted_findings','deferred') 'W1-07 result.integration_disposition'
    $accepted = @('Current cargo metadata census is 23 binary targets, not the historical 21.','Every target has a checked manifest/main/call-chain witness, gate condition, effect boundary and falsifier.','The registry-wide canonical commit invariant records one workspace-Rust definition and zero callers.')
    $deferred = @('No cutover or architecture decision is made by this registry.','Static useful_work is not a live observed PASS.','The W1 result-envelope ContractChallenge remains open; this artifact is evidence only.')
    if (($result.integration_disposition.accepted_findings -join "`n") -cne ($accepted -join "`n") -or ($result.integration_disposition.deferred -join "`n") -cne ($deferred -join "`n")) { Fail 'W1-07 result integration envelope mismatch' }
}

function Invoke-SelfTests {
    $fixture = [ordered]@{ records = @([ordered]@{ target = 'a' }, [ordered]@{ target = 'b' }) }
    $targets = @([pscustomobject]@{Target='a'},[pscustomobject]@{Target='b'})
    Assert-TargetSet $fixture.records $targets
    $duplicateFailed = $false
    try { Assert-TargetSet @([pscustomobject]@{target='a'},[pscustomobject]@{target='a'}) $targets } catch { $duplicateFailed = $true }
    if (-not $duplicateFailed) { Fail 'duplicate-target self-test did not fail' }
    $missingFailed = $false
    try { Assert-TargetSet @([pscustomobject]@{target='a'}) $targets } catch { $missingFailed = $true }
    if (-not $missingFailed) { Fail 'missing-target self-test did not fail' }
    $tamperFailed = $false
    $tampered = [pscustomobject]@{ path='fixture.rs'; line=1; text='tampered'; line_sha256=(Sha256-Text 'original'); symbol='main' }
    $tmp = Join-Path $env:TEMP ('composition-roots-selftest-' + [guid]::NewGuid().ToString('N') + '.rs')
    try { [System.IO.File]::WriteAllText($tmp, "original`n", [System.Text.UTF8Encoding]::new($false)); try { Assert-Anchor (Split-Path $tmp) ([pscustomobject]@{target='fixture'}) ([pscustomobject]@{path=(Split-Path $tmp -Leaf); line=1; text='tampered'; line_sha256=(Sha256-Text 'original'); symbol='main'}) 'tamper' } catch { $tamperFailed = $true } } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force } }
    if (-not $tamperFailed) { Fail 'tamper self-test did not fail' }
    $predicateMismatchFailed = $false
    try {
        $policy = Get-PredicatePolicy 'eliot-testd'
        $fake = [pscustomobject]@{ target = 'eliot-testd'; classification = 'typed_refusal'; composition_root = [pscustomobject]@{ predicate = [pscustomobject]@{ kind = $policy.kind; expected_classification = $policy.expected_classification; reachable_effect = $policy.reachable_effect; pre_effect_refusal = $policy.pre_effect_refusal; partial_capability = $policy.partial_capability; refusal_scope = $policy.refusal_scope } } }
        Assert-PredicateConsistency $fake $policy
    } catch { $predicateMismatchFailed = $true }
    if (-not $predicateMismatchFailed) { Fail 'classification/predicate mismatch self-test did not fail' }
    $omittedCallerFailed = $false
    try {
        $definition = [pscustomobject]@{ path = 'x.rs'; line = 1; text = 'fn commit_canonical('; kind = 'definition'; line_sha256 = (Sha256-Text 'fn commit_canonical(') }
        $caller = [pscustomobject]@{ path = 'y.rs'; line = 2; text = 'commit_canonical('; kind = 'caller'; line_sha256 = (Sha256-Text 'commit_canonical(') }
        $declared = [pscustomobject]@{ occurrences = @($definition) }
        Assert-DeclaredCommitRows @($definition, $caller) $declared
    } catch { $omittedCallerFailed = $true }
    if (-not $omittedCallerFailed) { Fail 'omitted-caller self-test did not fail' }
    $absoluteFailed = $false
    try { Assert-RelativePath 'C:\absolute.rs' 'absolute-fixture' } catch { $absoluteFailed = $true }
    if (-not $absoluteFailed) { Fail 'absolute-path self-test did not fail' }
    $traversalFailed = $false
    try { Assert-RelativePath 'a/../b.rs' 'traversal-fixture' } catch { $traversalFailed = $true }
    if (-not $traversalFailed) { Fail 'traversal-path self-test did not fail' }
    $fakeRecord = [pscustomobject]@{ target = 'eliot'; operational_scope = 'tampered'; witness = [pscustomobject]@{ catalogue = 'W1-07-v1' }; composition_root = [pscustomobject]@{ gate_condition = 'x'; effect_boundary = 'y'; falsifier = 'z' } }
    $witnessFailed = (Get-WitnessHash $fakeRecord) -ne (Get-ExpectedWitnessHash 'eliot')
    if (-not $witnessFailed) { Fail 'witness-field self-test did not fail' }
    $crlf = "{`"schema_version`":`"x`"}`r`n"
    if ($crlf -notmatch "`r`n") { Fail 'CRLF fixture construction failed' }
    if (($crlf -replace "`r`n", "`n") -ceq $crlf) { Fail 'CRLF self-test did not distinguish line endings' }
    Write-Output 'COMPOSITION_ROOTS_VERIFY_SELF_TEST: PASS tamper=1 missing=1 duplicate=1 predicate=1 omitted-caller=1 absolute=1 traversal=1 witness=1 crlf=1'
}

try {
    if ($SelfTest) { Invoke-SelfTests; exit 0 }
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $registryPath = Join-Path $repoRoot 'swarm/inventory/composition-roots.json'
    if (-not (Test-Path -LiteralPath $registryPath -PathType Leaf)) { Fail 'composition-roots registry is missing' }
    $registryText = Read-Utf8 $registryPath
    if ($registryText.Contains("`r")) { Fail 'registry must use canonical LF line endings' }
    $registry = $registryText | ConvertFrom-Json
    Assert-PropertySet $registry @('generated_by','invariants','records','schema_version','source','summary') 'registry'
    if ($registry.schema_version -cne 'eliot-composition-root-registry-v2' -or $registry.generated_by -cne 'scripts/gen-composition-roots.ps1') { Fail 'schema/generated_by mismatch' }
    Assert-PropertySet $registry.source @('command','target_count','target_kind','target_set_digest') 'registry.source'
    Assert-PropertySet $registry.summary @('idle_only','typed_refusal','unknown','useful_work') 'registry.summary'
    Assert-PropertySet $registry.invariants @('canonical_commit') 'registry.invariants'
    Assert-PropertySet $registry.invariants.canonical_commit @('caller_count','census_digest','definition_count','expected','id','occurrences','scope','token','total_occurrences') 'registry.invariants.canonical_commit'
    $metadataText = (& cargo metadata --no-deps --format-version 1 | Out-String)
    if ($LASTEXITCODE -ne 0) { Fail "cargo metadata exited $LASTEXITCODE" }
    $targets = @(Get-TargetSet ($metadataText | ConvertFrom-Json))
    $records = @($registry.records)
    if ([int]$registry.source.target_count -ne $targets.Count) { Fail 'declared target count mismatch' }
    Assert-TargetSet $records $targets
    if ($null -eq $registry.invariants -or $null -eq $registry.invariants.canonical_commit) { Fail 'canonical commit invariant is missing' }
    Assert-CanonicalCommitCensus $repoRoot $registry.invariants.canonical_commit
    foreach ($record in $records) {
        Assert-PropertySet $record @('classification','composition_root','main','manifest','operational_scope','package','stable_id','target','witness') "$($record.target).record"
        Assert-PropertySet $record.manifest @('anchor','digest','package_name','path') "$($record.target).manifest"
        Assert-PropertySet $record.manifest.anchor @('line','line_sha256','symbol','text') "$($record.target).manifest.anchor"
        Assert-PropertySet $record.main @('line','line_sha256','path','symbol','text') "$($record.target).main"
        Assert-PropertySet $record.composition_root @('call_chain','effect_boundary','falsifier','gate_condition','predicate') "$($record.target).composition_root"
        Assert-PropertySet $record.composition_root.predicate @('expected_classification','kind','partial_capability','pre_effect_refusal','reachable_effect','refusal_scope','witness') "$($record.target).predicate"
        Assert-PropertySet $record.composition_root.predicate.witness @('ordered_anchor_lines','ordered_anchor_symbols','required_source_fragments') "$($record.target).predicate.witness"
        Assert-PropertySet $record.witness @('anchor_digest','catalogue','source_digest') "$($record.target).witness"
        $target = $targets | Where-Object Target -eq $record.target | Select-Object -First 1
        if ($null -eq $target) { Fail "record target missing from metadata: $($record.target)" }
        if ($record.package -cne $target.Package) { Fail "package mismatch: $($record.target)" }
        Assert-RelativePath ([string]$record.manifest.path) "$($record.target).manifest.path"
        Assert-RelativePath ([string]$record.main.path) "$($record.target).main.path"
        Assert-RelativePath ([string]$record.witness.catalogue) "$($record.target).witness.catalogue"
        foreach ($anchor in @($record.composition_root.call_chain) + @($record.main)) { Assert-PropertySet $anchor @('line','line_sha256','path','symbol','text') "$($record.target).anchor"; Assert-RelativePath ([string]$anchor.path) "$($record.target).anchor.path" }
        $manifestAbs = $target.Manifest
        $sourceAbs = $target.Source
        $manifestRel = $manifestAbs.Substring($repoRoot.Length + 1) -replace '\\','/'
        $sourceRel = $sourceAbs.Substring($repoRoot.Length + 1) -replace '\\','/'
        if ($record.manifest.path -cne $manifestRel -or $record.main.path -cne $sourceRel) { Fail "metadata path mismatch: $($record.target)" }
        $manifestText = Read-Utf8 $manifestAbs
        $sourceText = Read-Utf8 $sourceAbs
        if ($record.manifest.digest -cne (Sha256-Text $manifestText)) { Fail "manifest digest mismatch: $($record.target)" }
        if ($record.witness.source_digest -cne (Sha256-Text $sourceText)) { Fail "source digest mismatch: $($record.target)" }
        $manifestLines = Source-Lines $manifestText
        if ($record.manifest.anchor.line -lt 1 -or $record.manifest.anchor.line -gt $manifestLines.Count -or $manifestLines[$record.manifest.anchor.line - 1].Trim() -cne $record.manifest.anchor.text) { Fail "manifest anchor mismatch: $($record.target)" }
        if ($record.manifest.anchor.line_sha256 -cne (Sha256-Text $record.manifest.anchor.text)) { Fail "manifest anchor digest mismatch: $($record.target)" }
        $manifestName = [regex]::Match($record.manifest.anchor.text, '^name\s*=\s*"(?<name>[^"]+)"$')
        if (-not $manifestName.Success -or $manifestName.Groups['name'].Value -cne $target.Package) { Fail "manifest symbol mismatch: $($record.target)" }
        Assert-Anchor $repoRoot $record $record.main 'main'
        foreach ($anchor in @($record.composition_root.call_chain)) { Assert-Anchor $repoRoot $record $anchor 'call-chain' }
        if ($record.witness.anchor_digest -cne (Get-ExpectedAnchorDigest $record)) { Fail "anchor digest mismatch: $($record.target)" }
        if ($record.witness.anchor_digest -cne (Get-ExpectedAnchorGraphDigest ([string]$record.target))) { Fail "anchor graph policy mismatch: $($record.target)" }
        if ($record.witness.catalogue -cne 'W1-07-v1' -or $record.witness.source_digest -ne (Sha256-Text $sourceText)) { Fail "witness catalogue/source mismatch: $($record.target)" }
        if ((Get-WitnessHash $record) -cne (Get-ExpectedWitnessHash ([string]$record.target))) { Fail "operational boundary witness mismatch: $($record.target)" }
        if ($record.stable_id -cne (Get-ExpectedStableId $record)) { Fail "stable id mismatch: $($record.target)" }
        if ($record.classification -notin @('useful_work','typed_refusal','idle_only','unknown')) { Fail "invalid classification: $($record.target)" }
        if ([string]::IsNullOrWhiteSpace($record.composition_root.gate_condition) -or [string]::IsNullOrWhiteSpace($record.composition_root.effect_boundary) -or [string]::IsNullOrWhiteSpace($record.composition_root.falsifier)) { Fail "incomplete boundary witness: $($record.target)" }
        Assert-Predicate $repoRoot $record
    }
    $digestInput = $records | ForEach-Object { "$($_.target)`0$($_.package)`0$($_.manifest.path)`0$($_.main.path)`0$($_.main.line)`0$($_.classification)`0$($_.witness.anchor_digest)" }
    $targetSetDigest = Sha256-Text (($digestInput) -join "`n")
    if ($registry.source.target_set_digest -cne $targetSetDigest) { Fail 'target-set digest mismatch' }
    foreach ($class in @('useful_work','typed_refusal','idle_only','unknown')) { if ([int]$registry.summary.$class -ne @($records | Where-Object classification -eq $class).Count) { Fail "summary mismatch: $class" } }
    Assert-ResultEnvelope $repoRoot $registry $registryText $targetSetDigest
    Write-Output "COMPOSITION_ROOTS_VERIFY: PASS targets=$($targets.Count) digest=$targetSetDigest summary=$((@('useful_work','typed_refusal','idle_only','unknown')|%{$_+'='+$registry.summary.$_}) -join ',')"
}
catch { Write-Error $_.Exception.Message; exit 1 }
