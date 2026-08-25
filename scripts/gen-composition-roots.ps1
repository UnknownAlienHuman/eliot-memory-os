[CmdletBinding()]
param(
    [switch] $Check,
    [string] $OutputPath,
    [string] $ResultPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail([string] $Message) { throw "COMPOSITION_ROOTS_GENERATE_FAIL: $Message" }

function Sha256-Bytes([byte[]] $Bytes) {
    [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Sha256-Text([string] $Text) { Sha256-Bytes ([System.Text.Encoding]::UTF8.GetBytes($Text)) }

function Read-Utf8([string] $Path) {
    [System.IO.File]::ReadAllText($Path, [System.Text.UTF8Encoding]::new($false, $true))
}

function Source-Lines([string] $Text) { [regex]::Split($Text, "`r`n|`n|`r") }

function Match-LineNumber([string] $Text, [int] $Index) {
    1 + ([regex]::Matches($Text.Substring(0, $Index), "`n")).Count
}

function Resolve-Relative([string] $Root, [string] $Path) {
    (Resolve-Path (Join-Path $Root $Path)).Path
}

function Get-PredicateDefinition([string] $Target, [string] $Classification) {
    $definitions = @{
        'eliot' = @{ kind = 'reachable_effect'; required = @('match cli.command') }
        'eliot-agent-bridge' = @{ kind = 'pre_effect_typed_refusal'; required = @('pub fn kernel_ports()', 'Err(RuntimeBuildError::KernelAdmissionRequired(', 'std::process::exit(PROVIDER_PORT_EXIT);') }
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
        'eliot-runtime-compiler' = @{ kind = 'reachable_effect'; required = @('compile(&CompileOptions', 'println!') }
        'eliot-store-surreal' = @{ kind = 'reachable_effect'; required = @('NamedPipeServer::create(', 'loop {') }
        'eliot-testd' = @{ kind = 'reachable_effect_partial_refusal'; required = @('UnavailableProcessIssuer', '&Response::Ready', 'for line in io::stdin().lock().lines()', 'Request::Submit', 'Request::Status', 'Request::Cancel') }
        'eliot-user-broker' = @{ kind = 'reachable_effect'; required = @('BrokerComposition::start_with_kernel(', 'dispatch(&mut composition') }
        'eliot-wasm-host' = @{ kind = 'pre_effect_typed_refusal'; required = @('parse_args(', 'std::process::exit(ADMISSION_REQUIRED_EXIT);') }
        'eliot-watchdog' = @{ kind = 'reachable_effect'; required = @('run_watchdog(', 'IndependentKernelSensor::') }
        'eliotd' = @{ kind = 'idle_only'; required = @('tokio::select!', 'tokio::signal::ctrl_c()', 'tokio::time::sleep', 'KernelTransitionPort::health') }
    }
    if (-not $definitions.ContainsKey($Target)) { Fail "missing predicate definition for target $Target" }
    $definition = $definitions[$Target]
    $expectedClassification = switch ([string]$definition.kind) {
        'reachable_effect' { 'useful_work' }
        'reachable_effect_partial_refusal' { 'useful_work' }
        'pre_effect_typed_refusal' { 'typed_refusal' }
        'idle_only' { 'idle_only' }
        default { 'unknown' }
    }
    if ($Classification -cne $expectedClassification) { Fail "catalogue classification/predicate mismatch for ${Target}: $Classification vs $expectedClassification" }
    [pscustomobject]@{ kind = [string]$definition.kind; expected_classification = $expectedClassification; required_source_fragments = @($definition.required); reachable_effect = $definition.kind -in @('reachable_effect','reachable_effect_partial_refusal'); pre_effect_refusal = $definition.kind -in @('pre_effect_typed_refusal','reachable_effect_partial_refusal'); partial_capability = $definition.kind -eq 'reachable_effect_partial_refusal'; refusal_scope = if ($definition.kind -eq 'reachable_effect_partial_refusal') { 'Submit only' } else { $null } }
}

function Get-RustCommitCensus([string] $Root) {
    $cached = @(& git -C $Root ls-files --cached -- '*.rs')
    if ($LASTEXITCODE -ne 0) { Fail "git cached Rust census exited $LASTEXITCODE" }
    $untracked = @(& git -C $Root ls-files --others --exclude-standard -- '*.rs')
    if ($LASTEXITCODE -ne 0) { Fail "git untracked Rust census exited $LASTEXITCODE" }
    $paths = @($cached + $untracked | ForEach-Object { ([string]$_).Replace('\','/') } | Sort-Object -Unique)
    $entries = [System.Collections.Generic.List[object]]::new()
    foreach ($relative in $paths) {
        $relative = ([string]$relative).Replace('\','/')
        $absolute = Join-Path $Root $relative
        $lines = Source-Lines (Read-Utf8 $absolute)
        for ($index = 0; $index -lt $lines.Count; $index++) {
            $line = [string]$lines[$index]
            if ($line -notmatch '\bcommit_canonical\s*\(') { continue }
            $kind = if ($line -match '\bfn\s+commit_canonical\s*\(') { 'definition' } else { 'caller' }
            $entries.Add([pscustomobject]@{ path = $relative; line = $index + 1; text = $line; kind = $kind; line_sha256 = Sha256-Text $line })
        }
    }
    @($entries | Sort-Object path, line, kind)
}

# This is deliberately a checked catalogue, rather than a regex classification.
# Every witness is tied to a source line and a symbol; stale source fails closed.
$catalogueJson = @'
[
  {"target":"eliot","classification":"useful_work","operational_scope":"product_cli","main":{"path":"bins/eliot/src/main.rs","line":324,"symbol":"main","text":"fn main() -> Result<()> {"},"call_chain":[{"path":"bins/eliot/src/main.rs","line":338,"symbol":"run","text":"fn run() -> Result<i32> {"},{"path":"bins/eliot/src/main.rs","line":341,"symbol":"run","text":"    match cli.command {"}],"gate_condition":"valid CLI command and its command-specific admission/configuration gates","effect_boundary":"CommandPort and governed command handlers; effects remain behind the selected command port","falsifier":"A current main-to-run path reaches only typed refusal or no command handler for every command"},
  {"target":"eliot-agent-bridge","classification":"typed_refusal","operational_scope":"product_ingress","main":{"path":"bins/eliot-agent-bridge/src/main.rs","line":48,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-agent-bridge/src/main.rs","line":65,"symbol":"kernel_ports","text":"    let (host_activation, mcp_forwarding) = match kernel_ports() {"},{"path":"bins/eliot-agent-bridge/src/lib.rs","line":451,"symbol":"kernel_ports","text":"pub fn kernel_ports() -> Result<KernelPorts, RuntimeBuildError> {"},{"path":"bins/eliot-agent-bridge/src/lib.rs","line":457,"symbol":"kernel_ports","text":"    Err(RuntimeBuildError::KernelAdmissionRequired("},{"path":"bins/eliot-agent-bridge/src/main.rs","line":155,"symbol":"main","text":"        std::process::exit(PROVIDER_PORT_EXIT);"},{"path":"bins/eliot-agent-bridge/src/main.rs","line":93,"symbol":"main","text":"    for line in io::stdin().lock().lines() {"}],"gate_condition":"Kernel admission must provide both bridge ports before stdin is consumed","effect_boundary":"Attach/forward frames are downstream of kernel_ports; no effect is reached when the provider rejects","falsifier":"kernel_ports has a reachable Ok branch that supplies admitted ports and main enters the request loop"},
  {"target":"eliot-campaign-executor","classification":"useful_work","operational_scope":"test_only","main":{"path":"workspace/tools/eliot-campaign-executor/src/main.rs","line":914,"symbol":"main","text":"fn main() -> ExitCode {"},"call_chain":[{"path":"workspace/tools/eliot-campaign-executor/src/main.rs","line":830,"symbol":"dispatch","text":"fn dispatch(command: Option<Command>) -> Result<(Value, bool)> {"},{"path":"workspace/tools/eliot-campaign-executor/src/main.rs","line":804,"symbol":"apply","text":"fn apply(campaign_root: PathBuf, command: String) -> Result<Value> {"}],"gate_condition":"valid campaign command and trusted campaign-root inputs","effect_boundary":"campaign receipt/evidence files under the supplied campaign root","falsifier":"main can no longer reach dispatch or dispatch has no non-refusal command branch"},
  {"target":"eliot-credential-suite-guard","classification":"useful_work","operational_scope":"test_only","main":{"path":"crates/eliot-windows-ipc/src/bin/eliot-credential-suite-guard.rs","line":15,"symbol":"main","text":"fn main() -> io::Result<()> {"},"call_chain":[{"path":"crates/eliot-windows-ipc/src/bin/eliot-credential-suite-guard.rs","line":22,"symbol":"isolated_operator_cursor_credentials","text":"    let current = isolated_operator_cursor_credentials()?;"},{"path":"crates/eliot-windows-ipc/src/bin/eliot-credential-suite-guard.rs","line":23,"symbol":"main","text":"    match action.to_str() {"}],"gate_condition":"exact snapshot/verify action and manifest path arguments","effect_boundary":"credential snapshot write or verification read under the supplied manifest path","falsifier":"both actions become unconditional usage/refusal with no credential observation or manifest effect"},
  {"target":"eliot-doctor","classification":"typed_refusal","operational_scope":"recovery","main":{"path":"bins/eliot-doctor/src/main.rs","line":7,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-doctor/src/main.rs","line":15,"symbol":"main","text":"    std::process::exit(EXIT_KERNEL_ADMISSION_REQUIRED);"}],"gate_condition":"Kernel must advertise and admit the Doctor operation","effect_boundary":"No diagnostic operation is entered; stderr refusal is the only effect","falsifier":"main has any reachable branch that performs a diagnostic operation and returns success"},
  {"target":"eliot-dreamer","classification":"typed_refusal","operational_scope":"product_dreamer","main":{"path":"bins/eliot-dreamer/src/main.rs","line":15,"symbol":"main","text":"fn main() -> ExitCode {"},"call_chain":[{"path":"bins/eliot-dreamer/src/main.rs","line":17,"symbol":"main","text":"    let error = match AuthenticatedKernelJobPort::connect() {"},{"path":"bins/eliot-dreamer/src/main.rs","line":25,"symbol":"main","text":"    ExitCode::from(KERNEL_ADMISSION_EXIT)"}],"gate_condition":"authenticated Kernel job admission with session-bound identity","effect_boundary":"Only serialized error response is emitted; no dream job submission is reached","falsifier":"the Ok(connect()) branch constructs a usable admitted job port and a success exit path"},
  {"target":"eliot-governor","classification":"useful_work","operational_scope":"product_governor","main":{"path":"crates/eliot-app/src/main.rs","line":2001,"symbol":"main","text":"fn main() -> Result<()> {"},"call_chain":[{"path":"crates/eliot-app/src/main.rs","line":2010,"symbol":"main","text":"            let cli = Cli::parse();"},{"path":"crates/eliot-app/src/main.rs","line":2021,"symbol":"dispatch_command","text":"            runtime.block_on(Box::pin(dispatch_command("}],"gate_condition":"valid CLI command plus configured runtime and command-specific authority gates","effect_boundary":"Governor command handlers and their governed app/store ports","falsifier":"the spawned main thread cannot reach dispatch_command for any command"},
  {"target":"eliot-host","classification":"useful_work","operational_scope":"product_host","main":{"path":"bins/eliot-host/src/main.rs","line":39,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-host/src/main.rs","line":53,"symbol":"run_console","text":"    if !run_console() {"},{"path":"bins/eliot-host/src/main.rs","line":68,"symbol":"open_host","text":"    let mut host = match open_host(launch_options) {"},{"path":"bins/eliot-host/src/main.rs","line":124,"symbol":"dispatch","text":"fn dispatch(host: &mut HostComposition, line: &str) -> (Response, bool) {"}],"gate_condition":"SCM or console launch bootstrap and HostComposition admission","effect_boundary":"Host lifecycle/process dispatch through HostComposition","falsifier":"all launch modes terminate before open_host or dispatch with typed refusal"},
  {"target":"eliot-kernel","classification":"useful_work","operational_scope":"product_kernel","main":{"path":"bins/eliot-kernel/src/main.rs","line":189,"symbol":"main","text":"async fn main() {"},"call_chain":[{"path":"bins/eliot-kernel/src/main.rs","line":190,"symbol":"parse_launch_options","text":"    let options = match parse_launch_options(std::env::args_os().skip(1)) {"},{"path":"bins/eliot-kernel/src/main.rs","line":212,"symbol":"KernelConfig::new","text":"        KernelConfig::new(options.work_root.clone()).require_descriptor_supervision_authority();"}],"gate_condition":"validated launch, host binding, store bootstrap, and eliotd descriptor","effect_boundary":"authenticated Kernel control pipe and admitted runtime services","falsifier":"all validated launch inputs still end before Kernel listener/service composition"},
  {"target":"eliot-live-canary","classification":"useful_work","operational_scope":"test_only","main":{"path":"workspace/tools/eliot-live-canary/src/main.rs","line":35,"symbol":"main","text":"async fn main() -> anyhow::Result<()> {"},"call_chain":[{"path":"workspace/tools/eliot-live-canary/src/main.rs","line":45,"symbol":"ProductionCanary::new","text":"    let canary = ProductionCanary::new(config.clone()).map_err(|error| anyhow::anyhow!(error))?;"},{"path":"workspace/tools/eliot-live-canary/src/main.rs","line":47,"symbol":"write_development_evidence","text":"    let publication = write_development_evidence(&config.evidence_dir, pulse, &disposition)"}],"gate_condition":"valid canary arguments and selected live evidence target","effect_boundary":"canary observation/evidence output; fault execution requires explicit flag","falsifier":"main has no branch that invokes the canary runner or emits a result"},
  {"target":"eliot-mod-research","classification":"useful_work","operational_scope":"product_research","main":{"path":"bins/eliot-mod-research/src/main.rs","line":36,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-mod-research/src/main.rs","line":39,"symbol":"compose_from_environment","text":"    let mut researcher = compose_from_environment();"},{"path":"bins/eliot-mod-research/src/main.rs","line":68,"symbol":"submit","text":"        Request::Submit { request } => submit(researcher, request)"}],"gate_condition":"researcher environment and a valid JSON Submit or Cancel request","effect_boundary":"ResearchComposition exchange jobs and response frames","falsifier":"stdin Submit and Cancel requests can no longer reach submit/cancel"},
  {"target":"eliot-native-worker","classification":"typed_refusal","operational_scope":"product_worker","main":{"path":"bins/eliot-native-worker/src/main.rs","line":7,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-native-worker/src/main.rs","line":8,"symbol":"KernelNativeWorkerClient::connect","text":"    let error = match KernelNativeWorkerClient::connect() {"},{"path":"bins/eliot-native-worker/src/main.rs","line":15,"symbol":"main","text":"    std::process::exit(KERNEL_ADMISSION_EXIT);"}],"gate_condition":"session-bound Kernel process request admission","effect_boundary":"Only typed error emission and exit; worker claim never reaches execution","falsifier":"connect has a reachable admitted worker branch followed by useful execution"},
  {"target":"eliot-notify","classification":"useful_work","operational_scope":"product_notify","main":{"path":"bins/eliot-notify/src/main.rs","line":65,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-notify/src/main.rs","line":79,"symbol":"register_watchdog_fallback_task","text":"        let receipt = match eliot_notify::register_watchdog_fallback_task() {"},{"path":"bins/eliot-notify/src/main.rs","line":165,"symbol":"dispatch_deliver","text":"                Ok(mut composition) => dispatch_deliver(&mut composition, &envelope, &request),"}],"gate_condition":"approved launch root and valid register/deliver request","effect_boundary":"watchdog task registration or notification delivery through NotifyComposition","falsifier":"every parsed mode exits before either registration or delivery"},
  {"target":"eliot-opencode-bootstrap","classification":"useful_work","operational_scope":"product_agent","main":{"path":"crates/agent/eliot-agent-opencode/src/bin/eliot-opencode-bootstrap.rs","line":235,"symbol":"main","text":"async fn main() -> ExitCode {"},"call_chain":[{"path":"crates/agent/eliot-agent-opencode/src/bin/eliot-opencode-bootstrap.rs","line":236,"symbol":"run","text":"    match run().await {"},{"path":"crates/agent/eliot-agent-opencode/src/bin/eliot-opencode-bootstrap.rs","line":169,"symbol":"run","text":"async fn run() -> Result<(), CliError> {"},{"path":"crates/agent/eliot-agent-opencode/src/bin/eliot-opencode-bootstrap.rs","line":208,"symbol":"OpenCodeClient::new","text":"    let client = OpenCodeClient::new(endpoint, auth, policy)"}],"gate_condition":"valid loopback endpoint, directory, prompt and authenticated OpenCode server","effect_boundary":"read-only OpenCode run request; no canonical authority claim","falsifier":"run cannot reach OpenCodeClient request for any valid argument set"},
  {"target":"eliot-process-guardian","classification":"useful_work","operational_scope":"test_only","main":{"path":"crates/eliot-windows-ipc/src/bin/eliot-process-guardian.rs","line":181,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"crates/eliot-windows-ipc/src/bin/eliot-process-guardian.rs","line":182,"symbol":"run","text":"    match run() {"},{"path":"crates/eliot-windows-ipc/src/bin/eliot-process-guardian.rs","line":115,"symbol":"SuspendedJobChild::spawn","text":"    let mut child = SuspendedJobChild::spawn(&child_command)?;"},{"path":"crates/eliot-windows-ipc/src/bin/eliot-process-guardian.rs","line":133,"symbol":"run","text":"    loop {"}],"gate_condition":"valid child command and optional timeout/stop request","effect_boundary":"bounded child process supervision and JSON exit evidence","falsifier":"valid child command always exits before spawn or supervision loop"},
  {"target":"eliot-runtime-compiler","classification":"useful_work","operational_scope":"test_only","main":{"path":"workspace/tools/eliot-runtime-compiler/src/main.rs","line":30,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"workspace/tools/eliot-runtime-compiler/src/main.rs","line":31,"symbol":"Args::parse","text":"    let args = Args::parse();"},{"path":"workspace/tools/eliot-runtime-compiler/src/main.rs","line":37,"symbol":"compile","text":"    let receipt = compile(&CompileOptions {"},{"path":"workspace/tools/eliot-runtime-compiler/src/main.rs","line":47,"symbol":"main","text":"    println!(\"{encoded}\");"}],"gate_condition":"valid compiler arguments and source descriptor","effect_boundary":"encoded runtime descriptor emitted to stdout","falsifier":"valid descriptor input cannot reach encoding/output"},
  {"target":"eliot-store-surreal","classification":"useful_work","operational_scope":"product_store","main":{"path":"bins/eliot-store-surreal/src/main.rs","line":42,"symbol":"main","text":"async fn main() {"},"call_chain":[{"path":"bins/eliot-store-surreal/src/main.rs","line":51,"symbol":"run","text":"async fn run() -> Result<(), String> {"},{"path":"bins/eliot-store-surreal/src/main.rs","line":83,"symbol":"NamedPipeServer::create","text":"    let mut server = NamedPipeServer::create(&config.store_pipe, &expectation)"},{"path":"bins/eliot-store-surreal/src/main.rs","line":121,"symbol":"run","text":"    loop {"}],"gate_condition":"valid protected/portable store configuration and semantic readiness","effect_boundary":"Store named-pipe request dispatch and bounded storage operations","falsifier":"a semantically ready configuration cannot reach NamedPipeServer::create or request loop"},
  {"target":"eliot-testd","classification":"useful_work","operational_scope":"test_only","main":{"path":"bins/eliot-testd/src/main.rs","line":49,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-testd/src/main.rs","line":53,"symbol":"TestdComposition::open","text":"    let daemon = match TestdComposition::open(state_path, Arc::new(UnavailableProcessIssuer)) {"},{"path":"bins/eliot-testd/src/main.rs","line":67,"symbol":"main","text":"        &Response::Ready {"},{"path":"bins/eliot-testd/src/main.rs","line":74,"symbol":"main","text":"    for line in io::stdin().lock().lines() {"},{"path":"bins/eliot-testd/src/main.rs","line":88,"symbol":"dispatch","text":"fn dispatch(daemon: &TestdComposition, line: &str) -> Response {"},{"path":"bins/eliot-testd/src/main.rs","line":98,"symbol":"submit","text":"        Request::Submit { request } => daemon.submit(*request),"},{"path":"bins/eliot-testd/src/main.rs","line":99,"symbol":"status","text":"        Request::Status { job_id } => daemon.status(&job_id),"},{"path":"bins/eliot-testd/src/main.rs","line":100,"symbol":"cancel","text":"        Request::Cancel {"}],"gate_condition":"Testd opens state and reaches Ready/stdin/Status/Cancel; Submit remains typed unavailable through UnavailableProcessIssuer","effect_boundary":"Ready/status/cancel transport and receipts are reachable; only core Submit execution is refused","falsifier":"Ready/stdin/Status/Cancel cease to be reachable, or UnavailableProcessIssuer is replaced and Submit reaches a successful process execution receipt"},
  {"target":"eliot-user-broker","classification":"useful_work","operational_scope":"product_broker","main":{"path":"bins/eliot-user-broker/src/main.rs","line":44,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-user-broker/src/main.rs","line":68,"symbol":"BrokerComposition::start_with_kernel","text":"    let mut composition = match BrokerComposition::start_with_kernel(BrokerConfig::from_root(root))"},{"path":"bins/eliot-user-broker/src/main.rs","line":126,"symbol":"dispatch","text":"            Ok(line) => dispatch(&mut composition, &line),"}],"gate_condition":"protected root, Kernel-backed composition, self-registration and admitted request stream","effect_boundary":"broker registration/heartbeat and user request messages","falsifier":"valid admitted broker startup cannot reach composition dispatch"},
  {"target":"eliot-wasm-host","classification":"typed_refusal","operational_scope":"product_wasm","main":{"path":"bins/eliot-wasm-host/src/main.rs","line":13,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-wasm-host/src/main.rs","line":14,"symbol":"parse_args","text":"    let config = match parse_args(std::env::args().skip(1)) {"},{"path":"bins/eliot-wasm-host/src/main.rs","line":35,"symbol":"main","text":"    std::process::exit(ADMISSION_REQUIRED_EXIT);"}],"gate_condition":"Kernel RuntimePorts, admitted artifact, authenticated request loop and live service","effect_boundary":"Only argument validation and typed admission error; no Wasm service starts","falsifier":"a valid profile reaches a live authenticated Wasm request loop"},
  {"target":"eliot-watchdog","classification":"useful_work","operational_scope":"product_watchdog","main":{"path":"bins/eliot-watchdog/src/main.rs","line":23,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliot-watchdog/src/main.rs","line":37,"symbol":"run_watchdog","text":"    if let Err(error) = run_watchdog(Arc::new(AtomicBool::new(false)), None) {"},{"path":"bins/eliot-watchdog/src/main.rs","line":43,"symbol":"run_watchdog","text":"fn run_watchdog("},{"path":"bins/eliot-watchdog/src/main.rs","line":69,"symbol":"IndependentKernelSensor::open_runtime_binding","text":"            Some(admission) => IndependentKernelSensor::open_runtime_binding("}],"gate_condition":"SCM bootstrap and approved Host/Kernel registration; no genesis lease is allowed","effect_boundary":"bounded watchdog observation and heartbeat authority after verified admission","falsifier":"valid admitted bootstrap cannot reach run_watchdog observation"},
  {"target":"eliotd","classification":"idle_only","operational_scope":"product_daemon","main":{"path":"bins/eliotd/src/main.rs","line":50,"symbol":"main","text":"fn main() {"},"call_chain":[{"path":"bins/eliotd/src/main.rs","line":61,"symbol":"run","text":"fn run() -> Result<(), String> {"},{"path":"bins/eliotd/src/main.rs","line":158,"symbol":"run_loop","text":"async fn run_loop(kernel: Arc<DaemonKernelClient>) -> Result<(), String> {"},{"path":"bins/eliotd/src/main.rs","line":160,"symbol":"run_loop","text":"        tokio::select! {"},{"path":"bins/eliotd/src/main.rs","line":161,"symbol":"run_loop","text":"            signal = tokio::signal::ctrl_c() => {"},{"path":"bins/eliotd/src/main.rs","line":165,"symbol":"run_loop","text":"            () = tokio::time::sleep(std::time::Duration::from_secs(5)) => {"},{"path":"bins/eliotd/src/main.rs","line":166,"symbol":"run_loop","text":"                KernelTransitionPort::health(&*kernel)"}],"gate_condition":"valid descriptor and Kernel connection; no task/submission ingress is wired","effect_boundary":"health heartbeat and shutdown observation only","falsifier":"run_loop gains a reachable task/admission/submission input path beyond ctrl_c and health"}
]
'@

function Get-Catalogue() { @($catalogueJson | ConvertFrom-Json) }

try {
    $repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    if ([string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath = Join-Path $repoRoot 'swarm/inventory/composition-roots.json' }
    elseif (-not [System.IO.Path]::IsPathRooted($OutputPath)) { $OutputPath = Join-Path $repoRoot $OutputPath }
    if ([string]::IsNullOrWhiteSpace($ResultPath)) { $ResultPath = Join-Path $repoRoot 'swarm/results/W1-07.json' }
    elseif (-not [System.IO.Path]::IsPathRooted($ResultPath)) { $ResultPath = Join-Path $repoRoot $ResultPath }
    $metadataText = (& cargo metadata --no-deps --format-version 1 | Out-String)
    if ($LASTEXITCODE -ne 0) { Fail "cargo metadata exited $LASTEXITCODE" }
    $metadata = $metadataText | ConvertFrom-Json
    $targets = @(
        foreach ($package in $metadata.packages) {
            foreach ($target in $package.targets) {
                if (@($target.kind) -contains 'bin') {
                    [pscustomobject]@{ Target = [string]$target.name; Package = [string]$package.name; PackageId = [string]$package.id; Manifest = ([string]$package.manifest_path -replace '\\','/'); Source = ([string]$target.src_path -replace '\\','/') }
                }
            }
        }
    ) | Sort-Object Target
    if ($targets.Count -eq 0) { Fail 'cargo metadata returned no binary targets' }
    $catalogue = @{}; foreach ($item in (Get-Catalogue)) { if ($catalogue.ContainsKey($item.target)) { Fail "duplicate catalogue target $($item.target)" }; $catalogue[$item.target] = $item }
    $targetNames = @($targets | ForEach-Object Target)
    foreach ($item in $targets) { if (-not $catalogue.ContainsKey($item.Target)) { Fail "missing witness catalogue entry for target $($item.Target)" } }
    foreach ($item in $catalogue.Keys) { if ($item -notin $targetNames) { Fail "catalogue target is not in cargo metadata: $item" } }

    $commitCensus = @(Get-RustCommitCensus $repoRoot)
    $commitDefinitions = @($commitCensus | Where-Object kind -eq 'definition')
    $commitCallers = @($commitCensus | Where-Object kind -eq 'caller')
    if ($commitDefinitions.Count -ne 1 -or $commitCallers.Count -ne 0) {
        Fail "canonical commit census changed: definitions=$($commitDefinitions.Count) callers=$($commitCallers.Count); refresh W1-07 evidence"
    }
    $commitCensusDigest = Sha256-Text (($commitCensus | ForEach-Object { "$($_.path)`0$($_.line)`0$($_.kind)`0$($_.line_sha256)" }) -join "`n")

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($item in $targets) {
        $w = $catalogue[$item.Target]
        $manifestAbs = $item.Manifest
        $sourceAbs = $item.Source
        $manifestText = Read-Utf8 $manifestAbs
        $sourceText = Read-Utf8 $sourceAbs
        $manifestLines = Source-Lines $manifestText
        $sourceLines = Source-Lines $sourceText
        $manifestName = [regex]::Match($manifestText, '(?m)^\s*name\s*=\s*"(?<name>[^"]+)"\s*$')
        if (-not $manifestName.Success -or $manifestName.Groups['name'].Value -ne $item.Package) { Fail "manifest package anchor mismatch for $($item.Target)" }
        $manifestLineNumber = Match-LineNumber $manifestText $manifestName.Index
        $manifestAnchor = [pscustomobject]@{ line = $manifestLineNumber; symbol = 'package.name'; text = $manifestLines[$manifestLineNumber - 1].Trim(); line_sha256 = Sha256-Text $manifestLines[$manifestLineNumber - 1].Trim() }
        $main = $w.main
        if ($main.path -ne ($item.Source.Substring($repoRoot.Length + 1) -replace '\\','/')) { Fail "main path mismatch for $($item.Target)" }
        if ($main.line -gt $sourceLines.Count -or $sourceLines[$main.line - 1] -cne $main.text) { Fail "stale main witness for $($item.Target) at $($main.path):$($main.line)" }
        $anchors = [System.Collections.Generic.List[object]]::new()
        foreach ($a in @($w.call_chain)) {
            $aAbs = Resolve-Relative $repoRoot $a.path
            $aLines = Source-Lines (Read-Utf8 $aAbs)
            if ($a.line -gt $aLines.Count -or $aLines[$a.line - 1] -cne $a.text) { Fail "stale call-chain witness for $($item.Target) at $($a.path):$($a.line)" }
            $anchors.Add([pscustomobject]@{ path = $a.path; line = [int]$a.line; symbol = [string]$a.symbol; text = [string]$a.text; line_sha256 = Sha256-Text ([string]$a.text) })
        }
        $mainRecord = [pscustomobject]@{ path = $main.path; line = [int]$main.line; symbol = [string]$main.symbol; text = [string]$main.text; line_sha256 = Sha256-Text ([string]$main.text) }
        $anchorDigest = Sha256-Text ((@($manifestAnchor.text, $mainRecord.text) + @($anchors | ForEach-Object { $_.text })) -join "`n")
        $predicateDefinition = Get-PredicateDefinition $item.Target ([string]$w.classification)
        $predicate = [pscustomobject]@{
            kind = $predicateDefinition.kind
            expected_classification = $predicateDefinition.expected_classification
            reachable_effect = $predicateDefinition.reachable_effect
            pre_effect_refusal = $predicateDefinition.pre_effect_refusal
            partial_capability = $predicateDefinition.partial_capability
            refusal_scope = $predicateDefinition.refusal_scope
            witness = [pscustomobject]@{
                ordered_anchor_lines = @($anchors | ForEach-Object { "$($_.path):$($_.line)" })
                ordered_anchor_symbols = @($anchors | ForEach-Object { $_.symbol })
                required_source_fragments = @($predicateDefinition.required_source_fragments)
            }
        }
        $manifestRel = $item.Manifest.Substring($repoRoot.Length + 1) -replace '\\','/'
        $sourceRel = $item.Source.Substring($repoRoot.Length + 1) -replace '\\','/'
        $stableSeed = "$($item.Target)`0$($item.Package)`0$manifestRel`0$sourceRel`0$($w.classification)`0$anchorDigest"
        $stableId = 'CR-' + (Sha256-Text $stableSeed).Substring(0, 24)
        $records.Add([pscustomobject]@{
            stable_id = $stableId; target = $item.Target; package = $item.Package
            manifest = [pscustomobject]@{ path = ($item.Manifest.Substring($repoRoot.Length + 1) -replace '\\','/'); package_name = $item.Package; anchor = $manifestAnchor; digest = Sha256-Text $manifestText }
            main = $mainRecord; classification = [string]$w.classification; operational_scope = [string]$w.operational_scope
            composition_root = [pscustomobject]@{ call_chain = @($anchors); gate_condition = [string]$w.gate_condition; effect_boundary = [string]$w.effect_boundary; falsifier = [string]$w.falsifier; predicate = $predicate }
            witness = [pscustomobject]@{ catalogue = 'W1-07-v1'; source_digest = Sha256-Text $sourceText; anchor_digest = $anchorDigest }
        })
    }
    $records = @($records | Sort-Object target)
    $targetSetDigest = Sha256-Text (($records | ForEach-Object { "$($_.target)`0$($_.package)`0$($_.manifest.path)`0$($_.main.path)`0$($_.main.line)`0$($_.classification)`0$($_.witness.anchor_digest)" }) -join "`n")
    $summary = [ordered]@{}
    foreach ($class in @('useful_work','typed_refusal','idle_only','unknown')) { $summary[$class] = @($records | Where-Object classification -eq $class).Count }
    $invariants = [ordered]@{
        canonical_commit = [ordered]@{
            id = 'canonical-commit-census-v2'; scope = 'workspace-rust-cached-plus-nonignored-untracked'; token = 'commit_canonical('; expected = 'one_definition_zero_callers'
            total_occurrences = $commitCensus.Count; definition_count = $commitDefinitions.Count; caller_count = $commitCallers.Count
            occurrences = @($commitCensus); census_digest = $commitCensusDigest
        }
    }
    $document = [ordered]@{ schema_version = 'eliot-composition-root-registry-v2'; generated_by = 'scripts/gen-composition-roots.ps1'; source = [ordered]@{ command = 'cargo metadata --no-deps --format-version 1'; target_kind = 'bin'; target_count = $records.Count; target_set_digest = $targetSetDigest }; summary = $summary; invariants = $invariants; records = $records }
    $expected = (($document | ConvertTo-Json -Depth 12) -replace "`r`n", "`n") + "`n"
    $registrySha256 = Sha256-Text $expected
    $recoveryFindings = @{
        'eliot-agent-bridge' = 'kernel_ports reaches KernelClient::load/probe and unconditionally returns KernelAdmissionRequired before stdin loop'
        'eliot-dreamer' = 'both connect branches produce an error response and ExitCode 78; the Ok branch is also KernelAdmissionRequired'
        'eliot-doctor' = 'main emits the Kernel admission refusal and unconditionally exits 78'
        'eliotd' = 'run_loop selects only ctrl_c and five-second Kernel health; no task/submission ingress is wired'
    }
    $recovery = @(
        foreach ($targetName in @('eliot-agent-bridge','eliot-dreamer','eliot-doctor','eliotd')) {
            $record = $records | Where-Object target -eq $targetName | Select-Object -First 1
            [ordered]@{ target = $targetName; classification = [string]$record.classification; anchor = (@($record.composition_root.call_chain | ForEach-Object { "$($_.path):$($_.line)" }) -join ', '); finding = $recoveryFindings[$targetName]; falsifier = [string]$record.composition_root.falsifier }
        }
    )
    $additional = @(
        [ordered]@{ target = 'eliot-native-worker'; classification = 'typed_refusal'; anchor = 'bins/eliot-native-worker/src/main.rs:8-15'; finding = 'KernelNativeWorkerClient::connect cannot yield a session-bound process request; main emits typed refusal and exits 78' }
        [ordered]@{ target = 'eliot-wasm-host'; classification = 'typed_refusal'; anchor = 'bins/eliot-wasm-host/src/main.rs:30-35'; finding = 'after argument parsing, main unconditionally emits KERNEL_ADMISSION_REQUIRED and exits' }
        [ordered]@{ target = 'eliot-testd'; classification = 'useful_work'; anchor = 'bins/eliot-testd/src/main.rs:53 and :98'; finding = 'main reaches Ready, stdin dispatch, Status and Cancel; only Submit is bound to UnavailableProcessIssuer and is typed unavailable'; predicate = 'reachable_effect_partial_refusal'; refusal_scope = 'Submit only' }
    )
    $structuredResult = [ordered]@{
        disposition = 'completed'
        schema_version = 'eliot-composition-root-audit-result-v3'
        authority_status = 'EVIDENCE_ONLY'
        work_item_id = 'W1-07'
        provider_id = 'codex-luna-w1-07'
        agent_profile = 'implementation'
        artifacts = @([ordered]@{ path = 'swarm/inventory/composition-roots.json'; sha256 = $registrySha256; kind = 'inventory' })
        evidence = @('Static Cargo-metadata composition-root census with source anchors, call-chain witnesses, falsifiers, and canonical commit census; no live runtime PASS is claimed.')
        discriminator_before = [ordered]@{ name = 'result-envelope-shape'; value = 'legacy W1-07 result fields were top-level'; status = 'observed' }
        discriminator_after = [ordered]@{ name = 'result-envelope-shape'; value = 'eliot.bootstrap-work-result.v1 with rich structured_result'; status = 'verified' }
        uncertainty = @('Classification is static source reachability evidence; it is not live runtime execution or product acceptance.')
        unresolved_questions = @('No cutover or architecture decision is made by this registry; the W1 ContractChallenge remains evidence-only.')
        proposed_effects = @('Any future cutover or runtime repair requires a separately admitted work item and independent gate; this artifact changes no product code.')
        evidence_lineage = @([ordered]@{ path = 'swarm/inventory/composition-roots.json'; sha256 = $registrySha256; role = 'generated composition-root registry' })
        authority_ceiling = 'EVIDENCE_ONLY; no terminal completion, release WIP, activation, or wave authorization.'
        registry = [ordered]@{ path = 'swarm/inventory/composition-roots.json'; generator = 'scripts/gen-composition-roots.ps1'; verifier = 'scripts/verify-composition-roots.ps1'; schema_version = 'eliot-composition-root-registry-v2'; cargo_metadata_target_count = $records.Count; target_set_digest = $targetSetDigest; registry_sha256 = $registrySha256 }
        classification = [ordered]@{ useful_work = $summary.useful_work; typed_refusal = $summary.typed_refusal; idle_only = $summary.idle_only; unknown = $summary.unknown }
        recovery_program_5_1 = $recovery
        additional_findings = $additional
        all_targets = @($records | ForEach-Object target)
        verification = [ordered]@{ kind = 'structured_evidence_only'; result = 'PASS'; commands = @('pwsh -NoProfile -File scripts/gen-composition-roots.ps1 -Check','pwsh -NoProfile -File scripts/verify-composition-roots.ps1 -SelfTest','pwsh -NoProfile -File scripts/verify-composition-roots.ps1'); self_tests = @('synthetic tamper rejected','synthetic missing target rejected','synthetic duplicate target rejected','classification/predicate mismatch rejected','omitted commit_canonical caller rejected','cached plus nonignored-untracked Rust census enforced','CRLF fixture distinguished from canonical LF'); proof_ceiling = 'static composition-root reachability; no live runtime PASS claim; no TerminalWorkUpdate claim' }
        integration_disposition = [ordered]@{ accepted_findings = @('Current cargo metadata census is 22 binary targets, not the historical 21.','Every target has a checked manifest/main/call-chain witness, gate condition, effect boundary and falsifier.','The registry-wide canonical commit invariant records one workspace-Rust definition and zero callers.'); deferred = @('No cutover or architecture decision is made by this registry.','Static useful_work is not a live observed PASS.','The W1 result-envelope ContractChallenge remains open; this artifact is evidence only.') }
    }
    $result = [ordered]@{ schema_version = 'eliot.bootstrap-work-result.v1'; authority_status = 'EVIDENCE_ONLY'; work_item_id = 'W1-07'; structured_result = $structuredResult }
    $resultExpected = (($result | ConvertTo-Json -Depth 12) -replace "`r`n", "`n") + "`n"
    if ($Check) {
        if (-not (Test-Path -LiteralPath $OutputPath -PathType Leaf)) { Fail "registry is missing: $OutputPath" }
        if ((Read-Utf8 $OutputPath) -cne $expected) { Fail 'composition-roots registry is stale; run generator' }
        if (-not (Test-Path -LiteralPath $ResultPath -PathType Leaf)) { Fail "result is missing: $ResultPath" }
        if ((Read-Utf8 $ResultPath) -cne $resultExpected) { Fail 'W1-07 result is stale; run generator' }
        Write-Output "COMPOSITION_ROOTS_GENERATE_CHECK: PASS targets=$($records.Count) digest=$targetSetDigest registry_sha256=$registrySha256 result=EVIDENCE_ONLY"
    } else {
        $parent = Split-Path -Parent $OutputPath
        if (-not (Test-Path -LiteralPath $parent -PathType Container)) { Fail "output parent is missing: $parent" }
        [System.IO.File]::WriteAllText($OutputPath, $expected, [System.Text.UTF8Encoding]::new($false))
        $resultParent = Split-Path -Parent $ResultPath
        if (-not (Test-Path -LiteralPath $resultParent -PathType Container)) { Fail "result parent is missing: $resultParent" }
        [System.IO.File]::WriteAllText($ResultPath, $resultExpected, [System.Text.UTF8Encoding]::new($false))
        Write-Output "COMPOSITION_ROOTS_GENERATE: PASS targets=$($records.Count) digest=$targetSetDigest output=$OutputPath result=$ResultPath authority=EVIDENCE_ONLY"
    }
}
catch { Write-Error $_.Exception.Message; exit 1 }
