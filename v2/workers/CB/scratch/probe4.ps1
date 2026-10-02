Import-Module -Name 'C:\Development\Rust\projects\eliot-swarm\M-CB\scripts\integration\IntegrationHarness.Store.psm1' -ErrorAction Stop
$runId = 'f00dfeed11112222333344445555666f'
$binding = @{
    runId = $runId; testClass = 'STORE'; providerName = 'eliot-store-surreal-isolated'
    providerRevision = 'eliot.integration.store-provider.v1'; owner = 'store-test-owner'
    generation = 1; deadlineUtc = ([DateTimeOffset]::UtcNow.AddMinutes(10)).ToString('o')
}
$global:listeners = [Collections.Generic.List[System.Net.Sockets.TcpListener]]::new()
function New-Alloc([string]$seed, [int]$port) {
    $s = $seed; $p = $port
    $ent = { return $s }.GetNewClosure()
    $res = { param($ctx)
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p); $l.Start()
        [void]$global:listeners.Add($l); return @{ port = $p; host = '127.0.0.1'; listener = $l } }.GetNewClosure()
    return (Invoke-StoreAllocate -Binding $binding -Plan (Invoke-StorePlan -Binding $binding -Requirement @{ testClass='STORE'; providerRevision='eliot.integration.store-provider.v1' }) `
        -BaseTemp ([IO.Path]::GetFullPath([IO.Path]::GetTempPath())) -Entropy $ent -PortReservation $res)
}
$acq = { param($c) return @{ version='3.1.4'; architecture='windows-x64'; peMachine='8664'
    digest='13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'
    provenance='acquired-verified'; storePath='C:\runtime\surreal.exe' } }.GetNewClosure()
$good = { param($i) return @{ observedPid=4242; observedNonce='feedface01'; imagePath='C:\runtime\surreal.exe'; startTimeUtc='2026-09-27T12:00:00.0000000Z' } }.GetNewClosure()
$losing = { param($i) throw 'lost-response: pipe closed before ack' }

$a1 = New-Alloc '00000001' 19301
$r1 = Invoke-StoreStart -Binding $binding -Allocation $a1 -Acquisition $acq -Launcher $losing -Entropy { return '0123abcd' }
"1) lost launch -> " + $r1['startState'] + " retryPermitted=" + $r1['retryPermitted']

# (A) Retry the SAME instance -> guard must refuse. Product behaviour.
$a1retry = ''
try { Invoke-StoreStart -Binding $binding -Allocation $a1 -Acquisition $acq -Launcher $good -Entropy { return '0123abcd' } | Out-Null }
catch { $a1retry = [string]$_.Exception.Message }
"   (A) same-instance retry refusal = [" + $a1retry + "]"

# (B) REPLACE the instance: a fresh allocation of the same run.
$a2 = New-Alloc '00000002' 19302
"   (B) replacement runRoot = " + $a2['runRoot']
"   (B) distinct from a1? " + ($a2['runRoot'] -cne $a1['runRoot'])
$a2msg = ''
try { $r2 = Invoke-StoreStart -Binding $binding -Allocation $a2 -Acquisition $acq -Launcher $good -Entropy { return 'cafef00d' }; $a2msg = 'StartRequested' }
catch { $a2msg = [string]$_.Exception.Message }
"   (B) replacement start = [" + $a2msg + "]"

# Now a real caller reconciles the old record, then replaces.
$res = Resolve-StoreReconciliationRecord -RunRoot $a1['runRoot'] -RunId $runId -Resolution 'no-store-process-running'
"   resolve -> " + ($res | ConvertTo-Json -Compress)
$a3 = New-Alloc '00000003' 19303
$a3msg = ''
try { $r3 = Invoke-StoreStart -Binding $binding -Allocation $a3 -Acquisition $acq -Launcher $good -Entropy { return 'deadbee1' }; $a3msg = 'StartRequested' }
catch { $a3msg = [string]$_.Exception.Message }
"   after resolve, replacement start = [" + $a3msg + "]"

foreach ($l in $global:listeners) { try { $l.Stop() } catch {} }
foreach ($a in @($a1,$a2,$a3)) { Remove-Item -LiteralPath $a['runRoot'] -Recurse -Force -ErrorAction SilentlyContinue }