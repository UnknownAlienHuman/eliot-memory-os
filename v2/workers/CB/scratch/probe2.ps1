Import-Module -Name 'C:\Development\Rust\projects\eliot-swarm\M-CB\scripts\integration\IntegrationHarness.Store.psm1' -ErrorAction Stop

$runId = 'f00dfeed11112222333344445555666f'
$binding = @{
    runId = $runId; testClass = 'STORE'; providerName = 'eliot-store-surreal-isolated'
    providerRevision = 'eliot.integration.store-provider.v1'; owner = 'store-test-owner'
    generation = 1; deadlineUtc = ([DateTimeOffset]::UtcNow.AddMinutes(10)).ToString('o')
}
$global:listeners = [Collections.Generic.List[System.Net.Sockets.TcpListener]]::new()
function New-Alloc([string]$seed, [int]$port) {
    $s = $seed
    $ent = { return $s }.GetNewClosure()
    $p = $port
    $res = {
        param($ctx)
        $l = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p)
        $l.Start()
        [void]$global:listeners.Add($l)
        return @{ port = $p; host = '127.0.0.1'; listener = $l }
    }.GetNewClosure()
    return (Invoke-StoreAllocate -Binding $binding -Plan (Invoke-StorePlan -Binding $binding -Requirement @{ testClass = 'STORE'; providerRevision = 'eliot.integration.store-provider.v1' }) `
        -BaseTemp ([IO.Path]::GetFullPath([IO.Path]::GetTempPath())) -Entropy $ent -PortReservation $res)
}
$acq = { param($c) return @{
        version = '3.1.4'; architecture = 'windows-x64'; peMachine = '8664'
        digest = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'
        provenance = 'acquired-verified'; storePath = 'C:\runtime\surreal.exe' } }.GetNewClosure()
$good = { param($i) return @{ observedPid = 4242; observedNonce = 'feedface01'; imagePath = 'C:\runtime\surreal.exe'; startTimeUtc = '2026-09-27T12:00:00.0000000Z' } }.GetNewClosure()
$losing = { param($i) throw 'lost-response: pipe closed before ack' }

$a1 = New-Alloc '00000001' 19201
"alloc1 runRoot = " + $a1['runRoot']
$r1 = Invoke-StoreStart -Binding $binding -Allocation $a1 -Acquisition $acq -Launcher $losing -Entropy { return '0123abcd' }
"start1 state=" + $r1['startState'] + " reconPath=" + $r1['reconciliationPath']
"  file exists = " + (Test-Path -LiteralPath ([string]$r1['reconciliationPath']) -PathType Leaf)

$a2 = New-Alloc '00000002' 19202
"alloc2 runRoot = " + $a2['runRoot']
$refusal2 = ''
$r2 = $null
try { $r2 = Invoke-StoreStart -Binding $binding -Allocation $a2 -Acquisition $acq -Launcher $good -Entropy { return 'cafef00d' } }
catch { $refusal2 = [string]$_.Exception.Message }
"start2 refusal = [" + $refusal2 + "]"

if ($r2 -is [hashtable]) {
    $st = Invoke-StoreStop -Binding $binding -StartReceipt $r2 -ProcessController { param($c) return @{ exited = $true; pid = $c['pid'] } }
    "stop2 state = " + $st['stopState'] + " phase=" + $st['stopPhase'] + " failure=" + $st['failure']
    "  reconPath = " + $st['reconciliationPath']
    "  reconFile = " + (Test-Path -LiteralPath ([string]$st['reconciliationPath']) -PathType Leaf)
    "  runRoot2 file = " + (Test-Path -LiteralPath ([string]$a2['runRoot'] + '\.eliot-harness-reconciliation.json') -PathType Leaf)
}
foreach ($l in $global:listeners) { try { $l.Stop() } catch {} }