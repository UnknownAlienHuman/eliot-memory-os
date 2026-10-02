Import-Module -Name 'C:\Development\Rust\projects\eliot-swarm\M-CB\scripts\integration\IntegrationHarness.Store.psm1' -ErrorAction Stop

$runId = '0123456789abcdef0123456789abcdef'
$binding = @{
    runId = $runId; testClass = 'STORE'; providerName = 'eliot-store-surreal-isolated'
    providerRevision = 'eliot.integration.store-provider.v1'; owner = 'store-test-owner'
    generation = 1; deadlineUtc = ([DateTimeOffset]::UtcNow.AddMinutes(10)).ToString('o')
}
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 19001)
$listener.Start()
$plan = Invoke-StorePlan -Binding $binding -Requirement @{ testClass = 'STORE'; providerRevision = 'eliot.integration.store-provider.v1' }
$alloc = Invoke-StoreAllocate -Binding $binding -Plan $plan -BaseTemp ([IO.Path]::GetFullPath([IO.Path]::GetTempPath())) `
    -Entropy { return '00000001' } -PortReservation { param($ctx) return @{ port = 19001; host = '127.0.0.1'; listener = $listener } }
"alloc runRoot = " + $alloc['runRoot']
"alloc endpoint = " + $alloc['endpoint']
"start runRoot  = " + $alloc['runRoot']

# First launch loses the response -> writes an unresolved launch record.
$losing = { param($i) throw 'lost-response: pipe closed before ack' }
$r1 = Invoke-StoreStart -Binding $binding -Allocation $alloc -Acquisition { param($c) return @{
        version = '3.1.4'; architecture = 'windows-x64'; peMachine = '8664'
        digest = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'
        provenance = 'acquired-verified'; storePath = 'C:\runtime\surreal.exe' } } `
    -Launcher $losing -Entropy { return '0123abcd' }
"first start state = " + $r1['startState'] + "  reconPath=" + $r1['reconciliationPath'] + " persisted=" + $r1['reconciliationPersisted']
"recon file exists = " + (Test-Path -LiteralPath $alloc['runRoot'] + '\.eliot-harness-reconciliation.json' -PathType Leaf)

# Second Start on a DIFFERENT allocation of the same run, same fake binding.
$listener2 = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 19002)
$listener2.Start()
$alloc2 = Invoke-StoreAllocate -Binding $binding -Plan $plan -BaseTemp ([IO.Path]::GetFullPath([IO.Path]::GetTempPath())) `
    -Entropy { return '00000002' } -PortReservation { param($ctx) return @{ port = 19002; host = '127.0.0.1'; listener = $listener2 } }
$refusal = ''
try {
    $r2 = Invoke-StoreStart -Binding $binding -Allocation $alloc2 -RunRoot2 2>$null
}
catch { $refusal = [string]$_.Exception.Message }
"second start refusal = [" + $refusal + "]"