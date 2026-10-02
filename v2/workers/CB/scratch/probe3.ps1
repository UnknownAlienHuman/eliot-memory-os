Import-Module -Name 'C:\Development\Rust\projects\eliot-swarm\M-CB\scripts\integration\IntegrationHarness.Store.psm1' -ErrorAction Stop

# Mirror the suite's own fixture helpers exactly (copied from the Tests.ps1 helper region).
$script:TestObservedImagePath = 'C:\runtime\surreal.exe'
$script:TestObservedStartTimeUtc = '2026-09-27T12:00:00.0000000Z'
$script:TestAllocationSerial = 0
$global:listeners = [Collections.Generic.List[System.Net.Sockets.TcpListener]]::new()
function Get-StoreTestBinding { param([string]$RunId = '0123456789abcdef0123456789abcdef')
    return @{ runId = $RunId; testClass = 'STORE'; providerName = 'eliot-store-surreal-isolated'
        providerRevision = 'eliot.integration.store-provider.v1'; owner = 'store-test-owner'
        generation = 1; deadlineUtc = ([DateTimeOffset]::UtcNow.AddMinutes(10)).ToString('o') } }
function Get-StoreTestRequirement { return @{ testClass = 'STORE'; providerRevision = 'eliot.integration.store-provider.v1' } }
function Get-StoreTestAcquisition { param([string]$Provenance = 'acquired-verified')
    return { param($ctx) return @{
        version = '3.1.4'; architecture = 'windows-x64'; peMachine = '8664'
        digest = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'
        provenance = $Provenance; storePath = 'C:\runtime\surreal.exe' } }.GetNewClosure() }
function New-StoreTestReservation { param([int]$Port)
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    $listener.Start(); [void]$global:listeners.Add($listener)
    return @{ port = $Port; host = '127.0.0.1'; listener = $listener } }
function New-StoreTestLauncher { param([int]$ObservedPid = 4242, [string]$Nonce = 'feedface01')
    return ({ param($input_) return @{ observedPid = $ObservedPid; observedNonce = $Nonce
        imagePath = 'C:\runtime\surreal.exe'; startTimeUtc = '2026-09-27T12:00:00.0000000Z' } }).GetNewClosure() }
function Get-StoreTestAllocation { param($Binding, [int]$Port = 0, [string]$EntropySeed = '')
    if ($null -eq $Binding) { $Binding = Get-StoreTestBinding }
    $script:TestAllocationSerial++
    if ($Port -le 0) { $Port = 18020 + $script:TestAllocationSerial }
    if ([string]::IsNullOrWhiteSpace($EntropySeed)) { $EntropySeed = ('{0:x8}' -f $script:TestAllocationSerial) }
    $plan = Invoke-StorePlan -Binding $Binding -Requirement (Get-StoreTestRequirement)
    $reservation = { param($ctx) return (New-StoreTestReservation -Port $Port) }.GetNewClosure()
    $entropy = { return $EntropySeed }.GetNewClosure()
    return (Invoke-StoreAllocate -Binding $Binding -Plan $plan -BaseTemp ([IO.Path]::GetTempPath()) -Entropy $entropy -PortReservation $reservation) }
function Get-StoreTestStartReceipt { param($Binding, $Allocation)
    if ($null -eq $Binding) { $Binding = Get-StoreTestBinding }
    if ($null -eq $Allocation) { $Allocation = Get-StoreTestAllocation $Binding }
    return (Invoke-StoreStart -Binding $Binding -Allocation $Allocation -Acquisition (Get-StoreTestAcquisition) -Launcher (New-StoreTestLauncher) -Entropy { return 'cafef00d' }) }

# ---- Replay case 11 exactly. ----
$binding = Get-StoreTestBinding
$allocation = Get-StoreTestAllocation $binding
$receipt = Get-StoreTestStartReceipt $binding $allocation
"alloc runRoot = " + $allocation['runRoot']
"start  runRoot = " + $receipt['runRoot']

$binding2 = Get-StoreTestBinding          # what case 12 does
$allocation2 = Get-StoreTestAllocation $binding2
"alloc2 runRoot = " + $allocation2['runRoot']
"allocation.runRoot -eq binding2-runRoot? binding2 has no runRoot key: " + ($binding2.ContainsKey('runRoot'))

$refusal = ''
try { $r = Invoke-StoreStart -Binding $binding2 -Allocation $allocation2 -Acquisition (Get-StoreTestAcquisition) -Launcher (New-StoreTestLauncher) -Entropy { return '0123abcd' } }
catch { $refusal = [string]$_.Exception.Message }
"case12 Start refusal = [" + $refusal + "]"

foreach ($l in $global:listeners) { try { $l.Stop() } catch {} }