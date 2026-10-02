# Copyright (c) Eliot contributors. Licensed under the repository terms.
# IntegrationHarness Store — authenticated isolated SurrealDB 3.1.4 provider for issue #909.
#
# This module holds the Store provider BEHAVIOR behind the closed 9-operation
# provider interface (ValidateRequirement, Plan, Allocate, Start,
# ObserveReadiness, ResetForTest, CollectEvidence, Stop, VerifyCleanup).
# A closed dispatcher validates the operation name, the binding shape, and
# the deadline via an injected clock, invokes the operation scriptblock, and
# validates the result carries no forbidden authority
# (testDenominator/providerChoice/command/argv/executable/shellCommand/
# testPassed/markPassed/verdictOverride). The dispatcher clones the caller
# binding into dispatcher-local scope, snapshots the proven run identity
# before invoking the implementation, and rejects any post-invocation
# mutation. New-StoreProviderOperationTable supplies the default table whose
# entries call the real Invoke-Store* operations with default real seams, so
# the dispatcher has true call edges instead of injected behavior only.
#
# Fail-closed rules enforced here:
# - Exact Store class (STORE) plus provider revision plus lock identity
#   (surreal.exe 3.1.4 windows-x64 pe 8664 sha
#   13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1,
#   per docs/release/SURREALDB_WINDOWS_X64.lock.json and
#   config/dependency-policy.toml [external_executables.surrealdb]).
#   Unsupported class or revision is rejected; there is no fallback provider.
#   Provider revision v1 requires exactly one Store schema generation whose
#   content identity is pinned in $Script:StoreRequiredSchemaDigest (sha256
#   over the ordered migrate_schema file set 000..010); Start records it on
#   every start receipt and ObserveReadiness compares the observed client
#   schemaDigest against it. Re-pin only through the eliot-store schema owner.
# - Plan is finite and mutation-free: it returns Approve-Plan shaped resources
#   (resourceKey/runId/testClass/providerRevision/owner/generation) and never
#   carries shellCommand/executablePath/rawArgv/url/credential/environmentMap/
#   outputPath. Plan performs no filesystem, process, port, or network action.
#   When the requirement carries requiredReceipts (store-receipt/git-receipt
#   descriptors bound by testClass+providerRevision+runId), Plan consumes and
#   binds the accepted set and Allocate re-validates it before deriving roots.
# - Allocate creates unique owned data/log/secret roots under the admitted run
#   root, writes the owner marker eliot-harness-owned-root-v1, derives
#   namespace/database from the run identity AND this allocation's own seed, and
#   reserves a loopback endpoint through an ownership-safe reservation->launch
#   protocol. A root is reused only when the marker CONTENT re-states the
#   complete claim (marker value, run, owner, generation) through the one
#   predicate Test-StoreOwnedRootClaim that the removal path also uses, so
#   re-allocation cannot adopt a root left under the same run name by another
#   owner or generation. The reservation is claimed by the ENDPOINT: two live
#   reservations can never name one host:port whatever their runId, owner,
#   generation or allocation seed are, so a racer holding a different run, a
#   different owner, a different generation or a different seed for an endpoint
#   another reservation still holds is refused as a genuine endpoint conflict,
#   while this run's own duplicate request for an endpoint it already holds
#   stays a distinct reused-reservation refusal. The reservation records which
#   ownership proof it actually carries, and each proof class guarantees only
#   what was measured:
#   'held-socket'   the seam returned a live TcpListener whose bound endpoint was
#                   re-read and still is this endpoint, so an exclusive bind is
#                   held by this process right now and Start re-proves it by
#                   re-reading that socket immediately before the child is
#                   created. This is the only proof that authorizes a launch.
#   'seam-asserted' the seam returned a port with no handle this module can
#                   re-verify. Any hold exists only inside the seam and cannot
#                   be observed, re-proven or released here, so this module holds
#                   nothing physical for the endpoint. The record is still kept
#                   and still keeps the endpoint claimed against every other
#                   allocation in this registry, but the launch handoff refuses
#                   it as STORE-RESERVATION-UNPROVEN instead of trusting the
#                   seam's word.
#   Start re-proves the proof immediately before creating the child and then
#   releases it exactly once, so a dropped registry entry (expired), a replaced
#   binding (foreign), a proof this module cannot re-verify (unproven), and an
#   endpoint that left the reservation (port race) are distinct typed refusals
#   raised before any process exists, while an endpoint that cannot be reserved
#   at all is a typed port conflict rather than an ownership failure. The
#   default reservation binds with ExclusiveAddressUse and returns its listener,
#   so a production reservation carries 'held-socket', not the unverifiable
#   'seam-asserted' class.
#   Creation runs through the FileSystem seam (default real); re-allocation for
#   the same run reuses the marker-verified roots and re-verifies the existing
#   run-principal-only ACL instead of re-writing it, while a foreign or missing
#   marker fails closed.
# - Start verifies the approved executable version/platform/arch/digest plus
#   acquisition provenance before execution, including cached binaries which
#   are fully re-verified (digest recomputed; a mismatched cache record fails
#   closed, never downgrades). It rejects latest/missing/caller-hash/wrong
#   version or arch. Invocation is fixed from typed accepted fields only, in
#   the production-canonical argv form (start --no-banner --bind <loopback>
#   --temporary-directory <runRoot> --log-file-enabled --log-file-path
#   <logRoot> --log-file-name surrealdb.log surrealkv://<dataRoot>);
#   arbitrary executable/URL/argv/env input is unrepresentable. The child
#   joins a Windows Job Object (kill-on-close) at launch; Job binding failure
#   fails the start. A start receipt without requested identity plus the
#   expected schema identity is stale and cannot authorize Stop or readiness.
# - ObserveReadiness binds exact process/start/endpoint identity plus an
#   authenticated protocol handshake plus namespace/database selection plus
#   the required schema identity carried on the start receipt. The handshake
#   first CREATES the allocated namespace/database with the bare
#   `DEFINE NAMESPACE` / `DEFINE DATABASE` forms on this run's own reserved
#   endpoint under its own ephemeral root credential. Those forms are the atomic
#   exclusive create: the server refuses the statement when the name already
#   exists, so exactly one run wins the name. A plain `USE NS x DB y` is not a
#   claim -- in SurrealDB 3.x regular mode it CREATES a missing namespace or
#   database and silently adopts an existing one, which would let a run proceed
#   on another run's namespace. Each name this run wins is recorded SEPARATELY,
#   at the instant its own exclusive create wins that name, so a later handshake
#   or fixture step of the SAME run is a recognized re-entry for that name alone,
#   and any namespace or database already present without this run's own record
#   for THAT name is refused as foreign (STORE-NAMESPACE-FOREIGN) rather than
#   adopted. One record never vouches for the other: winning the namespace does
#   not claim a database this run never created, and an unproven name is never
#   adopted on the strength of a proven neighbour. Process-alive,
#   TCP-open, authenticated, schema-ready, and fixture-ready are separate
#   receipts; schema-ready is true only when the observed client schemaDigest
#   equals the expected receipt identity, and liveness without auth is not
#   readiness. The receipt also carries a distinct failureClass
#   (none/process-crash/port-closed/auth-failed/schema-mismatch). When the
#   port observation proves a listener owner, it must equal the owned PID.
# - ResetForTest requires the exact declared fixture plus baseline
#   revalidation; a reset failure contaminates exactly its group, never the run.
# - CollectEvidence returns bounded redacted handles with truncation; it
#   redacts credential/query/source/data canaries and never emits secrets.
#   A sink/redaction failure keeps the original terminal state and owner.
# - Stop proves receipt ownership (requested requestKey/endpoint/schemaDigest
#   plus observed pid/nonce/endpoint/image/start-time binding) before
#   signalling anything, then performs a bounded graceful phase and, only
#   if needed, exact-owned-tree termination of the verified tree; never by
#   name, port, or unverified PID. A stale or foreign receipt is refused
#   without signalling any process, and forced termination is refused when
#   the observed descendant closure is explicitly incomplete.
# - VerifyCleanup checks the owner marker, process descendants, port, locks,
#   secrets, and roots; it is idempotent and never deletes foreign state. Once
#   every check is clean it removes exactly the run root this operation created
#   by exclusive marker create, and only that tree: the removal re-proves the
#   recorded owner/generation claim from marker CONTENT, refuses on any foreign
#   entry, reparse point, or missing proof, and reports a remaining root instead
#   of deleting it. A refusal or unknown removal keeps the root and returns
#   ReconciliationRequired.
#   Unbound process/port observers default to real observation, an
#   explicitly incomplete descendant closure blocks a clean verdict, and
#   unresolved launch/stop/cleanup reconciliation blocks a clean verdict.
# - Any launch/stop/cleanup with a lost response retains owner identity in a
#   reconciliation record under the owned run root (plus an in-memory
#   backstop); no replacement instance starts until the record resolves.
# - Paths are canonicalized under the admitted run root (traversal, reparse,
#   symlink, reserved device names, and foreign owner markers are rejected);
#   every existing chain level is reparse-checked, and the owner-marker walk
#   includes the run root itself.
# - Child environments are minimal and allowlisted; Start mints one ephemeral
#   credential per launch and delivers it to the child only through the
#   fixed SURREAL_USER/SURREAL_PASS channel inside a fresh child-only
#   environment block materialized immediately before process creation.
#   Credential values live in memory and protected channels only, never in
#   display text, receipts, or logs; receipts carry the credential handle.
#   Secret roots carry an explicit ACL for the run principal only (no
#   inherited rights) through the Acl seam (default real); an already protected
#   root is re-verified against that exact terminal state rather than rewritten,
#   because re-writing a protected DACL needs a privilege the run principal does
#   not hold and would make an owned root impossible to re-verify. Run, provider,
#   binary, config, process, start, endpoint, namespace, database, root, and
#   credential-handle identities plus deadlines are bound on every operation.
#   Terminal dispositions follow the closed I07-20 set; this provider never
#   carries testPassed or verdictOverride authority.
#
# Seams and defaults: clocks, entropy, port reservation, acquisition,
# launchers, process/port observers, Store clients, controllers, file probes,
# filesystem, and ACL are injectable scriptblocks. Each has a default real
# implementation (New-StoreDefault*) used when the caller binds no seam, so a
# production route gets true behavior while the 22 deterministic cases inject
# fakes. Importing this module performs no I/O and spawns nothing; bounded
# waits exist only inside default real seams under the operation deadline.
#
# Proof ceiling: STORE-PROVIDER-DEFAULTS-REAL (fake-seam proof for the 22
# deterministic cases; live SurrealDB, download, and cargo test remain the
# test-phase/smoke concern, not this module's import surface).

Set-StrictMode -Version Latest

$Script:StoreTestClass = 'STORE'
$Script:StoreProviderName = 'eliot-store-surreal-isolated'
$Script:StoreProviderRevision = 'eliot.integration.store-provider.v1'
$Script:StoreInterfaceVersion = 'eliot.integration.harness-provider.v1'
$Script:StoreArtifact = 'surreal.exe'
$Script:StoreRelativePath = 'runtime/surreal.exe'
$Script:StoreVersion = '3.1.4'
$Script:StoreArchitecture = 'windows-x64'
$Script:StorePlatform = 'windows'
$Script:StoreArch = 'x64'
$Script:StorePeMachine = '8664'
$Script:StoreDigest = '13781bc97db9348498bd6b5e0090cf2770e9d296640be8adacf73956e8a568a1'
# Required Store schema identity for provider revision v1: sha256 over the
# ordered migrate_schema content set (crates/eliot-store/src/surql/
# 000_schema.surql through 010_memory_search_fts.surql, LF bytes, numeric
# order), pinned at base 23e4670a. Any schema drift re-fences readiness;
# re-pin only through the eliot-store schema owner. The test phase binds the
# live client computation of this digest per the issue matrix.
$Script:StoreRequiredSchemaDigest = 'c238689ab71773c1b1ecffe8052a7dcd1b82c4e0feb509cf0b55c38596fcbb5c'
$Script:StoreOwnedRootMarker = 'eliot-harness-owned-root-v1'
$Script:StoreOwnerMarkerFile = '.eliot-harness-owner.json'
$Script:StoreReconciliationFile = '.eliot-harness-reconciliation.json'
$Script:StoreReconciliationMarker = 'eliot-harness-reconciliation-v1'
$Script:StoreLoopback = '127.0.0.1'
$Script:StoreGitReceiptRevision = 'eliot.integration.git-provider.v1'
$Script:StoreCredentialId = 'store-root'
$Script:StoreCredentialUserEnv = 'SURREAL_USER'
$Script:StoreCredentialPassEnv = 'SURREAL_PASS'
$Script:StoreSurrealScheme = 'surrealkv://'
$Script:StoreLogFileName = 'surrealdb.log'
# Accepted live schema observation, mirrored from
# crates/storage/eliot-store-surreal-adapter/src/schema.rs READ_SCHEMA_META.
$Script:StoreReadSchemaMeta = 'SELECT VALUE { generation: generation, migrations: migrations, compatible_bridge_range: compatible_bridge_range, migration_state: migration_state, migration_id: migration_id, migration_checksum_sha256: migration_checksum_sha256, updated_at: updated_at } FROM ONLY schema_meta:current;'
$Script:StoreFailureClasses = @(
    'none',
    'process-crash',
    'port-closed',
    'auth-failed',
    'schema-mismatch'
)
$Script:StoreReconciliationTable = @{}
$Script:StoreJobHandles = @{}
$Script:StoreLaunchDrains = @()
$Script:StorePortReservations = @{}

function Get-StorePortReservationId {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)] [string]$RunId,
        [Parameter(Mandatory)] [string]$Owner,
        [Parameter(Mandatory)] [int]$Generation,
        [Parameter(Mandatory)] [string]$AllocationSeed,
        [Parameter(Mandatory)] [string]$Endpoint
    )
    $builder = [System.Text.StringBuilder]::new()
    foreach ($part in @($RunId, $Owner, [string]$Generation, $AllocationSeed, $Endpoint)) {
        [void]$builder.Append($part.Length).Append(':').Append($part)
    }
    return $builder.ToString()
}

# Register one owned endpoint reservation and classify the ownership proof it
# actually carries, so the handoff can be proven instead of assumed:
#   'held-socket'  the seam returned a live TcpListener positively proven to be
#                  bound to the declared loopback endpoint right now, so no other
#                  process can take that port before the handoff releases it;
#   'seam-asserted' the seam returned the endpoint with no handle this module can
#                  re-verify, so nothing physical is held here and the launch
#                  handoff refuses it as an unproven ownership proof.
# A supplied handle that is absent, of the wrong type, already stopped, or bound
# to another endpoint is a genuine port conflict and is refused as one; a live
# reservation this run already holds is refused as a reused reservation. Those
# two refusals stay distinct instead of collapsing into one generic conflict.
function Register-StorePortReservation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)] [hashtable]$Reservation,
        [Parameter(Mandatory)] [string]$RunId,
        [Parameter(Mandatory)] [string]$Owner,
        [Parameter(Mandatory)] [int]$Generation,
        [Parameter(Mandatory)] [string]$AllocationSeed,
        [Parameter(Mandatory)] [string]$ReservationHost,
        [Parameter(Mandatory)] [int]$Port
    )
    $listener = $null
    if ($Reservation.ContainsKey('listener')) { $listener = $Reservation['listener'] }
    $proof = 'seam-asserted'
    if ($null -ne $listener) {
        if ($listener -isnot [System.Net.Sockets.TcpListener]) {
            throw [System.InvalidOperationException]::new('STORE-PORT-CONFLICT: the supplied reservation handle is not a TCP listener.')
        }
        $local = $null
        try {
            $local = [System.Net.IPEndPoint]$listener.LocalEndpoint
        } catch {
            throw [System.InvalidOperationException]::new('STORE-PORT-CONFLICT: the supplied reservation handle is not an active listener.')
        }
        # A released or rebound handle reports a different endpoint here, so this
        # comparison is a positive proof that this socket still holds the port.
        if ([string]$local.Address -cne $ReservationHost -or [int]$local.Port -ne $Port) {
            throw [System.InvalidOperationException]::new('STORE-PORT-CONFLICT: the supplied reservation handle does not own the requested loopback endpoint.')
        }
        $proof = 'held-socket'
    }
    $endpoint = ('{0}:{1}' -f $ReservationHost, $Port)
    $id = Get-StorePortReservationId -RunId $RunId -Owner $Owner -Generation $Generation `
        -AllocationSeed $AllocationSeed -Endpoint $endpoint
    $existing = $null
    if ($Script:StorePortReservations.ContainsKey($id)) {
        $existing = $Script:StorePortReservations[$id]
    }
    if ($null -ne $existing -and [string]$existing['state'] -cne 'Released') {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-REUSED: a live reservation for this run already holds the reservation identity.')
    }
    # An endpoint is claimed, not a name. While ANY live reservation in this
    # registry still holds this host:port, no second registration may name it,
    # whatever runId/owner/generation/seed the newcomer carries -- those fields
    # are the OWNER record of a claim, never the identity OF the claim. The two
    # refusals stay distinct: this run asking again for an endpoint it already
    # holds is a reused reservation; anyone else racing for a held endpoint is a
    # genuine port conflict.
    foreach ($other in $Script:StorePortReservations.Values) {
        if ([string]$other['state'] -ceq 'Released') { continue }
        if ([string]$other['endpoint'] -cne $endpoint) { continue }
        if ([string]$other['runId'] -ceq $RunId -and [string]$other['owner'] -ceq $Owner -and
            [int]$other['generation'] -eq $Generation) {
            throw [System.InvalidOperationException]::new('STORE-RESERVATION-REUSED: this run already holds a live reservation for the endpoint.')
        }
        throw [System.InvalidOperationException]::new('STORE-PORT-CONFLICT: another live reservation already holds the endpoint.')
    }
    $record = @{
        reservationId = $id
        runId = $RunId
        owner = $Owner
        generation = $Generation
        allocationSeed = $AllocationSeed
        endpoint = $endpoint
        reservationProof = $proof
        listener = $listener
        state = 'Pending'
    }
    $Script:StorePortReservations[$id] = $record
    return $record
}

function Close-StoreSuppliedReservationListener {
    [CmdletBinding()]
    [OutputType([bool])]
    param([Parameter(Mandatory)] [AllowNull()]$Reservation)
    if ($null -eq $Reservation) {
        return $true
    }
    $listener = $null
    if ($Reservation -is [System.Net.Sockets.TcpListener]) {
        $listener = $Reservation
    } elseif ($Reservation -is [hashtable] -and $Reservation.ContainsKey('listener')) {
        $listener = $Reservation['listener']
    } else {
        return $true
    }
    if ($null -eq $listener) { return $true }
    if ($listener -isnot [System.Net.Sockets.TcpListener]) {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-CLEANUP-UNKNOWN: supplied listener handle has an unsupported type.')
    }
    try { $listener.Stop() } catch {
        throw [System.InvalidOperationException]::new("STORE-RESERVATION-CLEANUP-UNKNOWN: supplied listener release failed: $($_.Exception.Message)")
    }
    return $true
}

function Throw-StoreAllocationFailure {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]$PrimaryMessage,
        [Parameter(Mandatory)] [AllowNull()] [hashtable]$ReservationIdentity,
        [Parameter(Mandatory)] [AllowNull()]$Reservation,
        [Parameter(Mandatory)] [string]$RunId,
        [Parameter(Mandatory)] [string]$Owner,
        [Parameter(Mandatory)] [int]$Generation,
        [Parameter(Mandatory)] [string]$Endpoint
    )
    try {
        if ($null -ne $ReservationIdentity) {
            [void](Complete-StorePortReservation -Identity $ReservationIdentity -RunId $RunId -Owner $Owner `
                -Generation $Generation -Endpoint $Endpoint -Disposition 'cleanup')
        } else {
            [void](Close-StoreSuppliedReservationListener -Reservation $Reservation)
        }
    } catch {
        throw [System.InvalidOperationException]::new(
            "STORE-ALLOCATION-RECONCILIATION-REQUIRED: failure='$PrimaryMessage'; cleanup='$($_.Exception.Message)' owner='$RunId'.")
    }
    throw [System.InvalidOperationException]::new($PrimaryMessage)
}

function Complete-StorePortReservation {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [hashtable]$Identity,
        [Parameter(Mandatory)] [string]$RunId,
        [Parameter(Mandatory)] [string]$Owner,
        [Parameter(Mandatory)] [int]$Generation,
        [Parameter(Mandatory)] [string]$Endpoint,
        [Parameter(Mandatory)] [ValidateSet('launch-handoff', 'cleanup')] [string]$Disposition
    )
    foreach ($field in @('reservationId', 'runId', 'owner', 'generation', 'allocationSeed', 'endpoint')) {
        if (-not $Identity.ContainsKey($field)) {
            throw [System.InvalidOperationException]::new("STORE-RESERVATION-FOREIGN: reservation identity is missing '$field'.")
        }
    }
    $id = [string]$Identity['reservationId']
    if ([string]$Identity['runId'] -cne $RunId -or [string]$Identity['owner'] -cne $Owner -or
        [int]$Identity['generation'] -ne $Generation -or [string]$Identity['endpoint'] -cne $Endpoint) {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-FOREIGN: reservation identity does not match its binding.')
    }
    $expectedId = Get-StorePortReservationId -RunId $RunId -Owner $Owner -Generation $Generation `
        -AllocationSeed ([string]$Identity['allocationSeed']) -Endpoint $Endpoint
    if ($id -cne $expectedId -or -not $Script:StorePortReservations.ContainsKey($id)) {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-UNKNOWN: pending reservation owner is unavailable.')
    }
    $registered = $Script:StorePortReservations[$id]
    if ([string]$registered['runId'] -cne $RunId -or [string]$registered['owner'] -cne $Owner -or
        [int]$registered['generation'] -ne $Generation -or [string]$registered['endpoint'] -cne $Endpoint -or
        [string]$registered['allocationSeed'] -cne [string]$Identity['allocationSeed']) {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-FOREIGN: reservation identity does not match its registered owner.')
    }
    if ([string]$registered['state'] -ceq 'Released') {
        if ($Disposition -ceq 'cleanup') { return $true }
        # A completed handoff is idempotent for the exact owner, but it stops
        # authorizing a launch once a competing live reservation holds the
        # endpoint: the released port is no longer this run's to hand off.
        foreach ($other in $Script:StorePortReservations.Values) {
            if ([string]$other['reservationId'] -ceq $id) { continue }
            if ([string]$other['state'] -ceq 'Released') { continue }
            if ([string]$other['endpoint'] -ceq $Endpoint) {
                throw [System.InvalidOperationException]::new('STORE-RESERVATION-REUSED: the released endpoint is held by a competing live reservation.')
            }
        }
        return $true
    }
    if (-not $Identity.ContainsKey('listener') -or -not [object]::ReferenceEquals($registered['listener'], $Identity['listener'])) {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-FOREIGN: pending reservation handle does not match its registered listener.')
    }
    if ($null -ne $registered['listener']) {
        try { $registered['listener'].Stop() } catch {
            throw [System.InvalidOperationException]::new("STORE-RESERVATION-CLEANUP-FAILED: owned listener release failed: $($_.Exception.Message)")
        }
    }
    $registered['state'] = 'Released'
    $registered['listener'] = $null
    $Identity['state'] = 'Released'
    $Identity['listener'] = $null
    return $true
}

function Get-StorePortReservationReceipt {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([Parameter(Mandatory)] [hashtable]$Identity)
    return @{
        reservationId = [string]$Identity['reservationId']
        runId = [string]$Identity['runId']
        owner = [string]$Identity['owner']
        generation = [int]$Identity['generation']
        allocationSeed = [string]$Identity['allocationSeed']
        endpoint = [string]$Identity['endpoint']
        reservationProof = [string]$Identity['reservationProof']
        state = [string]$Identity['state']
    }
}

# Prove the reservation is still this run's at the instant the endpoint is
# handed to the child, then release it exactly once. This is the step that makes
# the reservation->launch window safe: a reservation whose registry entry was
# dropped, whose binding was replaced, whose ownership proof this module cannot
# re-verify, or whose held socket no longer owns the loopback endpoint is
# refused as a lost/expired reservation, a foreign binding, an unproven proof, or
# a port race before any process is created, never released as if it were still
# ours.
function Assert-StorePortReservationHandoff {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)] [hashtable]$Identity,
        [Parameter(Mandatory)] [string]$RunId,
        [Parameter(Mandatory)] [string]$Owner,
        [Parameter(Mandatory)] [int]$Generation,
        [Parameter(Mandatory)] [string]$Endpoint
    )
    if (-not $Identity.ContainsKey('reservationId') -or -not $Identity.ContainsKey('reservationProof')) {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-UNKNOWN: the allocation carries no proven reservation identity.')
    }
    $id = [string]$Identity['reservationId']
    $proof = [string]$Identity['reservationProof']
    if ($proof -cne 'held-socket' -and $proof -cne 'seam-asserted') {
        throw [System.InvalidOperationException]::new("STORE-RESERVATION-UNKNOWN: reservation proof '$proof' is not an accepted ownership proof.")
    }
    if (-not $Script:StorePortReservations.ContainsKey($id)) {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-EXPIRED: the pending reservation owner is no longer registered.')
    }
    $registered = $Script:StorePortReservations[$id]
    if ([string]$registered['runId'] -cne $RunId -or [string]$registered['owner'] -cne $Owner -or
        [int]$registered['generation'] -ne $Generation -or [string]$registered['endpoint'] -cne $Endpoint -or
        [string]$registered['reservationProof'] -cne $proof) {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-FOREIGN: the registered reservation no longer matches this run binding.')
    }
    if ([string]$registered['state'] -ceq 'Pending') {
        # A launch needs an ownership proof this module can positively re-verify
        # now. 'held-socket' is that proof and it is re-read below; a
        # 'seam-asserted' record carries no socket at all, so nothing here can be
        # re-read and the seam's word alone must not authorize a child. It is a
        # distinct typed refusal from the expired/foreign/port-race ones because
        # its cause is an insufficient proof, not a lost or replaced claim.
        if ($proof -cne 'held-socket') {
            throw [System.InvalidOperationException]::new('STORE-RESERVATION-UNPROVEN: the reservation carries no re-verifiable ownership proof, so it cannot authorize a launch.')
        }
        $listener = $registered['listener']
        if ($null -eq $listener) {
            throw [System.InvalidOperationException]::new('STORE-RESERVATION-EXPIRED: the held-socket reservation lost its listener before launch.')
        }
        $local = $null
        try {
            $local = [System.Net.IPEndPoint]$listener.LocalEndpoint
        } catch {
            throw [System.InvalidOperationException]::new('STORE-PORT-RACE: the reserved endpoint is no longer held at launch.')
        }
        # A released or rebound handle no longer reports this endpoint, so the
        # comparison is a positive proof that this socket still holds the port.
        $parts = $Endpoint.Split(':')
        $portText = $parts[$parts.Count - 1]
        if ([string]$local.Address -cne $parts[0] -or [string]$local.Port -cne $portText) {
            throw [System.InvalidOperationException]::new('STORE-PORT-RACE: the reserved endpoint left this reservation before launch.')
        }
    }
    [void](Complete-StorePortReservation -Identity $Identity -RunId $RunId -Owner $Owner `
        -Generation $Generation -Endpoint $Endpoint -Disposition 'launch-handoff')
    return $true
}

$Script:StoreClosedOperations = @(
    'ValidateRequirement',
    'Plan',
    'Allocate',
    'Start',
    'ObserveReadiness',
    'ResetForTest',
    'CollectEvidence',
    'Stop',
    'VerifyCleanup'
)

$Script:StoreTerminalDispositions = @(
    'Passed',
    'AssertionFailed',
    'TimedOut',
    'ProcessCrashed',
    'InfrastructureBlocked',
    'UnsupportedExternalCredential',
    'HarnessError',
    'Cancelled',
    'NotExecutedDueToPriorContamination'
)

$Script:StoreForbiddenPlanKeys = @(
    'shellCommand',
    'executablePath',
    'rawArgv',
    'url',
    'credential',
    'environmentMap',
    'outputPath'
)

$Script:StoreForbiddenResultKeys = @(
    'testDenominator',
    'providerChoice',
    'chooseProvider',
    'command',
    'argv',
    'executable',
    'shellCommand',
    'testPassed',
    'markPassed',
    'verdictOverride'
)

$Script:StoreAllowedChildEnv = @(
    'PATH',
    'SystemRoot',
    'WINDIR',
    'TEMP',
    'TMP',
    'OS',
    'PATHEXT',
    'COMSPEC',
    'SURREAL_USER',
    'SURREAL_PASS'
)

$Script:StoreAllowedRootChildren = @(
    '.eliot-harness-owner.json',
    '.eliot-harness-reconciliation.json',
    'data',
    'logs',
    'secrets'
)

$Script:StoreReservedLeafPattern = '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\..*)?$'

function Get-StoreProviderIdentity {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{
        testClass        = $Script:StoreTestClass
        providerName     = $Script:StoreProviderName
        providerRevision = $Script:StoreProviderRevision
        interfaceVersion = $Script:StoreInterfaceVersion
        artifact         = $Script:StoreArtifact
        relativePath     = $Script:StoreRelativePath
        version          = $Script:StoreVersion
        architecture     = $Script:StoreArchitecture
        peMachine        = $Script:StorePeMachine
        digest           = $Script:StoreDigest
    }
}

function Get-StoreLockIdentity {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    return @{
        artifact     = $Script:StoreArtifact
        relativePath = $Script:StoreRelativePath
        version      = $Script:StoreVersion
        architecture = $Script:StoreArchitecture
        peMachine    = $Script:StorePeMachine
        sha256       = $Script:StoreDigest
    }
}

function Get-StoreClosedOperations {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:StoreClosedOperations)
}

function Get-StoreTerminalDispositions {
    [CmdletBinding()]
    [OutputType([string[]])]
    param()
    return @($Script:StoreTerminalDispositions)
}

function Test-StoreDigestFormat {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Digest
    )
    if ([string]::IsNullOrWhiteSpace($Digest)) {
        throw [System.ArgumentException]::new('STORE-INVALID-DIGEST: digest is empty.')
    }
    if ($Digest -cnotmatch '^[0-9a-f]{64}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-DIGEST: digest must be 64 lowercase hex.')
    }
    return $true
}

function Test-StoreClosedOperation {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Operation
    )
    if ([string]::IsNullOrWhiteSpace($Operation)) {
        throw [System.ArgumentException]::new('STORE-UNKNOWN-OPERATION: operation name is empty.')
    }
    foreach ($allowed in $Script:StoreClosedOperations) {
        if ($Operation -ceq $allowed) {
            return $true
        }
    }
    throw [System.ArgumentException]::new(
        "STORE-UNKNOWN-OPERATION: '$Operation' is not a member of the closed Store provider interface.")
}

function Test-StoreTerminalDisposition {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Disposition
    )
    if ([string]::IsNullOrWhiteSpace($Disposition)) {
        throw [System.ArgumentException]::new('STORE-INVALID-DISPOSITION: disposition is empty.')
    }
    foreach ($allowed in $Script:StoreTerminalDispositions) {
        if ($Disposition -ceq $allowed) {
            return $true
        }
    }
    throw [System.ArgumentException]::new(
        "STORE-INVALID-DISPOSITION: '$Disposition' is not an accepted terminal disposition.")
}

function Resolve-StoreDeadline {
    [CmdletBinding()]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock,
        [Parameter(Mandatory)]
        [string]$Operation
    )
    if (-not $Binding.ContainsKey('deadlineUtc') -or [string]::IsNullOrWhiteSpace([string]$Binding['deadlineUtc'])) {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: binding is missing deadlineUtc.')
    }
    $deadline = [System.DateTimeOffset]::Parse([string]$Binding['deadlineUtc'])
    $now = [System.DateTimeOffset]::UtcNow
    if ($null -ne $Clock) {
        $observed = (& $Clock)
        if ($observed -is [System.DateTimeOffset]) {
            $now = $observed
        } elseif ($observed -is [System.DateTime]) {
            $now = [System.DateTimeOffset]::new($observed.ToUniversalTime())
        } else {
            throw [System.ArgumentException]::new('STORE-INVALID-CLOCK: injected clock must return DateTimeOffset.')
        }
    }
    $remaining = [int]($deadline - $now).TotalSeconds
    if ($remaining -le 0) {
        throw [System.TimeoutException]::new("STORE-DEADLINE-EXCEEDED: operation '$Operation' has no remaining bound.")
    }
    return $remaining
}

function Test-StoreBindingShape {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    foreach ($field in @('runId', 'testClass', 'providerName', 'providerRevision', 'owner', 'generation', 'deadlineUtc')) {
        if (-not $Binding.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Binding[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-BINDING: binding is missing '$field'.")
        }
    }
    $runId = [string]$Binding['runId']
    if ($runId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: runId must be 32 lowercase hex.')
    }
    $gen = 0
    try { $gen = [int]$Binding['generation'] } catch {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: generation must be a positive integer.')
    }
    if ($gen -le 0) {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: generation must be positive.')
    }
    foreach ($key in @($Binding.Keys)) {
        foreach ($forbidden in @('shellCommand', 'executablePath', 'rawArgv', 'url', 'credential', 'environmentMap', 'outputPath')) {
            if ([string]$key -ieq $forbidden) {
                throw [System.InvalidOperationException]::new(
                    "STORE-BINDING-FORBIDDEN: binding must not carry '$key'.")
            }
        }
    }
    return $true
}

function Test-StoreProviderResultClosed {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Result,
        [Parameter(Mandatory)]
        [hashtable]$Binding
    )
    foreach ($key in @($Result.Keys)) {
        foreach ($forbidden in $Script:StoreForbiddenResultKeys) {
            if ([string]$key -ieq $forbidden) {
                throw [System.InvalidOperationException]::new(
                    "STORE-PROVIDER-FORBIDDEN: provider result must not contain '$key'.")
            }
        }
    }
    if ($Result.ContainsKey('runId') -and ([string]$Result['runId'] -cne [string]$Binding['runId'])) {
        throw [System.InvalidOperationException]::new('STORE-PROVIDER-FORBIDDEN: provider must not change the run identity.')
    }
    return $true
}

function Invoke-StoreProviderOperation {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Operation,
        [Parameter(Mandatory)]
        [hashtable]$Provider,
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter()]
        [hashtable]$Arguments,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock
    )
    [void](Test-StoreClosedOperation -Operation $Operation)
    if ($null -eq $Provider -or $Provider.Count -eq 0) {
        throw [System.ArgumentException]::new('STORE-INVALID-PROVIDER: provider table is empty.')
    }
    if (-not $Provider.ContainsKey($Operation)) {
        throw [System.ArgumentException]::new("STORE-UNKNOWN-OPERATION: provider has no implementation for '$Operation'.")
    }
    $implementation = $Provider[$Operation]
    if ($implementation -isnot [scriptblock]) {
        throw [System.ArgumentException]::new("STORE-INVALID-PROVIDER: operation '$Operation' must map to a scriptblock.")
    }
    [void](Test-StoreBindingShape -Binding $Binding)
    [void](Resolve-StoreDeadline -Binding $Binding -Clock $Clock -Operation $Operation)
    $localBinding = @{}
    foreach ($key in @($Binding.Keys)) {
        $localBinding[$key] = $Binding[$key]
    }
    $provenRunId = [string]$localBinding['runId']
    $provenBinding = @{
        runId            = $provenRunId
        testClass        = [string]$localBinding['testClass']
        providerRevision = [string]$localBinding['providerRevision']
    }
    $context = @{
        operation = $Operation
        binding   = $localBinding
        arguments = $Arguments
    }
    $raw = $null
    try {
        $raw = (& $implementation $context)
    } catch {
        throw [System.InvalidOperationException]::new(
            "STORE-PROVIDER-FAILED:$Operation : $($_.Exception.Message)")
    }
    if ($null -eq $raw) {
        throw [System.InvalidOperationException]::new("STORE-PROVIDER-FAILED:$Operation : provider returned no result.")
    }
    $result = @{}
    if ($raw -is [hashtable]) {
        $result = $raw
    } elseif ($raw -is [psobject]) {
        foreach ($prop in $raw.PSObject.Properties) {
            $result[[string]$prop.Name] = $prop.Value
        }
    } else {
        throw [System.InvalidOperationException]::new(
            "STORE-PROVIDER-FAILED:$Operation : provider result must be a hashtable.")
    }
    if ([string]$localBinding['runId'] -cne $provenRunId) {
        throw [System.InvalidOperationException]::new(
            'STORE-PROVIDER-FORBIDDEN: provider mutated the binding run identity.')
    }
    [void](Test-StoreProviderResultClosed -Result $result -Binding $provenBinding)
    return $result
}

function Invoke-StoreValidateRequirement {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Requirement,
        [Parameter(Mandatory)]
        [hashtable]$Lock
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    foreach ($field in @('testClass', 'providerRevision')) {
        if (-not $Requirement.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Requirement[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-REQUIREMENT: requirement is missing '$field'.")
        }
    }
    $reqClass = [string]$Requirement['testClass']
    if ($reqClass -cne $Script:StoreTestClass) {
        throw [System.InvalidOperationException]::new(
            "STORE-UNSUPPORTED-CLASS: requirement class '$reqClass' is not STORE.")
    }
    $reqRev = [string]$Requirement['providerRevision']
    if ($reqRev -cne $Script:StoreProviderRevision) {
        throw [System.InvalidOperationException]::new(
            "STORE-UNSUPPORTED-REVISION: provider revision '$reqRev' is not '$($Script:StoreProviderRevision)'.")
    }
    if ([string]$Binding['testClass'] -cne $Script:StoreTestClass) {
        throw [System.InvalidOperationException]::new('STORE-BINDING-MISMATCH: binding testClass is not STORE.')
    }
    if ([string]$Binding['providerRevision'] -cne $Script:StoreProviderRevision) {
        throw [System.InvalidOperationException]::new('STORE-BINDING-MISMATCH: binding providerRevision mismatch.')
    }
    if ([string]$Binding['providerName'] -cne $Script:StoreProviderName) {
        throw [System.InvalidOperationException]::new('STORE-BINDING-MISMATCH: binding providerName mismatch.')
    }
    foreach ($field in @('version', 'architecture', 'peMachine', 'sha256', 'artifact')) {
        if (-not $Lock.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Lock[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-LOCK: lock is missing '$field'.")
        }
    }
    if ([string]$Lock['version'] -cne $Script:StoreVersion) {
        throw [System.InvalidOperationException]::new(
            "STORE-LOCK-MISMATCH: lock version '$($Lock['version'])' is not '$($Script:StoreVersion)'.")
    }
    if ([string]$Lock['architecture'] -cne $Script:StoreArchitecture) {
        throw [System.InvalidOperationException]::new('STORE-LOCK-MISMATCH: lock architecture mismatch.')
    }
    if ([string]$Lock['peMachine'] -cne $Script:StorePeMachine) {
        throw [System.InvalidOperationException]::new('STORE-LOCK-MISMATCH: lock peMachine mismatch.')
    }
    if ([string]$Lock['artifact'] -cne $Script:StoreArtifact) {
        throw [System.InvalidOperationException]::new('STORE-LOCK-MISMATCH: lock artifact mismatch.')
    }
    [void](Test-StoreDigestFormat -Digest ([string]$Lock['sha256']))
    if ([string]$Lock['sha256'] -cne $Script:StoreDigest) {
        throw [System.InvalidOperationException]::new('STORE-LOCK-MISMATCH: lock digest does not match the pinned SurrealDB identity.')
    }
    return @{
        runId            = [string]$Binding['runId']
        testClass        = $Script:StoreTestClass
        providerName     = $Script:StoreProviderName
        providerRevision = $Script:StoreProviderRevision
        version          = $Script:StoreVersion
        architecture     = $Script:StoreArchitecture
        peMachine        = $Script:StorePeMachine
        digest           = $Script:StoreDigest
        artifact         = $Script:StoreArtifact
        accepted         = $true
    }
}

function Invoke-StorePlan {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Requirement
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    if ([string]$Requirement['testClass'] -cne $Script:StoreTestClass) {
        throw [System.InvalidOperationException]::new('STORE-UNSUPPORTED-CLASS: plan requirement class is not STORE.')
    }
    if ([string]$Requirement['providerRevision'] -cne $Script:StoreProviderRevision) {
        throw [System.InvalidOperationException]::new('STORE-UNSUPPORTED-REVISION: plan requirement revision mismatch.')
    }
    $runId = [string]$Binding['runId']
    $owner = [string]$Binding['owner']
    $gen = [int]$Binding['generation']
    $consumedReceipts = @()
    if ($Requirement.ContainsKey('requiredReceipts') -and $null -ne $Requirement['requiredReceipts']) {
        $consumedReceipts = @($Requirement['requiredReceipts'])
        [void](Test-StoreRequiredReceiptSet -RequiredReceipts $consumedReceipts -RunId $runId)
    }
    $resources = @(
        @{ resourceKey = 'surreal-data'; testClass = $Script:StoreTestClass; providerRevision = $Script:StoreProviderRevision; runId = $runId; owner = $owner; generation = $gen },
        @{ resourceKey = 'surreal-logs'; testClass = $Script:StoreTestClass; providerRevision = $Script:StoreProviderRevision; runId = $runId; owner = $owner; generation = $gen },
        @{ resourceKey = 'surreal-secrets'; testClass = $Script:StoreTestClass; providerRevision = $Script:StoreProviderRevision; runId = $runId; owner = $owner; generation = $gen }
    )
    foreach ($resource in $resources) {
        foreach ($key in @($resource.Keys)) {
            foreach ($forbidden in $Script:StoreForbiddenPlanKeys) {
                if ([string]$key -ieq $forbidden) {
                    throw [System.InvalidOperationException]::new(
                        "STORE-PLAN-FORBIDDEN: plan resource must not carry '$key'.")
                }
            }
        }
    }
    return @{
        runId            = $runId
        testClass        = $Script:StoreTestClass
        providerName     = $Script:StoreProviderName
        providerRevision = $Script:StoreProviderRevision
        owner            = $owner
        generation       = $gen
        resources        = $resources
        mutationFree     = $true
        requiredReceipts = $consumedReceipts
    }
}

function Resolve-StoreOwnedPath {
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ExpectedRunId
    )
    if ([string]::IsNullOrWhiteSpace($RunRoot)) {
        throw [System.ArgumentException]::new('STORE-INVALID-PATH: RunRoot is empty.')
    }
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw [System.ArgumentException]::new('STORE-INVALID-PATH: Path is empty.')
    }
    if ($ExpectedRunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: ExpectedRunId must be 32 lowercase hex.')
    }
    $rootFull = [System.IO.Path]::GetFullPath($RunRoot)
    $candidate = $Path
    if (-not [System.IO.Path]::IsPathFullyQualified($candidate)) {
        $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $candidate))
    } else {
        $candidate = [System.IO.Path]::GetFullPath($candidate)
    }
    $prefix = $rootFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if ($candidate -ine $rootFull -and -not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw [System.InvalidOperationException]::new("STORE-PATH-ESCAPE: path escapes the admitted run root: $candidate")
    }
    $leaf = [System.IO.Path]::GetFileName($candidate)
    if (-not [string]::IsNullOrEmpty($leaf) -and $leaf -match $Script:StoreReservedLeafPattern) {
        throw [System.InvalidOperationException]::new("STORE-RESERVED-PATH: reserved device name rejected: $leaf")
    }
    foreach ($segment in ($candidate.Substring($rootFull.Length).Split([System.IO.Path]::DirectorySeparatorChar))) {
        if ($segment -match $Script:StoreReservedLeafPattern) {
            throw [System.InvalidOperationException]::new("STORE-RESERVED-PATH: reserved device segment rejected: $segment")
        }
    }
    $probe = $candidate
    while ($null -ne $probe -and $probe.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $entry = $null
        try { $entry = Get-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue } catch { $entry = $null }
        if ($null -ne $entry) {
            if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                $linkKind = ''
                try { $linkKind = [string]$entry.LinkType } catch { $linkKind = '' }
                if ($linkKind -ieq 'SymbolicLink') {
                    throw [System.InvalidOperationException]::new("STORE-SYMLINK-ESCAPE: path crosses a symbolic link: $($entry.FullName)")
                }
                throw [System.InvalidOperationException]::new("STORE-REPARSE-ESCAPE: path crosses a reparse point: $($entry.FullName)")
            }
        }
        if ($probe -ieq $rootFull) { break }
        $parent = Split-Path -Parent $probe
        if ([string]::IsNullOrWhiteSpace($parent) -or $parent -eq $probe) { break }
        $probe = $parent
    }
    $cursor = $candidate
    while (-not [string]::IsNullOrWhiteSpace($cursor) -and $cursor.StartsWith($rootFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        $marker = Join-Path $cursor $Script:StoreOwnerMarkerFile
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            try {
                $recorded = Get-Content -LiteralPath $marker -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if ($recorded.run_id -cne $ExpectedRunId) {
                    throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: owner marker belongs to another run: $cursor")
                }
            } catch [System.InvalidOperationException] {
                throw
            } catch {
                throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: owner marker unreadable at: $cursor")
            }
            break
        }
        if ($cursor -ieq $rootFull) { break }
        $next = Split-Path -Parent $cursor
        if ([string]::IsNullOrWhiteSpace($next) -or $next -eq $cursor) { break }
        $cursor = $next
    }
    return $candidate
}

# The one ownership predicate for an owned root, shared by the reuse path
# (New-StoreDefaultFileSystem ensure-owned-root) and the removal path
# (Remove-StoreOwnedRoot) so a root is never reused or deleted on a weaker
# claim than the one that created it. Ownership is read back from marker
# CONTENT: the marker value, the run, the owner and the generation must all be
# stated by the recorded marker. A predictable root path proves nothing, and a
# marker that names only the run proves nothing about who owns it now.
function Test-StoreOwnedRootClaim {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        $Recorded,
        [Parameter(Mandatory)]
        [string]$RunId,
        [Parameter(Mandatory)]
        [string]$Owner,
        [Parameter(Mandatory)]
        [int]$Generation
    )
    if ($null -eq $Recorded) { return $false }
    $markerProp = $Recorded.PSObject.Properties['marker']
    if ($null -eq $markerProp -or [string]$markerProp.Value -cne $Script:StoreOwnedRootMarker) { return $false }
    $runProp = $Recorded.PSObject.Properties['run_id']
    if ($null -eq $runProp -or [string]$runProp.Value -cne $RunId) { return $false }
    $ownerProp = $Recorded.PSObject.Properties['owner']
    if ($null -eq $ownerProp -or [string]$ownerProp.Value -cne $Owner) { return $false }
    $generationProp = $Recorded.PSObject.Properties['generation']
    if ($null -eq $generationProp) { return $false }
    $recordedGeneration = -1
    try { $recordedGeneration = [int]$generationProp.Value } catch { $recordedGeneration = -1 }
    if ($recordedGeneration -ne $Generation) { return $false }
    return $true
}

function Get-StoreChildEnv {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Ambient
    )
    $filtered = @{}
    foreach ($key in @($Ambient.Keys)) {
        if ($key -cnotin $Script:StoreAllowedChildEnv) { continue }
        $name = [string]$key
        $isCredentialChannel = ($name -ceq $Script:StoreCredentialUserEnv -or $name -ceq $Script:StoreCredentialPassEnv)
        if (-not $isCredentialChannel) {
            $upper = $name.ToUpperInvariant()
            if ($upper.Contains('TOKEN') -or $upper.Contains('SECRET') -or $upper.Contains('CREDENTIAL') -or $upper.Contains('PASSWORD') -or $upper.Contains('KEY')) {
                continue
            }
        }
        $value = [string]$Ambient[$key]
        $bytes = [System.Text.Encoding]::UTF8.GetByteCount($value)
        if ($bytes -gt 4096) {
            throw [System.InvalidOperationException]::new("STORE-ENV-BOUND: child env value exceeds byte cap: $key")
        }
        $filtered[$key] = $value
    }
    return $filtered
}

function New-StoreEphemeralCredential {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$CredentialId,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Entropy
    )
    if ([string]::IsNullOrWhiteSpace($CredentialId)) {
        throw [System.ArgumentException]::new('STORE-INVALID-CREDENTIAL: credential id is empty.')
    }
    if ($CredentialId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-CREDENTIAL: credential id has an invalid shape.')
    }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or [string]::IsNullOrWhiteSpace($nonce)) {
            throw [System.ArgumentException]::new('STORE-INVALID-ENTROPY: entropy must return nonempty text.')
        }
    } else {
        $bytes = [byte[]]::new(16)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
        $nonce = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
    }
    if ($nonce -cnotmatch '^[0-9a-f]{8,128}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-ENTROPY: entropy nonce must be lowercase hex.')
    }
    $secret = ('store-ephemeral-' + $nonce)
    return @{
        credentialId     = $CredentialId
        credentialHandle = ('handle:' + $CredentialId + ':' + $nonce.Substring(0, 8))
        secret           = $secret
        ephemeral        = $true
    }
}

function Test-StoreProviderReceipt {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Receipt
    )
    foreach ($field in @('testClass', 'providerRevision', 'runId', 'digest', 'issuer')) {
        if (-not $Receipt.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Receipt[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-RECEIPT: provider receipt is missing '$field'.")
        }
    }
    $class = [string]$Receipt['testClass']
    if ($class -cne 'STORE' -and $class -cne 'GIT') {
        throw [System.InvalidOperationException]::new(
            "STORE-RECEIPT-CLASS: provider receipt class '$class' is not an accepted dependency lane.")
    }
    $expectedRevision = $Script:StoreProviderRevision
    $expectedIssuer = 'store-provider-owner'
    if ($class -ceq 'GIT') {
        $expectedRevision = $Script:StoreGitReceiptRevision
        $expectedIssuer = 'git-provider-owner'
    }
    if ([string]$Receipt['providerRevision'] -cne $expectedRevision) {
        throw [System.InvalidOperationException]::new(
            'STORE-RECEIPT-REVISION: provider receipt revision is not the accepted lane revision.')
    }
    if ([string]$Receipt['runId'] -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-RECEIPT: receipt runId must be 32 lowercase hex.')
    }
    [void](Test-StoreDigestFormat -Digest ([string]$Receipt['digest']))
    if ([string]$Receipt['issuer'] -cne $expectedIssuer) {
        throw [System.InvalidOperationException]::new(
            'STORE-RECEIPT-UNFABRICABLE: receipt issuer is not the lane owner; self-minted receipts are rejected.')
    }
    return $true
}

function Test-StoreRequiredReceiptSet {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [array]$RequiredReceipts,
        [Parameter(Mandatory)]
        [string]$RunId
    )
    $seen = @{}
    foreach ($entry in @($RequiredReceipts)) {
        if ($null -eq $entry -or $entry -isnot [hashtable]) {
            throw [System.ArgumentException]::new('STORE-INVALID-RECEIPT: required receipt entry must be a hashtable.')
        }
        foreach ($key in @($entry.Keys)) {
            if ([string]$key -cnotin @('kind', 'testClass', 'providerRevision', 'runId', 'digest', 'issuer')) {
                throw [System.ArgumentException]::new(
                    "STORE-INVALID-RECEIPT: required receipt carries an unexpected field '$key'.")
            }
        }
        foreach ($field in @('kind', 'testClass', 'providerRevision', 'runId')) {
            if (-not $entry.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$entry[$field])) {
                throw [System.ArgumentException]::new("STORE-INVALID-RECEIPT: required receipt is missing '$field'.")
            }
        }
        $kind = [string]$entry['kind']
        $class = [string]$entry['testClass']
        $paired = (($kind -ceq 'store-receipt' -and $class -ceq 'STORE') -or ($kind -ceq 'git-receipt' -and $class -ceq 'GIT'))
        if (-not $paired) {
            throw [System.InvalidOperationException]::new(
                "STORE-RECEIPT-KIND: required receipt kind '$kind' does not pair with class '$class'.")
        }
        $expectedRevision = $Script:StoreProviderRevision
        if ($class -ceq 'GIT') {
            $expectedRevision = $Script:StoreGitReceiptRevision
        }
        if ([string]$entry['providerRevision'] -cne $expectedRevision) {
            throw [System.InvalidOperationException]::new(
                'STORE-RECEIPT-REVISION: required receipt revision is not the accepted lane revision.')
        }
        if ([string]$entry['runId'] -cne $RunId) {
            throw [System.InvalidOperationException]::new(
                'STORE-RECEIPT-FOREIGN: required receipt run identity does not match the binding.')
        }
        if ($seen.ContainsKey($kind)) {
            throw [System.InvalidOperationException]::new(
                "STORE-RECEIPT-DUPLICATE: required receipt kind '$kind' appears more than once.")
        }
        $seen[$kind] = $true
        if ($entry.ContainsKey('digest') -or $entry.ContainsKey('issuer')) {
            [void](Test-StoreProviderReceipt -Receipt $entry)
        }
    }
    return $true
}

function Get-StoreRedactedText {
    [CmdletBinding()]
    [OutputType([psobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Text,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Secrets,
        [ValidateRange(1, 16777216)]
        [int]$MaxBytes = 65536
    )
    $redacted = $Text
    try {
        if ($null -ne $Secrets) {
            foreach ($secret in $Secrets) {
                if ([string]::IsNullOrEmpty($secret)) { continue }
                $redacted = $redacted.Replace($secret, '[redacted-store-secret]')
            }
        }
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)(password|passwd|secret|token|api[_-]?key|connectionstring)\s*[:=]\s*\S+',
            '$1=[redacted-store-secret]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)surreal_[a-z_]*(pass|secret|token|key)[a-z_]*\s*=\s*\S+',
            '[redacted-store-secret]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)CONTENT\s*\{[^}]{0,4096}\}',
            'CONTENT [redacted-store-secret]')
        $redacted = [regex]::Replace(
            $redacted,
            '(?i)[A-Za-z]:\\Users\\[^\\/:*?"<>|]+',
            '[redacted-user-path]')
    } catch {
        return [pscustomobject]@{
            text      = ''
            bytes     = 0
            truncated = $false
            failed    = $true
        }
    }
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($redacted)
    } catch {
        return [pscustomobject]@{
            text      = ''
            bytes     = 0
            truncated = $false
            failed    = $true
        }
    }
    $truncated = $bytes.Length -gt $MaxBytes
    $output = $redacted
    if ($truncated) {
        try {
            $output = [System.Text.Encoding]::UTF8.GetString($bytes, $bytes.Length - $MaxBytes, $MaxBytes)
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($output)
        } catch {
            return [pscustomobject]@{
                text      = ''
                bytes     = 0
                truncated = $true
                failed    = $true
            }
        }
    }
    return [pscustomobject]@{
        text      = $output
        bytes     = $bytes.Length
        truncated = $truncated
        failed    = $false
    }
}

function Invoke-StoreAllocate {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Plan,
        [Parameter(Mandatory)]
        [string]$BaseTemp,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Entropy,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$PortReservation,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileSystem,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Acl
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    $consumedReceipts = @()
    if ($Plan.ContainsKey('requiredReceipts') -and $null -ne $Plan['requiredReceipts']) {
        $consumedReceipts = @($Plan['requiredReceipts'])
        [void](Test-StoreRequiredReceiptSet -RequiredReceipts $consumedReceipts -RunId ([string]$Binding['runId']))
    }
    if ([string]$Plan['runId'] -cne [string]$Binding['runId']) {
        throw [System.InvalidOperationException]::new('STORE-ALLOCATION-MISMATCH: plan run identity does not match binding.')
    }
    if ([string]::IsNullOrWhiteSpace($BaseTemp)) {
        throw [System.ArgumentException]::new('STORE-INVALID-PATH: BaseTemp is empty.')
    }
    $runId = [string]$Binding['runId']
    $owner = [string]$Binding['owner']
    $gen = [int]$Binding['generation']
    $baseFull = [System.IO.Path]::GetFullPath($BaseTemp)
    $lower = $baseFull.ToLowerInvariant()
    if ($lower.Contains('onedrive') -or $lower.Contains('programdata')) {
        throw [System.InvalidOperationException]::new('STORE-FORBIDDEN-ROOT: allocation base crossed a forbidden host boundary.')
    }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or $nonce -cnotmatch '^[0-9a-f]{8,64}$') {
            throw [System.ArgumentException]::new('STORE-INVALID-ENTROPY: entropy must return lowercase hex.')
        }
    } else {
        $nonce = $runId.Substring(0, 8)
    }
    $runRoot = [System.IO.Path]::GetFullPath((Join-Path $baseFull ("eliot-store-{0}-{1}" -f $runId, $nonce)))
    $prefix = $baseFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $runRoot.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw [System.InvalidOperationException]::new("STORE-PATH-ESCAPE: allocated run root escaped its base: $runRoot")
    }
    $dataRoot = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'data'))
    $logRoot = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'logs'))
    $secretRoot = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'secrets'))
    [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $dataRoot -ExpectedRunId $runId)
    [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $logRoot -ExpectedRunId $runId)
    [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $secretRoot -ExpectedRunId $runId)
    # Namespace and database are PER-ALLOCATION names, not per-run names. The
    # entropy source is the same allocationSeed ($nonce) that already makes
    # $runRoot unique above: the FIRST 8 hex chars of the runId give the run half
    # (readable, stable) and the LAST 8 hex chars of that seed give the
    # per-allocation half, so two allocations inside ONE run -- which this module
    # explicitly supports and re-derives -- never collide on either name. The
    # derivation is a pure function of (runId prefix, allocationSeed suffix), so
    # re-running the same allocation re-derives the identical pair with no extra
    # randomness. Entropy honestly stated: it is exactly the 32 bits of the
    # injected entropy seam (or the runId-derived default when no seam is
    # injected), which is ample against accidental collision inside one process
    # but is NOT a cryptographic claim and is NOT unique across processes whose
    # seeds coincide. The module still never adopts a name it did not win
    # (STORE-NAMESPACE-FOREIGN); a name collision surfaces there rather than
    # being silently shared.
    $allocationTag = $nonce.Substring($nonce.Length - 8)
    $namespace = ('eliot_ns_' + $runId.Substring(0, 8) + '_' + $allocationTag)
    $database = ('eliot_db_' + $runId.Substring(0, 8) + '_' + $allocationTag)
    if ($namespace -cnotmatch '^[A-Za-z0-9_]{1,64}$' -or $database -cnotmatch '^[A-Za-z0-9_]{1,64}$') {
        throw [System.InvalidOperationException]::new('STORE-ALLOCATION-MISMATCH: derived namespace/database has an invalid shape.')
    }
    if ($null -eq $PortReservation) {
        throw [System.ArgumentException]::new('STORE-MISSING-RESERVATION: a port-reservation seam is required; no implicit bind is performed.')
    }
    $reservation = $null
    try {
        $reservation = (& $PortReservation @{ runId = $runId; namespace = $namespace; database = $database })
    } catch {
        # A reservation that could not be taken is a port race/conflict and stays
        # distinct from the reservation-ownership and cleanup refusals. No owned
        # endpoint exists yet, so Allocate refuses before any root is created.
        if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
        throw [System.InvalidOperationException]::new("STORE-PORT-CONFLICT: the loopback endpoint could not be reserved: $($_.Exception.Message)")
    }
    $port = 0
    $host_ = $Script:StoreLoopback
    $endpoint = 'unresolved'
    $reservationIdentity = $null
    try {
        if ($reservation -isnot [hashtable] -or -not $reservation.ContainsKey('port')) {
            throw [System.InvalidOperationException]::new('STORE-PORT-CONFLICT: reservation must return a port mapping.')
        }
        try { $port = [int]$reservation['port'] } catch {
            throw [System.InvalidOperationException]::new('STORE-PORT-CONFLICT: reservation port is not an integer.')
        }
        if ($port -lt 1024 -or $port -gt 65535) {
            throw [System.InvalidOperationException]::new("STORE-PORT-CONFLICT: reserved port '$port' is outside the ephemeral bound.")
        }
        if ($reservation.ContainsKey('host')) { $host_ = [string]$reservation['host'] }
        if ($host_ -cne $Script:StoreLoopback) {
            throw [System.InvalidOperationException]::new("STORE-ENDPOINT-FORBIDDEN: endpoint host '$host_' is not loopback.")
        }
        $endpoint = ('{0}:{1}' -f $host_, $port)
        $reservationIdentity = Register-StorePortReservation -Reservation $reservation `
            -RunId $runId -Owner $owner -Generation $gen -AllocationSeed $nonce -ReservationHost $host_ -Port $port
    } catch {
        $primary = $_.Exception.Message
        Throw-StoreAllocationFailure -PrimaryMessage $primary -ReservationIdentity $reservationIdentity `
            -Reservation $reservation -RunId $runId -Owner $owner -Generation $gen -Endpoint $endpoint
    }
    $fs = $FileSystem
    if ($null -eq $fs) {
        $fs = New-StoreDefaultFileSystem
    }
    $created = $false
    $existed = $false
    $markerPath = Join-Path $runRoot $Script:StoreOwnerMarkerFile
    try {
        $fsResult = (& $fs @{
            op         = 'ensure-owned-root'
            runRoot    = $runRoot
            dataRoot   = $dataRoot
            logRoot    = $logRoot
            secretRoot = $secretRoot
            runId      = $runId
            owner      = $owner
            generation = $gen
        })
    } catch {
        $primary = $_.Exception.Message
        if ($primary -notmatch '^STORE-[A-Z0-9-]+:') { $primary = "STORE-ALLOCATION-FAILED: owned root creation failed: $primary" }
        Throw-StoreAllocationFailure -PrimaryMessage $primary -ReservationIdentity $reservationIdentity `
            -Reservation $reservation -RunId $runId -Owner $owner -Generation $gen -Endpoint $endpoint
    }
    if ($null -ne $fsResult -and $fsResult -is [hashtable]) {
        if ($fsResult.ContainsKey('created')) { $created = [bool]$fsResult['created'] }
        if ($fsResult.ContainsKey('existed')) { $existed = [bool]$fsResult['existed'] }
        if ($fsResult.ContainsKey('markerPath')) { $markerPath = [string]$fsResult['markerPath'] }
    }
    $aclSeam = $Acl
    if ($null -eq $aclSeam) {
        $aclSeam = New-StoreDefaultAcl
    }
    foreach ($protectedRoot in @($secretRoot, $dataRoot, $logRoot)) {
        try {
            [void](& $aclSeam @{ op = 'protect'; path = $protectedRoot; runId = $runId })
        } catch {
            $primary = $_.Exception.Message
            if ($primary -notmatch '^STORE-[A-Z0-9-]+:') { $primary = "STORE-ACL-FAILED: root protection failed for '$protectedRoot': $primary" }
            Throw-StoreAllocationFailure -PrimaryMessage $primary -ReservationIdentity $reservationIdentity `
                -Reservation $reservation -RunId $runId -Owner $owner -Generation $gen -Endpoint $endpoint
        }
    }
    return @{
        runId          = $runId
        runRoot        = $runRoot
        dataRoot       = $dataRoot
        logRoot        = $logRoot
        secretRoot     = $secretRoot
        ownerMarker    = $Script:StoreOwnedRootMarker
        markerPath     = $markerPath
        rootsCreated   = $created
        rootsExisted   = $existed
        namespace      = $namespace
        database       = $database
        endpoint       = $endpoint
        host           = $host_
        port           = $port
        reservationIdentity = $reservationIdentity
        owner          = $owner
        generation     = $gen
        allocationSeed = $nonce
        credentialChannel = 'child-env'
        requiredReceipts = $consumedReceipts
    }
}

function Invoke-StoreStart {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Allocation,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Acquisition,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$Launcher,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Entropy,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileSystem,
        [Parameter()]
        [AllowNull()]
        [hashtable]$AmbientEnvironment
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]$Allocation['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-START-MISMATCH: allocation run identity does not match binding.')
    }
    foreach ($field in @('endpoint', 'namespace', 'database', 'dataRoot', 'logRoot', 'runRoot')) {
        if (-not $Allocation.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Allocation[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-ALLOCATION: allocation is missing '$field'.")
        }
    }
    if (-not $Allocation.ContainsKey('reservationIdentity') -or $Allocation['reservationIdentity'] -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-RESERVATION-UNKNOWN: allocation carries no owned reservation identity.')
    }
    $reservationIdentity = $Allocation['reservationIdentity']
    $reservationReleased = $false
    try {
    $storeFs = $FileSystem
    if ($null -eq $storeFs) {
        $storeFs = New-StoreDefaultFileSystem
    }
    $runRoot = [string]$Allocation['runRoot']
    Assert-StoreNoPendingReconciliation -FileSystem $storeFs -RunRoot $runRoot -RunId $runId
    if ($null -eq $Acquisition) {
        throw [System.ArgumentException]::new('STORE-MISSING-ACQUISITION: an acquisition seam is required; no download is performed here.')
    }
    $receipt = $null
    try {
        $receipt = (& $Acquisition @{ runId = $runId; artifact = $Script:StoreArtifact })
    } catch {
        if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
        throw [System.InvalidOperationException]::new("STORE-ACQUISITION-FAILED: $($_.Exception.Message)")
    }
    if ($null -eq $receipt -or $receipt -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-ACQUISITION-FAILED: acquisition must return a hashtable receipt.')
    }
    foreach ($field in @('version', 'architecture', 'peMachine', 'digest', 'provenance', 'storePath')) {
        if (-not $receipt.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$receipt[$field])) {
            throw [System.InvalidOperationException]::new("STORE-ACQUISITION-FAILED: receipt is missing '$field'.")
        }
    }
    $version = [string]$receipt['version']
    if ($version -ieq 'latest') {
        throw [System.InvalidOperationException]::new('STORE-LATEST-REJECTED: floating latest tag is never accepted.')
    }
    if ($version -cne $Script:StoreVersion) {
        throw [System.InvalidOperationException]::new("STORE-VERSION-MISMATCH: version '$version' is not '$($Script:StoreVersion)'.")
    }
    if ([string]$receipt['architecture'] -cne $Script:StoreArchitecture) {
        throw [System.InvalidOperationException]::new('STORE-ARCH-MISMATCH: architecture mismatch.')
    }
    if ([string]$receipt['peMachine'] -cne $Script:StorePeMachine) {
        throw [System.InvalidOperationException]::new('STORE-ARCH-MISMATCH: peMachine mismatch.')
    }
    [void](Test-StoreDigestFormat -Digest ([string]$receipt['digest']))
    if ([string]$receipt['digest'] -cne $Script:StoreDigest) {
        throw [System.InvalidOperationException]::new('STORE-DIGEST-MISMATCH: binary digest does not match the pinned SurrealDB identity.')
    }
    $provenance = [string]$receipt['provenance']
    if ($provenance -cne 'acquired-verified' -and $provenance -cne 'cached-reverified') {
        if ($provenance -ieq 'caller-hash' -or $provenance -ieq 'caller-supplied') {
            throw [System.InvalidOperationException]::new('STORE-CALLER-HASH-REJECTED: caller-supplied hashes never establish provenance.')
        }
        throw [System.InvalidOperationException]::new("STORE-PROVENANCE-MISSING: provenance '$provenance' is not an accepted verified acquisition.")
    }
    $storePath = [string]$receipt['storePath']
    if (-not $storePath.EndsWith($Script:StoreArtifact, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw [System.InvalidOperationException]::new('STORE-ACQUISITION-FAILED: store path does not name the approved artifact.')
    }
    $nonce = $null
    if ($null -ne $Entropy) {
        $nonce = (& $Entropy)
        if ($nonce -isnot [string] -or $nonce -cnotmatch '^[0-9a-f]{8,64}$') {
            throw [System.ArgumentException]::new('STORE-INVALID-ENTROPY: entropy must return lowercase hex.')
        }
    } else {
        $nonce = $runId.Substring(16, 8)
    }
    $credential = New-StoreEphemeralCredential -CredentialId $Script:StoreCredentialId -Entropy $Entropy
    $credentialUser = 'store-root'
    $credentialSecret = [string]$credential['secret']
    $dataUrl = ($Script:StoreSurrealScheme + (([string]$Allocation['dataRoot']).Replace('\', '/')))
    $fixedArgv = @(
        $storePath,
        'start',
        '--no-banner',
        '--bind', ([string]$Allocation['endpoint']),
        '--temporary-directory', $runRoot,
        '--log-file-enabled',
        '--log-file-path', ([string]$Allocation['logRoot']),
        '--log-file-name', $Script:StoreLogFileName,
        $dataUrl
    )
    $ambient = $AmbientEnvironment
    if ($null -eq $ambient) {
        $ambient = Get-StoreAmbientEnvironment
    }
    $childEnv = Get-StoreChildEnv -Ambient $ambient
    $childEnv['TEMP'] = $runRoot
    $childEnv['TMP'] = $runRoot
    $childEnv[$Script:StoreCredentialUserEnv] = $credentialUser
    $childEnv[$Script:StoreCredentialPassEnv] = $credentialSecret
    if ($null -eq $Launcher) {
        throw [System.ArgumentException]::new('STORE-MISSING-LAUNCHER: a process-launcher seam is required; no live spawn is performed here.')
    }
    $launchInput = @{
        runId            = $runId
        argv              = $fixedArgv
        endpoint         = [string]$Allocation['endpoint']
        namespace        = [string]$Allocation['namespace']
        database         = [string]$Allocation['database']
        childEnv         = $childEnv
        workingDirectory = $runRoot
        requestKey       = ('req-' + $nonce)
        credentialHandle = [string]$credential['credentialHandle']
        imageDigest      = [string]$receipt['digest']
        provenance       = $provenance
    }
    # Prove the reservation is still this run's owned endpoint immediately before
    # the child is created, then release it exactly once. A lost/expired
    # reservation and a port taken by someone else are distinct typed refusals
    # raised here, before any process exists.
    [void](Assert-StorePortReservationHandoff -Identity $reservationIdentity -RunId $runId `
        -Owner ([string]$Binding['owner']) -Generation ([int]$Binding['generation']) `
        -Endpoint ([string]$Allocation['endpoint']))
    $reservationReleased = $true
    $observed = $null
    try {
        $observed = (& $Launcher $launchInput)
    } catch {
        $message = $_.Exception.Message
        if ($message -match '(?i)lost-response|timeout|unknown') {
            $reconciliation = Write-StoreLostResponseRecord -FileSystem $storeFs -RunRoot $runRoot -RunId $runId -Operation 'launch' -RequestKey ([string]$launchInput['requestKey']) -Endpoint ([string]$launchInput['endpoint']) -Owner ([string]$Binding['owner']) -Generation ([int]$Binding['generation']) -Detail $message
            return @{
                runId                = $runId
                startState           = 'ReconciliationRequired'
                requested            = @{ requestKey = $launchInput['requestKey']; endpoint = $launchInput['endpoint']; namespace = $launchInput['namespace']; database = $launchInput['database']; schemaDigest = $Script:StoreRequiredSchemaDigest }
                observed             = $null
                invocation           = @{ argvCount = $fixedArgv.Count; bindEndpoint = $launchInput['endpoint']; imagePath = $storePath }
                binary               = @{ version = $version; digest = [string]$receipt['digest']; provenance = $provenance }
                credentialHandle     = [string]$credential['credentialHandle']
                retryPermitted       = $false
                reconciliationOwner  = $runId
                reconciliationPath   = [string]$reconciliation['path']
                reconciliationPersisted = [bool]$reconciliation['persisted']
                reservationIdentity = (Get-StorePortReservationReceipt -Identity $reservationIdentity)
                reservationHandoff = 'close-before-launch'
                failure              = ('lost-response-owned:' + $message)
            }
        }
        if ($message -match '^STORE-[A-Z0-9-]+:') { throw }
        throw [System.InvalidOperationException]::new("STORE-LAUNCH-FAILED: $message")
    }
    if ($null -eq $observed -or $observed -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: launcher must return a hashtable observation.')
    }
    if (-not $observed.ContainsKey('observedPid') -or -not $observed.ContainsKey('observedNonce')) {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: launcher observation is missing pid/nonce.')
    }
    $observedPid = 0
    try { $observedPid = [int]$observed['observedPid'] } catch {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: observed pid is not an integer.')
    }
    if ($observedPid -le 0) {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: observed pid is not positive.')
    }
    $observedNonce = [string]$observed['observedNonce']
    if ($observedNonce -ceq $nonce) {
        throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: requested and observed nonces must be distinct handles.')
    }
    # Two identities are deliberately kept apart and neither is inferred from the
    # other. The launched image is a fact of this step's own launch input: argv[0]
    # is the digest- and provenance-verified store binary this step created, so it
    # is carried unconditionally and never depends on a launcher volunteering it.
    # The observed image/start time are a fact only of the launcher's own
    # observation of the process it created; a process start time is not knowable
    # before that process exists. When the launcher does not report them the
    # receipt says so through an explicit named disposition instead of a silently
    # absent field that a later step would have to guess about. Readiness and
    # stop both already fail closed on an unobserved identity, so the disposition
    # names that condition rather than changing it.
    $observedIdentity = @{ pid = $observedPid; nonce = $observedNonce; endpoint = $launchInput['endpoint'] }
    $observedIdentityComplete = $true
    foreach ($extra in @('imagePath', 'startTimeUtc', 'jobName')) {
        if ($observed.ContainsKey($extra) -and -not [string]::IsNullOrWhiteSpace([string]$observed[$extra])) {
            $observedIdentity[$extra] = [string]$observed[$extra]
        }
        elseif ($extra -ne 'jobName') {
            # jobName is a bounded handle binding, not part of the process
            # identity that ownership and PID-reuse proofs depend on.
            $observedIdentityComplete = $false
        }
    }
    $observedIdentity['identityState'] = $(if ($observedIdentityComplete) { 'Observed' } else { 'Unobserved' })
    return @{
        runId      = $runId
        runRoot    = $runRoot
        startState = 'StartRequested'
        requested  = @{ requestKey = $launchInput['requestKey']; endpoint = $launchInput['endpoint']; namespace = $launchInput['namespace']; database = $launchInput['database']; nonce = $nonce; schemaDigest = $Script:StoreRequiredSchemaDigest }
        observed   = $observedIdentity
        invocation = @{ argvCount = $fixedArgv.Count; bindEndpoint = $launchInput['endpoint']; artifact = $Script:StoreArtifact; imagePath = $storePath }
        binary     = @{ version = $version; architecture = $Script:StoreArchitecture; peMachine = $Script:StorePeMachine; digest = [string]$receipt['digest']; provenance = $provenance }
        credentialHandle = [string]$credential['credentialHandle']
        reservationIdentity = (Get-StorePortReservationReceipt -Identity $reservationIdentity)
        reservationHandoff = 'close-before-launch'
    }
    } finally {
        if (-not $reservationReleased) {
            [void](Complete-StorePortReservation -Identity $reservationIdentity -RunId $runId -Owner ([string]$Binding['owner']) `
                -Generation ([int]$Binding['generation']) -Endpoint ([string]$Allocation['endpoint']) -Disposition 'cleanup')
        }
    }
}

function Invoke-StoreObserveReadiness {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$StartReceipt,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$ProcessObserver,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$PortObserver,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$StoreClient,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    [void](Resolve-StoreDeadline -Binding $Binding -Clock $Clock -Operation 'ObserveReadiness')
    $runId = [string]$Binding['runId']
    if ([string]$StartReceipt['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: start receipt run identity is foreign.')
    }
    if (-not $StartReceipt.ContainsKey('reservationHandoff') -or
        [string]$StartReceipt['reservationHandoff'] -cne 'close-before-launch') {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt has no declared reservation handoff mode.')
    }
    if ($null -eq $StartReceipt['observed'] -or ($StartReceipt['observed'] -isnot [hashtable])) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt carries no observed process handle.')
    }
    $observed = $StartReceipt['observed']
    if (-not $observed.ContainsKey('pid') -or -not $observed.ContainsKey('endpoint')) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt observation is incomplete.')
    }
    if ($observed.ContainsKey('identityState') -and [string]$observed['identityState'] -ceq 'Unobserved') {
        # The launcher returned no observation of the process it created, so the
        # started image/start time is unproven. Liveness, port ownership and auth
        # could not be bound to the launched process without it.
        throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: start receipt carries no observed launched-process identity.')
    }
    if (-not $observed.ContainsKey('imagePath') -or -not $observed.ContainsKey('startTimeUtc')) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt observation is incomplete.')
    }
    $ownedPid = [int]$observed['pid']
    $ownedEndpoint = [string]$observed['endpoint']
    if ($null -eq $ProcessObserver -or $null -eq $PortObserver -or $null -eq $StoreClient) {
        throw [System.ArgumentException]::new('STORE-MISSING-OBSERVER: process, port, and Store-client seams are all required.')
    }
    $process = (& $ProcessObserver @{ pid = $ownedPid; runId = $runId })
    $port = (& $PortObserver @{ endpoint = $ownedEndpoint; runId = $runId })
    if ($null -eq $process -or $process -isnot [hashtable] -or
        -not $process.ContainsKey('alive') -or -not $process.ContainsKey('pid') -or
        -not $process.ContainsKey('imagePath') -or -not $process.ContainsKey('startTimeUtc')) {
        throw [System.InvalidOperationException]::new('STORE-OBSERVER-FAILED: process observer must return an alive mapping.')
    }
    if ($null -eq $port -or $port -isnot [hashtable] -or
        -not $port.ContainsKey('open') -or -not $port.ContainsKey('endpoint')) {
        throw [System.InvalidOperationException]::new('STORE-OBSERVER-FAILED: port observer must return an open mapping.')
    }
    $alive = [bool]$process['alive']
    $open = [bool]$port['open']
    if ($process.ContainsKey('pid') -and ([int]$process['pid'] -ne $ownedPid)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: process observer returned a foreign pid.')
    }
    if (-not [string]::Equals([string]$process['imagePath'], [string]$observed['imagePath'], [System.StringComparison]::OrdinalIgnoreCase) -or
        [string]$process['startTimeUtc'] -cne [string]$observed['startTimeUtc']) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: process image or start identity changed after launch.')
    }
    if ($port.ContainsKey('endpoint') -and ([string]$port['endpoint'] -cne $ownedEndpoint)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: port observer returned a foreign endpoint.')
    }
    if (-not $port.ContainsKey('ownerPid') -or $null -eq $port['ownerPid']) {
        throw [System.InvalidOperationException]::new('STORE-PORT-OWNER-UNPROVEN: readiness requires an observed listener PID.')
    }
    $ownerPid = 0
    try { $ownerPid = [int]$port['ownerPid'] } catch {
        throw [System.InvalidOperationException]::new('STORE-OBSERVER-FAILED: port observer owner pid is not an integer.')
    }
    if ($ownerPid -ne $ownedPid) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: endpoint listener is owned by a foreign pid.')
    }
    $client = (& $StoreClient @{ runId = $runId; endpoint = $ownedEndpoint; pid = $ownedPid })
    if ($null -eq $client -or $client -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-CLIENT-FAILED: Store client must return a hashtable.')
    }
    foreach ($field in @('authenticated', 'namespace', 'database', 'schemaDigest')) {
        if (-not $client.ContainsKey($field)) {
            throw [System.InvalidOperationException]::new("STORE-CLIENT-FAILED: client receipt is missing '$field'.")
        }
    }
    $authenticated = [bool]$client['authenticated']
    [void](Test-StoreDigestFormat -Digest ([string]$client['schemaDigest']))
    if ($client.ContainsKey('endpoint') -and ([string]$client['endpoint'] -cne $ownedEndpoint)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: client receipt endpoint is foreign.')
    }
    $expectedNs = $null
    $expectedDb = $null
    if ($StartReceipt.ContainsKey('requested') -and $StartReceipt['requested'] -is [hashtable]) {
        $expectedNs = $StartReceipt['requested']['namespace']
        $expectedDb = $StartReceipt['requested']['database']
    }
    if ($null -eq $expectedNs -and $StartReceipt.ContainsKey('namespace')) { $expectedNs = $StartReceipt['namespace'] }
    if ($null -eq $expectedDb -and $StartReceipt.ContainsKey('database')) { $expectedDb = $StartReceipt['database'] }
    if ($null -ne $expectedNs -and ([string]$client['namespace'] -cne [string]$expectedNs)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: client namespace selection is foreign.')
    }
    if ($null -ne $expectedDb -and ([string]$client['database'] -cne [string]$expectedDb)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: client database selection is foreign.')
    }
    $fixtureReady = $false
    if ($client.ContainsKey('fixtureReady')) { $fixtureReady = [bool]$client['fixtureReady'] }
    $expectedSchema = $null
    if ($StartReceipt.ContainsKey('requested') -and $StartReceipt['requested'] -is [hashtable]) {
        $expectedSchema = $StartReceipt['requested']['schemaDigest']
    }
    if ($null -eq $expectedSchema -and $StartReceipt.ContainsKey('schemaDigest')) { $expectedSchema = $StartReceipt['schemaDigest'] }
    if ([string]::IsNullOrWhiteSpace([string]$expectedSchema)) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt carries no expected schema identity.')
    }
    [void](Test-StoreDigestFormat -Digest ([string]$expectedSchema))
    $schemaReady = ([string]$client['schemaDigest'] -ceq [string]$expectedSchema)
    $ready = ($alive -and $open -and $authenticated -and $schemaReady)
    $state = 'ObservedProcessReadinessUnknown'
    if ($ready) { $state = 'AcceptedSemanticReadiness' }
    $failureClass = 'none'
    if (-not $alive) {
        $failureClass = 'process-crash'
    } elseif (-not $open) {
        $failureClass = 'port-closed'
    } elseif (-not $authenticated) {
        $failureClass = 'auth-failed'
    } elseif (-not $schemaReady) {
        $failureClass = 'schema-mismatch'
    }
    return @{
        runId          = $runId
        readinessState = $state
        processAlive   = $alive
        tcpOpen        = $open
        authenticated  = $authenticated
        schemaReady    = $schemaReady
        fixtureReady   = $fixtureReady
        failureClass   = $failureClass
        schemaDigest   = [string]$client['schemaDigest']
        endpoint       = $ownedEndpoint
        pid            = $ownedPid
        listenerOwnerVerified = $true
        ready          = $ready
    }
}

function Invoke-StoreResetForTest {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Fixture,
        [Parameter(Mandatory)]
        [hashtable]$ReadinessReceipt,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$StoreClient
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    foreach ($field in @('fixtureName', 'baselineDigest')) {
        if (-not $Fixture.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Fixture[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-FIXTURE: fixture is missing '$field'.")
        }
    }
    [void](Test-StoreDigestFormat -Digest ([string]$Fixture['baselineDigest']))
    $fixtureName = [string]$Fixture['fixtureName']
    if ($fixtureName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-FIXTURE: fixture name has an invalid shape.')
    }
    if ([string]$ReadinessReceipt['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: readiness receipt run identity is foreign.')
    }
    if ($null -eq $StoreClient) {
        throw [System.ArgumentException]::new('STORE-MISSING-CLIENT: a Store-client seam is required.')
    }
    $result = (& $StoreClient @{ runId = $runId; fixtureName = $fixtureName; baselineDigest = [string]$Fixture['baselineDigest'] })
    if ($null -eq $result -or $result -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-CLIENT-FAILED: reset client must return a hashtable.')
    }
    if (-not $result.ContainsKey('resetOk') -or -not $result.ContainsKey('baselineOk')) {
        throw [System.InvalidOperationException]::new('STORE-CLIENT-FAILED: reset receipt is missing resetOk/baselineOk.')
    }
    if ($result.ContainsKey('fixtureName') -and ([string]$result['fixtureName'] -cne $fixtureName)) {
        throw [System.InvalidOperationException]::new('STORE-FIXTURE-MISMATCH: reset receipt fixture does not match the declared fixture.')
    }
    $resetOk = [bool]$result['resetOk']
    $baselineOk = [bool]$result['baselineOk']
    if ($resetOk -and $baselineOk) {
        return @{
            runId              = $runId
            fixtureName        = $fixtureName
            baselineVerified   = $true
            contaminationScope = 'none'
            resetState         = 'GroupInitialization'
        }
    }
    return @{
        runId              = $runId
        fixtureName        = $fixtureName
        baselineVerified   = $false
        contaminationScope = 'group'
        resetState         = 'GroupContaminated'
        resetOk            = $resetOk
        baselineOk         = $baselineOk
    }
}

function Invoke-StoreCollectEvidence {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$TerminalState,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$LogText,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyCollection()]
        [string[]]$Secrets,
        [ValidateRange(1, 16777216)]
        [int]$MaxBytes = 65536
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    [void](Test-StoreTerminalDisposition -Disposition $TerminalState)
    $redacted = Get-StoreRedactedText -Text $LogText -Secrets $Secrets -MaxBytes $MaxBytes
    if ([bool]$redacted.failed) {
        return @{
            runId          = [string]$Binding['runId']
            terminalState  = $TerminalState
            evidenceState  = 'EvidenceCollectionFailed'
            bytes          = 0
            truncated      = $false
            redactionFailed = $true
            owner          = [string]$Binding['owner']
        }
    }
    return @{
        runId          = [string]$Binding['runId']
        terminalState  = $TerminalState
        evidenceState  = 'TerminalTestEvidence'
        bytes          = [int]$redacted.bytes
        truncated      = [bool]$redacted.truncated
        text           = [string]$redacted.text
        owner          = [string]$Binding['owner']
    }
}

function Invoke-StoreStop {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$StartReceipt,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$ProcessController,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$ProcessObserver,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileSystem
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    [void](Resolve-StoreDeadline -Binding $Binding -Clock $Clock -Operation 'Stop')
    $runId = [string]$Binding['runId']
    if ([string]$StartReceipt['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: start receipt run identity is foreign.')
    }
    if ($null -eq $StartReceipt['requested'] -or ($StartReceipt['requested'] -isnot [hashtable])) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt carries no requested identity.')
    }
    $requested = $StartReceipt['requested']
    foreach ($field in @('requestKey', 'endpoint', 'schemaDigest')) {
        if (-not $requested.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$requested[$field])) {
            throw [System.InvalidOperationException]::new("STORE-RECEIPT-STALE: start receipt requested identity is missing '$field'.")
        }
    }
    if ($null -eq $StartReceipt['observed'] -or ($StartReceipt['observed'] -isnot [hashtable])) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-STALE: start receipt carries no observed pid.')
    }
    $observed = $StartReceipt['observed']
    foreach ($field in @('pid', 'nonce', 'endpoint')) {
        if (-not $observed.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$observed[$field])) {
            throw [System.InvalidOperationException]::new("STORE-RECEIPT-STALE: start receipt observation is missing '$field'.")
        }
    }
    if ([string]$observed['endpoint'] -cne [string]$requested['endpoint']) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: requested and observed endpoints do not match.')
    }
    $ownedPid = [int]$observed['pid']
    if ($ownedPid -le 0) {
        throw [System.ArgumentException]::new('STORE-INVALID-PID: owned pid is not positive.')
    }
    if ($null -eq $ProcessController) {
        throw [System.ArgumentException]::new('STORE-MISSING-CONTROLLER: a process-controller seam is required.')
    }
    $stopFs = $FileSystem
    if ($null -eq $stopFs) {
        $stopFs = New-StoreDefaultFileSystem
    }
    $stopRunRoot = ''
    if ($StartReceipt.ContainsKey('runRoot') -and -not [string]::IsNullOrWhiteSpace([string]$StartReceipt['runRoot'])) {
        $stopRunRoot = [string]$StartReceipt['runRoot']
    }
    $hasImage = ($observed.ContainsKey('imagePath') -and -not [string]::IsNullOrWhiteSpace([string]$observed['imagePath']))
    $hasStart = ($observed.ContainsKey('startTimeUtc') -and -not [string]::IsNullOrWhiteSpace([string]$observed['startTimeUtc']))
    if (-not $hasImage -or -not $hasStart) {
        # The receipt states whether the launcher observed the launched process.
        # An unobserved identity is named as such; the started image and start
        # time are never reconstructed from the requested launch input, because
        # the start time of a process is not knowable before it exists.
        $identityDetail = 'STORE-PROCESS-IDENTITY-UNPROVEN: start receipt carries no live-verifiable process identity.'
        if ($observed.ContainsKey('identityState') -and [string]$observed['identityState'] -ceq 'Unobserved') {
            $identityDetail = 'STORE-PROCESS-IDENTITY-UNPROVEN: launcher observed no launched-process image/start-time identity.'
        }
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail $identityDetail
    }
    $rootIdentity = @{
        pid          = $ownedPid
        imagePath    = [string]$observed['imagePath']
        startTimeUtc = [string]$observed['startTimeUtc']
    }
    $ownedTree = @($rootIdentity)
    $treeComplete = $false
    $stopObserver = $ProcessObserver
    if ($null -eq $stopObserver) {
        $stopObserver = New-StoreDefaultProcessObserver
    }
    $live = $null
    try {
        $live = (& $stopObserver @{ pid = $ownedPid; runId = $runId })
    } catch {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail $_.Exception.Message
    }
    if ($null -eq $live -or $live -isnot [hashtable]) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail 'STORE-OBSERVER-FAILED: stop observer must return a hashtable.'
    }
    $livePid = 0
    if ($live.ContainsKey('pid')) {
        try { $livePid = [int]$live['pid'] } catch { $livePid = 0 }
    }
    if (-not $live.ContainsKey('alive') -or $live['alive'] -isnot [bool] -or
        ($live.ContainsKey('pid') -and $livePid -ne $ownedPid)) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail 'STORE-OBSERVER-FAILED: stop observer did not establish the owned root state.'
    }
    $rootLiveBeforeGrace = [bool]$live['alive']
    if ($rootLiveBeforeGrace) {
        try {
            [void](Test-StoreProcessOwnership -Pid $ownedPid -ExpectedImagePath ([string]$rootIdentity['imagePath']) `
                -ExpectedStartTimeUtc ([string]$rootIdentity['startTimeUtc']) -Observation $live)
        } catch {
            return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
                -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail $_.Exception.Message
        }
    }
    if ($rootLiveBeforeGrace -and $live.ContainsKey('treeComplete') -and $live['treeComplete'] -is [bool]) {
        $treeComplete = [bool]$live['treeComplete']
    }
    if ($rootLiveBeforeGrace -and $live.ContainsKey('descendants') -and $null -ne $live['descendants']) {
        foreach ($child in @($live['descendants'])) {
            if ($null -eq $child -or $child -isnot [hashtable] -or
                -not $child.ContainsKey('pid') -or -not $child.ContainsKey('imagePath') -or -not $child.ContainsKey('startTimeUtc')) {
                $treeComplete = $false
                continue
            }
            $childPid = 0
            try { $childPid = [int]$child['pid'] } catch { $childPid = 0 }
            if ($childPid -le 0 -or $childPid -eq $ownedPid -or
                [string]::IsNullOrWhiteSpace([string]$child['imagePath']) -or
                [string]::IsNullOrWhiteSpace([string]$child['startTimeUtc'])) {
                $treeComplete = $false
                continue
            }
            $existing = @($ownedTree | Where-Object { [int]$_['pid'] -eq $childPid })
            if ($existing.Count -gt 0) {
                if ([string]$existing[0]['imagePath'] -ine [string]$child['imagePath'] -or
                    [string]$existing[0]['startTimeUtc'] -cne [string]$child['startTimeUtc']) {
                    $treeComplete = $false
                }
                continue
            }
            $ownedTree += @{
                pid          = $childPid
                imagePath    = [string]$child['imagePath']
                startTimeUtc = [string]$child['startTimeUtc']
            }
        }
    }
    $preGraceTreeComplete = [bool]$treeComplete
    $preGraceOwnedTree = @($ownedTree)
    try {
        $graceful = (& $ProcessController @{ phase = 'graceful'; pid = $ownedPid; runId = $runId; ownedTree = @($ownedTree) })
    } catch {
        $gracefulMessage = $_.Exception.Message
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail $gracefulMessage
    }
    if ($null -eq $graceful -or $graceful -isnot [hashtable] -or -not $graceful.ContainsKey('exited')) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail 'STORE-CONTROLLER-FAILED: graceful phase must return an exited mapping.'
    }
    if ($graceful['exited'] -isnot [bool]) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail 'STORE-CONTROLLER-FAILED: graceful phase returned an invalid exited value.'
    }
    $gracefulExited = [bool]$graceful['exited']
    $gracefulPid = 0
    if ($graceful.ContainsKey('pid')) {
        try { $gracefulPid = [int]$graceful['pid'] } catch { $gracefulPid = 0 }
    }
    if ($graceful.ContainsKey('pid') -and $gracefulPid -ne $ownedPid) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail 'STORE-FOREIGN-PROCESS: controller touched a foreign pid.'
    }
    $afterGrace = $null
    try {
        $afterGrace = (& $stopObserver @{ pid = $ownedPid; runId = $runId })
    } catch {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid `
            -Forced (-not $gracefulExited) -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId `
            -Detail ('STORE-DESCENDANT-CLOSURE-INCOMPLETE: post-grace observation failed: ' + $_.Exception.Message)
    }
    $afterGracePid = 0
    if ($null -ne $afterGrace -and $afterGrace -is [hashtable] -and $afterGrace.ContainsKey('pid')) {
        try { $afterGracePid = [int]$afterGrace['pid'] } catch { $afterGracePid = 0 }
    }
    if ($null -eq $afterGrace -or $afterGrace -isnot [hashtable] -or
        -not $afterGrace.ContainsKey('pid') -or $afterGracePid -ne $ownedPid -or
        -not $afterGrace.ContainsKey('alive') -or $afterGrace['alive'] -isnot [bool]) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid `
            -Forced (-not $gracefulExited) -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId `
            -Detail 'STORE-DESCENDANT-CLOSURE-INCOMPLETE: post-grace observation does not establish the owned root state.'
    }
    $rootStillLive = [bool]$afterGrace['alive']
    if ($rootStillLive) {
        try {
            [void](Test-StoreProcessOwnership -Pid $ownedPid -ExpectedImagePath ([string]$rootIdentity['imagePath']) `
                -ExpectedStartTimeUtc ([string]$rootIdentity['startTimeUtc']) -Observation $afterGrace)
        } catch {
            return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid `
                -Forced (-not $gracefulExited) -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail $_.Exception.Message
        }
        if ($gracefulExited) {
            return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $false `
                -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId `
                -Detail 'STORE-PROCESS-IDENTITY-UNPROVEN: graceful controller reported exit but the owned root remains live.'
        }
    }
    $afterTreeComplete = ($afterGrace.ContainsKey('treeComplete') -and $afterGrace['treeComplete'] -is [bool] -and [bool]$afterGrace['treeComplete'] -and
        $afterGrace.ContainsKey('descendants') -and $null -ne $afterGrace['descendants'])
    if ($afterTreeComplete) {
        foreach ($child in @($afterGrace['descendants'])) {
            if ($null -eq $child -or $child -isnot [hashtable] -or
                -not $child.ContainsKey('pid') -or -not $child.ContainsKey('imagePath') -or -not $child.ContainsKey('startTimeUtc')) {
                $afterTreeComplete = $false
                continue
            }
            $childPid = 0
            try { $childPid = [int]$child['pid'] } catch { $childPid = 0 }
            if ($childPid -le 0 -or $childPid -eq $ownedPid -or
                [string]::IsNullOrWhiteSpace([string]$child['imagePath']) -or
                [string]::IsNullOrWhiteSpace([string]$child['startTimeUtc'])) {
                $afterTreeComplete = $false
                continue
            }
            $existing = @($ownedTree | Where-Object { [int]$_['pid'] -eq $childPid })
            if ($existing.Count -gt 0) {
                if ([string]$existing[0]['imagePath'] -ine [string]$child['imagePath'] -or
                    [string]$existing[0]['startTimeUtc'] -cne [string]$child['startTimeUtc']) {
                    $afterTreeComplete = $false
                }
                continue
            }
            $ownedTree += @{
                pid          = $childPid
                imagePath    = [string]$child['imagePath']
                startTimeUtc = [string]$child['startTimeUtc']
            }
        }
    }
    $treeComplete = $afterTreeComplete
    if (-not $treeComplete) {
        $closureDetail = 'STORE-DESCENDANT-CLOSURE-INCOMPLETE: post-grace owned descendant closure could not be proven.'
        $reconciliationForced = (-not $gracefulExited)
        if (-not $rootStillLive) {
            $jobName = ''
            if ($StartReceipt['observed'].ContainsKey('jobName')) {
                $jobName = [string]$StartReceipt['observed']['jobName']
            }
            if (-not [string]::IsNullOrWhiteSpace($jobName) -and $jobName -cne 'inherited' -and
                $Script:StoreJobHandles.ContainsKey($jobName)) {
                $jobClosed = $null
                try { $jobClosed = Close-StoreJobBinding -JobName $jobName } catch { $jobClosed = @{ closed = $false } }
                if ($null -ne $jobClosed -and [bool]$jobClosed['closed']) {
                    return @{
                        runId     = $runId
                        stopPhase = 'forced'
                        ownedPid  = $ownedPid
                        stopState = 'OwnedResourcesStopped'
                        forced    = $true
                    }
                }
            }
            if ($preGraceTreeComplete) {
                $reconciliationForced = $true
                $closureDetail += ' A bounded best-effort forced attempt used the complete pre-grace identity tree; its response is not proof of cleanup.'
                try {
                    [void](& $ProcessController @{
                        phase           = 'forced'
                        pid             = $ownedPid
                        runId           = $runId
                        ownedTree       = @($preGraceOwnedTree)
                        treeComplete    = $true
                        rootObservedLive = $false
                    })
                } catch {
                    $closureDetail += ' The best-effort forced response was uncertain: ' + $_.Exception.Message
                }
            }
        }
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid `
            -Forced $reconciliationForced -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId `
            -Detail $closureDetail
    }
    if (-not $rootStillLive -and $ownedTree.Count -eq 1) {
        return @{
            runId     = $runId
            stopPhase = 'graceful'
            ownedPid  = $ownedPid
            stopState = 'OwnedResourcesStopped'
            forced    = $false
        }
    }
    try {
        $forced = (& $ProcessController @{ phase = 'forced'; pid = $ownedPid; runId = $runId; ownedTree = @($ownedTree); treeComplete = $treeComplete; rootObservedLive = $rootStillLive })
    } catch {
        $forcedMessage = $_.Exception.Message
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $true `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail $forcedMessage
    }
    if ($null -eq $forced -or $forced -isnot [hashtable] -or -not $forced.ContainsKey('exited')) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $true `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail 'STORE-CONTROLLER-FAILED: forced phase must return an exited mapping.'
    }
    if ($forced['exited'] -isnot [bool]) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $true `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail 'STORE-CONTROLLER-FAILED: forced phase returned an invalid exited value.'
    }
    if ($forced.ContainsKey('pid') -and ([int]$forced['pid'] -ne $ownedPid)) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $true `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail 'STORE-FOREIGN-PROCESS: controller touched a foreign pid.'
    }
    if (-not [bool]$forced['exited']) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $true `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId -Detail 'STORE-FORCED-STOP-INCOMPLETE: owned processes remain after the forced phase.'
    }
    $terminated = @($ownedPid)
    if ($forced.ContainsKey('terminatedPids') -and $null -ne $forced['terminatedPids']) {
        $terminated = @($forced['terminatedPids'])
    }
    $forcedCleanupProven = $false
    $jobName = ''
    if ($StartReceipt['observed'].ContainsKey('jobName')) {
        $jobName = [string]$StartReceipt['observed']['jobName']
    }
    if (-not [string]::IsNullOrWhiteSpace($jobName) -and $jobName -cne 'inherited' -and
        $Script:StoreJobHandles.ContainsKey($jobName)) {
        $jobClosed = $null
        try { $jobClosed = Close-StoreJobBinding -JobName $jobName } catch { $jobClosed = @{ closed = $false } }
        if ($null -eq $jobClosed -or -not [bool]$jobClosed['closed']) {
            return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $true `
                -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId `
                -Detail 'STORE-JOB-CLOSE-UNCONFIRMED: forced target handles exited but owned job close was not confirmed.'
        }
        $forcedCleanupProven = $true
    } else {
        $postForced = $null
        try {
            $postForced = (& $stopObserver @{ pid = $ownedPid; runId = $runId })
        } catch {
            return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $true `
                -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId `
                -Detail ('STORE-DESCENDANT-CLOSURE-INCOMPLETE: post-force closure observation failed: ' + $_.Exception.Message)
        }
        $postForcedPid = 0
        if ($null -ne $postForced -and $postForced -is [hashtable] -and $postForced.ContainsKey('pid')) {
            try { $postForcedPid = [int]$postForced['pid'] } catch { $postForcedPid = 0 }
        }
        if ($null -ne $postForced -and $postForced -is [hashtable] -and
            $postForced.ContainsKey('pid') -and $postForcedPid -eq $ownedPid -and
            $postForced.ContainsKey('alive') -and $postForced['alive'] -is [bool] -and -not [bool]$postForced['alive'] -and
            $postForced.ContainsKey('treeComplete') -and $postForced['treeComplete'] -is [bool] -and [bool]$postForced['treeComplete'] -and
            $postForced.ContainsKey('descendants') -and $null -ne $postForced['descendants'] -and
            @($postForced['descendants']).Count -eq 0) {
            $forcedCleanupProven = $true
        }
    }
    if (-not $forcedCleanupProven) {
        return New-StoreStopReconciliationResult -Binding $Binding -Requested $requested -OwnedPid $ownedPid -Forced $true `
            -RunRoot $stopRunRoot -FileSystem $stopFs -RunId $runId `
            -Detail 'STORE-DESCENDANT-CLOSURE-INCOMPLETE: forced target snapshot stopped but post-exit cleanup closure is unproven.'
    }
    return @{
        runId         = $runId
        stopPhase     = 'forced'
        ownedPid      = $ownedPid
        stopState     = 'OwnedResourcesStopped'
        forced        = $true
        exited        = [bool]$forced['exited']
        ownedTree     = @($ownedTree)
        terminatedPids = @($terminated)
    }
}

function New-StoreStopReconciliationResult {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Requested,
        [Parameter(Mandatory)]
        [int]$OwnedPid,
        [Parameter(Mandatory)]
        [bool]$Forced,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$FileSystem,
        [Parameter(Mandatory)]
        [string]$RunId,
        [Parameter(Mandatory)]
        [string]$Detail
    )
    $reconciliation = Write-StoreLostResponseRecord -FileSystem $FileSystem -RunRoot $RunRoot -RunId $RunId `
        -Operation 'stop' -RequestKey ([string]$Requested['requestKey']) -Endpoint ([string]$Requested['endpoint']) `
        -Owner ([string]$Binding['owner']) -Generation ([int]$Binding['generation']) -Detail $Detail
    return @{
        runId                   = $RunId
        stopPhase               = 'unknown'
        stopState               = 'ReconciliationRequired'
        ownedPid                = $OwnedPid
        forced                  = $Forced
        retryPermitted          = $false
        reconciliationOwner     = $RunId
        reconciliationPath      = [string]$reconciliation['path']
        reconciliationPersisted = [bool]$reconciliation['persisted']
        failure                 = ('stop-ownership-unproven:' + $Detail)
    }
}

# Real file probe for the owned-root removal step. It reports only what it
# observed by enumerating the owned run root: locksHeld is true when the root
# or a child cannot be enumerated, secretsPresent when secret material remains
# under the secret root, and rootsPresent only when an entry is outside the
# owned allowlist (a foreign entry is preserved, never deleted). In:
# {runRoot,runId}. Out: {runRoot,runId,locksHeld,secretsPresent,rootsPresent}.
function New-StoreDefaultFileProbe {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()
    $allowedChildren = $Script:StoreAllowedRootChildren
    $ownerMarkerName = $Script:StoreOwnerMarkerFile
    $probe = {
        param($Request)
        if ($null -eq $Request -or $Request -isnot [hashtable] -or -not $Request.ContainsKey('runRoot')) {
            throw [System.ArgumentException]::new('STORE-INVALID-FILE-PROBE: file probe request needs a runRoot.')
        }
        $probeRoot = [System.IO.Path]::GetFullPath([string]$Request['runRoot'])
        $locksHeld = $false
        $secretsPresent = $false
        $rootsPresent = $false
        if (Test-Path -LiteralPath $probeRoot -PathType Container) {
            $entries = @()
            try {
                $entries = @(Get-ChildItem -LiteralPath $probeRoot -Force -ErrorAction Stop)
            } catch {
                $locksHeld = $true
            }
            foreach ($entry in $entries) {
                if ([string]$entry.Name -cnotin $allowedChildren -and [string]$entry.Name -cne $ownerMarkerName) {
                    $rootsPresent = $true
                }
            }
            foreach ($child in @('data', 'logs', 'secrets')) {
                $childPath = Join-Path $probeRoot $child
                if (-not (Test-Path -LiteralPath $childPath -PathType Container)) { continue }
                $children = @()
                try {
                    $children = @(Get-ChildItem -LiteralPath $childPath -Force -ErrorAction Stop)
                } catch {
                    $locksHeld = $true
                    continue
                }
                if ($child -ceq 'secrets' -and $children.Count -gt 0) { $secretsPresent = $true }
            }
        }
        return @{
            runRoot         = $probeRoot
            runId           = [string]$Request['runId']
            locksHeld       = $locksHeld
            secretsPresent  = $secretsPresent
            rootsPresent    = $rootsPresent
        }
    }
    return $probe.GetNewClosure()
}

function Remove-StoreOwnedRoot {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Allocation,
        [Parameter(Mandatory)]
        [scriptblock]$FileProbe
    )
    $runId = [string]$Binding['runId']
    $owner = [string]$Binding['owner']
    $generation = [int]$Binding['generation']
    $runRoot = [System.IO.Path]::GetFullPath([string]$Allocation['runRoot'])
    $markerPath = [System.IO.Path]::GetFullPath((Join-Path $runRoot $Script:StoreOwnerMarkerFile))
    if (-not (Test-Path -LiteralPath $runRoot -PathType Container)) {
        return @{ removed = $true; alreadyAbsent = $true; failures = @(); ownedRoot = $runRoot }
    }
    if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('owner-marker-missing') }
    }
    # Ownership is proven by marker CONTENT, never by the path name: the
    # recorded claim must state this run, owner, generation and marker value,
    # read back through the same predicate the reuse path applies. A marker
    # that does not match belongs to another run and is never removed.
    $recorded = $null
    try {
        $recorded = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('owner-marker-unreadable') }
    }
    if (-not (Test-StoreOwnedRootClaim -Recorded $recorded -RunId $runId -Owner $owner -Generation $generation)) {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('ownership-verification-failed') }
    }
    $topLevel = @()
    try {
        $topLevel = @(Get-ChildItem -LiteralPath $runRoot -Force -ErrorAction Stop)
    } catch {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('owned-root-unreadable') }
    }
    $foreign = @()
    $reparse = @()
    foreach ($entry in $topLevel) {
        if ([string]$entry.Name -cnotin $Script:StoreAllowedRootChildren) {
            $foreign += [string]$entry.Name
        }
        if (($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            $reparse += [string]$entry.Name
        }
    }
    if ($reparse.Count -gt 0) {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('reparse-entry-preserved:' + ($reparse -join ',')) }
    }
    if ($foreign.Count -gt 0) {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('foreign-entry-preserved:' + ($foreign -join ',')) }
    }
    $reparseCount = 0
    try {
        foreach ($item in @(Get-ChildItem -LiteralPath $runRoot -Force -Recurse -ErrorAction Stop)) {
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { $reparseCount++ }
        }
    } catch {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('owned-root-unreadable') }
    }
    if ($reparseCount -gt 0) {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('reparse-entry-preserved') }
    }
    # Removal deletes nothing while a lock, a secret, or a still-present root is
    # reported by the caller's probe, and never touches a root the probe reports
    # as foreign.
    $probe = $null
    try {
        $probe = (& $FileProbe @{ runRoot = $runRoot; runId = $runId })
    } catch {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('file-probe-failed') }
    }
    if ($null -eq $probe -or $probe -isnot [hashtable]) {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('file-probe-failed') }
    }
    if ($probe.ContainsKey('runRoot') -and [System.IO.Path]::GetFullPath([string]$probe['runRoot']) -ine $runRoot) {
        throw [System.InvalidOperationException]::new('STORE-FOREIGN-ROOT: removal file probe returned a foreign root.')
    }
    foreach ($heldField in @('locksHeld', 'secretsPresent', 'rootsPresent')) {
        if ($probe.ContainsKey($heldField) -and [bool]$probe[$heldField]) {
            return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @($heldField) }
        }
    }
    try {
        Remove-Item -LiteralPath $runRoot -Recurse -Force -ErrorAction Stop
    } catch {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('removal-unknown') }
    }
    if (Test-Path -LiteralPath $runRoot) {
        return @{ removed = $false; alreadyAbsent = $false; ownedRoot = $runRoot; failures = @('roots-present') }
    }
    return @{ removed = $true; alreadyAbsent = $false; failures = @(); ownedRoot = $runRoot }
}

function Invoke-StoreVerifyCleanup {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Binding,
        [Parameter(Mandatory)]
        [hashtable]$Allocation,
        [Parameter(Mandatory)]
        [hashtable]$StartReceipt,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$ProcessObserver,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$PortObserver,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileProbe,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileSystem
    )
    [void](Test-StoreBindingShape -Binding $Binding)
    $runId = [string]$Binding['runId']
    if ([string]$Allocation['runId'] -cne $runId) {
        throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: allocation run identity is foreign.')
    }
    foreach ($field in @('runRoot', 'dataRoot', 'logRoot', 'secretRoot', 'endpoint', 'port')) {
        if (-not $Allocation.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Allocation[$field])) {
            throw [System.ArgumentException]::new("STORE-INVALID-ALLOCATION: allocation is missing '$field'.")
        }
    }
    if ($Allocation.ContainsKey('reservationIdentity') -and $Allocation['reservationIdentity'] -is [hashtable]) {
        [void](Complete-StorePortReservation -Identity $Allocation['reservationIdentity'] -RunId $runId `
            -Owner ([string]$Binding['owner']) -Generation ([int]$Binding['generation']) `
            -Endpoint ([string]$Allocation['endpoint']) -Disposition 'cleanup')
    }
    $runRoot = [System.IO.Path]::GetFullPath([string]$Allocation['runRoot'])
    $runLeaf = [System.IO.Path]::GetFileName($runRoot)
    if ([string]::IsNullOrWhiteSpace($runLeaf) -or -not $runLeaf.Contains($runId)) {
        throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: cleanup run root leaf does not carry the run identity: $runRoot")
    }
    $runPrefix = $runRoot.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    foreach ($rootField in @('dataRoot', 'logRoot', 'secretRoot')) {
        $rootFull = [System.IO.Path]::GetFullPath([string]$Allocation[$rootField])
        if ($rootFull -ine $runRoot -and -not $rootFull.StartsWith($runPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: allocation root '$rootField' escapes the owned run root.")
        }
        [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $rootFull -ExpectedRunId $runId)
    }
    [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $runRoot -ExpectedRunId $runId)
    $failures = New-Object Collections.Generic.List[string]
    if (Test-Path -LiteralPath $runRoot -PathType Container) {
        $markerPath = Join-Path $runRoot $Script:StoreOwnerMarkerFile
        if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
            [void]$failures.Add('owner-marker-missing')
        } else {
            try {
                $markerRecord = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if ([string]$markerRecord.run_id -cne $runId) {
                    [void]$failures.Add('owner-marker-foreign')
                }
            } catch {
                [void]$failures.Add('owner-marker-unreadable')
            }
        }
    }
    $ownedPid = 0
    if ($null -ne $StartReceipt['observed'] -and $StartReceipt['observed'] -is [hashtable] -and $StartReceipt['observed'].ContainsKey('pid')) {
        try { $ownedPid = [int]$StartReceipt['observed']['pid'] } catch { $ownedPid = 0 }
    }
    $verifyProcessObserver = $ProcessObserver
    if ($null -eq $verifyProcessObserver) {
        $verifyProcessObserver = New-StoreDefaultProcessObserver
    }
    if ($ownedPid -gt 0) {
        $process = $null
        try {
            $process = (& $verifyProcessObserver @{ pid = $ownedPid; runId = $runId })
        } catch {
            if ($_.Exception.Message -match '(?i)lost-response|timeout|unknown') {
                [void]$failures.Add('process-observer-unknown')
            } else {
                [void]$failures.Add('process-observer-failed')
            }
        }
        if ($null -ne $process -and $process -is [hashtable]) {
            if ($process.ContainsKey('pid') -and ([int]$process['pid'] -ne $ownedPid)) {
                throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: cleanup observer returned a foreign pid.')
            }
            if ($process.ContainsKey('alive') -and [bool]$process['alive']) {
                [void]$failures.Add('process-still-alive')
            }
            if ($process.ContainsKey('descendants') -and $null -ne $process['descendants']) {
                $descendants = @($process['descendants'])
                if ($descendants.Count -gt 0) {
                    [void]$failures.Add(('descendants-remaining:' + $descendants.Count))
                }
            }
            if ($process.ContainsKey('treeComplete') -and $null -ne $process['treeComplete'] -and -not [bool]$process['treeComplete']) {
                [void]$failures.Add('descendant-closure-incomplete')
            }
        }
    }
    $verifyPortObserver = $PortObserver
    if ($null -eq $verifyPortObserver) {
        $verifyPortObserver = New-StoreDefaultPortObserver
    }
    $port = $null
    try {
        $port = (& $verifyPortObserver @{ endpoint = [string]$Allocation['endpoint']; runId = $runId })
    } catch {
        if ($_.Exception.Message -match '(?i)lost-response|timeout|unknown') {
            [void]$failures.Add('port-observer-unknown')
        } else {
            [void]$failures.Add('port-observer-failed')
        }
    }
    if ($null -ne $port -and $port -is [hashtable]) {
        if ($port.ContainsKey('endpoint') -and ([string]$port['endpoint'] -cne [string]$Allocation['endpoint'])) {
            throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: cleanup port observer returned a foreign endpoint.')
        }
        if ($port.ContainsKey('open') -and [bool]$port['open']) {
            [void]$failures.Add('port-still-open')
        }
    }
    if ($null -ne $FileProbe) {
        $probe = $null
        try {
            $probe = (& $FileProbe @{ runRoot = $runRoot; runId = $runId })
        } catch {
            if ($_.Exception.Message -match '(?i)lost-response|timeout|unknown') {
                [void]$failures.Add('file-probe-unknown')
            } else {
                [void]$failures.Add('file-probe-failed')
            }
        }
        if ($null -ne $probe -and $probe -is [hashtable]) {
            if ($probe.ContainsKey('runRoot') -and ([System.IO.Path]::GetFullPath([string]$probe['runRoot']) -ine $runRoot)) {
                throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: cleanup file probe returned a foreign root.')
            }
            if ($probe.ContainsKey('locksHeld') -and [bool]$probe['locksHeld']) {
                [void]$failures.Add('locks-held')
            }
            if ($probe.ContainsKey('secretsPresent') -and [bool]$probe['secretsPresent']) {
                [void]$failures.Add('secrets-present')
            }
            if ($probe.ContainsKey('rootsPresent') -and [bool]$probe['rootsPresent']) {
                [void]$failures.Add('roots-present')
            }
            if ($probe.ContainsKey('entries')) {
                foreach ($entry in @($probe['entries'])) {
                    if ([string]$entry -cnotin $Script:StoreAllowedRootChildren) {
                        [void]$failures.Add(('foreign-entry-preserved:' + [string]$entry))
                    }
                }
            }
        }
    } else {
        if (Test-Path -LiteralPath $runRoot) {
            $entries = @(Get-ChildItem -LiteralPath $runRoot -Force -ErrorAction SilentlyContinue)
            foreach ($entry in $entries) {
                if ($entry.Name -cnotin $Script:StoreAllowedRootChildren) {
                    [void]$failures.Add(('foreign-entry-preserved:' + $entry.Name))
                }
            }
            if ($entries.Count -gt 0) {
                [void]$failures.Add('roots-present')
            }
        }
    }
    $verifyFs = $FileSystem
    if ($null -eq $verifyFs) {
        $verifyFs = New-StoreDefaultFileSystem
    }
    $pending = Test-StorePendingReconciliation -FileSystem $verifyFs -RunRoot $runRoot -RunId $runId
    if ($pending) {
        [void]$failures.Add('reconciliation-pending')
    }
    if ($failures.Count -gt 0) {
        return @{
            runId     = $runId
            cleanupState = 'ReconciliationRequired'
            cleaned   = $false
            failures  = @($failures)
            ownedRoot = $runRoot
        }
    }
    # Every check is clean, so the owned root is removed exactly once here.
    # 'roots-present' above is a pre-removal observation, not a terminal
    # verdict: without this step the root this operation created could never be
    # proven gone. A removal that refuses or is unknown keeps the root and
    # returns reconciliation instead of a clean verdict.
    $removalProbe = $FileProbe
    if ($null -eq $removalProbe) {
        $removalProbe = New-StoreDefaultFileProbe
    }
    $removal = Remove-StoreOwnedRoot -Binding $Binding -Allocation $Allocation -FileProbe $removalProbe
    if (-not [bool]$removal['removed']) {
        return @{
            runId     = $runId
            cleanupState = 'ReconciliationRequired'
            cleaned   = $false
            failures  = @($removal['failures'])
            ownedRoot = $runRoot
        }
    }
    [void](Resolve-StoreReconciliationRecord -FileSystem $verifyFs -RunRoot $runRoot -RunId $runId -Resolution 'cleanup-verified')
    return @{
        runId     = $runId
        cleanupState = 'CleanupVerified'
        cleaned   = $true
        failures  = @()
        ownedRoot = $runRoot
    }
}

function Get-StoreAmbientEnvironment {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()
    $snapshot = @{}
    foreach ($entry in (Get-ChildItem -Path 'env:' -ErrorAction Stop)) {
        $snapshot[[string]$entry.Name] = [string]$entry.Value
    }
    return $snapshot
}

function Test-StoreLoopbackEndpoint {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Endpoint
    )
    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
        throw [System.ArgumentException]::new('STORE-INVALID-ENDPOINT: endpoint is empty.')
    }
    $idx = $Endpoint.LastIndexOf(':')
    if ($idx -le 0 -or $idx -ge ($Endpoint.Length - 1)) {
        throw [System.ArgumentException]::new("STORE-INVALID-ENDPOINT: endpoint is not host:port: $Endpoint")
    }
    $host_ = $Endpoint.Substring(0, $idx)
    if ($host_ -cne $Script:StoreLoopback) {
        throw [System.InvalidOperationException]::new("STORE-ENDPOINT-FORBIDDEN: endpoint host '$host_' is not loopback.")
    }
    $port = 0
    try { $port = [int]$Endpoint.Substring($idx + 1) } catch {
        throw [System.InvalidOperationException]::new("STORE-PORT-CONFLICT: endpoint port is not an integer: $Endpoint")
    }
    if ($port -lt 1024 -or $port -gt 65535) {
        throw [System.InvalidOperationException]::new("STORE-PORT-CONFLICT: endpoint port '$port' is outside the ephemeral bound.")
    }
    return @{ host = $host_; port = $port }
}

function Read-StoreReconciliationRecord {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$FileSystem,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [string]$RunId
    )
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: RunId must be 32 lowercase hex.')
    }
    $memKey = $RunId
    if (-not [string]::IsNullOrWhiteSpace($RunRoot)) {
        $memKey = 'root:' + $RunRoot
    }
    if ($Script:StoreReconciliationTable.ContainsKey($memKey)) {
        $cached = $Script:StoreReconciliationTable[$memKey]
        if ($cached -is [hashtable]) { return $cached }
    }
    if ([string]::IsNullOrWhiteSpace($RunRoot)) { return $null }
    $fs = $FileSystem
    if ($null -eq $fs) {
        $fs = New-StoreDefaultFileSystem
    }
    $record = (& $fs @{ op = 'read-reconciliation'; runRoot = $RunRoot; runId = $RunId })
    if ($null -eq $record) { return $null }
    if ($record -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-RECONCILIATION-FAILED: reconciliation read must return a hashtable or null.')
    }
    return $record
}

function Test-StorePendingReconciliation {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$FileSystem,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [string]$RunId
    )
    $record = Read-StoreReconciliationRecord -FileSystem $FileSystem -RunRoot $RunRoot -RunId $RunId
    if ($null -eq $record) { return $false }
    return ([string]$record['state'] -cne 'resolved')
}

function Assert-StoreNoPendingReconciliation {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$FileSystem,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [string]$RunId
    )
    if (Test-StorePendingReconciliation -FileSystem $FileSystem -RunRoot $RunRoot -RunId $RunId) {
        throw [System.InvalidOperationException]::new('STORE-RECONCILIATION-REQUIRED: an unresolved launch/stop/cleanup record blocks a replacement instance.')
    }
}

function Write-StoreLostResponseRecord {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$FileSystem,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [string]$RunId,
        [Parameter(Mandatory)]
        [string]$Operation,
        [Parameter(Mandatory)]
        [string]$RequestKey,
        [Parameter(Mandatory)]
        [string]$Endpoint,
        [Parameter(Mandatory)]
        [string]$Owner,
        [Parameter(Mandatory)]
        [int]$Generation,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$Detail
    )
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: RunId must be 32 lowercase hex.')
    }
    if ($Operation -cnotin @('launch', 'stop', 'cleanup')) {
        throw [System.ArgumentException]::new("STORE-INVALID-RECONCILIATION: unknown operation '$Operation'.")
    }
    $record = @{
        marker      = $Script:StoreReconciliationMarker
        run_id      = $RunId
        operation   = $Operation
        request_key = $RequestKey
        endpoint    = $Endpoint
        owner       = $Owner
        generation  = $Generation
        observed_at = ([System.DateTimeOffset]::UtcNow.ToString('o'))
        state       = 'unknown-outcome'
        detail      = $Detail
    }
    $memKey = $RunId
    if (-not [string]::IsNullOrWhiteSpace($RunRoot)) {
        $memKey = 'root:' + $RunRoot
    }
    $Script:StoreReconciliationTable[$memKey] = $record
    $path = ''
    $persisted = $false
    if (-not [string]::IsNullOrWhiteSpace($RunRoot)) {
        $fs = $FileSystem
        if ($null -eq $fs) {
            $fs = New-StoreDefaultFileSystem
        }
        try {
            $written = (& $fs @{ op = 'write-reconciliation'; runRoot = $RunRoot; runId = $RunId; record = $record })
            if ($null -ne $written -and $written -is [hashtable]) {
                if ($written.ContainsKey('path')) { $path = [string]$written['path'] }
                if ($written.ContainsKey('persisted')) { $persisted = [bool]$written['persisted'] }
            }
        } catch {
            $persisted = $false
        }
    }
    return @{ path = $path; persisted = $persisted }
}

function Resolve-StoreReconciliationRecord {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [scriptblock]$FileSystem,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$RunRoot,
        [Parameter(Mandatory)]
        [string]$RunId,
        [Parameter(Mandatory)]
        [string]$Resolution
    )
    if ($RunId -cnotmatch '^[0-9a-f]{32}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-BINDING: RunId must be 32 lowercase hex.')
    }
    if ([string]::IsNullOrWhiteSpace($Resolution)) {
        throw [System.ArgumentException]::new('STORE-INVALID-RECONCILIATION: resolution is empty.')
    }
    $memKey = $RunId
    if (-not [string]::IsNullOrWhiteSpace($RunRoot)) {
        $memKey = 'root:' + $RunRoot
    }
    if ([string]::IsNullOrWhiteSpace($RunRoot)) {
        if ($Script:StoreReconciliationTable.ContainsKey($memKey)) {
            [void]$Script:StoreReconciliationTable.Remove($memKey)
        }
        return @{ resolved = $false; reason = 'no-record' }
    }
    $fs = $FileSystem
    if ($null -eq $fs) {
        $fs = New-StoreDefaultFileSystem
    }
    $result = (& $fs @{ op = 'resolve-reconciliation'; runRoot = $RunRoot; runId = $RunId; resolution = $Resolution })
    if ($null -eq $result -or $result -isnot [hashtable]) {
        throw [System.InvalidOperationException]::new('STORE-RECONCILIATION-FAILED: reconciliation resolve must return a hashtable.')
    }
    if ([bool]$result['resolved'] -and $Script:StoreReconciliationTable.ContainsKey($memKey)) {
        [void]$Script:StoreReconciliationTable.Remove($memKey)
    }
    return $result
}

function Get-StoreProcessIdentity {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [System.Diagnostics.Process]$Process
    )
    $pid = [int]$Process.Id
    try {
        if ($Process.HasExited) {
            throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: process exited before its identity was captured.')
        }
    } catch {
        if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
        throw [System.InvalidOperationException]::new("STORE-PROCESS-IDENTITY-UNPROVEN: process liveness could not be read: $($_.Exception.Message)")
    }
    $imagePath = ''
    try { $imagePath = [string]$Process.MainModule.FileName } catch { $imagePath = '' }
    $startTimeUtc = ''
    try { $startTimeUtc = $Process.StartTime.ToUniversalTime().ToString('o') } catch { $startTimeUtc = '' }
    if ([string]::IsNullOrWhiteSpace($imagePath) -or [string]::IsNullOrWhiteSpace($startTimeUtc)) {
        throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: process image path or start time could not be read.')
    }
    return @{
        pid          = $pid
        imagePath    = [System.IO.Path]::GetFullPath($imagePath)
        startTimeUtc = $startTimeUtc
    }
}

function Get-StoreNativeProcessApi {
    [CmdletBinding()]
    [OutputType([type])]
    param()
    $api = [System.Type]::GetType('EliotStoreNativeProcessApi')
    if ($null -eq $api) {
        $nativeSource = @'
using System;
using System.IO;
using System.Text;
using System.Runtime.InteropServices;
public static class EliotStoreNativeProcessApi {
    [StructLayout(LayoutKind.Sequential)]
    public struct FILETIME { public uint Low; public uint High; }
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetProcessTimes(IntPtr process, out FILETIME creation, out FILETIME exit, out FILETIME kernel, out FILETIME user);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool QueryFullProcessImageName(IntPtr process, int flags, StringBuilder imagePath, ref int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
    public static bool TryGetProcessIdentity(IntPtr process, out string imagePath, out long creationFileTime) {
        imagePath = String.Empty;
        creationFileTime = 0;
        FILETIME creation, exit, kernel, user;
        if (!GetProcessTimes(process, out creation, out exit, out kernel, out user)) return false;
        int size = 32768;
        StringBuilder path = new StringBuilder(size);
        if (!QueryFullProcessImageName(process, 0, path, ref size) || size <= 0) return false;
        try { imagePath = Path.GetFullPath(path.ToString()); }
        catch { imagePath = String.Empty; return false; }
        creationFileTime = ((long)creation.High << 32) | creation.Low;
        return !String.IsNullOrWhiteSpace(imagePath) && creationFileTime > 0;
    }
}
'@
        try {
            Add-Type -TypeDefinition $nativeSource -ErrorAction Stop | Out-Null
            $api = [System.Type]::GetType('EliotStoreNativeProcessApi')
        } catch {
            throw [System.InvalidOperationException]::new("STORE-PROCESS-IDENTITY-UNPROVEN: native process handle API is unavailable: $($_.Exception.Message)")
        }
    }
    if ($null -eq $api) {
        throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: native process handle API is unavailable.')
    }
    return $api
}

function Invoke-StoreNativeTerminateByIdentity {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [int]$Pid,
        [Parameter(Mandatory)]
        [string]$ExpectedImagePath,
        [Parameter(Mandatory)]
        [string]$ExpectedStartTimeUtc
    )
    if ($Pid -le 0 -or [string]::IsNullOrWhiteSpace($ExpectedImagePath) -or
        [string]::IsNullOrWhiteSpace($ExpectedStartTimeUtc)) {
        throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: native termination identity is incomplete.')
    }
    $api = Get-StoreNativeProcessApi
    $handle = $api::OpenProcess(0x00101001, $false, $Pid)
    if ($handle -eq [System.IntPtr]::Zero) {
        $openError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($openError -eq 87) {
            return @{ pid = $Pid; exited = $true; signalled = $false; handle = [System.IntPtr]::Zero }
        }
        throw [System.InvalidOperationException]::new("STORE-PROCESS-IDENTITY-UNPROVEN: process handle could not be opened for pid '$Pid' (win32 $openError).")
    }
    $keepHandle = $false
    try {
        $imagePath = ''
        $creationFileTime = [long]0
        if (-not $api::TryGetProcessIdentity($handle, [ref]$imagePath, [ref]$creationFileTime)) {
            throw [System.InvalidOperationException]::new("STORE-PROCESS-IDENTITY-UNPROVEN: pinned identity could not be read for pid '$Pid'.")
        }
        $expectedPath = [System.IO.Path]::GetFullPath($ExpectedImagePath)
        if (-not [string]::Equals($imagePath, $expectedPath, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw [System.InvalidOperationException]::new("STORE-FOREIGN-PROCESS: pinned image path for pid '$Pid' does not match the owned process.")
        }
        $pinnedStart = [System.DateTime]::FromFileTimeUtc($creationFileTime).ToString('o')
        if ($pinnedStart -cne $ExpectedStartTimeUtc) {
            throw [System.InvalidOperationException]::new("STORE-FOREIGN-PROCESS: pinned start identity for pid '$Pid' does not match the owned process.")
        }
        $waitState = $api::WaitForSingleObject($handle, [uint32]0)
        if ($waitState -eq 0) {
            return @{ pid = $Pid; exited = $true; signalled = $false; handle = [System.IntPtr]::Zero }
        }
        if ($waitState -ne 258) {
            throw [System.InvalidOperationException]::new("STORE-PROCESS-IDENTITY-UNPROVEN: pinned liveness could not be established for pid '$Pid'.")
        }
        if (-not $api::TerminateProcess($handle, [uint32]1)) {
            $terminateError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            $waitState = $api::WaitForSingleObject($handle, [uint32]0)
            if ($waitState -eq 0) {
                return @{ pid = $Pid; exited = $true; signalled = $false; handle = [System.IntPtr]::Zero }
            }
            throw [System.InvalidOperationException]::new("lost-response: pinned termination of pid '$Pid' was not confirmed (win32 $terminateError).")
        }
        $keepHandle = $true
        return @{ pid = $Pid; exited = $false; signalled = $true; handle = $handle }
    } finally {
        if (-not $keepHandle) { [void]$api::CloseHandle($handle) }
    }
}

function Test-StoreProcessOwnership {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [int]$Pid,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ExpectedImagePath,
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$ExpectedStartTimeUtc,
        [Parameter(Mandatory)]
        [hashtable]$Observation
    )
    if ($Pid -le 0) {
        throw [System.ArgumentException]::new('STORE-INVALID-PID: owned pid is not positive.')
    }
    if ($Observation.ContainsKey('pid') -and ([int]$Observation['pid'] -ne $Pid)) {
        throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: observed process id does not match the owned pid.')
    }
    if ([string]::IsNullOrWhiteSpace($ExpectedImagePath) -or [string]::IsNullOrWhiteSpace($ExpectedStartTimeUtc)) {
        throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: expected process identity is incomplete.')
    }
    if (-not $Observation.ContainsKey('imagePath') -or [string]::IsNullOrWhiteSpace([string]$Observation['imagePath'])) {
        throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: observation carries no image path.')
    }
    if (-not $Observation.ContainsKey('startTimeUtc') -or [string]::IsNullOrWhiteSpace([string]$Observation['startTimeUtc'])) {
        throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: observation carries no start time.')
    }
    $expectedFull = [System.IO.Path]::GetFullPath($ExpectedImagePath)
    $observedFull = [System.IO.Path]::GetFullPath([string]$Observation['imagePath'])
    if ($observedFull -ine $expectedFull) {
        throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: live process image does not match the owned start identity.')
    }
    $expectedStart = [string]$ExpectedStartTimeUtc
    $observedStart = [string]$Observation['startTimeUtc']
    if ($observedStart -cne $expectedStart) {
        throw [System.InvalidOperationException]::new('STORE-FOREIGN-PROCESS: live process start time does not match the owned start identity.')
    }
    return $true
}

function Get-StoreOwnedDescendants {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [int]$Pid,
        [Parameter()]
        [AllowNull()]
        [hashtable]$RootIdentity,
        [ValidateRange(1, 16)]
        [int]$MaxDepth = 8,
        [ValidateRange(1, 1024)]
        [int]$MaxCount = 256
    )
    $found = New-Object Collections.Generic.List[hashtable]
    $complete = $true
    try {
        $rootExpected = $RootIdentity
        if ($null -eq $rootExpected) {
            $rootProcess = $null
            try { $rootProcess = Get-Process -Id $Pid -ErrorAction SilentlyContinue } catch { $rootProcess = $null }
            if ($null -eq $rootProcess) {
                throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: owned root disappeared before descendant capture.')
            }
            $rootExpected = Get-StoreProcessIdentity -Process $rootProcess
        }
        $frontier = @(@{ pid = $Pid; identity = $rootExpected })
        $depth = 0
        while ($frontier.Count -gt 0 -and $depth -lt $MaxDepth -and $found.Count -lt $MaxCount) {
            $next = @()
            foreach ($parentRecord in $frontier) {
                $parent = 0
                try { $parent = [int]$parentRecord['pid'] } catch { $parent = 0 }
                if ($parent -le 0 -or $null -eq $parentRecord['identity'] -or $parentRecord['identity'] -isnot [hashtable]) {
                    throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: traversal parent identity is missing.')
                }
                $parentExpected = $parentRecord['identity']
                $parentBefore = $null
                try { $parentBefore = Get-Process -Id $parent -ErrorAction SilentlyContinue } catch { $parentBefore = $null }
                if ($null -eq $parentBefore) {
                    throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: traversal parent exited before its child scan.')
                }
                $parentBeforeIdentity = Get-StoreProcessIdentity -Process $parentBefore
                [void](Test-StoreProcessOwnership -Pid $parent -ExpectedImagePath ([string]$parentExpected['imagePath']) `
                    -ExpectedStartTimeUtc ([string]$parentExpected['startTimeUtc']) -Observation $parentBeforeIdentity)
                $children = @(Get-CimInstance -ClassName 'Win32_Process' -Filter ("ParentProcessId = {0}" -f $parent) -ErrorAction Stop | ForEach-Object { [int]$_.ProcessId })
                foreach ($child in $children) {
                    $alreadyFound = @($found | Where-Object { [int]$_['pid'] -eq $child })
                    if ($child -le 0 -or $child -eq $Pid -or $alreadyFound.Count -gt 0) { continue }
                    if ($found.Count -ge $MaxCount) { break }
                    $childProcess = $null
                    try { $childProcess = Get-Process -Id $child -ErrorAction SilentlyContinue } catch { $childProcess = $null }
                    if ($null -eq $childProcess) {
                        throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: a descendant exited during identity capture.')
                    }
                    $childIdentity = Get-StoreProcessIdentity -Process $childProcess
                    $relationship = @(Get-CimInstance -ClassName 'Win32_Process' -Filter ("ProcessId = {0}" -f $child) -ErrorAction Stop)
                    if ($relationship.Count -ne 1 -or [int]$relationship[0].ParentProcessId -ne $parent) {
                        throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: descendant parent changed during identity capture.')
                    }
                    $childAgain = $null
                    try { $childAgain = Get-Process -Id $child -ErrorAction SilentlyContinue } catch { $childAgain = $null }
                    if ($null -eq $childAgain) {
                        throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: a descendant exited during identity capture.')
                    }
                    $childLiveIdentity = Get-StoreProcessIdentity -Process $childAgain
                    [void](Test-StoreProcessOwnership -Pid $child -ExpectedImagePath ([string]$childIdentity['imagePath']) `
                        -ExpectedStartTimeUtc ([string]$childIdentity['startTimeUtc']) -Observation $childLiveIdentity)
                    $childIdentity['parentPid'] = $parent
                    [void]$found.Add($childIdentity)
                    $next += @{ pid = $child; identity = $childIdentity }
                }
                $parentAfter = $null
                try { $parentAfter = Get-Process -Id $parent -ErrorAction SilentlyContinue } catch { $parentAfter = $null }
                if ($null -eq $parentAfter) {
                    throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: traversal parent exited during its child scan.')
                }
                $parentAfterIdentity = Get-StoreProcessIdentity -Process $parentAfter
                [void](Test-StoreProcessOwnership -Pid $parent -ExpectedImagePath ([string]$parentExpected['imagePath']) `
                    -ExpectedStartTimeUtc ([string]$parentExpected['startTimeUtc']) -Observation $parentAfterIdentity)
            }
            $frontier = $next
            $depth++
        }
        if ($frontier.Count -gt 0) { $complete = $false }
    } catch {
        $complete = $false
    }
    return @{ pids = @($found | ForEach-Object { [int]$_['pid'] }); processes = @($found.ToArray()); complete = $complete }
}

# The exact accepted terminal state of a protected run root: inheritance broken,
# no deny rule, and exactly one allow rule granting the run principal full
# control of the root and everything created inside it. One predicate serves both
# the pre-write check and the post-write proof, so the state is compared the same
# way in both directions.
function Test-StoreRootAclState {
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory)]
        [System.Security.AccessControl.FileSystemSecurity]$Security,
        [Parameter(Mandatory)]
        [System.Security.Principal.SecurityIdentifier]$PrincipalSid
    )
    $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
    $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    if ($Security.AreAccessRulesProtected -ne $true) { return $false }
    $rules = @($Security.Access)
    if ($rules.Count -ne 1) { return $false }
    $rule = $rules[0]
    if ($rule.AccessControlType -ne $allow) { return $false }
    # A read ACL resolves the rule identity to an account name, so the rule is
    # compared by its stable SID rather than by a localizable name.
    $ruleSid = $null
    if ($rule.IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
        $ruleSid = [string]$rule.IdentityReference
    } else {
        $ruleSid = [string]$rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
    }
    if ($ruleSid -cne [string]$PrincipalSid) { return $false }
    if ([int]$rule.FileSystemRights -ne [int]$rights) { return $false }
    if ([int]$rule.InheritanceFlags -ne [int]$inherit) { return $false }
    return $true
}

function Protect-StoreRootAcl {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )
    if ([string]::IsNullOrWhiteSpace($Path)) {
        throw [System.ArgumentException]::new('STORE-INVALID-PATH: Path is empty.')
    }
    $full = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $full -PathType Container)) {
        throw [System.InvalidOperationException]::new("STORE-ACL-FAILED: root is not an existing directory: $full")
    }
    try {
        $principal = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($null -eq $principal -or $null -eq $principal.User) {
            throw [System.InvalidOperationException]::new('STORE-ACL-FAILED: run principal identity is unavailable.')
        }
        # Re-allocation for the same run reuses the marker-verified roots, so the
        # accepted terminal state is observed first. Re-writing an ACL that
        # already carries exactly the required run-principal-only grant is a
        # privileged no-op that the run principal cannot perform, and refusing it
        # would make an owned root impossible to re-verify on a real host.
        $observed = Get-Acl -LiteralPath $full -ErrorAction Stop
        if (Test-StoreRootAclState -Security $observed -PrincipalSid $principal.User) {
            return @{ path = $full; protected = $true; principal = [string]$principal.Name; aclWrite = 'already-protected' }
        }
        $security = Get-Acl -LiteralPath $full -ErrorAction Stop
        $security.SetAccessRuleProtection($true, $false)
        foreach ($rule in @($security.Access)) {
            [void]$security.RemoveAccessRuleAll($rule)
        }
        $rights = [System.Security.AccessControl.FileSystemRights]::FullControl
        $inherit = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        $propagate = [System.Security.AccessControl.PropagationFlags]::None
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $grant = [System.Security.AccessControl.FileSystemAccessRule]::new($principal.User, $rights, $inherit, $propagate, $allow)
        [void]$security.AddAccessRule($grant)
        Set-Acl -LiteralPath $full -AclObject $security -ErrorAction Stop
        $verify = Get-Acl -LiteralPath $full -ErrorAction Stop
        if (-not (Test-StoreRootAclState -Security $verify -PrincipalSid $principal.User)) {
            throw [System.InvalidOperationException]::new('STORE-ACL-FAILED: the protected root does not carry exactly the run-principal-only grant.')
        }
        return @{ path = $full; protected = $true; principal = [string]$principal.Name; aclWrite = 'applied' }
    } catch {
        if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
        throw [System.InvalidOperationException]::new("STORE-ACL-FAILED: explicit ACL failed for '$full': $($_.Exception.Message)")
    }
}

function New-StoreJobBinding {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [int]$Pid,
        [Parameter(Mandatory)]
        [string]$JobName
    )
    if ($Pid -le 0) {
        throw [System.ArgumentException]::new('STORE-INVALID-PID: owned pid is not positive.')
    }
    if ([string]::IsNullOrWhiteSpace($JobName) -or $JobName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        throw [System.ArgumentException]::new('STORE-INVALID-JOB: job name has an invalid shape.')
    }
    try {
        $api = [System.Type]::GetType('EliotStoreJobApi')
        if ($null -eq $api) {
            $csharp = @'
using System;
using System.Runtime.InteropServices;
public static class EliotStoreJobApi {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(int access, bool inherit, int pid);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool result);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateJobObject(IntPtr attrs, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, int size);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct IO_COUNTERS {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }
}
'@
            Add-Type -TypeDefinition $csharp -ErrorAction Stop | Out-Null
            $api = [System.Type]::GetType('EliotStoreJobApi')
        }
        if ($null -eq $api) {
            throw [System.InvalidOperationException]::new('STORE-JOB-FAILED: job helper type is unavailable.')
        }
        $handle = $api::OpenProcess(0x0101, $false, $Pid)
        if ($handle -eq [System.IntPtr]::Zero) {
            throw [System.InvalidOperationException]::new('STORE-JOB-FAILED: owned process could not be opened for job assignment.')
        }
        try {
            $inJob = $false
            $probed = $false
            try {
                $out = $false
                $probed = $api::IsProcessInJob($handle, [System.IntPtr]::Zero, [ref]$out)
                if ($probed) { $inJob = $out }
            } catch { $probed = $false }
            if ($probed -and $inJob) {
                return @{ jobName = 'inherited'; bound = $true; pid = $Pid }
            }
            $job = $api::CreateJobObject([System.IntPtr]::Zero, $JobName)
            if ($job -eq [System.IntPtr]::Zero) {
                throw [System.InvalidOperationException]::new('STORE-JOB-FAILED: job object could not be created.')
            }
            $info = New-Object 'EliotStoreJobApi+JOBOBJECT_EXTENDED_LIMIT_INFORMATION'
            $info.BasicLimitInformation.LimitFlags = [uint32]0x2000
            $size = [System.Runtime.InteropServices.Marshal]::SizeOf($info)
            if (-not ($api::SetInformationJobObject($job, 9, [ref]$info, $size))) {
                [void]$api::CloseHandle($job)
                throw [System.InvalidOperationException]::new('STORE-JOB-FAILED: kill-on-close limit could not be set.')
            }
            if (-not ($api::AssignProcessToJobObject($job, $handle))) {
                [void]$api::CloseHandle($job)
                throw [System.InvalidOperationException]::new('STORE-JOB-FAILED: owned process could not join the job object.')
            }
            $Script:StoreJobHandles[$JobName] = $job
            return @{ jobName = $JobName; bound = $true; pid = $Pid }
        } finally {
            [void]$api::CloseHandle($handle)
        }
    } catch {
        if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
        throw [System.InvalidOperationException]::new("STORE-JOB-FAILED: job binding failed: $($_.Exception.Message)")
    }
}

function Close-StoreJobBinding {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string]$JobName
    )
    if ([string]::IsNullOrWhiteSpace($JobName) -or $JobName -ceq 'inherited') {
        return @{ jobName = $JobName; closed = $false; reason = 'inherited' }
    }
    if (-not $Script:StoreJobHandles.ContainsKey($JobName)) {
        return @{ jobName = $JobName; closed = $false; reason = 'untracked' }
    }
    $job = $Script:StoreJobHandles[$JobName]
    try {
        $api = [System.Type]::GetType('EliotStoreJobApi')
        if ($null -ne $api -and $job -is [System.IntPtr] -and $job -ne [System.IntPtr]::Zero) {
            if (-not $api::CloseHandle($job)) {
                return @{ jobName = $JobName; closed = $false }
            }
            [void]$Script:StoreJobHandles.Remove($JobName)
            return @{ jobName = $JobName; closed = $true }
        }
        return @{ jobName = $JobName; closed = $false }
    } catch {
        return @{ jobName = $JobName; closed = $false; reason = 'close-failed' }
    }
}

# Real FileSystem seam. Ops: ensure-owned-root {runRoot,dataRoot,logRoot,
# secretRoot,runId,owner,generation} -> {created,existed,markerPath};
# read-reconciliation {runRoot,runId} -> record hashtable or $null;
# write-reconciliation {runRoot,runId,record} -> {path,persisted};
# resolve-reconciliation {runRoot,runId,resolution} -> {resolved,path|reason}.
function New-StoreDefaultFileSystem {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()
    $markerFile = $Script:StoreOwnerMarkerFile
    $markerValue = $Script:StoreOwnedRootMarker
    $reconFile = $Script:StoreReconciliationFile
    $reconMarker = $Script:StoreReconciliationMarker
    $dispatch = {
        param($Request)
        if ($null -eq $Request -or $Request -isnot [hashtable] -or -not $Request.ContainsKey('op')) {
            throw [System.ArgumentException]::new('STORE-INVALID-FILESYSTEM-OP: filesystem request must carry an op.')
        }
        $op = [string]$Request['op']
        $runId = [string]$Request['runId']
        if ($runId -cnotmatch '^[0-9a-f]{32}$') {
            throw [System.ArgumentException]::new('STORE-INVALID-BINDING: filesystem runId must be 32 lowercase hex.')
        }
        $runRoot = [System.IO.Path]::GetFullPath([string]$Request['runRoot'])
        if ($op -ceq 'ensure-owned-root') {
            foreach ($field in @('dataRoot', 'logRoot', 'secretRoot')) {
                if (-not $Request.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$Request[$field])) {
                    throw [System.ArgumentException]::new("STORE-INVALID-FILESYSTEM-OP: filesystem request is missing '$field'.")
                }
                [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path ([string]$Request[$field]) -ExpectedRunId $runId)
            }
            $owner = [string]$Request['owner']
            $gen = 0
            try { $gen = [int]$Request['generation'] } catch { $gen = 0 }
            if ([string]::IsNullOrWhiteSpace($owner) -or $gen -le 0) {
                throw [System.ArgumentException]::new('STORE-INVALID-FILESYSTEM-OP: owner/generation are required.')
            }
            $markerPath = [System.IO.Path]::GetFullPath((Join-Path $runRoot $markerFile))
            [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $markerPath -ExpectedRunId $runId)
            if (Test-Path -LiteralPath $runRoot -PathType Container) {
                if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
                    throw [System.InvalidOperationException]::new("STORE-ALLOCATION-CONFLICT: run root exists without an owner marker: $runRoot")
                }
                try {
                    $existing = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: owner marker unreadable at: $runRoot")
                }
                if (-not (Test-StoreOwnedRootClaim -Recorded $existing -RunId $runId -Owner $owner -Generation $gen)) {
                    throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: owner marker does not state this run's ownership claim: $runRoot")
                }
                foreach ($field in @('dataRoot', 'logRoot', 'secretRoot')) {
                    [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetFullPath([string]$Request[$field]))
                }
                return @{ created = $false; existed = $true; markerPath = $markerPath }
            }
            [void][System.IO.Directory]::CreateDirectory($runRoot)
            foreach ($field in @('dataRoot', 'logRoot', 'secretRoot')) {
                [void][System.IO.Directory]::CreateDirectory([System.IO.Path]::GetFullPath([string]$Request[$field]))
            }
            $marker = @{
                marker      = $markerValue
                run_id      = $runId
                owner       = $owner
                generation  = $gen
                created_utc = ([System.DateTimeOffset]::UtcNow.ToString('o'))
            }
            $markerJson = ($marker | ConvertTo-Json -Depth 4 -Compress)
            try {
                $stream = [System.IO.File]::Open($markerPath, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
                try {
                    $bytes = [System.Text.Encoding]::UTF8.GetBytes($markerJson)
                    $stream.Write($bytes, 0, $bytes.Length)
                } finally {
                    $stream.Close()
                }
            } catch [System.IO.IOException] {
                if (-not (Test-Path -LiteralPath $markerPath -PathType Leaf)) { throw }
                try {
                    $raced = Get-Content -LiteralPath $markerPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: owner marker unreadable at: $runRoot")
                }
                if (-not (Test-StoreOwnedRootClaim -Recorded $raced -RunId $runId -Owner $owner -Generation $gen)) {
                    throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: owner marker does not state this run's ownership claim: $runRoot")
                }
                return @{ created = $false; existed = $true; markerPath = $markerPath }
            }
            return @{ created = $true; existed = $false; markerPath = $markerPath }
        }
        if ($op -ceq 'read-reconciliation') {
            $reconPath = [System.IO.Path]::GetFullPath((Join-Path $runRoot $reconFile))
            [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $reconPath -ExpectedRunId $runId)
            if (-not (Test-Path -LiteralPath $reconPath -PathType Leaf)) { return $null }
            try {
                $stored = Get-Content -LiteralPath $reconPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            } catch {
                throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: reconciliation record unreadable at: $runRoot")
            }
            if ([string]$stored.marker -cne $reconMarker -or [string]$stored.run_id -cne $runId) {
                throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: reconciliation record belongs to another run: $runRoot")
            }
            $record = @{}
            foreach ($name in @('marker', 'run_id', 'operation', 'request_key', 'endpoint', 'owner', 'observed_at', 'state', 'detail', 'resolution', 'resolved_at')) {
                $prop = $stored.PSObject.Properties[$name]
                if ($null -ne $prop) { $record[$name] = [string]$prop.Value }
            }
            $genProp = $stored.PSObject.Properties['generation']
            if ($null -ne $genProp) {
                try { $record['generation'] = [int]$genProp.Value } catch { $record['generation'] = 0 }
            }
            return $record
        }
        if ($op -ceq 'write-reconciliation') {
            if (-not $Request.ContainsKey('record') -or $Request['record'] -isnot [hashtable]) {
                throw [System.ArgumentException]::new('STORE-INVALID-FILESYSTEM-OP: reconciliation write needs a record.')
            }
            $incoming = $Request['record']
            if ([string]$incoming['marker'] -cne $reconMarker -or [string]$incoming['run_id'] -cne $runId) {
                throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: reconciliation record identity is foreign.')
            }
            $reconPath = [System.IO.Path]::GetFullPath((Join-Path $runRoot $reconFile))
            [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $reconPath -ExpectedRunId $runId)
            if (Test-Path -LiteralPath $reconPath -PathType Leaf) {
                try {
                    $prior = Get-Content -LiteralPath $reconPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                } catch {
                    throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: reconciliation record unreadable at: $runRoot")
                }
                if ([string]$prior.run_id -cne $runId) {
                    throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: reconciliation record belongs to another run: $runRoot")
                }
            }
            $payload = ($incoming | ConvertTo-Json -Depth 6 -Compress)
            [System.IO.File]::WriteAllText($reconPath, $payload, [System.Text.Encoding]::UTF8)
            return @{ path = $reconPath; persisted = $true }
        }
        if ($op -ceq 'resolve-reconciliation') {
            $resolution = [string]$Request['resolution']
            if ([string]::IsNullOrWhiteSpace($resolution)) {
                throw [System.ArgumentException]::new('STORE-INVALID-RECONCILIATION: resolution is empty.')
            }
            $reconPath = [System.IO.Path]::GetFullPath((Join-Path $runRoot $reconFile))
            [void](Resolve-StoreOwnedPath -RunRoot $runRoot -Path $reconPath -ExpectedRunId $runId)
            if (-not (Test-Path -LiteralPath $reconPath -PathType Leaf)) {
                return @{ resolved = $false; reason = 'no-record' }
            }
            try {
                $stored = Get-Content -LiteralPath $reconPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            } catch {
                throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: reconciliation record unreadable at: $runRoot")
            }
            if ([string]$stored.run_id -cne $runId) {
                throw [System.InvalidOperationException]::new("STORE-FOREIGN-ROOT: reconciliation record belongs to another run: $runRoot")
            }
            $updated = [ordered]@{}
            foreach ($prop in $stored.PSObject.Properties) {
                $updated[[string]$prop.Name] = $prop.Value
            }
            $updated['state'] = 'resolved'
            $updated['resolution'] = $resolution
            $updated['resolved_at'] = ([System.DateTimeOffset]::UtcNow.ToString('o'))
            [System.IO.File]::WriteAllText($reconPath, ($updated | ConvertTo-Json -Depth 6 -Compress), [System.Text.Encoding]::UTF8)
            return @{ resolved = $true; path = $reconPath }
        }
        throw [System.ArgumentException]::new("STORE-INVALID-FILESYSTEM-OP: unknown filesystem op '$op'.")
    }
    return $dispatch.GetNewClosure()
}

# Real Acl seam. Op: protect {path,runId} -> {path,protected,principal,runId}.
# Fakes must accept the same request and return the same shape.
function New-StoreDefaultAcl {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()
    $dispatch = {
        param($Request)
        if ($null -eq $Request -or $Request -isnot [hashtable] -or -not $Request.ContainsKey('op')) {
            throw [System.ArgumentException]::new('STORE-INVALID-ACL-OP: ACL request must carry an op.')
        }
        $op = [string]$Request['op']
        if ($op -cne 'protect') {
            throw [System.ArgumentException]::new("STORE-INVALID-ACL-OP: unknown ACL op '$op'.")
        }
        if (-not $Request.ContainsKey('path') -or [string]::IsNullOrWhiteSpace([string]$Request['path'])) {
            throw [System.ArgumentException]::new('STORE-INVALID-ACL-OP: ACL protect needs a path.')
        }
        $result = Protect-StoreRootAcl -Path ([string]$Request['path'])
        $result['runId'] = [string]$Request['runId']
        return $result
    }
    return $dispatch.GetNewClosure()
}

# Real port reservation: hold the loopback bind until Start reaches launch
# handoff. Windows child launch cannot inherit this socket, so releasing it
# does not make the later bind atomic; ObserveReadiness must prove that the
# listener belongs to the exact launched PID before accepting readiness.
# Allocation carries the listener object and owner identity; cleanup releases
# only that exact listener.
# In: {runId,namespace,database}. Out: {port,host,listener}.
function New-StoreDefaultPortReservation {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()
    $loopback = $Script:StoreLoopback
    $reserve = {
        param($Context)
        $listener = $null
        try {
            $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Parse($loopback), 0)
            # The hold is the ownership token, so it is taken as an exclusive
            # bind: SO_EXCLUSIVEADDRUSE makes a competing bind of this endpoint
            # fail outright instead of succeeding while this reservation is
            # waiting for the launch handoff. Without it the exclusivity would
            # rest on the platform's default bind behaviour rather than on
            # anything this reservation states about itself.
            $listener.ExclusiveAddressUse = $true
            $listener.Start()
            $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
            if ($port -lt 1024 -or $port -gt 65535) {
                throw [System.InvalidOperationException]::new("STORE-PORT-CONFLICT: reserved port '$port' is outside the ephemeral bound.")
            }
            return @{ port = $port; host = $loopback; listener = $listener }
        } catch {
            $primary = $_.Exception.Message
            if ($null -ne $listener) {
                try { $listener.Stop() } catch {
                    throw [System.InvalidOperationException]::new(
                        "STORE-PORT-RESERVATION-RECONCILIATION-REQUIRED: failure='$primary'; cleanup='$($_.Exception.Message)'.")
                }
            }
            if ($primary -match '^STORE-[A-Z0-9-]+:') { throw [System.InvalidOperationException]::new($primary) }
            throw [System.InvalidOperationException]::new("STORE-PORT-CONFLICT: loopback reservation failed: $primary")
        }
    }
    return $reserve.GetNewClosure()
}

# Real acquisition: verifies <InstallRoot>/runtime/surreal.exe on every call
# (digest, then PE machine, then the fixed `version` probe) and reports
# acquired-verified, or cached-reverified when the bound cache record matches
# the pin and the recomputed digest. In: {runId,artifact}.
function New-StoreDefaultAcquisition {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param(
        [Parameter(Mandatory)]
        [string]$InstallRoot,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$CacheRecord
    )
    if ([string]::IsNullOrWhiteSpace($InstallRoot)) {
        throw [System.ArgumentException]::new('STORE-INVALID-ACQUISITION: install root is empty.')
    }
    $rootFull = [System.IO.Path]::GetFullPath($InstallRoot)
    $artifact = $Script:StoreArtifact
    $relativePath = $Script:StoreRelativePath
    $version = $Script:StoreVersion
    $architecture = $Script:StoreArchitecture
    $peMachine = $Script:StorePeMachine
    $digest = $Script:StoreDigest
    $cachePath = $CacheRecord
    $acquire = {
        param($Context)
        if ($null -eq $Context -or $Context -isnot [hashtable]) {
            throw [System.ArgumentException]::new('STORE-ACQUISITION-FAILED: acquisition context must be a hashtable.')
        }
        if (-not $Context.ContainsKey('artifact') -or [string]$Context['artifact'] -cne $artifact) {
            throw [System.InvalidOperationException]::new('STORE-ACQUISITION-FAILED: acquisition artifact is not the approved binary.')
        }
        $candidate = [System.IO.Path]::GetFullPath((Join-Path $rootFull $relativePath))
        $prefix = $rootFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
        if ($candidate -ine $rootFull -and -not $candidate.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw [System.InvalidOperationException]::new("STORE-ACQUISITION-FAILED: approved path escapes the install root: $candidate")
        }
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw [System.InvalidOperationException]::new("STORE-BINARY-MISSING: approved binary is absent: $candidate")
        }
        $computed = ''
        try {
            $stream = [System.IO.File]::OpenRead($candidate)
            try {
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $bytes = $sha.ComputeHash($stream)
                    $computed = ([System.BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()
                } finally {
                    $sha.Dispose()
                }
            } finally {
                $stream.Close()
            }
        } catch {
            if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
            throw [System.InvalidOperationException]::new("STORE-ACQUISITION-FAILED: digest computation failed: $($_.Exception.Message)")
        }
        if ($computed -cne $digest) {
            throw [System.InvalidOperationException]::new('STORE-DIGEST-MISMATCH: binary digest does not match the pinned SurrealDB identity.')
        }
        try {
            $probe = [System.IO.File]::OpenRead($candidate)
            try {
                if ($probe.Length -lt 64) {
                    throw [System.InvalidOperationException]::new('STORE-ARCH-MISMATCH: binary is too small to carry a PE header.')
                }
                $header = [byte[]]::new(64)
                [void]$probe.Read($header, 0, 64)
                if ($header[0] -ne 0x4D -or $header[1] -ne 0x5A) {
                    throw [System.InvalidOperationException]::new('STORE-ARCH-MISMATCH: binary is not a PE image.')
                }
                $peOffset = [System.BitConverter]::ToInt32($header, 0x3C)
                if ($peOffset -lt 0 -or ($peOffset + 6) -gt $probe.Length) {
                    throw [System.InvalidOperationException]::new('STORE-ARCH-MISMATCH: PE header offset is outside the binary.')
                }
                $probe.Seek([long]$peOffset, [System.IO.SeekOrigin]::Begin) | Out-Null
                $coff = [byte[]]::new(6)
                [void]$probe.Read($coff, 0, 6)
                $machine = [System.BitConverter]::ToUInt16($coff, 4)
                $machineHex = $machine.ToString('X4')
                if ($machineHex -cne $peMachine) {
                    throw [System.InvalidOperationException]::new("STORE-ARCH-MISMATCH: PE machine '$machineHex' is not '$peMachine'.")
                }
            } finally {
                $probe.Close()
            }
        } catch {
            if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
            throw [System.InvalidOperationException]::new("STORE-ACQUISITION-FAILED: PE inspection failed: $($_.Exception.Message)")
        }
        try {
            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName = $candidate
            $psi.Arguments = 'version'
            $psi.WorkingDirectory = $rootFull
            $psi.UseShellExecute = $false
            $psi.CreateNoWindow = $true
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError = $true
            $psi.EnvironmentVariables.Clear()
            $systemRoot = [System.Environment]::GetEnvironmentVariable('SystemRoot')
            if (-not [string]::IsNullOrWhiteSpace($systemRoot)) {
                $psi.EnvironmentVariables['SystemRoot'] = $systemRoot
            }
            $proc = [System.Diagnostics.Process]::Start($psi)
            if ($null -eq $proc) {
                throw [System.InvalidOperationException]::new('STORE-VERSION-MISMATCH: version probe produced no process.')
            }
            try {
                if (-not $proc.WaitForExit(15000)) {
                    try { $proc.Kill() } catch { }
                    throw [System.InvalidOperationException]::new('STORE-VERSION-MISMATCH: version probe timed out.')
                }
                $text = [string]$proc.StandardOutput.ReadToEnd() + [string]$proc.StandardError.ReadToEnd()
                if ($text -cnotmatch [regex]::Escape($version)) {
                    throw [System.InvalidOperationException]::new("STORE-VERSION-MISMATCH: version probe does not report '$version'.")
                }
            } finally {
                $proc.Close()
            }
        } catch {
            if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
            throw [System.InvalidOperationException]::new("STORE-VERSION-MISMATCH: version probe failed: $($_.Exception.Message)")
        }
        $provenance = 'acquired-verified'
        if (-not [string]::IsNullOrWhiteSpace($cachePath)) {
            $recordFull = [System.IO.Path]::GetFullPath($cachePath)
            if (-not (Test-Path -LiteralPath $recordFull -PathType Leaf)) {
                throw [System.InvalidOperationException]::new("STORE-DIGEST-MISMATCH: cache record is absent: $recordFull")
            }
            try {
                $recorded = Get-Content -LiteralPath $recordFull -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
            } catch {
                throw [System.InvalidOperationException]::new("STORE-DIGEST-MISMATCH: cache record unreadable: $recordFull")
            }
            if ([string]$recorded.sha256 -cne $digest -or [string]$recorded.sha256 -cne $computed) {
                throw [System.InvalidOperationException]::new('STORE-DIGEST-MISMATCH: cache record does not match the pinned and recomputed digest.')
            }
            $provenance = 'cached-reverified'
        }
        return @{
            version      = $version
            architecture = $architecture
            peMachine    = $peMachine
            digest       = $digest
            provenance   = $provenance
            storePath    = $candidate
        }
    }
    return $acquire.GetNewClosure()
}

# Real launcher: fixed argv, child-only env block, owned working directory,
# stdout/stderr drained to bounded owned logs, Job Object binding, vault
# capture of the ephemeral credential for the bound Store client.
# Out: {observedPid,observedNonce,imagePath,startTimeUtc,jobName}.
function New-StoreDefaultLauncher {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param(
        [Parameter()]
        [AllowNull()]
        [scriptblock]$VaultCapture
    )
    $artifact = $Script:StoreArtifact
    $userEnv = $Script:StoreCredentialUserEnv
    $passEnv = $Script:StoreCredentialPassEnv
    $capture = $VaultCapture
    $launch = {
        param($Input)
        if ($null -eq $Input -or $Input -isnot [hashtable]) {
            throw [System.ArgumentException]::new('STORE-LAUNCH-FAILED: launcher input must be a hashtable.')
        }
        foreach ($field in @('runId', 'argv', 'endpoint', 'namespace', 'database', 'childEnv', 'workingDirectory', 'requestKey')) {
            if (-not $Input.ContainsKey($field) -or $null -eq $Input[$field]) {
                throw [System.ArgumentException]::new("STORE-LAUNCH-FAILED: launcher input is missing '$field'.")
            }
        }
        $argv = @($Input['argv'])
        if ($argv.Count -lt 2) {
            throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: fixed argv is incomplete.')
        }
        $exe = [string]$argv[0]
        if (-not $exe.EndsWith($artifact, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: launcher input does not name the approved artifact.')
        }
        $workDir = [string]$Input['workingDirectory']
        if (-not (Test-Path -LiteralPath $workDir -PathType Container)) {
            throw [System.InvalidOperationException]::new("STORE-LAUNCH-FAILED: launcher working directory is absent: $workDir")
        }
        $childEnv = $Input['childEnv']
        if ($childEnv -isnot [hashtable]) {
            throw [System.ArgumentException]::new('STORE-LAUNCH-FAILED: launcher child env must be a hashtable.')
        }
        $quoted = New-Object Collections.Generic.List[string]
        for ($i = 1; $i -lt $argv.Count; $i++) {
            $token = [string]$argv[$i]
            if ($token.Contains('"')) {
                throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: fixed argv carries a quote character.')
            }
            if ($token.Contains(' ') -or $token.Contains("`t") -or [string]::IsNullOrEmpty($token)) {
                [void]$quoted.Add(('"' + $token + '"'))
            } else {
                [void]$quoted.Add($token)
            }
        }
        $logDir = [System.IO.Path]::GetFullPath((Join-Path $workDir 'logs'))
        if (-not (Test-Path -LiteralPath $logDir -PathType Container)) {
            [void][System.IO.Directory]::CreateDirectory($logDir)
        }
        $stdoutLog = Join-Path $logDir 'surrealdb.stdout.log'
        $stderrLog = Join-Path $logDir 'surrealdb.stderr.log'
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $exe
        $psi.Arguments = ($quoted -join ' ')
        $psi.WorkingDirectory = $workDir
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.EnvironmentVariables.Clear()
        foreach ($key in @($childEnv.Keys)) {
            $psi.EnvironmentVariables[[string]$key] = [string]$childEnv[$key]
        }
        $proc = $null
        try {
            $proc = [System.Diagnostics.Process]::Start($psi)
        } catch [System.ComponentModel.Win32Exception] {
            throw [System.InvalidOperationException]::new("STORE-LAUNCH-DENIED: process creation was denied: $($_.Exception.Message)")
        } catch {
            if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
            throw [System.InvalidOperationException]::new("STORE-LAUNCH-FAILED: process creation failed: $($_.Exception.Message)")
        }
        if ($null -eq $proc) {
            throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: process creation returned no handle.')
        }
        $drainCap = 1048576
        $stdoutDrain = {
            param($drainSender, $drainEvent)
            if ($null -ne $drainEvent.Data) {
                try {
                    $info = Get-Item -LiteralPath $stdoutLog -ErrorAction SilentlyContinue
                    if ($null -eq $info -or $info.Length -lt $drainCap) {
                        [System.IO.File]::AppendAllText($stdoutLog, ($drainEvent.Data + "`r`n"), [System.Text.Encoding]::UTF8)
                    }
                } catch { }
            }
        }.GetNewClosure()
        $stderrDrain = {
            param($drainSender, $drainEvent)
            if ($null -ne $drainEvent.Data) {
                try {
                    $info = Get-Item -LiteralPath $stderrLog -ErrorAction SilentlyContinue
                    if ($null -eq $info -or $info.Length -lt $drainCap) {
                        [System.IO.File]::AppendAllText($stderrLog, ($drainEvent.Data + "`r`n"), [System.Text.Encoding]::UTF8)
                    }
                } catch { }
            }
        }.GetNewClosure()
        try { $proc.add_OutputDataReceived($stdoutDrain) } catch { }
        try { $proc.add_ErrorDataReceived($stderrDrain) } catch { }
        try { $proc.BeginOutputReadLine() } catch { }
        try { $proc.BeginErrorReadLine() } catch { }
        $observedPid = $proc.Id
        $imagePath = ''
        try { $imagePath = [string]$proc.MainModule.FileName } catch { $imagePath = '' }
        $startTimeUtc = ''
        try { $startTimeUtc = $proc.StartTime.ToUniversalTime().ToString('o') } catch { $startTimeUtc = '' }
        if ([string]::IsNullOrWhiteSpace($imagePath) -or [string]::IsNullOrWhiteSpace($startTimeUtc)) {
            try { $proc.Kill() } catch { }
            throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: launched process identity is unavailable.')
        }
        $runId = [string]$Input['runId']
        $jobName = ('eliot-store-{0}-{1}' -f $runId.Substring(0, 8), ([string]$Input['requestKey'] -replace '[^A-Za-z0-9._-]', ''))
        if ($jobName.Length -gt 64) { $jobName = $jobName.Substring(0, 64) }
        try {
            $job = New-StoreJobBinding -Pid $observedPid -JobName $jobName
            $jobName = [string]$job['jobName']
        } catch {
            try { $proc.Kill() } catch { }
            throw
        }
        if ($null -ne $capture) {
            try {
                [void](& $capture $runId ([string]$childEnv[$userEnv]) ([string]$childEnv[$passEnv]) ([string]$Input['endpoint']) ([string]$Input['namespace']) ([string]$Input['database']))
            } catch {
                try { $proc.Kill() } catch { }
                throw [System.InvalidOperationException]::new("STORE-LAUNCH-FAILED: credential binding failed: $($_.Exception.Message)")
            }
        }
        $requestedKey = [string]$Input['requestKey']
        $observedNonce = ''
        $attempts = 0
        do {
            $nonceBytes = [byte[]]::new(4)
            [System.Security.Cryptography.RandomNumberGenerator]::GetBytes($nonceBytes)
            $observedNonce = ([System.BitConverter]::ToString($nonceBytes)).Replace('-', '').ToLowerInvariant()
            $attempts++
        } while ($('req-' + $observedNonce) -ceq $requestedKey -and $attempts -lt 8)
        if (('req-' + $observedNonce) -ceq $requestedKey) {
            try { $proc.Kill() } catch { }
            throw [System.InvalidOperationException]::new('STORE-LAUNCH-FAILED: observed nonce collided with the request key.')
        }
        return @{
            observedPid   = $observedPid
            observedNonce = $observedNonce
            imagePath     = $imagePath
            startTimeUtc  = $startTimeUtc
            jobName       = $jobName
        }
    }
    return $launch.GetNewClosure()
}

# Real process observer. In: {pid,runId}.
# Out: {alive,pid,imagePath,startTimeUtc,descendants,treeComplete}.
function New-StoreDefaultProcessObserver {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param()
    $observe = {
        param($Context)
        if ($null -eq $Context -or $Context -isnot [hashtable] -or -not $Context.ContainsKey('pid')) {
            throw [System.ArgumentException]::new('STORE-OBSERVER-FAILED: process observation needs a pid.')
        }
        $pid = 0
        try { $pid = [int]$Context['pid'] } catch {
            throw [System.InvalidOperationException]::new('STORE-OBSERVER-FAILED: observed pid is not an integer.')
        }
        if ($pid -le 0) {
            throw [System.ArgumentException]::new('STORE-INVALID-PID: observed pid is not positive.')
        }
        $proc = $null
        try { $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue } catch { $proc = $null }
        if ($null -eq $proc) {
            return @{ alive = $false; pid = $pid }
        }
        try {
            if ($proc.HasExited) {
                return @{ alive = $false; pid = $pid }
            }
        } catch {
            return @{ alive = $false; pid = $pid }
        }
        $identity = Get-StoreProcessIdentity -Process $proc
        $tree = Get-StoreOwnedDescendants -Pid $pid -RootIdentity $identity
        return @{
            alive        = $true
            pid          = $pid
            imagePath    = [string]$identity['imagePath']
            startTimeUtc = [string]$identity['startTimeUtc']
            descendants  = @($tree['processes'])
            treeComplete = [bool]$tree['complete']
        }
    }
    return $observe.GetNewClosure()
}

# Real port observer: loopback-only TCP connect plus listener-owner proof.
# In: {endpoint,runId}. Out: {open,endpoint,ownerPid?}.
function New-StoreDefaultPortObserver {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param(
        [ValidateRange(100, 30000)]
        [int]$ConnectTimeoutMs = 2000
    )
    $timeoutMs = $ConnectTimeoutMs
    $observe = {
        param($Context)
        if ($null -eq $Context -or $Context -isnot [hashtable] -or -not $Context.ContainsKey('endpoint')) {
            throw [System.ArgumentException]::new('STORE-OBSERVER-FAILED: port observation needs an endpoint.')
        }
        $parsed = Test-StoreLoopbackEndpoint -Endpoint ([string]$Context['endpoint'])
        $open = $false
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $task = $client.ConnectAsync([string]$parsed['host'], [int]$parsed['port'])
            $open = $task.Wait($timeoutMs)
            if ($open) { $open = $client.Connected }
        } catch {
            $open = $false
        } finally {
            $client.Close()
        }
        $result = @{ open = $open; endpoint = ([string]$Context['endpoint']) }
        try {
            $conn = Get-NetTCPConnection -LocalAddress ([string]$parsed['host']) -LocalPort ([int]$parsed['port']) -State 'Listen' -ErrorAction SilentlyContinue | Select-Object -First 1
            if ($null -ne $conn) {
                $result['ownerPid'] = [int]$conn.OwningProcess
            }
        } catch { }
        return $result
    }
    return $observe.GetNewClosure()
}

# Real Store client: version, then the exclusive create of this run's
# namespace/database, then authenticated USE NS/DB, then the accepted
# schema observation (or the exact declared fixture plus baseline
# re-observation on reset). Loopback only, bounded, Basic auth with the
# vaulted ephemeral credential; secrets never enter receipts or errors.
# Observe out: {authenticated,namespace,database,schemaDigest,fixtureReady,
# endpoint}. Reset out: {resetOk,baselineOk,fixtureName}.
function New-StoreDefaultStoreClient {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$RunContextLookup,
        [Parameter(Mandatory)]
        [string]$FixtureRoot,
        [ValidateRange(1000, 120000)]
        [int]$TimeoutMs = 10000
    )
    if ([string]::IsNullOrWhiteSpace($FixtureRoot)) {
        throw [System.ArgumentException]::new('STORE-INVALID-FIXTURE: fixture root is empty.')
    }
    $fixtureFull = [System.IO.Path]::GetFullPath($FixtureRoot)
    $lookup = $RunContextLookup
    $timeout = $TimeoutMs
    $schemaQuery = $Script:StoreReadSchemaMeta
    $expectedMajor = ([string]$Script:StoreVersion).Split('.')[0]
    # The namespace/database this run won its exclusive create with, keyed by
    # the run identity that won it. This is the ownership record that separates
    # "this run created it" from "it was already here", and it is the only
    # thing that makes a second interaction of the SAME run (handshake, then
    # fixture bootstrap) a recognized re-entry instead of a foreign adoption.
    $namespaceOwners = @{}
    $interact = {
        param($Context)
        if ($null -eq $Context -or $Context -isnot [hashtable] -or -not $Context.ContainsKey('runId')) {
            throw [System.ArgumentException]::new('STORE-CLIENT-FAILED: store client context needs a runId.')
        }
        $runId = [string]$Context['runId']
        if ($runId -cnotmatch '^[0-9a-f]{32}$') {
            throw [System.ArgumentException]::new('STORE-INVALID-BINDING: client runId must be 32 lowercase hex.')
        }
        $isReset = ($Context.ContainsKey('fixtureName') -and $null -ne $Context['fixtureName'])
        $vault = (& $lookup $runId)
        if ($null -eq $vault -or $vault -isnot [hashtable]) {
            throw [System.InvalidOperationException]::new('STORE-MISSING-CREDENTIAL: no bound run context carries the ephemeral credential.')
        }
        foreach ($field in @('user', 'pass', 'endpoint', 'namespace', 'database')) {
            if (-not $vault.ContainsKey($field) -or [string]::IsNullOrWhiteSpace([string]$vault[$field])) {
                throw [System.InvalidOperationException]::new("STORE-MISSING-CREDENTIAL: bound run context is missing '$field'.")
            }
        }
        $parsed = Test-StoreLoopbackEndpoint -Endpoint ([string]$vault['endpoint'])
        $namespace = [string]$vault['namespace']
        $database = [string]$vault['database']
        if ($namespace -cnotmatch '^[A-Za-z0-9_]{1,64}$' -or $database -cnotmatch '^[A-Za-z0-9_]{1,64}$') {
            throw [System.InvalidOperationException]::new('STORE-RECEIPT-FOREIGN: bound namespace/database has an invalid shape.')
        }
        $base = ('http://{0}:{1}' -f [string]$parsed['host'], [int]$parsed['port'])
        $pair = ('{0}:{1}' -f [string]$vault['user'], [string]$vault['pass'])
        $basic = 'Basic ' + [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($pair))
        $client = [System.Net.Http.HttpClient]::new()
        $client.Timeout = [System.TimeSpan]::FromMilliseconds($timeout)
        try {
            $versionText = ''
            try {
                $versionText = $client.GetStringAsync($base + '/version').GetAwaiter().GetResult()
            } catch {
                throw [System.InvalidOperationException]::new("STORE-PROTOCOL-FAILED: version handshake failed: $($_.Exception.Message)")
            }
            $major = ''
            if ($versionText -match '(\d+)\.') { $major = $Matches[1] }
            if ($major -cne $expectedMajor) {
                throw [System.InvalidOperationException]::new("STORE-VERSION-MISMATCH: live server major '$major' is not '$expectedMajor'.")
            }
            $usePrefix = ('USE NS {0} DB {1};' -f $namespace, $database)
            $defineNamespace = ('DEFINE NAMESPACE {0};' -f $namespace)
            $defineDatabase = ('DEFINE DATABASE {0};' -f $database)
            $sendSql = {
                param($Body)
                $content = [System.Net.Http.StringContent]::new($Body, [System.Text.Encoding]::UTF8, 'text/plain')
                $message = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::Post, $base + '/sql')
                $message.Headers.Add('Authorization', $basic)
                $message.Content = $content
                try {
                    $response = $client.SendAsync($message).GetAwaiter().GetResult()
                    try {
                        $code = [int]$response.StatusCode
                        if ($code -eq 401 -or $code -eq 403) {
                            throw [System.InvalidOperationException]::new('STORE-AUTH-FAILED: server refused the ephemeral credential.')
                        }
                        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
                        if ($code -lt 200 -or $code -ge 300) {
                            throw [System.InvalidOperationException]::new("STORE-PROTOCOL-FAILED: server returned status '$code'.")
                        }
                        if ($null -ne $body -and $body.Length -gt 1048576) {
                            throw [System.InvalidOperationException]::new('STORE-PROTOCOL-FAILED: server response exceeds the byte bound.')
                        }
                        return [string]$body
                    } finally {
                        $response.Dispose()
                    }
                } catch {
                    if ($_.Exception.Message -match '^STORE-[A-Z0-9-]+:') { throw }
                    throw [System.InvalidOperationException]::new("STORE-PROTOCOL-FAILED: store exchange failed: $($_.Exception.Message)")
                } finally {
                    $message.Dispose()
                    $content.Dispose()
                }
            }
            # Create the allocated namespace/database on this run's own reserved endpoint
            # under this run's own ephemeral root credential. The bare DEFINE
            # forms are the atomic exclusive create: the server REFUSES the
            # statement when the name already exists, so exactly one run can win
            # it. `USE NS x DB y` cannot do this job -- in SurrealDB 3.x regular
            # mode it creates a missing namespace or database and silently
            # adopts an existing one, so a run would proceed on whatever was
            # already there under that name. Whether a refusal is this run's own
            # create seen again on a later step, or a name this run never won, is
            # decided by the ownership record alone and never by the wording of
            # the server's error: unproven ownership is refused, not adopted.
            # Re-entry is recognized per NAME, never as one claim covering both.
            # A single blanket flag would let winning the namespace vouch for a
            # database this run never created, so a name whose own exclusive
            # create is still unproven stays unproven and is refused.
            $holdsNamespace = $false
            $holdsDatabase = $false
            if ($namespaceOwners.ContainsKey($runId)) {
                $held = $namespaceOwners[$runId]
                $heldNamespace = [string]$held['namespace']
                $heldDatabase = [string]$held['database']
                if (($heldNamespace.Length -gt 0 -and $heldNamespace -cne $namespace) -or
                    ($heldDatabase.Length -gt 0 -and $heldDatabase -cne $database)) {
                    throw [System.InvalidOperationException]::new('STORE-NAMESPACE-FOREIGN: this run already owns a different namespace/database than the one presented.')
                }
                $holdsNamespace = ($heldNamespace -ceq $namespace)
                $holdsDatabase = ($heldDatabase -ceq $database)
            }
            $defineNamespaceBody = (& $sendSql $defineNamespace)
            if ($defineNamespaceBody -match '"status"\s*:\s*"ERR"') {
                if (-not $holdsNamespace) {
                    throw [System.InvalidOperationException]::new('STORE-NAMESPACE-FOREIGN: the namespace was not created by this run''s exclusive create.')
                }
            } else {
                # The record is written for the namespace ONLY, at the moment its
                # own exclusive create won. The database stays unclaimed until its
                # own create wins it, so a refused database define can never be
                # mistaken for this run's own create seen again.
                $namespaceOwners[$runId] = @{ namespace = $namespace; database = '' }
            }
            $selectNamespaceBody = (& $sendSql ('USE NS {0};' -f $namespace))
            if ($selectNamespaceBody -match '"status"\s*:\s*"ERR"') {
                throw [System.InvalidOperationException]::new('STORE-NAMESPACE-FAILED: the namespace could not be selected after its exclusive create.')
            }
            $defineDatabaseBody = (& $sendSql $defineDatabase)
            if ($defineDatabaseBody -match '"status"\s*:\s*"ERR"') {
                if (-not $holdsDatabase) {
                    throw [System.InvalidOperationException]::new('STORE-NAMESPACE-FOREIGN: the database was not created by this run''s exclusive create.')
                }
            } else {
                $namespaceOwners[$runId] = @{ namespace = $namespace; database = $database }
            }
            $useBody = (& $sendSql $usePrefix)
            if ($useBody -match '"status"\s*:\s*"ERR"') {
                throw [System.InvalidOperationException]::new('STORE-AUTH-FAILED: namespace/database selection was refused.')
            }
            if ($isReset) {
                $fixtureName = [string]$Context['fixtureName']
                if ($fixtureName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
                    throw [System.ArgumentException]::new('STORE-INVALID-FIXTURE: fixture name has an invalid shape.')
                }
                if (-not $Context.ContainsKey('baselineDigest') -or [string]::IsNullOrWhiteSpace([string]$Context['baselineDigest'])) {
                    throw [System.ArgumentException]::new('STORE-INVALID-FIXTURE: reset needs a baseline digest.')
                }
                [void](Test-StoreDigestFormat -Digest ([string]$Context['baselineDigest']))
                $fixturePath = [System.IO.Path]::GetFullPath((Join-Path $fixtureFull ($fixtureName + '.surql')))
                $fixturePrefix = $fixtureFull.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
                if ($fixturePath -ine $fixtureFull -and -not $fixturePath.StartsWith($fixturePrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw [System.InvalidOperationException]::new("STORE-PATH-ESCAPE: fixture path escapes the fixture root: $fixturePath")
                }
                if (-not (Test-Path -LiteralPath $fixturePath -PathType Leaf)) {
                    throw [System.InvalidOperationException]::new("STORE-FIXTURE-UNKNOWN: fixture is absent: $fixtureName")
                }
                $fixtureInfo = Get-Item -LiteralPath $fixturePath -Force -ErrorAction Stop
                if ($fixtureInfo.Length -gt 1048576) {
                    throw [System.InvalidOperationException]::new("STORE-FIXTURE-BOUND: fixture exceeds the byte bound: $fixtureName")
                }
                $fixtureSql = [System.IO.File]::ReadAllText($fixturePath)
                $applyBody = (& $sendSql ($usePrefix + "`n" + $fixtureSql))
                $resetOk = ($applyBody -cnotmatch '"status"\s*:\s*"ERR"')
                $schemaBody = (& $sendSql ($usePrefix + ' ' + $schemaQuery))
                $schemaBytes = [System.Text.Encoding]::UTF8.GetBytes($schemaBody)
                $schemaHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($schemaBytes)
                $observedDigest = ([System.BitConverter]::ToString($schemaHash)).Replace('-', '').ToLowerInvariant()
                return @{
                    resetOk      = [bool]$resetOk
                    baselineOk   = ($observedDigest -ceq [string]$Context['baselineDigest'])
                    fixtureName  = $fixtureName
                }
            }
            $schemaBody = (& $sendSql ($usePrefix + ' ' + $schemaQuery))
            if ($schemaBody -match '"status"\s*:\s*"ERR"') {
                throw [System.InvalidOperationException]::new('STORE-SCHEMA-FAILED: schema observation was refused.')
            }
            $schemaBytes = [System.Text.Encoding]::UTF8.GetBytes($schemaBody)
            $schemaHash = [System.Security.Cryptography.SHA256]::Create().ComputeHash($schemaBytes)
            $observedDigest = ([System.BitConverter]::ToString($schemaHash)).Replace('-', '').ToLowerInvariant()
            return @{
                authenticated = $true
                namespace     = $namespace
                database      = $database
                schemaDigest  = $observedDigest
                fixtureReady  = $false
                endpoint      = [string]$vault['endpoint']
            }
        } finally {
            $client.Dispose()
        }
    }
    return $interact.GetNewClosure()
}

# Real process controller: bounded graceful phase, then exact-owned-tree
# forced termination after immediate image/start-identity revalidation.
# In: {phase,pid,runId,ownedTree}.
function New-StoreDefaultProcessController {
    [CmdletBinding()]
    [OutputType([scriptblock])]
    param(
        [ValidateRange(1000, 60000)]
        [int]$GracefulTimeoutMs = 10000,
        [ValidateRange(1000, 60000)]
        [int]$ForcedTimeoutMs = 5000
    )
    $gracefulMs = $GracefulTimeoutMs
    $forcedMs = $ForcedTimeoutMs
    $control = {
        param($Context)
        if ($null -eq $Context -or $Context -isnot [hashtable]) {
            throw [System.ArgumentException]::new('STORE-CONTROLLER-FAILED: controller context must be a hashtable.')
        }
        if (-not $Context.ContainsKey('phase') -or -not $Context.ContainsKey('pid')) {
            throw [System.ArgumentException]::new('STORE-CONTROLLER-FAILED: controller context needs phase and pid.')
        }
        $phase = [string]$Context['phase']
        $pid = 0
        try { $pid = [int]$Context['pid'] } catch {
            throw [System.InvalidOperationException]::new('STORE-CONTROLLER-FAILED: controller pid is not an integer.')
        }
        if ($pid -le 0) {
            throw [System.ArgumentException]::new('STORE-INVALID-PID: controller pid is not positive.')
        }
        if ($phase -cne 'graceful' -and $phase -cne 'forced') {
            throw [System.ArgumentException]::new("STORE-CONTROLLER-FAILED: unknown controller phase '$phase'.")
        }
        if (-not $Context.ContainsKey('ownedTree') -or $null -eq $Context['ownedTree']) {
            throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: controller received no identity-bearing owned tree.')
        }
        $targets = @()
        foreach ($candidate in @($Context['ownedTree'])) {
            if ($null -eq $candidate -or $candidate -isnot [hashtable] -or
                -not $candidate.ContainsKey('pid') -or -not $candidate.ContainsKey('imagePath') -or -not $candidate.ContainsKey('startTimeUtc')) {
                throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: every controller target needs an image and start identity.')
            }
            $candidatePid = 0
            try { $candidatePid = [int]$candidate['pid'] } catch { $candidatePid = 0 }
            if ($candidatePid -le 0 -or [string]::IsNullOrWhiteSpace([string]$candidate['imagePath']) -or
                [string]::IsNullOrWhiteSpace([string]$candidate['startTimeUtc'])) {
                throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: controller target identity is incomplete.')
            }
            $targets += @{
                pid          = $candidatePid
                imagePath    = [string]$candidate['imagePath']
                startTimeUtc = [string]$candidate['startTimeUtc']
            }
        }
        $rootIdentity = @($targets | Where-Object { [int]$_['pid'] -eq $pid } | Select-Object -First 1)
        if ($rootIdentity.Count -eq 0) {
            throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: controller tree does not carry the owned root identity.')
        }
        $rootIdentity = $rootIdentity[0]
        if ($phase -ceq 'graceful') {
            $proc = $null
            try { $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue } catch { $proc = $null }
            if ($null -eq $proc) {
                return @{ exited = $true; pid = $pid }
            }
            $currentIdentity = Get-StoreProcessIdentity -Process $proc
            [void](Test-StoreProcessOwnership -Pid $pid -ExpectedImagePath ([string]$rootIdentity['imagePath']) `
                -ExpectedStartTimeUtc ([string]$rootIdentity['startTimeUtc']) -Observation $currentIdentity)
            try { [void]$proc.CloseMainWindow() } catch { }
            $deadline = [System.DateTime]::UtcNow.AddMilliseconds($gracefulMs)
            while ([System.DateTime]::UtcNow -lt $deadline) {
                $live = $null
                try { $live = Get-Process -Id $pid -ErrorAction SilentlyContinue } catch { $live = $null }
                if ($null -eq $live) {
                    return @{ exited = $true; pid = $pid }
                }
                $liveIdentity = Get-StoreProcessIdentity -Process $live
                [void](Test-StoreProcessOwnership -Pid $pid -ExpectedImagePath ([string]$rootIdentity['imagePath']) `
                    -ExpectedStartTimeUtc ([string]$rootIdentity['startTimeUtc']) -Observation $liveIdentity)
                try {
                    if ($live.HasExited) { return @{ exited = $true; pid = $pid } }
                } catch {
                    throw [System.InvalidOperationException]::new('STORE-PROCESS-IDENTITY-UNPROVEN: root liveness could not be read during graceful stop.')
                }
                Start-Sleep -Milliseconds 100
            }
            $still = $null
            try { $still = Get-Process -Id $pid -ErrorAction SilentlyContinue } catch { $still = $null }
            if ($null -eq $still) {
                return @{ exited = $true; pid = $pid }
            }
            $stillIdentity = Get-StoreProcessIdentity -Process $still
            [void](Test-StoreProcessOwnership -Pid $pid -ExpectedImagePath ([string]$rootIdentity['imagePath']) `
                -ExpectedStartTimeUtc ([string]$rootIdentity['startTimeUtc']) -Observation $stillIdentity)
            return @{ exited = $false; pid = $pid }
        }
        if (-not $Context.ContainsKey('treeComplete') -or -not [bool]$Context['treeComplete']) {
            throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: forced termination refused because the owned descendant closure is incomplete.')
        }
        if (-not $Context.ContainsKey('rootObservedLive') -or $Context['rootObservedLive'] -isnot [bool]) {
            throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: forced termination has no post-grace root liveness proof.')
        }
        $rootObservedLive = [bool]$Context['rootObservedLive']
        $signalled = New-Object Collections.Generic.List[int]
        $pendingHandles = New-Object Collections.Generic.List[hashtable]
        $nativeApi = Get-StoreNativeProcessApi
        $forcedDeadline = [System.DateTime]::UtcNow.AddMilliseconds($forcedMs)
        $orderedTargets = @($targets | Where-Object { [int]$_['pid'] -ne $pid })
        $orderedTargets += @($targets | Where-Object { [int]$_['pid'] -eq $pid } | Select-Object -First 1)
        try {
            foreach ($targetIdentity in $orderedTargets) {
                if ([System.DateTime]::UtcNow -ge $forcedDeadline) {
                    throw [System.InvalidOperationException]::new('lost-response: forced termination deadline elapsed before all owned targets were handled.')
                }
                $target = [int]$targetIdentity['pid']
                $pinned = Invoke-StoreNativeTerminateByIdentity -Pid $target `
                    -ExpectedImagePath ([string]$targetIdentity['imagePath']) `
                    -ExpectedStartTimeUtc ([string]$targetIdentity['startTimeUtc'])
                if ($target -eq $pid -and $rootObservedLive -and [bool]$pinned['exited']) {
                    throw [System.InvalidOperationException]::new('STORE-DESCENDANT-CLOSURE-INCOMPLETE: owned root exited after the post-grace descendant snapshot.')
                }
                if (-not [bool]$pinned['exited']) {
                    [void]$signalled.Add($target)
                    [void]$pendingHandles.Add($pinned)
                }
            }
            foreach ($pending in $pendingHandles) {
                $remainingMs = [int][System.Math]::Ceiling(($forcedDeadline - [System.DateTime]::UtcNow).TotalMilliseconds)
                if ($remainingMs -lt 0) { $remainingMs = 0 }
                $waitState = $nativeApi::WaitForSingleObject([System.IntPtr]$pending['handle'], [uint32]$remainingMs)
                if ($waitState -ne 0) {
                    throw [System.InvalidOperationException]::new("lost-response: termination of owned pid '$([int]$pending['pid'])' was not confirmed by its pinned process handle.")
                }
            }
            return @{ exited = $true; pid = $pid; terminatedPids = @($signalled) }
        } finally {
            foreach ($pending in $pendingHandles) {
                [void]$nativeApi::CloseHandle([System.IntPtr]$pending['handle'])
            }
        }
    }
    return $control.GetNewClosure()
}

# Default 9-operation provider table: every closed operation routes to the
# real Invoke-Store* implementation with default real seams (callers may
# inject fakes per seam). The approved binary selection stays explicit:
# without -Acquisition, Start fails closed with STORE-MISSING-ACQUISITION.
function New-StoreProviderOperationTable {
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$BaseTemp,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Entropy,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$PortReservation,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Acquisition,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Launcher,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$ProcessObserver,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$PortObserver,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$StoreClient,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$ProcessController,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$FileSystem,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Acl,
        [Parameter()]
        [AllowNull()]
        [hashtable]$AmbientEnvironment,
        [Parameter()]
        [AllowNull()]
        [scriptblock]$Clock,
        [Parameter()]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$FixtureRoot
    )
    $tableBase = $BaseTemp
    if ([string]::IsNullOrWhiteSpace($tableBase)) {
        $tableBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    }
    $tableEntropy = $Entropy
    $tableReservation = $PortReservation
    if ($null -eq $tableReservation) {
        $tableReservation = New-StoreDefaultPortReservation
    }
    $tableAcquisition = $Acquisition
    if ($null -eq $tableAcquisition) {
        $tableAcquisition = {
            param($Context)
            throw [System.ArgumentException]::new('STORE-MISSING-ACQUISITION: no explicit approved-binary selection is bound; pass -Acquisition from an explicit tool input.')
        }.GetNewClosure()
    }
    $tableObserver = $ProcessObserver
    if ($null -eq $tableObserver) {
        $tableObserver = New-StoreDefaultProcessObserver
    }
    $tablePortObserver = $PortObserver
    if ($null -eq $tablePortObserver) {
        $tablePortObserver = New-StoreDefaultPortObserver
    }
    $tableController = $ProcessController
    if ($null -eq $tableController) {
        $tableController = New-StoreDefaultProcessController
    }
    $tableFs = $FileSystem
    if ($null -eq $tableFs) {
        $tableFs = New-StoreDefaultFileSystem
    }
    $tableAcl = $Acl
    if ($null -eq $tableAcl) {
        $tableAcl = New-StoreDefaultAcl
    }
    $tableAmbient = $AmbientEnvironment
    $tableClock = $Clock
    $vault = @{}
    $capture = {
        param($VaultRunId, $VaultUser, $VaultPass, $VaultEndpoint, $VaultNamespace, $VaultDatabase)
        $vault[$VaultRunId] = @{
            user      = $VaultUser
            pass      = $VaultPass
            endpoint  = $VaultEndpoint
            namespace = $VaultNamespace
            database  = $VaultDatabase
        }
    }.GetNewClosure()
    $tableLauncher = $Launcher
    if ($null -eq $tableLauncher) {
        $tableLauncher = New-StoreDefaultLauncher -VaultCapture $capture
    }
    $fixtureRootResolved = $FixtureRoot
    if ([string]::IsNullOrWhiteSpace($fixtureRootResolved)) {
        $fixtureRootResolved = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\testdata\integration\store-provider\fixtures'))
    }
    $lookup = {
        param($LookupRunId)
        if ($vault.ContainsKey($LookupRunId)) { return $vault[$LookupRunId] }
        return $null
    }.GetNewClosure()
    $tableClient = $StoreClient
    if ($null -eq $tableClient) {
        $tableClient = New-StoreDefaultStoreClient -RunContextLookup $lookup -FixtureRoot $fixtureRootResolved
    }
    $table = @{
        ValidateRequirement = {
            param($Context)
            $binding = $Context['binding']
            $args = $Context['arguments']
            if ($null -eq $args) { $args = @{} }
            $requirement = $args['requirement']
            if ($null -eq $requirement) {
                $requirement = @{ testClass = [string]$binding['testClass']; providerRevision = [string]$binding['providerRevision'] }
            }
            if (-not $args.ContainsKey('lock') -or $null -eq $args['lock']) {
                throw [System.ArgumentException]::new('STORE-INVALID-LOCK: operation arguments carry no lock identity.')
            }
            return Invoke-StoreValidateRequirement -Binding $binding -Requirement $requirement -Lock $args['lock']
        }.GetNewClosure()
        Plan = {
            param($Context)
            $binding = $Context['binding']
            $args = $Context['arguments']
            if ($null -eq $args) { $args = @{} }
            $requirement = $args['requirement']
            if ($null -eq $requirement) {
                $requirement = @{ testClass = [string]$binding['testClass']; providerRevision = [string]$binding['providerRevision'] }
            }
            return Invoke-StorePlan -Binding $binding -Requirement $requirement
        }.GetNewClosure()
        Allocate = {
            param($Context)
            $binding = $Context['binding']
            $args = $Context['arguments']
            if ($null -eq $args -or -not $args.ContainsKey('plan') -or $null -eq $args['plan']) {
                throw [System.ArgumentException]::new('STORE-MISSING-PLAN: allocate arguments carry no plan.')
            }
            return Invoke-StoreAllocate -Binding $binding -Plan $args['plan'] -BaseTemp $tableBase -Entropy $tableEntropy -PortReservation $tableReservation -FileSystem $tableFs -Acl $tableAcl
        }.GetNewClosure()
        Start = {
            param($Context)
            $binding = $Context['binding']
            $args = $Context['arguments']
            if ($null -eq $args -or -not $args.ContainsKey('allocation') -or $null -eq $args['allocation']) {
                throw [System.ArgumentException]::new('STORE-MISSING-ALLOCATION: start arguments carry no allocation.')
            }
            return Invoke-StoreStart -Binding $binding -Allocation $args['allocation'] -Acquisition $tableAcquisition -Launcher $tableLauncher -Entropy $tableEntropy -FileSystem $tableFs -AmbientEnvironment $tableAmbient
        }.GetNewClosure()
        ObserveReadiness = {
            param($Context)
            $binding = $Context['binding']
            $args = $Context['arguments']
            if ($null -eq $args -or -not $args.ContainsKey('startReceipt') -or $null -eq $args['startReceipt']) {
                throw [System.ArgumentException]::new('STORE-MISSING-START-RECEIPT: observe arguments carry no start receipt.')
            }
            return Invoke-StoreObserveReadiness -Binding $binding -StartReceipt $args['startReceipt'] -ProcessObserver $tableObserver -PortObserver $tablePortObserver -StoreClient $tableClient -Clock $tableClock
        }.GetNewClosure()
        ResetForTest = {
            param($Context)
            $binding = $Context['binding']
            $args = $Context['arguments']
            if ($null -eq $args -or -not $args.ContainsKey('fixture') -or $null -eq $args['fixture']) {
                throw [System.ArgumentException]::new('STORE-MISSING-FIXTURE: reset arguments carry no fixture.')
            }
            if (-not $args.ContainsKey('readinessReceipt') -or $null -eq $args['readinessReceipt']) {
                throw [System.ArgumentException]::new('STORE-MISSING-READINESS: reset arguments carry no readiness receipt.')
            }
            return Invoke-StoreResetForTest -Binding $binding -Fixture $args['fixture'] -ReadinessReceipt $args['readinessReceipt'] -StoreClient $tableClient
        }.GetNewClosure()
        CollectEvidence = {
            param($Context)
            $binding = $Context['binding']
            $args = $Context['arguments']
            if ($null -eq $args) { $args = @{} }
            if (-not $args.ContainsKey('terminalState') -or [string]::IsNullOrWhiteSpace([string]$args['terminalState'])) {
                throw [System.ArgumentException]::new('STORE-INVALID-DISPOSITION: collect arguments carry no terminal state.')
            }
            $logText = ''
            if ($args.ContainsKey('logText') -and $null -ne $args['logText']) { $logText = [string]$args['logText'] }
            $secrets = @()
            if ($args.ContainsKey('secrets') -and $null -ne $args['secrets']) { $secrets = @($args['secrets']) }
            $maxBytes = 65536
            if ($args.ContainsKey('maxBytes') -and $null -ne $args['maxBytes']) {
                try { $maxBytes = [int]$args['maxBytes'] } catch { $maxBytes = 65536 }
            }
            return Invoke-StoreCollectEvidence -Binding $binding -TerminalState ([string]$args['terminalState']) -LogText $logText -Secrets $secrets -MaxBytes $maxBytes
        }.GetNewClosure()
        Stop = {
            param($Context)
            $binding = $Context['binding']
            $args = $Context['arguments']
            if ($null -eq $args -or -not $args.ContainsKey('startReceipt') -or $null -eq $args['startReceipt']) {
                throw [System.ArgumentException]::new('STORE-MISSING-START-RECEIPT: stop arguments carry no start receipt.')
            }
            $result = Invoke-StoreStop -Binding $binding -StartReceipt $args['startReceipt'] -ProcessController $tableController -Clock $tableClock -ProcessObserver $tableObserver -FileSystem $tableFs
            if ([string]$result['stopState'] -ceq 'OwnedResourcesStopped') {
                $receipt = $args['startReceipt']
                if ($null -ne $receipt['observed'] -and $receipt['observed'] -is [hashtable] -and $receipt['observed'].ContainsKey('jobName')) {
                    $jobName = [string]$receipt['observed']['jobName']
                    if (-not [string]::IsNullOrWhiteSpace($jobName) -and $jobName -cne 'inherited' -and
                        $Script:StoreJobHandles.ContainsKey($jobName)) {
                        $closed = $null
                        try { $closed = Close-StoreJobBinding -JobName $jobName } catch { $closed = @{ closed = $false; failure = $_.Exception.Message } }
                        if ($null -eq $closed -or -not [bool]$closed['closed']) {
                            $requested = $receipt['requested']
                            $detail = 'STORE-JOB-CLOSE-UNCONFIRMED: owned process job handle did not close.'
                            if ($null -ne $closed -and $closed.ContainsKey('failure')) { $detail += ' ' + [string]$closed['failure'] }
                            $result = New-StoreStopReconciliationResult -Binding $binding -Requested $requested `
                                -OwnedPid ([int]$receipt['observed']['pid']) -Forced ([bool]$result['forced']) `
                                -RunRoot ([string]$receipt['runRoot']) -FileSystem $tableFs -RunId ([string]$binding['runId']) -Detail $detail
                        }
                    }
                }
            }
            return $result
        }.GetNewClosure()
        VerifyCleanup = {
            param($Context)
            $binding = $Context['binding']
            $args = $Context['arguments']
            if ($null -eq $args -or -not $args.ContainsKey('allocation') -or $null -eq $args['allocation']) {
                throw [System.ArgumentException]::new('STORE-MISSING-ALLOCATION: verify arguments carry no allocation.')
            }
            if (-not $args.ContainsKey('startReceipt') -or $null -eq $args['startReceipt']) {
                throw [System.ArgumentException]::new('STORE-MISSING-START-RECEIPT: verify arguments carry no start receipt.')
            }
            $probe = $null
            if ($args.ContainsKey('fileProbe')) { $probe = $args['fileProbe'] }
            return Invoke-StoreVerifyCleanup -Binding $binding -Allocation $args['allocation'] -StartReceipt $args['startReceipt'] -ProcessObserver $tableObserver -PortObserver $tablePortObserver -FileProbe $probe -FileSystem $tableFs
        }.GetNewClosure()
    }
    return $table
}

Export-ModuleMember -Function @(
    'Get-StoreProviderIdentity',
    'Get-StoreLockIdentity',
    'Get-StoreClosedOperations',
    'Get-StoreTerminalDispositions',
    'Test-StoreDigestFormat',
    'Test-StoreClosedOperation',
    'Test-StoreTerminalDisposition',
    'Resolve-StoreDeadline',
    'Test-StoreBindingShape',
    'Test-StoreProviderResultClosed',
    'Invoke-StoreProviderOperation',
    'Invoke-StoreValidateRequirement',
    'Invoke-StorePlan',
    'Resolve-StoreOwnedPath',
    'Test-StoreOwnedRootClaim',
    'Get-StoreChildEnv',
    'New-StoreEphemeralCredential',
    'Test-StoreProviderReceipt',
    'Test-StoreRequiredReceiptSet',
    'Get-StoreRedactedText',
    'Invoke-StoreAllocate',
    'Invoke-StoreStart',
    'Invoke-StoreObserveReadiness',
    'Invoke-StoreResetForTest',
    'Invoke-StoreCollectEvidence',
    'Invoke-StoreStop',
    'Invoke-StoreVerifyCleanup',
    'Remove-StoreOwnedRoot',
    'New-StoreDefaultFileProbe',
    'Get-StoreAmbientEnvironment',
    'Test-StoreLoopbackEndpoint',
    'Read-StoreReconciliationRecord',
    'Test-StorePendingReconciliation',
    'Assert-StoreNoPendingReconciliation',
    'Write-StoreLostResponseRecord',
    'Resolve-StoreReconciliationRecord',
    'Test-StoreProcessOwnership',
    'Get-StoreOwnedDescendants',
    'Protect-StoreRootAcl',
    'New-StoreJobBinding',
    'Close-StoreJobBinding',
    'New-StoreDefaultFileSystem',
    'New-StoreDefaultAcl',
    'New-StoreDefaultPortReservation',
    'New-StoreDefaultAcquisition',
    'New-StoreDefaultLauncher',
    'New-StoreDefaultProcessObserver',
    'New-StoreDefaultPortObserver',
    'New-StoreDefaultStoreClient',
    'New-StoreDefaultProcessController',
    'New-StoreProviderOperationTable'
)
