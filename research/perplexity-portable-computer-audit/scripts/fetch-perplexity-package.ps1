[CmdletBinding()]
param(
    [string]$RawRoot = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads\perplexity-portable-computer-audit'),
    [ValidateSet('arm64','amd64')][string]$Architecture = 'arm64',
    [string]$Version = '26.8.4',
    [string]$PackageName = 'perplexity',
    [string]$ExpectedFingerprint = '',
    [string]$WslDistribution = 'Ubuntu',
    [switch]$AllowUnverifiedRepository,
    [switch]$SkipPackage
)

# This script only downloads public repository metadata and archives.  It never
# invokes apt/dpkg and never executes anything extracted from an archive.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$RepoBase = 'https://packages.perplexity.ai/deb'
$KeyUrl = 'https://packages.perplexity.ai/perplexity.gpg'
$Suite = 'stable'
$Component = 'main'
$ExpectedHost = ([uri]$RepoBase).Host

function Get-Sha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}
function Ensure-Directory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}
function Assert-Under([string]$Path, [string]$Root) {
    $p = [IO.Path]::GetFullPath($Path).TrimEnd('\') + '\'
    $r = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if (-not $p.StartsWith($r, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing path outside raw root: $Path"
    }
}
function Find-7Zip {
    $cmd = Get-Command 7z.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($candidate in @('C:\Program Files\7-Zip\7z.exe','C:\Program Files (x86)\7-Zip\7z.exe')) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    throw '7z.exe is required to unpack repository indexes and was not found.'
}
function Find-Application([string]$Name,[string[]]$Candidates) {
    foreach($candidate in $Candidates){if(Test-Path -LiteralPath $candidate -PathType Leaf){return $candidate}}
    $cmd=Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue|Select-Object -First 1
    if($cmd){return $cmd.Source}
    return $null
}
function Convert-ToWslPath([string]$Path) {
    $full=[IO.Path]::GetFullPath($Path)
    if($full -notmatch '^([A-Za-z]):\\(.*)$'){throw "Cannot convert path to WSL form: $full"}
    return "/mnt/$($Matches[1].ToLowerInvariant())/$($Matches[2].Replace('\','/'))"
}
function Invoke-CurlDownload([string]$Url, [string]$Destination, [string]$Kind) {
    Assert-Under $Destination $RawRoot
    Ensure-Directory (Split-Path -Parent $Destination)
    $metaPath = "$Destination.curl.json"
    $stderrPath = "$Destination.curl.stderr.log"
    $format = '{"http_code":"%{http_code}","url_effective":"%{url_effective}","content_type":"%{content_type}","size_download":"%{size_download}"}'
    $args = @('-fL','--retry','3','--retry-all-errors','--connect-timeout','20','--max-time','120','--silent','--show-error','-o',$Destination,'-w',$format,$Url)
    $json = (& curl.exe @args 2> $stderrPath | Out-String).Trim()
    $exit = $LASTEXITCODE
    if ($exit -ne 0) { throw "curl failed for $Kind (exit $exit): $((Get-Content -Raw -LiteralPath $stderrPath).Trim())" }
    $m = $json | ConvertFrom-Json
    $uri = [uri]$m.url_effective
    if ($uri.Host -ne $ExpectedHost -and -not $uri.Host.EndsWith('.perplexity.ai',[StringComparison]::OrdinalIgnoreCase)) {
        throw "Unexpected redirect host for ${Kind}: $($uri.Host)"
    }
    $item = [ordered]@{ kind=$Kind; source_url=$Url; final_url=$m.url_effective; http_status=[int]$m.http_code; content_type=$m.content_type; size=[int64](Get-Item -LiteralPath $Destination).Length; sha256=(Get-Sha256 $Destination); curl_exit_code=$exit }
    $item | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $metaPath -Encoding UTF8
    return [pscustomobject]$item
}
function Invoke-CurlHeadProbe([string]$Url, [string]$HeadersPath, [string]$Kind) {
    Assert-Under $HeadersPath $RawRoot
    Ensure-Directory (Split-Path -Parent $HeadersPath)
    $format = '{"http_code":"%{http_code}","url_effective":"%{url_effective}","content_type":"%{content_type}","num_redirects":"%{num_redirects}"}'
    $args = @('-sS','-L','-I','--retry','3','--retry-all-errors','--connect-timeout','20','--max-time','120','-o',$HeadersPath,'-w',$format,$Url)
    $json = (& curl.exe @args 2>&1 | Out-String).Trim()
    $exit = $LASTEXITCODE
    $meta = $null
    if ($exit -eq 0) {
        try { $meta = $json | ConvertFrom-Json } catch { $meta = $null }
    }
    $finalUrl = if ($meta) { [string]$meta.url_effective } else { $null }
    if ($finalUrl) {
        $uri = [uri]$finalUrl
        if ($uri.Host -ne $ExpectedHost -and -not $uri.Host.EndsWith('.perplexity.ai',[StringComparison]::OrdinalIgnoreCase)) {
            throw "Unexpected redirect host for ${Kind}: $($uri.Host)"
        }
    }
    return [pscustomobject][ordered]@{
        kind = $Kind
        request_url = $Url
        final_url = $finalUrl
        http_status = if ($meta) { [int]$meta.http_code } else { $null }
        content_type = if ($meta) { [string]$meta.content_type } else { $null }
        redirects = if ($meta) { [int]$meta.num_redirects } else { $null }
        curl_exit_code = $exit
        headers_path = $HeadersPath
        error = if ($exit -ne 0 -or -not $meta) { $json } else { $null }
    }
}
function Parse-Paragraphs([string]$Text) {
    $result = @(); $current = [ordered]@{}; $last = $null; $raw = @()
    foreach ($line in ($Text -split "`r?`n")) {
        if ([string]::IsNullOrWhiteSpace($line)) { if ($current.Count) { $current['__raw'] = ($raw -join "`n"); $result += [pscustomobject]$current; $current=[ordered]@{}; $last=$null; $raw=@() }; continue }
        $raw += $line
        if ($line -match '^\s' -and $last) { $current[$last] = "$($current[$last])`n$($line.Trim())"; continue }
        if ($line -match '^([^:]+):\s?(.*)$') { $last=$Matches[1]; $current[$last]=$Matches[2] }
    }
    if ($current.Count) { $current['__raw'] = ($raw -join "`n"); $result += [pscustomobject]$current }
    return $result
}
function Get-ReleaseHash([string]$ReleaseText, [string]$RelativePath) {
    $needle = $RelativePath.Replace('\','/')
    foreach ($line in ($ReleaseText -split "`r?`n")) {
        if ($line -match '^\s*([0-9a-fA-F]{64})\s+(\d+)\s+(.+)$' -and $Matches[3].Trim() -eq $needle) {
            return [pscustomobject]@{ sha256=$Matches[1].ToLowerInvariant(); size=[int64]$Matches[2]; path=$needle }
        }
    }
    return $null
}
function Get-Field([object]$Object, [string]$Name) {
    $p = $Object.PSObject.Properties[$Name]; if ($p) { return [string]$p.Value }; return $null
}
function Write-Provenance([object[]]$Items, [hashtable]$Extra) {
    $payload = [ordered]@{ generated_utc=(Get-Date).ToUniversalTime().ToString('o'); raw_root=$RawRoot; repository=$RepoBase; files=$Items; details=$Extra }
    $payload | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $ReportRoot 'repository-provenance.json') -Encoding UTF8
}

$RawRoot = [IO.Path]::GetFullPath($RawRoot)
$ReportRoot = Join-Path $RawRoot '99-generated-reports'
foreach ($d in @('00-repository','01-downloads','02-deb-outer','03-control','04-rootfs','05-source-package','06-binary-analysis','07-search-results','99-generated-reports')) { Ensure-Directory (Join-Path $RawRoot $d) }
Ensure-Directory $ReportRoot
$repoDir = Join-Path $RawRoot '00-repository'; $downloadDir = Join-Path $RawRoot '01-downloads'; $indexDir = Join-Path $RawRoot '00-repository\indexes'
Ensure-Directory $indexDir
$items = @(); $signatureStatus = 'SIGNATURE_TOOL_UNAVAILABLE'; $signerIdentityStatus = 'UNKNOWN'

$downloadErrors = @()
try { $items += Invoke-CurlDownload $KeyUrl (Join-Path $repoDir 'perplexity.gpg') 'repository-key' } catch { $downloadErrors += "repository-key: $($_.Exception.Message)" }
foreach ($name in @('InRelease','Release','Release.gpg')) {
    try { $items += Invoke-CurlDownload "$RepoBase/dists/$Suite/$name" (Join-Path $repoDir $name) "release-$name" }
    catch { $downloadErrors += "release-${name}: $($_.Exception.Message)"; if ($name -eq 'Release') { throw } }
}
$gpg = Find-Application 'gpg.exe' @('C:\Program Files\Git\usr\bin\gpg.exe','C:\Program Files\GnuPG\bin\gpg.exe','C:\Program Files (x86)\GnuPG\bin\gpg.exe')
$gpgv = Find-Application 'gpgv.exe' @('C:\Program Files\Git\usr\bin\gpgv.exe','C:\Program Files\GnuPG\bin\gpgv.exe','C:\Program Files (x86)\GnuPG\bin\gpgv.exe')
$wsl = Find-Application 'wsl.exe' @('C:\Windows\System32\wsl.exe')
$key = Join-Path $repoDir 'perplexity.gpg'
if ($gpg) {
    & $gpg --batch --show-keys --with-fingerprint $key 2>&1 | Set-Content -LiteralPath (Join-Path $repoDir 'gpg-show-keys.txt') -Encoding UTF8
}
$releasePath = Join-Path $repoDir 'Release'; $inReleasePath = Join-Path $repoDir 'InRelease'; $releaseText = Get-Content -Raw -LiteralPath $releasePath
$sigOut = @(); $sigExit = $null
if ($wsl -and (Test-Path -LiteralPath $inReleasePath)) {
    $wslKey=Convert-ToWslPath $key
    $wslInRelease=Convert-ToWslPath $inReleasePath
    $sigOut=@(& $wsl -d $WslDistribution -- gpgv --keyring $wslKey $wslInRelease 2>&1);$sigExit=$LASTEXITCODE
}
if (($null -eq $sigExit -or $sigExit -ne 0) -and $gpgv) {
    $portableKey = $key.Replace('\','/')
    if (Test-Path -LiteralPath $inReleasePath) { $sigOut += (& $gpgv --keyring $portableKey $inReleasePath 2>&1); $sigExit=$LASTEXITCODE }
    if ($sigExit -ne 0 -and (Test-Path -LiteralPath (Join-Path $repoDir 'Release.gpg'))) { $sigOut += (& $gpgv --keyring $portableKey (Join-Path $repoDir 'Release.gpg') $releasePath 2>&1); $sigExit=$LASTEXITCODE }
}
if (($null -eq $sigExit -or $sigExit -ne 0) -and $gpg) {
    if ($sigOut.Count) { $sigOut | Set-Content -LiteralPath (Join-Path $repoDir 'gpgv-attempt.txt') -Encoding UTF8 }
    $gpgHome = Join-Path $repoDir ("gpg-home-" + [Guid]::NewGuid().ToString('N'))
    Ensure-Directory $gpgHome
    $importOut = @(& $gpg --homedir $gpgHome --batch --import $key 2>&1); $importExit=$LASTEXITCODE
    $verifyOut = @()
    if ($importExit -eq 0 -and (Test-Path -LiteralPath $inReleasePath)) { $verifyOut = @(& $gpg --homedir $gpgHome --batch --status-fd 1 --verify $inReleasePath 2>&1); $sigExit=$LASTEXITCODE }
    $sigOut = @($importOut) + @($verifyOut)
}
if ($sigOut.Count) { $sigOut | Set-Content -LiteralPath (Join-Path $repoDir 'gpg-verification.txt') -Encoding UTF8 }
if ($null -ne $sigExit) {
    if ($sigExit -eq 0) {
        $fingerprint = if (($sigOut -join "`n") -match '(?i)(?:VALIDSIG|using (?:RSA )?key)\s+([0-9A-F]{40})') { $Matches[1].ToUpperInvariant() } else { '' }
        if ($ExpectedFingerprint) {
            $expected = ($ExpectedFingerprint -replace '\s','').ToUpperInvariant()
            if ($fingerprint -ne $expected) { throw "Repository signer fingerprint mismatch. Expected $expected; got $fingerprint." }
            $signatureStatus = 'VERIFIED'
            $signerIdentityStatus = 'PINNED_FINGERPRINT_MATCH'
        } else {
            $signatureStatus = 'VERIFIED'
            $signerIdentityStatus = 'UNPINNED_SAME_ORIGIN_KEY'
        }
    } else { $signatureStatus = 'SIGNATURE_INVALID' }
    if ($signatureStatus -eq 'SIGNATURE_INVALID') { throw 'Repository signature verification failed; package download stopped.' }
}
if ($signatureStatus -eq 'SIGNATURE_TOOL_UNAVAILABLE' -and -not $AllowUnverifiedRepository) { throw 'No usable isolated OpenPGP verifier was found; package download stopped.' }
$architectures = @(); if ($releaseText -match '(?m)^Architectures:\s*(.+)$') { $architectures = $Matches[1].Trim() -split '\s+' }
$components = @(); if ($releaseText -match '(?m)^Components:\s*(.+)$') { $components = $Matches[1].Trim() -split '\s+' }
if (-not $architectures) { $architectures = @('arm64','amd64') }
if ($architectures -notcontains $Architecture) { throw "Requested architecture $Architecture is not declared by Release." }
$chosenIndex = @{}; $packageStanzas = @()
$sevenZip = Find-7Zip
foreach ($arch in $architectures) {
    foreach ($ext in @('xz','gz','zst','')) {
        # Release hash paths are relative to dists/<suite>, e.g. main/binary-arm64/Packages.xz.
        $rel = "$Component/binary-$arch/Packages$([string]::IsNullOrEmpty($ext) ? '' : ".$ext")"
        $rh = Get-ReleaseHash $releaseText $rel
        if (-not $rh) { continue }
        $dest = Join-Path $indexDir ("Packages-$arch" + $(if ($ext) { ".$ext" } else { '' }))
        try { $item = Invoke-CurlDownload "$RepoBase/dists/$Suite/$rel" $dest "packages-$arch$([string]::IsNullOrEmpty($ext) ? '' : ".$ext")" } catch { continue }
        if ($rh -and (($item.sha256 -ne $rh.sha256) -or ($item.size -ne $rh.size))) { throw "Packages index hash/size mismatch: $rel" }
        $items += $item; $chosenIndex[$arch] = $dest
        $extractDir = Join-Path $indexDir "unpacked-$arch"; Ensure-Directory $extractDir
        & $sevenZip x $dest "-o$extractDir" '-y' | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "7-Zip failed to unpack $dest (exit $LASTEXITCODE)." }
        $plain = Join-Path $extractDir 'Packages'; if (-not (Test-Path -LiteralPath $plain)) { $plain = Get-ChildItem -LiteralPath $extractDir -File | Select-Object -First 1 -ExpandProperty FullName }
        $text = Get-Content -Raw -LiteralPath $plain
        foreach ($stanza in (Parse-Paragraphs $text)) { if ((Get-Field $stanza 'Package') -eq $PackageName) { $packageStanzas += $stanza } }
        break
    }
}
if (-not $packageStanzas) { throw "No active $PackageName stanza found in downloaded Packages indexes." }
$allStanzas = Join-Path $repoDir 'perplexity-package-stanzas.txt'
($packageStanzas | ForEach-Object { $_.PSObject.Properties['__raw'].Value; ''; }) | Set-Content -LiteralPath $allStanzas -Encoding UTF8
$selected = $packageStanzas | Where-Object { (Get-Field $_ 'Architecture') -eq $Architecture -and ((-not $Version) -or (Get-Field $_ 'Version') -eq $Version) } | Select-Object -First 1
if (-not $selected) { throw "Requested package/version/architecture not found: $PackageName $Version $Architecture" }
$filename = (Get-Field $selected 'Filename').Trim(); if (-not $filename -or $filename.StartsWith('/') -or $filename.Contains('..')) { throw 'Unsafe Filename field in Packages stanza.' }
$packageUrl = "$RepoBase/$filename"
$fileName = Split-Path -Leaf $filename; $packagePath = Join-Path $downloadDir $fileName
$expectedSize = [int64](Get-Field $selected 'Size'); $expectedHash = (Get-Field $selected 'SHA256').ToLowerInvariant()
$packageItem = $null
if (-not $SkipPackage) {
    try { $packageItem = Invoke-CurlDownload $packageUrl $packagePath 'deb-package' } catch {
        if ($packageUrl.Contains('+')) {
            $encoded = $packageUrl.Replace('+','%2B')
            $packageItem = Invoke-CurlDownload $encoded $packagePath 'deb-package-encoded-plus'
        } else { throw }
    }
    if ($packageItem.size -ne $expectedSize -or $packageItem.sha256 -ne $expectedHash) { throw "Package size/hash mismatch. Expected $expectedSize/$expectedHash; got $($packageItem.size)/$($packageItem.sha256)." }
}
$packageRecord = [ordered]@{ package=$PackageName; version=(Get-Field $selected 'Version'); architecture=(Get-Field $selected 'Architecture'); filename=$filename; url=$packageUrl; final_url=$(if($packageItem){$packageItem.final_url}else{$null}); size=$expectedSize; sha256=$expectedHash; repository_signature_status=$signatureStatus; signer_identity_status=$signerIdentityStatus; downloaded_utc=$(if($packageItem){(Get-Date).ToUniversalTime().ToString('o')}else{$null}); packages_stanza_path=$allStanzas; package_download_skipped=[bool]$SkipPackage }
$packageRecord | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $repoDir 'package-provenance.json') -Encoding UTF8

# Check both signed Release entries and the standard source-index paths.  An
# unlisted HTTP 200 response is not trusted as signed repository metadata.
$sourceStatus = 'NO_PUBLIC_APT_SOURCE_INDEX'; $sourceStanza = $null; $listedSourcePathFound = $false
foreach ($ext in @('xz','gz','zst','')) {
    $rel = "$Component/source/Sources$([string]::IsNullOrEmpty($ext) ? '' : ".$ext")"; $rh=Get-ReleaseHash $releaseText $rel
    if (-not $rh) { continue }
    $listedSourcePathFound = $true
    $dest=Join-Path $indexDir ("Sources" + $(if ($ext) { ".$ext" } else { '' }))
    try { $si=Invoke-CurlDownload "$RepoBase/dists/$Suite/$rel" $dest 'source-index' } catch { continue }
    if ($rh -and ($rh.sha256 -ne $si.sha256 -or $rh.size -ne $si.size)) { throw "Sources index hash/size mismatch: $rel" }
    $sourceStatus='PUBLIC_SOURCE_INDEX_WITHOUT_PERPLEXITY'; $sd=Join-Path $indexDir 'unpacked-source'; Ensure-Directory $sd; & $sevenZip x $dest "-o$sd" '-y' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7-Zip failed to unpack source index (exit $LASTEXITCODE)." }
    $sp=Join-Path $sd 'Sources'; if (-not (Test-Path -LiteralPath $sp)) { $sp=Get-ChildItem -LiteralPath $sd -File | Select-Object -First 1 -ExpandProperty FullName }
    $sourceName=Get-Field $selected 'Source'; if ($sourceName) { $sourceName=($sourceName -split '\s+')[0] } else { $sourceName=$PackageName }
    $sourceStanza=(Parse-Paragraphs (Get-Content -Raw -LiteralPath $sp) | Where-Object { (Get-Field $_ 'Package') -eq $sourceName } | Select-Object -First 1)
    if ($sourceStanza) {
        $sourceStatus='PUBLIC_SOURCE_PACKAGE_FOUND'
        [string]$sourceStanza.PSObject.Properties['__raw'].Value | Set-Content -LiteralPath (Join-Path $repoDir 'source-stanza.txt') -Encoding UTF8
    }
    break
}
$sourceProbeRecords = @()
if (-not $listedSourcePathFound) {
    $sourceProbeDir = Join-Path $repoDir 'source-probes'; Ensure-Directory $sourceProbeDir
    foreach ($ext in @('xz','gz','zst','')) {
        $name = "Sources$([string]::IsNullOrEmpty($ext) ? '' : ".$ext")"
        $url = "$RepoBase/dists/$Suite/$Component/source/$name"
        $headersPath = Join-Path $sourceProbeDir "$name.headers.txt"
        $sourceProbeRecords += Invoke-CurlHeadProbe $url $headersPath "source-index-$name"
    }
    if (($sourceProbeRecords | Where-Object { $_.http_status -eq 200 }).Count -gt 0) {
        $sourceStatus = 'SOURCE_METADATA_INCOMPLETE'
    }
    [ordered]@{
        captured_utc = (Get-Date).ToUniversalTime().ToString('o')
        method = 'curl HEAD only; no unlisted source-index body downloaded'
        release_lists_source_index = $false
        probes = @($sourceProbeRecords)
        classification = $sourceStatus
    } | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $sourceProbeDir 'source-index-probes.json') -Encoding UTF8
}
$extra=@{ signature_status=$signatureStatus; signer_identity_status=$signerIdentityStatus; download_errors=$downloadErrors; architectures=$architectures; components=$components; selected_packages_index=$chosenIndex; source_status=$sourceStatus; source_stanza_found=[bool]$sourceStanza; source_index_probes=$sourceProbeRecords; package=$packageRecord }
Write-Provenance $items $extra
if ($SkipPackage) { Write-Host 'Metadata and indexes downloaded; package download was skipped.' } else { Write-Host "Downloaded and verified $fileName ($($packageItem.sha256))." }
