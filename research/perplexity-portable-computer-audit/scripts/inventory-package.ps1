[CmdletBinding()]
param(
    [string]$RawRoot = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads\perplexity-portable-computer-audit'),
    [string]$RootfsPath
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Ensure-Directory([string]$p){if(-not(Test-Path -LiteralPath $p -PathType Container)){New-Item -ItemType Directory -Path $p -Force|Out-Null}}
function Read-Prefix([string]$p,[int]$count){
    $stream=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try{$buffer=New-Object byte[] $count;$read=$stream.Read($buffer,0,$count);if($read -eq $count){return ,$buffer};if($read -eq 0){return ,([byte[]]@())};return ,([byte[]]$buffer[0..($read-1)])}
    finally{$stream.Dispose()}
}
function Get-Magic([string]$p){
    try{$b=Read-Prefix $p 16}catch{return 'unknown'}
    if($b.Length -ge 4 -and $b[0]-eq 0x7f -and $b[1]-eq 0x45 -and $b[2]-eq 0x4c -and $b[3]-eq 0x46){return 'ELF'}
    if($b.Length -ge 2 -and $b[0]-eq 0x4d -and $b[1]-eq 0x5a){return 'PE/MZ'}
    if($b.Length -ge 4 -and $b[0]-eq 0x50 -and $b[1]-eq 0x4b){return 'ZIP'}
    if($b.Length -ge 5 -and [Text.Encoding]::ASCII.GetString($b,0,5)-eq '%PDF-'){return 'PDF'}
    if($b.Length -ge 4 -and [Text.Encoding]::ASCII.GetString($b,0,4)-eq 'ustar'){return 'TAR'}
    if($b.Length -ge 2 -and $b[0]-eq 0x1f -and $b[1]-eq 0x8b){return 'GZIP'}
    if($b.Length -ge 4 -and $b[0]-eq 0x28 -and $b[1]-eq 0xb5 -and $b[2]-eq 0x2f -and $b[3]-eq 0xfd){return 'ZSTD'}
    return 'unknown'
}
function Get-TextKind([string]$p){
    try{$bytes=Read-Prefix $p 4096}catch{return 'unknown'}
    if(-not $bytes.Length){return 'text'}; $bad=0; foreach($x in $bytes){if($x -eq 0){$bad++;continue};if(($x -lt 7) -or ($x -gt 14 -and $x -lt 32)){$bad++}}
    if($bad -gt [math]::Max(2,[int]($bytes.Length*.02))){return 'binary'};return 'text'
}
function Component([string]$Rel){if($Rel -match '(?i)(^|/)(usr/bin|bin|sbin|lib|libexec)'){'runtime'}elseif($Rel -match '(?i)(python|node|electron|asar)'){'language-runtime'}elseif($Rel -match '(?i)(service|systemd|daemon)'){'service'}elseif($Rel -match '(?i)(license|copyright|notice)'){'licensing'}elseif($Rel -match '(?i)(config|etc|\.json$|\.toml$|\.yaml$|\.yml$)'){'configuration'}else{'package-file'}}
$RawRoot=[IO.Path]::GetFullPath($RawRoot); if(-not $RootfsPath){$RootfsPath=Join-Path $RawRoot '04-rootfs'}; $RootfsPath=[IO.Path]::GetFullPath($RootfsPath)
if(-not(Test-Path -LiteralPath $RootfsPath -PathType Container)){throw "Rootfs not found: $RootfsPath"}; $reports=Join-Path $RawRoot '99-generated-reports';Ensure-Directory $reports
$reparse=Get-ChildItem -LiteralPath $RootfsPath -Recurse -Force -ErrorAction Stop|Where-Object{$_.Attributes -band [IO.FileAttributes]::ReparsePoint}|Select-Object -First 1
if($reparse){throw "Refusing to inventory a tree containing a reparse point: $($reparse.FullName)"}
$files=Get-ChildItem -LiteralPath $RootfsPath -Recurse -File -Force | Sort-Object FullName; $rows=foreach($f in $files){
    $rel=$f.FullName.Substring($RootfsPath.Length).TrimStart('\','/').Replace('\','/'); $kind=Get-TextKind $f.FullName
    [pscustomobject]@{relative_path=$rel;size=[int64]$f.Length;extension=$f.Extension.ToLowerInvariant();sha256=(Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash.ToLowerInvariant();magic=(Get-Magic $f.FullName);text_or_binary=$kind;archive_attributes='';suspected_component=(Component $rel)}
}
$rows|Export-Csv -LiteralPath (Join-Path $reports 'file-inventory.csv') -NoTypeInformation -Encoding UTF8
$rows|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $reports 'file-inventory.json') -Encoding UTF8
$tree=foreach($f in $files){$f.FullName.Substring($RootfsPath.Length).TrimStart('\','/').Replace('\','/')};$tree|Set-Content -LiteralPath (Join-Path $reports 'directory-tree.txt') -Encoding UTF8
$rows|Sort-Object size -Descending|Select-Object -First 100 size,sha256,relative_path|Format-Table -AutoSize|Out-String|Set-Content -LiteralPath (Join-Path $reports 'largest-files.txt') -Encoding UTF8
$listingFiles=Get-ChildItem -LiteralPath $RawRoot -Recurse -File -ErrorAction SilentlyContinue|Where-Object{$_.Name -ne 'archive-listings.txt' -and $_.Name -match '(?i)listing.*\.txt$'}|Sort-Object FullName;if($listingFiles){Get-Content -LiteralPath $listingFiles.FullName|Set-Content -LiteralPath (Join-Path $reports 'archive-listings.txt') -Encoding UTF8}else{''|Set-Content -LiteralPath (Join-Path $reports 'archive-listings.txt') -Encoding UTF8}
$rows|ForEach-Object{"$($_.sha256)  $($_.relative_path)"}|Set-Content -LiteralPath (Join-Path $reports 'all-hashes.sha256') -Encoding UTF8
$exec=$rows|Where-Object{$_.relative_path -match '(?i)(/|^)(bin|sbin|usr/bin|usr/sbin|usr/libexec)/|\.(exe|dll|so|elf)$|^ELF$'};$exec|Format-Table -AutoSize|Out-String|Set-Content -LiteralPath (Join-Path $reports 'executables.txt') -Encoding UTF8
$script=$rows|Where-Object{$_.relative_path -match '(?i)\.(sh|bash|py|pyc|js|mjs|cjs|ts)$|(^|/)Dockerfile[^/]*$'};$script|Format-Table -AutoSize|Out-String|Set-Content -LiteralPath (Join-Path $reports 'scripts.txt') -Encoding UTF8
$config=$rows|Where-Object{$_.relative_path -match '(?i)\.(json|toml|ya?ml|ini|conf|proto|wit|map)$|(^|/)(package\.json|Cargo\.(toml|lock)|requirements[^/]*\.txt|uv\.lock|compose[^/]*\.ya?ml)$'};$config|Format-Table -AutoSize|Out-String|Set-Content -LiteralPath (Join-Path $reports 'configs.txt') -Encoding UTF8
$service=$rows|Where-Object{$_.relative_path -match '(?i)\.(service|socket|timer|path|target|desktop)$|(^|/)(systemd|services?)/'};$service|Format-Table -AutoSize|Out-String|Set-Content -LiteralPath (Join-Path $reports 'services.txt') -Encoding UTF8
$license=$rows|Where-Object{$_.relative_path -match '(?i)(^|/)(LICENSE(?:\.[^/]*)?|LICENSES(?:\.[^/]*)?|COPYING(?:\.[^/]*)?|NOTICE(?:\.[^/]*)?|copyright|.*\.dist-info/METADATA)$|(^|/)(SBOM|cyclonedx|spdx)'};$license|Format-Table -AutoSize|Out-String|Set-Content -LiteralPath (Join-Path $reports 'licenses.txt') -Encoding UTF8
$source=$rows|Where-Object{$_.relative_path -match '(?i)\.(rs|c|cc|cpp|h|hpp|go|py|js|mjs|ts|tsx|jsx|java|kt|swift|proto|wit)$|(^|/)(Cargo\.toml|package\.json)$'};$source|Format-Table -AutoSize|Out-String|Set-Content -LiteralPath (Join-Path $reports 'source-like-files.txt') -Encoding UTF8
$binary=$rows|Where-Object{$_.text_or_binary -eq 'binary' -or $_.magic -in @('ELF','PE/MZ','ZIP','GZIP','ZSTD')};$binary|Format-Table -AutoSize|Out-String|Set-Content -LiteralPath (Join-Path $reports 'binary-like-files.txt') -Encoding UTF8
$interesting=$rows|Where-Object{$_.relative_path -match '(?i)(systemd|service|sandbox|container|docker|model|weights|checkpoint|sqlite|rocksdb|tantivy|index|skill|connector|advisor|pii|telemetry|update|credential|secret|\.asar)'};$interesting|Format-Table -AutoSize|Out-String|Set-Content -LiteralPath (Join-Path $reports 'interesting-paths.txt') -Encoding UTF8
[ordered]@{generated_utc=(Get-Date).ToUniversalTime().ToString('o');rootfs=$RootfsPath;file_count=$rows.Count;executed_code=$false;notes='Inventory reads file metadata and bounded prefixes only.'}|ConvertTo-Json|Set-Content -LiteralPath (Join-Path $reports 'inventory-provenance.json') -Encoding UTF8
Write-Host "Inventoried $($rows.Count) files under $RootfsPath."
