[CmdletBinding()]
param(
    [string]$RawRoot = (Join-Path ([Environment]::GetFolderPath('UserProfile')) 'Downloads\perplexity-portable-computer-audit'),
    [string]$PackagePath
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Ensure-Directory([string]$Path) { if (-not (Test-Path -LiteralPath $Path -PathType Container)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }
function Assert-Under([string]$Path, [string]$Root) {
    $p=[IO.Path]::GetFullPath($Path).TrimEnd('\')+'\'; $r=[IO.Path]::GetFullPath($Root).TrimEnd('\')+'\'
    if (-not $p.StartsWith($r,[StringComparison]::OrdinalIgnoreCase)) { throw "Refusing path outside raw root: $Path" }
}
function Find-7Zip { $c=Get-Command 7z.exe -ErrorAction SilentlyContinue; if ($c) { return $c.Source }; foreach($p in @('C:\Program Files\7-Zip\7z.exe','C:\Program Files (x86)\7-Zip\7z.exe')) { if(Test-Path -LiteralPath $p -PathType Leaf){return $p} }; throw '7z.exe not found.' }
function Invoke-7z([string]$Exe,[string[]]$Arguments,[string]$Log) {
    $out = @(& $Exe @Arguments 2>&1); $exit=$LASTEXITCODE
    $out | Set-Content -LiteralPath $Log -Encoding UTF8
    if ($exit -ne 0) { throw "7-Zip failed (exit $exit). See $Log" }
    return $out
}
function Assert-SafeListing([object[]]$Lines,[string]$Archive) {
    $members=$false
    foreach($rawLine in $Lines) {
        $line=[string]$rawLine
        if($line -eq '----------'){$members=$true;continue}
        if(-not $members){continue}
        if($line -match '^Path = (.*)$'){
            $member=$Matches[1]
            if($member -ne '.'){
                $normalized=$member.Replace('/','\').TrimStart('.','\')
                $segments=$normalized -split '\\'
                if([IO.Path]::IsPathRooted($member) -or $member -match '^[\\/]' -or $member -match '^[A-Za-z]:' -or $segments -contains '..' -or $normalized.Contains(':')){throw "Unsafe archive member in ${Archive}: $member"}
            }
        }
        if($line -match '^(Symbolic Link|Hard Link) = (.+)$'){throw "Archive links are not extracted: $line"}
        if($line -match '^Mode = ([^d-].*)$'){throw "Archive special file is not extracted: $line"}
        if($line -match '^(Device Major|Device Minor) = (.+)$'){throw "Archive device member is not extracted: $line"}
    }
}
function Assert-ExtractedTree([string]$Destination) {
    $root=[IO.Path]::GetFullPath($Destination).TrimEnd('\')+'\'
    foreach($item in Get-ChildItem -LiteralPath $Destination -Recurse -Force) {
        $resolved=[IO.Path]::GetFullPath($item.FullName)
        if(-not (($resolved+'\').StartsWith($root,[StringComparison]::OrdinalIgnoreCase))){throw "Extracted path escaped destination: $resolved"}
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw "Extracted reparse point is not permitted: $resolved"}
    }
}
function Get-Archive([string]$Dir,[string]$Pattern) {
    $x=Get-ChildItem -LiteralPath $Dir -File | Where-Object { $_.Name -like $Pattern } | Select-Object -First 1
    if (-not $x) { throw "Expected archive $Pattern was not found in $Dir." }; return $x.FullName
}
function Extract-Archive([string]$Exe,[string]$Archive,[string]$Destination,[string]$Label,[string]$ListingRoot) {
    Assert-Under $Archive $RawRoot; Assert-Under $Destination $RawRoot; Ensure-Directory $Destination
    $safe=Split-Path -Leaf $Archive
    $listing=Invoke-7z $Exe @('l','-slt',$Archive) (Join-Path $ListingRoot "$Label-$safe.listing.txt")
    Assert-SafeListing $listing $Archive
    Invoke-7z $Exe @('x',$Archive,"-o$Destination",'-y') (Join-Path $ListingRoot "$Label-$safe.extract.log") | Out-Null
    Assert-ExtractedTree $Destination
}

$RawRoot=[IO.Path]::GetFullPath($RawRoot); $outer=Join-Path $RawRoot '02-deb-outer'; $control=Join-Path $RawRoot '03-control'; $rootfs=Join-Path $RawRoot '04-rootfs'; $reports=Join-Path $RawRoot '99-generated-reports'
foreach($destination in @($outer,$control,$rootfs)) {
    if((Test-Path -LiteralPath $destination -PathType Container) -and (Get-ChildItem -LiteralPath $destination -Force | Select-Object -First 1)) { throw "Extraction destination is not empty; refusing overwrite: $destination" }
}
Ensure-Directory $outer; Ensure-Directory $control; Ensure-Directory $rootfs; Ensure-Directory $reports
if (-not $PackagePath) { $PackagePath=Get-ChildItem -LiteralPath (Join-Path $RawRoot '01-downloads') -Filter '*.deb' -File | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName }
if (-not $PackagePath -or -not (Test-Path -LiteralPath $PackagePath -PathType Leaf)) { throw 'No .deb package supplied or found under 01-downloads.' }
$PackagePath=[IO.Path]::GetFullPath($PackagePath); Assert-Under $PackagePath $RawRoot
$seven=Find-7Zip; $listingRoot=Join-Path $reports 'archive-listings'; Ensure-Directory $listingRoot
$outerListing=Invoke-7z $seven @('l','-slt',$PackagePath) (Join-Path $listingRoot 'deb-outer.listing.txt')
Assert-SafeListing $outerListing $PackagePath
Invoke-7z $seven @('x',$PackagePath,"-o$outer",'-y') (Join-Path $listingRoot 'deb-outer.extract.log') | Out-Null
Assert-ExtractedTree $outer
$controlArchive=Get-Archive $outer 'control.tar*'; $dataArchive=Get-Archive $outer 'data.tar*'
Extract-Archive $seven $controlArchive $control 'control' $listingRoot
Extract-Archive $seven $dataArchive $rootfs 'data' $listingRoot

# Some 7-Zip builds expose control.tar.xz/data.tar.xz as an intermediate file;
# extract the inner tar a second time when necessary. No file is ever executed.
foreach ($destination in @($control,$rootfs)) {
    $inner=Get-ChildItem -LiteralPath $destination -Recurse -File -Filter '*.tar' | Select-Object -First 1
    if ($inner) {
        $innerDest=Join-Path $destination '_tar-extracted'; Ensure-Directory $innerDest
        Extract-Archive $seven $inner.FullName $innerDest (Split-Path -Leaf $destination) $listingRoot
        Get-ChildItem -LiteralPath $innerDest -Force | ForEach-Object { Move-Item -LiteralPath $_.FullName -Destination $destination -Force }
        Remove-Item -LiteralPath $innerDest -Recurse -Force
    }
}
$allListings=Get-ChildItem -LiteralPath $listingRoot -File -Filter '*.listing.txt' | Sort-Object Name
Get-Content -LiteralPath $allListings.FullName | Set-Content -LiteralPath (Join-Path $reports 'archive-listings.txt') -Encoding UTF8
[ordered]@{ generated_utc=(Get-Date).ToUniversalTime().ToString('o'); package=$PackagePath; outer_root=$outer; control_root=$control; rootfs=$rootfs; listings=$listingRoot; executed_code=$false } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $reports 'extraction-provenance.json') -Encoding UTF8
Write-Host "Extracted archive listings, control metadata, and rootfs using $seven. No package code was executed."
