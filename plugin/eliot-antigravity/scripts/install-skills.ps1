param([switch]$Apply)
if (-not $Apply) { Write-Output 'dry-run: plugin install skipped'; exit 0 }
throw 'G3A plugin bundle is not installable'
