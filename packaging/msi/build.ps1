# Build the Windows installer from the unpacked release zip (PowerShell 7, WiX v5 on the Path
# with WixToolset.Util.wixext added globally; the release workflow's msi job sets both up):
#
#   packaging/msi/build.ps1 -Version 0.4.0 -Payload <unpacked zip folder> -Out watermelon-pgp.msi
param(
  [Parameter(Mandatory)] [string] $Version,
  [Parameter(Mandatory)] [string] $Payload,
  [Parameter(Mandatory)] [string] $Out
)
$ErrorActionPreference = 'Stop'

# An MSI version is numbers only; the first three count for upgrades.
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "MSI versions are X.Y.Z, not '$Version'" }
if (-not (Test-Path (Join-Path $Payload 'watermelonpgp.exe'))) { throw "no watermelonpgp.exe in $Payload" }

# service.ps1 once per custom action, as a full command line. -EncodedCommand (base64 of UTF-16)
# needs no quoting, and the MSI's [brackets] can't occur in it.
$script = Get-Content -Raw (Join-Path $PSScriptRoot 'service.ps1')
# [System64Folder] is C:\Windows\system32\: no spaces, so no quotes (which a define can't hold).
$powershell = '[System64Folder]WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand'
$generated = Join-Path ([IO.Path]::GetTempPath()) "watermelonpgp-msi-$PID"
New-Item -ItemType Directory -Force $generated | Out-Null
$defines = foreach ($pair in @(
    @('CmdCheckInstall', 'check-install'), @('CmdCheckUninstall', 'check-uninstall'),
    @('CmdStop', 'stop'), @('CmdStart', 'start'))) {
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("`$action = '$($pair[1])'`n$script"))
  "  <?define $($pair[0]) = `"$powershell $encoded`" ?>"
}
Set-Content (Join-Path $generated 'actions.wxi') -Encoding utf8 -Value @(
  '<?xml version="1.0" encoding="utf-8"?>', '<Include>', $defines, '</Include>')

try {
  wix build (Join-Path $PSScriptRoot 'watermelon-pgp.wxs') -arch x64 -ext WixToolset.Util.wixext `
    -d "Version=$Version" -d "Payload=$((Resolve-Path $Payload).Path)" -d "Generated=$generated" -o $Out
  if ($LASTEXITCODE -ne 0) { throw "wix build failed ($LASTEXITCODE)" }
} finally {
  Remove-Item $generated -Recurse -Force -ErrorAction SilentlyContinue
}
Get-Item $Out | Select-Object Name, Length
