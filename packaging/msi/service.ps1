# The MSI's checks and service handling (Windows PowerShell 5.1). build.ps1 embeds this script
# once per custom action, after a first line `$action = '<action>'`:
#
#   check-install    refuse while a service runs watermelon.exe (0.3 and earlier, see "From 0.3")
#   check-uninstall  refuse while a service runs the installed watermelonpgp.exe
#   stop             stop the services running watermelonpgp.exe; remember which (upgrade, repair)
#   start            start the remembered services again (after the upgrade, or on rollback)
#
# Services are matched by program path, whatever their name (`service install --name`), as in
# packaging/chocolatey/tools/common.ps1. The output goes to the MSI log (`msiexec /l*v`).
$ErrorActionPreference = 'Stop'
$dir = Join-Path $env:ProgramFiles 'WatermelonPGP'
$exe = Join-Path $dir 'watermelonpgp.exe'
$legacyExe = Join-Path $dir 'watermelon.exe'
# Deferred actions run as LocalSystem, so this is C:\Windows\Temp, not a user's folder.
$restartList = Join-Path $env:windir 'Temp\watermelonpgp-msi-restart.txt'

function Get-WatermelonService([string]$Program) {
  @(Get-CimInstance Win32_Service | Where-Object {
    $path = "$($_.PathName)".Trim()
    if ($path.StartsWith('"')) {
      $path.Substring(1).Split('"')[0] -ieq $Program
    } else {
      ($path -ieq $Program) -or $path.StartsWith("$Program ", [StringComparison]::OrdinalIgnoreCase)
    }
  })
}
function Join-Name($services) { ($services | ForEach-Object { $_.Name }) -join ', ' }

switch ($action) {
  'check-install' {
    $legacy = Get-WatermelonService $legacyExe
    if ($legacy) {
      Write-Output "WatermelonPGP: the Windows service $(Join-Name $legacy) runs $legacyExe. The program is now watermelonpgp.exe, so remove the service with the old program first (watermelon service uninstall; the data directory and master key stay), then install this MSI and the service again. See docs/deployment.md, 'From 0.3'."
      exit 1
    }
  }
  'check-uninstall' {
    $services = Get-WatermelonService $exe
    if ($services) {
      Write-Output "WatermelonPGP: the Windows service $(Join-Name $services) runs $exe; removing it would leave a service that can't start. Run watermelonpgp service uninstall first (the data directory and master key stay), then uninstall again."
      exit 1
    }
  }
  'stop' {
    $running = @(Get-WatermelonService $exe | Where-Object { $_.State -ne 'Stopped' })
    Set-Content -Path $restartList -Value ($running | ForEach-Object { $_.Name })
    foreach ($service in $running) {
      Write-Output "WatermelonPGP: stopping the $($service.Name) service; running jobs finish their current file first."
      Stop-Service -Name $service.Name
    }
  }
  'start' {
    # A service that doesn't start is reported, not fatal: undoing the upgrade wouldn't help
    # once the new version has migrated the database.
    if (Test-Path $restartList) {
      foreach ($name in Get-Content $restartList) {
        if (-not $name) { continue }
        Write-Output "WatermelonPGP: starting the $name service again."
        try { Start-Service -Name $name }
        catch { Write-Output "WatermelonPGP: the $name service didn't start: $($_.Exception.Message) See its log in the data directory." }
      }
      Remove-Item $restartList -Force
    }
  }
  default { throw "unknown action '$action'" }
}
