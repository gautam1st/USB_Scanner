$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

$installRoot = Join-Path $env:LOCALAPPDATA "USB-Guard"
New-Item -ItemType Directory -Force -Path $installRoot | Out-Null

if (-not (Test-Path .\app\USB-Guard.exe)) {
    & powershell -ExecutionPolicy Bypass -File .\app\build.ps1
}
Copy-Item .\app\USB-Guard.exe (Join-Path $installRoot "USB-Guard.exe") -Force

$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
New-Item -Path $runKey -Force | Out-Null
Set-ItemProperty -Path $runKey -Name "USB-Guard-SOC" -Value "`"$installRoot\USB-Guard.exe`""

Write-Host "Installed to $installRoot"
Write-Host "USB-Guard will run in the background after the next login."
Write-Host "Set USB_GUARD_VT_API_KEY before launching to enable VirusTotal lookups."
Start-Process (Join-Path $installRoot "USB-Guard.exe")
