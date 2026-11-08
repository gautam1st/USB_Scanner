$ErrorActionPreference = "Stop"
Set-Location (Split-Path -Parent $PSScriptRoot)

python -m pip install -r .\requirements.txt
python -m pip install pyinstaller
python -m PyInstaller --clean --noconfirm .\app\USBGuard.spec
Copy-Item .\dist\USB-Guard.exe .\app\USB-Guard.exe -Force

Write-Host "Built .\app\USB-Guard.exe"
