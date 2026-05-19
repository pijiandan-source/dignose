Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

python -m pip install --upgrade pip
python -m pip install -e . pyinstaller
pyinstaller --onefile --name dignose --clean --noupx --paths src scripts/dignose_entry.py

Write-Host "Build complete: $ProjectRoot\dist\dignose.exe"
