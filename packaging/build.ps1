# build.ps1 — produce a standalone kraken.exe that runs WITHOUT Python.
#
#   powershell -ExecutionPolicy Bypass -File packaging\build.ps1
#
# Output:  dist\kraken.exe  — one self-contained executable for Windows.
# Copy it anywhere and run it; the target PC needs no Python, no pip, nothing.
#
# To BUILD you need Python 3.10+ for Windows (the python.org installer bundles
# Tk, so the GUI is included) and one-time internet access to fetch PyInstaller.
$ErrorActionPreference = "Stop"

# Repo root = parent of this script's folder.
Set-Location (Join-Path $PSScriptRoot "..")

# Find a Python launcher.
$py = $null
foreach ($c in @("python", "py")) {
    if (Get-Command $c -ErrorAction SilentlyContinue) { $py = $c; break }
}
if (-not $py) { throw "Python 3 not found. Install it from https://www.python.org/downloads/windows/ (tick 'Add to PATH')." }

Write-Host "[*] Building with $py ($(& $py --version))"
if ((& $py -c "import tkinter" 2>$null; $LASTEXITCODE) -eq 0) {
    Write-Host "[*] Tkinter present - the desktop GUI will be bundled."
} else {
    Write-Host "[!] Tkinter NOT found - CLI will work but the bundled GUI will not."
}

$venv = ".build-venv"
if (-not (Test-Path "$venv\Scripts\pyinstaller.exe")) {
    Write-Host "[*] Creating one-time build environment in $venv\ ..."
    if (Test-Path $venv) { Remove-Item -Recurse -Force $venv }
    & $py -m venv $venv
    & "$venv\Scripts\python.exe" -m pip install --upgrade pip | Out-Null
    & "$venv\Scripts\python.exe" -m pip install "pyinstaller>=6.0"
}

Write-Host "[*] Running PyInstaller ..."
& "$venv\Scripts\pyinstaller.exe" --noconfirm --clean packaging\kraken.spec

Write-Host ""
Write-Host "[+] Done: $((Get-Location).Path)\dist\kraken.exe"
& ".\dist\kraken.exe" --version
Write-Host ""
Write-Host "Try it:"
Write-Host "  .\dist\kraken.exe --help        # list commands"
Write-Host "  .\dist\kraken.exe exposure      # audit this host's exposure"
Write-Host "  .\dist\kraken.exe gui           # open the desktop app (or just double-click the .exe)"
