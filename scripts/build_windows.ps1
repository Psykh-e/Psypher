$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonPath = Join-Path $projectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Önce Python 3.12 ile .venv oluşturup geliştirme bağımlılıklarını kurun.'
}
Push-Location $projectRoot
try {
    & $pythonPath -m PyInstaller --noconfirm --clean --onedir --console --name Psypher --paths src scripts/entrypoint.py
    if ($LASTEXITCODE -ne 0) { throw 'Paketleme başarısız.' }
    & './dist/Psypher/Psypher.exe' --version
    if ($LASTEXITCODE -ne 0) { throw 'Çalıştırılabilir dosya kontrolü başarısız.' }
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath './dist/Psypher/Psypher.exe'
    $hash.Hash | Set-Content -Encoding ascii -LiteralPath './dist/Psypher/Psypher.exe.sha256'
    Copy-Item -LiteralPath 'README.md', 'LICENSE', 'SECURITY.md' -Destination './dist/Psypher'
    Copy-Item -LiteralPath 'docs' -Destination './dist/Psypher' -Recurse
    Compress-Archive -LiteralPath './dist/Psypher' -DestinationPath './dist/Psypher-2.0.0b1-windows-x64.zip' -Force
} finally {
    Pop-Location
}
