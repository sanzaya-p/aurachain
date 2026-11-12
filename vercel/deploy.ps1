# Copies the shared Quantum v1.0 consensus code, UI, and seed chain into vercel/ and deploys to Production.
# Usage:  .\vercel\deploy.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
Set-Location $root
New-Item -ItemType Directory -Force -Path vercel\seed | Out-Null
Copy-Item src\chain.rs, src\crypto.rs, src\explorer.html vercel\src\ -Force
Copy-Item seed\chain.json vercel\seed\chain.json -Force
Set-Location vercel
cargo build --release 2>&1 | Select-Object -Last 2
vercel deploy --prod --yes
