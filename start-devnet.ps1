# Starts a local AuraChain devnet: 2 mining/validating nodes + the L2 sequencer demo.
# Usage:  .\start-devnet.ps1          (add -Fresh to wipe chain data and restart from genesis)
param([switch]$Fresh)
Set-Location $PSScriptRoot
$bin = ".\target\release\aurachain.exe"
if (!(Test-Path $bin)) { cargo build --release }
New-Item -ItemType Directory -Force devnet | Out-Null
foreach ($n in 'miner-a', 'miner-b', 'l2seq') {
    if (!(Test-Path "devnet\$n.json")) { & $bin keygen --out "devnet\$n.json" }
}
if ($Fresh) { Remove-Item -Recurse -Force devnet\node1, devnet\node2 -ErrorAction SilentlyContinue }
Start-Process powershell -ArgumentList "-NoExit", "-Command", "$bin node --port 7001 --data devnet\node1 --key devnet\miner-a.json --mine --peer http://127.0.0.1:7002"
Start-Sleep 2
Start-Process powershell -ArgumentList "-NoExit", "-Command", "$bin node --port 7002 --data devnet\node2 --key devnet\miner-b.json --mine --peer http://127.0.0.1:7001"
Start-Sleep 5
Start-Process powershell -ArgumentList "-NoExit", "-Command", "$bin l2 --key devnet\l2seq.json --interval 15"
Write-Host "Devnet running. Explorer: http://127.0.0.1:7001  (second node: http://127.0.0.1:7002)"
