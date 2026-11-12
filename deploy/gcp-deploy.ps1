<#
Deploys a 24/7 AuraChain validator node to Google Cloud's ALWAYS-FREE tier.

Stays inside the free tier by construction:
  * exactly ONE e2-micro VM, in us-central1 (free-tier region)
  * 10 GB pd-standard boot disk (free tier allows 30 GB pd-standard)
  * ephemeral external IP on the STANDARD network tier (no reserved static IP);
    Standard tier includes 200 GB/month free internet egress per region
  * the node does NOT mine: it boots from a chain snapshot that is already past
    the PoW phase and only signs VPoS blocks (negligible CPU)
Remaining cost risk: egress above 200 GB/month - practically unreachable for a
devnet (the explorer and peer sync are tuned to use very little bandwidth).

Prereqs: gcloud logged in (gcloud auth login), Docker running, a GCP project
with billing enabled (required by Google even for free-tier VMs).

Usage:
  .\deploy\gcp-deploy.ps1 -Project <project-id> -ValidatorKey devnet\cloud-validator.json -Snapshot devnet\node1\chain.json
#>
param(
    [Parameter(Mandatory)] [string]$Project,
    [Parameter(Mandatory)] [string]$ValidatorKey,
    [Parameter(Mandatory)] [string]$Snapshot,
    [string]$Zone = "us-central1-a",
    [string]$Name = "aurachain-node-1"
)
$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)

Write-Host "==> Checking for an existing e2-micro in the project (free tier = only one)"
$existing = gcloud compute instances list --project $Project --filter="machineType~e2-micro" --format="value(name)"
if ($existing -and ($existing -notcontains $Name)) {
    throw "Project already has e2-micro VM(s): $existing. A second one would NOT be free. Aborting."
}

Write-Host "==> Enabling Compute Engine API (free)"
gcloud services enable compute.googleapis.com --project $Project

Write-Host "==> Building Linux binary in Docker"
New-Item -ItemType Directory -Force deploy\out | Out-Null
docker build --target build -t aurachain-build .
$cid = docker create aurachain-build
docker cp "${cid}:/src/target/release/aurachain" deploy\out\aurachain
docker rm $cid | Out-Null

Write-Host "==> Firewall rule: allow TCP 7001 to VMs tagged 'aurachain' (free)"
$fw = gcloud compute firewall-rules list --project $Project --filter="name=allow-aurachain" --format="value(name)"
if (-not $fw) {
    gcloud compute firewall-rules create allow-aurachain --project $Project --allow tcp:7001 --target-tags aurachain --description "AuraChain node API/explorer"
}

if (-not ($existing -contains $Name)) {
    Write-Host "==> Creating free-tier VM $Name ($Zone, e2-micro, 10GB pd-standard)"
    gcloud compute instances create $Name --project $Project --zone $Zone `
        --machine-type e2-micro --image-family debian-12 --image-project debian-cloud `
        --boot-disk-size 10GB --boot-disk-type pd-standard --tags aurachain `
        --network-tier STANDARD
    Start-Sleep 30
}
$ip = gcloud compute instances describe $Name --project $Project --zone $Zone --format="value(networkInterfaces[0].accessConfigs[0].natIP)"
Write-Host "==> VM external IP: $ip"

Write-Host "==> Uploading binary, chain snapshot and validator key"
gcloud compute scp --project $Project --zone $Zone deploy\out\aurachain $Snapshot $ValidatorKey deploy\aurachain.service "${Name}:/tmp/" --quiet
$keyFile = Split-Path $ValidatorKey -Leaf
$snapFile = Split-Path $Snapshot -Leaf

$remote = @"
set -e
sudo useradd -r -s /usr/sbin/nologin aurachain 2>/dev/null || true
sudo install -d -o aurachain -m 700 /var/lib/aurachain /etc/aurachain
sudo install -m 755 /tmp/aurachain /usr/local/bin/aurachain
if [ ! -f /var/lib/aurachain/chain.json ]; then sudo install -o aurachain -m 600 /tmp/$snapFile /var/lib/aurachain/chain.json; fi
sudo install -o aurachain -m 600 /tmp/$keyFile /etc/aurachain/validator.json
sed "s/__PUBLIC_IP__/$ip/" /tmp/aurachain.service | sudo tee /etc/systemd/system/aurachain.service >/dev/null
rm -f /tmp/$keyFile
sudo systemctl daemon-reload
sudo systemctl enable --now aurachain
sudo systemctl restart aurachain
sleep 3
curl -s localhost:7001/tip
"@
$remote = $remote -replace "`r", ""   # bash chokes on Windows CRLF line endings
gcloud compute ssh $Name --project $Project --zone $Zone --command $remote --quiet

Write-Host ""
Write-Host "AuraChain node is live 24/7:  http://${ip}:7001"
Write-Host "Connect your local node:      aurachain node --port 7001 --data devnet\node1 --peer http://${ip}:7001"
