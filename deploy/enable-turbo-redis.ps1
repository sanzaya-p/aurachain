# Enables AuraChain Quantum v2.0 Hybrid Sub-25ms Turbo Mode (Upstash Redis + GitHub Git-CAS Archival).
# AuraChain v2.0 automatically hydrates Redis from sanzaya-p/aurachain-ledger on first request with zero state loss!
#
# Usage:
#   .\deploy\enable-turbo-redis.ps1 -RedisUrl "https://<endpoint>.upstash.io" -RedisToken "<token>"
param(
    [Parameter(Mandatory = $true)][string]$RedisUrl,
    [Parameter(Mandatory = $true)][string]$RedisToken
)

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..\vercel")
$RedisUrl | vercel env add UPSTASH_REDIS_REST_URL production --force
$RedisToken | vercel env add UPSTASH_REDIS_REST_TOKEN production --force
vercel deploy --prod --yes
Write-Host "Hybrid Turbo Mode (hybrid-redis-git-cas) active! Verify via GET /info -> storage."
