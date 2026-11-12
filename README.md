# AuraChain v0.3 (devnet)

A working blockchain that implements the core of the AuraChain research:
a **fair-launch Proof-of-Work bootstrap** (no pre-mine) that automatically
switches to **Verified Proof-of-Stake (VPoS)** at a fixed block height.
It also has an **EIP-1559 fee burn**, a **10 billion AURA hard cap**, and
**L2 state roots anchored on L1**.

Everything runs locally and costs nothing.

## Quick start (Windows PowerShell)

```powershell
cd aurachain
cargo build --release          # one-time, ~1 minute
.\start-devnet.ps1             # 2 nodes + L2 sequencer, each in its own window
start http://127.0.0.1:7001    # live explorer
```

## Commands

```text
aurachain keygen  --out me.json                     # create a wallet (keep the file private!)
aurachain address --key me.json
aurachain balance <address>
aurachain send    --key me.json --to <address> --amount 12.5
aurachain stake   --key me.json --amount 1000       # become a VPoS validator
aurachain unstake --key me.json --amount 1000
aurachain anchor  --key me.json --data "any L2 state root"
aurachain info
aurachain node    --port 7003 --data devnet\node3 --key me.json --mine --peer http://127.0.0.1:7001
aurachain l2      --key me.json --interval 15        # Metropolis L2 sequencer demo
```

Add `--node http://host:port` to any wallet command to talk to a different node.

## Consensus rules (src/chain.rs)

| Rule | Value (devnet) |
|---|---|
| Genesis | Timestamped message, empty state, **no pre-mine** |
| PoW | SHA-256 over (header digest ‖ nonce); retarget every 5 blocks toward 5 s blocks; max 4× change per retarget |
| PoW → VPoS | Automatic at block **40** if anything is staked (mainnet design: 525,600); falls back to PoW if nobody stakes |
| VPoS | 5 s slots; a stake-weighted lottery seeded by (parent hash, height, slot); a missed slot elects a new leader; the block must be signed by the leader's Ed25519 key |
| Saturation | No validator's lottery weight exceeds ¼ of total stake |
| Emission | 5,000 AURA per block, halving every 1,000,000 blocks, hard cap 10,000,000,000 AURA |
| Fees | Base fee burned (adjusts ±12.5% toward 50 txs/block); tip paid to producer |
| Fork choice | Heaviest cumulative work |
| Transactions | Ed25519 signatures, per-account nonces, network-ID domain separation |

## API

`GET /info`, `GET /blocks?from=&limit=`, `GET /block/<h>`, `GET /account/<addr>`,
`GET /mempool`, `GET /anchors`, `POST /tx`, `POST /block`, `POST /peers`, `GET /` (explorer).

## Hosting a 24/7 node for free

`deploy/gcp-deploy.ps1` puts a validator node on **Google Cloud's Always-Free tier**. The script is
built to stay free: exactly one `e2-micro` VM in `us-central1`, a 10 GB `pd-standard` disk, and a
**Standard-tier** ephemeral IP, which includes 200 GB/month of free outbound traffic. The script
refuses to run if the project already has another e2-micro.

The hosted node **does not mine**. It boots from a chain snapshot that is already past the PoW
phase, and from then on it only signs VPoS blocks.

```powershell
gcloud auth login                                    # once, in your browser
.\target\release\aurachain.exe keygen --out devnet\cloud-validator.json
# fund and stake the cloud validator from an existing wallet (see aurachain send / stake), then:
.\deploy\gcp-deploy.ps1 -Project <your-gcp-project> -ValidatorKey devnet\cloud-validator.json -Snapshot devnet\node1\chain.json
```

Docker alternative: `docker build -t aurachain .`, then run the image anywhere (see the Dockerfile header).

## Not yet implemented (see the research v2 doc for the roadmap)

Slashing and double-sign evidence, unbonding period, finality gadget, libp2p networking,
RocksDB storage, EVM execution, ZK proofs, bridges, and on-chain DAO voting.

**This is a devnet. Do not use it to hold anything of value.**
