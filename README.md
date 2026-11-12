# AuraChain Quantum v1.0 (`aurachain-quantum-1`)

[![Autonomous Pulse & CI](https://github.com/sanzaya-p/aurachain/actions/workflows/autonomous-pulse.yml/badge.svg)](https://github.com/sanzaya-p/aurachain/actions/workflows/autonomous-pulse.yml)
[![Live Network](https://img.shields.io/badge/Live_Super--App-aurachain--drab.vercel.app-7c3aed)](https://aurachain-quantum.vercel.app)
[![Post-Quantum](https://img.shields.io/badge/Cryptography-NIST_FIPS_204_ML--DSA--44_%2B_Ed25519-06b6d4)](./src/crypto.rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-10b981.svg)](./Cargo.toml)

**AuraChain Quantum** is an open-source, sovereign **Post-Quantum Layer-1 settlement blockchain + Layer-2 rollup ecosystem** written in safe Rust. It synthesizes five foundational breakthroughs in distributed systems and modern cryptography into a single cohesive, verifiable codebase:

1. **Bitcoin's Fair Launch & Hard Scarcity** — **0% pre-mine, 0% VC/team allocation**, Proof-of-Work genesis bootstrap, permissionless zero-fee `powmine` SHA3-256 fair distribution, and a strict **10,000,000,000 AURA** hard cap with halving every 1,000,000 blocks.
2. **NIST Post-Quantum Lattice Cryptography** — Every account and validator block is authenticated with a **Hybrid Dual-Signature (`Ed25519` + NIST FIPS 204 `ML-DSA-44` Module-Lattice)** and **NIST FIPS 202 `SHA3-256`** hashing, with quantum-shielded `aura1q…` public-key commitment addresses.
3. **Ouroboros VPoS + Casper ⅔ BFT Finality** — Automatic transition from PoW bootstrap to stake-weighted **Verified Proof-of-Stake** with a **¼ pool saturation cap**, **10-block unbonding lockups**, **cryptographic double-sign slashing** (50% burned + 10% whistleblower bounty), and **Casper-style ⅔ supermajority checkpoint finality**.
4. **Ethereum EIP-1559 Deflationary Fee Burn** — Dynamic base fee adjusting ±12.5% per block toward target utilization, with **100% of base fees permanently burned** from supply.
5. **Native Sovereign Ecosystem + L2 "Metropolis" Rollup Settlement** — Built-in **On-Chain DAO Governance** (`Propose` / `Vote`), **AuraLaunch** rug-proof `x·y=k` bonding-curve token factory & DEX, **AUA Quantum NFTs** with consensus-enforced creator royalties, **SHA3-256 Merkle light-client proofs**, and **L2 Metropolis** state root batch anchoring.

---

## 🌐 Live Autonomous Network (Zero Setup — Open in Browser)

- **Live Super-App (Explorer · PQ Wallet · Browser SHA3-256 Miner · DEX · NFTs · DAO):**  
  **https://aurachain-quantum.vercel.app**
- **Live Telemetry JSON:** https://aurachain-quantum.vercel.app/info
- **Live Ecosystem State:** https://aurachain-quantum.vercel.app/ecosystem
- **Technical Whitepaper:** [AuraChain_Quantum_Whitepaper.md](./AuraChain_Quantum_Whitepaper.md)

Anyone can open the live web app, generate a non-custodial client-side **NIST FIPS 204 ML-DSA-44 + Ed25519** wallet (`@noble/post-quantum` + `@noble/curves`, keys never leave your browser), mine **50 AURA** via real SHA3-256 Proof-of-Work in seconds, stake, delegate, launch tokens, mint royalty NFTs, and vote on DAO proposals.

---

## ⚡ Quickstart: CLI Wallet, Miner & Full Verifying Peer Node

Download the prebuilt binary from [GitHub Releases](https://github.com/sanzaya-p/aurachain/releases) or compile from source:

```bash
git clone https://github.com/sanzaya-p/aurachain.git
cd aurachain
cargo test
cargo build --release
```

### 1. Create a Post-Quantum Wallet & Mine 50 AURA on the Live Network

```bash
# Generate a 256-bit master quantum seed -> Hybrid Ed25519 + ML-DSA-44 keypair (keep this file private!)
./target/release/aurachain keygen --out my-wallet.json

# Mine a zero-fee SHA3-256 PoW share to mint +50.000000 AURA directly to your wallet
./target/release/aurachain pow-claim --key my-wallet.json --node https://aurachain-quantum.vercel.app

# Inspect your balance, stake, tokens, and NFTs
./target/release/aurachain address --key my-wallet.json
./target/release/aurachain info --node https://aurachain-quantum.vercel.app
```

### 2. Join the Live Network as a Full Verifying Peer Node

Every peer node downloads the chain from genesis, independently verifies every SHA3-256 PoW header, Hybrid ML-DSA-44 + Ed25519 VPoS signature, Merkle root, state root, and BFT checkpoint:

```bash
./target/release/aurachain node \
  --port 7001 \
  --data ./aura-node-data \
  --key my-wallet.json \
  --peer https://aurachain-quantum.vercel.app
```

Or via Docker:

```bash
docker build -t aurachain-quantum .
docker run -p 7001:7001 -v aura-data:/data aurachain-quantum
```

### 3. Stake, Delegate, Trade, Govern & Anchor L2 Batches via CLI

```bash
# Stake AURA to enter the active VPoS validator set (or vote in DAO governance)
aurachain stake --key my-wallet.json --amount 25

# Non-custodial stake delegation to an active validator
aurachain delegate --key my-wallet.json --validator aura1q1800124bd7f843ee4010155bef66329f607058a0

# Launch a rug-proof constant-product (x*y=k) community token & swap
aurachain create-token --key my-wallet.json --symbol NOVA --name "Nova Quantum Compute"
aurachain buy-token --key my-wallet.json --symbol QBIT --aura 5
aurachain sell-token --key my-wallet.json --symbol QBIT --amount 100

# Submit & vote on On-Chain DAO Improvement Proposals (1 Staked AURA = 1 Vote)
aurachain propose --key my-wallet.json --title "AIP-2: Cross-Rollup State Proofs" --summary "Standardize L2 recursive proof headers"
aurachain vote --key my-wallet.json --id 1 --aye

# Anchor an L2 Metropolis rollup batch commitment onto L1
aurachain anchor --key my-wallet.json --data "metropolis-zk:batch=custom:root=..."
aurachain ecosystem
```

---

## 🔐 Cryptographic & Consensus Architecture

| Layer | Specification | Implementation |
|---|---|---|
| **Network ID** | `aurachain-quantum-1` (domain-separated across keys, txs, headers, PoW) | `src/chain.rs` |
| **Signature Scheme** | **Hybrid `Ed25519` (64 B) + NIST FIPS 204 `ML-DSA-44` (2,420 B)** — both *must* verify | `src/crypto.rs` (`#!(deny(unsafe_code))` `fips204`) |
| **Public Keys & Addresses** | 1,344 B Hybrid PK (`32 B Ed25519 ‖ 1,312 B ML-DSA-44`); `aura1q` + 20-byte `SHA3-256` commitment | Quantum-shielded against Shor's algorithm at rest |
| **Hashing & Merkle Trees** | **NIST FIPS 202 `SHA3-256`** with leaf/internal node domain separation (`0x01`) | `/proof/<height>/<tx_idx>` light-client proofs |
| **Fair Launch & Cap** | 0% Pre-Mine · 5,000 AURA block subsidy (halving every 1M blocks) · **10B AURA max** | Permissionless `powmine` (`50 AURA` per valid SHA3 share) |
| **Consensus & Saturation** | PoW Bootstrap (`#0..#19`) → Ouroboros-style VPoS (`#20+`, 5s slots, ¼ stake saturation cap) | Automatic PoW fallback if total stake drops to zero |
| **Finality & Slashing** | **Casper ⅔ Stake Checkpoint Finality** + **Double-Sign Slashing** (50% burned, 10% reporter bounty) | Reorgs past `finalized_height` rejected by all nodes |
| **Fee Mechanism** | **EIP-1559** dynamic base fee (±12.5% toward 50 txs/block), **100% burned** | Deflationary pressure under high ecosystem demand |
| **Autonomous Cloud Architecture** | Rust serverless validator (`vercel/`) + immutable CAS snapshots on Vercel Blob + scheduled `/pulse` | Zero local machine dependency, $0.00 infrastructure |

---

## 📡 Public REST / RPC API

All endpoints return `application/json` with `Access-Control-Allow-Origin: *`:

| Method & Path | Description |
|---|---|
| `GET /` | Interactive 6-Tab AuraChain Quantum Web Super-App |
| `GET /info` | Full chain, validator weights, BFT finality, supply, burn, and target telemetry |
| `GET /tip` | Bandwidth-frugal sync header (`height`, `hash`, `finalized_height`, `chainwork`) |
| `GET /ecosystem` | Active DAO proposals, AuraLaunch DEX pools, AUA NFTs, L2 Metropolis batches, slashes |
| `GET /blocks?from=0&limit=50` | Paginated full block & transaction feed |
| `GET /block/<height>` | Single block with header hash and transactions |
| `GET /proof/<height>/<tx_idx>` | Verified SHA3-256 Merkle inclusion branch for light clients & bridges |
| `GET /account/<aura1q…>` | Balance, active stake, delegation, unbonding queue, token balances, owned NFTs, nonce |
| `POST /tx` | Submit a Hybrid Post-Quantum signed transaction (`Tx` JSON) |
| `GET /pulse` | Idempotent autonomous VPoS slot + L2 Metropolis batch trigger |

---

## 📂 Repository Structure

- `src/crypto.rs` — Hybrid `Ed25519` + NIST FIPS 204 `ML-DSA-44` key derivation, hedged deterministic signing, dual verification, `aura1q…` commitment addresses, and `@noble/post-quantum` parity tests.
- `src/chain.rs` — Deterministic L1 state machine: PoW/VPoS consensus, Casper ⅔ BFT finality, double-sign slashing, unbonding, `PowMine`, EIP-1559 burn, DAO, `x·y=k` DEX, Royalty NFTs, L2 batch anchoring, and SHA3-256 Merkle proofs.
- `src/node.rs` — Multi-threaded sovereign P2P full node, miner, VPoS validator, chunked sync engine, and HTTP RPC server.
- `src/main.rs` — Full-featured CLI wallet, miner, DAO/DEX client, L2 sequencer, and genesis seed bootstrapper.
- `src/explorer.html` — Single-file zero-build Post-Quantum Web Super-App.
- `vercel/` — Autonomous serverless cloud validator & persistent Delta-snapshot CAS ledger (`Store::Blob` / `Store::Upstash` / `Store::File`).
- `deploy/gcp-deploy.ps1` — Optional Google Cloud Always-Free `e2-micro` sovereign peer node deployment script.
- `.github/workflows/autonomous-pulse.yml` — Continuous Rust cryptographic test suite + 10-minute autonomous cloud pulse keeper.

---

## ⚠️ Engineering Honesty & Disclaimer

AuraChain Quantum v1.0 is an authentic, open-source cryptographic protocol and autonomous public network engineered for zero-cost sovereign operation, post-quantum security research, and decentralized application experimentation. `AURA` is a native utility token earned permissionlessly via Proof-of-Work and Proof-of-Stake; it carries **no promise of financial return or fiat exchange value**. Never commit wallet seed files (`*.json`) to version control.
