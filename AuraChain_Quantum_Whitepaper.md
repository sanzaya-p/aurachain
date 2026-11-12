# AuraChain Quantum (`aurachain-quantum-1`): Technical Whitepaper

**Version 1.0 — Hybrid Post-Quantum Sovereign Settlement Layer & Rollup Ecosystem**  
**Live Network:** https://aurachain-quantum.vercel.app · **Source:** https://github.com/sanzaya-p/aurachain

---

## Abstract

Public blockchains built between 2009 and 2024 rely almost universally on elliptic-curve digital signatures (`secp256k1` ECDSA or `Ed25519` EdDSA), both of which are broken in polynomial time by Shor's quantum algorithm on a cryptographically relevant quantum computer (CRQC). Simultaneously, first- and second-generation networks suffer from structural trade-offs: pure Proof-of-Work chains expend continuous energy after initial distribution, while pre-mined Proof-of-Stake chains concentrate genesis supply among insiders and lack permissionless entry for newcomers.

**AuraChain Quantum (`aurachain-quantum-1`)** resolves these tensions in a compact, auditable Rust state machine:

1. **Hybrid Post-Quantum Authentication:** Every transaction and validator block carries a composite signature combining classical **RFC 8032 `Ed25519`** with **NIST FIPS 204 `ML-DSA-44`** (Module-Lattice Digital Signature Standard) and **NIST FIPS 202 `SHA3-256`** hashing. Compromise requires breaking *both* elliptic-curve discrete logarithms and Module-LWE/SIS lattice problems simultaneously.
2. **Quantum-Shielded Commitment Addresses (`aura1q…`):** Public keys (1,344 bytes) remain hidden behind a 160-bit domain-separated `SHA3-256` commitment until an account spends for the first time.
3. **Fair-Launch PoW Bootstrap → Ouroboros VPoS + Permissionless `PowMine`:** Genesis begins with **0% pre-mine**, transitions automatically to stake-weighted **Verified Proof-of-Stake (VPoS)** with a **¼ saturation cap**, and preserves ongoing permissionless fair distribution via zero-fee **SHA3-256 `PowMine` work shares** directly from any browser or CLI.
4. **Casper ⅔ BFT Checkpoint Finality & Cryptographic Slashing:** Validator attestations finalize checkpoints irreversibly once ≥⅔ of active stake attests, while equivocating validators are slashed on-chain via verifiable double-sign proofs (50% stake burned, 10% whistleblower bounty).
5. **Native Application Primitives & L2 "Metropolis" Settlement:** Rather than exposing reentrancy-prone ad-hoc scripting for core financial primitives, AuraChain embeds constant-product (`x · y = k`) **AuraLaunch** liquidity pools, consensus-enforced **AUA Creator-Royalty NFTs**, stake-weighted **On-Chain DAO Governance**, **EIP-1559 fee burning**, **SHA3-256 Merkle inclusion proofs**, and **L2 Metropolis** rollup state commitments directly in deterministic Rust consensus.

---

## 1. Threat Model & Hybrid Post-Quantum Cryptography

### 1.1 Dual-Primitive Defense-in-Depth

From a single 256-bit (32-byte) master entropy seed $S \in \{0,1\}^{256}$, AuraChain deterministically derives two independent keypairs via domain-separated `SHA3-256`:

$$S_{\text{ed}} = \text{SHA3-256}(\text{"aurachain-ed25519-v1:"} \parallel S)$$

$$S_{\text{pq}} = \text{SHA3-256}(\text{"aurachain-mldsa44-v1:"} \parallel S)$$

- $(pk_{\text{ed}}, sk_{\text{ed}}) \leftarrow \text{Ed25519.KeyGen}(S_{\text{ed}})$, where $|pk_{\text{ed}}| = 32\text{ B}$ and $|\sigma_{\text{ed}}| = 64\text{ B}$.
- $(pk_{\text{pq}}, sk_{\text{pq}}) \leftarrow \text{ML-DSA-44.KeyGen}(S_{\text{pq}})$ per NIST FIPS 204 Algorithm 6, where $|pk_{\text{pq}}| = 1{,}312\text{ B}$ and $|\sigma_{\text{pq}}| = 2{,}420\text{ B}$.

The composite public key is $PK = pk_{\text{ed}} \parallel pk_{\text{pq}}$ ($1{,}344\text{ bytes}$), and the quantum-shielded account address is:

$$\text{Addr}(PK) = \text{"aura1q"} \parallel \text{Hex}\!\left(\text{SHA3-256}(\text{"aurachain-addr-v1:"} \parallel PK)_{[0..20]}\right)$$

A composite signature $\Sigma = \sigma_{\text{ed}} \parallel \sigma_{\text{pq}}$ ($2{,}484\text{ bytes}$) over canonical domain-separated message $M$ is valid if and only if:

$$\text{Ed25519.Verify}(pk_{\text{ed}}, M, \sigma_{\text{ed}}) = 1 \quad \wedge \quad \text{ML-DSA-44.Verify}(pk_{\text{pq}}, M, \sigma_{\text{pq}}, \text{ctx}=\varepsilon) = 1$$

This identical derivation and signing pipeline runs natively in Rust (`fips204` + `ed25519-dalek`) and client-side in standard web browsers (`@noble/post-quantum` + `@noble/curves`), verified by cross-language test vectors in `src/crypto.rs`.

---

## 2. Monetary Policy, Fair Launch & EIP-1559 Economics

- **Genesis Allocation:** `0 AURA` pre-mined. Genesis state contains zero funded accounts (`State::genesis()`).
- **Hard Supply Cap:** `10,000,000,000.000000 AURA` (`10^16` micro-AURA). Consensus rejects any mint exceeding `MAX_SUPPLY`.
- **Block Subsidy & Halving:** `5,000 AURA` per block, halving every `1,000,000` blocks (`subsidy >> halvings`).
- **Permissionless `PowMine` Distribution:** Even after the network transitions to energy-efficient VPoS, any user with zero balance can compute a valid `SHA3-256` Proof-of-Work share anchored to a recent block header (`height - anchor_height <= 30`) and submit a zero-fee `powmine` transaction to mint `50 AURA`. Anti-replay nullifiers (`SHA3-256(sender : anchor_hash : nonce)`) and dynamic difficulty adjustment prevent spam while keeping entry 100% permissionless worldwide.
- **EIP-1559 Fee Burn:** Every block enforces a protocol `base_fee` (adjusting ±12.5% around `TARGET_TXS_PER_BLOCK = 50`). **100% of `base_fee × tx_count` is permanently burned** (`state.burned`), while optional priority tips (`tx.fee - base_fee`) reward the block producer.

---

## 3. Consensus: PoW Bootstrap, Saturated VPoS & Casper BFT Finality

### 3.1 PoW → VPoS Transition & Pool Saturation

Blocks `#1` through `#19` (`POS_START_HEIGHT - 1`) are mined via `SHA3-256` Proof-of-Work with per-5-block difficulty retargeting clamped to `[0.25×, 4×]`. Starting at height `#20`, whenever `total_stake > 0`, consensus switches automatically to 5-second **VPoS slots**.

To prevent stake centralization, each validator $v$'s effective lottery weight $w_v$ (including non-custodial delegations $D_v$) is capped at **one-quarter of total network stake**:

$$w_v = \min\!\left(\text{stake}(v) + \sum_{d \in D_v} \text{stake}(d),\; \max\!\left(1, \left\lfloor \frac{S_{\text{total}}}{4} \right\rfloor\right)\right)$$

For height $h$ and slot $s$, the deterministic slot leader is drawn proportional to $w_v$ using `SHA3-256("aurachain-leader-v1:" || parent_hash || h || s)`. If a leader is offline during slot $s$, slot $s+1$ automatically elects a fresh leader without stalling liveness.

### 3.2 Casper-Style ⅔ Checkpoint Finality & Slashing

Every VPoS block producer implicitly attests (and validators may explicitly submit `Attest` transactions) to the highest checkpoint height $c \equiv 0 \pmod{5}$. Once cumulative effective stake attesting to checkpoint $c$ reaches $\ge \frac{2}{3} S_{\text{total}}$, `state.finalized_height` advances irreversibly to $c$. Full nodes (`src/node.rs`) strictly reject any competing fork that fails to preserve `finalized_hash` at `finalized_height`.

If any validator signs two distinct VPoS headers at the same `(height, slot)`, anyone can submit a `Slash` transaction containing both signed headers. Consensus verifies both Hybrid Post-Quantum signatures on-chain, **burns 50% of the offender's locked stake**, awards a **10% whistleblower bounty** to the reporter, and permanently expels the validator. Unstaking enforces a **10-block unbonding queue** so misbehaving validators cannot withdraw before evidence is submitted.

---

## 4. Native Ecosystem & L2 "Metropolis" Rollup Architecture

1. **AuraLaunch Rug-Proof DEX (`CreateToken`, `BuyToken`, `SellToken`):** Anyone can launch a fixed-supply (`1,000,000,000` units) token seeded into a protocol-owned constant-product AMM pool with virtual `AURA` reserve ($x_{\text{eff}} \cdot y = k$) and 0.30% LP fee retained inside the pool — eliminating LP-removal rug pulls by construction.
2. **AUA Quantum NFTs (`MintNft`, `ListNft`, `BuyNft`):** Native on-chain NFTs with immutable creator provenance and consensus-enforced creator royalties (up to 25.00% / `2500 bps`) settled atomically on every secondary sale.
3. **On-Chain DAO Governance (`Propose`, `Vote`):** Stake-weighted protocol governance (`1 Staked AURA = 1 Vote`) with transparent quorum tracking over 200-block voting epochs.
4. **L2 "Metropolis" Rollup Settlement (`Anchor`) & Light-Client Proofs:** High-throughput off-chain execution batches compress thousands of L2 transactions into deterministic `SHA3-256` state commitments anchored onto L1, paired with `/proof/<height>/<idx>` `SHA3-256` Merkle inclusion branches for trust-minimized verification.

---

## 5. Zero-Cost Autonomous Cloud & Sovereign Peer Topology

AuraChain operates via a hybrid **Serverless Cloud Validator + Permissionless Sovereign Peer** topology:

- **Cloud Validator (`vercel/`):** Runs as a stateless Rust binary backed by **Delta-Lake-style immutable CAS snapshots** (`aura-q1/snap/<version>-<hash>.json`) and permanent block objects (`aura-q1/b/<height>.json`) on persistent object storage, advancing VPoS blocks and L2 Metropolis batches on user transactions and scheduled `/pulse` heartbeats at **$0.00/month**.
- **Sovereign Full Peers (`src/node.rs`):** Any user worldwide can run `aurachain node --peer https://aurachain-quantum.vercel.app` on a laptop, Raspberry Pi, or free cloud micro-VM to independently mirror, audit, and validate every single block from Genesis `#0`.
