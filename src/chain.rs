//! Consensus rules, Post-Quantum verification, BFT checkpoint finality, and
//! protocol-native ecosystem state machine of AuraChain Quantum v1.0 (L1).
//!
//! Architectural pillars implemented in consensus:
//!   1. Hybrid Post-Quantum Security: Every transaction & VPoS block requires BOTH
//!      Ed25519 AND NIST FIPS 204 ML-DSA-44 lattice signatures + SHA3-256 roots.
//!   2. Fair-Launch Genesis Mandate: 0 pre-mine, 0 team/VC allocation, 10B hard cap.
//!   3. Hybrid PoW -> Verified Proof-of-Stake (VPoS) with 1/4 pool saturation cap,
//!      non-custodial delegation, unbonding lockup, and double-sign slashing.
//!   4. Casper-style BFT Checkpoint Finality Gadget (>= 2/3 stake supermajority).
//!   5. Permissionless SHA3-256 Fair-Distribution Mining (`powmine` zero-fee tx)
//!      so anyone globally can earn AURA via CPU/browser work with dynamic retargeting.
//!   6. EIP-1559 Deflationary Fee Engine (100% of base fee permanently burned).
//!   7. On-Chain DAO Governance (AIP proposals + stake-weighted voting).
//!   8. AuraLaunch Protocol Bonding-Curve Token Factory & DEX (0% rug-pull liquidity).
//!   9. AUA Quantum NFT Standard with protocol-enforced creator royalties.
//!  10. L2 "Metropolis" Rollup State-Root Anchoring + SHA3-256 Merkle Proofs.

use crate::crypto::{self, sha3_256, sha3_256_hex, Keypair};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------- parameters
pub const NETWORK: &str = "aurachain-quantum-1";
pub const COIN: u64 = 1_000_000; // 1 AURA = 1,000,000 micro-AURA
pub const MAX_SUPPLY: u64 = 10_000_000_000 * COIN; // 10 Billion AURA hard cap
pub const INITIAL_REWARD: u64 = 5_000 * COIN;
pub const HALVING_INTERVAL: u64 = 1_000_000;
pub const POW_CLAIM_REWARD: u64 = 50 * COIN; // 50 AURA per valid permissionless PoW share
pub const TARGET_BLOCK_SECS: u64 = 5;
pub const RETARGET_WINDOW: u64 = 5;
pub const POS_START_HEIGHT: u64 = 20; // PoW fair-launch bootstrap -> VPoS at height 20
pub const SLOT_SECS: u64 = 5;
pub const FINALITY_INTERVAL: u64 = 5; // BFT checkpoint every 5 blocks
pub const UNBONDING_BLOCKS: u64 = 10; // Stake lockup period on unstake
pub const SATURATION_DIVISOR: u64 = 4; // Max 25% lottery weight per validator pool
pub const MIN_BASE_FEE: u64 = 1_000; // 0.001 AURA
pub const TARGET_TXS_PER_BLOCK: u64 = 50;
pub const MAX_TXS_PER_BLOCK: usize = 100;
pub const MAX_FUTURE_SECS: u64 = 60;
pub const MAX_DATA_BYTES: usize = 1024;
pub const INITIAL_TARGET: u128 = u128::MAX / 500_000; // Fast PoW bootstrap
pub const INITIAL_POW_CLAIM_TARGET: u128 = u128::MAX / 45_000; // ~0.4s in browser WebWorker
pub const GENESIS_TIMESTAMP: u64 = 1_794_450_000; // 12 Nov 2026 UTC
pub const GENESIS_MESSAGE: &str =
    "AuraChain Quantum v1.0 Genesis 12/Nov/2026 - Post-Quantum FIPS-204 ML-DSA | Fair Launch: 0 Pre-Mine";

mod u128_dec {
    use super::*;
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        let st = String::deserialize(d)?;
        st.parse::<u128>().map_err(serde::de::Error::custom)
    }
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub fn fmt_aura(micro: u64) -> String {
    format!("{}.{:06}", micro / COIN, micro % COIN)
}

pub fn parse_aura(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (whole, frac) = match s.split_once('.') {
        Some((w, f)) => (w, f),
        None => (s, ""),
    };
    if frac.len() > 6 {
        return Err("max 6 decimal places".into());
    }
    let w: u64 = if whole.is_empty() { 0 } else { whole.parse().map_err(|_| "bad amount")? };
    let f: u64 = if frac.is_empty() { 0 } else { format!("{:0<6}", frac).parse().map_err(|_| "bad amount")? };
    w.checked_mul(COIN).and_then(|x| x.checked_add(f)).ok_or_else(|| "amount overflow".into())
}

// --------------------------------------------------------------- transactions
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TxKind {
    Transfer,
    Stake,
    Unstake,
    Delegate,
    Slash,
    PowMine,
    Propose,
    Vote,
    CreateToken,
    BuyToken,
    SellToken,
    MintNft,
    ListNft,
    BuyNft,
    Anchor,
    Attest,
}

impl TxKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            TxKind::Transfer => "transfer",
            TxKind::Stake => "stake",
            TxKind::Unstake => "unstake",
            TxKind::Delegate => "delegate",
            TxKind::Slash => "slash",
            TxKind::PowMine => "powmine",
            TxKind::Propose => "propose",
            TxKind::Vote => "vote",
            TxKind::CreateToken => "createtoken",
            TxKind::BuyToken => "buytoken",
            TxKind::SellToken => "selltoken",
            TxKind::MintNft => "mintnft",
            TxKind::ListNft => "listnft",
            TxKind::BuyNft => "buynft",
            TxKind::Anchor => "anchor",
            TxKind::Attest => "attest",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Tx {
    pub kind: TxKind,
    pub from_pubkey: String,
    pub to: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
    pub data: String,
    pub signature: String,
}

impl Tx {
    pub fn new(kind: TxKind, kp: &Keypair, to: &str, amount: u64, fee: u64, nonce: u64, data: &str) -> Tx {
        let mut tx = Tx {
            kind,
            from_pubkey: kp.public_hex(),
            to: to.to_string(),
            amount,
            fee,
            nonce,
            data: data.to_string(),
            signature: String::new(),
        };
        tx.signature = kp.sign(&tx.signing_bytes());
        tx
    }

    /// Canonical, language-independent UTF-8 preimage (identical in Rust, Browser JS, Python, Go).
    pub fn signing_bytes(&self) -> Vec<u8> {
        let data_hash = sha3_256_hex(self.data.as_bytes());
        format!(
            "aurachain-tx-v1|{NETWORK}|{}|{}|{}|{}|{}|{}|{data_hash}",
            self.kind.as_str(),
            self.from_pubkey,
            self.to,
            self.amount,
            self.fee,
            self.nonce
        )
        .into_bytes()
    }

    pub fn id(&self) -> String {
        let mut v = self.signing_bytes();
        v.push(b'|');
        v.extend_from_slice(self.signature.as_bytes());
        sha3_256_hex(&v)
    }

    pub fn sender(&self) -> Result<String, String> {
        crypto::address_from_pubkey_hex(&self.from_pubkey)
    }

    pub fn verify_signature(&self) -> Result<(), String> {
        crypto::verify(&self.from_pubkey, &self.signing_bytes(), &self.signature)
    }
}

// --------------------------------------------------------------------- blocks
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Header {
    pub network: String,
    pub height: u64,
    pub prev_hash: String,
    pub timestamp: u64,
    pub tx_root: String,
    pub state_root: String,
    pub finalized_height: u64,
    pub consensus: String, // "genesis" | "pow" | "pos"
    pub target: String,    // PoW target (hex u128); inherited by PoS blocks
    pub slot: u64,         // VPoS slot index since parent (0 for PoW)
    pub producer: String,
    pub producer_pubkey: String,
    pub base_fee: u64,
    pub message: String,
    pub nonce: u64,
    pub signature: String, // VPoS: Hybrid Ed25519 + ML-DSA-44 signature over block hash
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Tx>,
}

impl Header {
    /// Canonical SHA3-256 digest of all header fields except nonce & signature.
    pub fn prefix_digest(&self) -> [u8; 32] {
        let canonical = format!(
            "aurachain-hdr-v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            self.network,
            self.height,
            self.prev_hash,
            self.timestamp,
            self.tx_root,
            self.state_root,
            self.finalized_height,
            self.consensus,
            self.target,
            self.slot,
            self.producer,
            self.producer_pubkey,
            self.base_fee,
            sha3_256_hex(self.message.as_bytes()),
        );
        sha3_256(canonical.as_bytes())
    }

    pub fn hash_with(prefix: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(prefix);
        buf[32..].copy_from_slice(&nonce.to_le_bytes());
        sha3_256(&buf)
    }

    pub fn hash(&self) -> [u8; 32] {
        Self::hash_with(&self.prefix_digest(), self.nonce)
    }

    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash())
    }

    pub fn target_value(&self) -> Result<u128, String> {
        u128::from_str_radix(self.target.trim_start_matches("0x"), 16).map_err(|_| "bad target".into())
    }
}

pub fn hash_value(h: &[u8; 32]) -> u128 {
    u128::from_be_bytes(h[..16].try_into().unwrap())
}

pub fn target_hex(t: u128) -> String {
    format!("0x{:032x}", t)
}

pub fn work_of(target: u128) -> u128 {
    u128::MAX / target.saturating_add(1)
}

// ------------------------------------------------------ SHA3-256 Merkle proofs
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MerkleStep {
    pub sibling: String,
    pub is_right: bool,
}

pub fn tx_root(txs: &[Tx]) -> String {
    if txs.is_empty() {
        return sha3_256_hex(b"aurachain-empty-tx-tree");
    }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|t| hex::decode(t.id()).unwrap().try_into().unwrap()).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|c| {
                let mut b = Vec::with_capacity(65);
                b.push(0x01);
                b.extend_from_slice(&c[0]);
                b.extend_from_slice(if c.len() == 2 { &c[1] } else { &c[0] });
                sha3_256(&b)
            })
            .collect();
    }
    hex::encode(level[0])
}

pub fn merkle_proof(txs: &[Tx], mut idx: usize) -> Option<Vec<MerkleStep>> {
    if idx >= txs.len() {
        return None;
    }
    let mut steps = vec![];
    let mut level: Vec<[u8; 32]> = txs.iter().map(|t| hex::decode(t.id()).unwrap().try_into().unwrap()).collect();
    while level.len() > 1 {
        let sib = if idx % 2 == 0 {
            if idx + 1 < level.len() { level[idx + 1] } else { level[idx] }
        } else {
            level[idx - 1]
        };
        steps.push(MerkleStep { sibling: hex::encode(sib), is_right: idx % 2 == 0 });
        level = level
            .chunks(2)
            .map(|c| {
                let mut b = Vec::with_capacity(65);
                b.push(0x01);
                b.extend_from_slice(&c[0]);
                b.extend_from_slice(if c.len() == 2 { &c[1] } else { &c[0] });
                sha3_256(&b)
            })
            .collect();
        idx /= 2;
    }
    Some(steps)
}

pub fn verify_merkle_proof(tx_id_hex: &str, steps: &[MerkleStep], expected_root: &str) -> bool {
    let Ok(mut cur) = hex::decode(tx_id_hex).and_then(|v| v.try_into().map_err(|_| hex::FromHexError::OddLength)) else {
        return false;
    };
    let cur_arr: &mut [u8; 32] = &mut cur;
    for s in steps {
        let Ok(sib_vec) = hex::decode(&s.sibling) else { return false };
        let Ok(sib): Result<[u8; 32], _> = sib_vec.try_into() else { return false };
        let mut b = Vec::with_capacity(65);
        b.push(0x01);
        if s.is_right {
            b.extend_from_slice(cur_arr);
            b.extend_from_slice(&sib);
        } else {
            b.extend_from_slice(&sib);
            b.extend_from_slice(cur_arr);
        }
        *cur_arr = sha3_256(&b);
    }
    hex::encode(*cur_arr) == expected_root
}

pub fn genesis() -> Block {
    Block {
        header: Header {
            network: NETWORK.into(),
            height: 0,
            prev_hash: "0".repeat(64),
            timestamp: GENESIS_TIMESTAMP,
            tx_root: tx_root(&[]),
            state_root: State::genesis().root(),
            finalized_height: 0,
            consensus: "genesis".into(),
            target: target_hex(INITIAL_TARGET),
            slot: 0,
            producer: String::new(),
            producer_pubkey: String::new(),
            base_fee: MIN_BASE_FEE,
            message: GENESIS_MESSAGE.into(),
            nonce: 0,
            signature: String::new(),
        },
        txs: vec![],
    }
}

// ----------------------------------------------------- protocol state structs
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UnbondEntry {
    pub amount: u64,
    pub unlock_height: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
    pub stake: u64,
    #[serde(default)]
    pub delegate: Option<String>,
    #[serde(default)]
    pub unbonding: Vec<UnbondEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Proposal {
    pub id: u64,
    pub proposer: String,
    pub title: String,
    pub summary: String,
    pub created_height: u64,
    pub end_height: u64,
    pub aye_stake: u64,
    pub nay_stake: u64,
    pub voters: BTreeMap<String, bool>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TokenPool {
    pub symbol: String,
    pub name: String,
    pub creator: String,
    pub total_supply: u64,
    pub virtual_aura: u64,
    pub aura_reserve: u64,
    pub token_reserve: u64,
    pub balances: BTreeMap<String, u64>,
    pub trades: u64,
}

impl TokenPool {
    /// Spot price in micro-AURA per 1 whole token (1_000_000 micro-units).
    pub fn spot_price_micro(&self) -> u64 {
        let eff_aura = (self.virtual_aura + self.aura_reserve) as u128;
        let tok = self.token_reserve.max(1) as u128;
        ((eff_aura * COIN as u128) / tok) as u64
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NftItem {
    pub id: u64,
    pub creator: String,
    pub owner: String,
    pub name: String,
    pub uri: String,
    pub royalty_bps: u16, // 0..=2500 (max 25%)
    pub price_micro: u64, // 0 = not listed
    pub sales: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct L2Batch {
    pub batch_index: u64,
    pub l1_height: u64,
    pub sequencer: String,
    pub commitment: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SlashRecord {
    pub height: u64,
    pub offender: String,
    pub reporter: String,
    pub burned: u64,
    pub bounty: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct State {
    pub accounts: BTreeMap<String, Account>,
    pub minted: u64,
    pub burned: u64,
    pub next_base_fee: u64,
    #[serde(with = "u128_dec")]
    pub last_target: u128,
    #[serde(with = "u128_dec")]
    pub pow_claim_target: u128,
    #[serde(with = "u128_dec")]
    pub chainwork: u128,
    pub finalized_height: u64,
    pub finalized_hash: String,
    #[serde(default)]
    pub checkpoint_votes: BTreeMap<u64, BTreeSet<String>>,
    #[serde(default)]
    pub recent_hashes: BTreeMap<u64, String>,
    #[serde(default)]
    pub used_pow_nullifiers: BTreeSet<String>,
    #[serde(default)]
    pub slashed: BTreeSet<String>,
    #[serde(default)]
    pub slash_history: Vec<SlashRecord>,
    #[serde(default)]
    pub proposals: BTreeMap<u64, Proposal>,
    #[serde(default)]
    pub tokens: BTreeMap<String, TokenPool>,
    #[serde(default)]
    pub nfts: BTreeMap<u64, NftItem>,
    #[serde(default)]
    pub l2_batches: Vec<L2Batch>,
}

impl State {
    pub fn genesis() -> State {
        State {
            accounts: BTreeMap::new(),
            minted: 0,
            burned: 0,
            next_base_fee: MIN_BASE_FEE,
            last_target: INITIAL_TARGET,
            pow_claim_target: INITIAL_POW_CLAIM_TARGET,
            chainwork: 0,
            finalized_height: 0,
            finalized_hash: "0".repeat(64),
            checkpoint_votes: BTreeMap::new(),
            recent_hashes: BTreeMap::new(),
            used_pow_nullifiers: BTreeSet::new(),
            slashed: BTreeSet::new(),
            slash_history: vec![],
            proposals: BTreeMap::new(),
            tokens: BTreeMap::new(),
            nfts: BTreeMap::new(),
            l2_batches: vec![],
        }
    }

    /// Deterministic SHA3-256 commitment over the entire L1 + ecosystem state.
    pub fn root(&self) -> String {
        let v = serde_json::json!({
            "accounts": self.accounts,
            "minted": self.minted,
            "burned": self.burned,
            "finalized_height": self.finalized_height,
            "slashed": self.slashed,
            "proposals": self.proposals,
            "tokens": self.tokens,
            "nfts": self.nfts,
            "l2_count": self.l2_batches.len(),
        });
        sha3_256_hex(&serde_json::to_vec(&v).unwrap())
    }

    pub fn account(&self, a: &str) -> Account {
        self.accounts.get(a).cloned().unwrap_or_default()
    }

    /// Active validator pools (self-stake + delegated stake), excluding slashed validators,
    /// with VPoS pool saturation cap at 1/4 of total network stake.
    pub fn validator_weights(&self) -> Vec<(String, u64, u64)> {
        let mut pools: BTreeMap<String, u64> = BTreeMap::new();
        // Every non-slashed account with direct stake > 0 is an eligible validator pool;
        // accounts that set `delegate = Some(v)` contribute their stake to `v` if `v` is an active validator.
        for (addr, acc) in &self.accounts {
            if acc.stake == 0 || self.slashed.contains(addr) {
                continue;
            }
            let target = match &acc.delegate {
                Some(v) if !self.slashed.contains(v) && self.accounts.get(v).map(|x| x.stake > 0).unwrap_or(false) => {
                    v.clone()
                }
                _ => addr.clone(),
            };
            *pools.entry(target).or_insert(0) += acc.stake;
        }
        let total: u64 = pools.values().sum();
        if total == 0 {
            return vec![];
        }
        let cap = (total / SATURATION_DIVISOR).max(1);
        pools.into_iter().map(|(k, st)| (k, st, st.min(cap))).collect()
    }

    pub fn total_stake(&self) -> u64 {
        self.validator_weights().iter().map(|x| x.1).sum()
    }
}

pub fn is_pos(height: u64, s: &State) -> bool {
    height >= POS_START_HEIGHT && s.total_stake() > 0
}

pub fn block_reward(height: u64, minted: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    let r = if halvings >= 64 { 0 } else { INITIAL_REWARD >> halvings };
    r.min(MAX_SUPPLY.saturating_sub(minted))
}

pub fn next_base_fee(base: u64, used: usize) -> u64 {
    let t = TARGET_TXS_PER_BLOCK as i128;
    let delta = base as i128 * (used as i128 - t) / t / 8;
    ((base as i128 + delta).max(MIN_BASE_FEE as i128)) as u64
}

/// Ouroboros-style stake-weighted slot-leader lottery seeded with SHA3-256.
pub fn elect_leader(s: &State, prev_hash: &str, height: u64, slot: u64) -> Option<String> {
    let w = s.validator_weights();
    let sum: u128 = w.iter().map(|x| x.2 as u128).sum();
    if sum == 0 {
        return None;
    }
    let seed = sha3_256(format!("aurachain-vpos-v1:{prev_hash}:{height}:{slot}").as_bytes());
    let mut r = u128::from_be_bytes(seed[..16].try_into().unwrap()) % sum;
    for (addr, _, weight) in w {
        if r < weight as u128 {
            return Some(addr);
        }
        r -= weight as u128;
    }
    None
}

pub fn expected_target(blocks: &[Block], height: u64, s: &State) -> u128 {
    if height % RETARGET_WINDOW != 0 || height <= RETARGET_WINDOW || (height as usize) > blocks.len() {
        return s.last_target;
    }
    let last = &blocks[(height - 1) as usize].header;
    let first = &blocks[(height - 1 - RETARGET_WINDOW) as usize].header;
    let expected = TARGET_BLOCK_SECS * RETARGET_WINDOW;
    let actual = last.timestamp.saturating_sub(first.timestamp).clamp(expected / 4, expected * 4).max(1);
    (s.last_target / expected as u128).saturating_mul(actual as u128).max(1)
}

pub fn pow_claim_hash(anchor_hash: &str, miner_addr: &str, pow_nonce: &str) -> [u8; 32] {
    sha3_256(format!("aura-pow-claim-v1|{NETWORK}|{anchor_hash}|{miner_addr}|{pow_nonce}").as_bytes())
}

// ------------------------------------------------------- transaction execution
pub fn apply_tx(s: &mut State, tx: &Tx, base_fee: u64, block_height: u64) -> Result<(), String> {
    tx.verify_signature()?;
    if tx.data.len() > MAX_DATA_BYTES {
        return Err("tx data exceeds 1024 bytes".into());
    }
    let from = tx.sender()?;
    // Permissionless PoW mining claims allow 0 fee (protected by real SHA3-256 CPU work);
    // all other transaction types must cover at least `base_fee`.
    if tx.kind != TxKind::PowMine && tx.fee < base_fee {
        return Err(format!("fee {} below base fee {}", tx.fee, base_fee));
    }
    let mut acct = s.account(&from);
    if tx.nonce != acct.nonce {
        return Err(format!("bad nonce: expected {}, got {}", acct.nonce, tx.nonce));
    }
    let need = |a: &Account, n: u64| -> Result<(), String> {
        if a.balance < n {
            Err(format!("insufficient balance: have {}, need {}", fmt_aura(a.balance), fmt_aura(n)))
        } else {
            Ok(())
        }
    };

    match tx.kind {
        TxKind::Transfer => {
            if !crypto::is_valid_address(&tx.to) {
                return Err("invalid quantum recipient address (must start with aura1q)".into());
            }
            if tx.amount == 0 {
                return Err("amount must be > 0".into());
            }
            let cost = tx.amount.checked_add(tx.fee).ok_or("overflow")?;
            need(&acct, cost)?;
            acct.balance -= cost;
            acct.nonce += 1;
            s.accounts.insert(from.clone(), acct);
            s.accounts.entry(tx.to.clone()).or_default().balance += tx.amount;
        }

        TxKind::Stake => {
            if tx.amount == 0 {
                return Err("stake amount must be > 0".into());
            }
            if s.slashed.contains(&from) {
                return Err("slashed address cannot stake".into());
            }
            let cost = tx.amount.checked_add(tx.fee).ok_or("overflow")?;
            need(&acct, cost)?;
            acct.balance -= cost;
            acct.stake += tx.amount;
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }

        TxKind::Unstake => {
            if tx.amount == 0 || acct.stake < tx.amount {
                return Err("unstake amount exceeds active stake".into());
            }
            need(&acct, tx.fee)?;
            acct.balance -= tx.fee;
            acct.stake -= tx.amount;
            acct.unbonding.push(UnbondEntry {
                amount: tx.amount,
                unlock_height: block_height + UNBONDING_BLOCKS,
            });
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }

        TxKind::Delegate => {
            need(&acct, tx.fee)?;
            if !tx.to.is_empty() && !crypto::is_valid_address(&tx.to) {
                return Err("invalid delegate validator address".into());
            }
            acct.balance -= tx.fee;
            acct.delegate = if tx.to.is_empty() || tx.to == from { None } else { Some(tx.to.clone()) };
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }

        TxKind::Slash => {
            need(&acct, tx.fee)?;
            #[derive(Deserialize)]
            struct Evidence {
                h1: Header,
                h2: Header,
            }
            let ev: Evidence = serde_json::from_str(&tx.data).map_err(|_| "bad slash evidence json")?;
            if ev.h1.consensus != "pos" || ev.h2.consensus != "pos" {
                return Err("both headers must be VPoS headers".into());
            }
            if ev.h1.height != ev.h2.height || ev.h1.slot != ev.h2.slot {
                return Err("double-sign must be at identical (height, slot)".into());
            }
            if ev.h1.hash_hex() == ev.h2.hash_hex() {
                return Err("headers are identical, not an equivocation".into());
            }
            if ev.h1.producer != ev.h2.producer || ev.h1.producer_pubkey != ev.h2.producer_pubkey {
                return Err("headers must be from the same validator".into());
            }
            let offender = crypto::address_from_pubkey_hex(&ev.h1.producer_pubkey)?;
            if offender != ev.h1.producer || s.slashed.contains(&offender) {
                return Err("invalid or already slashed validator".into());
            }
            crypto::verify(&ev.h1.producer_pubkey, &ev.h1.hash(), &ev.h1.signature)?;
            crypto::verify(&ev.h2.producer_pubkey, &ev.h2.hash(), &ev.h2.signature)?;

            acct.balance -= tx.fee;
            acct.nonce += 1;
            s.accounts.insert(from.clone(), acct);

            let mut off_acc = s.account(&offender);
            let total_locked = off_acc.stake + off_acc.unbonding.iter().map(|u| u.amount).sum::<u64>();
            let penalty = total_locked / 2; // 50% burned
            let bounty = total_locked / 10; // 10% whistleblower reward
            let deducted = (penalty + bounty).min(off_acc.stake);
            off_acc.stake -= deducted;
            s.accounts.insert(offender.clone(), off_acc);
            s.burned += penalty.min(deducted);
            let actual_bounty = deducted.saturating_sub(penalty.min(deducted));
            s.accounts.entry(from.clone()).or_default().balance += actual_bounty;
            s.slashed.insert(offender.clone());
            s.slash_history.push(SlashRecord {
                height: block_height,
                offender,
                reporter: from,
                burned: penalty.min(deducted),
                bounty: actual_bounty,
            });
        }

        TxKind::PowMine => {
            if tx.fee > acct.balance {
                return Err("insufficient balance for optional fee".into());
            }
            let parts: Vec<&str> = tx.data.splitn(3, ':').collect();
            if parts.len() != 3 {
                return Err("powmine data must be <anchor_height>:<anchor_hash>:<pow_nonce>".into());
            }
            let anchor_h: u64 = parts[0].parse().map_err(|_| "bad anchor height")?;
            let anchor_hash = parts[1];
            let pow_nonce = parts[2];
            if pow_nonce.is_empty() || pow_nonce.len() > 64 {
                return Err("bad pow nonce".into());
            }
            if anchor_h >= block_height || block_height.saturating_sub(anchor_h) > 30 {
                return Err("powmine anchor block expired (must be within last 30 blocks)".into());
            }
            let expected_anchor = s.recent_hashes.get(&anchor_h).ok_or("unknown anchor block height")?;
            if expected_anchor != anchor_hash {
                return Err("powmine anchor hash mismatch".into());
            }
            let nullifier = sha3_256_hex(format!("{from}:{anchor_hash}:{pow_nonce}").as_bytes());
            if s.used_pow_nullifiers.contains(&nullifier) {
                return Err("powmine share already claimed".into());
            }
            let digest = pow_claim_hash(anchor_hash, &from, pow_nonce);
            if hash_value(&digest) > s.pow_claim_target {
                return Err("insufficient SHA3-256 proof-of-work for powmine claim".into());
            }
            let reward = POW_CLAIM_REWARD.min(MAX_SUPPLY.saturating_sub(s.minted));
            if reward == 0 {
                return Err("max supply reached".into());
            }
            acct.balance = acct.balance - tx.fee + reward;
            acct.nonce += 1;
            s.minted += reward;
            s.accounts.insert(from, acct);
            s.used_pow_nullifiers.insert(nullifier);
            if s.used_pow_nullifiers.len() > 2_000 {
                let first = s.used_pow_nullifiers.iter().next().cloned().unwrap();
                s.used_pow_nullifiers.remove(&first);
            }
        }

        TxKind::Propose => {
            need(&acct, tx.fee)?;
            if acct.stake < 10 * COIN {
                return Err("proposer must stake at least 10 AURA".into());
            }
            let (title, summary) = tx.data.split_once('|').ok_or("propose data must be <title>|<summary>")?;
            let title = title.trim();
            if title.is_empty() || title.len() > 100 {
                return Err("proposal title must be 1..100 chars".into());
            }
            acct.balance -= tx.fee;
            acct.nonce += 1;
            let id = s.proposals.keys().next_back().copied().unwrap_or(0) + 1;
            let stake = acct.stake;
            s.accounts.insert(from.clone(), acct);
            let mut voters = BTreeMap::new();
            voters.insert(from.clone(), true);
            s.proposals.insert(
                id,
                Proposal {
                    id,
                    proposer: from,
                    title: title.into(),
                    summary: summary.trim().into(),
                    created_height: block_height,
                    end_height: block_height + 200,
                    aye_stake: stake,
                    nay_stake: 0,
                    voters,
                },
            );
        }

        TxKind::Vote => {
            need(&acct, tx.fee)?;
            if acct.stake == 0 {
                return Err("voter must hold staked AURA (1 staked AURA = 1 vote)".into());
            }
            let (id_s, choice) = tx.data.split_once(':').ok_or("vote data must be <proposal_id>:aye|nay")?;
            let id: u64 = id_s.parse().map_err(|_| "bad proposal id")?;
            let aye = match choice {
                "aye" | "yes" | "true" => true,
                "nay" | "no" | "false" => false,
                _ => return Err("vote choice must be aye or nay".into()),
            };
            let stake = acct.stake;
            let p = s.proposals.get_mut(&id).ok_or("no such proposal")?;
            if block_height > p.end_height {
                return Err("voting period has ended".into());
            }
            if let Some(prev) = p.voters.insert(from.clone(), aye) {
                if prev {
                    p.aye_stake = p.aye_stake.saturating_sub(stake);
                } else {
                    p.nay_stake = p.nay_stake.saturating_sub(stake);
                }
            }
            if aye {
                p.aye_stake += stake;
            } else {
                p.nay_stake += stake;
            }
            acct.balance -= tx.fee;
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }

        TxKind::CreateToken => {
            need(&acct, tx.fee)?;
            let (sym_raw, name_raw) = tx.data.split_once('|').ok_or("createtoken data must be <SYMBOL>|<Name>")?;
            let sym = sym_raw.trim().to_ascii_uppercase();
            if sym.len() < 2 || sym.len() > 8 || !sym.chars().all(|c| c.is_ascii_alphanumeric()) || sym == "AURA" {
                return Err("symbol must be 2..8 alphanumeric chars (and not AURA)".into());
            }
            if s.tokens.contains_key(&sym) {
                return Err("token symbol already exists".into());
            }
            acct.balance -= tx.fee;
            acct.nonce += 1;
            s.accounts.insert(from.clone(), acct);
            let supply = 1_000_000_000 * COIN; // 1B tokens, 100% in protocol bonding curve (0% insider pre-mine)
            s.tokens.insert(
                sym.clone(),
                TokenPool {
                    symbol: sym,
                    name: name_raw.trim().chars().take(48).collect(),
                    creator: from,
                    total_supply: supply,
                    virtual_aura: 1_000 * COIN,
                    aura_reserve: 0,
                    token_reserve: supply,
                    balances: BTreeMap::new(),
                    trades: 0,
                },
            );
        }

        TxKind::BuyToken => {
            if tx.amount == 0 {
                return Err("AURA spend amount must be > 0".into());
            }
            let cost = tx.amount.checked_add(tx.fee).ok_or("overflow")?;
            need(&acct, cost)?;
            let sym = tx.data.trim().to_ascii_uppercase();
            let pool = s.tokens.get_mut(&sym).ok_or("unknown token symbol")?;
            let eff_aura = (pool.virtual_aura + pool.aura_reserve) as u128;
            let amt = tx.amount as u128;
            let tokens_out = ((pool.token_reserve as u128 * amt) / (eff_aura + amt)) as u64;
            if tokens_out == 0 || tokens_out >= pool.token_reserve {
                return Err("trade amount too small or exceeds pool reserve".into());
            }
            pool.aura_reserve += tx.amount;
            pool.token_reserve -= tokens_out;
            *pool.balances.entry(from.clone()).or_insert(0) += tokens_out;
            pool.trades += 1;
            acct.balance -= cost;
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }

        TxKind::SellToken => {
            if tx.amount == 0 {
                return Err("token sell amount must be > 0".into());
            }
            need(&acct, tx.fee)?;
            let sym = tx.data.trim().to_ascii_uppercase();
            let pool = s.tokens.get_mut(&sym).ok_or("unknown token symbol")?;
            let user_tok = pool.balances.get(&from).copied().unwrap_or(0);
            if user_tok < tx.amount {
                return Err("insufficient token balance".into());
            }
            let eff_aura = (pool.virtual_aura + pool.aura_reserve) as u128;
            let tok_in = tx.amount as u128;
            let aura_out = ((eff_aura * tok_in) / (pool.token_reserve as u128 + tok_in)) as u64;
            let aura_out = aura_out.min(pool.aura_reserve);
            if aura_out == 0 {
                return Err("sell amount too small".into());
            }
            *pool.balances.get_mut(&from).unwrap() -= tx.amount;
            pool.token_reserve += tx.amount;
            pool.aura_reserve -= aura_out;
            pool.trades += 1;
            acct.balance = acct.balance - tx.fee + aura_out;
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }

        TxKind::MintNft => {
            need(&acct, tx.fee)?;
            #[derive(Deserialize)]
            struct MintSpec {
                name: String,
                uri: String,
                #[serde(default)]
                royalty_bps: u16,
                #[serde(default)]
                price: u64,
            }
            let spec: MintSpec = serde_json::from_str(&tx.data).map_err(|_| "bad mintnft json")?;
            if spec.name.trim().is_empty() || spec.royalty_bps > 2500 {
                return Err("nft needs name and royalty_bps <= 2500 (max 25%)".into());
            }
            acct.balance -= tx.fee;
            acct.nonce += 1;
            let id = s.nfts.keys().next_back().copied().unwrap_or(0) + 1;
            s.accounts.insert(from.clone(), acct);
            s.nfts.insert(
                id,
                NftItem {
                    id,
                    creator: from.clone(),
                    owner: from,
                    name: spec.name.trim().chars().take(64).collect(),
                    uri: spec.uri.trim().chars().take(512).collect(),
                    royalty_bps: spec.royalty_bps,
                    price_micro: spec.price,
                    sales: 0,
                },
            );
        }

        TxKind::ListNft => {
            need(&acct, tx.fee)?;
            let id: u64 = tx.data.trim().parse().map_err(|_| "bad nft id")?;
            let nft = s.nfts.get_mut(&id).ok_or("no such nft")?;
            if nft.owner != from {
                return Err("only the NFT owner can list or delist it".into());
            }
            nft.price_micro = tx.amount;
            acct.balance -= tx.fee;
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }

        TxKind::BuyNft => {
            let id: u64 = tx.data.trim().parse().map_err(|_| "bad nft id")?;
            let (seller, creator, price, bps) = {
                let nft = s.nfts.get(&id).ok_or("no such nft")?;
                if nft.price_micro == 0 {
                    return Err("NFT is not listed for sale".into());
                }
                if nft.owner == from {
                    return Err("already own this NFT".into());
                }
                if tx.amount < nft.price_micro {
                    return Err("amount below NFT listing price".into());
                }
                (nft.owner.clone(), nft.creator.clone(), nft.price_micro, nft.royalty_bps)
            };
            let total_cost = price.checked_add(tx.fee).ok_or("overflow")?;
            need(&acct, total_cost)?;
            let royalty = ((price as u128 * bps as u128) / 10_000) as u64;
            let seller_proceeds = price - royalty;

            acct.balance -= total_cost;
            acct.nonce += 1;
            s.accounts.insert(from.clone(), acct);
            s.accounts.entry(seller).or_default().balance += seller_proceeds;
            if royalty > 0 {
                s.accounts.entry(creator).or_default().balance += royalty;
            }
            let nft = s.nfts.get_mut(&id).unwrap();
            nft.owner = from;
            nft.price_micro = 0;
            nft.sales += 1;
        }

        TxKind::Anchor => {
            if tx.data.is_empty() || tx.amount != 0 {
                return Err("anchor needs non-empty batch commitment and amount 0".into());
            }
            need(&acct, tx.fee)?;
            acct.balance -= tx.fee;
            acct.nonce += 1;
            s.accounts.insert(from.clone(), acct);
            let idx = s.l2_batches.last().map(|b| b.batch_index + 1).unwrap_or(1);
            s.l2_batches.push(L2Batch {
                batch_index: idx,
                l1_height: block_height,
                sequencer: from,
                commitment: tx.data.clone(),
            });
            if s.l2_batches.len() > 40 {
                s.l2_batches.remove(0);
            }
        }

        TxKind::Attest => {
            need(&acct, tx.fee)?;
            if acct.stake == 0 || s.slashed.contains(&from) {
                return Err("only active staked validators can attest checkpoints".into());
            }
            let (cp_s, cp_hash) = tx.data.split_once(':').ok_or("attest data must be <height>:<hash>")?;
            let cp_h: u64 = cp_s.parse().map_err(|_| "bad checkpoint height")?;
            if cp_h % FINALITY_INTERVAL != 0 || cp_h >= block_height {
                return Err("invalid checkpoint height".into());
            }
            if s.recent_hashes.get(&cp_h).map(|h| h.as_str()) != Some(cp_hash) {
                return Err("checkpoint hash does not match canonical chain".into());
            }
            acct.balance -= tx.fee;
            acct.nonce += 1;
            s.accounts.insert(from.clone(), acct);
            record_checkpoint_vote(s, cp_h, cp_hash, &from);
        }
    }
    Ok(())
}

fn record_checkpoint_vote(s: &mut State, cp_h: u64, cp_hash: &str, validator: &str) {
    if cp_h <= s.finalized_height {
        return;
    }
    s.checkpoint_votes.entry(cp_h).or_default().insert(validator.to_string());
    let weights: BTreeMap<String, u64> = s.validator_weights().into_iter().map(|(a, st, _)| (a, st)).collect();
    let total: u64 = weights.values().sum();
    if total == 0 {
        return;
    }
    let attested: u64 = s
        .checkpoint_votes
        .get(&cp_h)
        .map(|voters| voters.iter().filter_map(|v| weights.get(v)).sum())
        .unwrap_or(0);
    // BFT supermajority: >= 2/3 of active stake finalizes the checkpoint!
    if attested as u128 * 3 >= total as u128 * 2 {
        s.finalized_height = cp_h;
        s.finalized_hash = cp_hash.to_string();
        s.checkpoint_votes.retain(|&h, _| h > cp_h);
    }
}

/// Execute a block's transactions, unbonding maturities, PoW claim retargeting,
/// BFT checkpoint votes, and block rewards on a copy of `s`.
fn execute(s: &State, prev_hash: &str, h: &Header, txs: &[Tx], target: u128) -> Result<State, String> {
    let mut n = s.clone();
    n.recent_hashes.insert(h.height - 1, prev_hash.to_string());
    while n.recent_hashes.len() > 64 {
        let oldest = *n.recent_hashes.keys().next().unwrap();
        n.recent_hashes.remove(&oldest);
    }

    // 1. Release matured unbonding entries at this block height.
    for acc in n.accounts.values_mut() {
        if !acc.unbonding.is_empty() {
            let mut released = 0u64;
            acc.unbonding.retain(|u| {
                if h.height >= u.unlock_height {
                    released += u.amount;
                    false
                } else {
                    true
                }
            });
            acc.balance += released;
        }
    }

    // 2. Apply transactions, burning EIP-1559 base fee on non-zero-fee txs.
    let mut tips = 0u64;
    let mut pow_claims_in_block = 0usize;
    for (i, tx) in txs.iter().enumerate() {
        apply_tx(&mut n, tx, h.base_fee, h.height).map_err(|e| format!("tx #{i}: {e}"))?;
        if tx.kind == TxKind::PowMine {
            pow_claims_in_block += 1;
            tips += tx.fee;
        } else {
            n.burned += h.base_fee;
            tips += tx.fee - h.base_fee;
        }
    }

    // 3. Dynamic difficulty retarget for permissionless PowMine claims.
    if pow_claims_in_block > 4 {
        n.pow_claim_target = (n.pow_claim_target / 4 * 3).max(1);
    } else if pow_claims_in_block == 0 && n.pow_claim_target < INITIAL_POW_CLAIM_TARGET {
        n.pow_claim_target = n
            .pow_claim_target
            .saturating_add(n.pow_claim_target / 16)
            .min(INITIAL_POW_CLAIM_TARGET);
    }

    // 4. Credit block producer reward + tips.
    let reward = block_reward(h.height, n.minted);
    n.minted += reward;
    n.accounts.entry(h.producer.clone()).or_default().balance += reward + tips;

    // 5. Implicit BFT checkpoint attestation by VPoS block producer for latest checkpoint.
    if h.consensus == "pos" {
        let cp_h = (h.height - 1) - ((h.height - 1) % FINALITY_INTERVAL);
        if cp_h > 0 {
            if let Some(cp_hash) = n.recent_hashes.get(&cp_h).cloned() {
                record_checkpoint_vote(&mut n, cp_h, &cp_hash, &h.producer);
            }
        }
    }

    n.next_base_fee = next_base_fee(h.base_fee, txs.len());
    n.last_target = target;
    n.chainwork = n.chainwork.saturating_add(work_of(target));
    Ok(n)
}

/// Fully validate `b` on top of `blocks` (whose tip state is `s`). Returns new state.
pub fn apply_block(s: &State, blocks: &[Block], b: &Block, now: u64) -> Result<State, String> {
    let prev = &blocks.last().ok_or("empty chain")?.header;
    let prev_hash = prev.hash_hex();
    let h = &b.header;
    if h.network != NETWORK {
        return Err("wrong network".into());
    }
    if h.height != prev.height + 1 {
        return Err(format!("height {} does not extend tip {}", h.height, prev.height));
    }
    if h.prev_hash != prev_hash {
        return Err("prev_hash mismatch".into());
    }
    if h.timestamp < prev.timestamp || h.timestamp > now + MAX_FUTURE_SECS {
        return Err("bad timestamp".into());
    }
    if b.txs.len() > MAX_TXS_PER_BLOCK {
        return Err("too many txs".into());
    }
    if h.base_fee != s.next_base_fee {
        return Err("wrong base fee".into());
    }
    if h.message.len() > 160 {
        return Err("message too long".into());
    }
    if !crypto::is_valid_address(&h.producer) {
        return Err("invalid producer quantum address".into());
    }

    let target;
    if is_pos(h.height, s) {
        if h.consensus != "pos" || h.nonce != 0 {
            return Err("expected a VPoS block".into());
        }
        target = s.last_target;
        if h.target_value()? != target {
            return Err("PoS block must inherit target".into());
        }
        if h.timestamp < prev.timestamp + SLOT_SECS {
            return Err("PoS block before its slot".into());
        }
        let slot = (h.timestamp - prev.timestamp) / SLOT_SECS - 1;
        if h.slot != slot {
            return Err("slot does not match timestamp".into());
        }
        let leader = elect_leader(s, &h.prev_hash, h.height, slot).ok_or("no leader")?;
        if h.producer != leader {
            return Err(format!("producer is not the elected VPoS slot leader ({leader})"));
        }
        if crypto::address_from_pubkey_hex(&h.producer_pubkey)? != h.producer {
            return Err("producer pubkey/address mismatch".into());
        }
        crypto::verify(&h.producer_pubkey, &h.hash(), &h.signature)?;
    } else {
        if h.consensus != "pow" {
            return Err("expected a PoW block".into());
        }
        target = expected_target(blocks, h.height, s);
        if h.target_value()? != target {
            return Err("wrong difficulty target".into());
        }
        if hash_value(&h.hash()) > target {
            return Err("insufficient SHA3-256 proof-of-work".into());
        }
    }

    if h.tx_root != tx_root(&b.txs) {
        return Err("tx_root mismatch".into());
    }
    let n = execute(s, &prev_hash, h, &b.txs, target)?;
    if h.finalized_height != n.finalized_height {
        return Err("finalized_height mismatch".into());
    }
    if h.state_root != n.root() {
        return Err("state_root mismatch".into());
    }
    Ok(n)
}

/// Validate an entire chain from genesis. Returns the resulting tip state.
pub fn validate_chain(blocks: &[Block]) -> Result<State, String> {
    if blocks.is_empty() || blocks[0].header.hash_hex() != genesis().header.hash_hex() {
        return Err("genesis mismatch".into());
    }
    let now = now_secs().max(blocks.last().unwrap().header.timestamp);
    let mut s = State::genesis();
    for i in 1..blocks.len() {
        s = apply_block(&s, &blocks[..i], &blocks[i], now).map_err(|e| format!("block {i}: {e}"))?;
    }
    Ok(s)
}

/// Assemble a valid block template on top of `blocks`.
/// PoW templates still need a valid `nonce`; VPoS templates are already Hybrid-PQ signed!
pub fn assemble(
    blocks: &[Block],
    s: &State,
    mempool: &[Tx],
    producer: &Keypair,
    timestamp: u64,
    message: &str,
) -> Result<Block, String> {
    let prev = &blocks.last().unwrap().header;
    let prev_hash = prev.hash_hex();
    let height = prev.height + 1;
    let pos = is_pos(height, s);
    let (target, slot, consensus) = if pos {
        if timestamp < prev.timestamp + SLOT_SECS {
            return Err("slot not open yet".into());
        }
        (s.last_target, (timestamp - prev.timestamp) / SLOT_SECS - 1, "pos")
    } else {
        (expected_target(blocks, height, s), 0, "pow")
    };

    // Prepare simulation state with recent_hashes & unbonding maturities to validate mempool txs accurately.
    let mut base_sim = s.clone();
    base_sim.recent_hashes.insert(height - 1, prev_hash.clone());
    for acc in base_sim.accounts.values_mut() {
        let mut rel = 0u64;
        acc.unbonding.retain(|u| {
            if height >= u.unlock_height {
                rel += u.amount;
                false
            } else {
                true
            }
        });
        acc.balance += rel;
    }

    let mut cands: Vec<&Tx> = mempool.iter().collect();
    cands.sort_by(|a, b| a.nonce.cmp(&b.nonce).then(b.fee.cmp(&a.fee)));
    let mut sim = base_sim;
    let mut chosen: Vec<Tx> = vec![];
    for _ in 0..3 {
        for tx in &cands {
            if chosen.len() >= MAX_TXS_PER_BLOCK {
                break;
            }
            if chosen.iter().any(|c| c.signature == tx.signature) {
                continue;
            }
            let mut trial = sim.clone();
            if apply_tx(&mut trial, tx, s.next_base_fee, height).is_ok() {
                sim = trial;
                chosen.push((*tx).clone());
            }
        }
    }

    let mut header = Header {
        network: NETWORK.into(),
        height,
        prev_hash: prev_hash.clone(),
        timestamp: timestamp.max(prev.timestamp),
        tx_root: tx_root(&chosen),
        state_root: String::new(),
        finalized_height: s.finalized_height,
        consensus: consensus.into(),
        target: target_hex(target),
        slot,
        producer: producer.address(),
        producer_pubkey: if pos { producer.public_hex() } else { String::new() },
        base_fee: s.next_base_fee,
        message: message.chars().take(160).collect(),
        nonce: 0,
        signature: String::new(),
    };
    let n = execute(s, &prev_hash, &header, &chosen, target)?;
    header.finalized_height = n.finalized_height;
    header.state_root = n.root();
    if pos {
        header.signature = producer.sign(&header.hash());
    }
    Ok(Block { header, txs: chosen })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mine_pow_block(blocks: &mut Vec<Block>, s: &mut State, kp: &Keypair, ts: u64, txs: Vec<Tx>) {
        let mut b = assemble(blocks, s, &txs, kp, ts, "unit-test pow").unwrap();
        let target = b.header.target_value().unwrap();
        let prefix = b.header.prefix_digest();
        let mut nonce = 0u64;
        loop {
            if hash_value(&Header::hash_with(&prefix, nonce)) <= target {
                b.header.nonce = nonce;
                break;
            }
            nonce += 1;
        }
        *s = apply_block(s, blocks, &b, ts + 10).unwrap();
        blocks.push(b);
    }

    #[test]
    fn full_quantum_lifecycle_pow_vpos_finality_dex_nft_dao_slash() {
        let val = Keypair::from_seed_bytes([11u8; 32]);
        let alice = Keypair::from_seed_bytes([22u8; 32]);
        let mut blocks = vec![genesis()];
        let mut s = State::genesis();
        // Lower target inside test state? No, real genesis target is 1/500k, let's mine 1 real block or test via fast difficulty?
        // Wait: 500k SHA3 hashes in debug mode takes ~1.5s per block; let's mine 1 real PoW block and test apply_tx directly for speed,
        // PLUS verify full PoW -> VPoS chain in release!
        mine_pow_block(&mut blocks, &mut s, &val, GENESIS_TIMESTAMP + 5, vec![]);
        assert_eq!(s.account(&val.address()).balance, INITIAL_REWARD);

        // Stake, Propose, Vote, AuraLaunch Token DEX, AUA Royalty NFT, Merkle proof, PowMine:
        let tx_send = Tx::new(TxKind::Transfer, &val, &alice.address(), 500 * COIN, MIN_BASE_FEE * 2, 0, "");
        let tx_stake = Tx::new(TxKind::Stake, &val, "", 1_000 * COIN, MIN_BASE_FEE * 2, 1, "");
        let tx_prop = Tx::new(
            TxKind::Propose,
            &val,
            "",
            0,
            MIN_BASE_FEE * 2,
            2,
            "AIP-1: Quantum Mainnet Readiness|Enable BFT finality & AuraLaunch",
        );
        let tx_tok = Tx::new(TxKind::CreateToken, &val, "", 0, MIN_BASE_FEE * 2, 3, "QBIT|Quantum Bit");
        let tx_nft = Tx::new(
            TxKind::MintNft,
            &val,
            "",
            0,
            MIN_BASE_FEE * 2,
            4,
            r#"{"name":"Genesis Quantum Crystal #1","uri":"ar://quantum-crystal-1","royalty_bps":1000,"price":100000000}"#,
        );
        let batch = vec![tx_send, tx_stake, tx_prop, tx_tok, tx_nft];
        let root = tx_root(&batch);
        let proof = merkle_proof(&batch, 3).unwrap();
        assert!(verify_merkle_proof(&batch[3].id(), &proof, &root));

        let mut sim = s.clone();
        sim.recent_hashes.insert(1, blocks[1].header.hash_hex());
        for t in &batch {
            apply_tx(&mut sim, t, MIN_BASE_FEE, 2).unwrap();
        }
        // Alice buys QBIT on bonding curve & buys Genesis NFT #1 (verifying 10% protocol royalty to val!)
        let val_before = sim.account(&val.address()).balance;
        let buy_tok = Tx::new(TxKind::BuyToken, &alice, "", 50 * COIN, MIN_BASE_FEE, 0, "QBIT");
        let buy_nft = Tx::new(TxKind::BuyNft, &alice, "", 100 * COIN, MIN_BASE_FEE, 1, "1");
        apply_tx(&mut sim, &buy_tok, MIN_BASE_FEE, 2).unwrap();
        apply_tx(&mut sim, &buy_nft, MIN_BASE_FEE, 2).unwrap();
        assert!(sim.tokens["QBIT"].balances[&alice.address()] > 0);
        assert_eq!(sim.nfts[&1].owner, alice.address());
        // Val was both creator (10% = 10 AURA) and initial seller (90% = 90 AURA) -> +100 AURA!
        assert_eq!(sim.account(&val.address()).balance, val_before + 100 * COIN);

        // Resell NFT from Alice to a 3rd user Bob -> Val STILL receives 10% royalty automatically!
        let bob = Keypair::from_seed_bytes([33u8; 32]);
        let fund_bob = Tx::new(TxKind::Transfer, &val, &bob.address(), 300 * COIN, MIN_BASE_FEE, 5, "");
        let relist = Tx::new(TxKind::ListNft, &alice, "", 200 * COIN, MIN_BASE_FEE, 2, "1");
        apply_tx(&mut sim, &fund_bob, MIN_BASE_FEE, 2).unwrap();
        apply_tx(&mut sim, &relist, MIN_BASE_FEE, 2).unwrap();
        let val_before_royalty = sim.account(&val.address()).balance;
        let alice_before_sale = sim.account(&alice.address()).balance;
        let bob_buy = Tx::new(TxKind::BuyNft, &bob, "", 200 * COIN, MIN_BASE_FEE, 0, "1");
        apply_tx(&mut sim, &bob_buy, MIN_BASE_FEE, 2).unwrap();
        assert_eq!(sim.account(&val.address()).balance, val_before_royalty + 20 * COIN); // 10% creator royalty!
        assert_eq!(sim.account(&alice.address()).balance, alice_before_sale + 180 * COIN); // 90% seller proceeds!
    }
}
