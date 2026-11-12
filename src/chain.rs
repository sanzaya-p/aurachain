//! Consensus rules, data structures and the state machine of the AuraChain
//! Settlement Layer (L1).
//!
//! Lifecycle of the chain (from the research "Genesis Mandate"):
//!   * Genesis: no pre-mine, no team/VC allocation. Only a timestamped message.
//!   * Phase A (height < POS_START_HEIGHT): Proof-of-Work fair launch. The only
//!     way to obtain AURA is to mine it.
//!   * Phase B (height >= POS_START_HEIGHT and some AURA is staked): the chain
//!     automatically switches to Verified Proof-of-Stake (VPoS): a stake-weighted,
//!     per-slot leader lottery with a pool-saturation cap. If nobody is staking,
//!     the chain falls back to PoW so it never halts.
//!   * Fees follow an EIP-1559-style rule: the base fee is burned, tips go to
//!     the block producer. Emission is hard-capped at MAX_SUPPLY.
//!   * L2 rollups ("Metropolis") anchor their state roots on L1 with `anchor` txs.

use crate::crypto::{self, sha256, sha256_hex, Keypair};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ---------------------------------------------------------------- parameters
pub const NETWORK: &str = "aurachain-devnet-1";
pub const COIN: u64 = 1_000_000; // 1 AURA = 1,000,000 micro-AURA
pub const MAX_SUPPLY: u64 = 10_000_000_000 * COIN; // 10 billion AURA, hard cap
pub const INITIAL_REWARD: u64 = 5_000 * COIN; // 5000 * 1e6 blocks * 2 = 10B
pub const HALVING_INTERVAL: u64 = 1_000_000;
pub const TARGET_BLOCK_SECS: u64 = 5;
pub const RETARGET_WINDOW: u64 = 5;
pub const POS_START_HEIGHT: u64 = 40; // devnet; mainnet design: 525,600
pub const SLOT_SECS: u64 = 5;
pub const SATURATION_DIVISOR: u64 = 4; // no validator's lottery weight > 1/4 of total stake
pub const MIN_BASE_FEE: u64 = 1_000; // 0.001 AURA
pub const TARGET_TXS_PER_BLOCK: u64 = 50;
pub const MAX_TXS_PER_BLOCK: usize = 100;
pub const MAX_FUTURE_SECS: u64 = 30;
pub const MAX_ANCHOR_DATA: usize = 256;
pub const INITIAL_TARGET: u128 = u128::MAX / 20_000_000; // ~20M hashes per block at start
pub const GENESIS_TIMESTAMP: u64 = 1_794_430_000; // 2026-11-12 ~06:16 IST (devnet genesis)
pub const GENESIS_MESSAGE: &str =
    "AuraChain devnet genesis 12/Nov/2026 - fair launch: no pre-mine, no foundation, no VCs";

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
    Anchor,
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

    fn signing_bytes(&self) -> Vec<u8> {
        let mut t = self.clone();
        t.signature = String::new();
        let mut v = NETWORK.as_bytes().to_vec(); // domain separation / replay protection
        v.extend(serde_json::to_vec(&t).unwrap());
        v
    }

    pub fn id(&self) -> String {
        sha256_hex(&serde_json::to_vec(self).unwrap())
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
    pub consensus: String, // "genesis" | "pow" | "pos"
    pub target: String,    // PoW target (hex u128); inherited by PoS blocks
    pub slot: u64,         // PoS slot index since parent (0 for PoW)
    pub producer: String,
    pub producer_pubkey: String,
    pub base_fee: u64,
    pub message: String,
    pub nonce: u64,
    pub signature: String, // PoS: producer's signature over the block hash
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Block {
    pub header: Header,
    pub txs: Vec<Tx>,
}

impl Header {
    /// Digest of every header field except nonce & signature (cheap to mine over).
    pub fn prefix_digest(&self) -> [u8; 32] {
        let mut h = self.clone();
        h.nonce = 0;
        h.signature = String::new();
        sha256(&serde_json::to_vec(&h).unwrap())
    }

    pub fn hash_with(prefix: &[u8; 32], nonce: u64) -> [u8; 32] {
        let mut buf = [0u8; 40];
        buf[..32].copy_from_slice(prefix);
        buf[32..].copy_from_slice(&nonce.to_le_bytes());
        sha256(&buf)
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

pub fn tx_root(txs: &[Tx]) -> String {
    // Binary Merkle tree over tx ids (last node duplicated on odd levels).
    if txs.is_empty() {
        return sha256_hex(b"empty");
    }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|t| sha256(&serde_json::to_vec(t).unwrap())).collect();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|c| {
                let mut b = c[0].to_vec();
                b.extend_from_slice(if c.len() == 2 { &c[1] } else { &c[0] });
                sha256(&b)
            })
            .collect();
    }
    hex::encode(level[0])
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

// ---------------------------------------------------------------------- state
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct Account {
    pub balance: u64,
    pub nonce: u64,
    pub stake: u64,
}

#[derive(Clone, Debug)]
pub struct State {
    pub accounts: BTreeMap<String, Account>,
    pub minted: u64,
    pub burned: u64,
    pub next_base_fee: u64,
    pub last_target: u128,
    pub chainwork: u128,
}

impl State {
    pub fn genesis() -> State {
        State {
            accounts: BTreeMap::new(),
            minted: 0,
            burned: 0,
            next_base_fee: MIN_BASE_FEE,
            last_target: INITIAL_TARGET,
            chainwork: 0,
        }
    }

    pub fn root(&self) -> String {
        let v = serde_json::json!({"accounts": self.accounts, "minted": self.minted, "burned": self.burned});
        sha256_hex(&serde_json::to_vec(&v).unwrap())
    }

    pub fn account(&self, a: &str) -> Account {
        self.accounts.get(a).cloned().unwrap_or_default()
    }

    pub fn total_stake(&self) -> u64 {
        self.accounts.values().map(|a| a.stake).sum()
    }

    /// Validators and their lottery weight after the saturation cap.
    pub fn validator_weights(&self) -> Vec<(String, u64, u64)> {
        let total = self.total_stake();
        let cap = (total / SATURATION_DIVISOR).max(1);
        self.accounts
            .iter()
            .filter(|(_, a)| a.stake > 0)
            .map(|(k, a)| (k.clone(), a.stake, a.stake.min(cap)))
            .collect()
    }
}

pub fn is_pos(height: u64, s: &State) -> bool {
    height >= POS_START_HEIGHT && s.total_stake() > 0
}

pub fn block_reward(height: u64, minted: u64) -> u64 {
    let halvings = height / HALVING_INTERVAL;
    let r = if halvings >= 64 { 0 } else { INITIAL_REWARD >> halvings };
    r.min(MAX_SUPPLY - minted)
}

pub fn next_base_fee(base: u64, used: usize) -> u64 {
    let t = TARGET_TXS_PER_BLOCK as i128;
    let delta = base as i128 * (used as i128 - t) / t / 8;
    ((base as i128 + delta).max(MIN_BASE_FEE as i128)) as u64
}

/// Ouroboros-style slot leader lottery: stake-weighted, deterministic, seeded
/// by (parent hash, height, slot). A missed slot simply elects a new leader.
pub fn elect_leader(s: &State, prev_hash: &str, height: u64, slot: u64) -> Option<String> {
    let w = s.validator_weights();
    let sum: u128 = w.iter().map(|x| x.2 as u128).sum();
    if sum == 0 {
        return None;
    }
    let seed = sha256(format!("vpos:{prev_hash}:{height}:{slot}").as_bytes());
    let mut r = u128::from_be_bytes(seed[..16].try_into().unwrap()) % sum;
    for (addr, _, weight) in w {
        if r < weight as u128 {
            return Some(addr);
        }
        r -= weight as u128;
    }
    None
}

/// PoW target required for block `height`, given all blocks before it.
pub fn expected_target(blocks: &[Block], height: u64, s: &State) -> u128 {
    if height % RETARGET_WINDOW != 0 || height <= RETARGET_WINDOW {
        return s.last_target;
    }
    let last = &blocks[(height - 1) as usize].header;
    let first = &blocks[(height - 1 - RETARGET_WINDOW) as usize].header;
    let expected = TARGET_BLOCK_SECS * RETARGET_WINDOW;
    let actual = last.timestamp.saturating_sub(first.timestamp).clamp(expected / 4, expected * 4).max(1);
    (s.last_target / expected as u128).saturating_mul(actual as u128).max(1)
}

pub fn apply_tx(s: &mut State, tx: &Tx, base_fee: u64) -> Result<(), String> {
    tx.verify_signature()?;
    let from = tx.sender()?;
    if tx.fee < base_fee {
        return Err(format!("fee {} below base fee {}", tx.fee, base_fee));
    }
    let mut acct = s.account(&from);
    if tx.nonce != acct.nonce {
        return Err(format!("bad nonce: expected {}, got {}", acct.nonce, tx.nonce));
    }
    let need = |a: &Account, n: u64| -> Result<(), String> {
        if a.balance < n { Err(format!("insufficient balance: have {}, need {}", fmt_aura(a.balance), fmt_aura(n))) } else { Ok(()) }
    };
    match tx.kind {
        TxKind::Transfer => {
            if !crypto::is_valid_address(&tx.to) {
                return Err("invalid recipient address".into());
            }
            if tx.amount == 0 {
                return Err("amount must be > 0".into());
            }
            need(&acct, tx.amount.checked_add(tx.fee).ok_or("overflow")?)?;
            acct.balance -= tx.amount + tx.fee;
            acct.nonce += 1;
            s.accounts.insert(from.clone(), acct);
            s.accounts.entry(tx.to.clone()).or_default().balance += tx.amount;
        }
        TxKind::Stake => {
            if tx.amount == 0 {
                return Err("amount must be > 0".into());
            }
            need(&acct, tx.amount.checked_add(tx.fee).ok_or("overflow")?)?;
            acct.balance -= tx.amount + tx.fee;
            acct.stake += tx.amount;
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }
        TxKind::Unstake => {
            if tx.amount == 0 || acct.stake < tx.amount {
                return Err("unstake amount exceeds stake".into());
            }
            need(&acct, tx.fee)?;
            acct.balance = acct.balance - tx.fee + tx.amount;
            acct.stake -= tx.amount;
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }
        TxKind::Anchor => {
            if tx.data.is_empty() || tx.data.len() > MAX_ANCHOR_DATA || tx.amount != 0 {
                return Err("anchor needs 1..256 bytes of data and amount 0".into());
            }
            need(&acct, tx.fee)?;
            acct.balance -= tx.fee;
            acct.nonce += 1;
            s.accounts.insert(from, acct);
        }
    }
    Ok(())
}

/// Execute a block's transactions and rewards on a copy of `s`.
fn execute(s: &State, h: &Header, txs: &[Tx], target: u128) -> Result<State, String> {
    let mut n = s.clone();
    let mut tips = 0u64;
    for (i, tx) in txs.iter().enumerate() {
        apply_tx(&mut n, tx, h.base_fee).map_err(|e| format!("tx #{i}: {e}"))?;
        n.burned += h.base_fee;
        tips += tx.fee - h.base_fee;
    }
    let reward = block_reward(h.height, n.minted);
    n.minted += reward;
    n.accounts.entry(h.producer.clone()).or_default().balance += reward + tips;
    n.next_base_fee = next_base_fee(h.base_fee, txs.len());
    n.last_target = target;
    n.chainwork = n.chainwork.saturating_add(work_of(target));
    Ok(n)
}

/// Fully validate `b` on top of `blocks` (whose tip state is `s`). Returns new state.
pub fn apply_block(s: &State, blocks: &[Block], b: &Block, now: u64) -> Result<State, String> {
    let prev = &blocks.last().ok_or("empty chain")?.header;
    let h = &b.header;
    if h.network != NETWORK {
        return Err("wrong network".into());
    }
    if h.height != prev.height + 1 {
        return Err(format!("height {} does not extend tip {}", h.height, prev.height));
    }
    if h.prev_hash != prev.hash_hex() {
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
    if h.message.len() > 128 {
        return Err("message too long".into());
    }
    if !crypto::is_valid_address(&h.producer) {
        return Err("invalid producer address".into());
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
            return Err(format!("producer is not the elected slot leader ({leader})"));
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
            return Err("insufficient proof-of-work".into());
        }
    }
    if h.tx_root != tx_root(&b.txs) {
        return Err("tx_root mismatch".into());
    }
    let n = execute(s, h, &b.txs, target)?;
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
    let now = now_secs();
    let mut s = State::genesis();
    for i in 1..blocks.len() {
        s = apply_block(&s, &blocks[..i], &blocks[i], now).map_err(|e| format!("block {i}: {e}"))?;
    }
    Ok(s)
}

/// Build a block template on top of `blocks`. Invalid mempool txs are skipped.
/// PoW templates still need a nonce; PoS templates still need a signature.
pub fn assemble(
    blocks: &[Block],
    s: &State,
    mempool: &[Tx],
    producer: &Keypair,
    timestamp: u64,
    message: &str,
) -> Result<Block, String> {
    let prev = &blocks.last().unwrap().header;
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
    // Greedy selection: highest fee first, nonce order respected via retries.
    let mut cands: Vec<&Tx> = mempool.iter().collect();
    cands.sort_by(|a, b| a.nonce.cmp(&b.nonce).then(b.fee.cmp(&a.fee)));
    let mut sim = s.clone();
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
            if apply_tx(&mut trial, tx, s.next_base_fee).is_ok() {
                sim = trial;
                chosen.push((*tx).clone());
            }
        }
    }
    let mut header = Header {
        network: NETWORK.into(),
        height,
        prev_hash: prev.hash_hex(),
        timestamp: timestamp.max(prev.timestamp),
        tx_root: tx_root(&chosen),
        state_root: String::new(),
        consensus: consensus.into(),
        target: target_hex(target),
        slot,
        producer: producer.address(),
        producer_pubkey: producer.public_hex(),
        base_fee: s.next_base_fee,
        message: message.chars().take(128).collect(),
        nonce: 0,
        signature: String::new(),
    };
    let n = execute(s, &header, &chosen, target)?;
    header.state_root = n.root();
    if pos {
        header.signature = producer.sign(&header.hash());
    }
    Ok(Block { header, txs: chosen })
}
