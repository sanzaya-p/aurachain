//! AuraChain serverless node for Vercel (Rust runtime).
//!
//! Vercel functions cannot run background loops, so this node is *request-driven*:
//! on every request it checks whether a VPoS slot is open and whether its
//! validator key is the elected leader; if so it produces the block right then
//! (immediately when transactions are pending, otherwise as a heartbeat every
//! HEARTBEAT_SECS). Consensus rules are exactly those of src/chain.rs - only the
//! production *policy* differs. State lives in Upstash Redis (Vercel Marketplace)
//! with atomic compare-and-swap writes, so concurrent invocations never fork.
//!
//! Env:
//!   KV_REST_API_URL / KV_REST_API_TOKEN   (or UPSTASH_REDIS_REST_URL / _TOKEN)
//!   AURA_VALIDATOR_KEY                    hex secret of the staked validator
//!   AURA_STORE_DIR                        local file store for testing (instead of Upstash)
#![allow(dead_code)]

#[path = "../src/chain.rs"]
mod chain;
#[path = "../src/crypto.rs"]
mod crypto;

use chain::{Account, Block, State, Tx};
use crypto::Keypair;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use vercel_runtime::{run, service_fn, Error, Request, Response, ResponseBody};

const EXPLORER_HTML: &str = include_str!("../src/explorer.html");
const SEED_CHAIN: &str = include_str!("../seed/chain.json");
const HEARTBEAT_SECS: u64 = 30;
const RECENT: usize = 30;

// ------------------------------------------------------------------- head
#[derive(Serialize, Deserialize, Clone)]
struct Snap {
    accounts: BTreeMap<String, Account>,
    minted: u64,
    burned: u64,
    next_base_fee: u64,
    last_target: String,
    chainwork: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct Head {
    blocks: Vec<Block>, // most recent RECENT blocks; last = tip
    state: Snap,
    mempool: Vec<Tx>,
    anchors: Vec<Value>,
    log: Vec<String>,
}

impl Head {
    fn state(&self) -> State {
        State {
            accounts: self.state.accounts.clone(),
            minted: self.state.minted,
            burned: self.state.burned,
            next_base_fee: self.state.next_base_fee,
            last_target: self.state.last_target.parse().unwrap_or(chain::INITIAL_TARGET),
            chainwork: self.state.chainwork.parse().unwrap_or(0),
        }
    }
    fn set_state(&mut self, s: &State) {
        self.state = Snap {
            accounts: s.accounts.clone(),
            minted: s.minted,
            burned: s.burned,
            next_base_fee: s.next_base_fee,
            last_target: s.last_target.to_string(),
            chainwork: s.chainwork.to_string(),
        };
    }
    fn tip(&self) -> &Block {
        self.blocks.last().unwrap()
    }
    fn log(&mut self, m: String) {
        self.log.push(format!("[{}] {m}", chain::now_secs()));
        let n = self.log.len();
        if n > 12 {
            self.log.drain(..n - 12);
        }
    }
    fn prune_mempool(&mut self) {
        let st = self.state();
        let included: std::collections::HashSet<String> =
            self.blocks.iter().flat_map(|b| b.txs.iter().map(|t| t.signature.clone())).collect();
        self.mempool.retain(|t| {
            !included.contains(&t.signature) && t.sender().map(|a| t.nonce >= st.account(&a).nonce).unwrap_or(false)
        });
    }
    fn record_anchors(&mut self, b: &Block) {
        for t in b.txs.iter().filter(|t| t.kind == chain::TxKind::Anchor) {
            self.anchors
                .insert(0, json!({"height": b.header.height, "from": t.sender().unwrap_or_default(), "data": t.data}));
        }
        self.anchors.truncate(20);
    }
}

// ------------------------------------------------------------------ store
enum Store {
    Upstash { url: String, token: String },
    File { dir: std::path::PathBuf },
}

static FILE_LOCK: Mutex<()> = Mutex::new(());
static CACHE: Mutex<Option<(Instant, String, Head)>> = Mutex::new(None);

// Atomic compare-and-swap: KEYS = [ver, head]; ARGV = [expected_ver, new_ver, head_json, k1, v1, k2, v2, ...]
const CAS_SCRIPT: &str = "if (redis.call('GET', KEYS[1]) or '0') ~= ARGV[1] then return 0 end \
redis.call('SET', KEYS[1], ARGV[2]) redis.call('SET', KEYS[2], ARGV[3]) \
for i = 4, #ARGV, 2 do redis.call('SET', ARGV[i], ARGV[i+1]) end return 1";

impl Store {
    fn from_env() -> Result<Store, String> {
        let env = |a: &str, b: &str| std::env::var(a).or_else(|_| std::env::var(b)).ok();
        if let (Some(url), Some(token)) =
            (env("KV_REST_API_URL", "UPSTASH_REDIS_REST_URL"), env("KV_REST_API_TOKEN", "UPSTASH_REDIS_REST_TOKEN"))
        {
            return Ok(Store::Upstash { url: url.trim_end_matches('/').into(), token });
        }
        if let Ok(d) = std::env::var("AURA_STORE_DIR") {
            std::fs::create_dir_all(format!("{d}/b")).map_err(|e| e.to_string())?;
            return Ok(Store::File { dir: d.into() });
        }
        Err("no storage configured: connect Upstash Redis to this Vercel project".into())
    }

    fn redis(&self, args: Vec<String>) -> Result<Value, String> {
        let Store::Upstash { url, token } = self else { unreachable!() };
        let r: Value = ureq::post(url)
            .set("Authorization", &format!("Bearer {token}"))
            .timeout(Duration::from_secs(8))
            .send_json(json!(args))
            .map_err(|e| format!("upstash: {e}"))?
            .into_json()
            .map_err(|e| e.to_string())?;
        if let Some(e) = r.get("error") {
            return Err(format!("upstash: {e}"));
        }
        Ok(r["result"].clone())
    }

    /// Returns (version, head) or None if the store is empty.
    fn load(&self) -> Result<Option<(String, Head)>, String> {
        let (ver, raw) = match self {
            Store::Upstash { .. } => {
                let r = self.redis(vec!["MGET".into(), "aura:ver".into(), "aura:head".into()])?;
                (r[0].as_str().map(String::from), r[1].as_str().map(String::from))
            }
            Store::File { dir } => (
                std::fs::read_to_string(dir.join("ver")).ok(),
                std::fs::read_to_string(dir.join("head.json")).ok(),
            ),
        };
        match (ver, raw) {
            (Some(v), Some(h)) => Ok(Some((v, serde_json::from_str(&h).map_err(|e| e.to_string())?))),
            _ => Ok(None),
        }
    }

    /// Atomically replace head (and write archived blocks) iff the version is unchanged.
    fn cas(&self, ver: &str, new_ver: &str, head: &Head, blocks: &[&Block]) -> Result<bool, String> {
        let head_json = serde_json::to_string(head).unwrap();
        match self {
            Store::Upstash { .. } => {
                let mut args: Vec<String> =
                    vec!["EVAL".into(), CAS_SCRIPT.into(), "2".into(), "aura:ver".into(), "aura:head".into()];
                args.extend([ver.to_string(), new_ver.to_string(), head_json]);
                for b in blocks {
                    args.push(format!("aura:b:{}", b.header.height));
                    args.push(serde_json::to_string(b).unwrap());
                }
                Ok(self.redis(args)?.as_i64() == Some(1))
            }
            Store::File { dir } => {
                let _g = FILE_LOCK.lock().unwrap();
                let cur = std::fs::read_to_string(dir.join("ver")).unwrap_or_else(|_| "0".into());
                if cur != ver {
                    return Ok(false);
                }
                for b in blocks {
                    std::fs::write(dir.join(format!("b/{}.json", b.header.height)), serde_json::to_string(b).unwrap())
                        .map_err(|e| e.to_string())?;
                }
                std::fs::write(dir.join("head.json"), head_json).map_err(|e| e.to_string())?;
                std::fs::write(dir.join("ver"), new_ver).map_err(|e| e.to_string())?;
                Ok(true)
            }
        }
    }

    fn get_blocks(&self, from: u64, to: u64) -> Result<Vec<Block>, String> {
        let raws: Vec<Option<String>> = match self {
            Store::Upstash { .. } => {
                let mut args = vec!["MGET".to_string()];
                args.extend((from..=to).map(|h| format!("aura:b:{h}")));
                let r = self.redis(args)?;
                r.as_array().cloned().unwrap_or_default().iter().map(|v| v.as_str().map(String::from)).collect()
            }
            Store::File { dir } => {
                (from..=to).map(|h| std::fs::read_to_string(dir.join(format!("b/{h}.json"))).ok()).collect()
            }
        };
        Ok(raws.into_iter().flatten().filter_map(|r| serde_json::from_str(&r).ok()).collect())
    }
}

// ---------------------------------------------------------------- consensus glue
fn seed(store: &Store) -> Result<(String, Head), String> {
    let blocks: Vec<Block> = serde_json::from_str(SEED_CHAIN).map_err(|e| format!("bad seed: {e}"))?;
    let st = chain::validate_chain(&blocks).map_err(|e| format!("seed chain invalid: {e}"))?;
    let empty = Snap {
        accounts: BTreeMap::new(),
        minted: 0,
        burned: 0,
        next_base_fee: 0,
        last_target: String::new(),
        chainwork: String::new(),
    };
    let mut head = Head {
        blocks: blocks[blocks.len().saturating_sub(RECENT)..].to_vec(),
        state: empty,
        mempool: vec![],
        anchors: vec![],
        log: vec![],
    };
    head.set_state(&st);
    for b in &blocks {
        head.record_anchors(b);
    }
    head.log(format!("seeded from snapshot at height {}", blocks.len() - 1));
    // Archive older blocks first (version stays "0"), then publish head with CAS 0 -> 1.
    let refs: Vec<&Block> = blocks.iter().collect();
    for c in refs.chunks(200) {
        if let Store::File { dir } = store {
            for b in c {
                std::fs::write(dir.join(format!("b/{}.json", b.header.height)), serde_json::to_string(b).unwrap())
                    .map_err(|e| e.to_string())?;
            }
        } else {
            let mut args = vec!["MSET".to_string()];
            for b in c {
                args.push(format!("aura:b:{}", b.header.height));
                args.push(serde_json::to_string(b).unwrap());
            }
            store.redis(args)?;
        }
    }
    if !store.cas("0", "1", &head, &[])? {
        return store.load()?.ok_or_else(|| "seed race".to_string());
    }
    Ok(("1".into(), head))
}

/// Request-driven VPoS block production. Returns the new block if one was made.
fn maybe_produce(head: &mut Head, key: &Keypair, now: u64) -> Option<Block> {
    let tip = head.tip().header.clone();
    let next = tip.height + 1;
    let st = head.state();
    if !chain::is_pos(next, &st) || now < tip.timestamp + chain::SLOT_SECS {
        return None; // the serverless node never mines PoW
    }
    if head.mempool.is_empty() && now - tip.timestamp < HEARTBEAT_SECS {
        return None;
    }
    let slot = (now - tip.timestamp) / chain::SLOT_SECS - 1;
    if chain::elect_leader(&st, &tip.hash_hex(), next, slot).as_deref() != Some(key.address().as_str()) {
        return None;
    }
    let b = chain::assemble(&head.blocks, &st, &head.mempool, key, now, "VPoS slot leader (vercel)").ok()?;
    let ns = chain::apply_block(&st, &head.blocks, &b, now).ok()?;
    head.set_state(&ns);
    head.record_anchors(&b);
    head.blocks.push(b.clone());
    let n = head.blocks.len();
    if n > RECENT {
        head.blocks.drain(..n - RECENT);
    }
    head.prune_mempool();
    head.log(format!("produced block #{} POS ({} txs)", b.header.height, b.txs.len()));
    Some(b)
}

fn admit_tx(head: &Head, tx: &Tx) -> Result<(), String> {
    tx.verify_signature()?;
    let from = tx.sender()?;
    if head.mempool.iter().any(|t| t.signature == tx.signature) {
        return Err("already in mempool".into());
    }
    if head.mempool.len() >= 500 {
        return Err("mempool full".into());
    }
    let mut sim = head.state();
    let mut pending: Vec<&Tx> =
        head.mempool.iter().filter(|t| t.sender().map(|a| a == from).unwrap_or(false)).collect();
    pending.sort_by_key(|t| t.nonce);
    for t in pending {
        let _ = chain::apply_tx(&mut sim, t, chain::MIN_BASE_FEE);
    }
    chain::apply_tx(&mut sim, tx, chain::MIN_BASE_FEE)
}

fn info(head: &Head, key: &Option<Keypair>) -> Value {
    let s = head.state();
    let tip = &head.tip().header;
    let next = tip.height + 1;
    let vals: Vec<Value> = s
        .validator_weights()
        .into_iter()
        .map(|(a, st, w)| json!({"address": a, "stake": chain::fmt_aura(st), "weight": chain::fmt_aura(w)}))
        .collect();
    json!({
        "network": chain::NETWORK, "height": tip.height, "tip_hash": tip.hash_hex(), "tip_timestamp": tip.timestamp,
        "genesis_hash": chain::genesis().header.hash_hex(), "genesis_message": chain::GENESIS_MESSAGE,
        "next_consensus": if chain::is_pos(next, &s) { "pos" } else { "pow" },
        "pos_start_height": chain::POS_START_HEIGHT, "chainwork": s.chainwork.to_string(),
        "difficulty": (u128::MAX / s.last_target.max(1)) as f64, "target": chain::target_hex(s.last_target),
        "minted": chain::fmt_aura(s.minted), "burned": chain::fmt_aura(s.burned),
        "circulating": chain::fmt_aura(s.minted - s.burned), "max_supply": chain::fmt_aura(chain::MAX_SUPPLY),
        "block_reward": chain::fmt_aura(chain::block_reward(next, s.minted)),
        "base_fee": chain::fmt_aura(s.next_base_fee), "base_fee_micro": s.next_base_fee,
        "total_staked": chain::fmt_aura(s.total_stake()), "validators": vals, "accounts": s.accounts.len(),
        "mempool": head.mempool.len(), "peers": [], "self_url": "vercel serverless node (blocks on demand)",
        "node_address": key.as_ref().map(|k| k.address()), "hashrate": 0,
        "heartbeat_secs": HEARTBEAT_SECS, "log": head.log.iter().rev().take(8).collect::<Vec<_>>(),
    })
}

// -------------------------------------------------------------------- HTTP
fn json_err(c: u16, e: String) -> (u16, String, &'static str) {
    (c, json!({ "error": e }).to_string(), "application/json")
}

fn handle_sync(method: String, path: String, query: String, body: Vec<u8>) -> (u16, String, &'static str) {
    let q = |k: &str| -> Option<u64> {
        query.split('&').find_map(|kv| kv.split_once('=').filter(|(a, _)| *a == k).and_then(|(_, v)| v.parse().ok()))
    };
    if method == "GET" && (path == "/" || path == "/index.html") {
        return (200, EXPLORER_HTML.to_string(), "text/html; charset=utf-8");
    }
    let store = match Store::from_env() {
        Ok(s) => s,
        Err(e) => return json_err(503, e),
    };
    let key = std::env::var("AURA_VALIDATOR_KEY").ok().and_then(|k| Keypair::from_secret_hex(&k).ok());
    let now = chain::now_secs();

    // Load (1 s in-memory cache for reads); seed the store on first ever use.
    let cached = if method == "GET" {
        CACHE
            .lock()
            .unwrap()
            .as_ref()
            .filter(|c| c.0.elapsed() < Duration::from_secs(1))
            .map(|c| (c.1.clone(), c.2.clone()))
    } else {
        None
    };
    let (mut ver, mut head) = match cached {
        Some(c) => c,
        None => match store.load() {
            Ok(Some(c)) => c,
            Ok(None) => match seed(&store) {
                Ok(c) => c,
                Err(e) => return json_err(500, e),
            },
            Err(e) => return json_err(502, e),
        },
    };

    let mut reply: Option<(u16, Value)> = None;
    for _attempt in 0..3 {
        let mut changed = false;
        let mut new_blocks: Vec<Block> = vec![];
        if method == "POST" && path == "/tx" {
            let tx = match serde_json::from_slice::<Tx>(&body) {
                Ok(t) => t,
                Err(e) => return json_err(400, format!("bad tx json: {e}")),
            };
            if let Err(e) = admit_tx(&head, &tx) {
                return json_err(400, e);
            }
            let id = tx.id();
            head.log(format!("mempool += {:?} {}", tx.kind, &id[..12]));
            head.mempool.push(tx);
            changed = true;
            reply = Some((200, json!({ "txid": id })));
        }
        if let Some(k) = &key {
            if let Some(b) = maybe_produce(&mut head, k, now) {
                new_blocks.push(b);
                changed = true;
            }
        }
        if !changed {
            break;
        }
        let nv = (ver.parse::<u64>().unwrap_or(0) + 1).to_string();
        let refs: Vec<&Block> = new_blocks.iter().collect();
        match store.cas(&ver, &nv, &head, &refs) {
            Ok(true) => {
                ver = nv;
                break;
            }
            Ok(false) => match store.load() {
                // another invocation wrote first: reload and retry on fresh state
                Ok(Some((v, h))) => {
                    ver = v;
                    head = h;
                    reply = None;
                }
                _ => return json_err(502, "store reload failed".into()),
            },
            Err(e) => return json_err(502, e),
        }
    }
    *CACHE.lock().unwrap() = Some((Instant::now(), ver.clone(), head.clone()));

    let out: (u16, Value) = match (method.as_str(), path.as_str()) {
        ("POST", "/tx") => reply.unwrap_or((503, json!({"error": "busy, retry"}))),
        ("GET", "/tip") => {
            let t = &head.tip().header;
            (200, json!({"height": t.height, "hash": t.hash_hex(), "chainwork": head.state.chainwork}))
        }
        ("GET", "/info") => (200, info(&head, &key)),
        ("GET", "/mempool") => (200, json!(head.mempool)),
        ("GET", "/anchors") => (200, json!(head.anchors)),
        ("GET", p) if p.starts_with("/account/") => {
            let a = &p[9..];
            let s = head.state();
            let acc = s.account(a);
            let pend = head
                .mempool
                .iter()
                .filter(|t| t.sender().map(|x| x == a).unwrap_or(false))
                .map(|t| t.nonce + 1)
                .max();
            (
                200,
                json!({"address": a, "balance": chain::fmt_aura(acc.balance), "balance_micro": acc.balance,
                "stake": chain::fmt_aura(acc.stake), "nonce": acc.nonce, "next_nonce": pend.unwrap_or(acc.nonce).max(acc.nonce)}),
            )
        }
        ("GET", p) if p.starts_with("/block/") => match p[7..].parse::<u64>() {
            Ok(h) => match store.get_blocks(h, h) {
                Ok(v) if !v.is_empty() => {
                    let mut j = json!(v[0]);
                    j["hash"] = json!(v[0].header.hash_hex());
                    (200, j)
                }
                _ => (404, json!({"error": "no such block"})),
            },
            Err(_) => (400, json!({"error": "bad height"})),
        },
        ("GET", "/blocks") => {
            let tip_h = head.tip().header.height;
            let from = q("from").unwrap_or(0).min(tip_h);
            let limit = q("limit").unwrap_or(50).clamp(1, 500);
            let to = (from + limit - 1).min(tip_h);
            let first_recent = head.blocks[0].header.height;
            if from >= first_recent {
                let v: Vec<&Block> =
                    head.blocks.iter().filter(|b| b.header.height >= from && b.header.height <= to).collect();
                (200, json!(v))
            } else {
                match store.get_blocks(from, to) {
                    Ok(v) => (200, json!(v)),
                    Err(e) => (502, json!({ "error": e })),
                }
            }
        }
        ("POST", "/peers") => (200, json!({"peers": [], "note": "serverless node: peers pull from it"})),
        ("POST", "/block") => (400, json!({"error": "serverless node is the block producer; it does not accept pushed blocks"})),
        _ => (404, json!({"error": "not found"})),
    };
    (out.0, out.1.to_string(), "application/json")
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

async fn handler(req: Request) -> Result<Response<ResponseBody>, Error> {
    let (parts, body) = req.into_parts();
    let method = parts.method.as_str().to_string();
    let raw_q = parts.uri.query().unwrap_or("").to_string();
    // vercel.json rewrites "/(.*)" -> "/api/node?__p=/$1"; otherwise use the URI path.
    let mut path = parts.uri.path().to_string();
    let mut rest = vec![];
    for kv in raw_q.split('&').filter(|s| !s.is_empty()) {
        match kv.strip_prefix("__p=") {
            Some(p) => path = percent_decode(p),
            None => rest.push(kv.to_string()),
        }
    }
    if path.is_empty() || path == "/api/node" {
        path = "/".into();
    }
    if !path.starts_with('/') {
        path = format!("/{path}");
    }
    let query = rest.join("&");
    let bytes = body.collect().await?.to_bytes().to_vec();
    let (code, out, ctype) = tokio::task::spawn_blocking(move || handle_sync(method, path, query, bytes)).await?;
    Ok(Response::builder()
        .status(code)
        .header("content-type", ctype)
        .header("access-control-allow-origin", "*")
        .header("cache-control", "no-store")
        .body(ResponseBody::from(out))?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handler)).await
}
