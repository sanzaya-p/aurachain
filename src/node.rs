//! Full node: chain storage, mempool, HTTP/JSON-RPC API, peer sync,
//! PoW miner and VPoS block producer.

use crate::chain::{self, Block, State, Tx};
use crate::crypto::Keypair;
use serde_json::{json, Value};
use std::io::Read;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

const EXPLORER_HTML: &str = include_str!("explorer.html");

pub struct Node {
    pub blocks: Vec<Block>,
    pub state: State,
    pub mempool: Vec<Tx>,
    pub peers: Vec<String>,
    pub data_dir: PathBuf,
    pub self_url: String,
    pub log: Vec<String>,
}

pub struct Ctx {
    pub node: Mutex<Node>,
    pub tip: AtomicU64, // bumps on every chain change; lets the miner abort stale work
    pub key: Option<Keypair>,
    pub hashrate: AtomicU64,
}

fn log(n: &mut Node, msg: String) {
    let line = format!("[{}] {}", chain::now_secs(), msg);
    println!("{line}");
    n.log.push(line);
    if n.log.len() > 200 {
        n.log.remove(0);
    }
}

impl Node {
    fn load(data_dir: PathBuf, self_url: String) -> Node {
        std::fs::create_dir_all(&data_dir).ok();
        let mut blocks = vec![chain::genesis()];
        let mut state = State::genesis();
        if let Ok(raw) = std::fs::read(data_dir.join("chain.json")) {
            if let Ok(saved) = serde_json::from_slice::<Vec<Block>>(&raw) {
                match chain::validate_chain(&saved) {
                    Ok(s) => {
                        blocks = saved;
                        state = s;
                    }
                    Err(e) => eprintln!("stored chain invalid ({e}); starting from genesis"),
                }
            }
        }
        Node { blocks, state, mempool: vec![], peers: vec![], data_dir, self_url, log: vec![] }
    }

    fn save(&self) {
        let tmp = self.data_dir.join("chain.json.tmp");
        if std::fs::write(&tmp, serde_json::to_vec(&self.blocks).unwrap()).is_ok() {
            std::fs::rename(&tmp, self.data_dir.join("chain.json")).ok();
        }
    }

    fn prune_mempool(&mut self) {
        let in_chain: std::collections::HashSet<String> = self
            .blocks
            .iter()
            .rev()
            .take(50)
            .flat_map(|b| b.txs.iter().map(|t| t.signature.clone()))
            .collect();
        let st = &self.state;
        self.mempool.retain(|t| {
            !in_chain.contains(&t.signature)
                && t.sender().map(|a| t.nonce >= st.account(&a).nonce).unwrap_or(false)
        });
    }

    fn try_extend(&mut self, b: Block) -> Result<(), String> {
        let ns = chain::apply_block(&self.state, &self.blocks, &b, chain::now_secs())?;
        let h = b.header.height;
        let what = format!(
            "block #{h} {} by {}… ({} txs) {}",
            b.header.consensus.to_uppercase(),
            &b.header.producer[..12],
            b.txs.len(),
            &b.header.hash_hex()[..16]
        );
        self.blocks.push(b);
        self.state = ns;
        self.prune_mempool();
        self.save();
        log(self, format!("accepted {what}"));
        Ok(())
    }

    fn try_replace(&mut self, cand: Vec<Block>, cand_state: State) -> bool {
        if cand_state.chainwork <= self.state.chainwork {
            return false;
        }
        let old = self.blocks.len();
        let mut leftovers: Vec<Tx> = self.blocks.iter().flat_map(|b| b.txs.clone()).collect();
        leftovers.extend(self.mempool.drain(..));
        self.blocks = cand;
        self.state = cand_state;
        self.mempool = leftovers;
        self.prune_mempool();
        self.save();
        let msg = format!("reorg/sync: switched to heavier chain (height {} -> {})", old - 1, self.blocks.len() - 1);
        log(self, msg);
        true
    }

    fn add_tx(&mut self, tx: Tx) -> Result<String, String> {
        tx.verify_signature()?;
        let from = tx.sender()?;
        if self.mempool.iter().any(|t| t.signature == tx.signature) {
            return Err("already in mempool".into());
        }
        if tx.nonce < self.state.account(&from).nonce {
            return Err("nonce already used".into());
        }
        if tx.fee < chain::MIN_BASE_FEE {
            return Err("fee below minimum base fee".into());
        }
        if self.mempool.len() >= 5000 {
            return Err("mempool full".into());
        }
        // Admission check: replay this sender's pending txs, then this one, on a
        // scratch copy of the state. Rejects overspends and nonce gaps up front.
        let mut sim = self.state.clone();
        let mut pending: Vec<&Tx> = self
            .mempool
            .iter()
            .filter(|t| t.sender().map(|a| a == from).unwrap_or(false))
            .collect();
        pending.sort_by_key(|t| t.nonce);
        for t in pending {
            let _ = chain::apply_tx(&mut sim, t, chain::MIN_BASE_FEE);
        }
        chain::apply_tx(&mut sim, &tx, chain::MIN_BASE_FEE)?;
        let id = tx.id();
        log(self, format!("mempool += {:?} {} from {}…", tx.kind, &id[..12], &from[..12]));
        self.mempool.push(tx);
        Ok(id)
    }

    fn next_nonce(&self, addr: &str) -> u64 {
        let base = self.state.account(addr).nonce;
        let pend = self
            .mempool
            .iter()
            .filter(|t| t.sender().map(|a| a == addr).unwrap_or(false) && t.nonce >= base)
            .map(|t| t.nonce + 1)
            .max();
        pend.unwrap_or(base).max(base)
    }
}

// ------------------------------------------------------------------ networking
fn post_json(url: &str, body: &Value) -> Result<Value, String> {
    ureq::post(url)
        .timeout(Duration::from_secs(3))
        .send_json(body.clone())
        .map_err(|e| e.to_string())?
        .into_json::<Value>()
        .map_err(|e| e.to_string())
}

fn get_json(url: &str) -> Result<Value, String> {
    ureq::get(url)
        .timeout(Duration::from_secs(10))
        .call()
        .map_err(|e| e.to_string())?
        .into_json::<Value>()
        .map_err(|e| e.to_string())
}

fn broadcast(peers: Vec<String>, path: &'static str, body: Value) {
    thread::spawn(move || {
        for p in peers {
            let _ = post_json(&format!("{p}{path}"), &body);
        }
    });
}

fn sync_loop(ctx: Arc<Ctx>) {
    // Bandwidth-frugal sync: poll a ~100-byte /tip; when a peer has more work,
    // fetch only the last few blocks and splice them onto our chain. Fall back
    // to a full download only for deep forks.
    let mut round: u64 = 0;
    loop {
        thread::sleep(Duration::from_secs(3));
        round += 1;
        let (peers, my_work, my_height, self_url) = {
            let n = ctx.node.lock().unwrap();
            (n.peers.clone(), n.state.chainwork, n.blocks.len() as u64 - 1, n.self_url.clone())
        };
        for p in peers {
            let tip = match get_json(&format!("{p}/tip")) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if round % 20 == 1 {
                // Re-announce ourselves occasionally (bidirectional gossip).
                let _ = post_json(&format!("{p}/peers"), &json!({ "url": self_url }));
            }
            let their: u128 = tip["chainwork"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
            if their <= my_work {
                continue;
            }
            let from = my_height.saturating_sub(20);
            let mut cand: Option<Vec<Block>> = None;
            if let Ok(recent) = get_json(&format!("{p}/blocks?from={from}&limit=500"))
                .and_then(|v| serde_json::from_value::<Vec<Block>>(v).map_err(|e| e.to_string()))
            {
                let n = ctx.node.lock().unwrap();
                if let Some(first) = recent.first() {
                    let h = first.header.height as usize;
                    if h >= 1 && h <= n.blocks.len() && n.blocks[h - 1].header.hash_hex() == first.header.prev_hash {
                        let mut c = n.blocks[..h].to_vec();
                        c.extend(recent);
                        cand = Some(c);
                    }
                }
            }
            if cand.is_none() {
                cand = get_json(&format!("{p}/blocks?from=0&limit=1000000"))
                    .and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string()))
                    .ok();
            }
            let Some(cand) = cand else { continue };
            match chain::validate_chain(&cand) {
                Ok(st) => {
                    let mut n = ctx.node.lock().unwrap();
                    if n.try_replace(cand, st) {
                        ctx.tip.fetch_add(1, Ordering::SeqCst);
                    }
                }
                Err(e) => {
                    let mut n = ctx.node.lock().unwrap();
                    log(&mut n, format!("rejected chain from {p}: {e}"));
                }
            }
        }
    }
}

fn announce(ctx: &Arc<Ctx>, b: &Block) {
    let peers = ctx.node.lock().unwrap().peers.clone();
    broadcast(peers, "/block", serde_json::to_value(b).unwrap());
}

// ------------------------------------------------------------- block production
fn miner_loop(ctx: Arc<Ctx>) {
    let key = ctx.key.as_ref().unwrap();
    let mut rng_nonce: u64 = rand::random();
    loop {
        let tip_ver = ctx.tip.load(Ordering::SeqCst);
        let tmpl = {
            let n = ctx.node.lock().unwrap();
            let next = n.blocks.last().unwrap().header.height + 1;
            if chain::is_pos(next, &n.state) {
                None
            } else {
                chain::assemble(&n.blocks, &n.state, &n.mempool, key, chain::now_secs(), "mined on AuraChain devnet").ok()
            }
        };
        let Some(mut block) = tmpl else {
            thread::sleep(Duration::from_millis(1000));
            continue;
        };
        let target = block.header.target_value().unwrap();
        let prefix = block.header.prefix_digest();
        let started = std::time::Instant::now();
        let mut tried: u64 = 0;
        let mut found = None;
        'outer: loop {
            for _ in 0..50_000 {
                rng_nonce = rng_nonce.wrapping_add(1);
                tried += 1;
                if chain::hash_value(&chain::Header::hash_with(&prefix, rng_nonce)) <= target {
                    found = Some(rng_nonce);
                    break 'outer;
                }
            }
            let el = started.elapsed().as_secs_f64();
            if el > 0.5 {
                ctx.hashrate.store((tried as f64 / el) as u64, Ordering::Relaxed);
            }
            // Abandon stale work when the tip changes or the template is old.
            if ctx.tip.load(Ordering::SeqCst) != tip_ver || el > 15.0 {
                break;
            }
        }
        if let Some(nonce) = found {
            block.header.nonce = nonce;
            let mut n = ctx.node.lock().unwrap();
            match n.try_extend(block.clone()) {
                Ok(()) => {
                    drop(n);
                    ctx.tip.fetch_add(1, Ordering::SeqCst);
                    announce(&ctx, &block);
                }
                Err(e) => log(&mut n, format!("mined block discarded (stale or invalid): {e}")),
            }
        }
    }
}

fn validator_loop(ctx: Arc<Ctx>) {
    let key = ctx.key.as_ref().unwrap();
    let me = key.address();
    loop {
        thread::sleep(Duration::from_millis(400));
        let produced = {
            let mut n = ctx.node.lock().unwrap();
            let prev = n.blocks.last().unwrap().header.clone();
            let next = prev.height + 1;
            let now = chain::now_secs();
            if !chain::is_pos(next, &n.state) || now < prev.timestamp + chain::SLOT_SECS {
                continue;
            }
            let slot = (now - prev.timestamp) / chain::SLOT_SECS - 1;
            if chain::elect_leader(&n.state, &prev.hash_hex(), next, slot).as_deref() != Some(me.as_str()) {
                continue;
            }
            match chain::assemble(&n.blocks, &n.state, &n.mempool, key, now, "VPoS slot leader") {
                Ok(b) => match n.try_extend(b.clone()) {
                    Ok(()) => Some(b),
                    Err(e) => {
                        log(&mut n, format!("own PoS block rejected: {e}"));
                        None
                    }
                },
                Err(_) => None,
            }
        };
        if let Some(b) = produced {
            ctx.tip.fetch_add(1, Ordering::SeqCst);
            announce(&ctx, &b);
        }
    }
}

// ------------------------------------------------------------------- HTTP API
fn info_json(ctx: &Ctx, n: &Node) -> Value {
    let tip = &n.blocks.last().unwrap().header;
    let next = tip.height + 1;
    let s = &n.state;
    let target = chain::expected_target(&n.blocks, next, s);
    let vals: Vec<Value> = s
        .validator_weights()
        .into_iter()
        .map(|(a, st, w)| json!({"address": a, "stake": chain::fmt_aura(st), "weight": chain::fmt_aura(w)}))
        .collect();
    json!({
        "network": chain::NETWORK,
        "height": tip.height,
        "tip_hash": tip.hash_hex(),
        "tip_timestamp": tip.timestamp,
        "genesis_hash": n.blocks[0].header.hash_hex(),
        "genesis_message": chain::GENESIS_MESSAGE,
        "next_consensus": if chain::is_pos(next, s) { "pos" } else { "pow" },
        "pos_start_height": chain::POS_START_HEIGHT,
        "chainwork": s.chainwork.to_string(),
        "difficulty": (u128::MAX / target.max(1)) as f64,
        "target": chain::target_hex(target),
        "minted": chain::fmt_aura(s.minted),
        "burned": chain::fmt_aura(s.burned),
        "circulating": chain::fmt_aura(s.minted - s.burned),
        "max_supply": chain::fmt_aura(chain::MAX_SUPPLY),
        "block_reward": chain::fmt_aura(chain::block_reward(next, s.minted)),
        "base_fee": chain::fmt_aura(s.next_base_fee),
        "base_fee_micro": s.next_base_fee,
        "total_staked": chain::fmt_aura(s.total_stake()),
        "validators": vals,
        "accounts": s.accounts.len(),
        "mempool": n.mempool.len(),
        "peers": n.peers,
        "self_url": n.self_url,
        "node_address": ctx.key.as_ref().map(|k| k.address()),
        "hashrate": ctx.hashrate.load(Ordering::Relaxed),
        "log": n.log.iter().rev().take(8).collect::<Vec<_>>(),
    })
}

fn respond(req: tiny_http::Request, code: u16, body: String, ctype: &str) {
    let resp = tiny_http::Response::from_string(body)
        .with_status_code(code)
        .with_header(tiny_http::Header::from_bytes("Content-Type", ctype).unwrap())
        .with_header(tiny_http::Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap());
    let _ = req.respond(resp);
}

fn handle(ctx: &Arc<Ctx>, mut req: tiny_http::Request) {
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let q = |k: &str| -> Option<u64> {
        query.split('&').find_map(|kv| kv.split_once('=').filter(|(a, _)| *a == k).and_then(|(_, v)| v.parse().ok()))
    };
    let method = req.method().clone();
    let remote_is_loopback = req.remote_addr().map(|a| a.ip().is_loopback()).unwrap_or(false);
    let mut body = String::new();
    if method == tiny_http::Method::Post {
        let _ = req.as_reader().take(4 << 20).read_to_string(&mut body);
    }
    let ok = |v: Value| (200u16, v);
    let err = |c: u16, e: String| (c, json!({ "error": e }));

    if method == tiny_http::Method::Get && path == "/" {
        return respond(req, 200, EXPLORER_HTML.to_string(), "text/html; charset=utf-8");
    }

    let (code, out): (u16, Value) = match (method.as_str(), path) {
        ("GET", "/tip") => {
            let n = ctx.node.lock().unwrap();
            let t = &n.blocks.last().unwrap().header;
            ok(json!({"height": t.height, "hash": t.hash_hex(), "chainwork": n.state.chainwork.to_string()}))
        }
        ("GET", "/info") => {
            let n = ctx.node.lock().unwrap();
            ok(info_json(ctx, &n))
        }
        ("GET", "/blocks") => {
            let n = ctx.node.lock().unwrap();
            let from = q("from").unwrap_or(0) as usize;
            let limit = q("limit").unwrap_or(50) as usize;
            let slice: Vec<&Block> = n.blocks.iter().skip(from).take(limit).collect();
            ok(serde_json::to_value(slice).unwrap())
        }
        ("GET", p) if p.starts_with("/block/") => {
            let n = ctx.node.lock().unwrap();
            match p[7..].parse::<usize>().ok().and_then(|h| n.blocks.get(h)) {
                Some(b) => {
                    let mut v = serde_json::to_value(b).unwrap();
                    v["hash"] = json!(b.header.hash_hex());
                    ok(v)
                }
                None => err(404, "no such block".into()),
            }
        }
        ("GET", p) if p.starts_with("/account/") => {
            let n = ctx.node.lock().unwrap();
            let a = &p[9..];
            let acc = n.state.account(a);
            ok(json!({
                "address": a, "balance": chain::fmt_aura(acc.balance), "balance_micro": acc.balance,
                "stake": chain::fmt_aura(acc.stake), "nonce": acc.nonce, "next_nonce": n.next_nonce(a),
            }))
        }
        ("GET", "/mempool") => {
            let n = ctx.node.lock().unwrap();
            ok(serde_json::to_value(&n.mempool).unwrap())
        }
        ("GET", "/anchors") => {
            let n = ctx.node.lock().unwrap();
            let v: Vec<Value> = n
                .blocks
                .iter()
                .flat_map(|b| {
                    b.txs.iter().filter(|t| t.kind == chain::TxKind::Anchor).map(move |t| {
                        json!({"height": b.header.height, "from": t.sender().unwrap_or_default(), "data": t.data})
                    })
                })
                .collect();
            ok(json!(v.into_iter().rev().take(50).collect::<Vec<_>>()))
        }
        ("POST", "/tx") => match serde_json::from_str::<Tx>(&body) {
            Ok(tx) => {
                let r = ctx.node.lock().unwrap().add_tx(tx.clone());
                match r {
                    Ok(id) => {
                        let peers = ctx.node.lock().unwrap().peers.clone();
                        broadcast(peers, "/tx", serde_json::to_value(&tx).unwrap());
                        ok(json!({ "txid": id }))
                    }
                    Err(e) => err(400, e),
                }
            }
            Err(e) => err(400, format!("bad tx json: {e}")),
        },
        ("POST", "/block") => match serde_json::from_str::<Block>(&body) {
            Ok(b) => {
                let r = ctx.node.lock().unwrap().try_extend(b.clone());
                match r {
                    Ok(()) => {
                        ctx.tip.fetch_add(1, Ordering::SeqCst);
                        announce(ctx, &b);
                        ok(json!({"accepted": true}))
                    }
                    Err(e) => err(400, e),
                }
            }
            Err(e) => err(400, format!("bad block json: {e}")),
        },
        ("POST", "/peers") => {
            let v: Value = serde_json::from_str(&body).unwrap_or(json!({}));
            match v["url"].as_str() {
                Some(u) if u.starts_with("http") => {
                    let mut n = ctx.node.lock().unwrap();
                    let u = u.trim_end_matches('/').to_string();
                    // A remote machine's "127.0.0.1" would point back at *us*; ignore it.
                    let loopback_url = u.contains("://127.") || u.contains("://localhost");
                    if loopback_url && !remote_is_loopback {
                        ok(json!({"peers": n.peers, "note": "loopback peer url ignored"}))
                    } else {
                        if u != n.self_url && !n.peers.contains(&u) && n.peers.len() < 32 {
                            n.peers.push(u.clone());
                            log(&mut n, format!("peer added: {u}"));
                        }
                        ok(json!({"peers": n.peers}))
                    }
                }
                _ => err(400, "need {\"url\": \"http://host:port\"}".into()),
            }
        }
        _ => err(404, "not found".into()),
    };
    respond(req, code, out.to_string(), "application/json");
}

pub fn run(port: u16, data_dir: PathBuf, key: Option<Keypair>, mine: bool, peers: Vec<String>, public_host: String) {
    let self_url = format!("http://{public_host}:{port}");
    let mut node = Node::load(data_dir, self_url.clone());
    node.peers = peers.into_iter().map(|p| p.trim_end_matches('/').to_string()).collect();
    println!("AuraChain node v{} | network {}", env!("CARGO_PKG_VERSION"), chain::NETWORK);
    println!("  genesis  {}", node.blocks[0].header.hash_hex());
    println!("  height   {}", node.blocks.len() - 1);
    println!("  api      {self_url}   (explorer: open it in a browser)");
    if let Some(k) = &key {
        println!("  identity {}  (mining: {mine}, VPoS validator: yes)", k.address());
    }
    let ctx = Arc::new(Ctx { node: Mutex::new(node), tip: AtomicU64::new(0), key, hashrate: AtomicU64::new(0) });

    let server = Arc::new(tiny_http::Server::http(("0.0.0.0", port)).expect("cannot bind port"));
    for _ in 0..4 {
        let (s, c) = (server.clone(), ctx.clone());
        thread::spawn(move || loop {
            if let Ok(req) = s.recv() {
                handle(&c, req);
            }
        });
    }
    {
        let c = ctx.clone();
        thread::spawn(move || sync_loop(c));
    }
    if ctx.key.is_some() {
        let c = ctx.clone();
        thread::spawn(move || validator_loop(c));
        if mine {
            let c = ctx.clone();
            thread::spawn(move || miner_loop(c));
        }
    }
    loop {
        thread::sleep(Duration::from_secs(3600));
    }
}
