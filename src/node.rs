//! Full P2P node: chain storage, mempool, HTTP/JSON API, peer sync,
//! BFT finality fork-choice guard, SHA3-256 PoW miner, and VPoS validator.

use crate::chain::{self, Block, State, Tx, TxKind};
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
    pub tip: AtomicU64,
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
            "block #{h} {} (fin #{}) by {}… ({} txs) {}",
            b.header.consensus.to_uppercase(),
            ns.finalized_height,
            &b.header.producer[..14.min(b.header.producer.len())],
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
        // BFT Finality Guard: never reorg across an irreversibly finalized checkpoint!
        let fin_h = self.state.finalized_height as usize;
        if fin_h > 0 {
            if cand.len() <= fin_h || cand[fin_h].header.hash_hex() != self.state.finalized_hash {
                log(self, format!("rejected fork violating BFT finalized checkpoint #{fin_h}"));
                return false;
            }
        }
        let old = self.blocks.len();
        let mut leftovers: Vec<Tx> = self.blocks.iter().flat_map(|b| b.txs.clone()).collect();
        leftovers.extend(self.mempool.drain(..));
        self.blocks = cand;
        self.state = cand_state;
        self.mempool = leftovers;
        self.prune_mempool();
        self.save();
        let msg = format!("sync/reorg: switched to heavier chain (height {} -> {})", old - 1, self.blocks.len() - 1);
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
        if tx.kind != TxKind::PowMine && tx.fee < chain::MIN_BASE_FEE {
            return Err("fee below minimum base fee".into());
        }
        if self.mempool.len() >= 5000 {
            return Err("mempool full".into());
        }
        let next_h = self.blocks.last().unwrap().header.height + 1;
        let mut sim = self.state.clone();
        sim.recent_hashes.insert(next_h - 1, self.blocks.last().unwrap().header.hash_hex());
        let mut pending: Vec<&Tx> = self
            .mempool
            .iter()
            .filter(|t| t.sender().map(|a| a == from).unwrap_or(false))
            .collect();
        pending.sort_by_key(|t| t.nonce);
        for t in pending {
            let _ = chain::apply_tx(&mut sim, t, chain::MIN_BASE_FEE, next_h);
        }
        chain::apply_tx(&mut sim, &tx, chain::MIN_BASE_FEE, next_h)?;
        let id = tx.id();
        log(self, format!("mempool += {} {} from {}…", tx.kind.as_str(), &id[..12], &from[..14]));
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
        .timeout(Duration::from_secs(6))
        .send_json(body.clone())
        .map_err(|e| e.to_string())?
        .into_json::<Value>()
        .map_err(|e| e.to_string())
}

fn get_json(url: &str) -> Result<Value, String> {
    ureq::get(url)
        .timeout(Duration::from_secs(12))
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
    let mut round: u64 = 0;
    loop {
        thread::sleep(Duration::from_secs(4));
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
                // Chunked full sync from genesis so peers can sync arbitrarily long chains cleanly.
                let mut full: Vec<Block> = vec![];
                let mut cur = 0u64;
                let target_h = tip["height"].as_u64().unwrap_or(0);
                let mut ok_all = true;
                while cur <= target_h {
                    match get_json(&format!("{p}/blocks?from={cur}&limit=200"))
                        .and_then(|v| serde_json::from_value::<Vec<Block>>(v).map_err(|e| e.to_string()))
                    {
                        Ok(chunk) if !chunk.is_empty() => {
                            cur = chunk.last().unwrap().header.height + 1;
                            full.extend(chunk);
                        }
                        _ => {
                            ok_all = false;
                            break;
                        }
                    }
                }
                if ok_all && !full.is_empty() {
                    cand = Some(full);
                }
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
                chain::assemble(&n.blocks, &n.state, &n.mempool, key, chain::now_secs(), "mined on AuraChain Quantum").ok()
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
                Err(e) => log(&mut n, format!("mined block discarded: {e}")),
            }
        }
    }
}

fn validator_loop(ctx: Arc<Ctx>) {
    let key = ctx.key.as_ref().unwrap();
    let me = key.address();
    loop {
        thread::sleep(Duration::from_millis(500));
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
            match chain::assemble(&n.blocks, &n.state, &n.mempool, key, now, "VPoS Quantum Slot Leader") {
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
        "version": env!("CARGO_PKG_VERSION"),
        "network": chain::NETWORK,
        "crypto_suite": "Hybrid Ed25519 + NIST FIPS 204 ML-DSA-44 + SHA3-256",
        "height": tip.height,
        "tip_hash": tip.hash_hex(),
        "tip_timestamp": tip.timestamp,
        "finalized_height": s.finalized_height,
        "finalized_hash": s.finalized_hash,
        "genesis_hash": n.blocks[0].header.hash_hex(),
        "genesis_message": chain::GENESIS_MESSAGE,
        "next_consensus": if chain::is_pos(next, s) { "pos" } else { "pow" },
        "pos_start_height": chain::POS_START_HEIGHT,
        "chainwork": s.chainwork.to_string(),
        "difficulty": (u128::MAX / target.max(1)) as f64,
        "target": chain::target_hex(target),
        "pow_claim_target": chain::target_hex(s.pow_claim_target),
        "pow_claim_reward": chain::fmt_aura(chain::POW_CLAIM_REWARD),
        "minted": chain::fmt_aura(s.minted),
        "burned": chain::fmt_aura(s.burned),
        "circulating": chain::fmt_aura(s.minted.saturating_sub(s.burned)),
        "max_supply": chain::fmt_aura(chain::MAX_SUPPLY),
        "block_reward": chain::fmt_aura(chain::block_reward(next, s.minted)),
        "base_fee": chain::fmt_aura(s.next_base_fee),
        "base_fee_micro": s.next_base_fee,
        "total_staked": chain::fmt_aura(s.total_stake()),
        "validators": vals,
        "accounts": s.accounts.len(),
        "proposals_count": s.proposals.len(),
        "tokens_count": s.tokens.len(),
        "nfts_count": s.nfts.len(),
        "l2_batches_count": s.l2_batches.len(),
        "slashed_count": s.slashed.len(),
        "mempool": n.mempool.len(),
        "peers": n.peers,
        "self_url": n.self_url,
        "node_address": ctx.key.as_ref().map(|k| k.address()),
        "hashrate": ctx.hashrate.load(Ordering::Relaxed),
        "log": n.log.iter().rev().take(10).collect::<Vec<_>>(),
    })
}

fn ecosystem_json(s: &State, height: u64) -> Value {
    let proposals: Vec<Value> = s
        .proposals
        .values()
        .rev()
        .map(|p| {
            let status = if height <= p.end_height {
                "active"
            } else if p.aye_stake > p.nay_stake && p.aye_stake > 0 {
                "passed"
            } else {
                "rejected"
            };
            json!({
                "id": p.id,
                "proposer": p.proposer,
                "title": p.title,
                "summary": p.summary,
                "created_height": p.created_height,
                "end_height": p.end_height,
                "aye_aura": chain::fmt_aura(p.aye_stake),
                "nay_aura": chain::fmt_aura(p.nay_stake),
                "voters_count": p.voters.len(),
                "status": status,
            })
        })
        .collect();
    let tokens: Vec<Value> = s
        .tokens
        .values()
        .map(|t| {
            json!({
                "symbol": t.symbol,
                "name": t.name,
                "creator": t.creator,
                "aura_reserve": chain::fmt_aura(t.aura_reserve),
                "token_reserve": chain::fmt_aura(t.token_reserve),
                "spot_price_aura": chain::fmt_aura(t.spot_price_micro()),
                "holders": t.balances.values().filter(|&&b| b > 0).count(),
                "trades": t.trades,
            })
        })
        .collect();
    let nfts: Vec<Value> = s
        .nfts
        .values()
        .rev()
        .map(|nft| {
            json!({
                "id": nft.id,
                "name": nft.name,
                "uri": nft.uri,
                "creator": nft.creator,
                "owner": nft.owner,
                "royalty_bps": nft.royalty_bps,
                "price_aura": if nft.price_micro > 0 { Some(chain::fmt_aura(nft.price_micro)) } else { None },
                "price_micro": nft.price_micro,
                "sales": nft.sales,
            })
        })
        .collect();
    json!({
        "proposals": proposals,
        "tokens": tokens,
        "nfts": nfts,
        "l2_batches": s.l2_batches.iter().rev().take(25).collect::<Vec<_>>(),
        "slashes": s.slash_history,
    })
}

fn respond(req: tiny_http::Request, code: u16, body: String, ctype: &str) {
    let resp = tiny_http::Response::from_string(body)
        .with_status_code(code)
        .with_header(tiny_http::Header::from_bytes("Content-Type", ctype).unwrap())
        .with_header(tiny_http::Header::from_bytes("Access-Control-Allow-Origin", "*").unwrap())
        .with_header(tiny_http::Header::from_bytes("Access-Control-Allow-Headers", "Content-Type").unwrap())
        .with_header(tiny_http::Header::from_bytes("Access-Control-Allow-Methods", "GET, POST, OPTIONS").unwrap());
    let _ = req.respond(resp);
}

fn handle(ctx: &Arc<Ctx>, mut req: tiny_http::Request) {
    let url = req.url().to_string();
    let (path, query) = url.split_once('?').unwrap_or((&url, ""));
    let q = |k: &str| -> Option<u64> {
        query.split('&').find_map(|kv| kv.split_once('=').filter(|(a, _)| *a == k).and_then(|(_, v)| v.parse().ok()))
    };
    let method = req.method().clone();
    if method == tiny_http::Method::Options {
        return respond(req, 204, String::new(), "text/plain");
    }
    let remote_is_loopback = req.remote_addr().map(|a| a.ip().is_loopback()).unwrap_or(false);
    let mut body = String::new();
    if method == tiny_http::Method::Post {
        let _ = req.as_reader().take(4 << 20).read_to_string(&mut body);
    }
    let ok = |v: Value| (200u16, v);
    let err = |c: u16, e: String| (c, json!({ "error": e }));

    if method == tiny_http::Method::Get && (path == "/" || path == "/index.html") {
        return respond(req, 200, EXPLORER_HTML.to_string(), "text/html; charset=utf-8");
    }

    let (code, out): (u16, Value) = match (method.as_str(), path) {
        ("GET", "/tip") | ("GET", "/pulse") => {
            let n = ctx.node.lock().unwrap();
            let t = &n.blocks.last().unwrap().header;
            ok(json!({
                "height": t.height,
                "hash": t.hash_hex(),
                "finalized_height": n.state.finalized_height,
                "chainwork": n.state.chainwork.to_string()
            }))
        }
        ("GET", "/info") => {
            let n = ctx.node.lock().unwrap();
            ok(info_json(ctx, &n))
        }
        ("GET", "/ecosystem") => {
            let n = ctx.node.lock().unwrap();
            let h = n.blocks.last().unwrap().header.height;
            ok(ecosystem_json(&n.state, h))
        }
        ("GET", "/blocks") => {
            let n = ctx.node.lock().unwrap();
            let from = q("from").unwrap_or(0) as usize;
            let limit = q("limit").unwrap_or(50).min(500) as usize;
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
        ("GET", p) if p.starts_with("/proof/") => {
            let parts: Vec<&str> = p[7..].split('/').collect();
            if parts.len() != 2 {
                err(400, "usage: /proof/<height>/<tx_index>".into())
            } else {
                let n = ctx.node.lock().unwrap();
                let h = parts[0].parse::<usize>().ok();
                let idx = parts[1].parse::<usize>().ok();
                match (h.and_then(|x| n.blocks.get(x)), idx) {
                    (Some(b), Some(i)) if i < b.txs.len() => {
                        let steps = chain::merkle_proof(&b.txs, i).unwrap_or_default();
                        let tx_id = b.txs[i].id();
                        let verified = chain::verify_merkle_proof(&tx_id, &steps, &b.header.tx_root);
                        ok(json!({
                            "height": b.header.height,
                            "block_hash": b.header.hash_hex(),
                            "tx_index": i,
                            "tx_id": tx_id,
                            "tx_root": b.header.tx_root,
                            "steps": steps,
                            "verified": verified,
                        }))
                    }
                    _ => err(404, "block or tx index not found".into()),
                }
            }
        }
        ("GET", p) if p.starts_with("/account/") => {
            let n = ctx.node.lock().unwrap();
            let a = &p[9..];
            let acc = n.state.account(a);
            let tok_bals: serde_json::Map<String, Value> = n
                .state
                .tokens
                .iter()
                .filter_map(|(sym, pool)| {
                    let b = pool.balances.get(a).copied().unwrap_or(0);
                    if b > 0 {
                        Some((sym.clone(), json!({"balance": chain::fmt_aura(b), "micro": b})))
                    } else {
                        None
                    }
                })
                .collect();
            let nfts_owned: Vec<u64> =
                n.state.nfts.values().filter(|nft| nft.owner == a).map(|nft| nft.id).collect();
            ok(json!({
                "address": a,
                "balance": chain::fmt_aura(acc.balance),
                "balance_micro": acc.balance,
                "stake": chain::fmt_aura(acc.stake),
                "stake_micro": acc.stake,
                "delegate": acc.delegate,
                "unbonding": acc.unbonding,
                "token_balances": tok_bals,
                "nfts_owned": nfts_owned,
                "nonce": acc.nonce,
                "next_nonce": n.next_nonce(a),
            }))
        }
        ("GET", "/mempool") => {
            let n = ctx.node.lock().unwrap();
            ok(serde_json::to_value(&n.mempool).unwrap())
        }
        ("GET", "/anchors") => {
            let n = ctx.node.lock().unwrap();
            let v: Vec<Value> = n
                .state
                .l2_batches
                .iter()
                .rev()
                .map(|b| json!({"height": b.l1_height, "from": b.sequencer, "data": b.commitment, "batch_index": b.batch_index}))
                .collect();
            ok(json!(v))
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
    println!("AuraChain Quantum v{} | network {}", env!("CARGO_PKG_VERSION"), chain::NETWORK);
    println!("  crypto   Hybrid Ed25519 + NIST FIPS 204 ML-DSA-44 + SHA3-256");
    println!("  genesis  {}", node.blocks[0].header.hash_hex());
    println!("  height   {} (BFT finalized #{})", node.blocks.len() - 1, node.state.finalized_height);
    println!("  api      {self_url}   (explorer & quantum wallet: open in browser)");
    if let Some(k) = &key {
        println!("  identity {}  (PoW miner: {mine}, VPoS validator: yes)", k.address());
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
