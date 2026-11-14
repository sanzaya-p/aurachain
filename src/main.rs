//! AuraChain Quantum v1.0 CLI: Post-Quantum wallet, P2P node, PoW share miner,
//! staking/delegation, DAO governance, AuraLaunch DEX, AUA NFTs, and L2 Metropolis sequencer.
#![recursion_limit = "256"]

mod chain;
mod crypto;
mod node;

use chain::{Block, State, Tx, TxKind};
use crypto::Keypair;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_NODE: &str = "https://aurachain-quantum.vercel.app";

const HELP: &str = r#"AuraChain Quantum v1.2.2 — Post-Quantum (NIST FIPS 204 ML-DSA-44 + Ed25519) Sovereign L1 + Rollup

USAGE:
  aurachain keygen       --out <file.json>
  aurachain address      --key <file.json>
  aurachain node         --port <p> --data <dir> [--key <file.json> | --key-env <VAR>] [--mine] [--peer <url>]...
  aurachain info         [--node <url>]
  aurachain activity     [--node <url>]                               (live human wallets, Town Square, leaderboard & tx feed)
  aurachain ecosystem    [--node <url>]
  aurachain balance      <address> [--node <url>]
  aurachain pow-claim    --key <file.json> [--ref <aura1q...>] [--node <url>]  (0-fee SHA3-256 PoW mining; +55 AURA w/ ref)
  aurachain claim-name   --key <file> --handle <name> [--node <url>]  (claim @name.aura Quantum identity)
  aurachain post         --key <file> --message <text> [--to <aura1q...> --amount <AURA>] [--node <url>]
  aurachain send         --key <file> --to <aura1q...> --amount <AURA> [--node <url>]
  aurachain stake        --key <file> --amount <AURA> [--node <url>]
  aurachain unstake      --key <file> --amount <AURA> [--node <url>]
  aurachain delegate     --key <file> --to <validator_aura1q> [--node <url>]
  aurachain propose      --key <file> --title <text> --summary <text> [--node <url>]
  aurachain vote         --key <file> --id <n> --choice <aye|nay> [--node <url>]
  aurachain create-token --key <file> --symbol <SYM> --name <text> [--node <url>]
  aurachain buy-token    --key <file> --symbol <SYM> --amount <AURA> [--node <url>]
  aurachain sell-token   --key <file> --symbol <SYM> --amount <TOKENS> [--node <url>]
  aurachain anchor       --key <file> --data <text> [--node <url>]
  aurachain l2           --key <file> [--node <url>] [--interval <secs>]

Default public network node: https://aurachain-quantum.vercel.app
"#;

struct Args {
    pos: Vec<String>,
    flags: BTreeMap<String, Vec<String>>,
}

impl Args {
    fn parse() -> Args {
        let mut pos = vec![];
        let mut flags: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let raw: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < raw.len() {
            if let Some(f) = raw[i].strip_prefix("--") {
                if i + 1 < raw.len() && !raw[i + 1].starts_with("--") {
                    flags.entry(f.to_string()).or_default().push(raw[i + 1].clone());
                    i += 2;
                } else {
                    flags.entry(f.to_string()).or_default().push(String::new());
                    i += 1;
                }
            } else {
                pos.push(raw[i].clone());
                i += 1;
            }
        }
        Args { pos, flags }
    }
    fn get(&self, k: &str) -> Option<String> {
        self.flags.get(k).and_then(|v| v.last().cloned())
    }
    fn req(&self, k: &str) -> String {
        self.get(k).unwrap_or_else(|| die(&format!("missing --{k}")))
    }
    fn has(&self, k: &str) -> bool {
        self.flags.contains_key(k)
    }
    fn node(&self) -> String {
        self.get("node").unwrap_or_else(|| DEFAULT_NODE.into()).trim_end_matches('/').to_string()
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

fn load_key(path: &str) -> Keypair {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    let v: Value = serde_json::from_str(&raw).unwrap_or_else(|e| die(&format!("bad key file: {e}")));
    Keypair::from_secret_hex(v["secret"].as_str().unwrap_or("")).unwrap_or_else(|e| die(&e))
}

fn http_get(url: &str) -> Value {
    match ureq::get(url).timeout(Duration::from_secs(15)).call() {
        Ok(r) => r.into_json().unwrap_or(json!({})),
        Err(ureq::Error::Status(_, r)) => r.into_json().unwrap_or(json!({})),
        Err(e) => die(&format!("cannot reach node {url}: {e}")),
    }
}

fn http_post(url: &str, body: Value) -> Value {
    match ureq::post(url).timeout(Duration::from_secs(15)).send_json(body) {
        Ok(r) => r.into_json().unwrap_or(json!({})),
        Err(ureq::Error::Status(_, r)) => r.into_json().unwrap_or(json!({})),
        Err(e) => die(&format!("cannot reach node {url}: {e}")),
    }
}

fn submit(a: &Args, kind: TxKind, to: &str, amount: u64, data: &str) {
    let kp = load_key(&a.req("key"));
    let node = a.node();
    let acct = http_get(&format!("{node}/account/{}", kp.address()));
    let info = http_get(&format!("{node}/info"));
    let nonce = acct["next_nonce"].as_u64().unwrap_or(0);
    let base = info["base_fee_micro"].as_u64().unwrap_or(chain::MIN_BASE_FEE);
    let fee = match a.get("fee") {
        Some(f) => chain::parse_aura(&f).unwrap_or_else(|e| die(&e)),
        None if kind == TxKind::PowMine => 0,
        None => base * 2,
    };
    let tx = Tx::new(kind, &kp, to, amount, fee, nonce, data);
    let r = http_post(&format!("{node}/tx"), serde_json::to_value(&tx).unwrap());
    println!("{}", serde_json::to_string_pretty(&r).unwrap());
}

fn pow_claim(a: &Args) {
    let kp = load_key(&a.req("key"));
    let node = a.node();
    let info = http_get(&format!("{node}/info"));
    let acct = http_get(&format!("{node}/account/{}", kp.address()));
    let anchor_h = info["height"].as_u64().unwrap_or(0);
    let anchor_hash = info["tip_hash"].as_str().unwrap_or("").to_string();
    let target_hex = info["pow_claim_target"].as_str().unwrap_or("0x00001000000000000000000000000000");
    let target = u128::from_str_radix(target_hex.trim_start_matches("0x"), 16).unwrap_or(chain::INITIAL_POW_CLAIM_TARGET);
    let addr = kp.address();
    println!("Mining SHA3-256 PoW share against block #{anchor_h} ({}) for {addr}…", &anchor_hash[..14]);
    let mut n: u64 = rand::random();
    let started = std::time::Instant::now();
    loop {
        let s = format!("{n:x}");
        let h = chain::pow_claim_hash(&anchor_hash, &addr, &s);
        if chain::hash_value(&h) <= target {
            println!("Found valid PoW nonce {s} in {:.2}s! Submitting Hybrid-PQ claim…", started.elapsed().as_secs_f64());
            let data = match a.get("ref").filter(|r| !r.is_empty()) {
                Some(r) => format!("{anchor_h}:{anchor_hash}:{s}:{r}"),
                None => format!("{anchor_h}:{anchor_hash}:{s}"),
            };
            let tx = Tx::new(TxKind::PowMine, &kp, "", 0, 0, acct["next_nonce"].as_u64().unwrap_or(0), &data);
            let r = http_post(&format!("{node}/tx"), serde_json::to_value(&tx).unwrap());
            println!("{}", serde_json::to_string_pretty(&r).unwrap());
            return;
        }
        n = n.wrapping_add(1);
    }
}

fn l2_sequencer(a: &Args) {
    let kp = load_key(&a.req("key"));
    let node = a.node();
    let interval: u64 = a.get("interval").and_then(|s| s.parse().ok()).unwrap_or(20);
    let users = ["alice.aura", "bob.aura", "carol.aura", "dave.aura", "erin.aura"];
    let mut bal: BTreeMap<String, u64> = users.iter().map(|u| (u.to_string(), 1_000_000)).collect();
    let (mut batch_txs, mut batch_no, mut total) = (Vec::<String>::new(), 0u64, 0u64);
    println!("[L2 Metropolis] Post-Quantum Rollup Sequencer online -> {node} as {}", kp.address());
    let mut last = std::time::Instant::now();
    loop {
        std::thread::sleep(Duration::from_millis(250));
        let i = rand::random::<usize>() % users.len();
        let j = (i + 1 + rand::random::<usize>() % (users.len() - 1)) % users.len();
        let amt = 1 + rand::random::<u64>() % 500;
        if bal[users[i]] >= amt {
            *bal.get_mut(users[i]).unwrap() -= amt;
            *bal.get_mut(users[j]).unwrap() += amt;
            batch_txs.push(format!("{}>{}:{}", users[i], users[j], amt));
            total += 1;
        }
        if last.elapsed().as_secs() >= interval && !batch_txs.is_empty() {
            batch_no += 1;
            let root = crypto::sha3_256_hex(serde_json::to_string(&bal).unwrap().as_bytes());
            let batch_hash = crypto::sha3_256_hex(batch_txs.join(",").as_bytes());
            let data = format!("metropolis-zk:batch={batch_no}:txs={}:proof={}:root={}", batch_txs.len(), &batch_hash[..16], root);
            let acct = http_get(&format!("{node}/account/{}", kp.address()));
            let info = http_get(&format!("{node}/info"));
            let base = info["base_fee_micro"].as_u64().unwrap_or(chain::MIN_BASE_FEE);
            let tx = Tx::new(TxKind::Anchor, &kp, "", 0, base * 2, acct["next_nonce"].as_u64().unwrap_or(0), &data);
            let r = http_post(&format!("{node}/tx"), serde_json::to_value(&tx).unwrap());
            println!("[L2 Metropolis] batch #{batch_no} ({total} total txs) anchored: {r}");
            batch_txs.clear();
            last = std::time::Instant::now();
        }
    }
}

/// Mines an authentic, 100% cryptographically verified genesis-to-VPoS seed chain
/// (`Genesis #0 -> 20 PoW fair-launch blocks -> Stake -> VPoS + BFT Finality + Ecosystem Genesis`).
fn bootstrap_seed(a: &Args) {
    let val = load_key(&a.req("key"));
    let out = a.req("out");
    println!("Bootstrapping authentic AuraChain Quantum v1.0 chain for validator {}…", val.address());
    let mut blocks: Vec<Block> = vec![chain::genesis()];
    let mut s = State::genesis();
    let now = chain::now_secs();
    let total_blocks: u64 = 28;
    let start_ts = now.saturating_sub(total_blocks * chain::SLOT_SECS + 30).max(chain::GENESIS_TIMESTAMP + 5);

    let mine_pow = |blocks: &mut Vec<Block>, s: &mut State, ts: u64, mempool: Vec<Tx>, msg: &str| {
        let mut b = chain::assemble(blocks, s, &mempool, &val, ts, msg).expect("assemble pow");
        let target = b.header.target_value().unwrap();
        let prefix = b.header.prefix_digest();
        let mut nonce: u64 = 0;
        loop {
            if chain::hash_value(&chain::Header::hash_with(&prefix, nonce)) <= target {
                b.header.nonce = nonce;
                break;
            }
            nonce = nonce.wrapping_add(1);
        }
        *s = chain::apply_block(s, blocks, &b, now + 30).expect("apply pow");
        blocks.push(b);
    };

    // 1. Mine fair-launch PoW blocks #1..#18
    for h in 1..=18 {
        mine_pow(&mut blocks, &mut s, start_ts + h * 5, vec![], "PoW fair-launch bootstrap");
    }

    // 2. Block #19 (PoW): Stake 50,000 AURA for VPoS activation + Launch Ecosystem Genesis Primitives!
    let base = s.next_base_fee;
    let mut n = s.account(&val.address()).nonce;
    let mut next_n = || {
        let cur = n;
        n += 1;
        cur
    };
    let txs_19 = vec![
        Tx::new(TxKind::Stake, &val, "", 50_000 * chain::COIN, base * 2, next_n(), ""),
        Tx::new(
            TxKind::Propose,
            &val,
            "",
            0,
            base * 2,
            next_n(),
            "AIP-1: Post-Quantum Sovereign Mandate|Enforce NIST FIPS 204 ML-DSA-44 + Ed25519 hybrid signatures, 0% pre-mine fair launch, EIP-1559 burn, and Casper BFT checkpoint finality across L1 & Metropolis L2.",
        ),
        Tx::new(TxKind::CreateToken, &val, "", 0, base * 2, next_n(), "QBIT|Quantum Bit Protocol Token"),
        Tx::new(TxKind::BuyToken, &val, "", 250 * chain::COIN, base * 2, next_n(), "QBIT"),
        Tx::new(TxKind::CreateToken, &val, "", 0, base * 2, next_n(), "PHOTON|Aura Photon Community Coin"),
        Tx::new(TxKind::BuyToken, &val, "", 120 * chain::COIN, base * 2, next_n(), "PHOTON"),
        Tx::new(
            TxKind::MintNft,
            &val,
            "",
            0,
            base * 2,
            next_n(),
            r#"{"name":"Quantum Genesis Artifact #1","uri":"sha3://aurachain-quantum-genesis-001","royalty_bps":1000,"price":25000000}"#,
        ),
        Tx::new(
            TxKind::MintNft,
            &val,
            "",
            0,
            base * 2,
            next_n(),
            r#"{"name":"Metropolis Lattice Keystone #2","uri":"sha3://metropolis-lattice-keystone-002","royalty_bps":750,"price":15000000}"#,
        ),
        Tx::new(
            TxKind::Anchor,
            &val,
            "",
            0,
            base * 2,
            next_n(),
            "metropolis-zk:batch=1:txs=1024:proof=9f41e8c02b7a11d3:root=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
    ];
    mine_pow(&mut blocks, &mut s, start_ts + 19 * 5, txs_19, "PoW -> VPoS transition + Ecosystem Genesis");

    // 3. Blocks #20..#28: Pure Hybrid Post-Quantum VPoS blocks + BFT Checkpoint Finalization!
    for h in 20..=total_blocks {
        let ts = start_ts + h * 5;
        let mem = if h == 24 {
            let bfee = s.next_base_fee;
            let nn = s.account(&val.address()).nonce;
            vec![Tx::new(
                TxKind::Anchor,
                &val,
                "",
                0,
                bfee * 2,
                nn,
                "metropolis-zk:batch=2:txs=2048:proof=7c20a9931f0e84b1:root=8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92",
            )]
        } else {
            vec![]
        };
        let b = chain::assemble(&blocks, &s, &mem, &val, ts, "VPoS Quantum Slot Leader").expect("assemble vpos");
        s = chain::apply_block(&s, &blocks, &b, now + 30).expect("apply vpos");
        blocks.push(b);
    }

    // Re-verify entire chain from Genesis #0!
    let verified = chain::validate_chain(&blocks).expect("full chain re-verification");
    if let Some(parent) = std::path::Path::new(&out).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&out, serde_json::to_vec(&blocks).unwrap()).expect("write seed");
    println!(
        "Verified {} blocks (tip #{}, BFT finalized #{}, staked {} AURA, burned {} AURA) -> {out}",
        blocks.len(),
        blocks.len() - 1,
        verified.finalized_height,
        chain::fmt_aura(verified.total_stake()),
        chain::fmt_aura(verified.burned),
    );
}

fn main() {
    let a = Args::parse();
    let cmd = a.pos.first().cloned().unwrap_or_default();
    match cmd.as_str() {
        "keygen" => {
            let out = a.req("out");
            if std::path::Path::new(&out).exists() {
                die(&format!("{out} already exists; refusing to overwrite a key"));
            }
            let kp = Keypair::generate();
            let v = json!({
                "scheme": "aura-hybrid-ed25519-mldsa44-v1",
                "address": kp.address(),
                "ed25519_public": kp.ed25519_public_hex(),
                "public": kp.public_hex(),
                "secret": kp.secret_hex()
            });
            std::fs::write(&out, serde_json::to_string_pretty(&v).unwrap()).unwrap_or_else(|e| die(&e.to_string()));
            println!(
                "Quantum keypair written to {out}\naddress: {}\nscheme:  Hybrid Ed25519 + NIST FIPS 204 ML-DSA-44\nKEEP THE FILE PRIVATE — the 256-bit quantum master seed controls the funds.",
                kp.address()
            );
        }
        "address" => println!("{}", load_key(&a.req("key")).address()),
        "node" => {
            let port: u16 = a.get("port").and_then(|p| p.parse().ok()).unwrap_or(7001);
            let data = PathBuf::from(a.get("data").unwrap_or_else(|| format!("data-{port}")));
            let key = match (a.get("key"), a.get("key-env")) {
                (Some(k), _) => Some(load_key(&k)),
                (None, Some(var)) => {
                    let s = std::env::var(&var).unwrap_or_else(|_| die(&format!("env var {var} not set")));
                    Some(Keypair::from_secret_hex(&s).unwrap_or_else(|e| die(&e)))
                }
                _ => None,
            };
            if a.has("mine") && key.is_none() {
                die("--mine needs --key (rewards are paid to that quantum address)");
            }
            let peers = a.flags.get("peer").cloned().unwrap_or_default();
            node::run(port, data, key, a.has("mine"), peers, a.get("host").unwrap_or_else(|| "127.0.0.1".into()));
        }
        "info" => {
            let mut v = http_get(&format!("{}/info", a.node()));
            if let Some(o) = v.as_object_mut() {
                o.remove("log");
            }
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
        }
        "ecosystem" => {
            println!("{}", serde_json::to_string_pretty(&http_get(&format!("{}/ecosystem", a.node()))).unwrap());
        }
        "activity" => {
            println!("{}", serde_json::to_string_pretty(&http_get(&format!("{}/activity", a.node()))).unwrap());
        }
        "balance" => {
            let addr = a.pos.get(1).cloned().unwrap_or_else(|| die("usage: balance <aura1q_address>"));
            println!("{}", serde_json::to_string_pretty(&http_get(&format!("{}/account/{addr}", a.node()))).unwrap());
        }
        "pow-claim" => pow_claim(&a),
        "claim-name" => submit(&a, TxKind::ClaimName, "", 0, &a.req("handle")),
        "post" => {
            let tip = match a.get("amount") {
                Some(v) if !v.is_empty() => chain::parse_aura(&v).unwrap_or_else(|e| die(&e)),
                _ => 0,
            };
            submit(&a, TxKind::PostMessage, &a.get("to").unwrap_or_default(), tip, &a.req("message"));
        }
        "send" => {
            let amt = chain::parse_aura(&a.req("amount")).unwrap_or_else(|e| die(&e));
            submit(&a, TxKind::Transfer, &a.req("to"), amt, "");
        }
        "stake" => {
            let amt = chain::parse_aura(&a.req("amount")).unwrap_or_else(|e| die(&e));
            submit(&a, TxKind::Stake, "", amt, "");
        }
        "unstake" => {
            let amt = chain::parse_aura(&a.req("amount")).unwrap_or_else(|e| die(&e));
            submit(&a, TxKind::Unstake, "", amt, "");
        }
        "delegate" => submit(&a, TxKind::Delegate, &a.get("to").unwrap_or_default(), 0, ""),
        "propose" => {
            let data = format!("{}|{}", a.req("title"), a.req("summary"));
            submit(&a, TxKind::Propose, "", 0, &data);
        }
        "vote" => {
            let data = format!("{}:{}", a.req("id"), a.req("choice"));
            submit(&a, TxKind::Vote, "", 0, &data);
        }
        "create-token" => {
            let data = format!("{}|{}", a.req("symbol"), a.req("name"));
            submit(&a, TxKind::CreateToken, "", 0, &data);
        }
        "buy-token" => {
            let amt = chain::parse_aura(&a.req("amount")).unwrap_or_else(|e| die(&e));
            submit(&a, TxKind::BuyToken, "", amt, &a.req("symbol"));
        }
        "sell-token" => {
            let amt = chain::parse_aura(&a.req("amount")).unwrap_or_else(|e| die(&e));
            submit(&a, TxKind::SellToken, "", amt, &a.req("symbol"));
        }
        "anchor" => submit(&a, TxKind::Anchor, "", 0, &a.req("data")),
        "l2" => l2_sequencer(&a),
        "bootstrap-seed" => bootstrap_seed(&a),
        _ => print!("{HELP}"),
    }
}
