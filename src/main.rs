//! AuraChain command-line entry point: node, wallet and L2 sequencer demo.

mod chain;
mod crypto;
mod node;

use chain::{Tx, TxKind};
use crypto::Keypair;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_NODE: &str = "http://127.0.0.1:7001";

const HELP: &str = r#"AuraChain v0.3 - fair-launch PoW -> VPoS settlement layer (devnet)

USAGE:
  aurachain keygen  --out <file.json>
  aurachain address --key <file.json>
  aurachain node    --port <p> --data <dir> [--key <file.json> | --key-env <VAR>] [--mine] [--peer <url>]... [--host <public-ip>]
  aurachain info    [--node <url>]
  aurachain balance <address> [--node <url>]
  aurachain send    --key <file> --to <address> --amount <AURA> [--fee <AURA>] [--node <url>]
  aurachain stake   --key <file> --amount <AURA> [--node <url>]
  aurachain unstake --key <file> --amount <AURA> [--node <url>]
  aurachain anchor  --key <file> --data <text> [--node <url>]
  aurachain l2      --key <file> [--node <url>] [--interval <secs>]   (Metropolis L2 sequencer demo)

Default node: http://127.0.0.1:7001
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
    std::process::exit(1)
}

fn load_key(path: &str) -> Keypair {
    let raw = std::fs::read_to_string(path).unwrap_or_else(|e| die(&format!("cannot read {path}: {e}")));
    let v: Value = serde_json::from_str(&raw).unwrap_or_else(|e| die(&format!("bad key file: {e}")));
    Keypair::from_secret_hex(v["secret"].as_str().unwrap_or("")).unwrap_or_else(|e| die(&e))
}

fn http_get(url: &str) -> Value {
    match ureq::get(url).timeout(Duration::from_secs(10)).call() {
        Ok(r) => r.into_json().unwrap_or(json!({})),
        Err(ureq::Error::Status(_, r)) => r.into_json().unwrap_or(json!({})),
        Err(e) => die(&format!("cannot reach node {url}: {e}")),
    }
}

fn http_post(url: &str, body: Value) -> Value {
    match ureq::post(url).timeout(Duration::from_secs(10)).send_json(body) {
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
        None => base * 2, // base fee (burned) + equal tip for the producer
    };
    let tx = Tx::new(kind, &kp, to, amount, fee, nonce, data);
    let r = http_post(&format!("{node}/tx"), serde_json::to_value(&tx).unwrap());
    println!("{}", serde_json::to_string_pretty(&r).unwrap());
}

fn l2_sequencer(a: &Args) {
    // "Metropolis" L2 demo: executes transfers off-chain at high speed, then posts
    // a compressed batch commitment (tx count + state root) to the L1 via `anchor`.
    let kp = load_key(&a.req("key"));
    let node = a.node();
    let interval: u64 = a.get("interval").and_then(|s| s.parse().ok()).unwrap_or(20);
    let users = ["alice", "bob", "carol", "dave", "erin"];
    let mut bal: BTreeMap<String, u64> = users.iter().map(|u| (u.to_string(), 1_000_000)).collect();
    let (mut batch_txs, mut batch_no, mut total) = (Vec::<String>::new(), 0u64, 0u64);
    println!("[L2 Metropolis] sequencer online; anchoring to {node} every {interval}s as {}", kp.address());
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
            let root = crypto::sha256_hex(serde_json::to_string(&bal).unwrap().as_bytes());
            let batch_hash = crypto::sha256_hex(batch_txs.join(",").as_bytes());
            let data = format!("metropolis:batch={batch_no}:txs={}:batch={}:root={}", batch_txs.len(), &batch_hash[..16], root);
            println!("[L2 Metropolis] batch #{batch_no}: {} L2 txs ({} total) -> anchoring root {}…", batch_txs.len(), total, &root[..16]);
            let acct = http_get(&format!("{node}/account/{}", kp.address()));
            let info = http_get(&format!("{node}/info"));
            let base = info["base_fee_micro"].as_u64().unwrap_or(chain::MIN_BASE_FEE);
            let tx = Tx::new(TxKind::Anchor, &kp, "", 0, base * 2, acct["next_nonce"].as_u64().unwrap_or(0), &data);
            let r = http_post(&format!("{node}/tx"), serde_json::to_value(&tx).unwrap());
            println!("[L2 Metropolis] L1 response: {r}");
            batch_txs.clear();
            last = std::time::Instant::now();
        }
    }
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
            let v = json!({"address": kp.address(), "public": kp.public_hex(), "secret": kp.secret_hex()});
            std::fs::write(&out, serde_json::to_string_pretty(&v).unwrap()).unwrap_or_else(|e| die(&e.to_string()));
            println!("new key written to {out}\naddress: {}\nKEEP THE FILE PRIVATE - the secret controls the funds.", kp.address());
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
                die("--mine needs --key (rewards are paid to that address)");
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
        "balance" => {
            let addr = a.pos.get(1).cloned().unwrap_or_else(|| die("usage: balance <address>"));
            println!("{}", serde_json::to_string_pretty(&http_get(&format!("{}/account/{addr}", a.node()))).unwrap());
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
        "anchor" => submit(&a, TxKind::Anchor, "", 0, &a.req("data")),
        "l2" => l2_sequencer(&a),
        _ => print!("{HELP}"),
    }
}
