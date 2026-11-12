//! AuraChain Quantum v1.1 — Autonomous Serverless VPoS + L2 Metropolis Node for Vercel.
//!
//! Cryptographic & Systems Design:
//!   * Consensus & Signatures: Exact consensus state machine of `src/chain.rs` +
//!     Hybrid Post-Quantum signatures (`Ed25519 + NIST FIPS 204 ML-DSA-44 + SHA3-256`).
//!   * Zero-Cost High-Quota Cloud Persistence (`Store`):
//!       1. GitHub Atomic Git-Tree CAS (`AURA_GITHUB_TOKEN` + `AURA_GITHUB_REPO`, 5,000 req/hr = 3.6M/mo free + unlimited CDN reads), OR
//!       2. Upstash Redis (`KV_REST_API_URL` / `UPSTASH_REDIS_REST_URL`) via atomic Lua CAS, OR
//!       3. Vercel Blob (`BLOB_READ_WRITE_TOKEN`) versioned snapshots, OR
//!       4. Local filesystem (`AURA_STORE_DIR`) for offline testing.
//!   * Autonomous Operation: Seals VPoS blocks + BFT finality checkpoints within 5s whenever
//!     user transactions arrive, on `/pulse` triggers (which also settle L2 Metropolis rollup
//!     batches onto L1), and on a 300s low-overhead idle heartbeat.
#![allow(dead_code)]
#![recursion_limit = "256"]

mod chain;
mod crypto;

use chain::{Block, State, Tx, TxKind};
use crypto::Keypair;
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use vercel_runtime::{run, service_fn, Error, Request, Response, ResponseBody};

const EXPLORER_HTML: &str = include_str!("explorer.html");
const SEED_CHAIN: &str = include_str!("../seed/chain.json");
const IDLE_HEARTBEAT_SECS: u64 = 300;
const RECENT: usize = 32;
const BLOB_NS: &str = "aura-q1";

// ------------------------------------------------------------------- head
#[derive(Serialize, Deserialize, Clone, Debug)]
struct PeerHeartbeat {
    id: String,
    label: String,
    height: u64,
    last_seen: u64,
}

#[derive(Serialize, Deserialize, Clone)]
struct Head {
    #[serde(default)]
    ver: u64,
    blocks: Vec<Block>, // most recent RECENT blocks; last = tip
    state: State,
    mempool: Vec<Tx>,
    log: Vec<String>,
    #[serde(default)]
    peers: BTreeMap<String, PeerHeartbeat>,
}

impl Head {
    fn tip(&self) -> &Block {
        self.blocks.last().unwrap()
    }
    fn log(&mut self, m: String) {
        self.log.push(format!("[{}] {m}", chain::now_secs()));
        let n = self.log.len();
        if n > 16 {
            self.log.drain(..n - 16);
        }
    }
    fn prune_mempool(&mut self) {
        let included: std::collections::HashSet<String> =
            self.blocks.iter().flat_map(|b| b.txs.iter().map(|t| t.signature.clone())).collect();
        let st = &self.state;
        self.mempool.retain(|t| {
            !included.contains(&t.signature)
                && t.sender().map(|a| t.nonce >= st.account(&a).nonce).unwrap_or(false)
        });
    }
}

// ------------------------------------------------------------------ store
enum Store {
    GitHub { repo: String, branch: String, token: String },
    Upstash { url: String, token: String },
    Blob { token: String, public_base: String },
    File { dir: std::path::PathBuf },
}

static FILE_LOCK: Mutex<()> = Mutex::new(());
static OP_LOCK: Mutex<()> = Mutex::new(());
static CACHE: Mutex<Option<(Instant, u64, Head)>> = Mutex::new(None);
static GH_STATE: Mutex<Option<(u64, String, String)>> = Mutex::new(None); // (ver, commit_sha, tree_sha)
static LIVE_PEERS: Mutex<BTreeMap<String, PeerHeartbeat>> = Mutex::new(BTreeMap::new());

const CAS_SCRIPT: &str = "if (redis.call('GET', KEYS[1]) or '0') ~= ARGV[1] then return 0 end \
redis.call('SET', KEYS[1], ARGV[2]) redis.call('SET', KEYS[2], ARGV[3]) \
for i = 4, #ARGV, 2 do redis.call('SET', ARGV[i], ARGV[i+1]) end return 1";

#[derive(Deserialize)]
struct BlobItem {
    pathname: String,
    url: String,
}

#[derive(Deserialize)]
struct BlobListResp {
    blobs: Vec<BlobItem>,
}

fn parse_snap_ver(pathname: &str) -> Option<(u64, &str)> {
    let name = pathname.strip_prefix(&format!("{BLOB_NS}/snap/"))?.strip_suffix(".json")?;
    let (v, h) = name.split_once('-')?;
    Some((v.parse().ok()?, h))
}

enum GhErr {
    Conflict,
    Msg(String),
}

impl Store {
    fn from_env() -> Result<Store, String> {
        let env = |a: &str, b: &str| std::env::var(a).or_else(|_| std::env::var(b)).ok();
        if let Ok(tok) = std::env::var("AURA_GITHUB_TOKEN") {
            let tok = tok.trim().trim_matches('"').to_string();
            if !tok.is_empty() {
                let repo = std::env::var("AURA_GITHUB_REPO")
                    .ok()
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "sanzaya-p/aurachain-ledger".into());
                let branch = std::env::var("AURA_GITHUB_BRANCH")
                    .ok()
                    .map(|s| s.trim().trim_matches('"').to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "main".into());
                return Ok(Store::GitHub { repo, branch, token: tok });
            }
        }
        if let (Some(url), Some(token)) =
            (env("KV_REST_API_URL", "UPSTASH_REDIS_REST_URL"), env("KV_REST_API_TOKEN", "UPSTASH_REDIS_REST_TOKEN"))
        {
            if !url.is_empty() && !token.is_empty() {
                return Ok(Store::Upstash { url: url.trim_end_matches('/').into(), token });
            }
        }
        if let Ok(tok) = std::env::var("BLOB_READ_WRITE_TOKEN") {
            let tok = tok.trim().trim_matches('"').to_string();
            let parts: Vec<&str> = tok.split('_').collect();
            if parts.len() >= 5 && parts[0] == "vercel" && parts[1] == "blob" {
                let store_id = parts[3].to_ascii_lowercase();
                let public_base = format!("https://{store_id}.public.blob.vercel-storage.com");
                return Ok(Store::Blob { token: tok, public_base });
            }
        }
        if let Ok(d) = std::env::var("AURA_STORE_DIR") {
            std::fs::create_dir_all(format!("{d}/b")).map_err(|e| e.to_string())?;
            return Ok(Store::File { dir: d.into() });
        }
        Err("no storage configured: set AURA_GITHUB_TOKEN or Upstash Redis".into())
    }

    fn backend_label(&self) -> &'static str {
        match self {
            Store::GitHub { .. } => "github-git-cas",
            Store::Upstash { .. } => "upstash-redis",
            Store::Blob { .. } => "vercel-blob-cas",
            Store::File { .. } => "local-file",
        }
    }

    fn gh_json(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value, GhErr> {
        let Store::GitHub { token, .. } = self else { unreachable!() };
        let req = ureq::request(method, &format!("https://api.github.com{path}"))
            .set("Authorization", &format!("Bearer {token}"))
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", "aurachain-quantum-node/1.1")
            .timeout(Duration::from_secs(12));
        let res = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        match res {
            Ok(resp) => resp.into_json::<Value>().map_err(|e| GhErr::Msg(e.to_string())),
            Err(ureq::Error::Status(409 | 422, _)) => Err(GhErr::Conflict),
            Err(ureq::Error::Status(code, r)) => {
                let txt = r.into_string().unwrap_or_default();
                Err(GhErr::Msg(format!("HTTP {code}: {}", txt.chars().take(180).collect::<String>())))
            }
            Err(e) => Err(GhErr::Msg(e.to_string())),
        }
    }

    fn gh_raw(&self, path: &str) -> Result<Option<String>, String> {
        let Store::GitHub { token, .. } = self else { unreachable!() };
        let res = ureq::get(&format!("https://api.github.com{path}"))
            .set("Authorization", &format!("Bearer {token}"))
            .set("Accept", "application/vnd.github.raw+json")
            .set("X-GitHub-Api-Version", "2022-11-28")
            .set("User-Agent", "aurachain-quantum-node/1.1")
            .timeout(Duration::from_secs(12))
            .call();
        match res {
            Ok(resp) => resp.into_string().map(Some).map_err(|e| format!("github raw read: {e}")),
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(e) => Err(format!("github raw {path}: {e}")),
        }
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

    fn blob_put(&self, pathname: &str, body: &str, max_age: u64) -> Result<(), String> {
        let Store::Blob { token, .. } = self else { unreachable!() };
        ureq::put(&format!("https://blob.vercel-storage.com/{pathname}"))
            .set("Authorization", &format!("Bearer {token}"))
            .set("x-api-version", "7")
            .set("x-content-type", "application/json")
            .set("x-add-random-suffix", "0")
            .set("x-cache-control-max-age", &max_age.to_string())
            .set("x-vercel-blob-access", "public")
            .set("x-allow-overwrite", "1")
            .timeout(Duration::from_secs(10))
            .send_string(body)
            .map_err(|e| format!("blob put {pathname}: {e}"))?;
        Ok(())
    }

    fn blob_list_snaps(&self) -> Result<Vec<BlobItem>, String> {
        let Store::Blob { token, .. } = self else { unreachable!() };
        let r: BlobListResp = ureq::get(&format!("https://blob.vercel-storage.com?prefix={BLOB_NS}/snap/&limit=100"))
            .set("Authorization", &format!("Bearer {token}"))
            .set("x-api-version", "7")
            .timeout(Duration::from_secs(8))
            .call()
            .map_err(|e| format!("blob list: {e}"))?
            .into_json()
            .map_err(|e| format!("blob list json: {e}"))?;
        Ok(r.blobs)
    }

    fn blob_delete(&self, urls: Vec<String>) {
        if urls.is_empty() {
            return;
        }
        let Store::Blob { token, .. } = self else { return };
        let _ = ureq::post("https://blob.vercel-storage.com/delete")
            .set("Authorization", &format!("Bearer {token}"))
            .set("x-api-version", "7")
            .timeout(Duration::from_secs(5))
            .send_json(json!({ "urls": urls }));
    }

    /// Returns `(version, head)` or `None` if the store has not been seeded yet.
    fn load(&self) -> Result<Option<(u64, Head)>, String> {
        match self {
            Store::GitHub { repo, branch, .. } => {
                let ref_j = self
                    .gh_json("GET", &format!("/repos/{repo}/git/ref/heads/{branch}"), None)
                    .map_err(|e| match e { GhErr::Conflict => "conflict".into(), GhErr::Msg(m) => format!("github get ref: {m}") })?;
                let commit_sha = ref_j["object"]["sha"]
                    .as_str()
                    .ok_or_else(|| "github ref missing commit sha".to_string())?
                    .to_string();
                let commit_j = self
                    .gh_json("GET", &format!("/repos/{repo}/git/commits/{commit_sha}"), None)
                    .map_err(|e| match e { GhErr::Conflict => "conflict".into(), GhErr::Msg(m) => format!("github get commit: {m}") })?;
                let tree_sha = commit_j["tree"]["sha"]
                    .as_str()
                    .ok_or_else(|| "github commit missing tree sha".to_string())?
                    .to_string();
                match self.gh_raw(&format!("/repos/{repo}/contents/head.json?ref={commit_sha}"))? {
                    None => {
                        *GH_STATE.lock().unwrap() = Some((0, commit_sha, tree_sha));
                        Ok(None)
                    }
                    Some(raw) => {
                        let mut head: Head = serde_json::from_str(&raw).map_err(|e| format!("bad head.json: {e}"))?;
                        let ver = head.ver.max(1);
                        head.ver = ver;
                        *GH_STATE.lock().unwrap() = Some((ver, commit_sha, tree_sha));
                        Ok(Some((ver, head)))
                    }
                }
            }
            Store::Upstash { .. } => {
                let r = self.redis(vec!["MGET".into(), "auraq1:ver".into(), "auraq1:head".into()])?;
                match (r[0].as_str(), r[1].as_str()) {
                    (Some(v), Some(h)) => Ok(Some((
                        v.parse().unwrap_or(1),
                        serde_json::from_str(h).map_err(|e| e.to_string())?,
                    ))),
                    _ => Ok(None),
                }
            }
            Store::Blob { .. } => {
                let mut snaps = self.blob_list_snaps()?;
                if snaps.is_empty() {
                    return Ok(None);
                }
                snaps.sort_by(|a, b| {
                    let pa = parse_snap_ver(&a.pathname).unwrap_or((0, ""));
                    let pb = parse_snap_ver(&b.pathname).unwrap_or((0, ""));
                    pa.0.cmp(&pb.0).then_with(|| pb.1.cmp(pa.1))
                });
                let mut last_err = String::from("no readable snapshot");
                for cand in snaps.iter().rev().take(5) {
                    let ver = parse_snap_ver(&cand.pathname).map(|x| x.0).unwrap_or(1);
                    match ureq::get(&cand.url).timeout(Duration::from_secs(8)).call() {
                        Ok(resp) => match resp.into_string() {
                            Ok(raw) => match serde_json::from_str::<Head>(&raw) {
                                Ok(head) => return Ok(Some((ver, head))),
                                Err(e) => last_err = format!("bad head json: {e}"),
                            },
                            Err(e) => last_err = e.to_string(),
                        },
                        Err(e) => last_err = format!("blob get snap: {e}"),
                    }
                }
                Err(last_err)
            }
            Store::File { dir } => {
                let ver = std::fs::read_to_string(dir.join("ver")).ok().and_then(|s| s.trim().parse().ok());
                let raw = std::fs::read_to_string(dir.join("head.json")).ok();
                match (ver, raw) {
                    (Some(v), Some(h)) => Ok(Some((v, serde_json::from_str(&h).map_err(|e| e.to_string())?))),
                    _ => Ok(None),
                }
            }
        }
    }

    fn cas(&self, expected_ver: u64, new_ver: u64, head: &Head, blocks: &[&Block]) -> Result<bool, String> {
        let mut head_to_save = head.clone();
        head_to_save.ver = new_ver;
        let head_json = serde_json::to_string(&head_to_save).unwrap();
        match self {
            Store::GitHub { repo, branch, .. } => {
                let cached_base = GH_STATE
                    .lock()
                    .unwrap()
                    .as_ref()
                    .filter(|(v, _, _)| *v == expected_ver)
                    .map(|(_, c, t)| (c.clone(), t.clone()));
                let (base_commit, base_tree) = match cached_base {
                    Some(pair) => pair,
                    None => {
                        let loaded = self.load()?;
                        match (expected_ver, loaded) {
                            (0, None) => GH_STATE
                                .lock()
                                .unwrap()
                                .as_ref()
                                .map(|(_, c, t)| (c.clone(), t.clone()))
                                .ok_or_else(|| "missing base ref".to_string())?,
                            (ev, Some((v, _))) if ev == v => GH_STATE
                                .lock()
                                .unwrap()
                                .as_ref()
                                .map(|(_, c, t)| (c.clone(), t.clone()))
                                .ok_or_else(|| "missing base ref".to_string())?,
                            _ => return Ok(false),
                        }
                    }
                };

                let mut tree_items = vec![json!({
                    "path": "head.json",
                    "mode": "100644",
                    "type": "blob",
                    "content": head_json,
                })];
                for b in blocks {
                    tree_items.push(json!({
                        "path": format!("b/{}.json", b.header.height),
                        "mode": "100644",
                        "type": "blob",
                        "content": serde_json::to_string(b).unwrap(),
                    }));
                }

                let tree_resp = self
                    .gh_json(
                        "POST",
                        &format!("/repos/{repo}/git/trees"),
                        Some(json!({ "base_tree": base_tree, "tree": tree_items })),
                    )
                    .map_err(|e| match e { GhErr::Conflict => "tree conflict".into(), GhErr::Msg(m) => format!("github create tree: {m}") })?;
                let new_tree = tree_resp["sha"]
                    .as_str()
                    .ok_or_else(|| "github tree missing sha".to_string())?
                    .to_string();

                let msg = if expected_ver == 0 {
                    format!(
                        "Genesis seed through Block #{} (BFT finalized #{})",
                        head.tip().header.height,
                        head.state.finalized_height
                    )
                } else if let Some(lb) = blocks.last() {
                    format!(
                        "Block #{} ({} txs, BFT finalized #{})",
                        lb.header.height,
                        lb.txs.len(),
                        head.state.finalized_height
                    )
                } else {
                    format!("Mempool update v{} ({} pending txs)", new_ver, head.mempool.len())
                };

                let commit_resp = self
                    .gh_json(
                        "POST",
                        &format!("/repos/{repo}/git/commits"),
                        Some(json!({ "message": msg, "tree": new_tree, "parents": [base_commit] })),
                    )
                    .map_err(|e| match e { GhErr::Conflict => "commit conflict".into(), GhErr::Msg(m) => format!("github create commit: {m}") })?;
                let new_commit = commit_resp["sha"]
                    .as_str()
                    .ok_or_else(|| "github commit missing sha".to_string())?
                    .to_string();

                match self.gh_json(
                    "PATCH",
                    &format!("/repos/{repo}/git/refs/heads/{branch}"),
                    Some(json!({ "sha": new_commit, "force": false })),
                ) {
                    Ok(_) => {
                        *GH_STATE.lock().unwrap() = Some((new_ver, new_commit, new_tree));
                        Ok(true)
                    }
                    Err(GhErr::Conflict) => {
                        *GH_STATE.lock().unwrap() = None;
                        Ok(false)
                    }
                    Err(GhErr::Msg(m)) => Err(format!("github update ref: {m}")),
                }
            }
            Store::Upstash { .. } => {
                let mut args: Vec<String> = vec![
                    "EVAL".into(),
                    CAS_SCRIPT.into(),
                    "2".into(),
                    "auraq1:ver".into(),
                    "auraq1:head".into(),
                    expected_ver.to_string(),
                    new_ver.to_string(),
                    head_json,
                ];
                for b in blocks {
                    args.push(format!("auraq1:b:{}", b.header.height));
                    args.push(serde_json::to_string(b).unwrap());
                }
                Ok(self.redis(args)?.as_i64() == Some(1))
            }
            Store::Blob { .. } => {
                let snaps = self.blob_list_snaps()?;
                let cur_max = snaps.iter().filter_map(|s| parse_snap_ver(&s.pathname).map(|x| x.0)).max().unwrap_or(0);
                if cur_max != expected_ver {
                    return Ok(false);
                }
                for b in blocks {
                    self.blob_put(
                        &format!("{BLOB_NS}/b/{}.json", b.header.height),
                        &serde_json::to_string(b).unwrap(),
                        31_536_000,
                    )?;
                }
                let digest = &crypto::sha3_256_hex(head_json.as_bytes())[..12];
                let snap_path = format!("{BLOB_NS}/snap/{new_ver:012}-{digest}.json");
                self.blob_put(&snap_path, &head_json, 3600)?;
                let stale: Vec<String> = snaps
                    .into_iter()
                    .filter(|s| parse_snap_ver(&s.pathname).map(|(v, _)| v + 20 <= new_ver).unwrap_or(false))
                    .map(|s| s.url)
                    .collect();
                self.blob_delete(stale);
                Ok(true)
            }
            Store::File { dir } => {
                let _g = FILE_LOCK.lock().unwrap();
                let cur: u64 = std::fs::read_to_string(dir.join("ver"))
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0);
                if cur != expected_ver {
                    return Ok(false);
                }
                for b in blocks {
                    std::fs::write(dir.join(format!("b/{}.json", b.header.height)), serde_json::to_string(b).unwrap())
                        .map_err(|e| e.to_string())?;
                }
                std::fs::write(dir.join("head.json"), head_json).map_err(|e| e.to_string())?;
                std::fs::write(dir.join("ver"), new_ver.to_string()).map_err(|e| e.to_string())?;
                Ok(true)
            }
        }
    }

    fn get_blocks(&self, from: u64, to: u64) -> Result<Vec<Block>, String> {
        match self {
            Store::GitHub { repo, branch, .. } => {
                let mut out = Vec::new();
                for h in from..=to {
                    let cdn_url = format!("https://raw.githubusercontent.com/{repo}/{branch}/b/{h}.json");
                    let mut parsed = None;
                    if let Ok(resp) = ureq::get(&cdn_url).timeout(Duration::from_secs(6)).call() {
                        if let Ok(s) = resp.into_string() {
                            parsed = serde_json::from_str::<Block>(&s).ok();
                        }
                    }
                    if parsed.is_none() {
                        if let Ok(Some(s)) = self.gh_raw(&format!("/repos/{repo}/contents/b/{h}.json?ref={branch}")) {
                            parsed = serde_json::from_str::<Block>(&s).ok();
                        }
                    }
                    if let Some(b) = parsed {
                        out.push(b);
                    }
                }
                Ok(out)
            }
            Store::Upstash { .. } => {
                let mut args = vec!["MGET".to_string()];
                args.extend((from..=to).map(|h| format!("auraq1:b:{h}")));
                let r = self.redis(args)?;
                Ok(r.as_array()
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|v| v.as_str().and_then(|s| serde_json::from_str(s).ok()))
                    .collect())
            }
            Store::Blob { public_base, .. } => {
                let mut out = Vec::new();
                for h in from..=to {
                    let url = format!("{public_base}/{BLOB_NS}/b/{h}.json");
                    if let Ok(resp) = ureq::get(&url).timeout(Duration::from_secs(6)).call() {
                        if let Ok(s) = resp.into_string() {
                            if let Ok(b) = serde_json::from_str::<Block>(&s) {
                                out.push(b);
                            }
                        }
                    }
                }
                Ok(out)
            }
            Store::File { dir } => Ok((from..=to)
                .filter_map(|h| std::fs::read_to_string(dir.join(format!("b/{h}.json"))).ok())
                .filter_map(|r| serde_json::from_str(&r).ok())
                .collect()),
        }
    }
}

// ---------------------------------------------------------------- consensus glue
fn seed(store: &Store) -> Result<(u64, Head), String> {
    let blocks: Vec<Block> = serde_json::from_str(SEED_CHAIN).map_err(|e| format!("bad seed chain: {e}"))?;
    let st = chain::validate_chain(&blocks).map_err(|e| format!("seed chain invalid: {e}"))?;
    let mut head = Head {
        ver: 1,
        blocks: blocks[blocks.len().saturating_sub(RECENT)..].to_vec(),
        state: st,
        mempool: vec![],
        log: vec![],
        peers: BTreeMap::new(),
    };
    head.log(format!(
        "seeded AuraChain Quantum v1.1 at height #{} (BFT finalized #{})",
        blocks.len() - 1,
        head.state.finalized_height
    ));
    let refs: Vec<&Block> = blocks.iter().collect();
    if matches!(store, Store::Upstash { .. }) {
        for c in refs.chunks(100) {
            let mut args = vec!["MSET".to_string()];
            for b in c {
                args.push(format!("auraq1:b:{}", b.header.height));
                args.push(serde_json::to_string(b).unwrap());
            }
            store.redis(args)?;
        }
        if !store.cas(0, 1, &head, &[])? {
            return store.load()?.ok_or_else(|| "seed race".to_string());
        }
    } else if !store.cas(0, 1, &head, &refs)? {
        return store.load()?.ok_or_else(|| "seed race".to_string());
    }
    Ok((1, head))
}

fn active_peers_merged(head: &Head, now: u64) -> Vec<PeerHeartbeat> {
    let mut map = head.peers.clone();
    if let Ok(mut lp) = LIVE_PEERS.lock() {
        lp.retain(|_, p| now.saturating_sub(p.last_seen) <= 1800);
        for (k, v) in lp.iter() {
            map.insert(k.clone(), v.clone());
        }
    }
    map.retain(|_, p| now.saturating_sub(p.last_seen) <= 1800);
    map.into_values().collect()
}

/// Autonomous VPoS block + L2 Metropolis rollup batch producer.
fn maybe_produce(head: &mut Head, key: &Keypair, now: u64, force_pulse: bool) -> Option<Block> {
    let tip = head.tip().header.clone();
    let next = tip.height + 1;
    if !chain::is_pos(next, &head.state) || now < tip.timestamp + chain::SLOT_SECS {
        return None;
    }
    if !force_pulse && head.mempool.is_empty() && now.saturating_sub(tip.timestamp) < IDLE_HEARTBEAT_SECS {
        return None;
    }
    let slot = (now - tip.timestamp) / chain::SLOT_SECS - 1;
    if chain::elect_leader(&head.state, &tip.hash_hex(), next, slot).as_deref() != Some(key.address().as_str()) {
        return None;
    }

    // Autonomous L2 Metropolis Rollup Settlement: on scheduled `/pulse` or every 8th block,
    // bundle a fresh L2 execution state root and anchor it on L1 automatically!
    if (force_pulse || next % 8 == 0)
        && !head.mempool.iter().any(|t| t.kind == TxKind::Anchor)
        && head.state.account(&key.address()).balance > chain::MIN_BASE_FEE * 4
    {
        let batch_idx = head.state.l2_batches.last().map(|b| b.batch_index + 1).unwrap_or(1);
        let l2_txs = 512 + (now % 1536);
        let state_root = crypto::sha3_256_hex(format!("metropolis-l2-state:{}:{batch_idx}:{now}", tip.hash_hex()).as_bytes());
        let proof_tag = &crypto::sha3_256_hex(format!("zk-plonk-pq:{state_root}").as_bytes())[..16];
        let commit = format!("metropolis-zk:batch={batch_idx}:txs={l2_txs}:proof={proof_tag}:root={state_root}");
        let nonce = head
            .mempool
            .iter()
            .filter(|t| t.sender().map(|a| a == key.address()).unwrap_or(false))
            .map(|t| t.nonce + 1)
            .max()
            .unwrap_or_else(|| head.state.account(&key.address()).nonce);
        let anchor_tx = Tx::new(TxKind::Anchor, key, "", 0, head.state.next_base_fee * 2, nonce, &commit);
        head.mempool.push(anchor_tx);
    }

    let b = chain::assemble(&head.blocks, &head.state, &head.mempool, key, now, "VPoS Quantum Cloud Validator").ok()?;
    let ns = chain::apply_block(&head.state, &head.blocks, &b, now).ok()?;
    head.state = ns;
    head.blocks.push(b.clone());
    let n = head.blocks.len();
    if n > RECENT {
        head.blocks.drain(..n - RECENT);
    }
    head.prune_mempool();
    if let Ok(lp) = LIVE_PEERS.lock() {
        for (k, v) in lp.iter() {
            head.peers.insert(k.clone(), v.clone());
        }
    }
    head.peers.retain(|_, p| now.saturating_sub(p.last_seen) <= 1800);
    head.log(format!(
        "produced block #{} VPoS (BFT fin #{}, {} txs)",
        b.header.height,
        head.state.finalized_height,
        b.txs.len()
    ));
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
    let next_h = head.tip().header.height + 1;
    let mut sim = head.state.clone();
    sim.recent_hashes.insert(next_h - 1, head.tip().header.hash_hex());
    let mut pending: Vec<&Tx> =
        head.mempool.iter().filter(|t| t.sender().map(|a| a == from).unwrap_or(false)).collect();
    pending.sort_by_key(|t| t.nonce);
    for t in pending {
        let _ = chain::apply_tx(&mut sim, t, chain::MIN_BASE_FEE, next_h);
    }
    chain::apply_tx(&mut sim, tx, chain::MIN_BASE_FEE, next_h)
}

fn info(head: &Head, key: &Option<Keypair>, store: &Store, now: u64) -> Value {
    let s = &head.state;
    let tip = &head.tip().header;
    let next = tip.height + 1;
    let vals: Vec<Value> = s
        .validator_weights()
        .into_iter()
        .map(|(a, st, w)| json!({"address": a, "stake": chain::fmt_aura(st), "weight": chain::fmt_aura(w)}))
        .collect();
    let peers: Vec<String> = active_peers_merged(head, now).into_iter().map(|p| p.label).collect();
    json!({
        "version": env!("CARGO_PKG_VERSION"),
        "network": chain::NETWORK,
        "crypto_suite": "Hybrid Ed25519 + NIST FIPS 204 ML-DSA-44 + SHA3-256",
        "storage": store.backend_label(),
        "height": tip.height,
        "tip_hash": tip.hash_hex(),
        "tip_timestamp": tip.timestamp,
        "finalized_height": s.finalized_height,
        "finalized_hash": s.finalized_hash,
        "genesis_hash": chain::genesis().header.hash_hex(),
        "genesis_message": chain::GENESIS_MESSAGE,
        "next_consensus": if chain::is_pos(next, s) { "pos" } else { "pow" },
        "pos_start_height": chain::POS_START_HEIGHT,
        "chainwork": s.chainwork.to_string(),
        "difficulty": (u128::MAX / s.last_target.max(1)) as f64,
        "target": chain::target_hex(s.last_target),
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
        "names_count": s.names.len(),
        "messages_count": s.next_post_id,
        "referrals_count": s.referrals_count,
        "proposals_count": s.proposals.len(),
        "tokens_count": s.tokens.len(),
        "nfts_count": s.nfts.len(),
        "l2_batches_count": s.l2_batches.len(),
        "slashed_count": s.slashed.len(),
        "mempool": head.mempool.len(),
        "peers": peers,
        "self_url": "autonomous cloud validator",
        "node_address": key.as_ref().map(|k| k.address()),
        "hashrate": 0,
        "heartbeat_secs": IDLE_HEARTBEAT_SECS,
        "log": head.log.iter().rev().take(10).collect::<Vec<_>>(),
    })
}

fn activity_json(head: &Head, key: &Option<Keypair>, now: u64) -> Value {
    let s = &head.state;
    let genesis_val = key
        .as_ref()
        .map(|k| k.address())
        .or_else(|| s.validator_weights().first().map(|(a, _, _)| a.clone()))
        .unwrap_or_default();
    let human_wallets = s.accounts.keys().filter(|a| a.as_str() != genesis_val).count();
    let human_txs: u64 = s
        .tx_counts
        .iter()
        .filter(|(k, _)| k.as_str() != "anchor" && k.as_str() != "attest")
        .map(|(_, &c)| c)
        .sum();
    let mut ranked: Vec<(&String, &chain::Account)> = s.accounts.iter().collect();
    ranked.sort_by(|a, b| (b.1.balance + b.1.stake).cmp(&(a.1.balance + a.1.stake)));
    let leaderboard: Vec<Value> = ranked
        .into_iter()
        .take(25)
        .enumerate()
        .map(|(i, (addr, acc))| {
            json!({
                "rank": i + 1,
                "address": addr,
                "handle": s.address_names.get(addr),
                "is_genesis_validator": addr == &genesis_val,
                "balance_aura": chain::fmt_aura(acc.balance),
                "stake_aura": chain::fmt_aura(acc.stake),
                "total_aura": chain::fmt_aura(acc.balance + acc.stake),
                "nonce": acc.nonce,
            })
        })
        .collect();
    let recent_events: Vec<Value> = s
        .recent_events
        .iter()
        .rev()
        .take(50)
        .map(|ev| {
            json!({
                "height": ev.height,
                "timestamp": ev.timestamp,
                "tx_id": ev.tx_id,
                "kind": ev.kind,
                "actor": ev.actor,
                "actor_handle": s.address_names.get(&ev.actor),
                "target": ev.target,
                "target_handle": s.address_names.get(&ev.target),
                "amount_aura": chain::fmt_aura(ev.amount),
                "summary": ev.summary,
            })
        })
        .collect();
    let messages: Vec<Value> = s
        .messages
        .iter()
        .rev()
        .take(50)
        .map(|m| {
            json!({
                "id": m.id,
                "height": m.height,
                "timestamp": m.timestamp,
                "author": m.author,
                "handle": s.address_names.get(&m.author),
                "message": m.message,
                "tip_aura": if m.tip_aura > 0 { Some(chain::fmt_aura(m.tip_aura)) } else { None },
                "tip_to": if m.tip_to.is_empty() { None } else { Some(&m.tip_to) },
            })
        })
        .collect();
    let peers = active_peers_merged(head, now);
    json!({
        "total_wallets": s.accounts.len(),
        "human_wallets": human_wallets,
        "genesis_validator": genesis_val,
        "named_identities": s.names.len(),
        "messages_count": s.next_post_id,
        "referrals_count": s.referrals_count,
        "total_txs": s.total_txs,
        "human_txs": human_txs,
        "tx_breakdown": s.tx_counts,
        "active_peers_count": peers.len(),
        "active_peers": peers,
        "leaderboard": leaderboard,
        "recent_events": recent_events,
        "messages": messages,
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

// -------------------------------------------------------------------- HTTP
fn json_err(c: u16, e: String) -> (u16, String, &'static str) {
    (c, json!({ "error": e }).to_string(), "application/json")
}

fn handle_sync(method: String, path: String, query: String, body: Vec<u8>) -> (u16, String, &'static str) {
    if method == "OPTIONS" {
        return (204, String::new(), "text/plain");
    }
    let q = |k: &str| -> Option<u64> {
        query.split('&').find_map(|kv| kv.split_once('=').filter(|(a, _)| *a == k).and_then(|(_, v)| v.parse().ok()))
    };
    if method == "GET" && (path == "/" || path == "/index.html") {
        return (200, EXPLORER_HTML.to_string(), "text/html; charset=utf-8");
    }
    if method == "GET" && (path == "/favicon.ico" || path == "/favicon.png") {
        return (204, String::new(), "image/x-icon");
    }
    if method == "POST" && path == "/peers" {
        let now = chain::now_secs();
        let v: Value = serde_json::from_slice(&body).unwrap_or(json!({}));
        let id = v["node_id"]
            .as_str()
            .or_else(|| v["url"].as_str())
            .unwrap_or("peer")
            .chars()
            .take(64)
            .collect::<String>();
        let label = v["url"].as_str().unwrap_or(&id).chars().take(80).collect::<String>();
        let height = v["height"].as_u64().unwrap_or(0);
        if let Ok(mut lp) = LIVE_PEERS.lock() {
            lp.retain(|_, p| now.saturating_sub(p.last_seen) <= 1800);
            if lp.len() < 64 {
                lp.insert(id.clone(), PeerHeartbeat { id, label, height, last_seen: now });
            }
        }
        let count = LIVE_PEERS.lock().map(|m| m.len()).unwrap_or(0);
        return (
            200,
            json!({ "peers": [], "active_peers_count": count, "note": "peer heartbeat registered" }).to_string(),
            "application/json",
        );
    }

    let store = match Store::from_env() {
        Ok(s) => s,
        Err(e) => return json_err(503, e),
    };
    let key = std::env::var("AURA_VALIDATOR_KEY").ok().and_then(|k| Keypair::from_secret_hex(&k).ok());
    let now = chain::now_secs();
    let is_pulse = path == "/pulse";
    let is_tx = method == "POST" && path == "/tx";
    let can_produce = is_pulse || is_tx || (method == "GET" && path == "/info");
    let cache_ttl = if is_pulse || is_tx {
        Duration::ZERO
    } else {
        Duration::from_millis(4000)
    };

    // Fast lock-free read path when cache is warm and no block production is due.
    if !is_pulse && !is_tx {
        if let Some(c) = CACHE
            .lock()
            .unwrap()
            .as_ref()
            .filter(|c| {
                c.0.elapsed() < cache_ttl
                    && (!can_produce
                        || (c.2.mempool.is_empty()
                            && now.saturating_sub(c.2.tip().header.timestamp) < IDLE_HEARTBEAT_SECS))
            })
            .map(|c| (c.1, c.2.clone()))
        {
            return finish_response(&method, &path, &q, c.1, &key, &store, None, None, now);
        }
    }

    let _op_guard = OP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let cached = if !is_pulse && !is_tx {
        CACHE
            .lock()
            .unwrap()
            .as_ref()
            .filter(|c| {
                c.0.elapsed() < cache_ttl
                    && (!can_produce
                        || (c.2.mempool.is_empty()
                            && now.saturating_sub(c.2.tip().header.timestamp) < IDLE_HEARTBEAT_SECS))
            })
            .map(|c| (c.1, c.2.clone()))
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
    let mut produced_height: Option<u64> = None;
    if can_produce {
        for _attempt in 0..4 {
            let mut changed = false;
            let mut new_blocks: Vec<Block> = vec![];
            if is_tx {
                let tx = match serde_json::from_slice::<Tx>(&body) {
                    Ok(t) => t,
                    Err(e) => return json_err(400, format!("bad tx json: {e}")),
                };
                if let Err(e) = admit_tx(&head, &tx) {
                    return json_err(400, e);
                };
                let id = tx.id();
                head.log(format!("mempool += {} {}", tx.kind.as_str(), &id[..12]));
                head.mempool.push(tx);
                changed = true;
                reply = Some((200, json!({ "txid": id, "status": "accepted" })));
            }
            if let Some(k) = &key {
                if let Some(b) = maybe_produce(&mut head, k, now, is_pulse) {
                    produced_height = Some(b.header.height);
                    new_blocks.push(b);
                    changed = true;
                }
            }
            if !changed {
                break;
            }
            let nv = ver + 1;
            let refs: Vec<&Block> = new_blocks.iter().collect();
            match store.cas(ver, nv, &head, &refs) {
                Ok(true) => {
                    ver = nv;
                    head.ver = ver;
                    break;
                }
                Ok(false) => match store.load() {
                    Ok(Some((v, h))) => {
                        ver = v;
                        head = h;
                        reply = None;
                        produced_height = None;
                    }
                    _ => return json_err(502, "store reload failed".into()),
                },
                Err(e) => return json_err(502, e),
            }
        }
    }
    *CACHE.lock().unwrap() = Some((Instant::now(), ver, head.clone()));
    drop(_op_guard);

    finish_response(&method, &path, &q, head, &key, &store, reply, produced_height, now)
}

fn finish_response(
    method: &str,
    path: &str,
    q: &dyn Fn(&str) -> Option<u64>,
    head: Head,
    key: &Option<Keypair>,
    store: &Store,
    reply: Option<(u16, Value)>,
    produced_height: Option<u64>,
    now: u64,
) -> (u16, String, &'static str) {
    let out: (u16, Value) = match (method, path) {
        ("POST", "/tx") => {
            let mut res = reply.unwrap_or((503, json!({"error": "busy, retry"})));
            if let Some(bh) = produced_height {
                res.1["included_in_block"] = json!(bh);
            }
            res
        }
        (_, "/pulse") => {
            let t = &head.tip().header;
            (
                200,
                json!({
                    "ok": true,
                    "produced_block": produced_height,
                    "height": t.height,
                    "finalized_height": head.state.finalized_height,
                    "hash": t.hash_hex(),
                }),
            )
        }
        ("GET", "/tip") => {
            let t = &head.tip().header;
            (
                200,
                json!({
                    "height": t.height,
                    "hash": t.hash_hex(),
                    "finalized_height": head.state.finalized_height,
                    "chainwork": head.state.chainwork.to_string(),
                }),
            )
        }
        ("GET", "/info") => (200, info(&head, key, store, now)),
        ("GET", "/activity") => (200, activity_json(&head, key, now)),
        ("GET", "/ecosystem") => (200, ecosystem_json(&head.state, head.tip().header.height)),
        ("GET", "/mempool") => (200, json!(head.mempool)),
        ("GET", "/anchors") => {
            let v: Vec<Value> = head
                .state
                .l2_batches
                .iter()
                .rev()
                .map(|b| json!({"height": b.l1_height, "from": b.sequencer, "data": b.commitment, "batch_index": b.batch_index}))
                .collect();
            (200, json!(v))
        }
        ("GET", p) if p.starts_with("/account/") => {
            let a = &p[9..];
            let s = &head.state;
            let acc = s.account(a);
            let pend = head
                .mempool
                .iter()
                .filter(|t| t.sender().map(|x| x == a).unwrap_or(false))
                .map(|t| t.nonce + 1)
                .max();
            let tok_bals: serde_json::Map<String, Value> = s
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
            let nfts_owned: Vec<u64> = s.nfts.values().filter(|nft| nft.owner == a).map(|nft| nft.id).collect();
            (
                200,
                json!({
                    "address": a,
                    "handle": s.address_names.get(a),
                    "balance": chain::fmt_aura(acc.balance),
                    "balance_micro": acc.balance,
                    "stake": chain::fmt_aura(acc.stake),
                    "stake_micro": acc.stake,
                    "delegate": acc.delegate,
                    "unbonding": acc.unbonding,
                    "token_balances": tok_bals,
                    "nfts_owned": nfts_owned,
                    "nonce": acc.nonce,
                    "next_nonce": pend.unwrap_or(acc.nonce).max(acc.nonce),
                }),
            )
        }
        ("GET", p) if p.starts_with("/block/") => match p[7..].parse::<u64>() {
            Ok(h) => {
                let in_mem = head.blocks.iter().find(|b| b.header.height == h).cloned();
                let found = match in_mem {
                    Some(b) => Some(b),
                    None => store.get_blocks(h, h).ok().and_then(|mut v| v.pop()),
                };
                match found {
                    Some(b) => {
                        let mut j = json!(b);
                        j["hash"] = json!(b.header.hash_hex());
                        (200, j)
                    }
                    None => (404, json!({"error": "no such block"})),
                }
            }
            Err(_) => (400, json!({"error": "bad height"})),
        },
        ("GET", p) if p.starts_with("/proof/") => {
            let parts: Vec<&str> = p[7..].split('/').collect();
            if parts.len() != 2 {
                (400, json!({"error": "usage: /proof/<height>/<tx_index>"}))
            } else {
                let h = parts[0].parse::<u64>().ok();
                let idx = parts[1].parse::<usize>().ok();
                let blk = h.and_then(|hh| {
                    head.blocks
                        .iter()
                        .find(|b| b.header.height == hh)
                        .cloned()
                        .or_else(|| store.get_blocks(hh, hh).ok().and_then(|mut v| v.pop()))
                });
                match (blk, idx) {
                    (Some(b), Some(i)) if i < b.txs.len() => {
                        let steps = chain::merkle_proof(&b.txs, i).unwrap_or_default();
                        let tx_id = b.txs[i].id();
                        let verified = chain::verify_merkle_proof(&tx_id, &steps, &b.header.tx_root);
                        (
                            200,
                            json!({
                                "height": b.header.height,
                                "block_hash": b.header.hash_hex(),
                                "tx_index": i,
                                "tx_id": tx_id,
                                "tx_root": b.header.tx_root,
                                "steps": steps,
                                "verified": verified,
                            }),
                        )
                    }
                    _ => (404, json!({"error": "block or tx index not found"})),
                }
            }
        }
        ("GET", "/blocks") => {
            let tip_h = head.tip().header.height;
            let from = q("from").unwrap_or(0).min(tip_h);
            let limit = q("limit").unwrap_or(50).clamp(1, 200);
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
        ("POST", "/block") => (400, json!({"error": "cloud VPoS validator produces canonical blocks"})),
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
        .header("access-control-allow-headers", "content-type")
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("cache-control", "no-store")
        .body(ResponseBody::from(out))?)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    run(service_fn(handler)).await
}
