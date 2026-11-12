#!/usr/bin/env python3
"""
AuraChain Quantum — Autonomous Continuous Publisher & Network Digest Generator.

Runs every 6 hours via GitHub Actions (.github/workflows/continuous-publish.yml)
at $0.00 cost using Python 3 standard library only:
  1. Queries live on-chain state (/info, /activity, /ecosystem) from AuraChain Quantum.
  2. Publishes SEO-indexed docs/digest.html, docs/rss.xml, docs/sitemap.xml,
     docs/robots.txt, docs/llms.txt, and docs/status.json to GitHub Pages.
  3. Optionally syndicates live network digests to Bluesky (AT Protocol),
     Discord Webhooks, Telegram Channels, and Dev.to when secrets are configured.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import os
import pathlib
import time
import urllib.error
import urllib.request
from email.utils import format_datetime

NODE_URL = os.environ.get("AURA_NODE_URL", "https://aurachain-quantum.vercel.app").rstrip("/")
PORTAL_URL = os.environ.get("AURA_PORTAL_URL", "https://sanzaya-p.github.io/aurachain").rstrip("/")
REPO_URL = "https://github.com/sanzaya-p/aurachain"
LEDGER_URL = "https://github.com/sanzaya-p/aurachain-ledger"

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def fetch_json(path: str, retries: int = 4) -> dict:
    url = f"{NODE_URL}{path}"
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "AuraChain-Continuous-Publisher/1.2 (+https://github.com/sanzaya-p/aurachain)"},
            )
            with urllib.request.urlopen(req, timeout=25) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            last_err = exc
            time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"Failed to fetch {url}: {last_err}")


def post_json(url: str, payload: dict, headers: dict[str, str] | None = None) -> dict:
    hdrs = {"Content-Type": "application/json", "User-Agent": "AuraChain-Continuous-Publisher/1.2"}
    if headers:
        hdrs.update(headers)
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        raw = resp.read().decode("utf-8")
        return json.loads(raw) if raw.strip() else {}


def esc(val: object) -> str:
    return html.escape(str(val), quote=True)


def fmt_ts(ts: int | float) -> str:
    return dt.datetime.fromtimestamp(int(ts), tz=dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def rfc2822(ts: int | float) -> str:
    return format_datetime(dt.datetime.fromtimestamp(int(ts), tz=dt.timezone.utc))


def build_digest_html(info: dict, activity: dict, eco: dict, now_utc: dt.datetime) -> str:
    iso_now = now_utc.strftime("%Y-%m-%d %H:%M UTC")
    height = info.get("height", 0)
    fin_h = info.get("finalized_height", 0)
    humans = activity.get("human_wallets", 0)
    names = activity.get("named_identities", 0)
    posts_cnt = activity.get("messages_count", 0)
    circ = info.get("circulating", "0")
    staked = info.get("total_staked", "0")
    burned = info.get("burned", "0")
    human_txs = activity.get("human_txs", 0)

    messages = activity.get("messages", [])[:15]
    events = [
        e for e in activity.get("recent_events", [])
        if e.get("kind") not in ("anchor", "attest")
    ][:20]
    leaders = activity.get("leaderboard", [])[:12]
    tokens = eco.get("tokens", [])[:10]
    nfts = eco.get("nfts", [])[:10]

    msg_rows = ""
    if messages:
        for m in messages:
            author = f"@{m['handle']}.aura" if m.get("handle") else f"{str(m.get('author', ''))[:16]}…"
            tip_badge = f' <span class="badge pos">+{esc(m["tip_aura"])} AURA tip</span>' if m.get("tip_aura") else ""
            msg_rows += (
                f'<div class="post">'
                f'<div class="post-hdr"><strong>{esc(author)}</strong>{tip_badge}'
                f'<span>Block #{esc(m.get("height"))} · {esc(fmt_ts(m.get("timestamp", 0)))}</span></div>'
                f'<div class="post-body">{esc(m.get("message", ""))}</div>'
                f"</div>\n"
            )
    else:
        msg_rows = '<p class="mute">No Town Square messages yet — be the first to post on-chain!</p>'

    ev_rows = ""
    for ev in events:
        ev_rows += (
            f"<tr>"
            f"<td>#{esc(ev.get('height'))}</td>"
            f"<td><code>{esc(ev.get('kind'))}</code></td>"
            f"<td>{esc(ev.get('summary'))}</td>"
            f"<td class='mute'>{esc(fmt_ts(ev.get('timestamp', 0)))}</td>"
            f"</tr>\n"
        )
    if not ev_rows:
        ev_rows = "<tr><td colspan='4' class='mute'>Waiting for next community transaction…</td></tr>"

    lead_rows = ""
    for row in leaders:
        tag = " (Genesis Validator)" if row.get("is_genesis_validator") else ""
        ident = f"@{row['handle']}.aura" if row.get("handle") else f"{str(row.get('address', ''))[:20]}…"
        lead_rows += (
            f"<tr>"
            f"<td>#{esc(row.get('rank'))}</td>"
            f"<td><strong>{esc(ident)}</strong><span class='mute'>{esc(tag)}</span></td>"
            f"<td>{esc(row.get('balance_aura'))} AURA</td>"
            f"<td>{esc(row.get('stake_aura'))} AURA</td>"
            f"</tr>\n"
        )

    tok_rows = ""
    for t in tokens:
        tok_rows += (
            f"<tr><td><strong>${esc(t.get('symbol'))}</strong> ({esc(t.get('name'))})</td>"
            f"<td>{esc(t.get('spot_price_aura'))} AURA</td>"
            f"<td>{esc(t.get('aura_reserve'))} AURA</td>"
            f"<td>{esc(t.get('holders'))} holders · {esc(t.get('trades'))} swaps</td></tr>\n"
        )
    if not tok_rows:
        tok_rows = "<tr><td colspan='4' class='mute'>No custom tokens launched yet — create the first pool on AuraLaunch DEX!</td></tr>"

    nft_rows = ""
    for n in nfts:
        price = f"{esc(n['price_aura'])} AURA" if n.get("price_aura") else "Unlisted"
        royalty_pct = float(n.get("royalty_bps", 0)) / 100.0
        nft_rows += (
            f"<tr><td>#{esc(n.get('id'))} <strong>{esc(n.get('name'))}</strong></td>"
            f"<td>{royalty_pct:.1f}%</td>"
            f"<td>{price}</td>"
            f"<td>{esc(n.get('sales', 0))} sales</td></tr>\n"
        )
    if not nft_rows:
        nft_rows = "<tr><td colspan='4' class='mute'>No AUA NFTs minted yet — mint #1 on AuraChain Quantum!</td></tr>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AuraChain Quantum Live Network Digest — Block #{esc(height)} ({esc(humans)} Human Wallets)</title>
<meta name="description" content="Auto-published 6-hourly AuraChain Quantum on-chain report: Block #{esc(height)}, Casper BFT Finalized #{esc(fin_h)}, {esc(humans)} human wallets, {esc(names)} .aura identities, Town Square posts, DEX pools, and holder leaderboard.">
<link rel="canonical" href="{PORTAL_URL}/digest.html">
<link rel="alternate" type="application/rss+xml" title="AuraChain Quantum RSS Feed" href="{NODE_URL}/feed.xml">
<meta property="og:title" content="AuraChain Quantum Live Digest — Block #{esc(height)} · {esc(humans)} Wallets">
<meta property="og:description" content="Casper BFT Finalized #{esc(fin_h)} · {esc(circ)} AURA circulating · {esc(names)} @name.aura identities · Mine 50–55 AURA free in browser.">
<meta property="og:url" content="{PORTAL_URL}/digest.html">
<meta property="og:image" content="{NODE_URL}/og.svg">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="{NODE_URL}/og.svg">
<style>
  :root {{
    --bg:#070a12; --panel:#11182b; --line:#22304f; --txt:#e5ecff; --mute:#8b9bb8;
    --aura:#8b5cf6; --cyan:#22d3ee; --pos:#10b981; --pow:#f59e0b;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font:15px/1.6 Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif; background:var(--bg); color:var(--txt); }}
  a {{ color:var(--cyan); text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  header {{ border-bottom:1px solid var(--line); background:#0b1020ee; position:sticky; top:0; backdrop-filter:blur(10px); z-index:10; }}
  .nav {{ max-width:1120px; margin:0 auto; padding:14px 22px; display:flex; align-items:center; justify-content:space-between; gap:12px; flex-wrap:wrap; }}
  .brand {{ font-weight:800; font-size:17px; color:#fff; display:flex; align-items:center; gap:10px; }}
  .logo {{ width:32px; height:32px; border-radius:9px; background:conic-gradient(from 120deg, var(--aura), var(--cyan), var(--pos), var(--aura)); display:grid; place-items:center; font-size:13px; font-weight:900; }}
  main {{ max-width:1120px; margin:0 auto; padding:34px 22px 70px; }}
  h1 {{ font-size:30px; margin:0 0 8px; }}
  h2 {{ font-size:19px; margin:0 0 14px; color:#fff; }}
  .mute {{ color:var(--mute); font-size:13px; }}
  .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:12px; margin:22px 0 28px; }}
  .card {{ background:var(--panel); border:1px solid var(--line); border-radius:13px; padding:15px 16px; }}
  .card .k {{ font-size:11px; text-transform:uppercase; color:var(--mute); letter-spacing:.6px; }}
  .card .v {{ font-size:22px; font-weight:800; margin-top:4px; }}
  .grid2 {{ display:grid; grid-template-columns:1fr 1fr; gap:18px; margin-bottom:18px; }}
  @media (max-width:880px) {{ .grid2 {{ grid-template-columns:1fr; }} }}
  section {{ background:var(--panel); border:1px solid var(--line); border-radius:14px; padding:18px 20px; margin-bottom:18px; overflow-x:auto; }}
  table {{ width:100%; border-collapse:collapse; font-size:13.5px; }}
  th, td {{ text-align:left; padding:8px 10px; border-bottom:1px solid #1c2844; }}
  th {{ color:var(--mute); font-size:11px; text-transform:uppercase; }}
  code {{ font-family:ui-monospace,Consolas,monospace; background:#17223b; padding:2px 6px; border-radius:5px; color:#67e8f9; font-size:12px; }}
  .post {{ border:1px solid #1e2c4a; background:#0c1222; border-radius:11px; padding:12px 14px; margin-bottom:10px; }}
  .post-hdr {{ display:flex; justify-content:space-between; gap:8px; flex-wrap:wrap; font-size:12.5px; color:var(--mute); margin-bottom:5px; }}
  .post-hdr strong {{ color:var(--cyan); font-size:13.5px; }}
  .post-body {{ color:#e5ecff; word-break:break-word; }}
  .badge {{ padding:2px 8px; border-radius:999px; font-size:11px; font-weight:600; }}
  .badge.pos {{ background:#10b98122; color:var(--pos); border:1px solid #10b98155; }}
  .btn {{ display:inline-flex; align-items:center; gap:7px; padding:9px 16px; border-radius:9px; font-weight:700; font-size:13.5px; color:#fff; background:linear-gradient(135deg, var(--aura), #0891b2); text-decoration:none; }}
  footer {{ border-top:1px solid var(--line); padding:26px 22px; text-align:center; color:var(--mute); font-size:13px; }}
</style>
</head>
<body>
<header>
  <div class="nav">
    <a class="brand" href="./index.html"><span class="logo">AQ</span> AuraChain Quantum</a>
    <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;font-size:14px">
      <a href="./index.html">Launch Portal</a>
      <a href="./post-quantum-blockchain-rust.html">Architecture Deep Dive</a>
      <a href="./rss.xml">RSS Feed</a>
      <a href="{REPO_URL}">GitHub</a>
      <a class="btn" href="{NODE_URL}/">⛏️ Mine 50–55 AURA Free</a>
    </div>
  </div>
</header>

<main>
  <div class="mute">Autonomous Cloud Publisher · Snapshot generated {esc(iso_now)} from <code>{esc(NODE_URL)}</code></div>
  <h1>AuraChain Quantum — Live On-Chain Network Digest</h1>
  <p class="mute" style="font-size:15px">
    Cryptographically verified state of <code>aurachain-quantum-1</code> (Hybrid NIST FIPS 204 ML-DSA-44 + Ed25519 + SHA3-256), archived atomically on <a href="{LEDGER_URL}/commits/main">github.com/sanzaya-p/aurachain-ledger</a>.
  </p>

  <div class="cards">
    <div class="card"><div class="k">Block Height</div><div class="v">#{esc(height)}</div><div class="mute">Casper BFT Finalized #{esc(fin_h)}</div></div>
    <div class="card"><div class="k">Human Wallets</div><div class="v" style="color:var(--cyan)">{esc(humans)}</div><div class="mute">{esc(names)} @name.aura identities</div></div>
    <div class="card"><div class="k">Human Transactions</div><div class="v" style="color:var(--pos)">{esc(human_txs)}</div><div class="mute">{esc(posts_cnt)} Town Square posts</div></div>
    <div class="card"><div class="k">Circulating Supply</div><div class="v" style="color:var(--pow)">{esc(circ)}</div><div class="mute">Burned: {esc(burned)} AURA</div></div>
    <div class="card"><div class="k">Total VPoS Stake</div><div class="v">{esc(staked)}</div><div class="mute">25% saturation cap</div></div>
  </div>

  <div class="grid2">
    <section>
      <h2>💬 Latest Quantum Town Square Posts</h2>
      {msg_rows}
    </section>
    <section>
      <h2>🏆 Top Wallet Leaderboard</h2>
      <table>
        <thead><tr><th>#</th><th>Identity / Wallet</th><th>Liquid</th><th>Staked</th></tr></thead>
        <tbody>{lead_rows}</tbody>
      </table>
    </section>
  </div>

  <div class="grid2">
    <section>
      <h2>🚀 AuraLaunch DEX Liquidity Pools</h2>
      <table>
        <thead><tr><th>Token</th><th>Spot Price</th><th>AURA Reserve</th><th>Activity</th></tr></thead>
        <tbody>{tok_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>🎨 AUA Royalty NFTs</h2>
      <table>
        <thead><tr><th>NFT</th><th>Royalty</th><th>List Price</th><th>Sales</th></tr></thead>
        <tbody>{nft_rows}</tbody>
      </table>
    </section>
  </div>

  <section>
    <h2>⚡ Recent Human &amp; Ecosystem Transactions</h2>
    <table>
      <thead><tr><th>Block</th><th>Kind</th><th>Summary</th><th>Timestamp</th></tr></thead>
      <tbody>{ev_rows}</tbody>
    </table>
  </section>
</main>

<footer>
  AuraChain Quantum (<code>aurachain-quantum-1</code>) · Auto-published every 6 hours via GitHub Actions ·
  <a href="{NODE_URL}/">Open Super-App</a> ·
  <a href="{NODE_URL}/feed.xml">Live Node RSS</a> ·
  <a href="./rss.xml">Mirror RSS</a> ·
  <a href="{REPO_URL}">Source Code</a>
</footer>
</body>
</html>
"""


def build_rss_xml(info: dict, activity: dict, now_utc: dt.datetime) -> str:
    height = info.get("height", 0)
    fin_h = info.get("finalized_height", 0)
    humans = activity.get("human_wallets", 0)
    names = activity.get("named_identities", 0)
    circ = info.get("circulating", "0")
    items: list[str] = []

    items.append(
        f"""    <item>
      <title>{esc(f"AuraChain Quantum Digest: Block #{height} (BFT #{fin_h}, {humans} Human Wallets)")}</title>
      <link>{PORTAL_URL}/digest.html</link>
      <guid isPermaLink="false">aurachain-digest-{fin_h}</guid>
      <pubDate>{rfc2822(now_utc.timestamp())}</pubDate>
      <description>{esc(f"Live snapshot: Block #{height}, Casper BFT Finalized #{fin_h}, {humans} human wallets, {names} @name.aura identities, and {circ} AURA circulating. Mine 50-55 AURA free in browser at {NODE_URL}/")}</description>
    </item>"""
    )

    for m in activity.get("messages", [])[:15]:
        author = f"@{m['handle']}.aura" if m.get("handle") else str(m.get("author", ""))[:16]
        items.append(
            f"""    <item>
      <title>{esc(f"Town Square #{m.get('id', 0) + 1}: {author}")}</title>
      <link>{NODE_URL}/</link>
      <guid isPermaLink="false">aurachain-msg-{esc(m.get("id"))}</guid>
      <pubDate>{rfc2822(m.get("timestamp", now_utc.timestamp()))}</pubDate>
      <description>{esc(m.get("message", ""))}</description>
    </item>"""
        )

    joined = "\n".join(items)
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>AuraChain Quantum — Autonomous Network Digest &amp; Town Square</title>
    <link>{PORTAL_URL}/</link>
    <atom:link href="{PORTAL_URL}/rss.xml" rel="self" type="application/rss+xml"/>
    <description>6-hourly cryptographic network digest and on-chain Town Square feed for AuraChain Quantum (NIST FIPS 204 ML-DSA-44 + Ed25519 + SHA3-256).</description>
    <language>en-us</language>
    <lastBuildDate>{rfc2822(now_utc.timestamp())}</lastBuildDate>
{joined}
  </channel>
</rss>
"""


def build_portal_sitemap(now_utc: dt.datetime) -> str:
    ts = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>{PORTAL_URL}/</loc><lastmod>{ts}</lastmod><changefreq>hourly</changefreq><priority>1.0</priority></url>
  <url><loc>{PORTAL_URL}/digest.html</loc><lastmod>{ts}</lastmod><changefreq>hourly</changefreq><priority>0.9</priority></url>
  <url><loc>{PORTAL_URL}/post-quantum-blockchain-rust.html</loc><lastmod>{ts}</lastmod><changefreq>weekly</changefreq><priority>0.9</priority></url>
  <url><loc>{PORTAL_URL}/rss.xml</loc><lastmod>{ts}</lastmod><changefreq>hourly</changefreq><priority>0.8</priority></url>
  <url><loc>{PORTAL_URL}/llms.txt</loc><lastmod>{ts}</lastmod><changefreq>hourly</changefreq><priority>0.8</priority></url>
  <url><loc>{NODE_URL}/</loc><lastmod>{ts}</lastmod><changefreq>hourly</changefreq><priority>1.0</priority></url>
</urlset>
"""


def syndicate_optional_channels(info: dict, activity: dict) -> list[str]:
    """Posts concise network milestone updates to optional zero-cost APIs if configured."""
    results: list[str] = []
    height = info.get("height", 0)
    fin_h = info.get("finalized_height", 0)
    humans = activity.get("human_wallets", 0)
    names = activity.get("named_identities", 0)
    circ = info.get("circulating", "0")

    summary = (
        f"⛓️ AuraChain Quantum Digest — Block #{height} (Casper BFT Finalized #{fin_h})\n"
        f"👥 {humans} Human Wallets · {names} @name.aura PQ Identities\n"
        f"🪙 {circ} AURA Circulating (NIST FIPS 204 ML-DSA-44 + Ed25519 + SHA3-256)\n"
        f"⛏️ Mine 50–55 AURA free in browser: {NODE_URL}/"
    )

    # 1. Discord Webhook (if DISCORD_WEBHOOK_URL is set)
    discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "").strip()
    if discord_url:
        try:
            post_json(discord_url, {"content": f"{summary}\n📊 Digest: {PORTAL_URL}/digest.html"})
            results.append("discord:posted")
        except Exception as exc:  # noqa: BLE001
            results.append(f"discord:error:{exc}")

    # 2. Telegram Bot API (if TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID are set)
    tg_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    tg_chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
    if tg_token and tg_chat:
        try:
            post_json(
                f"https://api.telegram.org/bot{tg_token}/sendMessage",
                {"chat_id": tg_chat, "text": f"{summary}\n📊 {PORTAL_URL}/digest.html"},
            )
            results.append("telegram:posted")
        except Exception as exc:  # noqa: BLE001
            results.append(f"telegram:error:{exc}")

    # 3. Bluesky AT Protocol (if BSKY_HANDLE + BSKY_APP_PASSWORD are set)
    bsky_handle = os.environ.get("BSKY_HANDLE", "").strip()
    bsky_pw = os.environ.get("BSKY_APP_PASSWORD", "").strip()
    if bsky_handle and bsky_pw:
        try:
            sess = post_json(
                "https://bsky.social/xrpc/com.atproto.server.createSession",
                {"identifier": bsky_handle, "password": bsky_pw},
            )
            created_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            post_text = (
                f"AuraChain Quantum Live Digest: Block #{height} (BFT #{fin_h}) · "
                f"{humans} wallets · {names} .aura PQ IDs. "
                f"Mine 50 AURA free in browser (NIST FIPS 204 ML-DSA-44 + SHA3-256):"
            )
            post_json(
                "https://bsky.social/xrpc/com.atproto.repo.createRecord",
                {
                    "repo": sess["did"],
                    "collection": "app.bsky.feed.post",
                    "record": {
                        "$type": "app.bsky.feed.post",
                        "text": post_text,
                        "createdAt": created_at,
                        "embed": {
                            "$type": "app.bsky.embed.external",
                            "external": {
                                "uri": f"{NODE_URL}/",
                                "title": f"AuraChain Quantum — Block #{height} Live Miner & Wallet",
                                "description": "Post-Quantum Layer-1 in Safe Rust. Mine 50–55 AURA in browser & claim @name.aura.",
                            },
                        },
                    },
                },
                headers={"Authorization": f"Bearer {sess['accessJwt']}"},
            )
            results.append("bluesky:posted")
        except Exception as exc:  # noqa: BLE001
            results.append(f"bluesky:error:{exc}")

    return results


def main() -> None:
    DOCS.mkdir(parents=True, exist_ok=True)
    now_utc = dt.datetime.now(dt.timezone.utc)

    info = fetch_json("/info")
    activity = fetch_json("/activity")
    eco = fetch_json("/ecosystem")

    status = {
        "generated_at": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "network": info.get("network"),
        "version": info.get("version"),
        "height": info.get("height"),
        "finalized_height": info.get("finalized_height"),
        "human_wallets": activity.get("human_wallets"),
        "named_identities": activity.get("named_identities"),
        "messages_count": activity.get("messages_count"),
        "referrals_count": activity.get("referrals_count"),
        "human_txs": activity.get("human_txs"),
        "circulating_aura": info.get("circulating"),
        "total_staked_aura": info.get("total_staked"),
        "tokens_count": info.get("tokens_count"),
        "nfts_count": info.get("nfts_count"),
        "proposals_count": info.get("proposals_count"),
        "app_url": f"{NODE_URL}/",
        "portal_url": f"{PORTAL_URL}/",
    }

    (DOCS / "status.json").write_text(json.dumps(status, indent=2) + "\n", encoding="utf-8")
    (DOCS / "digest.html").write_text(build_digest_html(info, activity, eco, now_utc), encoding="utf-8")
    (DOCS / "rss.xml").write_text(build_rss_xml(info, activity, now_utc), encoding="utf-8")
    (DOCS / "sitemap.xml").write_text(build_portal_sitemap(now_utc), encoding="utf-8")
    (DOCS / "robots.txt").write_text(
        f"User-agent: *\nAllow: /\nSitemap: {PORTAL_URL}/sitemap.xml\n", encoding="utf-8"
    )
    (DOCS / "llms.txt").write_text(
        f"# AuraChain Quantum Launch Portal\n\n"
        f"> Post-Quantum Layer-1 Blockchain (NIST FIPS 204 ML-DSA-44 + Ed25519 + SHA3-256) in Safe Rust.\n\n"
        f"- Live Super-App & Free Browser SHA3 Miner: {NODE_URL}/\n"
        f"- Full Live AI Manifest: {NODE_URL}/llms.txt\n"
        f"- Live On-Chain RSS 2.0 Feed: {NODE_URL}/feed.xml\n"
        f"- 6-Hourly Network Digest: {PORTAL_URL}/digest.html\n"
        f"- Rust Post-Quantum Architecture Article: {PORTAL_URL}/post-quantum-blockchain-rust.html\n"
        f"- Source Repository: {REPO_URL}\n"
        f"- Public Git-CAS Block Ledger: {LEDGER_URL}\n",
        encoding="utf-8",
    )
    (DOCS / ".nojekyll").write_text("", encoding="utf-8")

    syndicated = syndicate_optional_channels(info, activity)
    print(
        f"[ok] Generated AuraChain digest for Block #{info.get('height')} "
        f"({activity.get('human_wallets')} human wallets). Syndication: {syndicated or ['pages+rss+seo']}"
    )


if __name__ == "__main__":
    main()
