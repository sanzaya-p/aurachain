#!/usr/bin/env python3
"""
AuraChain Quantum v2.0 — Official Model Context Protocol (MCP) Server.

Zero-dependency Python 3.10+ stdio MCP server giving AI coding agents
(Antigravity, Claude Code, Cursor, Windsurf, Cline) native access to the
AuraChain Quantum Post-Quantum Layer-1 Blockchain (NIST FIPS 204 ML-DSA-44 + Ed25519 + SHA3-256):
  - Read tools work immediately over HTTPS against https://aurachain-quantum.vercel.app (zero setup).
  - Write/signing tools use the local `aurachain` Rust CLI binary + wallet keyfile (`AURA_KEY_FILE`).
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

NODE_URL = os.environ.get("AURA_NODE_URL", "https://aurachain-quantum.vercel.app").rstrip("/")
REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def find_cli() -> str | None:
    env_bin = os.environ.get("AURA_CLI_BIN")
    if env_bin and pathlib.Path(env_bin).exists():
        return env_bin
    for rel in ("target/release/aurachain.exe", "target/release/aurachain"):
        cand = REPO_ROOT / rel
        if cand.exists():
            return str(cand)
    return shutil.which("aurachain")


def http_get_json(path: str) -> dict[str, Any]:
    url = f"{NODE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "AuraChain-MCP/2.0"})
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            return json.loads(raw)
        except Exception:  # noqa: BLE001
            return {"error": f"HTTP {exc.code}: {raw[:240]}"}


def run_cli(args: list[str], key_file: str | None = None) -> dict[str, Any]:
    cli = find_cli()
    if not cli:
        return {
            "error": "aurachain CLI binary not found. Run `cargo build --release` or set AURA_CLI_BIN."
        }
    kf = key_file or os.environ.get("AURA_KEY_FILE", "")
    cmd = [cli, *args, "--node", NODE_URL]
    if kf:
        if not pathlib.Path(kf).exists():
            subprocess.run([cli, "keygen", "--out", kf], check=True, capture_output=True, text=True)
        cmd.extend(["--key", kf])
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=False)
    out = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    if proc.returncode != 0:
        return {"error": err or out or f"CLI exited with {proc.returncode}"}
    return {"ok": True, "output": out}


TOOLS: list[dict[str, Any]] = [
    {
        "name": "aura_network_status",
        "description": "Fetch live AuraChain Quantum L1 consensus telemetry: block height, Casper 2/3 BFT finalized checkpoint, circulating/burned AURA, active validators, and Post-Quantum notary count.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "aura_resolve_identity",
        "description": "Resolve an @handle.aura Quantum identity or aura1q... address to liquid AURA balance, staked AURA, token holdings, NFTs, nonce, and public profile URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "identity": {
                    "type": "string",
                    "description": "Handle such as '@sanzaya.aura' or quantum address 'aura1q...'",
                }
            },
            "required": ["identity"],
        },
    },
    {
        "name": "aura_verify_notary",
        "description": "Verify whether a local file or 64-hex SHA3-256 digest has an on-chain Post-Quantum (NIST FIPS 204 ML-DSA-44) timestamp certificate and SHA3 Merkle inclusion proof.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "file_path": {"type": "string", "description": "Optional path to local file to hash with SHA3-256 (0 bytes uploaded)"},
                "sha3_hex": {"type": "string", "description": "Optional 64-character SHA3-256 hex digest or certificate ID"},
            },
        },
    },
    {
        "name": "aura_recent_activity",
        "description": "Retrieve recent on-chain Town Square messages, Post-Quantum notarized certificates, DEX token pools, and top holder leaderboard.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "aura_mine_share",
        "description": "Autonomously mine 1 zero-fee SHA3-256 Proof-of-Work share (+50 or +55 AURA) into the agent's Post-Quantum wallet.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "key_file": {"type": "string", "description": "Path to wallet JSON (auto-generated if missing; defaults to AURA_KEY_FILE)"},
                "referrer": {"type": "string", "description": "Optional referrer aura1q... address for +55 AURA bonus"},
            },
        },
    },
    {
        "name": "aura_notarize_artifact",
        "description": "Stamp a local file or text string on AuraChain Quantum L1 with a Hybrid NIST FIPS 204 ML-DSA-44 + Ed25519 signature (burns 1 AURA) and return its shareable /cert/<sha3> URL.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Certificate title (1..120 chars)"},
                "file_path": {"type": "string", "description": "Optional path to local file to hash locally via SHA3-256"},
                "content_text": {"type": "string", "description": "Optional raw text/commit/JSON to hash via SHA3-256 if file_path is omitted"},
                "meta": {"type": "string", "description": "Optional MIME/version metadata note"},
                "key_file": {"type": "string", "description": "Path to wallet JSON (defaults to AURA_KEY_FILE)"},
            },
            "required": ["title"],
        },
    },
    {
        "name": "aura_send_aura",
        "description": "Transfer AURA to any @handle.aura or aura1q... recipient signed with NIST FIPS 204 ML-DSA-44 + Ed25519.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string", "description": "Recipient @handle.aura or aura1q... address"},
                "amount": {"type": "string", "description": "Amount in AURA (e.g. '5' or '1.5')"},
                "key_file": {"type": "string", "description": "Path to wallet JSON (defaults to AURA_KEY_FILE)"},
            },
            "required": ["to", "amount"],
        },
    },
    {
        "name": "aura_post_town_square",
        "description": "Publish an on-chain signed message (up to 280 chars) to the AuraChain Quantum Town Square.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message text (1..280 printable chars)"},
                "key_file": {"type": "string", "description": "Path to wallet JSON (defaults to AURA_KEY_FILE)"},
            },
            "required": ["message"],
        },
    },
]


def call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "aura_network_status":
        info = http_get_json("/info")
        info.pop("log", None)
        return info

    if name == "aura_resolve_identity":
        ident = str(args.get("identity", "")).strip()
        res = http_get_json(f"/account/{urllib.parse.quote(ident)}")
        if res.get("handle"):
            res["profile_url"] = f"{NODE_URL}/@{res['handle']}"
        return res

    if name == "aura_verify_notary":
        fp = args.get("file_path")
        if fp:
            data = pathlib.Path(fp).read_bytes()
            q = hashlib.sha3_256(data).hexdigest()
        else:
            q = str(args.get("sha3_hex", "")).strip().lower()
        if not q:
            return {"error": "Provide file_path or sha3_hex"}
        res = http_get_json(f"/notary/{urllib.parse.quote(q)}")
        res["queried_sha3_256"] = q
        res["certificate_url"] = f"{NODE_URL}/cert/{q}"
        return res

    if name == "aura_recent_activity":
        act = http_get_json("/activity")
        eco = http_get_json("/ecosystem")
        return {
            "human_wallets": act.get("human_wallets"),
            "named_identities": act.get("named_identities"),
            "human_txs": act.get("human_txs"),
            "notarizations": eco.get("notarizations", [])[:10],
            "messages": act.get("messages", [])[:10],
            "tokens": eco.get("tokens", []),
            "leaderboard": act.get("leaderboard", [])[:10],
        }

    if name == "aura_mine_share":
        cli_args = ["pow-claim"]
        if args.get("referrer"):
            cli_args.extend(["--ref", str(args["referrer"])])
        return run_cli(cli_args, args.get("key_file"))

    if name == "aura_notarize_artifact":
        title = str(args.get("title", "Artifact")).strip()
        fp = args.get("file_path")
        if fp:
            digest = hashlib.sha3_256(pathlib.Path(fp).read_bytes()).hexdigest()
        else:
            raw = str(args.get("content_text", "")).encode("utf-8")
            if not raw:
                return {"error": "Provide file_path or content_text"}
            digest = hashlib.sha3_256(raw).hexdigest()
        cli_args = ["notarize", "--hash", digest, "--title", title]
        if args.get("meta"):
            cli_args.extend(["--meta", str(args["meta"])])
        res = run_cli(cli_args, args.get("key_file"))
        res["sha3_256"] = digest
        res["certificate_url"] = f"{NODE_URL}/cert/{digest}"
        return res

    if name == "aura_send_aura":
        return run_cli(
            ["send", "--to", str(args["to"]), "--amount", str(args["amount"])],
            args.get("key_file"),
        )

    if name == "aura_post_town_square":
        return run_cli(["post", "--message", str(args["message"])], args.get("key_file"))

    return {"error": f"Unknown tool: {name}"}


def handle_rpc(msg: dict[str, Any]) -> dict[str, Any] | None:
    method = msg.get("method", "")
    msg_id = msg.get("id")
    if method == "notifications/initialized" or msg_id is None:
        return None
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "aurachain-quantum-mcp", "version": "2.0.0"},
            },
        }
    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = msg.get("params") or {}
        t_name = params.get("name", "")
        t_args = params.get("arguments") or {}
        try:
            payload = call_tool(t_name, t_args)
            is_err = "error" in payload and not payload.get("ok")
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(payload, indent=2)}],
                    "isError": is_err,
                },
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps({"error": str(exc)})}],
                    "isError": True,
                },
            }
    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {"code": -32601, "message": f"Method not found: {method}"},
    }


def main() -> None:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    while True:
        line = stdin.readline()
        if not line:
            break
        stripped = line.strip()
        if not stripped:
            continue
        use_headers = False
        if stripped.lower().startswith(b"content-length:"):
            use_headers = True
            length = int(stripped.split(b":", 1)[1].strip())
            while True:
                hdr = stdin.readline()
                if not hdr or hdr in (b"\r\n", b"\n"):
                    break
            body = stdin.read(length)
        else:
            body = stripped
        try:
            req = json.loads(body.decode("utf-8"))
        except Exception:  # noqa: BLE001
            continue
        resp = handle_rpc(req)
        if resp is not None:
            encoded = json.dumps(resp).encode("utf-8")
            if use_headers:
                stdout.write(f"Content-Length: {len(encoded)}\r\n\r\n".encode("ascii") + encoded)
            else:
                stdout.write(encoded + b"\n")
            stdout.flush()


if __name__ == "__main__":
    main()
