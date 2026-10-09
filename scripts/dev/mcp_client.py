#!/usr/bin/env python3
"""Minimal JSON-RPC client for correlic-mcp over stdio.

Starts the MCP server as a subprocess, performs the MCP handshake and runs
the requested tool calls, printing every request and response as pretty
JSON. Used to capture the transcript in backend/docs/MCP_SERVER.md and to
smoke-test the server against a running stack without an MCP host.

Usage:
    scripts/dev/mcp_client.py [--server PATH] [--allow-writes] [--max-chars N] \
        [TOOL[:JSON_ARGS] ...]

    # list tools only
    CORRELIC_API_URL=https://127.0.0.1:28080 CORRELIC_API_KEY=... \
    CORRELIC_TLS_CA_FILE=... CORRELIC_TLS_CLIENT_CERT_FILE=... CORRELIC_TLS_CLIENT_KEY_FILE=... \
        scripts/dev/mcp_client.py --server ./correlic-mcp

    # call tools
    scripts/dev/mcp_client.py --server ./correlic-mcp \
        correlic.agents.list \
        'correlic.findings.list:{"severity":"critical","since":"24h"}'

The server inherits the environment (CORRELIC_API_URL, CORRELIC_API_KEY,
CORRELIC_TLS_*). Tool results are JSON text; --max-chars trims long ones in
the printed output (the full result is still parsed).
"""
import argparse
import json
import os
import subprocess
import sys

PROTOCOL_VERSION = "2025-06-18"  # what current MCP clients send; the server answers with its own


class McpStdio:
    def __init__(self, cmd):
        self.proc = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr, text=True, bufsize=1
        )
        self.next_id = 1

    def request(self, method, params=None, max_chars=None):
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.next_id += 1
        print(f"--> {json.dumps(msg)}")
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        line = self.proc.stdout.readline()
        if not line:
            raise SystemExit("server closed stdout")
        resp = json.loads(line)
        print(f"<-- {render(resp, max_chars)}")
        return resp

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        print(f"--> {json.dumps(msg)}")
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()

    def close(self):
        self.proc.stdin.close()
        self.proc.wait(timeout=10)


def render(resp, max_chars):
    """Pretty-print a response; tool result text (JSON) is expanded in place."""
    out = json.loads(json.dumps(resp))  # deep copy
    result = out.get("result")
    if isinstance(result, dict) and isinstance(result.get("content"), list):
        for block in result["content"]:
            if block.get("type") == "text":
                try:
                    block["text"] = json.loads(block["text"])
                except (ValueError, TypeError):
                    pass
    text = json.dumps(out, indent=2, sort_keys=False)
    if max_chars and len(text) > max_chars:
        text = text[:max_chars] + f"\n... [{len(text) - max_chars} more characters trimmed]"
    return text


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--server", default=os.environ.get("CORRELIC_MCP_BIN", "correlic-mcp"), help="path to correlic-mcp")
    ap.add_argument("--allow-writes", action="store_true", help="start the server with --allow-writes")
    ap.add_argument("--max-chars", type=int, default=4000, help="trim printed responses to this many characters (0 = no trim)")
    ap.add_argument("calls", nargs="*", help="TOOL or TOOL:JSON_ARGS")
    args = ap.parse_args()

    cmd = [args.server]
    if args.allow_writes:
        cmd.append("--allow-writes")
    client = McpStdio(cmd)
    try:
        client.request("initialize", {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "mcp_client.py", "version": "1"},
        }, args.max_chars)
        client.notify("notifications/initialized")
        client.request("tools/list", max_chars=args.max_chars)
        for call in args.calls:
            name, _, raw = call.partition(":")
            params = {"name": name, "arguments": json.loads(raw) if raw else {}}
            client.request("tools/call", params, args.max_chars)
    finally:
        client.close()


if __name__ == "__main__":
    main()
