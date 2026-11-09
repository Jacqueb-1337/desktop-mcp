#!/usr/bin/env python3
"""Private Secure MCP Tunnel upstream: stdio to bearer-authenticated loopback TLS.

Run under a dedicated account that can read only the upstream bearer and CA, not
under the gateway account or root. This adapter opens no listening socket.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import sys

LIMIT = 65536
RESULT_LIMIT = 524288
MODERN = "2026-07-28"
LEGACY = {"2025-11-25", "2025-06-18"}


def error(message, request_id=None, code=-32603):
    result = {"jsonrpc": "2.0", "error": {"code": code, "message": message}}
    if request_id is not None:
        result["id"] = request_id
    return result


def read_token(path):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 256:
        raise ValueError("invalid credential file")
    if os.name != "nt" and (info.st_uid != os.geteuid() or info.st_mode & 0o077):
        raise ValueError("private owner-only credential file required")
    token = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[a-fA-F0-9]{64}", token):
        raise ValueError("invalid credential format")
    return token


def emit(result):
    sys.stdout.write(json.dumps(result, ensure_ascii=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ca", type=Path, required=True)
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument("--port", type=int, default=19875)
    args = parser.parse_args()
    try:
        token = read_token(args.token_file)
        context = ssl.create_default_context(cafile=str(args.ca))
    except (OSError, ValueError):
        print("Desktop MCP bridge credentials or TLS trust unavailable", file=sys.stderr)
        return 2
    if not 1 <= args.port <= 65535:
        parser.error("invalid upstream port")
    legacy = None
    while line := sys.stdin.buffer.readline(LIMIT + 1):
        if len(line) > LIMIT:
            emit(error("Request exceeds bridge limit", code=-32600))
            return 2
        try:
            message = json.loads(line)
            if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                raise ValueError("invalid message")
            method = message["method"]
            if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z0-9_/.-]{1,100}", method):
                raise ValueError("invalid method")
            params = message.get("params", {})
            if not isinstance(params, dict):
                raise ValueError("invalid params")
            meta = params.get("_meta", {})
            if not isinstance(meta, dict):
                raise ValueError("invalid metadata")
            version = meta.get("io.modelcontextprotocol/protocolVersion", legacy)
            if version is not None and (not isinstance(version, str) or not re.fullmatch(r"[0-9-]{10}", version)):
                raise ValueError("invalid protocol version")
            request_id = message.get("id")
            if request_id is not None and type(request_id) not in (int, str):
                raise ValueError("invalid request id")
            headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                       "Authorization": "Bearer " + token, "Mcp-Method": method}
            if version:
                headers["MCP-Protocol-Version"] = version
            if method == "tools/call":
                name = params.get("name")
                if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name):
                    raise ValueError("invalid tool name")
                headers["Mcp-Name"] = name
        except (ValueError, KeyError, UnicodeError):
            emit(error("Invalid MCP request", code=-32600))
            continue
        connection = http.client.HTTPSConnection("127.0.0.1", args.port, timeout=112, context=context)
        try:
            connection.request("POST", "/mcp", line, headers)
            response = connection.getresponse()
            data = response.read(RESULT_LIMIT + 1)
            if request_id is None:
                continue  # Notifications never receive a JSON-RPC response.
            if len(data) > RESULT_LIMIT or not data:
                emit(error("Private gateway rejected the request", request_id))
                continue
            result = json.loads(data)
            if not isinstance(result, dict) or result.get("id") != request_id or result.get("jsonrpc") != "2.0":
                emit(error("Invalid gateway response", request_id))
                continue
            if method == "initialize":
                protocol = result.get("result", {}).get("protocolVersion")
                if protocol in LEGACY:
                    legacy = protocol
            emit(result)
        except (OSError, ValueError, http.client.HTTPException):
            if request_id is not None:
                emit(error("Private gateway unavailable", request_id))
        finally:
            connection.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
