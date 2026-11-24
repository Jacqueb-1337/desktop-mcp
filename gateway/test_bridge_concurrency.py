#!/usr/bin/env python3
"""Exercise the real stdio bridge against a disposable local HTTPS fixture."""
import hmac
import json
import os
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from smoke_gateway import make_certs

VERSION = "2026-07-28"


def main():
    with tempfile.TemporaryDirectory(prefix="desktop-mcp-bridge-test-") as tmp:
        root = Path(tmp)
        ca, cert, key = make_certs(root)
        token = secrets.token_hex(32)
        token_file = root / "token"
        token_file.write_text(token, encoding="ascii")
        token_file.chmod(0o600)
        condition = threading.Condition()
        arrived = set()
        completed = []
        released = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                if self.path != "/mcp" or not hmac.compare_digest(
                    self.headers.get("Authorization", ""), "Bearer " + token
                ):
                    self.send_error(401)
                    return
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                rid = request["id"]
                if request["method"] != "tools/call" or request["params"]["name"] != "git_status":
                    self.send_error(400)
                    return
                with condition:
                    arrived.add(rid)
                    condition.notify_all()
                # Request 1 cannot finish until the test driver sees both short replies.
                if rid == 1 and not released.wait(10):
                    self.send_error(504)
                    return
                payload = json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"fixture": True}}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert), str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        bridge = Path(__file__).with_name("tunnel_stdio.py")
        process = subprocess.Popen(
            [sys.executable, str(bridge), "--ca", str(ca), "--token-file", str(token_file),
             "--port", str(server.server_port)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )

        def collect():
            for line in process.stdout:
                response = json.loads(line)
                with condition:
                    completed.append(response)
                    condition.notify_all()

        reader = threading.Thread(target=collect, daemon=True)
        reader.start()
        try:
            def send(rid):
                request = {"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                           "params": {"name": "git_status", "arguments": {},
                                      "_meta": {"io.modelcontextprotocol/protocolVersion": VERSION}}}
                process.stdin.write(json.dumps(request) + "\n")
                process.stdin.flush()

            send(1)
            with condition:
                assert condition.wait_for(lambda: 1 in arrived, timeout=5), "first request did not arrive"
            send(2)
            send(3)
            with condition:
                assert condition.wait_for(lambda: arrived == {1, 2, 3}, timeout=5), "bridge serialized ingress"
                assert condition.wait_for(lambda: len(completed) >= 2, timeout=5), "short replies blocked"
                assert {r["id"] for r in completed} == {2, 3}, completed
                assert all(r.get("result") == {"fixture": True} for r in completed), completed
            released.set()
            process.stdin.close()
            assert process.wait(timeout=10) == 0
            reader.join(timeout=2)
            assert [r["id"] for r in completed][-1] == 1, completed
            assert len(completed) == 3 and all(r.get("result") == {"fixture": True} for r in completed)
            print("PASS: three independent TLS requests arrived; both short replies returned before long reply")
        finally:
            released.set()
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=2)
            server.shutdown()
            server.server_close()
            worker.join(timeout=2)


if __name__ == "__main__":
    main()
