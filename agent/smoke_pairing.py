#!/usr/bin/env python3
"""Local-only enrollment smoke test using two independent Desktop MCP agents.
No remote network listener or production workspace is involved.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()

class Agent:
    def __init__(self, executable, root, label):
        self.repo = root / (label + "-repo")
        self.state = root / (label + "-state")
        self.repo.mkdir()
        self.state.mkdir()
        git(self.repo, "init", "-q")
        git(self.repo, "config", "user.name", "Pairing Smoke")
        git(self.repo, "config", "user.email", "smoke@example.invalid")
        (self.repo / "test.txt").write_bytes(b"unchanged\n")
        git(self.repo, "add", "test.txt")
        git(self.repo, "commit", "-q", "-m", "initial")
        self.executable = executable
        self.process = None
        self.info = None
        self.start()

    def start(self):
        self.process = subprocess.Popen(
            [str(self.executable), "--workspace", str(self.repo),
             "--state-dir", str(self.state), "--serve-local"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )
        for _ in range(100):
            path = self.state / "local-agent.json"
            if path.exists():
                candidate = json.loads(path.read_text())
                if candidate["pid"] == self.process.pid:
                    self.info = candidate
                    break
            if self.process.poll() is not None:
                raise RuntimeError("Agent exited: " + self.process.stderr.read().decode())
            time.sleep(0.04)
        else:
            raise RuntimeError("Agent failed to start")

    def request(self, method, **params):
        payload = {"token": self.info["token"], "method": method, **params}
        with socket.create_connection(("127.0.0.1", self.info["port"]), timeout=3) as client:
            client.settimeout(5)
            client.sendall(json.dumps(payload).encode() + b"\n")
            data = bytearray()
            while not data.endswith(b"\n"):
                chunk = client.recv(65536)
                if not chunk:
                    break
                data.extend(chunk)
        response = json.loads(data)
        return response

    def cli(self, action, value=None, name=None):
        args = [str(self.executable), "--state-dir", str(self.state), "--pair-action", action]
        payload_file = self.state / "exchange.json"
        if value is not None:
            payload_file.write_text(json.dumps(value))
            if os.name != "nt":
                payload_file.chmod(0o600)
            args += ["--pair-payload-file", str(payload_file)]
        if name is not None:
            args += ["--pair-name", name]
        result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=12)
        if result.returncode:
            raise RuntimeError(f"pair command {action} failed: {result.stderr}")
        return json.loads(result.stdout)

    def close(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=4)

def main(binary):
    with tempfile.TemporaryDirectory(prefix="desktop-mcp-pairing-") as temp:
        root = Path(temp)
        a = Agent(binary, root, "desktop")
        b = Agent(binary, root, "laptop")
        try:
            id_a = a.cli("pair_identity")["host_id"]
            id_b = b.cli("pair_identity")["host_id"]
            assert id_a != id_b
            assert not a.request("status")["policy"]["writes_currently_authorized"]
            invitation = a.cli("pair_create_invite")
            request = b.cli("pair_prepare_join", invitation, "Laptop")
            assert request["join_request"]["peer_id"] == id_b
            # Reject tampering without accepting or consuming the valid invite.
            fake = json.loads(json.dumps(request))
            fake["join_request"]["peer_name"] = "Forged Name"
            failure = a.request("pair_accept_join", join_request=fake["join_request"])
            assert failure.get("error") == "INVALID_JOIN_SIGNATURE"
            receipt = a.cli("pair_accept_join", request)
            assert receipt["status"] == "enrolled"
            assert not receipt["remote_tools_enabled"]
            result = b.cli("pair_finalize_join", receipt, "Desktop")
            assert result["status"] == "enrolled"
            assert not result["remote_tools_enabled"]
            assert len(a.cli("pair_list")["peers"]) == 1
            assert len(b.cli("pair_list")["peers"]) == 1
            assert a.request("pair_accept_join", join_request=request["join_request"]).get("error") == "INVITATION_NOT_ACTIVE"
            b.close()
            b.start()
            assert b.cli("pair_identity")["host_id"] == id_b
            assert len(b.cli("pair_list")["peers"]) == 1
            assert a.cli("pair_revoke", name=id_b)["status"] == "revoked"
            assert len(a.cli("pair_list")["peers"]) == 0
            assert (a.repo / "test.txt").read_bytes() == b"unchanged\n"
            print("PASS: two independent local services, signed join/receipt, tamper and replay rejection, durable identity, revoke, no remote permissions")
        finally:
            a.close()
            b.close()

if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
