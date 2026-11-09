#!/usr/bin/env python3
"""Exercise local authenticated IPC and approval lifecycle on a disposable Git repo."""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def git(root: Path, *args):
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def request(info, method, **kwargs):
    payload = {"token": info["token"], "method": method, **kwargs}
    with socket.create_connection(("127.0.0.1", info["port"]), timeout=2) as client:
        client.settimeout(4)
        client.sendall(json.dumps(payload).encode() + b"\n")
        raw = bytearray()
        while not raw.endswith(b"\n"):
            chunk = client.recv(65536)
            if not chunk:
                break
            raw.extend(chunk)
        if not raw:
            raise RuntimeError(f"Empty local response for {method}")
        return json.loads(raw)


def main(binary):
    with tempfile.TemporaryDirectory(prefix="desktop-mcp-ipc-") as temporary:
        root = Path(temporary)
        workspace = root / "project"
        state = root / "agent-config"
        workspace.mkdir()
        state.mkdir()
        git(workspace, "init", "-q")
        git(workspace, "config", "user.name", "Desktop MCP Test")
        git(workspace, "config", "user.email", "test@example.invalid")
        (workspace / "file.txt").write_bytes(b"before\n")
        git(workspace, "add", "file.txt")
        git(workspace, "commit", "-q", "-m", "initial")
        agent = subprocess.Popen(
            [str(binary), "--workspace", str(workspace), "--state-dir", str(state),
             "--serve-local", "--allow-writes"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(100):
                runtime = state / "local-agent.json"
                if runtime.exists():
                    break
                if agent.poll() is not None:
                    raise RuntimeError("Agent quit: " + agent.stderr.read())
                time.sleep(.04)
            else:
                raise RuntimeError("Agent did not create discovery credentials")
            info = json.loads(runtime.read_text())
            if os.name != "nt":
                assert runtime.stat().st_mode & 0o077 == 0, "Credential file permissions too permissive"
                assert state.stat().st_mode & 0o077 == 0, "Credential directory permissions too permissive"
            assert len(info["token"]) == 64
            status = request(info, "status")
            assert status["running"] and not status["policy"]["writes_currently_authorized"]
            from_cli = json.loads(subprocess.check_output(
                [str(binary), "--state-dir", str(state), "--local-status"], text=True))
            assert from_cli["pid"] == agent.pid

            def tool(name, arguments):
                return request(info, "tool", name=name, arguments=arguments)

            scope = {"host_id": "local", "workspace_id": "default"}
            read = tool("fs_read", {**scope, "path": "file.txt"})["result"]
            assert read["content"] == "before\n"
            prepared = tool("patch_prepare", {
                **scope, "expected_head": read["head"],
                "changes": [{"path": "file.txt", "operation": "modify",
                             "expected_sha256": hashlib.sha256(b"before\n").hexdigest(),
                             "new_content": "after\n"}]
            })["result"]
            patch = {**scope, "patch_id": prepared["patch_id"]}
            assert "APPROVAL_REQUIRED" in tool("patch_apply", patch)["error"]

            assert request(info, "set_policy", mode="auto", duration="30")["policy"]["writes_currently_authorized"]
            assert tool("patch_apply", patch)["result"]["status"] == "applied"
            assert tool("git_commit_patch", {**patch, "message": "approved edit"})["result"]["status"] == "committed"
            assert git(workspace, "log", "-1", "--format=%s") == "approved edit"
            assert (workspace / "file.txt").read_text() == "after\n"
            delete_patch = tool("patch_prepare", {
                **scope,
                "expected_head": git(workspace, "rev-parse", "HEAD"),
                "changes": [{
                    "path": "file.txt",
                    "operation": "delete",
                    "expected_sha256": hashlib.sha256(b"after\n").hexdigest(),
                    "new_content": None,
                }],
            })["result"]
            denied_delete = tool("patch_apply", {**scope, "patch_id": delete_patch["patch_id"]})
            assert "DESTRUCTIVE_APPROVAL_REQUIRED" in denied_delete["error"]
            assert (workspace / "file.txt").read_text() == "after\n"

            assert request(info, "revoke")["policy"]["writes_currently_authorized"] is False
            assert "APPROVAL_REQUIRED" in tool("patch_apply", patch)["error"]
            status = request(info, "status")
            assert status["running"] and not status["policy"]["writes_currently_authorized"]

            with socket.create_connection(("127.0.0.1", info["port"]), timeout=2) as sock:
                sock.settimeout(2)
                sock.sendall(json.dumps({"token": "0"*64, "method": "status"}).encode() + b"\n")
                assert sock.recv(1024) == b"", "Unauthenticated request received data"

            print("PASS: local authentication, separate-process status, default deny, timed approval, patch+commit, revoke")
        finally:
            agent.terminate()
            try:
                agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                agent.kill()
                agent.wait(timeout=5)


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve())
