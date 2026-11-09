#!/usr/bin/env python3
"""End-to-end MCP stdio smoke test. Uses a disposable Git repository only."""
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def run(binary):
    with tempfile.TemporaryDirectory(prefix="desktop-mcp-smoke-") as temp:
        root = Path(temp)
        git(root, "init", "-q")
        git(root, "config", "user.name", "MCP Smoke Test")
        git(root, "config", "user.email", "mcp@example.invalid")
        (root / "target.txt").write_text("original\n")
        (root / "unrelated.txt").write_text("preserve\n")
        git(root, "add", ".")
        git(root, "commit", "-q", "-m", "Initial")
        (root / "unrelated.txt").write_text("other changes\n")
        git(root, "add", "unrelated.txt")
        proc = subprocess.Popen(
            [str(binary), "--workspace", str(root), "--allow-writes"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        counter = 0

        def request(method, params=None):
            nonlocal counter
            counter += 1
            message = {"jsonrpc": "2.0", "id": counter, "method": method}
            if params is not None:
                message["params"] = params
            proc.stdin.write(json.dumps(message) + "\n")
            proc.stdin.flush()
            line = proc.stdout.readline()
            if not line:
                raise RuntimeError("Agent stopped: " + proc.stderr.read())
            response = json.loads(line)
            assert response["id"] == counter, response
            assert "error" not in response, response
            return response["result"]

        def call(name, args):
            reply = request("tools/call", {"name": name, "arguments": args})
            assert not reply.get("isError", False), reply
            return reply["structuredContent"]

        base = {"host_id": "local", "workspace_id": "default"}
        initialized = request(
            "initialize",
            {"protocolVersion": "2025-06-18",
             "capabilities": {},
             "clientInfo": {"name": "mcp-smoke", "version": "0.1"}},
        )
        assert initialized["serverInfo"]["name"] == "desktop-mcp-agent"
        tools = request("tools/list")["tools"]
        assert len(tools) > 100
        names = {t["name"] for t in tools}
        assert {"fs_read", "patch_prepare", "patch_apply", "git_commit_patch"}.issubset(names)
        read = call("fs_read", {**base, "path": "target.txt"})
        assert read["content"] == "original\n"
        patch = call("patch_prepare", {
            **base, "expected_head": read["head"],
            "changes": [{
                "path": "target.txt",
                "operation": "modify",
                "expected_sha256": hashlib.sha256(b"original\n").hexdigest(),
                "new_content": "updated\n",
            }],
        })
        assert patch["status"] == "prepared"
        assert (root / "target.txt").read_text() == "original\n"
        patch_id = patch["patch_id"]
        preview = call("patch_review", {**base, "patch_id": patch_id})
        assert "+updated" in preview["diff"]
        applied = call("patch_apply", {**base, "patch_id": patch_id})
        assert applied["status"] == "applied"
        result = call("git_commit_patch", {
            **base, "patch_id": patch_id,
            "message": "MCP patch smoke test",
        })
        assert result["status"] == "committed"
        assert (root / "target.txt").read_text() == "updated\n"
        assert git(root, "show", "--format=", "--name-only", "HEAD") == "target.txt"
        assert git(root, "diff", "--cached", "--name-only") == "unrelated.txt"
        assert (root / "unrelated.txt").read_text() == "other changes\n"
        proc.stdin.close()
        code = proc.wait(timeout=10)
        if code != 0:
            raise RuntimeError(f"Agent exited {code}: {proc.stderr.read()}")
        print(f"PASS: MCP handshake, {len(tools)} tools, hash checked patch, selective Git commit, staged work preserved")


if __name__ == "__main__":
    run(Path(sys.argv[1]))
