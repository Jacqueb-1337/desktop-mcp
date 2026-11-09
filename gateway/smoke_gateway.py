#!/usr/bin/env python3
"""Isolated TLS gateway presence test. Never connects or executes remote MCP tools."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import uuid

def run(*args):
    if args[0] == "openssl" and os.name == "nt":
        openssl = Path("C:/Program Files/Git/usr/bin/openssl.exe")
        if not openssl.is_file():
            raise RuntimeError("OpenSSL not found in Git for Windows")
        args = (str(openssl), *args[1:])
    return subprocess.run(args, capture_output=True, text=True, check=True)

def setup_agent(agent, root):
    repo = root / "repo"
    state = root / "state"
    repo.mkdir()
    state.mkdir(mode=0o700)
    run("git", "init", "-q", str(repo))
    run("git", "-C", str(repo), "config", "user.name", "Gateway Test")
    run("git", "-C", str(repo), "config", "user.email", "smoke@example.invalid")
    (repo / "example.txt").write_bytes(b"leave-me-alone\n")
    run("git", "-C", str(repo), "add", "example.txt")
    run("git", "-C", str(repo), "commit", "-q", "-m", "initial")
    p = subprocess.Popen([str(agent), "--workspace", str(repo), "--state-dir",
                          str(state), "--serve-local"], stdout=subprocess.DEVNULL,
                         stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            f = state / "local-agent.json"
            if f.exists():
                info = json.loads(f.read_text())
                if info["pid"] == p.pid:
                    break
            if p.poll() is not None:
                raise RuntimeError("Local agent died: " + p.stderr.read().decode())
            time.sleep(0.03)
        else:
            raise RuntimeError("Agent startup timeout")
        identity = json.loads(run(str(agent), "--state-dir", str(state),
                                  "--pair-action", "pair_identity").stdout)
    finally:
        p.terminate()
        p.wait(timeout=5)
    return state, repo, identity

def make_certs(root):
    ca = root / "ca.pem"
    key = root / "ca.key"
    server = root / "server.pem"
    server_key = root / "server.key"
    csr = root / "server.csr"
    ext = root / "server.ext"
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-noenc",
        "-keyout", str(key), "-out", str(ca), "-days", "1", "-subj", "/CN=DesktopMcpTestCA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-new", "-newkey", "rsa:2048", "-noenc",
        "-keyout", str(server_key), "-out", str(csr), "-subj", "/CN=localhost")
    ext.write_text("subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n")
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(key),
        "-CAcreateserial", "-out", str(server), "-days", "1", "-extfile", str(ext))
    server_key.chmod(0o600)
    return ca, server, server_key

def launch_gateway(gateway, ca, cert, key, allowlist, root, route=None, policy=None):
    command=[str(gateway), "--listen", "127.0.0.1:0",
             "--cert", str(cert), "--key", str(key),
             "--allowlist", str(allowlist), "--once"]
    if route is not None:
        audit_dir = root / "gateway-audit"
        audit_dir.mkdir(mode=0o700,exist_ok=True)
        command.extend(["--route-intent",str(route),"--policy",str(policy),
                        "--audit-dir",str(audit_dir)])
    p = subprocess.Popen(command,stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE,text=True)
    line = p.stdout.readline().strip()
    match = re.fullmatch(r"LISTENING (127\.0\.0\.1:\d+) identity_only no_remote_commands", line)
    if not match:
        p.kill()
        p.wait(timeout=5)
        raise RuntimeError("Gateway failed: " + line + " " + p.stderr.read())
    return p, match.group(1)

def client_attempt(agent, state, addr, tls_name, ca):
    return subprocess.run([str(agent), "--state-dir", str(state), "--gateway-probe",
                           "--gateway-address", addr, "--gateway-tls-name", tls_name,
                           "--gateway-ca", str(ca)], capture_output=True, text=True, timeout=20)

def main(agent, gateway):
    with tempfile.TemporaryDirectory(prefix="desktop-mcp-gateway-smoke-",
                                     dir=Path.home() if os.name == "nt" else None) as temp:
        root = Path(temp)
        state, repo, identity = setup_agent(agent, root)
        ca, cert, key = make_certs(root)
        allowlist = root / "allowlist.json"
        allowlist.write_text(json.dumps({"version": 1, "hosts": [
            {"host_id": identity["host_id"], "public_key": identity["public_key"]}]}))

        def check(should_pass, tls_name="localhost", trusted_ca=None):
            p, addr = launch_gateway(gateway, ca, cert, key, allowlist, root)
            try:
                result = client_attempt(agent, state, addr, tls_name, trusted_ca or ca)
                assert (result.returncode == 0) == should_pass, (result.stdout, result.stderr)
                if should_pass:
                    output = json.loads(result.stdout)
                    assert output["status"] == "authenticated"
                    assert output["tls_verified"] is True
                    assert output["remote_tools_enabled"] is False
                    assert output["authorization"] == "identity_only"
                    assert output["control_probe_verified"] is True
                    assert output["host_id"] == identity["host_id"]
            finally:
                try:
                    p.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.communicate(timeout=5)

        check(True)
        # A policy-scoped operator request crosses authenticated TLS, but
        # remains unexecuted pending explicit local approval.
        route_file=root / "route-intent.json"
        policy_file=root / "route-policy.json"
        route_file.write_text(json.dumps({
            "request_id":str(uuid.uuid4()),"target_host_id":identity["host_id"],
            "workspace_id":"default","tool":"fs_read"}))
        policy_file.write_text(json.dumps({"version":1,"hosts":[{
            "host_id":identity["host_id"],"workspace_id":"default",
            "tools":["fs_read"]}]}))
        p, addr=launch_gateway(gateway,ca,cert,key,allowlist,root,route_file,policy_file)
        try:
            result=client_attempt(agent,state,addr,"localhost",ca)
            assert result.returncode==0,(result.stdout,result.stderr)
            body=json.loads(result.stdout)
            assert body["control_probe_verified"] is True
            assert body["route_denial_sent"] is True
            output,errors=p.communicate(timeout=5)
            assert p.returncode==0,(output,errors)
            assert "ROUTE_REQUIRES_LOCAL_APPROVAL" in output,(output,errors)
        finally:
            if p.poll() is None:
                p.kill()
                p.communicate(timeout=5)
        # The same route ID is rejected by a fresh gateway process.
        # The first process already fsynced its keyed reservation.
        p, addr=launch_gateway(gateway,ca,cert,key,allowlist,root,route_file,policy_file)
        try:
            result=client_attempt(agent,state,addr,"localhost",ca)
            assert result.returncode!=0,(result.stdout,result.stderr)
            output,errors=p.communicate(timeout=5)
            assert p.returncode!=0,(output,errors)
            assert "AUDIT_REPLAYED_REQUEST" in errors,(output,errors)
            assert "ROUTE_REQUIRES_LOCAL_APPROVAL" not in output,(output,errors)
        finally:
            if p.poll() is None:
                p.kill()
                p.communicate(timeout=5)
        # The journal and key are integrity bound: corruption must not be
        # accepted as a fresh start. Test this after all legitimate routes.        assert (repo / "example.txt").read_bytes()==b"leave-me-alone\n"
        # A request for a different host must never reach the local agent.
        route_file.write_text(json.dumps({
            "request_id":str(uuid.uuid4()),
            "target_host_id":"00000000000000000000000000000000",
            "workspace_id":"default","tool":"fs_read"}))
        p, addr=launch_gateway(gateway,ca,cert,key,allowlist,root,route_file,policy_file)
        try:
            result=client_attempt(agent,state,addr,"localhost",ca)
            assert result.returncode!=0,(result.stdout,result.stderr)
            output,errors=p.communicate(timeout=5)
            assert p.returncode!=0,(output,errors)
            assert "ROUTE_REQUIRES_LOCAL_APPROVAL" not in output,(output,errors)
            assert "ROUTE_POLICY_DENIED" in errors,(output,errors)
        finally:
            if p.poll() is None:
                p.kill()
                p.communicate(timeout=5)
        # A damaged persistent audit journal must prevent the gateway
        # from accepting further routed requests, not reset the history.
        with (root/"gateway-audit"/"route-audit-v1.jsonl").open("ab") as file:
            file.write(b"{incomplete")
        try:
            launch_gateway(gateway,ca,cert,key,allowlist,root,route_file,policy_file)
        except RuntimeError as error:
            assert "AUDIT_INCOMPLETE_LOG" in str(error),error
        else:
            raise AssertionError("Corrupted gateway audit unexpectedly accepted")
        check(False, tls_name="wrong.example.invalid")
        allowlist.write_text(json.dumps({"version": 1, "hosts": []}))
        check(False)
        assert (repo / "example.txt").read_bytes() == b"leave-me-alone\n"
        print("PASS: TLS identity, routed denial, cross-host rejection, no remote commands, disposable files untouched")

if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
