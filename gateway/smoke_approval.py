"""End-to-end authenticated route to local review inbox, without execution."""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from smoke_gateway import setup_agent, make_certs, launch_gateway, client_attempt

def local_call(state, method, **params):
    runtime=json.loads((state/"local-agent.json").read_text())
    with socket.create_connection(("127.0.0.1",runtime["port"]),timeout=2) as client:
        client.settimeout(3)
        outgoing={"token":runtime["token"],"method":method,**params}
        client.sendall((json.dumps(outgoing)+"\n").encode())
        with client.makefile("rb") as reader:
            response=json.loads(reader.readline())
    return response

def restart_local_service(service, agent, repo, state, remote_readonly=False, require_pairing_consent=False):
    if service.poll() is None:
        service.terminate()
        try:
            service.communicate(timeout=4)
        except subprocess.TimeoutExpired:
            service.kill()
            service.communicate(timeout=4)
    gate=state/"remote-readonly.enabled"
    if remote_readonly and not gate.exists():
        gate.write_bytes(b"enabled\n");gate.chmod(0o600)
    next_service=subprocess.Popen([str(agent),"--workspace",str(repo),
        "--state-dir",str(state),"--serve-local",*(["--allow-remote-readonly"] if remote_readonly else []),*(["--require-pairing-consent"] if require_pairing_consent else [])],
        stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    for _ in range(80):
        if next_service.poll() is not None:
            raise AssertionError("Restarted local agent failed: "+next_service.stderr.read())
        try:
            return next_service,local_call(state,"approval_list")
        except (OSError,ValueError):
            time.sleep(.05)
    raise AssertionError("Restarted local agent unavailable")
def main(agent, gateway):
    with tempfile.TemporaryDirectory(prefix="desktop-mcp-approval-smoke-",
            dir=Path.home() if os.name=="nt" else None) as temp:
        root=Path(temp)
        state, repo, identity=setup_agent(agent,root)
        service=subprocess.Popen([str(agent),"--workspace",str(repo),
            "--state-dir",str(state),"--serve-local"],
            stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(60):
                if service.poll() is not None:
                    raise AssertionError("Local agent failed to start: "+service.stderr.read())
                if (state/"local-agent.json").exists():
                    try:
                        local_call(state,"approval_list")
                        break
                    except (OSError,ValueError):
                        pass
                time.sleep(.05)
            else:
                raise AssertionError("Local agent was not ready")
            ca,cert,key=make_certs(root)
            allowed=root/"allowlist.json"
            allowed.write_text(json.dumps({"version":1,"hosts":[{
                "host_id":identity["host_id"],"public_key":identity["public_key"]}]}))
            policy=root/"policy.json"
            policy.write_text(json.dumps({"version":1,"hosts":[{
                "host_id":identity["host_id"],"workspace_id":"default",
                "tools":["fs_read"]}]}))
            intent=root/"intent.json"
            request_id=str(uuid.uuid4())
            intent.write_text(json.dumps({"request_id":request_id,
                "target_host_id":identity["host_id"],
                "workspace_id":"default","tool":"fs_read"}))
            gateway_proc,addr=launch_gateway(gateway,ca,cert,key,allowed,root,intent,policy)
            try:
                client=client_attempt(agent,state,addr,"localhost",ca)
                assert client.returncode==0,(client.stdout,client.stderr)
                out,err=gateway_proc.communicate(timeout=5)
                assert gateway_proc.returncode==0,(out,err)
                assert "ROUTE_REQUIRES_LOCAL_APPROVAL" in out
            finally:
                if gateway_proc.poll() is None:
                    gateway_proc.kill()
                    gateway_proc.communicate(timeout=5)
            listed=local_call(state,"approval_list")
            pending=listed["pending"]
            assert len(pending)==1,pending
            item=pending[0]
            # Stage was fsynced to disk before the TLS client got its response.
            service,restored=restart_local_service(service,agent,repo,state)
            assert len(restored["pending"])==1,restored
            assert restored["pending"][0]["request_id"]==request_id
            assert item["request_id"]==request_id
            assert item["tool"]=="fs_read"
            assert item["execution_enabled"] is False
            duplicate=local_call(state,"approval_stage",route={
                "type":"route_intent","version":1,"request_id":request_id,
                "target_host_id":identity["host_id"],"workspace_id":"default",
                "tool":"fs_read","nonce":item["nonce"]})
            assert duplicate["error"]=="APPROVAL_REPLAYED",duplicate
            wrong=local_call(state,"approval_decide",request_id=request_id,
                nonce=item["nonce"],request_hash="0"*64,decision="approve")
            assert wrong["error"]=="APPROVAL_REQUEST_MISMATCH",wrong
            decision=local_call(state,"approval_decide",request_id=request_id,
                nonce=item["nonce"],request_hash=item["request_hash"],decision="approve")
            assert decision["decision"]=="approved_for_review"
            assert decision["authorization_granted"] is False
            assert decision["executed"] is False
            assert local_call(state,"approval_list")["pending"]==[]
            # Replaying the same ID with a different nonce after a second
            # process restart is still denied, even after review resolution.
            service,restored=restart_local_service(service,agent,repo,state)
            assert restored["pending"]==[],restored
            replay=local_call(state,"approval_stage",route={
                "type":"route_intent","version":1,"request_id":request_id,
                "target_host_id":identity["host_id"],"workspace_id":"default",
                "tool":"fs_read","nonce":"cd"*32})
            assert replay["error"]=="APPROVAL_REPLAYED",replay
            assert (repo/"example.txt").read_bytes()==b"leave-me-alone\n"
            print("PASS: TLS route journaled; restarts preserve inbox and used IDs; fingerprint mismatch denied; no execution")
        finally:
            if service.poll() is None:
                service.terminate()
                try:
                    service.communicate(timeout=4)
                except subprocess.TimeoutExpired:
                    service.kill()
                    service.communicate(timeout=4)

if __name__=="__main__":
    main(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
