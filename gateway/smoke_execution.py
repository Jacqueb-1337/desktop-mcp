#!/usr/bin/env python3
"""Isolated real HTTPS -> persistent TLS -> local approval -> Git status test.
Test automation approves only its disposable repository, never a real workspace.
"""
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from smoke_gateway import setup_agent,make_certs,client_attempt
from smoke_approval import local_call,restart_local_service
from smoke_mcp import request,VERSION

def wait_pending(state):
    for _ in range(240):
        items=local_call(state,"approval_list")["pending"]
        if items:return items[0]
        time.sleep(.05)
    raise AssertionError("No local approval arrived")
def approve(state,item,decision="approve"):
    return local_call(state,"approval_decide",request_id=item["request_id"],nonce=item["nonce"],request_hash=item["request_hash"],decision=decision)

def main(agent,gateway,permissions=False):
    with tempfile.TemporaryDirectory(prefix="desktop-mcp-execution-",dir=Path.home() if os.name=="nt" else None) as tmp:
        root=Path(tmp);state,repo,identity=setup_agent(agent,root)
        ca,cert,key=make_certs(root)
        identities = [identity]
        if permissions:
            other_root = root / "other"
            other_root.mkdir()
            _, _, other_identity = setup_agent(agent, other_root)
            identities.append(other_identity)
        allowed=root/"allowlist.json";allowed.write_text(json.dumps({"version":1,"hosts":[{"host_id":item["host_id"],"public_key":item["public_key"]} for item in identities]}))
        tools = ["git_status", "fs_read"] + (["request_permission", "system_volume_status", "admin_command"] if permissions else [])
        policy=root/"policy.json";policy.write_text(json.dumps({"version":1,"hosts":[{"host_id":identity["host_id"],"workspace_id":"default","tools":tools}]}))
        audit=root/"audit";audit.mkdir(mode=0o700)
        token=secrets.token_hex(32);token_path=root/"token";token_path.write_text(token);token_path.chmod(0o600)
        with socket.socket() as sock:sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        processes=[]
        pool=concurrent.futures.ThreadPoolExecutor(2)
        try:
            service,_=restart_local_service(subprocess.Popen([sys.executable,"-c","pass"]),agent,repo,state,True,require_pairing_consent=permissions);processes.append(service)
            def start_gateway(peer=None, expected_host=None):
                private_listener = ["--allow-lan", "--private-listen", "127.0.0.1:0", "--private-peer", peer, "--private-host", expected_host] if peer else []
                process=subprocess.Popen([str(gateway),"--cert",str(cert),"--key",str(key),"--allowlist",str(allowed),"--policy",str(policy),"--audit-dir",str(audit),"--mcp-listen",f"127.0.0.1:{port}","--mcp-authority",f"localhost:{port}","--mcp-token-file",str(token_path),*private_listener],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                processes.append(process)
                line=process.stdout.readline();assert line.startswith("LISTENING "),line
                address=line.split()[1]
                if peer:
                    line=process.stdout.readline();assert line.startswith("PRIVATE_LISTENING "),line
                    assert line.split()[1] != address
                    address=line.split()[1]
                return process, address

            if permissions:
                rejected, address = start_gateway("127.0.0.2", identity["host_id"])
                with socket.create_connection(("127.0.0.1", int(address.rsplit(":", 1)[1])), timeout=5) as client:
                    try:
                        assert client.recv(1) == b"", "Unexpected traffic to wrong source IP"
                    except ConnectionResetError:
                        pass
                rejected.terminate()
                rejected.communicate(timeout=5)

                rejected, address = start_gateway("127.0.0.1", other_identity["host_id"])
                attempt = client_attempt(agent, state, address, "localhost", ca)
                assert attempt.returncode != 0, "Private listener accepted a different allowlisted host"
                rejected.terminate()
                _, log = rejected.communicate(timeout=5)
                assert "LISTENER_HOST_MISMATCH" in log, log
                gw, address = start_gateway("127.0.0.1", identity["host_id"])
            else:
                gw, address = start_gateway()
            presence=subprocess.Popen([str(agent),"--state-dir",str(state),"--gateway-connect","--gateway-address",address,"--gateway-tls-name","localhost","--gateway-ca",str(ca)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True);processes.append(presence)
            assert gw.stdout.readline().startswith("ENROLLED_SESSION ")
            assert gw.stdout.readline().startswith("CONTROL_PROBE_OK ")
            def call(request_id=None,host=None,tool="git_status",path=None,**extra):
                payload=request("tools/call",name=tool,arguments={"host_id":host or identity["host_id"],"workspace_id":"default",**({"request_id":request_id} if request_id else {}),**({"path":path} if path is not None else {}),**extra})
                connection=http.client.HTTPSConnection("localhost",port,context=ssl.create_default_context(cafile=str(ca)),timeout=115)
                connection.request("POST","/mcp",json.dumps(payload),{"Authorization":"Bearer "+token,"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":VERSION,"Mcp-Method":"tools/call","Mcp-Name":tool})
                response=connection.getresponse();body=json.loads(response.read());connection.close();assert response.status==200,body;return body["result"]
            assert call(host="ff"*16)["isError"] is True
            (repo/"example.txt").write_text("changed\n")
            if permissions:
                def grant(capability, duration, choice="approve"):
                    future = pool.submit(call, tool="request_permission", capability=capability, duration=duration)
                    item = wait_pending(state)
                    assert item["tool"] == "request_permission" and item["arguments"] == {"capability": capability, "duration": duration}, item
                    assert not future.done()
                    approve(state, item, choice)
                    result = future.result(20)
                    if choice == "approve":
                        assert result["structuredContent"]["outcome"]["data"] == {"capability": capability, "duration": duration, "granted": True}, result
                    else:
                        assert result["isError"] is True, result

                assert local_call(state,"set_admin_command",duration="permanent")["error"] == "ADMIN_HELPER_UNAVAILABLE"
                assert call(tool="admin_command",command="Write-Output 'disposable test'")["structuredContent"]["outcome"]["error"] == "ADMIN_HELPER_UNAVAILABLE"
                assert call(tool="request_permission", capability="admin_command", duration="7m")["structuredContent"]["outcome"]["error"] == "ADMIN_HELPER_UNAVAILABLE"
                assert call(tool="system_volume_status")["structuredContent"]["outcome"]["error"] == "ADMIN_HELPER_UNAVAILABLE"
                assert call(tool="request_permission", capability="system_volume_status", duration="permanent")["structuredContent"]["outcome"]["error"] == "ADMIN_HELPER_UNAVAILABLE"
                assert call()["structuredContent"]["outcome"]["error"] == "LOCAL_PERMISSION_REQUIRED"
                assert local_call(state,"approval_list")["pending"] == []
                grant("pairing", "permanent")
                assert call()["structuredContent"]["outcome"]["error"] == "LOCAL_PERMISSION_REQUIRED"
                grant("git_status", "30m")
                grant("fs_read", "permanent", "deny")
                assert call(tool="fs_read", path="example.txt")["structuredContent"]["outcome"]["error"] == "LOCAL_PERMISSION_REQUIRED"
                grant("git_status", "permanent")
                service,_=restart_local_service(service,agent,repo,state,True,require_pairing_consent=True);processes.append(service)
                future=pool.submit(call);item=wait_pending(state)
                assert item["tool"] == "git_status" and not future.done()
                approve(state,item)
                assert future.result(20)["structuredContent"]["outcome"]["data"]["entries"][0]["path"]=="example.txt"
                local_call(state,"revoke")
                local_call(state,"set_remote_readonly",enabled=True)
                assert call()["structuredContent"]["outcome"]["error"] == "LOCAL_PERMISSION_REQUIRED"
                print("PASS: private peer/identity restrictions, permission approval and denial, renewal, restart, exact tool approval and revocation over HTTPS/TLS")
                return
            reqid=str(uuid.uuid4());future=pool.submit(call,reqid);item=wait_pending(state)
            assert not future.done(),"Executed before approval"
            assert item["request_id"]==reqid and item["tool"]=="git_status" and item["arguments"]=={}
            assert approve(state,{**item,"request_hash":"00"*32}).get("error")=="APPROVAL_REQUEST_MISMATCH"
            assert not future.done()
            grant=approve(state,item);assert grant["authorization_granted"] is True and grant["executed"] is False,grant
            result=future.result(20);assert result["isError"] is False,result
            actual=result["structuredContent"];assert actual["request_id"]==reqid
            assert actual["outcome"]["executed"] is True
            assert actual["outcome"]["data"]["entries"][0]["path"]=="example.txt",actual
            assert call(reqid)["isError"] is True,"Gateway permitted replay"
            future=pool.submit(call);item=wait_pending(state);assert approve(state,item,"deny")["authorization_granted"] is False
            result=future.result(20);assert result["isError"] is True and result["structuredContent"]["outcome"]["executed"] is False,result
            future=pool.submit(call);item=wait_pending(state);local_call(state,"revoke")
            assert future.result(20)["structuredContent"]["outcome"]["executed"] is False
            service,_=restart_local_service(service,agent,repo,state,True);processes.append(service)
            assert local_call(state,"status")["policy"]["remote_access_enabled"] is False
            local_call(state,"set_remote_readonly",enabled=True)
            future=pool.submit(call);item=wait_pending(state)
            service,_=restart_local_service(service,agent,repo,state,True);processes.append(service)
            result=future.result(20);assert result["structuredContent"]["outcome"]["executed"] is False,result
            assert approve(state,item).get("error"),"Restart revived pending authorization"
            future=pool.submit(call);item=wait_pending(state);approve(state,item)
            assert future.result(20)["isError"] is False,"Fresh requests failed after service restart"
            future=pool.submit(call,tool="fs_read",path="example.txt");item=wait_pending(state)
            assert item["arguments"]=={"path":"example.txt"};approve(state,item)
            result=future.result(20);assert result["isError"] is False and result["structuredContent"]["outcome"]["data"]["content"]==(repo/"example.txt").read_bytes().decode("utf-8"),result
            # Closing the requesting client must stop pending execution.
            connection=http.client.HTTPSConnection("localhost",port,context=ssl.create_default_context(cafile=str(ca)),timeout=10)
            canceled_id=str(uuid.uuid4())
            connection.request("POST","/mcp",json.dumps(request("tools/call",name="git_status",arguments={"host_id":identity["host_id"],"workspace_id":"default","request_id":canceled_id})),{"Authorization":"Bearer "+token,"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":VERSION,"Mcp-Method":"tools/call","Mcp-Name":"git_status"})
            item=wait_pending(state);connection.close();time.sleep(1);approve(state,item);time.sleep(.5)
            events=[json.loads(line) for line in (state/"remote-approval-journal-v1.jsonl").read_text().splitlines()]
            assert not any(e.get("choice")=="consume" and e.get("request_id")==canceled_id for e in events),"Canceled operation executed"
            local_call(state,"revoke");local_call(state,"set_remote_readonly",enabled=True)
            # Windows junction escape must fail even after an exact local approval.
            outside=root/"outside";outside.mkdir();(outside/"secret.txt").write_text("not shared")
            if os.name=="nt":
                subprocess.run(["cmd","/c","mklink","/J",str(repo/"escape"),str(outside)],capture_output=True,check=True)
            else: (repo/"escape").symlink_to(outside,target_is_directory=True)
            future=pool.submit(call,tool="fs_read",path="escape/secret.txt");item=wait_pending(state);approve(state,item)
            result=future.result(20);assert result["isError"] is True and "not shared" not in json.dumps(result),result
            print("PASS: real MCP HTTPS/TLS lifecycle, genuine Git result, exact approval, wrong hash, denial, replay, revoke, service restart/recovery, scoped file read and junction escape rejection")
        finally:
            for process in reversed(processes):
                if process.poll() is None:process.terminate()
                try:process.communicate(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.communicate(timeout=5)
            pool.shutdown(wait=False,cancel_futures=True)
if __name__=="__main__":main(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve(),"--permissions" in sys.argv[3:])
