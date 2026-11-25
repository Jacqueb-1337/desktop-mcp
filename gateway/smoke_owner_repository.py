#!/usr/bin/env python3
"""Exercise the real non-elevated repository relay against a private fixture.
No installed service, production state, real gateway, or user grants are touched.
The Windows SYSTEM token launcher itself requires a separate installed-service test.
"""
import contextlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from smoke_gateway import setup_agent
from smoke_approval import local_call

def main(agent):
    if os.name!="nt": raise SystemExit("Windows owner relay test")
    with contextlib.ExitStack() as stack:
        root=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="dmcp-owner-relay-",dir=Path.home())))
        share=os.environ.get("DMCP_SMOKE_REPO_PARENT")
        parent=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="dmcp-owner-relay-",dir=share))) if share else None
        state,repo,identity=setup_agent(agent,root,repo_parent=parent)
        target=root/"com.jacqueb.desktopmcp"
        state.rename(target);state=target
        host=identity["host_id"]
        (state/"selected-repository.txt").write_text(str(repo.resolve()),encoding="utf-8")
        (state/"remote-readonly.enabled").write_bytes(b"enabled\n")
        processes=[]
        def launch(*args,**kwargs):
            process=subprocess.Popen([str(agent),*args],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,**kwargs)
            processes.append(process)
            return process
        try:
            service=launch("--state-dir",str(state),"--serve-local","--allow-remote-readonly","--require-pairing-consent")
            for _ in range(120):
                if service.poll() is not None:raise AssertionError(service.stderr.read())
                try:
                    status=local_call(state,"status")
                    if status.get("repository_relay_ready"):break
                except (OSError,ValueError):pass
                time.sleep(.05)
            else:raise AssertionError("Local repository agent unavailable")
            assert status["identity"]["host_id"]==host and not status["policy"]["system_mode"] and status["policy"]["remote_access_enabled"],status
            def frame(tool,**args):
                return {"type":"route_intent","version":2,"request_id":str(uuid.uuid4()),
                    "target_host_id":host,"workspace_id":"default","tool":tool,
                    "nonce":secrets.token_hex(32),"arguments":args,"expires_at":int(time.time())+90}
            def connect():
                listener=socket.socket()
                listener.bind(("127.0.0.1",0));listener.listen(1);listener.settimeout(5)
                nonce=secrets.token_hex(32)
                child=launch("--user-repository-worker",str(listener.getsockname()[1]),nonce,
                    env={**os.environ,"APPDATA":str(root)})
                stream,_=listener.accept();listener.close();stream.settimeout(10)
                reader=stream.makefile("rb")
                assert reader.readline().decode().strip()==nonce
                stack.callback(stream.close);stack.callback(reader.close)
                return stream,reader,child
            stream,reader,child=connect()
            def call(method,route):
                stream.sendall((json.dumps({"method":method,"route":route,"host":host})+"\n").encode())
                reply=json.loads(reader.readline())
                assert reply["route_id"]==route["request_id"] and reply["method"]==method,reply
                return reply["reply"]
            def stage(route):
                return call("approval_stage",route)
            def approve(route,choice="approve"):
                pending=local_call(state,"approval_list")["pending"]
                item=next(i for i in pending if i["request_id"]==route["request_id"])
                result=local_call(state,"approval_decide",request_id=item["request_id"],
                    nonce=item["nonce"],request_hash=item["request_hash"],decision=choice)
                assert result.get("authorization_granted")== (choice=="approve"),result
            def approved(route):
                assert stage(route).get("queued"),route
                assert call("approval_execute",route)=={"pending":True}
                approve(route)
                result=call("approval_execute",route)
                assert result.get("executed") and not result.get("error"),result
                return result["data"]
            first=stage(frame("git_status"));assert first.get("error")=="LOCAL_PERMISSION_REQUIRED",(first,status)
            for cap in ("pairing","git_status","fs_read","fs_search","use_repository","patch_prepare","patch_apply","patch_review","git_commit_patch"):
                assert approved(frame("request_permission",capability=cap,duration="30m"))["granted"]
            current=approved(frame("git_status"))
            source=approved(frame("fs_read",path="example.txt",start_line=1,end_line=1))
            assert source["content"]=="leave-me-alone\n",source
            result=approved(frame("fs_search",query={"mode":"text","pattern":"leave-me-alone"}))
            assert result["results"][0]["path"]=="example.txt",result
            change=approved(frame("patch_prepare",expected_head=source["head"],changes=[{
                "path":"example.txt","operation":"modify","expected_sha256":source["sha256"],"new_content":"owner-relay\n"}]))
            assert "owner-relay" in approved(frame("patch_review",patch_id=change["patch_id"]))["diff"]
            approved(frame("patch_apply",patch_id=change["patch_id"]))
            approved(frame("git_commit_patch",patch_id=change["patch_id"],message="Owner relay fixture"))
            assert (repo/"example.txt").read_bytes()==b"owner-relay\n"
            # No stale authorization after a cancel or selection change.
            denied=frame("fs_read",path="example.txt");assert stage(denied)["queued"]
            approve(denied,"deny");assert not call("approval_execute",denied)["executed"]
            canceled=frame("fs_read",path="example.txt");assert stage(canceled)["queued"]
            approve(canceled);assert call("approval_cancel",canceled)["canceled"]
            assert not call("approval_execute",canceled)["executed"]
            stale=frame("fs_read",path="example.txt");assert stage(stale)["queued"]
            other=root/"other";other.mkdir()
            approved(frame("use_repository",path=str(other),initialize=True))
            approve(stale)
            assert call("approval_execute",stale)["error"]=="APPROVAL_WORKSPACE_CHANGED_OR_UNBOUND"
            approved(frame("use_repository",path=str(repo),initialize=False))
            assert approved(frame("fs_read",path="example.txt"))["content"]=="owner-relay\n"
            local_call(state,"revoke")
            assert stage(frame("fs_read",path="example.txt"))["error"]=="REMOTE_READONLY_DISABLED"
            # Worker rejects a command before ever touching the local agent.
            stream.sendall((json.dumps({"method":"approval_stage","route":frame("admin_command",command="echo forbidden"),"host":host})+"\n").encode())
            assert reader.readline()==b""
            assert child.wait(timeout=5)!=0
            print("PASS: owner relay exact grants, denied/canceled operations, persistent search/patch state, workspace binding, revoke, arbitrary-command rejection; fixture:",repo)
        finally:
            for process in reversed(processes):
                if process.poll() is None:process.terminate()
                try:process.communicate(timeout=5)
                except subprocess.TimeoutExpired:process.kill();process.communicate(timeout=5)
if __name__=="__main__":main(Path(sys.argv[1]).resolve())
