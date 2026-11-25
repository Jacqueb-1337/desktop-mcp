#!/usr/bin/env python3
"""Exercise a finite, explicitly approved Task Scheduler launch on Windows.
The disposable test task has no automatic triggers and is removed in finally.
No production state, permissions, or installed binaries are modified.
"""
import contextlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import uuid
from smoke_gateway import setup_agent
from smoke_approval import local_call

def main(agent):
    if os.name!="nt":raise SystemExit("Windows only")
    with contextlib.ExitStack() as stack:
        root=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="dmcp-detached-test-",dir=Path.home())))
        share=os.environ.get("DMCP_SMOKE_REPO_PARENT")
        parent=Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="dmcp-detached-test-",dir=share))) if share else None
        state,repo,identity=setup_agent(agent,root,repo_parent=parent)
        (state/"selected-repository.txt").write_text(str(repo.resolve()),encoding="utf-8")
        (state/"remote-readonly.enabled").write_bytes(b"enabled\n")
        host=identity["host_id"]
        proc=subprocess.Popen([str(agent),"--state-dir",str(state),"--serve-local","--allow-remote-readonly","--require-pairing-consent"],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        def frame(tool,**args):
            return {"type":"route_intent","version":2,"request_id":str(uuid.uuid4()),"target_host_id":host,
                    "workspace_id":"default","tool":tool,"nonce":secrets.token_hex(32),"arguments":args,"expires_at":int(time.time())+90}
        launch=frame("process_spawn_detached",command="Set-Content -LiteralPath './detached-started.txt' -Value $PID; Start-Sleep -Seconds 5; Set-Content -LiteralPath './detached-finished.txt' -Value 'done'",working_directory=str(repo))
        task=r"\DesktopMCP-Detached-"+launch["request_id"]
        denied=frame("process_spawn_detached",command="Write-Output 'never executed'")
        denied_task=r"\DesktopMCP-Detached-"+denied["request_id"]
        def approve(route,decision="approve"):
            item=next(i for i in local_call(state,"approval_list")["pending"] if i["request_id"]==route["request_id"])
            result=local_call(state,"approval_decide",request_id=item["request_id"],nonce=item["nonce"],request_hash=item["request_hash"],decision=decision)
            assert result.get("authorization_granted")== (decision=="approve"),result
        def approved(route):
            assert local_call(state,"approval_stage",route=route).get("queued"),route
            assert local_call(state,"approval_execute",route=route)=={"pending":True}
            approve(route)
            result=local_call(state,"approval_execute",route=route)
            assert result.get("executed") and not result.get("error"),result
            return result["data"]
        def query(name):
            return subprocess.run(["schtasks.exe","/Query","/TN",name,"/XML"],capture_output=True,text=True)
        try:
            for _ in range(120):
                if proc.poll() is not None:raise AssertionError(proc.stderr.read())
                try:
                    if local_call(state,"status").get("repository_relay_ready"):break
                except (OSError,ValueError):pass
                time.sleep(.05)
            else:raise AssertionError("Fixture agent unavailable")
            assert not local_call(state,"approval_stage",route=launch).get("queued")
            for cap in ("pairing","process_spawn_detached"):
                assert approved(frame("request_permission",capability=cap,duration="10m"))["granted"]
            assert local_call(state,"approval_stage",route=denied)["queued"]
            approve(denied,"deny")
            assert not local_call(state,"approval_execute",route=denied)["executed"]
            assert query(denied_task).returncode!=0
            result=approved(launch)
            print("Task Scheduler returned:",result,flush=True)
            assert result["task_name"]==task and result["unmanaged_by_mcp"]
            assert not local_call(state,"approval_execute",route=launch)["executed"],"Replay permitted"
            import xml.etree.ElementTree as ET
            definition=query(task)
            assert definition.returncode==0,definition.stderr
            node=ET.fromstring(definition.stdout.lstrip("\ufeff"))
            ns={"t":"http://schemas.microsoft.com/windows/2004/02/mit/task"}
            triggers=node.find("t:Triggers",ns)
            assert triggers is None or not list(triggers)
            assert node.findtext(".//t:RunLevel",namespaces=ns) in (None,"LeastPrivilege")
            assert node.findtext(".//t:ExecutionTimeLimit",namespaces=ns)=="PT0S"
            start=repo/"detached-started.txt";finish=repo/"detached-finished.txt"
            for _ in range(100):
                if start.exists():break
                time.sleep(.05)
            else:raise AssertionError("Task never wrote start marker")
            actual_pid=int(start.read_text().strip())
            assert actual_pid>0 and not finish.exists()
            local_call(state,"revoke")
            proc.terminate();proc.communicate(timeout=5)
            assert not finish.exists(),"Task ended before agent shutdown"
            for _ in range(200):
                if finish.exists():break
                time.sleep(.05)
            else:raise AssertionError("Detached task did not survive agent shutdown")
            assert finish.read_text().strip()=="done"
            print("PASS: detached task PID",actual_pid,"survived MCP revoke and process shutdown on",repo,flush=True)
        finally:
            if proc.poll() is None:proc.terminate();proc.communicate(timeout=5)
            for name in (task,denied_task):
                subprocess.run(["schtasks.exe","/End","/TN",name],capture_output=True)
                subprocess.run(["schtasks.exe","/Delete","/TN",name,"/F"],capture_output=True)
                assert query(name).returncode!=0,("Fixture task cleanup failed",name)
if __name__=="__main__":main(Path(sys.argv[1]).resolve())
