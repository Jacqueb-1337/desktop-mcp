"""Compare end-to-end approval-bound small remote operations on an isolated repo."""
import concurrent.futures
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import time
from smoke_gateway import setup_agent, make_certs
from smoke_approval import restart_local_service, local_call
from smoke_execution import approve
from smoke_mcp import request, VERSION

def main(agent,gateway):
    with tempfile.TemporaryDirectory(prefix="desktop-mcp-latency-",dir=Path.home() if os.name=="nt" else None) as tmp:
        root=Path(tmp);state,repo,identity=setup_agent(agent,root)
        ca,cert,key=make_certs(root)
        allowed=root/"allowlist.json";allowed.write_text(json.dumps({"version":1,"hosts":[{"host_id":identity["host_id"],"public_key":identity["public_key"]}]}))
        policy=root/"policy.json";policy.write_text(json.dumps({"version":1,"hosts":[{"host_id":identity["host_id"],"workspace_id":"default","tools":["git_status","fs_read","fs_search"]}]}))
        audit=root/"audit";audit.mkdir(mode=0o700)
        token=secrets.token_hex(32);token_path=root/"token";token_path.write_text(token);token_path.chmod(0o600)
        with socket.socket() as sock:sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        procs=[]
        pool=concurrent.futures.ThreadPoolExecutor(1)
        try:
            service,_=restart_local_service(subprocess.Popen([sys.executable,"-c","pass"]),agent,repo,state,True)
            procs.append(service)
            gw=subprocess.Popen([str(gateway),"--cert",str(cert),"--key",str(key),"--allowlist",str(allowed),"--policy",str(policy),"--audit-dir",str(audit),"--mcp-listen",f"127.0.0.1:{port}","--mcp-authority",f"localhost:{port}","--mcp-token-file",str(token_path)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True);procs.append(gw)
            address=gw.stdout.readline().split()[1]
            presence=subprocess.Popen([str(agent),"--state-dir",str(state),"--gateway-connect","--gateway-address",address,"--gateway-tls-name","localhost","--gateway-ca",str(ca)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True);procs.append(presence)
            assert gw.stdout.readline().startswith("ENROLLED_SESSION ")
            assert gw.stdout.readline().startswith("CONTROL_PROBE_OK ")
            ctx=ssl.create_default_context(cafile=str(ca))
            def call(tool,**args):
                payload=request("tools/call",name=tool,arguments={"host_id":identity["host_id"],"workspace_id":"default",**args})
                c=http.client.HTTPSConnection("127.0.0.1",port,context=ctx,timeout=20)
                try:
                    c.request("POST","/mcp",json.dumps(payload),{"Host":f"localhost:{port}","Authorization":"Bearer "+token,"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":VERSION,"Mcp-Method":"tools/call","Mcp-Name":tool})
                    resp=c.getresponse();body=json.loads(resp.read())
                    assert resp.status==200 and not body["result"]["isError"],body
                    return body
                finally:c.close()
            def sample(tool,args):
                t=time.perf_counter()
                f=pool.submit(call,tool,**args)
                deadline=t+10
                while time.perf_counter()<deadline:
                    items=local_call(state,"approval_list")["pending"]
                    if items:break
                    time.sleep(.005)
                else:raise AssertionError("approval missing")
                approve(state,items[0])
                accepted=time.perf_counter()
                f.result(timeout=20)
                end=time.perf_counter()
                return (round((end-t)*1000,2),round((end-accepted)*1000,2))
            for tool,args in [("git_status",{}),("fs_read",{"path":"example.txt"}),("fs_search",{"query":{"mode":"paths","pattern":"example.txt","engine":"native"}})]:
                sample(tool,args)
                samples=[sample(tool,args) for _ in range(5)]
                print(json.dumps({"tool":tool,"total_median_ms":round(statistics.median(a for a,b in samples),2),"after_approval_median_ms":round(statistics.median(b for a,b in samples),2),"samples":samples}),flush=True)
        finally:
            for p in reversed(procs):
                if p.poll() is None:p.terminate()
                try:p.communicate(timeout=5)
                except subprocess.TimeoutExpired:p.kill();p.communicate(timeout=5)
            pool.shutdown(wait=False,cancel_futures=True)
if __name__=="__main__":main(Path(sys.argv[1]).resolve(),Path(sys.argv[2]).resolve())
