#!/usr/bin/env python3
"""Real HTTPS ingress regression; isolated keys and no production exposure."""
import hashlib
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
from smoke_gateway import make_certs

VERSION = "2026-07-28"
def request(method="tools/list", **params):
    return {"jsonrpc":"2.0", "id":1, "method":method, "params":{
        "_meta":{"io.modelcontextprotocol/protocolVersion":VERSION,
                 "io.modelcontextprotocol/clientCapabilities":{}}, **params}}

def main(gateway):
    with tempfile.TemporaryDirectory(prefix="desktop-mcp-ingress-", dir=Path.home() if os.name=="nt" else None) as tmp:
        root=Path(tmp); ca,cert,key=make_certs(root)
        allowed=root/"allowed.json"; allowed.write_text('{"version":1,"hosts":[]}')
        policy=root/"policy.json";policy.write_text('{"version":1,"hosts":[]}')
        audit=root/"audit";audit.mkdir(mode=0o700)
        token=secrets.token_hex(32); token_file=root/"token";token_file.write_text(token);token_file.chmod(0o600)
        with socket.socket() as s:
            s.bind(("127.0.0.1",0)); port=s.getsockname()[1]
        proc=subprocess.Popen([str(gateway),"--cert",str(cert),"--key",str(key),"--allowlist",str(allowed),
             "--policy",str(policy),"--audit-dir",str(audit),"--mcp-listen",f"127.0.0.1:{port}","--mcp-authority",f"127.0.0.1:{port}","--mcp-token-file",str(token_file)],
             stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            assert proc.stdout.readline().startswith("LISTENING ")
            context=ssl.create_default_context(cafile=str(ca))
            def call(payload, auth=token, extra=None):
                connection=http.client.HTTPSConnection("localhost",port,context=context,timeout=5)
                headers={"Host":f"127.0.0.1:{port}","Content-Type":"application/json","Accept":"application/json, text/event-stream",
                    "MCP-Protocol-Version":VERSION,"Mcp-Method":payload.get("method","")}
                if auth: headers["Authorization"]="Bearer "+auth
                if payload.get("method")=="tools/call":headers["Mcp-Name"]=payload["params"]["name"]
                headers.update(extra or {})
                connection.request("POST","/mcp",json.dumps(payload),headers)
                response=connection.getresponse();data=response.read();connection.close()
                return response.status,json.loads(data) if data else None
            assert call(request(),auth=None)[0]==401
            assert call(request(),auth="00"*32)[0]==401
            assert call(request(),extra={"Origin":"https://attacker.invalid"})[0]==403
            status,body=call(request("server/discover"));assert status==200 and VERSION in body["result"]["supportedVersions"]
            status,body=call(request());assert status==200 and "git_status" in [t["name"] for t in body["result"]["tools"]]
            key="d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
            host=hashlib.sha256(bytes.fromhex(key)).hexdigest()[:32]
            pair=request("tools/call",name="pair_device",arguments={"code":"DM1-"+key})
            assert call(pair,auth=None)[0]==401
            status,body=call(pair)
            assert status==200 and body["result"]["structuredContent"]["host_id"]==host
            status,body=call(request("tools/call",name="list_projects",arguments={}))
            projects=body["result"]["structuredContent"]["projects"]
            assert projects==[{"host_id":host,"workspace_id":"default","tools":["request_permission","admin_command"],"connected":False}]
            assert call(request(),extra={"Mcp-Method":"tools/call"})[1]["error"]["code"]==-32020
            assert call(request("tools/call",name="shell",arguments={}))[1]["error"]["code"]==-32602
            status,body=call(request("tools/call",name="git_status",arguments={"host_id":"ab"*16,"workspace_id":"default"}))
            assert status==200 and body["result"]["isError"] is True
            init={"jsonrpc":"2.0","id":5,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}
            assert call(init,auth=None)[0]==401
            status,body=call(init);assert status==200 and body["result"]["protocolVersion"]=="2025-11-25"
            status,body=call({"jsonrpc":"2.0","id":6,"method":"tools/list"},extra={"MCP-Protocol-Version":"2025-11-25"});assert status==200 and {"pair_device","request_permission","admin_command"} <= {tool["name"] for tool in body["result"]["tools"]}
            assert call({"jsonrpc":"2.0","method":"notifications/initialized"},extra={"MCP-Protocol-Version":"2025-11-25"})[0]==202
            bridge=Path(__file__).with_name("tunnel_stdio.py")
            bridge_requests=[init,{"jsonrpc":"2.0","method":"notifications/initialized"},{"jsonrpc":"2.0","id":6,"method":"tools/list"},request("server/discover")]
            stdio=subprocess.run([sys.executable,str(bridge),"--ca",str(ca),"--token-file",str(token_file),"--port",str(port)],input="".join(json.dumps(r)+"\n" for r in bridge_requests),capture_output=True,text=True,check=True,timeout=15)
            replies=[json.loads(line) for line in stdio.stdout.splitlines()]
            assert len(replies)==3 and replies[0]["result"]["protocolVersion"]=="2025-11-25"
            assert replies[1]["result"]["tools"] and VERSION in replies[2]["result"]["supportedVersions"]
            # Insecure credential files must fail startup, never fall back to open access.
            unsafe=root/"unsafe-token";unsafe.write_text(token)
            if os.name=="nt":subprocess.run(["icacls",str(unsafe),"/grant","*S-1-1-0:R"],capture_output=True,check=True)
            else:unsafe.chmod(0o644)
            args=list(proc.args);args[args.index("--mcp-token-file")+1]=str(unsafe)
            denied=subprocess.run(args,capture_output=True,text=True,timeout=15)
            assert denied.returncode!=0 and ("WINDOWS_PRIVATE_ACL_REQUIRED" in denied.stderr or "TOKEN_PERMISSIONS" in denied.stderr),denied.stderr
            print("PASS: real HTTPS auth, discovery, origin, header validation, safe tool errors")
        finally:
            proc.terminate();proc.communicate(timeout=5)
if __name__=="__main__":main(Path(sys.argv[1]).resolve())
