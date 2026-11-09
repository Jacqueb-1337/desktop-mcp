mod core;
mod elevation;
mod registry;
mod service;
mod pairing;
mod gateway_client;
mod control;
mod route;
mod readonly;
mod windows_acl;
mod unattended;
mod terminal;
mod approval;

use core::Agent;
use serde_json::{json, Value};
use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

fn success(id: &Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn protocol_error(id: &Value, code:i64, message:&str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn tool_result(result: Result<Value, String>) -> Value {
    match result {
        Ok(value) => {
            let is_shim = value.get("status").and_then(Value::as_str)==Some("not_implemented");
            json!({
                "content":[{"type":"text","text":serde_json::to_string_pretty(&value).unwrap_or_default()}],
                "structuredContent":value,
                "isError":is_shim
            })
        }
        Err(message) => json!({
            "content":[{"type":"text","text":message}],
            "isError":true
        })
    }
}

fn process(request:&Value, agent:&mut Agent) -> Option<Value> {
    let method=request.get("method")?.as_str()?;
    if !request.is_object() || request.get("jsonrpc").and_then(Value::as_str)!=Some("2.0") {
        return Some(protocol_error(&Value::Null,-32600,"Invalid JSON-RPC request"));
    }
    let id=match request.get("id") {
        Some(id) => id,
        None => return None, // MCP notifications never receive replies.
    };
    match method {
        "initialize" => {
            let version=request.pointer("/params/protocolVersion").and_then(Value::as_str);
            let chosen=match version {
                Some("2025-06-18") | Some("2025-03-26") | Some("2024-11-05")=>version.unwrap(),
                _=>"2025-06-18"
            };
            Some(success(id,json!({
                "protocolVersion":chosen,
                "capabilities":{"tools":{"listChanged":false}},
                "serverInfo":{"name":"desktop-mcp-agent","version":"0.1.0"}
            })))
        }
        "ping" => Some(success(id,json!({}))),
        "tools/list" => Some(success(id,json!({"tools":registry::definitions()}))),
        "tools/call" => {
            let name=request.pointer("/params/name").and_then(Value::as_str).unwrap_or("");
            if !registry::is_known(name) {
                return Some(protocol_error(id,-32602,"Unknown MCP tool"));
            }
            let args=request.pointer("/params/arguments").cloned()
                .unwrap_or_else(|| json!({}));
            Some(success(id,tool_result(agent.dispatch(name,&args))))
        }
        _ => Some(protocol_error(id,-32601,"Method not found"))
    }
}

fn main() {
    let raw:Vec<_>=env::args_os().skip(1).collect();
    if raw.first().is_some_and(|v|v=="--readonly-status-worker" || v=="--readonly-read-worker") {
        let read=raw[0]=="--readonly-read-worker";
        if raw.len()!=if read {4}else{3} || raw[1]!="--workspace" {std::process::exit(2);}
        let result=PathBuf::from(&raw[2]).canonicalize().map_err(|_|"WORKSPACE_UNAVAILABLE".to_string()).and_then(|root|if read {raw[3].to_str().ok_or("READ_PATH_ENCODING".to_string()).and_then(|path|readonly::read_worker(&root,path))}else{readonly::status_worker(&root)});
        println!("{}",match result {Ok(data)=>json!({"data":data}),Err(error)=>json!({"error":error})});return;
    }

    let mut args=env::args().skip(1);
    let mut workspace:Option<PathBuf>=None;
    let mut allow_writes=false;
    let mut serve_local=false;
    let mut remote_readonly=false;
    let mut require_pairing_consent=false;
    let mut enable_admin_diagnostics=false;
    let mut enable_admin_commands=false;
    let mut system_mode=false;
    let mut machine_host_id=false;
    let mut local_request:Option<String>=None;
    let mut state_dir:Option<PathBuf>=None;
    let mut pair_payload:Option<PathBuf>=None;
    let mut pair_name:Option<String>=None;
    let mut gateway_action:Option<String>=None;
    let mut gateway_address:Option<String>=None;
    let mut gateway_tls_name:Option<String>=None;
    let mut gateway_ca:Option<PathBuf>=None;
    while let Some(arg)=args.next() {
        match arg.as_str() {
            "--workspace" => workspace=args.next().map(PathBuf::from),
            "--allow-writes" => allow_writes=true,
            "--serve-local" => serve_local=true,
            "--allow-remote-readonly" => remote_readonly=true,
            "--require-pairing-consent" => require_pairing_consent=true,
            "--enable-admin-diagnostics" => enable_admin_diagnostics=true,
            "--enable-admin-commands" => enable_admin_commands=true,
            "--system-mode" => system_mode=true,
            "--machine-host-id" => machine_host_id=true,
            "--local-status" => local_request=Some("status".into()),
            "--local-revoke" => local_request=Some("revoke".into()),
            "--state-dir" => state_dir=args.next().map(PathBuf::from),
            "--pair-action" => local_request=args.next(),
            "--pair-payload-file" => pair_payload=args.next().map(PathBuf::from),
            "--pair-name" => pair_name=args.next(),
            "--gateway-probe" => gateway_action=Some("probe".into()),
            "--gateway-connect" => gateway_action=Some("connect".into()),
            "--gateway-address" => gateway_address=args.next(),
            "--gateway-tls-name" => gateway_tls_name=args.next(),
            "--gateway-ca" => gateway_ca=args.next().map(PathBuf::from),
            "--version" => {
                eprintln!("desktop-mcp-agent 0.1.0");
                return;
            }
            _ => {
                eprintln!("Unknown argument: {arg}. Usage: desktop-mcp-agent --serve-local --state-dir <directory> or --workspace <git-repo>");
                std::process::exit(2);
            }
        }
    }
    if machine_host_id {
        let Some(dir)=state_dir.as_deref() else {eprintln!("STATE_DIR_REQUIRED");std::process::exit(2)};
        if let Err(error)=unattended::verify_machine_identity_path(dir) {
            eprintln!("MACHINE_IDENTITY_DENIED: {error}");std::process::exit(2);
        }
        match pairing::Pairing::open(dir) {
            Ok(identity)=>{
                let info=identity.identity();
                println!("{}",info["host_id"].as_str().unwrap_or(""));
                return;
            }
            Err(error)=>{eprintln!("{error}");std::process::exit(2)}
        }
    }
    if system_mode && (!serve_local || gateway_action.is_some() || local_request.is_some()) {
        eprintln!("SYSTEM_MODE_REQUIRES_SERVICE_ONLY");
        std::process::exit(2);
    }
    if let Some(action)=gateway_action {
        if local_request.is_some() || serve_local || allow_writes {
            eprintln!("GATEWAY_MODE_MUST_BE_INDEPENDENT");
            std::process::exit(2);
        }
        let (Some(dir),Some(address),Some(tls_name),Some(ca)) =
            (state_dir.as_deref(),gateway_address.as_deref(),gateway_tls_name.as_deref(),gateway_ca.as_deref())
        else {eprintln!("GATEWAY_REQUIRES_STATE_DIR_ADDRESS_TLS_NAME_CA");std::process::exit(2)};
        let target=gateway_client::GatewayTarget {
            state_dir:dir,address,server_name:tls_name,trusted_ca:ca
        };
        if action=="probe" {
            match gateway_client::connect(&target,true) {
                Ok(result)=>println!("{}",serde_json::to_string_pretty(&result).unwrap_or_default()),
                Err(error)=>{eprintln!("GATEWAY_CONNECT_FAILED: {error}");std::process::exit(1)}
            }
            return;
        }
        gateway_client::reconnect_forever(&target);
    }
    if let Some(method)=local_request {
        let Some(dir)=state_dir else {eprintln!("STATE_DIR_REQUIRED");std::process::exit(2)};
        let params: Value = if let Some(path)=pair_payload {
            match std::fs::read(&path).ok().and_then(|b|serde_json::from_slice(&b).ok()) {
                Some(v)=>v, None=>{eprintln!("INVALID_PAIR_PAYLOAD_FILE");std::process::exit(2)}
            }
        } else {json!({})};
        let mut extra=json!({});
        match method.as_str() {
            "pair_prepare_join" => {
                extra["invitation"] = params.get("invitation").cloned().unwrap_or(params);
                extra["name"]=json!(pair_name.unwrap_or_default());
            }
            "pair_accept_join" => extra["join_request"]=params.get("join_request").cloned().unwrap_or(params),
            "pair_finalize_join" => {
                extra["receipt"]=params.get("receipt").cloned().unwrap_or(params);
                extra["name"]=json!(pair_name.unwrap_or_default());
            }
            "pair_revoke" => extra["host_id"]=json!(pair_name.unwrap_or_default()),
            _ => {}
        }
        match service::request(&dir,&method,extra) {
            Ok(v)=>println!("{}",serde_json::to_string_pretty(&v).unwrap_or_default()),
            Err(e)=>{eprintln!("{e}");std::process::exit(1)}
        }
        return;
    }
    let workspace=workspace.or_else(||env::var_os("DESKTOP_MCP_WORKSPACE_ROOT").map(PathBuf::from));
    // Standalone local service can start without selecting or creating any project.
    // Legacy explicit-workspace CLI still enforces Git-root validation.
    let mut agent=match (workspace, serve_local, state_dir.as_deref()) {
        (Some(root), _, _) => Agent::new(&root, allow_writes),
        (None, true, Some(dir)) => Agent::new_desktop(dir),
        _ => Err("WORKSPACE_REQUIRED_FOR_STDIO_OR_STATE_REQUIRED_FOR_SERVICE".into()),
    }.unwrap_or_else(|e| {eprintln!("{e}"); std::process::exit(2)});
    if serve_local {
        let Some(dir)=state_dir else {eprintln!("STATE_DIR_REQUIRED");std::process::exit(2)};
        if system_mode {
            if let Err(e)=unattended::verify_system_state(&dir) {
                eprintln!("SYSTEM_STARTUP_REJECTED: {e}");std::process::exit(2);
            }
        }
        if let Err(e)=service::serve(&mut agent,&dir,allow_writes,remote_readonly,require_pairing_consent,enable_admin_diagnostics,enable_admin_commands,system_mode) {
            eprintln!("LOCAL_AGENT_ERROR: {e}"); std::process::exit(1);
        }
        return;
    }
    eprintln!("Desktop MCP stdio agent started; workspace={}; writes={allow_writes}; network=false",
              agent.root().display());
    let stdin=io::stdin();
    let mut stdout=io::stdout().lock();
    for line in stdin.lock().lines() {
        let line=match line {Ok(s)=>s, Err(e)=>{eprintln!("STDIO_ERROR: {e}");break;}};
        if line.trim().is_empty() {continue;}
        let parsed:Result<Value,_>=serde_json::from_str(&line);
        let reply=match parsed {
            Ok(ref value)=>process(value,&mut agent),
            Err(_)=>Some(protocol_error(&Value::Null,-32700,"Parse error"))
        };
        if let Some(result)=reply {
            match serde_json::to_string(&result) {
                Ok(out)=>{
                    if writeln!(stdout,"{out}").is_err() || stdout.flush().is_err() {
                        break;
                    }
                }
                Err(e)=>{eprintln!("SERIALIZE_ERROR: {e}");break;}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn protocol_reply_can_be_serialized() {
        let value=success(&json!(7),json!({"ok":true}));
        assert_eq!(value["id"],7);
        assert_eq!(value["result"]["ok"],true);
    }
    #[test]
    fn shim_has_is_error() {
        let t=tool_result(Ok(json!({"status":"not_implemented"})));
        assert_eq!(t["isError"],true);
    }
}
