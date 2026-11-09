//! Authenticated tray-to-local-agent client.
//! Never opens a listener or allows the WebView to supply the shared secret.
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream},
    path::Path,
    time::Duration,
};

const MAX_RESPONSE: u64 = 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Runtime {
    version: u32,
    port: u16,
    token: String,
    pid: u32,
}

pub fn request(dir: &Path, method: &str, params: Value) -> Result<Value, String> {
    if !["status", "set_policy", "set_remote_readonly", "revoke", "pair_identity", "pair_list", "pair_create_invite", "pair_prepare_join", "pair_accept_join", "pair_finalize_join", "pair_revoke", "pair_cancel", "approval_list", "approval_decide", "set_admin_command"].contains(&method) {
        return Err("Unsupported local agent operation".into());
    }
    let path = dir.join("local-agent.json");
    let meta = fs::symlink_metadata(&path).map_err(|e| format!("Agent not running: {e}"))?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 4096 {
        return Err("Invalid local agent discovery file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.mode() & 0o077 != 0 || meta.uid() != unsafe { libc::geteuid() } {
            return Err("Insecure local agent discovery permissions".into());
        }
    }
    let runtime: Runtime = serde_json::from_slice(&fs::read(&path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("Invalid local agent discovery: {e}"))?;
    if runtime.version != 1 || runtime.port == 0 || runtime.pid == 0 ||
        runtime.token.len() != 64 || !runtime.token.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err("Invalid local agent credentials".into());
    }
    let socket=SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),runtime.port);
    let mut client=TcpStream::connect_timeout(&socket,Duration::from_millis(700))
        .map_err(|e|format!("Agent not running: {e}"))?;
    client.set_read_timeout(Some(Duration::from_secs(2))).map_err(|e|e.to_string())?;
    client.set_write_timeout(Some(Duration::from_secs(2))).map_err(|e|e.to_string())?;
    let mut req=json!({"token":runtime.token,"method":method});
    let extras=params.as_object().ok_or("Invalid local agent command")?;
    for (k,v) in extras {
        if k=="token" || k=="method" {
            return Err("Reserved local agent argument".into());
        }
        req[k] = v.clone();
    }
    client.write_all(serde_json::to_string(&req).map_err(|e|e.to_string())?.as_bytes())
        .map_err(|e|e.to_string())?;
    client.write_all(b"\n").map_err(|e|e.to_string())?;
    client.flush().map_err(|e|e.to_string())?;
    let mut raw=Vec::new();
    BufReader::new(client).take(MAX_RESPONSE+1)
        .read_until(b'\n',&mut raw).map_err(|e|e.to_string())?;
    if raw.len() as u64 > MAX_RESPONSE {return Err("Agent response too large".into());}
    let reply:Value=serde_json::from_slice(&raw)
        .map_err(|e|format!("Invalid agent response: {e}"))?;
    if let Some(message)=reply.get("error").and_then(Value::as_str) {
        return Err(message.to_string());
    }
    Ok(reply)
}

pub fn is_agent_offline(error: &str) -> bool {
    error.starts_with("Agent not running:")
}
