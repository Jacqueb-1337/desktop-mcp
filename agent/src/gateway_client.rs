//! Agent-initiated TLS presence registration. No remote MCP calls are accepted.
use crate::pairing::Pairing;
use sha2::Digest;
use crate::control;
use crate::route;
use crate::service;
use rustls::{pki_types::ServerName, ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufReader, Read, Write},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    sync::Arc,
    thread,
    time::Duration,
};

const FRAME_LIMIT: usize = 128*1024;

fn recv_json(stream: &mut impl Read) -> Result<Value, String> {
    let mut line = Vec::new();
    for _ in 0..FRAME_LIMIT {
        let mut byte = [0u8];
        stream.read_exact(&mut byte).map_err(|e|format!("GATEWAY_READ: {e}"))?;
        if byte[0] == b'\n' {
            return serde_json::from_slice(&line).map_err(|_|"GATEWAY_INVALID_JSON".into());
        }
        line.push(byte[0]);
    }
    Err("GATEWAY_FRAME_TOO_LARGE".into())
}

fn send_json(stream: &mut impl Write, frame: &Value) -> Result<(), String> {
    let mut data=serde_json::to_vec(frame).map_err(|e|e.to_string())?;
    if data.len()>=FRAME_LIMIT {return Err("GATEWAY_FRAME_TOO_LARGE".into())}
    data.push(b'\n');
    stream.write_all(&data).map_err(|e|e.to_string())?;
    stream.flush().map_err(|e|e.to_string())
}

fn gateway_roots(ca_path: &Path) -> Result<RootCertStore, String> {
    let metadata=fs::symlink_metadata(ca_path).map_err(|e|e.to_string())?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len()>65536 {
        return Err("GATEWAY_CA_FILE_INVALID".into());
    }
    let data=fs::read(ca_path).map_err(|e|e.to_string())?;
    let certificates = rustls_pemfile::certs(&mut BufReader::new(data.as_slice()))
        .collect::<Result<Vec<_>,_>>().map_err(|e|e.to_string())?;
    if certificates.len()!=1 {
        return Err("GATEWAY_REQUIRES_EXACTLY_ONE_TRUST_ANCHOR".into());
    }
    let mut roots=RootCertStore::empty();
    roots.add(certificates[0].clone()).map_err(|e|format!("INVALID_GATEWAY_CA: {e}"))?;
    Ok(roots)
}

pub struct GatewayTarget<'a> {
    pub address: &'a str,
    pub server_name: &'a str,
    pub trusted_ca: &'a Path,
    pub state_dir: &'a Path,
}

fn check_identity_directory(dir: &Path) -> Result<(), String> {
    let meta=fs::symlink_metadata(dir).map_err(|_|"GATEWAY_STATE_DIR_MISSING".to_string())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("GATEWAY_STATE_DIR_UNSAFE".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if meta.permissions().mode()&0o077!=0 || meta.uid()!=unsafe{libc::geteuid()} {
            return Err("GATEWAY_STATE_DIR_INSECURE_PERMISSIONS".into());
        }
    }
    Ok(())
}

pub fn connect(target: &GatewayTarget<'_>, probe: bool) -> Result<Value, String> {
    check_identity_directory(target.state_dir)?;
    let pairing=Pairing::open(target.state_dir)?;
    let roots=gateway_roots(target.trusted_ca)?;
    let mut config=ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols=vec![b"desktop-mcp-presence/1".to_vec()];
    let hostname=ServerName::try_from(target.server_name.to_owned())
        .map_err(|_|"INVALID_GATEWAY_TLS_HOSTNAME")?;
    let config=Arc::new(config);
    let mut endpoint=None;
    let mut last_error="GATEWAY_UNREACHABLE".to_string();
    for address in target.address.to_socket_addrs().map_err(|e|format!("INVALID_GATEWAY_ADDRESS: {e}"))? {
        let attempt=(|| {
            let socket=TcpStream::connect_timeout(&address,Duration::from_secs(4))
                .map_err(|e|format!("GATEWAY_CONNECT_FAILED: {e}"))?;
            socket.set_read_timeout(Some(Duration::from_secs(12))).map_err(|e|e.to_string())?;
            socket.set_write_timeout(Some(Duration::from_secs(12))).map_err(|e|e.to_string())?;
            let connection=ClientConnection::new(config.clone(),hostname.clone()).map_err(|e|e.to_string())?;
            let mut tls=StreamOwned::new(connection,socket);
            let challenge=recv_json(&mut tls)?;
            if challenge["type"]!="challenge" || challenge["version"]!=1 || !challenge["nonce"].is_string() {
                return Err("UNEXPECTED_GATEWAY_CHALLENGE".into());
            }
            Ok((tls,challenge))
        })();
        match attempt {
            Ok(verified)=>{endpoint=Some(verified);break;}
            Err(error)=>last_error=error,
        }
    }
    let (mut tls,challenge)=endpoint.ok_or(last_error)?;
    let nonce=challenge.get("nonce").and_then(Value::as_str).ok_or("GATEWAY_NONCE_MISSING")?;
    let mut auth=pairing.sign_gateway_challenge(nonce)?;
    // This feature only allows a fixed presence response, never tool execution.
    auth["features"]=control::advertised_features();
    send_json(&mut tls,&auth)?;
    let reply=recv_json(&mut tls)?;
    if reply.get("type").and_then(Value::as_str)!=Some("accepted")
        || reply.get("version").and_then(Value::as_u64)!=Some(1)
        || reply.get("host_id")!=auth.get("host_id")
        || reply.get("remote_tools_enabled")!=Some(&Value::Bool(false))
        || reply.get("authorization").and_then(Value::as_str)!=Some("identity_only") {
        return Err(format!("GATEWAY_AUTH_FAILED: {}",reply.get("reason").and_then(Value::as_str).unwrap_or("UNEXPECTED_REPLY")));
    }
    // Older gateways omit the feature. Reject unexpected feature negotiation.
    let (probe_enabled,route_enabled,exec_enabled)=match reply.get("features") {
        None=>(false,false,false),
        Some(features) if *features==json!([control::FEATURE])=>(true,false,false),
        Some(features) if *features==json!([control::FEATURE,route::FEATURE])=>(true,true,false),
        Some(features) if *features==control::advertised_features()=>(true,false,true),
        _=>return Err("GATEWAY_UNSUPPORTED_CONTROL_FEATURES".into()),
    };
    if probe_enabled {
        let request=recv_json(&mut tls)?;
        let host_id=auth.get("host_id").and_then(Value::as_str).ok_or("HOST_ID_MISSING")?;
        let answer=control::probe_response(&request,host_id)?;
        send_json(&mut tls,&answer)?;
        let ack=recv_json(&mut tls)?;
        control::verify_ack(&ack,request.get("nonce").and_then(Value::as_str).unwrap_or(""))?;
    }
if route_enabled {
        let incoming=recv_json(&mut tls)?;
        let host_id=auth.get("host_id").and_then(Value::as_str).ok_or("HOST_ID_MISSING")?;
        let denied=route::deny(&incoming,host_id)?;
        // Review is staged only through the authenticated loopback agent.
        // Missing/offline local service fails closed and never unlocks tools.
        match service::request(target.state_dir,"approval_stage",json!({"route":incoming})) {
            Ok(ack) if ack.get("queued")==Some(&Value::Bool(true)) => {},
            Ok(_) => eprintln!("Local approval staging returned no confirmation"),
            Err(reason) => eprintln!("Local approval unavailable: {reason}"),
        }
        send_json(&mut tls,&denied)?;
    }
    eprintln!("Authenticated TLS gateway presence: identity_only, remote_tools_enabled=false");
    loop {
        send_json(&mut tls,&json!({"type":"heartbeat","version":1}))?;
        let ack=recv_json(&mut tls)?;
        if ack.get("type").and_then(Value::as_str)!=Some("heartbeat_ack")
            || ack.get("remote_tools_enabled")!=Some(&Value::Bool(false)) {
            return Err("GATEWAY_HEARTBEAT_REJECTED".into());
        }
        if let Some(frame)=ack.get("route") {
            if !exec_enabled {return Err("EXECUTABLE_ROUTE_NOT_NEGOTIATED".into());}
            let outcome = scoped_route(&mut tls,target.state_dir,frame,auth["host_id"].as_str().ok_or("HOST_REQUIRED")?);
            if frame["tool"].as_str().is_some_and(crate::elevation::is_privileged) {
                let _ = service::request(target.state_dir, "approval_cancel", json!({"route":frame}));
            }
            outcome?;
        }
        if probe {
            return Ok(json!({
                "status":"authenticated",
                "host_id":auth["host_id"],
                "tls_verified":true,
                "remote_tools_enabled":false,
                "authorization":"identity_only",
                "control_probe_verified":probe_enabled,
                "route_denial_sent":route_enabled
            }));
        }
        thread::sleep(Duration::from_secs(4));
    }
}

fn scoped_route(tls:&mut (impl Read + Write),state:&Path,frame:&Value,host:&str)->Result<(),String> {
    route::deny(frame,host)?;
    if frame["version"]!=2 {return Err("EXECUTABLE_ROUTE_REQUIRED".into());}
    let hash=hex::encode(sha2::Sha256::digest(serde_json::to_vec(frame).map_err(|_|"ROUTE_ENCODE")?));
    let stage = service::request(state, "approval_stage", json!({"route":frame}));
    if !stage.as_ref().is_ok_and(|reply| reply["queued"] == true) {
        let reason = match stage.as_ref().err().map(String::as_str) {
            Some("LOCAL_PERMISSION_REQUIRED") => "LOCAL_PERMISSION_REQUIRED",
            Some("PERMISSION_REQUESTS_DISABLED") => "PERMISSION_REQUESTS_DISABLED",
            Some("REMOTE_READONLY_DISABLED") => "REMOTE_READONLY_DISABLED",
            Some("ADMIN_HELPER_UNAVAILABLE") => "ADMIN_HELPER_UNAVAILABLE",
            _ => "LOCAL_APPROVAL_UNAVAILABLE",
        };
        return send_json(tls, &json!({"type":"route_rejected","version":2,"request_id":frame["request_id"],"request_hash":hash,"error":reason}));
    }
    send_json(tls,&json!({"type":"route_staged","version":2,"request_id":frame["request_id"],"request_hash":hash}))?;
    loop {
        let poll=recv_json(tls)?;
        if poll!=json!({"type":"route_poll","version":2,"request_hash":hash}) {return Err("ROUTE_POLL_MISMATCH".into());}
        let outcome=service::request(state,"approval_execute",json!({"route":frame})).unwrap_or_else(|_|json!({"pending":false,"executed":false,"error":"LOCAL_AGENT_UNAVAILABLE"}));
        if outcome["pending"]==true {
            send_json(tls,&json!({"type":"route_pending","version":2,"request_hash":hash}))?;
        }else {
            send_json(tls,&json!({"type":"route_result","version":2,"request_id":frame["request_id"],"target_host_id":host,"nonce":frame["nonce"],"request_hash":hash,"outcome":outcome}))?;
            return Ok(());
        }
    }
}

pub fn reconnect_forever(target: &GatewayTarget<'_>) -> ! {
    let mut delay=1;
    loop {
        match connect(target,false) {
            Ok(_)=>{},
            Err(e)=>eprintln!("Gateway presence disconnected: {e}"),
        }
        thread::sleep(Duration::from_secs(delay));
        delay=(delay*2).min(30);
    }
}
