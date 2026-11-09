mod policy;
mod control;
mod route;
mod audit;
mod mcp;
mod broker;
mod windows_acl;
// Identity-only TLS gateway. This intentionally has NO MCP tool execution,
// file access, arbitrary command routing or ChatGPT-facing endpoint.
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use rustls::{pki_types::PrivateKeyDer, ServerConfig, ServerConnection, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::{self, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

const FRAME_LIMIT: usize = 128*1024;
const MAX_SESSIONS: usize = 16;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AllowedHost {
    host_id: String,
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Allowlist {
    version: u32,
    hosts: Vec<AllowedHost>,
}

#[derive(Serialize, Clone)]
struct Session {
    host_id: String,
    connected_seconds: u64,
    remote_tools_enabled: bool,
}

type Sessions = Arc<Mutex<HashMap<String, Session>>>;

#[derive(Clone)]
struct RouteJob {
    policy: policy::PolicyFile,
    intent: policy::Intent,
    audit: Arc<Mutex<audit::Audit>>,
}

fn framed(domain: &[u8], fields: &[&str]) -> Vec<u8> {
    let mut data = domain.to_vec();
    for field in fields {
        data.extend_from_slice(&(field.len() as u32).to_be_bytes());
        data.extend_from_slice(field.as_bytes());
    }
    data
}

fn host_fingerprint(public_key: &[u8; 32]) -> String {
    let hash = Sha256::digest(public_key);
    hex::encode(&hash[..16])
}

fn read_json(stream: &mut impl Read) -> Result<Value, String> {
    let mut line = Vec::new();
    let started=Instant::now();
    for _ in 0..FRAME_LIMIT {
        if started.elapsed()>Duration::from_secs(10){return Err("FRAME_DEADLINE".into());}
        let mut byte = [0u8];
        stream.read_exact(&mut byte).map_err(|e| format!("FRAME_READ_FAILED: {e}"))?;
        if byte[0] == b'\n' {
            return serde_json::from_slice(&line).map_err(|_| "FRAME_INVALID_JSON".into());
        }
        line.push(byte[0]);
    }
    Err("FRAME_LIMIT_EXCEEDED".into())
}

fn send_json(stream: &mut impl Write, object: &Value) -> Result<(), String> {
    let mut payload = serde_json::to_vec(object).map_err(|e| e.to_string())?;
    if payload.len() >= FRAME_LIMIT {
        return Err("FRAME_LIMIT_EXCEEDED".into());
    }
    payload.push(b'\n');
    stream.write_all(&payload).map_err(|e| format!("FRAME_WRITE_FAILED: {e}"))?;
    stream.flush().map_err(|e| e.to_string())
}

fn secure_file(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 256 * 1024 {
        return Err("UNSAFE_OR_OVERSIZE_GATEWAY_FILE".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if meta.permissions().mode() & 0o022 != 0 {
            return Err("INSECURE_WRITABLE_GATEWAY_FILE".into());
        }
    }
    fs::read(path).map_err(|e| e.to_string())
}

fn load_allowlist(path: &Path) -> Result<HashMap<String, String>, String> {
    let bytes = secure_file(path)?;
    let list: Allowlist =
        serde_json::from_slice(&bytes).map_err(|e| format!("INVALID_ALLOWLIST: {e}"))?;
    if list.version != 1 || list.hosts.len() > 256 {
        return Err("INVALID_ALLOWLIST_VERSION_OR_SIZE".into());
    }
    let mut permitted = HashMap::new();
    for item in list.hosts {
        let decoded: [u8; 32] = hex::decode(&item.public_key)
            .map_err(|_| "INVALID_ALLOWED_PUBLIC_KEY".to_string())?
            .try_into().map_err(|_| "INVALID_ALLOWED_PUBLIC_KEY_LENGTH")?;
        VerifyingKey::from_bytes(&decoded).map_err(|_| "INVALID_ALLOWED_ED25519_KEY")?;
        if host_fingerprint(&decoded) != item.host_id {
            return Err("ALLOWLIST_ID_MISMATCH".into());
        }
        if permitted.insert(item.host_id, item.public_key).is_some() {
            return Err("DUPLICATE_ALLOWED_ID".into());
        }
    }
    Ok(permitted)
}

fn tls_config(cert_path: &Path, key_path: &Path) -> Result<Arc<ServerConfig>, String> {
    #[cfg(windows)] crate::windows_acl::verify_private(key_path)?;
    let cert_data = secure_file(cert_path)?;
    let key_data = secure_file(key_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(key_path).map_err(|e| e.to_string())?.permissions().mode();
        if mode & 0o077 != 0 {
            return Err("PRIVATE_KEY_MUST_BE_MODE_0600".into());
        }
    }
    let certs = rustls_pemfile::certs(&mut BufReader::new(cert_data.as_slice()))
        .collect::<Result<Vec<_>, _>>().map_err(|e|e.to_string())?;
    if certs.is_empty() { return Err("TLS_CERTIFICATE_REQUIRED".into()) }
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(key_data.as_slice()))
            .map_err(|e|e.to_string())?.ok_or("TLS_PRIVATE_KEY_REQUIRED")?;
    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("TLS_CONFIG_INVALID: {e}"))?;
    config.alpn_protocols = vec![b"desktop-mcp-presence/1".to_vec()];
    Ok(Arc::new(config))
}

fn verify_claim(claim: &Value, nonce: &str, allowed: &HashMap<String, String>) -> Result<String, String> {
    if claim.get("type").and_then(Value::as_str) != Some("authenticate")
        || claim.get("version").and_then(Value::as_u64) != Some(1) {
        return Err("INVALID_AUTH_FRAME".into());
    }
    let id = claim.get("host_id").and_then(Value::as_str).ok_or("HOST_ID_REQUIRED")?;
    let key_hex = claim.get("public_key").and_then(Value::as_str).ok_or("PUBLIC_KEY_REQUIRED")?;
    if allowed.get(id).map(String::as_str) != Some(key_hex) {
        return Err("HOST_NOT_ALLOWED".into());
    }
    let key: [u8; 32] = hex::decode(key_hex).map_err(|_|"INVALID_PUBLIC_KEY")?
        .try_into().map_err(|_|"INVALID_PUBLIC_KEY_LENGTH")?;
    if host_fingerprint(&key) != id {
        return Err("HOST_FINGERPRINT_MISMATCH".into());
    }
    let signature_hex = claim.get("signature").and_then(Value::as_str).ok_or("SIGNATURE_REQUIRED")?;
    let signature: [u8; 64] = hex::decode(signature_hex).map_err(|_|"INVALID_SIGNATURE")?
        .try_into().map_err(|_|"INVALID_SIGNATURE_LENGTH")?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_|"INVALID_ED25519_KEY")?;
    let message = framed(b"desktop-mcp/gateway-presence/v1\0", &[nonce, id, key_hex]);
    key.verify_strict(&message, &Signature::from_bytes(&signature))
        .map_err(|_| "SIGNATURE_VERIFICATION_FAILED")?;
    Ok(id.to_owned())
}

struct Registration {
    id: String,
    sessions: Sessions,
    broker:Option<Arc<broker::Broker>>,
}

impl Drop for Registration {
    fn drop(&mut self) {
        if let Some(broker)=&self.broker {broker.unregister(&self.id);}
        if let Ok(mut guard) = self.sessions.lock() {
            guard.remove(&self.id);
        }
    }
}

fn handle(stream: TcpStream, config: Arc<ServerConfig>, allowlist_path: PathBuf, sessions: Sessions, route_job: Option<RouteJob>, broker:Option<Arc<broker::Broker>>, expected_host:Option<&str>) -> Result<(), String> {
    stream.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e|e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(10))).map_err(|e|e.to_string())?;
    let connection = ServerConnection::new(config).map_err(|e|e.to_string())?;
    let mut tls = StreamOwned::new(connection, stream);
    let mut nonce = [0u8;32];
    OsRng.fill_bytes(&mut nonce);
    let nonce = hex::encode(nonce);
    send_json(&mut tls, &json!({"type":"challenge","version":1,"nonce":nonce}))?;
    let claim = read_json(&mut tls)?;
    let mut allowed=load_allowlist(&allowlist_path)?;
    if let Some(broker)=&broker {broker.extend_allowlist(&mut allowed)?;}
    let id = match verify_claim(&claim,&nonce,&allowed) {
        Ok(id)=>id,
        Err(e)=>{
            let _=send_json(&mut tls,&json!({"type":"rejected","reason":e}));
            return Err(e);
        }
    };
    if expected_host.is_some_and(|host| host != id) {
        let _ = send_json(&mut tls, &json!({"type":"rejected","reason":"LISTENER_HOST_MISMATCH"}));
        return Err("LISTENER_HOST_MISMATCH".into());
    }
    let control_enabled=control::agent_opted_in(&claim);
    let exec_enabled=broker.is_some() && control::exec_opted_in(&claim);
    let route_enabled=route_job.is_some() && control::route_opted_in(&claim);
    if route_job.is_some() && !route_enabled {
        return Err("ROUTE_FEATURE_NOT_NEGOTIATED".into());
    }
    let now = Instant::now();
    {
        let mut guard = sessions.lock().map_err(|_| "REGISTRY_LOCK_POISONED")?;
        if guard.contains_key(&id) { return Err("DUPLICATE_ACTIVE_HOST".into()) }
        guard.insert(id.clone(), Session {
            host_id:id.clone(),connected_seconds:0,remote_tools_enabled:false
        });
    }
    let _registration=Registration {id:id.clone(), sessions:sessions.clone(),broker:if exec_enabled {broker.clone()} else {None}};
    let requests=if exec_enabled {Some(broker.as_ref().ok_or("BROKER_REQUIRED")?.register(&id)?)}else{None};
    let mut accepted=json!({
        "type":"accepted","version":1,
        "host_id":id, "remote_tools_enabled":false,
        "authorization":"identity_only"
    });
    if control_enabled {
        accepted["features"]=if exec_enabled {
            json!([control::FEATURE,route::FEATURE,broker::FEATURE])
        } else if route_enabled {
            json!([control::FEATURE,route::FEATURE])
        } else {
            json!([control::FEATURE])
        };
    }
    send_json(&mut tls, &accepted)?;
    println!("ENROLLED_SESSION {}",id);
    if control_enabled {
        let mut bytes=[0u8;32];
        OsRng.fill_bytes(&mut bytes);
        let nonce=hex::encode(bytes);
        send_json(&mut tls,&control::challenge(&id,&nonce))?;
        let response=read_json(&mut tls)?;
        control::verify_result(&response,&id,&nonce)?;
        send_json(&mut tls,&control::ack(&nonce))?;
        println!("CONTROL_PROBE_OK {}",id);
    }
    let route_completed=route_job.is_some();
    if let Some(job)=route_job {
        let decision=job.policy.decide(&job.intent,&id);
        if decision!=policy::Decision::RequiresLocalApproval {
            return Err("ROUTE_POLICY_DENIED".into());
        }
        // Authenticate and check policy, then durably consume the request ID
        // before forwarding its request frame to the agent.
        {
            let mut guard=job.audit.lock().map_err(|_|"AUDIT_LOCK_POISONED")?;
            guard.reserve(&job.intent,&id)?;
        }
        let mut bytes=[0u8;32];
        OsRng.fill_bytes(&mut bytes);
        let route_nonce=hex::encode(bytes);
        send_json(&mut tls,&route::request(&job.intent,&route_nonce))?;
        let response=read_json(&mut tls)?;
        route::verify_denial(&response,&job.intent,&route_nonce)?;
        {
            let mut guard=job.audit.lock().map_err(|_|"AUDIT_LOCK_POISONED")?;
            guard.record_denial(&job.intent,&id)?;
        }
        println!("ROUTE_REQUIRES_LOCAL_APPROVAL {}",job.intent.request_id);
    }
    loop {
        let heartbeat = read_json(&mut tls)?;
        // An updated allowlist takes effect on the next heartbeat.
        if !host_allowed(&allowlist_path,&id,broker.as_deref())? {
            return Err("HOST_REVOKED".into());
        }
        if heartbeat.get("type").and_then(Value::as_str)!=Some("heartbeat")
            || heartbeat.get("version").and_then(Value::as_u64)!=Some(1) {
            let _=send_json(&mut tls,&json!({"type":"rejected","reason":"REMOTE_TOOLS_DISABLED"}));
            return Err("UNSUPPORTED_REMOTE_MESSAGE".into());
        }
        if let Ok(mut guard)=sessions.lock() {
            if let Some(info)=guard.get_mut(&id) {
                info.connected_seconds=now.elapsed().as_secs();
            }
        }
        let job=requests.as_ref().and_then(|rx|rx.try_recv().ok());
        if let Some(job)=job {
            let broker=broker.as_ref().ok_or("BROKER_REQUIRED")?;
            if job.canceled.load(std::sync::atomic::Ordering::SeqCst) {send_json(&mut tls,&json!({"type":"heartbeat_ack","remote_tools_enabled":false}))?;continue;}
            if broker.policy_decision(&job.intent,&id)!=policy::Decision::RequiresLocalApproval {let _=job.response.send(Err("POLICY_DENIED".into()));send_json(&mut tls,&json!({"type":"heartbeat_ack","remote_tools_enabled":false}))?;continue;}
            let reserved=broker.audit.lock().map_err(|_|"AUDIT_LOCK_POISONED")?.reserve_bound(&job.intent,&id,&job.frame);
            if reserved.is_err(){let _=job.response.send(Err("REQUEST_REPLAYED_OR_AUDIT_UNAVAILABLE".into()));send_json(&mut tls,&json!({"type":"heartbeat_ack","remote_tools_enabled":false}))?;continue;}
            send_json(&mut tls,&json!({"type":"heartbeat_ack","remote_tools_enabled":false,"route":job.frame}))?;
            let result=run_scoped_route(&mut tls,&job,&allowlist_path,&id,broker);
            if result.is_ok(){broker.audit.lock().map_err(|_|"AUDIT_LOCK_POISONED")?.record_completion(&job.intent,&id)?;}
            let failed=result.is_err();let _=job.response.send(result);
            if failed {return Err("SCOPED_ROUTE_FAILED".into());}
        }else {send_json(&mut tls,&json!({"type":"heartbeat_ack","remote_tools_enabled":false}))?;}

        if route_completed { return Ok(()); }
    }
}

fn host_allowed(path:&Path,host:&str,broker:Option<&broker::Broker>)->Result<bool,String> {
    Ok(load_allowlist(path)?.contains_key(host) || broker.and_then(|broker|broker.paired_key(host)).is_some())
}

fn run_scoped_route(tls:&mut StreamOwned<ServerConnection,TcpStream>,job:&broker::Job,allowlist:&Path,host:&str,broker:&broker::Broker)->Result<Value,String> {
    let staged=read_json(tls)?;
    if let Some(reason @ ("LOCAL_PERMISSION_REQUIRED" | "PERMISSION_REQUESTS_DISABLED" | "REMOTE_READONLY_DISABLED" | "LOCAL_APPROVAL_UNAVAILABLE" | "ADMIN_HELPER_UNAVAILABLE")) = staged["error"].as_str() {
        if staged == json!({"type":"route_rejected","version":2,"request_id":job.frame["request_id"],"request_hash":broker::digest(&job.frame),"error":reason}) {
            return Ok(json!({"request_id":job.frame["request_id"],"host_id":host,"workspace_id":"default",
                "outcome":{"pending":false,"executed":false,"error":reason}}));
        }
    }
    if staged!=json!({"type":"route_staged","version":2,"request_id":job.frame["request_id"],"request_hash":broker::digest(&job.frame)}) {return Err("ROUTE_STAGE_FAILED".into());}
    let expires=job.frame["expires_at"].as_u64().ok_or("INVALID_EXPIRY")?;
    loop {
        let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_|"CLOCK_INVALID")?.as_secs();
        if job.canceled.load(std::sync::atomic::Ordering::SeqCst) || now>=expires || !host_allowed(allowlist,host,Some(broker))? {return Err("ROUTE_CANCELED_EXPIRED_OR_REVOKED".into());}
        send_json(tls,&json!({"type":"route_poll","version":2,"request_hash":broker::digest(&job.frame)}))?;
        let response=read_json(tls)?;
        if response==json!({"type":"route_pending","version":2,"request_hash":broker::digest(&job.frame)}) {thread::sleep(Duration::from_millis(250));continue;}
        broker::verify_result(&response,&job.frame)?;
        return Ok(json!({"request_id":job.frame["request_id"],"host_id":host,"workspace_id":"default","outcome":response["outcome"]}));
    }
}

#[derive(Clone)]
struct ListenerState {
    tls: Arc<ServerConfig>,
    allowlist: PathBuf,
    sessions: Sessions,
    workers: Arc<std::sync::atomic::AtomicUsize>,
    broker: Option<Arc<broker::Broker>>,
}

fn serve_agent_listener(listener: TcpListener, state: ListenerState, private_peer: Option<(IpAddr, String)>) -> Result<(), String> {
    use std::sync::atomic::Ordering;

    struct Worker(Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for Worker {
        fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
    }

    for incoming in listener.incoming() {
        let stream = match incoming {
            Ok(stream) => stream,
            Err(error) => { eprintln!("ACCEPT_ERROR: {error}"); continue; }
        };
        if let Some((peer, _)) = &private_peer {
            if !stream.peer_addr().is_ok_and(|addr| addr.ip() == *peer) {
                continue;
            }
        }
        if state.sessions.lock().map_err(|_| "REGISTRY_LOCK_POISONED")?.len() >= MAX_SESSIONS {
            continue;
        }
        if state.workers.fetch_add(1, Ordering::SeqCst) >= MAX_SESSIONS {
            state.workers.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let state = state.clone();
        let expected_host = private_peer.as_ref().map(|(_, host)| host.clone());
        thread::spawn(move || {
            let _worker = Worker(state.workers);
            if let Err(error) = handle(stream, state.tls, state.allowlist, state.sessions, None, state.broker, expected_host.as_deref()) {
                eprintln!("SESSION_CLOSED: {error}");
            }
        });
    }
    Ok(())
}

fn private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            ip.is_private() || ip.is_loopback() || (octets[0] == 100 && (64..128).contains(&octets[1]))
        }
        IpAddr::V6(_) => false,
    }
}

fn run() -> Result<(), String> {
    let mut args=std::env::args().skip(1);
    let mut listen:SocketAddr="127.0.0.1:0".parse().unwrap();
    let mut cert=None;
    let mut key=None;
    let mut allowlist=None;
    let mut relay_listen:Option<SocketAddr>=None;
    let mut policy_path:Option<PathBuf>=None;
    let mut check_intent:Option<PathBuf>=None;
    let mut check_intents:Option<PathBuf>=None;
    let mut route_intent_path:Option<PathBuf>=None;
    let mut audit_dir:Option<PathBuf>=None;
    let mut target_host:Option<String>=None;
    let mut allow_lan=false;
    let mut once=false;
    let mut private_listen: Option<SocketAddr> = None;
    let mut private_peer: Option<IpAddr> = None;
    let mut private_host = None;
    let mut mcp_listen:Option<SocketAddr>=None;
    let mut mcp_token:Option<PathBuf>=None;
    let mut mcp_authority:Option<String>=None;
    while let Some(arg)=args.next() {
        match arg.as_str() {
            "--private-listen" => private_listen = Some(args.next().ok_or("PRIVATE_LISTEN_REQUIRED")?.parse().map_err(|_|"INVALID_PRIVATE_LISTEN")?),
            "--private-peer" => private_peer = Some(args.next().ok_or("PRIVATE_PEER_REQUIRED")?.parse().map_err(|_|"INVALID_PRIVATE_PEER")?),
            "--private-host" => private_host = Some(args.next().ok_or("PRIVATE_HOST_REQUIRED")?),
            "--mcp-listen"=>mcp_listen=Some(args.next().ok_or("MCP_LISTEN_REQUIRED")?.parse().map_err(|_|"INVALID_MCP_LISTEN")?),
            "--mcp-token-file"=>mcp_token=args.next().map(PathBuf::from),
            "--mcp-authority"=>mcp_authority=args.next(),
            "--listen"=>listen=args.next().ok_or("MISSING_LISTEN")?
                .parse().map_err(|_|"INVALID_LISTEN")?,
            "--cert"=>cert=args.next().map(PathBuf::from),
            "--key"=>key=args.next().map(PathBuf::from),
            "--relay-listen"=>relay_listen=Some(args.next().ok_or("RELAY_LISTEN_REQUIRED")?.parse().map_err(|_|"INVALID_RELAY_LISTEN")?),
            "--allowlist"=>allowlist=args.next().map(PathBuf::from),
            "--policy"=>policy_path=args.next().map(PathBuf::from),
            "--check-intent"=>check_intent=args.next().map(PathBuf::from),
            "--check-intents"=>check_intents=args.next().map(PathBuf::from),
            "--route-intent"=>route_intent_path=args.next().map(PathBuf::from),
            "--audit-dir"=>audit_dir=args.next().map(PathBuf::from),
            "--target-host"=>target_host=args.next(),
            "--allow-lan"=>allow_lan=true,
            "--once"=>once=true,
            "--version"=>{println!("desktop-mcp-gateway 0.1.0");return Ok(())},
            _=>return Err(format!("UNKNOWN_ARGUMENT: {arg}")),
        }
    }
    if check_intent.is_some() && check_intents.is_some() {
        return Err("CONFLICTING_PREFLIGHT_MODES".into());
    }
    if let Some(path)=check_intents {
        let configured=policy_path.ok_or("POLICY_REQUIRED_FOR_PREFLIGHT")?;
        let target=target_host.ok_or("TARGET_HOST_REQUIRED_FOR_PREFLIGHT")?;
        let p:policy::PolicyFile=serde_json::from_slice(&secure_file(&configured)?)
            .map_err(|e|format!("POLICY_INVALID: {e}"))?;
        p.validate()?;
        let requests:Vec<Value>=serde_json::from_slice(&secure_file(&path)?)
            .map_err(|e|format!("INTENT_BATCH_INVALID: {e}"))?;
        let decisions=policy::policy_decisions_batch(&p,&requests,&target)?;
        println!("{}",Value::Array(decisions));
        return Ok(());
    }
    if let Some(path)=check_intent {
        let configured=policy_path.ok_or("POLICY_REQUIRED_FOR_PREFLIGHT")?;
        let target=target_host.ok_or("TARGET_HOST_REQUIRED_FOR_PREFLIGHT")?;
        let p:policy::PolicyFile=serde_json::from_slice(&secure_file(&configured)?)
            .map_err(|e|format!("POLICY_INVALID: {e}"))?;
        p.validate()?;
        let intent:Value=serde_json::from_slice(&secure_file(&path)?)
            .map_err(|e|format!("INTENT_INVALID: {e}"))?;
        println!("{}",policy::policy_decision(&p,&intent,&target));
        return Ok(());
    }
    let route_job=if let Some(path)=route_intent_path {
        if !once || check_intent.is_some() || check_intents.is_some() {
            return Err("ROUTE_INTENT_REQUIRES_ONCE_MODE".into());
        }
        let file=policy_path.as_ref().ok_or("POLICY_REQUIRED_FOR_ROUTING")?;
        let p:policy::PolicyFile=serde_json::from_slice(&secure_file(file)?)
            .map_err(|e|format!("POLICY_INVALID: {e}"))?;
        p.validate()?;
        let request:policy::Intent=serde_json::from_slice(&secure_file(&path)?)
            .map_err(|e|format!("ROUTE_INTENT_INVALID: {e}"))?;
        let audit_path=audit_dir.as_ref().ok_or("AUDIT_DIRECTORY_REQUIRED_FOR_ROUTING")?;
        let audit=Arc::new(Mutex::new(audit::Audit::open(audit_path)?));
        Some(RouteJob{policy:p,intent:request,audit})
    } else {
        if audit_dir.is_some() && mcp_listen.is_none() {
            return Err("AUDIT_DIRECTORY_REQUIRES_ROUTE_INTENT".into());
        }
        None
    };
    if !listen.ip().is_loopback() && !allow_lan {
        return Err("NON_LOOPBACK_REQUIRES_EXPLICIT_ALLOW_LAN".into());
    }
    let cert = cert.ok_or("CERT_REQUIRED")?;
    let key = key.ok_or("KEY_REQUIRED")?;
    let allowlist=allowlist.ok_or("ALLOWLIST_REQUIRED")?;
    let tls=tls_config(&cert,&key)?;
    let configured_hosts = load_allowlist(&allowlist)?;
    let private_listener = match (private_listen, private_peer, private_host) {
        (None, None, None) => None,
        (Some(address), Some(peer), Some(host)) => {
            if once || mcp_listen.is_none() || !allow_lan
                || !private_address(address.ip()) || !private_address(peer)
                || address.ip().is_loopback() != peer.is_loopback()
                || !configured_hosts.contains_key(&host)
            {
                return Err("PRIVATE_LISTENER_POLICY_DENIED".into());
            }
            let listener = TcpListener::bind(address).map_err(|e| format!("PRIVATE_BIND_FAILED: {e}"))?;
            Some((listener, peer, host))
        }
        _ => return Err("PRIVATE_LISTENER_REQUIRES_ADDRESS_PEER_AND_HOST".into()),
    };
    let relay_listener=if let Some(address)=relay_listen {
        if !address.ip().is_loopback() || once || mcp_listen.is_none() {
            return Err("RELAY_REQUIRES_LOOPBACK_AND_PERSISTENT_MCP".into());
        }
        Some(TcpListener::bind(address).map_err(|e|format!("RELAY_BIND_FAILED: {e}"))?)
    } else {None};
    let listener=TcpListener::bind(listen).map_err(|e|format!("BIND_FAILED: {e}"))?;
    let broker=if let Some(address)=mcp_listen {
        if !address.ip().is_loopback() && !allow_lan {return Err("MCP_NON_LOOPBACK_REQUIRES_ALLOW_LAN".into());}
        if once || route_job.is_some() {return Err("MCP_REQUIRES_PERSISTENT_MODE".into());}
        let cfg=mcp::Config::load(&mcp_token.ok_or("MCP_TOKEN_FILE_REQUIRED")?,mcp_authority.ok_or("MCP_AUTHORITY_REQUIRED")?)?;
        let path=policy_path.as_ref().ok_or("MCP_POLICY_REQUIRED")?;
        let policy:policy::PolicyFile=serde_json::from_slice(&secure_file(path)?).map_err(|_|"MCP_POLICY_INVALID")?;policy.validate()?;
        let state=audit_dir.as_ref().ok_or("MCP_AUDIT_REQUIRED")?;
        let audit=audit::Audit::open(state)?;
        let broker=Arc::new(broker::Broker::new(policy,audit,state)?);let dispatch=broker.clone();
        mcp::start(address,(*tls).clone(),cfg,Arc::new(move|tool,args,alive|dispatch.call(tool,args,alive)))?;
        Some(broker)
    } else {if mcp_token.is_some() || mcp_authority.is_some() {return Err("MCP_LISTEN_REQUIRED".into());}None};
    let address=listener.local_addr().map_err(|e|e.to_string())?;
    println!("LISTENING {} identity_only no_remote_commands",address);
    let sessions:Sessions=Arc::new(Mutex::new(HashMap::new()));
    if once {
        io::stdout().flush().map_err(|e| e.to_string())?;
        let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
        return handle(stream, tls, allowlist, sessions, route_job, broker, None);
    }
    let state = ListenerState {
        tls, allowlist, sessions, broker,
        workers: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };
    if let Some((listener, peer, host)) = private_listener {
        println!("PRIVATE_LISTENING {}", listener.local_addr().map_err(|e| e.to_string())?);
        let state = state.clone();
        thread::spawn(move || {
            if let Err(error) = serve_agent_listener(listener, state, Some((peer, host))) {
                eprintln!("PRIVATE_LISTENER_FAILED: {error}");
                std::process::exit(2);
            }
        });
    }
    if let Some(relay)=relay_listener {
        let mut state=state.clone();
        state.workers=Arc::new(std::sync::atomic::AtomicUsize::new(0));
        thread::spawn(move || {
            if let Err(error)=serve_agent_listener(relay,state,None) {
                eprintln!("RELAY_LISTENER_FAILED: {error}");
                std::process::exit(2);
            }
        });
    }
    io::stdout().flush().map_err(|e| e.to_string())?;
    serve_agent_listener(listener, state, None)
}

fn main() {
    if let Err(error)=run() {
        eprintln!("GATEWAY_ERROR: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn verify_requires_allowlisted_identity_and_fresh_signed_nonce() {
        let key=SigningKey::generate(&mut OsRng);
        let public_key=hex::encode(key.verifying_key().to_bytes());
        let id=host_fingerprint(key.verifying_key().as_bytes());
        let nonce="01".repeat(32);
        let payload=framed(b"desktop-mcp/gateway-presence/v1\0",&[&nonce,&id,&public_key]);
        let sig=hex::encode(key.sign(&payload).to_bytes());
        let claim=json!({"type":"authenticate","version":1,"host_id":id,"public_key":public_key,"signature":sig});
        let allow=HashMap::from([(id.clone(),public_key)]);
        assert_eq!(verify_claim(&claim,&nonce,&allow).unwrap(),id);
        assert!(verify_claim(&claim,&"02".repeat(32),&allow).is_err());
        assert!(verify_claim(&claim,&nonce,&HashMap::new()).is_err());
    }

    #[test]
    fn frames_have_bounds_and_disjoint_fields() {
        let first=framed(b"domain",&["ab","c"]);
        let second=framed(b"domain",&["a","bc"]);
        assert_ne!(first,second);
        assert!(send_json(&mut Vec::new(), &json!({"large":"x".repeat(FRAME_LIMIT)})).is_err());
    }
}
