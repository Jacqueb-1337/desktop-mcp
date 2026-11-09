//! Local, authenticated, loopback-only agent endpoint. Not a remote MCP gateway.
//! The random 256-bit secret is stored in the calling OS user's config directory.
//! On Unix it is mode 0600, with the parent directory mode 0700.
//! On Windows the directory must be inside the user's ACL-protected profile.
//! No admin commands, remote agents or unrestricted shell exist at this layer.
use crate::core::Agent;
use crate::pairing::Pairing;
use crate::approval::Inbox;
use crate::elevation;
use crate::unattended;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::Path,
    time::{Duration, Instant},
};

const MAX_MESSAGE_BYTES: u64 = 6 * 1024 * 1024;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(8);

#[derive(Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
struct Runtime {
    version: u32,
    port: u16,
    token: String,
    pid: u32,
}

#[derive(Debug)]
struct Policy {
    mode: String,
    remote_reads_enabled:bool,
    require_pairing_consent:bool,
    admin_enabled:bool,
    admin_commands_enabled:bool,
    admin_run:Option<elevation::Run>,
    system_run:Option<unattended::Task>,
    terminals:crate::terminal::Pool,
    system_request:Option<Value>,
    system_command:Option<(Value, uuid::Uuid)>,
    system_mode:bool,
    started: Option<Instant>,
    until: Option<Instant>,
    persistent: bool,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            mode: "ask".into(),
            remote_reads_enabled:false,
            require_pairing_consent:false,
            admin_enabled:false,
            admin_commands_enabled:false,
            admin_run:None,
            system_run:None,
            terminals:crate::terminal::Pool::default(),
            system_request:None,
            system_command:None,
            system_mode:false,
            started: None,
            until: None,
            persistent: false,
        }
    }
}

impl Policy {
    fn privileged_enabled(&self, tool: &str) -> bool {
        match tool {
            elevation::TOOL => self.admin_enabled,
            elevation::COMMAND => self.admin_commands_enabled,
            _ => false,
        }
    }

    fn allowed(&self) -> bool {
        self.mode == "auto" && (self.persistent || self.until.is_some_and(|end| Instant::now() < end))
    }

    fn reset(&mut self) {
        *self = Self { require_pairing_consent: self.require_pairing_consent, admin_enabled: self.admin_enabled, admin_commands_enabled: self.admin_commands_enabled, system_mode: self.system_mode, ..Self::default() };
    }

    fn set(&mut self, mode: &str, duration: &str, writes_enabled: bool) -> Result<(), String> {
        if !["ask", "auto", "read_only"].contains(&mode) {
            return Err("INVALID_POLICY_MODE".into());
        }
        if mode == "auto" && !writes_enabled {
            return Err("WRITE_DENIED: agent was not locally started with --allow-writes".into());
        }
        self.mode = mode.into();
        self.started = Some(Instant::now());
        self.until = None;
        self.persistent = false;
        if mode == "auto" {
            match duration {
                "30" => self.until = Some(Instant::now() + Duration::from_secs(30 * 60)),
                "60" => self.until = Some(Instant::now() + Duration::from_secs(60 * 60)),
                "240" => self.until = Some(Instant::now() + Duration::from_secs(240 * 60)),
                "persistent" => self.persistent = true,
                _ => {
                    self.reset();
                    return Err("INVALID_DURATION".into());
                }
            }
        }
        Ok(())
    }

    fn status(&self) -> Value {
        json!({
            "mode": self.mode,
            "writes_currently_authorized": self.allowed(),
            "remaining_seconds": self.until.map(|t|t.saturating_duration_since(Instant::now()).as_secs()),
            "persistent": self.persistent,
            "administrator_enabled": self.admin_enabled,
            "admin_commands_enabled": self.admin_commands_enabled,
            "system_mode":self.system_mode,
            "remote_access_enabled": self.remote_reads_enabled
        })
    }
}

fn token_matches(provided: &str, correct: &str) -> bool {
    // Equal-length hexadecimal tokens, compared without early exit.
    if provided.len() != correct.len() {return false}
    let mut different = 0u8;
    for (a,b) in provided.bytes().zip(correct.bytes()) { different |= a ^ b; }
    different == 0
}

#[cfg(unix)]
fn secure_directory(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let meta = fs::symlink_metadata(dir).map_err(|e| e.to_string())?;
    if !meta.is_dir() || meta.file_type().is_symlink() {
        return Err("INSECURE_STATE_DIR".into());
    }
    // The OS user running this process must own the token store.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err("STATE_DIR_NOT_OWNED_BY_USER".into());
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e|e.to_string())
}

#[cfg(windows)]
fn secure_directory(dir: &Path) -> Result<(), String> {
    // Caller supplies a path inside the current user's profile.
    // Windows profile default inherited DACLs protect this config directory.
    let profile = std::env::var_os("USERPROFILE").ok_or("USERPROFILE_NOT_SET")?;
    let base=Path::new(&profile).canonicalize().map_err(|e|e.to_string())?;
    fs::create_dir_all(dir).map_err(|e|e.to_string())?;
    let canon=dir.canonicalize().map_err(|e|e.to_string())?;
    if !canon.starts_with(base) || fs::symlink_metadata(dir).map_err(|e|e.to_string())?.file_type().is_symlink() {
        return Err("STATE_DIRECTORY_OUTSIDE_USER_PROFILE".into());
    }
    Ok(())
}

const REMOTE_GATE: &str = "remote-readonly.enabled";
fn remote_gate_enabled(dir:&Path)->bool {
    let path=dir.join(REMOTE_GATE);
    fs::symlink_metadata(&path).is_ok_and(|m|m.is_file() && !m.file_type().is_symlink() && m.len()==8)
        && fs::read(path).is_ok_and(|data|data==b"enabled\n")
}
fn persist_remote_gate(dir:&Path,enabled:bool)->Result<(),String> {
    let path=dir.join(REMOTE_GATE);
    let scratch=dir.join(format!(".remote-readonly-{}.tmp",uuid::Uuid::new_v4()));
    let mut options=OpenOptions::new();options.write(true).create_new(true);
    #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;options.mode(0o600);}
    let mut file=options.open(&scratch).map_err(|_|"REMOTE_GATE_CREATE_FAILED")?;
    file.write_all(if enabled{b"enabled\n"}else{b"disabled\n"}).and_then(|_|file.sync_all()).map_err(|_|"REMOTE_GATE_SYNC_FAILED")?;
    drop(file);
    #[cfg(windows)] if path.exists(){fs::remove_file(&path).map_err(|_|"REMOTE_GATE_REPLACE_FAILED")?;}
    fs::rename(&scratch,&path).map_err(|_|"REMOTE_GATE_REPLACE_FAILED")?;
    #[cfg(unix)] fs::File::open(dir).and_then(|d|d.sync_all()).map_err(|_|"REMOTE_GATE_SYNC_FAILED")?;
    Ok(())
}

fn runtime_file(dir: &Path) -> std::path::PathBuf {dir.join("local-agent.json")}

fn write_runtime(dir: &Path, r: &Runtime) -> Result<(), String> {
    let path = runtime_file(dir);
    let payload = serde_json::to_vec(r).map_err(|e|e.to_string())?;
    let scratch=dir.join(format!(".local-agent-{}.tmp",std::process::id()));
    let file=OpenOptions::new().write(true).create_new(true).open(&scratch)
        .map_err(|e|format!("RUNTIME_CREATE_ERROR: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|e|e.to_string())?;
    }
    let mut file = file;
    file.write_all(&payload).map_err(|e|e.to_string())?;
    file.sync_all().map_err(|e|e.to_string())?;
    drop(file);
    #[cfg(windows)]
    {
        // Windows rename does not replace existing files. This file is only a
        // discovery pointer; the old process has already released its lock.
        let _=fs::remove_file(&path);
    }
    fs::rename(&scratch, &path).map_err(|e|format!("RUNTIME_RENAME_ERROR: {e}"))
}

fn run_request(agent: &mut Agent, pairing: &mut Pairing, policy: &mut Policy, inbox: &mut Inbox, writes_enabled: bool, remote_capable:bool, dir:&Path, value: &Value) -> Value {
    let op = value.get("method").and_then(Value::as_str).unwrap_or("");
    match op {
        "status" => json!({
            "running":true,"pid":std::process::id(),"protocol":"desktop-mcp-local-v1",
            "workspace":agent.root().display().to_string(),
            "identity":pairing.identity(),
            "writes_enabled_at_launch":writes_enabled,
            "remote_patch_engine_enabled":agent.remote_patch_enabled(),
            "policy":policy.status(),
            "admin_command_granted":policy.remote_reads_enabled && policy.admin_commands_enabled
                && ( (policy.system_mode && unattended::active(dir,
                     pairing.identity()["host_id"].as_str().unwrap_or(""),elevation::COMMAND))
                     || inbox.has_permission(elevation::COMMAND, agent.authorization_scope().to_str().unwrap_or("")) ),
            "unattended_elevated_active":policy.system_mode && unattended::active(
                dir,pairing.identity()["host_id"].as_str().unwrap_or(""),elevation::COMMAND)
        }),
        "set_admin_command" => {
            let duration = match value.get("duration") {
                Some(Value::Null) => None,
                Some(Value::String(duration)) => Some(duration.as_str()),
                _ => return json!({"error":"INVALID_PERMISSION_DURATION"}),
            };
            if duration.is_some() && !(policy.admin_commands_enabled && policy.remote_reads_enabled) {
                return json!({"error":"ADMIN_HELPER_UNAVAILABLE"});
            }
            if duration.is_some_and(|duration| crate::route::permission_duration(duration).is_none()) {
                return json!({"error":"INVALID_PERMISSION_DURATION"});
            }
            policy.admin_run = None;
            match inbox.set_admin_command(agent.authorization_scope().to_str().unwrap_or(""), duration) {
                Ok(()) => json!({"enabled":duration.is_some()}),
                Err(error) => {
                    policy.remote_reads_enabled = false;
                    let _ = persist_remote_gate(dir, false);
                    json!({"error":error})
                }
            }
        },
        "set_remote_readonly" => {
            let Some(enabled)=value["enabled"].as_bool() else {return json!({"error":"BOOLEAN_REQUIRED"});};
            if enabled && !remote_capable {return json!({"error":"REMOTE_READONLY_NOT_ENABLED_AT_LAUNCH"});}
            if !enabled {policy.remote_reads_enabled=false;policy.admin_run=None;policy.terminals.close_all();}
            if let Err(error)=persist_remote_gate(dir,enabled){return json!({"error":error});}
            if !enabled {if let Err(error)=inbox.clear(){return json!({"error":error});}}
            policy.remote_reads_enabled=enabled;json!({"enabled":enabled})
        },
        "set_policy" => {
            let mode=value.get("mode").and_then(Value::as_str).unwrap_or("");
            let duration=value.get("duration").and_then(Value::as_str).unwrap_or("60");
            match policy.set(mode,duration,writes_enabled) {
                Ok(())=>json!({"status":"ok","policy":policy.status()}),
                Err(e)=>json!({"error":e})
            }
        },
        "revoke" => {
            policy.remote_reads_enabled=false;
            if let Err(error)=persist_remote_gate(dir,false){return json!({"error":error});}
            if let Err(error)=inbox.clear() { return json!({"error":error}); }
            policy.reset();
            pairing.cancel_invite();
            json!({"status":"revoked","policy":policy.status()})
        },
        "approval_stage" => {
            let identity=pairing.identity();
            let host=identity["host_id"].as_str().unwrap_or("");
            let route=value.get("route").unwrap_or(&Value::Null);
            if host.is_empty() { return json!({"error":"APPROVAL_IDENTITY_UNAVAILABLE"}); }
            if route["version"]==2 && !policy.remote_reads_enabled {return json!({"error":"REMOTE_READONLY_DISABLED"});}
            let tool = route["tool"].as_str().unwrap_or("");
            let capability = if tool == "request_permission" {
                route["arguments"]["capability"].as_str().unwrap_or("")
            } else { tool };
            if policy.system_mode {
                if route["version"]!=2 || !policy.admin_commands_enabled {
                    return json!({"error":"LOCAL_PERMISSION_REQUIRED"});
                }
                if tool=="request_permission" && capability==elevation::COMMAND {
                    let scope=agent.authorization_scope().to_str().unwrap_or("");
                    return match inbox.stage(route,Some(scope)).and_then(|queued| {
                        unattended::stage_request(dir,route)?;
                        policy.system_request=Some(route.clone());
                        Ok(queued)
                    }) {
                        Ok(queued)=>queued,
                        Err(error)=>json!({"error":error}),
                    };
                }
                if !matches!(tool,elevation::COMMAND|"admin_command_result") && !crate::terminal::is_tool(tool) {
                    return json!({"error":"LOCAL_PERMISSION_REQUIRED"});
                }
                let Some(grant)=unattended::grant_id(dir,host) else {
                    return json!({"error":"LOCAL_PERMISSION_REQUIRED"});
                };
                if policy.system_run.is_some() {
                    return json!({"error":"SYSTEM_COMMAND_BUSY"});
                }
                return match inbox.approve_automatic(route) {
                    Ok(queued)=>{
                        policy.system_command=Some((route.clone(),grant));
                        queued
                    },
                    Err(error)=>json!({"error":error}),
                };
            }
            if tool=="admin_command_result" || crate::terminal::is_tool(tool) {return json!({"error":"LOCAL_PERMISSION_REQUIRED"});}
            if elevation::is_privileged(capability) && !policy.privileged_enabled(capability) {
                return json!({"error":"ADMIN_HELPER_UNAVAILABLE"});
            }
            if policy.admin_run.as_ref().is_some_and(|run| !run.matches(route)) {
                policy.admin_run = None;
            }
            let path = agent.authorization_scope().to_str().unwrap_or("");
            let scope = if tool == "request_permission" {
                let admin_permission = policy.privileged_enabled(capability)
                    || (capability == "pairing" && (policy.admin_enabled || policy.admin_commands_enabled));
                if !policy.require_pairing_consent && !admin_permission {
                    return json!({"error":"PERMISSION_REQUESTS_DISABLED"});
                }
                Some(path)
            } else {
                if route["version"] == 2
                    && (policy.require_pairing_consent || elevation::is_privileged(tool))
                    && !(inbox.has_permission("pairing", path) && inbox.has_permission(tool, path))
                {
                    return json!({"error":"LOCAL_PERMISSION_REQUIRED"});
                }
                None
            };
            inbox.stage(route, scope).unwrap_or_else(|error|json!({"error":error}))
        },
        "approval_list" => {let mut list=inbox.list();list["workspace_path"]=json!(agent.root().display().to_string());list},
        "approval_cancel" => {
            let frame=&value["route"];
            if policy.system_request.as_ref()==Some(frame) {
                policy.system_request=None;
                unattended::clear_request(dir);
            }
            if policy.system_command.as_ref().is_some_and(|(staged,_)|staged==frame) {
                policy.system_command=None;
            }
            if policy.system_run.as_ref().is_some_and(|run|run.matches(frame)) {
                policy.system_run=None;
            }
            if policy.admin_run.as_ref().is_some_and(|run| run.matches(&value["route"])) {
                policy.admin_run = None;
            }
            json!({"canceled":true})
        },
        "approval_execute" => {
            let frame=value.get("route").unwrap_or(&Value::Null);
            if !policy.remote_reads_enabled {return json!({"pending":false,"executed":false,"error":"REMOTE_READONLY_DISABLED"});}
            let tool = frame["tool"].as_str().unwrap_or("");
            let path = agent.authorization_scope().to_str().unwrap_or("");
            let host_id=pairing.identity()["host_id"].as_str().unwrap_or("").to_string();
            if policy.system_mode {
                let rejected=|error|json!({"pending":false,"executed":false,"error":error});
                if policy.system_request.as_ref()==Some(frame) {
                    let Some(approved)=unattended::owner_decision(dir,frame) else {
                        return json!({"pending":true});
                    };
                    policy.system_request=None;
                    unattended::clear_request(dir);
                    let id=frame["request_id"].as_str().unwrap_or("");
                    let nonce=frame["nonce"].as_str().unwrap_or("");
                    let hash=hex::encode(sha2::Sha256::digest(serde_json::to_vec(frame).unwrap()));
                    let choice=if approved {"approve"} else {"deny"};
                    let outcome=inbox.decide(id,nonce,&hash,choice).and_then(|_| {
                        if !approved {return Err("LOCAL_OWNER_DECLINED".into());}
                        if !inbox.consume(frame)? {return Err("LOCAL_APPROVAL_REQUIRED".into());}
                        unattended::issue_grant(dir,frame)
                    });
                    return match outcome {
                        Ok(())=>json!({"pending":false,"executed":true,"data":{
                            "capability":elevation::COMMAND,"duration":frame["arguments"]["duration"],
                            "granted":true,"unattended":true
                        }}),
                        Err(error)=>rejected(error),
                    };
                }
                if let Some(run)=policy.system_run.as_ref() {
                    if !run.matches(frame) {return rejected("SYSTEM_COMMAND_BUSY".into());}
                    let result=run.poll();
                    if result["pending"]!=true {policy.system_run=None;}
                    return result;
                }
                let Some((staged,grant))=policy.system_command.as_ref() else {
                    return rejected("LOCAL_PERMISSION_REQUIRED".into());
                };
                if staged!=frame {return rejected("APPROVAL_REQUEST_MISMATCH".into());}
                let grant=*grant;
                policy.system_command=None;
                if unattended::grant_id(dir,&host_id)!=Some(grant) {
                    return rejected("UNATTENDED_GRANT_INACTIVE".into());
                }
                if crate::terminal::is_tool(tool) {
                    return match inbox.consume(frame).and_then(|spent| {
                        if !spent {return Err("LOCAL_APPROVAL_REQUIRED".into());}
                        policy.terminals.call(dir,&host_id,grant,tool,&frame["arguments"])
                    }) {
                        Ok(data)=>json!({"pending":false,"executed":true,"data":data}),
                        Err(error)=>rejected(error),
                    };
                }
                if tool=="admin_command_result" {
                    return match inbox.consume(frame).and_then(|spent| {
                        if !spent {return Err("LOCAL_APPROVAL_REQUIRED".into());}
                        unattended::command_result(dir,grant,&frame["arguments"]["run_id"])
                    }) {
                        Ok(data)=>json!({"pending":false,"executed":true,"data":data}),
                        Err(error)=>rejected(error),
                    };
                }
                return match inbox.consume(frame).and_then(|spent| {
                    if !spent {return Err("LOCAL_APPROVAL_REQUIRED".into());}
                    unattended::Task::start(frame,dir,&host_id,grant)
                }) {
                    Ok(run)=>{policy.system_run=Some(run);json!({"pending":true})},
                    Err(error)=>rejected(error),
                };
            }
            if (policy.require_pairing_consent || elevation::is_privileged(tool)) && tool != "request_permission"
                && !(inbox.has_permission("pairing", path) && inbox.has_permission(tool, path))
            {
                return json!({"pending":false,"executed":false,"error":"LOCAL_PERMISSION_REQUIRED"});
            }
            if elevation::is_privileged(tool) {
                if !policy.privileged_enabled(tool) {
                    return elevation::rejected("ADMIN_HELPER_UNAVAILABLE");
                }
                if let Some(run) = &policy.admin_run {
                    if !run.matches(frame) {
                        return elevation::rejected("ADMIN_REQUEST_MISMATCH");
                    }
                    let result = run.poll();
                    if result["pending"] != true { policy.admin_run = None; }
                    return result;
                }
            }
            match inbox.consume(frame) {
                Ok(false)=>json!({"pending":true}),
                Ok(true) if elevation::is_privileged(tool) => match elevation::Run::start(frame, agent.root()) {
                    Ok(run) => { policy.admin_run = Some(run); json!({"pending":true}) }
                    Err(error) => elevation::rejected(error),
                },
                Ok(true) if tool == "request_permission" => json!({
                    "pending":false,"executed":true,
                    "data":{"capability":frame["arguments"]["capability"],"duration":frame["arguments"]["duration"],"granted":true}
                }),
                Ok(true) if tool == "git_snapshot" || matches!(tool,"patch_prepare"|"patch_review"|"patch_apply"|"patch_status"|"git_commit_patch") => {
                    let mut args=frame["arguments"].clone();
                    args["host_id"]=json!("local");
                    args["workspace_id"]=json!("default");
                    match agent.dispatch(tool,&args) {
                        Ok(data)=>json!({"pending":false,"executed":true,"data":data}),
                        Err(error)=>json!({"pending":false,"executed":true,"error":error}),
                    }
                },
                Ok(true) if tool == "use_repository" => match agent.use_repository(
                    frame["arguments"]["path"].as_str().unwrap_or(""),
                    frame["arguments"]["initialize"].as_bool().unwrap_or(false),
                ) {
                    Ok(data)=>json!({"pending":false,"executed":true,"data":data}),
                    Err(error)=>json!({"pending":false,"executed":true,"error":error}),
                },
                Ok(true)=>match if frame["tool"]=="git_status" {crate::readonly::git_status(agent.root(),&frame["arguments"])}else{crate::readonly::fs_read(agent.root(),&frame["arguments"])} {
                    Ok(data)=>json!({"pending":false,"executed":true,"data":data}),
                    Err(error)=>json!({"pending":false,"executed":true,"error":error}),
                },
                Err(error)=>json!({"pending":false,"executed":false,"error":error}),
            }
        },
        "approval_decide" => {
            let id=value.get("request_id").and_then(Value::as_str).unwrap_or("");
            let nonce=value.get("nonce").and_then(Value::as_str).unwrap_or("");
            let choice=value.get("decision").and_then(Value::as_str).unwrap_or("");
            let hash=value.get("request_hash").and_then(Value::as_str).unwrap_or("");
            inbox.decide(id,nonce,hash,choice).unwrap_or_else(|error|json!({"error":error}))
        },        "pair_identity" => pairing.identity(),
        "pair_list" => pairing.list(),
        "pair_create_invite" => pairing.create_invitation().unwrap_or_else(|e| json!({"error":e})),
        "pair_prepare_join" => {
            let invite=value.get("invitation").unwrap_or(&Value::Null);
            let name=value.get("name").and_then(Value::as_str).unwrap_or("");
            pairing.prepare_join(invite,name).unwrap_or_else(|e| json!({"error":e}))
        },
        "pair_accept_join" => {
            let join=value.get("join_request").unwrap_or(&Value::Null);
            pairing.accept_join(join).unwrap_or_else(|e| json!({"error":e}))
        },
        "pair_finalize_join" => {
            let receipt=value.get("receipt").unwrap_or(&Value::Null);
            let name=value.get("name").and_then(Value::as_str).unwrap_or("");
            pairing.finalize_join(receipt,name).unwrap_or_else(|e| json!({"error":e}))
        },
        "pair_revoke" => {
            let id=value.get("host_id").and_then(Value::as_str).unwrap_or("");
            pairing.revoke(id).unwrap_or_else(|e| json!({"error":e}))
        },
        "pair_cancel" => pairing.cancel_invite(),
        "tool" => {
            let name=value.get("name").and_then(Value::as_str).unwrap_or("");
            let args=value.get("arguments").cloned().unwrap_or(json!({}));
            let mutation=matches!(name,"patch_apply"|"git_commit_patch");
            if mutation && (!writes_enabled || !policy.allowed()) {
                return json!({"error":"APPROVAL_REQUIRED: local write policy does not authorize this operation"});
            }
            // Destructive deletes require a distinct explicit approval mechanism.
            // Until implemented, auto-approval cannot authorize them.
            if name == "patch_apply" {
                let Some(patch_id) = args.get("patch_id").and_then(Value::as_str) else {
                    return json!({"error":"INVALID_ARGUMENT: patch_id required"});
                };
                match agent.patch_contains_delete(patch_id) {
                    Ok(true) => return json!({"error":"DESTRUCTIVE_APPROVAL_REQUIRED: deleting files is disabled in local auto mode"}),
                    Err(reason) => return json!({"error":reason}),
                    Ok(false) => {}
                }
            }
            // Policy is checked again per operation, never just at connection.
            match agent.dispatch(name,&args) {
                Ok(v)=>json!({"result":v}),
                Err(e)=>json!({"error":e})
            }
        }
        _ => json!({"error":"UNKNOWN_LOCAL_METHOD"})
    }
}

fn handle_connection(
    mut stream: TcpStream,
    agent: &mut Agent,
    pairing: &mut Pairing,
    policy: &mut Policy,
    inbox: &mut Inbox,
    writes_enabled: bool,
    remote_capable:bool,
    dir:&Path,
    token: &str,
) -> Result<(), String> {
    stream.set_read_timeout(Some(SOCKET_TIMEOUT)).map_err(|e|e.to_string())?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).map_err(|e|e.to_string())?;
    let mut reader = BufReader::new(stream.try_clone().map_err(|e|e.to_string())?);
    let mut body=Vec::new();
    reader.by_ref().take(MAX_MESSAGE_BYTES+1).read_until(b'\n',&mut body)
        .map_err(|e|e.to_string())?;
    if body.len() as u64 > MAX_MESSAGE_BYTES {
        return Err("LOCAL_MESSAGE_TOO_LARGE".into());
    }
    let incoming: Value = serde_json::from_slice(&body).map_err(|e|format!("INVALID_JSON: {e}"))?;
    let supplied=incoming.get("token").and_then(Value::as_str).unwrap_or("");
    if !token_matches(supplied,token) {
        // Never execute or return any sensitive information to unauthenticated peers.
        return Err("LOCAL_AUTHENTICATION_FAILED".into());
    }
    let response=run_request(agent,pairing,policy,inbox,writes_enabled,remote_capable,dir,&incoming);
    let mut outgoing=serde_json::to_vec(&response).map_err(|e|e.to_string())?;
    outgoing.push(b'\n');
    stream.write_all(&outgoing).map_err(|e|e.to_string())?;
    stream.flush().map_err(|e|e.to_string())
}

pub fn serve(agent: &mut Agent, dir: &Path, writes_enabled: bool, remote_capable:bool, require_pairing_consent:bool, enable_admin_diagnostics:bool, enable_admin_commands:bool, system_mode:bool) -> Result<(), String> {
    if system_mode {
        unattended::verify_system_state(dir)?;
        unattended::clear_request(dir);
    }
    else {secure_directory(dir)?;}
    #[cfg(windows)] if remote_capable && !system_mode {crate::windows_acl::verify_private(dir)?;}
    let lock_path=dir.join("local-agent.lock");
    let lock=OpenOptions::new().read(true).write(true).create(true).open(lock_path)
        .map_err(|e|e.to_string())?;
    lock.try_lock().map_err(|_|"LOCAL_AGENT_ALREADY_RUNNING".to_string())?;
    if system_mode {crate::terminal::start_cleanup(dir)?;}
    let listener=TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),0))
        .map_err(|e|format!("LOCAL_BIND_ERROR: {e}"))?;
    let port=listener.local_addr().map_err(|e|e.to_string())?.port();
    let token=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());

    let mut policy=Policy::default();
    policy.remote_reads_enabled=remote_capable && remote_gate_enabled(dir);
    policy.require_pairing_consent=require_pairing_consent;
    policy.admin_enabled=enable_admin_diagnostics && remote_capable && elevation::available(elevation::TOOL);
    policy.admin_commands_enabled=enable_admin_commands && remote_capable
        && (system_mode || elevation::available(elevation::COMMAND));
    policy.system_mode=system_mode;
    let mut pairing=Pairing::open(dir)?;
    let own_host_id=pairing.identity()["host_id"].as_str()
        .ok_or("APPROVAL_IDENTITY_MISSING")?.to_owned();
    let mut inbox=Inbox::open(dir,&own_host_id)?;
    write_runtime(dir,&Runtime{version:1,port,token:token.clone(),pid:std::process::id()})?;
    eprintln!("Local agent running on IPv4 loopback; pid={}; system_mode={system_mode}",std::process::id());
    for request in listener.incoming() {
        match request {
            Ok(stream)=>{
                // The TCP listener is IPv4 loopback only, no remote interface.
                if !stream.peer_addr().map(|addr|addr.ip().is_loopback()).unwrap_or(false) {
                    continue;
                }
                if let Err(e)=handle_connection(stream,agent,&mut pairing,&mut policy,&mut inbox,writes_enabled,remote_capable,dir,&token) {
                    eprintln!("Local request rejected: {e}");
                }
            },
            Err(e)=>eprintln!("Local listener error: {e}")
        }
    }
    let _=fs::remove_file(runtime_file(dir));
    Ok(())
}

pub fn request(dir: &Path, method:&str, extra: Value) -> Result<Value, String> {
    if !["status","set_policy","set_remote_readonly","revoke","tool","pair_identity","pair_list",
        "pair_create_invite","pair_prepare_join","pair_accept_join",
        "pair_finalize_join","pair_revoke","pair_cancel",
        "approval_stage","approval_list","approval_decide","approval_execute","approval_cancel","set_admin_command"].contains(&method) {
        return Err("INVALID_LOCAL_METHOD".into());
    }
    let runtime: Runtime=serde_json::from_slice(
        &fs::read(runtime_file(dir)).map_err(|e|format!("LOCAL_AGENT_OFFLINE: {e}"))?
    ).map_err(|e|format!("INVALID_LOCAL_RUNTIME: {e}"))?;
    if runtime.version!=1 || runtime.token.len()!=64 || runtime.port==0 {
        return Err("INVALID_LOCAL_RUNTIME".into());
    }
    let dest=SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST),runtime.port);
    let mut stream=TcpStream::connect_timeout(&dest,Duration::from_secs(2))
        .map_err(|e|format!("LOCAL_AGENT_OFFLINE: {e}"))?;
    stream.set_read_timeout(Some(SOCKET_TIMEOUT)).map_err(|e|e.to_string())?;
    stream.set_write_timeout(Some(SOCKET_TIMEOUT)).map_err(|e|e.to_string())?;
    let mut query=json!({"token":runtime.token,"method":method});
    let values=extra.as_object().ok_or("INVALID_ARGUMENTS: expected an object")?;
    for (k,v) in values {
        if k=="token" || k=="method" {return Err("RESERVED_LOCAL_ARGUMENT".into())}
        query[k]=v.clone();
    }
    let mut req=serde_json::to_vec(&query).map_err(|e|e.to_string())?;
    req.push(b'\n');
    stream.write_all(&req).map_err(|e|e.to_string())?;
    let mut out=Vec::new();
    BufReader::new(stream).take(MAX_MESSAGE_BYTES+1).read_until(b'\n',&mut out)
        .map_err(|e|e.to_string())?;
    if out.len() as u64 > MAX_MESSAGE_BYTES { return Err("LOCAL_RESPONSE_TOO_LARGE".into()) }
    let answer:Value=serde_json::from_slice(&out).map_err(|e|e.to_string())?;
    if method=="approval_execute" && answer["pending"]==false && answer["executed"].is_boolean() {return Ok(answer);}
    if let Some(e)=answer.get("error").and_then(Value::as_str) {
        return Err(e.into());
    }
    Ok(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn remote_opt_in_is_fail_closed_and_revocation_is_persistent() {
        let dir=tempfile::tempdir().unwrap();assert!(!remote_gate_enabled(dir.path()));
        persist_remote_gate(dir.path(),true).unwrap();assert!(remote_gate_enabled(dir.path()));
        persist_remote_gate(dir.path(),false).unwrap();assert!(!remote_gate_enabled(dir.path()));
        fs::write(dir.path().join(REMOTE_GATE),"enable").unwrap();assert!(!remote_gate_enabled(dir.path()));
    }
    #[test]
    fn policy_is_deny_by_default_and_expires() {
        let mut p=Policy::default();
        assert!(!p.allowed());
        p.set("auto","30",true).unwrap();
        assert!(p.allowed());
        p.until=Some(Instant::now()-Duration::from_secs(1));
        assert!(!p.allowed());
        p.reset();
        assert!(!p.allowed());
    }
    #[test]
    fn cannot_enable_without_explicit_write_capability() {
        let mut p=Policy::default();
        assert!(p.set("auto","60",false).is_err());
        assert!(!p.allowed());
        assert!(p.set("auto","garbage",true).is_err());
        assert!(!p.allowed());
    }
    #[test]
    fn comparisons_reject_wrong_tokens() {
        assert!(token_matches(&"ab".repeat(32),&"ab".repeat(32)));
        assert!(!token_matches(&"ab".repeat(32),&"ac".repeat(32)));
    }
}
