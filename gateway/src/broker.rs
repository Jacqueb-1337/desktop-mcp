//! Bounded per-authenticated-host queues. Session loss drops queued requests;
//! clients never receive or create an execution grant at this layer.
use crate::{
    audit::Audit,
    policy::{Decision, HostScope, Intent, PolicyFile},
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path,PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
pub const FEATURE: &str = "scoped_readonly_v2";
pub struct Job {
    pub intent: Intent,
    pub frame: Value,
    pub response: SyncSender<Result<Value, String>>,
    pub canceled: Arc<AtomicBool>,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Devices {
    keys: HashMap<String, String>,
    nicknames: HashMap<String, String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PairingStore {
    Current(Devices),
    Legacy(HashMap<String, String>),
}

pub fn valid_nickname(name: &str) -> bool {
    !name.trim().is_empty() && name.chars().count() <= 64 && !name.chars().any(char::is_control)
}

pub struct Broker {
    policy: PolicyFile,
    paired: Mutex<Devices>,
    pairing_file: PathBuf,
    pub audit: Arc<Mutex<Audit>>,
    hosts: Mutex<HashMap<String, SyncSender<Job>>>,
}
impl Broker {
    pub fn new(policy: PolicyFile, audit: Audit, state:&Path) -> Result<Self,String> {
        let pairing_file=state.join("paired-devices.json");
        let paired=match fs::symlink_metadata(&pairing_file) {
            Err(error) if error.kind()==std::io::ErrorKind::NotFound=>Devices::default(),
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() && metadata.len()<=32_768=>{
                let mut records=match serde_json::from_slice(&crate::secure_file(&pairing_file)?).map_err(|_|"INVALID_PAIRING_STORE")? {
                    PairingStore::Current(records)=>records,
                    PairingStore::Legacy(keys)=>Devices{keys,nicknames:HashMap::new()},
                };
                if records.keys.len()>64 || records.nicknames.len()>128 || records.keys.iter().any(|(id,key)| setup_key(&format!("DM1-{key}")).is_none_or(|(host,_)|host!=*id)) {
                    return Err("INVALID_PAIRING_STORE".into());
                }
                records.nicknames.retain(|host,_|
                    records.keys.contains_key(host) || policy.hosts.iter().any(|scope|&scope.host_id==host));
                let mut names=std::collections::HashSet::new();
                for name in records.nicknames.values() {
                    if !valid_nickname(name) || name.trim()!=name || !names.insert(name.to_lowercase()) {
                        return Err("INVALID_PAIRING_NICKNAMES".into());
                    }
                }
                records
            },
            _=>return Err("INVALID_PAIRING_STORE".into()),
        };
        Ok(Self {
            policy,
            paired:Mutex::new(paired),
            pairing_file,
            audit: Arc::new(Mutex::new(audit)),
            hosts: Mutex::new(HashMap::new()),
        })
    }
    pub fn register(&self, host: &str) -> Result<Receiver<Job>, String> {
        let (tx, rx) = mpsc::sync_channel(4);
        let mut hosts = self.hosts.lock().map_err(|_| "HOST_REGISTRY_UNAVAILABLE")?;
        if hosts.contains_key(host) {
            return Err("HOST_ALREADY_CONNECTED".into());
        }
        hosts.insert(host.into(), tx);
        Ok(rx)
    }
    pub fn unregister(&self, host: &str) {
        if let Ok(mut hosts) = self.hosts.lock() {
            hosts.remove(host);
        }
    }
    pub fn policy_decision(&self, intent: &Intent, host: &str) -> Decision {
        let mut mapped;
        let intent=if intent.tool=="admin_command_result" || terminal_tool(&intent.tool) {
            mapped=intent.clone();
            mapped.tool="admin_command".into();
            &mapped
        } else {intent};
        let decision=self.policy.decide(intent,host);
        if decision==Decision::RequiresLocalApproval || self.policy.hosts.iter().any(|scope|scope.host_id==host) {
            return decision;
        }
        if self.paired_key(host).is_none() {return Decision::Denied;}
        PolicyFile{version:1,hosts:vec![paired_scope(host)]}.decide(intent,host)
    }
    pub fn paired_key(&self,host:&str)->Option<String> {
        self.paired.lock().ok()?.keys.get(host).cloned()
    }
    pub fn extend_allowlist(&self,allowed:&mut HashMap<String,String>)->Result<(),String> {
        for (host,key) in self.paired.lock().map_err(|_|"PAIRING_STORE_UNAVAILABLE")?.keys.iter() {
            allowed.entry(host.clone()).or_insert_with(||key.clone());
        }
        Ok(())
    }
    fn save_devices(&self, devices: &Devices) -> Result<(), String> {
        use std::io::Write;
        let directory=self.pairing_file.parent().ok_or("PAIRING_STORE_UNAVAILABLE")?;
        let mut file=tempfile::NamedTempFile::new_in(directory).map_err(|_|"PAIRING_STORE_UNAVAILABLE")?;
        let bytes=serde_json::to_vec(devices).map_err(|_|"PAIRING_STORE_WRITE_FAILED")?;
        if bytes.len()>32_768 || devices.nicknames.len()>128 {return Err("PAIRING_STORE_FULL".into());}
        file.write_all(&bytes).map_err(|_|"PAIRING_STORE_WRITE_FAILED")?;
        file.flush().and_then(|_|file.as_file().sync_all()).map_err(|_|"PAIRING_STORE_WRITE_FAILED")?;
        file.persist(&self.pairing_file).map_err(|_|"PAIRING_STORE_WRITE_FAILED")?;
        Ok(())
    }
    fn assign_nickname(devices: &mut Devices, host: &str, nickname: &str) -> Result<(), String> {
        if !valid_nickname(nickname) { return Err("INVALID_NICKNAME".into()); }
        let nickname=nickname.trim();
        let folded=nickname.to_lowercase();
        if devices.nicknames.iter().any(|(id,name)| id!=host && name.to_lowercase()==folded) {
            return Err("NICKNAME_ALREADY_IN_USE".into());
        }
        devices.nicknames.insert(host.into(),nickname.into());
        Ok(())
    }
    fn pair_device(&self,code:&str,nickname:Option<&str>)->Result<Value,String> {
        let (host,key)=setup_key(code).ok_or("INVALID_DEVICE_CODE")?;
        let mut paired=self.paired.lock().map_err(|_|"PAIRING_STORE_UNAVAILABLE")?;
        let new=!paired.keys.contains_key(&host) && !self.policy.hosts.iter().any(|scope|scope.host_id==host);
        if new || nickname.is_some() {
            let mut next=paired.clone();
            if new {
                if next.keys.len()>=64 {return Err("PAIRING_STORE_FULL".into());}
                next.keys.insert(host.clone(),key);
            }
            if let Some(name)=nickname {Self::assign_nickname(&mut next,&host,name)?;}
            self.save_devices(&next)?;
            *paired=next;
        }
        Ok(json!({"host_id":host,"workspace_id":"default","paired":true,
            "nickname":paired.nicknames.get(&host),"elevated_access_requires_owner_approval":true}))
    }
    fn rename_device(&self,host:&str,nickname:&str)->Result<Value,String> {
        let mut paired=self.paired.lock().map_err(|_|"PAIRING_STORE_UNAVAILABLE")?;
        if !paired.keys.contains_key(host) && !self.policy.hosts.iter().any(|scope|scope.host_id==host) {
            return Err("DEVICE_NOT_PAIRED".into());
        }
        let mut next=paired.clone();
        Self::assign_nickname(&mut next,host,nickname)?;
        self.save_devices(&next)?;
        *paired=next;
        Ok(json!({"host_id":host,"nickname":paired.nicknames.get(host)}))
    }
    pub fn call(
        &self,
        tool: &str,
        args: &Value,
        alive: &dyn Fn() -> bool,
    ) -> Result<Value, String> {
        if tool=="pair_device" {
            return self.pair_device(args["code"].as_str().ok_or("INVALID_DEVICE_CODE")?,args["nickname"].as_str());
        }
        if tool=="rename_device" {
            return self.rename_device(args["host_id"].as_str().ok_or("HOST_REQUIRED")?,args["nickname"].as_str().ok_or("NICKNAME_REQUIRED")?);
        }
        if tool == "list_projects" {
            let paired=self.paired.lock().map_err(|_|"PAIRING_STORE_UNAVAILABLE")?;
            let scopes=self.policy.hosts.iter().cloned().chain(paired.keys.keys().filter(|id|
                !self.policy.hosts.iter().any(|scope|scope.host_id==**id)).map(|id|paired_scope(id)));
            let hosts = self.hosts.lock().map_err(|_| "HOST_REGISTRY_UNAVAILABLE")?;
            return Ok(
                json!({"projects":scopes.map(|scope|{
                    let mut row=json!({"host_id":scope.host_id,"workspace_id":scope.workspace_id,
                        "tools":scope.tools,"connected":hosts.contains_key(&scope.host_id)});
                    if let Some(name)=paired.nicknames.get(&scope.host_id) {row["nickname"]=json!(name);}
                    row
                }).collect::<Vec<_>>()}),
            );
        }
        let host = args["host_id"].as_str().ok_or("HOST_REQUIRED")?;
        let request_id = args["request_id"]
            .as_str()
            .map(str::to_string)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let intent = Intent {
            request_id,
            target_host_id: host.into(),
            workspace_id: "default".into(),
            tool: tool.into(),
        };
        if !matches!(tool, "git_status" | "fs_read" | "use_repository" | "git_snapshot" | "patch_prepare" | "patch_review" | "patch_status" | "patch_apply" | "git_commit_patch" | "request_permission" | "system_volume_status" | "admin_command" | "admin_command_result") && !terminal_tool(tool)
            || self.policy_decision(&intent, host) != Decision::RequiresLocalApproval
        {
            return Err("POLICY_DENIED".into());
        }
        if tool == "request_permission" {
            let capability = args["capability"].as_str().ok_or("CAPABILITY_REQUIRED")?;
            if !matches!(capability, "pairing" | "git_status" | "fs_read" | "use_repository" | "git_snapshot" | "patch_prepare" | "patch_review" | "patch_status" | "patch_apply" | "git_commit_patch" | "system_volume_status" | "admin_command")
                || !args["duration"].as_str().is_some_and(crate::policy::valid_duration)
            {
                return Err("INVALID_PERMISSION_REQUEST".into());
            }
            if capability != "pairing" {
                let mut scope = intent.clone();
                scope.tool = capability.into();
                if self.policy_decision(&scope, host) != Decision::RequiresLocalApproval {
                    return Err("POLICY_DENIED".into());
                }
            }
        }
        if tool == "admin_command" && !args["command"].as_str().is_some_and(crate::policy::valid_command) {
            return Err("INVALID_ADMIN_COMMAND".into());
        }
        let tx = self
            .hosts
            .lock()
            .map_err(|_| "HOST_REGISTRY_UNAVAILABLE")?
            .get(host)
            .cloned()
            .ok_or("HOST_DISCONNECTED")?;
        let expires = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "CLOCK_INVALID")?
            .as_secs()
            + 100;
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let arguments = match tool {
            "fs_read" => json!({"path":args["path"]}),
            "use_repository" => json!({"path":args["path"],"initialize":args["initialize"]}),
            "git_snapshot" => json!({"paths":args["paths"],"message":args["message"]}),
            "patch_prepare" => json!({"expected_head":args["expected_head"],"changes":args["changes"]}),
            "patch_review"|"patch_status"|"patch_apply" => json!({"patch_id":args["patch_id"]}),
            "git_commit_patch" => json!({"patch_id":args["patch_id"],"message":args["message"]}),
            "admin_command" => json!({"command":args["command"]}),
            "admin_command_result" => json!({"run_id":args["run_id"]}),
            tool if terminal_tool(tool) => {
                let mut payload=args.clone();
                if let Some(fields)=payload.as_object_mut() {
                    for key in ["host_id","workspace_id","request_id"] {fields.remove(key);}
                }
                payload
            },
            "request_permission" => json!({"capability":args["capability"],"duration":args["duration"]}),
            _ => json!({}),
        };
        let frame = json!({"type":"route_intent","version":2,"request_id":intent.request_id,"target_host_id":host,"workspace_id":"default","tool":tool,"arguments":arguments,"expires_at":expires,"nonce":hex::encode(nonce)});
        let (response, rx) = mpsc::sync_channel(1);
        let canceled = Arc::new(AtomicBool::new(false));
        tx.try_send(Job {
            intent,
            frame,
            response,
            canceled: canceled.clone(),
        })
        .map_err(|_| "HOST_BUSY_OR_DISCONNECTED")?;
        let started = std::time::Instant::now();
        let result = loop {
            if !alive() || started.elapsed() >= Duration::from_secs(110) {
                break Err("REQUEST_CANCELED_OR_TIMEOUT".into());
            }
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(result) => break result,
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => break Err("HOST_DISCONNECTED".into()),
            }
        };
        canceled.store(true, Ordering::SeqCst);
        result
    }
}
pub fn terminal_tool(tool:&str)->bool {
    matches!(tool,"terminal_open"|"terminal_list"|"terminal_run"|"terminal_read"|"terminal_close")
}

fn paired_scope(host:&str)->HostScope {
    HostScope{host_id:host.into(),workspace_id:"default".into(),
        tools:vec!["request_permission".into(),"admin_command".into()]}
}
pub fn setup_key(code:&str)->Option<(String,String)> {
    let key=code.strip_prefix("DM1-")?;
    if key.len()!=64 || !key.bytes().all(|byte|byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) {
        return None;
    }
    let decoded:[u8;32]=hex::decode(key).ok()?.try_into().ok()?;
    let verifying_key=ed25519_dalek::VerifyingKey::from_bytes(&decoded).ok()?;
    if verifying_key.is_weak() {return None;}
    Some((crate::host_fingerprint(&decoded),key.into()))
}
pub fn digest(frame: &Value) -> String {
    hex::encode(Sha256::digest(
        serde_json::to_vec(frame).unwrap_or_default(),
    ))
}
pub fn verify_result(result: &Value, frame: &Value) -> Result<(), String> {
    let keys = [
        "type",
        "version",
        "request_id",
        "target_host_id",
        "nonce",
        "request_hash",
        "outcome",
    ];
    if result
        .as_object()
        .is_none_or(|o| o.len() != keys.len() || keys.iter().any(|k| !o.contains_key(*k)))
        || result["type"] != "route_result"
        || result["version"] != 2
        || result["request_id"] != frame["request_id"]
        || result["target_host_id"] != frame["target_host_id"]
        || result["nonce"] != frame["nonce"]
        || result["request_hash"] != digest(frame)
    {
        return Err("ROUTE_RESULT_BINDING_MISMATCH".into());
    }
    let outcome = &result["outcome"];
    if !outcome.is_object()
        || outcome["pending"] != false
        || !outcome["executed"].is_boolean()
        || (outcome.get("data").is_some() == outcome.get("error").is_some())
        || (outcome.get("data").is_some() && outcome["executed"] != true)
    {
        return Err("ROUTE_OUTCOME_INVALID".into());
    }
    if frame["tool"] == "admin_command" && outcome.get("data").is_some()
        && !outcome["data"].as_object().is_some_and(|data| {
            data.len() == 4 && outcome["data"]["exit_code"].as_i64().is_some_and(|n| i32::try_from(n).is_ok())
                && outcome["data"]["stdout"].as_str().is_some_and(|s| s.len() <= 24_000)
                && outcome["data"]["stderr"].as_str().is_some_and(|s| s.len() <= 24_000)
                && outcome["data"]["truncated"].is_boolean()
        })
    {
        return Err("ADMIN_COMMAND_RESULT_INVALID".into());
    }
    if frame["tool"] == "system_volume_status" && outcome.get("data").is_some()
        && !outcome["data"].as_object().is_some_and(|data| {
            data.len() == 1 && outcome["data"]["needs_disk_check"].is_boolean()
        })
    {
        return Err("ADMIN_RESULT_INVALID".into());
    }
    if frame["tool"]=="request_permission" && outcome.get("data").is_some() {
        let mut expected=json!({"capability":frame["arguments"]["capability"],
            "duration":frame["arguments"]["duration"],"granted":true});
        if expected["capability"]=="admin_command" && outcome["data"]["unattended"]==true {
            expected["unattended"]=json!(true);
        }
        if outcome["data"]!=expected {return Err("PERMISSION_RESULT_BINDING_MISMATCH".into());}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn setup_code_registers_only_the_expected_host_and_persists() {
        #[cfg(windows)] let state=tempfile::tempdir_in(std::env::var_os("USERPROFILE").unwrap()).unwrap();
        #[cfg(not(windows))] let state=tempfile::tempdir().unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(state.path(),fs::Permissions::from_mode(0o700)).unwrap();
        }
        let public=SigningKey::from_bytes(&[42;32]).verifying_key().to_bytes();
        let code=format!("DM1-{}",hex::encode(public));
        let host=crate::host_fingerprint(&public);
        let policy=||PolicyFile{version:1,hosts:vec![]};
        let open=||Broker::new(policy(),Audit::open(state.path()).unwrap(),state.path()).unwrap();
        let intent=|tool:&str|Intent{request_id:uuid::Uuid::new_v4().to_string(),
            target_host_id:host.clone(),workspace_id:"default".into(),tool:tool.into()};
        let broker=open();
        assert_eq!(broker.policy_decision(&intent("admin_command"),&host),Decision::Denied);
        assert!(broker.pair_device(&format!("DM1-{}","00".repeat(32)),None).is_err());
        assert_eq!(broker.pair_device(&code,Some("Dad's PC")).unwrap()["host_id"],host);
        let other=SigningKey::from_bytes(&[43;32]).verifying_key().to_bytes();
        let other_code=format!("DM1-{}",hex::encode(other));
        assert_eq!(broker.pair_device(&other_code,Some("DAD'S PC")).unwrap_err(),"NICKNAME_ALREADY_IN_USE");
        assert!(broker.paired_key(&crate::host_fingerprint(&other)).is_none());
        assert_eq!(broker.rename_device(&host,"Workshop PC").unwrap()["nickname"],"Workshop PC");
        assert_eq!(broker.pair_device(&code,None).unwrap()["paired"],true);
        assert_eq!(broker.policy_decision(&intent("patch_apply"),&host),Decision::Denied);
        drop(broker);
        let reopened=open();
        assert_eq!(reopened.paired_key(&host),Some(hex::encode(public)));
        assert_eq!(reopened.call("list_projects",&json!({}),&||true).unwrap()["projects"][0]["nickname"],"Workshop PC");
        assert_eq!(reopened.policy_decision(&intent("request_permission"),&host),Decision::RequiresLocalApproval);
        assert_eq!(reopened.policy_decision(&intent("admin_command"),&host),Decision::RequiresLocalApproval);
    }
}
