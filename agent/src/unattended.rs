//! SYSTEM-only unattended delegation. A grant is written only by the elevated
//! Desktop MCP service management UI to an ACL-protected ProgramData folder.
//! Pairing and generic local-agent flags are NEVER sufficient to enable this mode.
use serde_json::{json, Value};
use std::{path::Path,fs, time::{SystemTime,UNIX_EPOCH,Duration,Instant},process::{Command,Stdio},sync::mpsc::{self,Receiver},thread,io::Read};
use uuid::Uuid;
use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

pub(crate) fn epoch()->u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0,|v|v.as_secs())
}

pub fn machine_root()->Result<std::path::PathBuf,String> {
    let program=std::env::var_os("ProgramData").ok_or("PROGRAM_DATA_UNAVAILABLE")?;
    Ok(Path::new(&program).join("DesktopMCP"))
}

pub fn verify_machine_identity_path(state:&Path)->Result<(),String>{
    let expected=machine_root()?.join("State");
    if state.canonicalize().map_err(|_|"MACHINE_STATE_MISSING")?
        !=expected.canonicalize().map_err(|_|"MACHINE_STATE_MISSING")? {
        return Err("SYSTEM_STATE_PATH_MISMATCH".into());
    }
    // This operation prints the non-secret host ID. Access to the protected
    // state file is enforced by Windows; SYSTEM is not required to print it.
    Ok(())
}

pub fn verify_system_state(state:&Path)->Result<(),String> {
    let expected=machine_root()?.join("State");
    if state.canonicalize().map_err(|_|"MACHINE_STATE_MISSING")?
        !=expected.canonicalize().map_err(|_|"MACHINE_STATE_MISSING")? {
        return Err("SYSTEM_STATE_PATH_MISMATCH".into());
    }
    #[cfg(windows)]
    crate::windows_acl::verify_system_private(&expected)?;
    #[cfg(not(windows))]
    return Err("WINDOWS_ONLY".into());
    Ok(())
}

/// The signed-in owner approves these grants through UAC. A grant never comes
/// from a remote request, an environment variable, or a user-writable file.
pub fn active(state:&Path,host_id:&str,tool:&str)->bool {
    tool == crate::elevation::COMMAND && grant_id(state,host_id).is_some()
}

pub fn grant_id(state:&Path,host_id:&str)->Option<Uuid> {
    let root=machine_root().ok()?;
    let expected=root.join("State").canonicalize().ok()?;
    if state.canonicalize().ok()? != expected {return None;}
    let value=read_record(&root.join("grant.json"))?;
    if !valid_grant(&value,host_id,epoch()) {return None;}
    Uuid::parse_str(value["grant_id"].as_str()?).ok()
}

fn read_record(path:&Path)->Option<Value> {
    let metadata=fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len()>4096 {
        return None;
    }
    serde_json::from_slice(&fs::read(path).ok()?).ok()
}

pub(crate) fn write_record(path:&Path,value:&Value)->Result<(),String> {
    let temporary=path.with_extension(format!("{}.tmp",Uuid::new_v4()));
    let result=(|| {
        let mut file=fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        serde_json::to_writer(&mut file,value)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary,path)
    })();
    if result.is_err() {let _=fs::remove_file(temporary);}
    result.map_err(|_|"MACHINE_RECORD_WRITE_FAILED".into())
}

pub fn stage_request(state:&Path,frame:&Value)->Result<(),String> {
    write_record(&state.join("owner-request.json"),&json!({
        "request_id":frame["request_id"],"host_id":frame["target_host_id"],
        "expires_at":frame["expires_at"],"duration":frame["arguments"]["duration"]
    }))
}

pub fn owner_decision(state:&Path,frame:&Value)->Option<bool> {
    let pending=read_record(&state.join("owner-request.json"))?;
    if pending["request_id"]!=frame["request_id"] {return None;}
    let record=read_record(&state.join("owner-decision.json"))?;
    if record["request_id"]!=frame["request_id"] {return None;}
    record["approved"].as_bool()
}

pub fn clear_request(state:&Path) {
    let _=fs::remove_file(state.join("owner-request.json"));
}

pub fn issue_grant(state:&Path,frame:&Value)->Result<(),String> {
    let issued_at=epoch();
    if !frame["expires_at"].as_u64().is_some_and(|expires|issued_at<expires) {
        return Err("APPROVAL_EXPIRED".into());
    }
    let duration=frame["arguments"]["duration"].as_str()
        .and_then(crate::route::permission_duration).ok_or("INVALID_PERMISSION_DURATION")?;
    let grant=json!({
        "version":1,"scope":"unattended_admin","host_id":frame["target_host_id"],
        "grant_id":Uuid::new_v4().to_string(),"issued_at":issued_at,
        "expires_at":duration.map(|seconds|issued_at+seconds),"revoked":false,
        "request_id":frame["request_id"]
    });
    audit_record(state,frame,&json!({"executed":false,"error":"owner_approved",
        "grant_id":grant["grant_id"]}))?;
    write_record(&machine_root()?.join("grant.json"),&grant)
}

fn valid_grant(value:&Value,host_id:&str,now:u64)->bool{
    if value["version"]!=1 || value["scope"]!="unattended_admin"
        || value["host_id"]!=host_id || value["revoked"]!=false {return false;}
    if value["grant_id"].as_str().is_none_or(|id|Uuid::parse_str(id).is_err()){return false;}
    let start=match value["issued_at"].as_u64(){Some(v)=>v,None=>return false};
    now>=start && start>0 && value["expires_at"].as_u64().is_none_or(|x|x>now)
        && (value["expires_at"].is_null() || value["expires_at"].as_u64().is_some())
}

/// Durable SYSTEM-only audit for delegated privileged operations.
pub fn audit(state:&Path,frame:&Value,outcome:&Value){
    let _=audit_record(state,frame,outcome);
}
fn audit_record(state:&Path,frame:&Value,outcome:&Value)->Result<(),String>{
    use std::io::Write;
    use sha2::{Sha256,Digest};
    let path=state.join("unattended-audit.jsonl");
    if fs::symlink_metadata(&path).is_ok_and(|m|m.len()>16*1024*1024 || m.file_type().is_symlink()){
        return Err("AUDIT_LOG_UNSAFE_OR_FULL".into());
    }
    let encoded=serde_json::to_vec(&frame["arguments"]).map_err(|_|"AUDIT_ENCODE_FAILED")?;
    let record=json!({"at":epoch(),"request_id":frame["request_id"],"tool":frame["tool"],
        "arguments_sha256":hex::encode(Sha256::digest(&encoded)),
        "grant_id":outcome["grant_id"],"executed":outcome["executed"],"result_error":outcome["error"],
        "exit_code":outcome["data"]["exit_code"]});
    let mut options=fs::OpenOptions::new();
    options.create(true).append(true);
    let mut file=options.open(path).map_err(|_|"AUDIT_LOG_OPEN_FAILED")?;
    let line=serde_json::to_vec(&record).map_err(|_|"AUDIT_ENCODE_FAILED")?;
    file.write_all(&line).and_then(|_|file.write_all(b"\n")).and_then(|_|file.sync_data())
        .map_err(|_|"AUDIT_WRITE_FAILED".into())
}

const RESULT_LIMIT: usize = 64;
const RESULT_RETENTION: u64 = 24 * 60 * 60;
static RESULTS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn load_results(path: &Path) -> Result<Vec<Value>, String> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err("COMMAND_HISTORY_UNAVAILABLE".into()),
    };
    let mut bytes = Vec::new();
    const MAX_BYTES: u64 = 8 * 1024 * 1024;
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)
        .map_err(|_| "COMMAND_HISTORY_UNAVAILABLE")?;
    if bytes.len() as u64 > MAX_BYTES { return Err("COMMAND_HISTORY_TOO_LARGE".into()); }
    let mut records: Vec<Value> =
        serde_json::from_slice(&bytes).map_err(|_| "COMMAND_HISTORY_INVALID")?;
    let now = epoch();
    records.retain(|record| record["finished_at"].as_u64()
        .is_some_and(|at| at <= now && now - at < RESULT_RETENTION));
    Ok(records)
}

fn remember_result(state: &Path, frame: &Value, grant: Uuid, outcome: &Value) -> Result<(), String> {
    let _guard = RESULTS_LOCK.lock().map_err(|_| "COMMAND_HISTORY_UNAVAILABLE")?;
    let path = state.join("command-results.json");
    let mut records = load_results(&path)?;
    records.insert(0, json!({"run_id":frame["request_id"], "grant_id":grant.to_string(),
        "finished_at":epoch(), "outcome":outcome}));
    records.truncate(RESULT_LIMIT);
    write_record(&path, &json!(records))
}

pub fn command_result(state: &Path, grant: Uuid, run_id: &Value) -> Result<Value, String> {
    let _guard = RESULTS_LOCK.lock().map_err(|_| "COMMAND_HISTORY_UNAVAILABLE")?;
    let grant = grant.to_string();
    let mut record = load_results(&state.join("command-results.json"))?.into_iter()
        .find(|record| &record["run_id"] == run_id && record["grant_id"] == grant)
        .ok_or("COMMAND_RESULT_NOT_FOUND_OR_EXPIRED")?;
    record.as_object_mut().ok_or("COMMAND_HISTORY_INVALID")?.remove("grant_id");
    Ok(record)
}

#[derive(Debug)]
pub struct Task {
    frame:Value,
    receiver:Receiver<Value>,
    canceled:Arc<AtomicBool>,
}
impl Drop for Task {
    fn drop(&mut self) {self.canceled.store(true,Ordering::Release);}
}
impl Task {
    pub fn start(frame:&Value,state:&Path,host:&str,grant:Uuid)->Result<Self,String>{
        if grant_id(state,host)!=Some(grant){return Err("UNATTENDED_GRANT_INACTIVE".into());}
        let command=frame["arguments"]["command"].as_str().ok_or("COMMAND_REQUIRED")?;
        if !crate::elevation::valid_command(command){return Err("INVALID_ADMIN_COMMAND".into());}
        let expires=frame["expires_at"].as_u64().ok_or("INVALID_ROUTE_EXPIRY")?;
        // Never execute an elevated command unless the audit intent is durable.
        audit_record(state,frame,&json!({"executed":false,"error":"started","grant_id":grant.to_string()}))?;
        let command=command.to_owned();
        let state=state.to_path_buf();
        let host=host.to_owned();
        let frame_copy=frame.clone();
        let (sender,receiver)=mpsc::channel();
        let canceled=Arc::new(AtomicBool::new(false));
        let worker_canceled=canceled.clone();
        thread::Builder::new().name("desktop-mcp-system-command".into()).spawn(move ||{
            let result=run(&command,&state,&host,expires,grant,&worker_canceled);
            let mut record=result.clone();
            record["grant_id"]=json!(grant.to_string());
            audit(&state,&frame_copy,&record);
            if let Err(error) = remember_result(&state, &frame_copy, grant, &result) {
                eprintln!("Command result was not retained: {error}");
            }
            let _=sender.send(result);
        }).map_err(|_|"SYSTEM_COMMAND_WORKER_UNAVAILABLE")?;
        Ok(Self{frame:frame.clone(),receiver,canceled})
    }
    pub fn matches(&self,frame:&Value)->bool {&self.frame==frame}
    pub fn poll(&self)->Value{
        match self.receiver.try_recv(){
            Ok(result)=>result,
            Err(mpsc::TryRecvError::Empty)=>json!({"pending":true}),
            Err(mpsc::TryRecvError::Disconnected)=>json!({"pending":false,"executed":false,"error":"SYSTEM_COMMAND_WORKER_FAILED"})
        }
    }
}

fn run(command:&str,state:&Path,host:&str,expires:u64,grant:Uuid,canceled:&AtomicBool)->Value {
    let authorized=|| !canceled.load(Ordering::Acquire) && grant_id(state,host)==Some(grant);
    if !authorized(){return json!({"pending":false,"executed":false,"error":"GRANT_REVOKED"});}
    let now=epoch();
    if expires<=now || expires-now>120 {return json!({"pending":false,"executed":false,"error":"ROUTE_EXPIRED"});}
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let powershell=Path::new(&std::env::var_os("SystemRoot").unwrap_or_default())
            .join("System32").join("WindowsPowerShell").join("v1.0").join("powershell.exe");
        let bytes:Vec<u8>=command.encode_utf16().flat_map(u16::to_le_bytes).collect();
        // PowerShell -EncodedCommand is an argument encoding, not an authorization.
        let encoded=base64_encode(&bytes);
        let mut child=match Command::new(powershell)
            .args(["-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",&encoded])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped())
            .creation_flags(0x08000000).spawn(){
                Ok(v)=>v,Err(_)=>return json!({"pending":false,"executed":false,"error":"SHELL_UNAVAILABLE"})
            };
        let stdout=child.stdout.take().unwrap();
        let stderr=child.stderr.take().unwrap();
        let out=thread::spawn(move||capture(stdout));
        let err=thread::spawn(move||capture(stderr));
        let deadline=Instant::now()+Duration::from_secs(expires.saturating_sub(now).min(100));
        loop {
            if !authorized() || epoch()>=expires || Instant::now()>=deadline {
                #[cfg(windows)] {
                    // Stop spawned process descendants as well as the PowerShell parent.
                    let helper=Path::new(&std::env::var_os("SystemRoot").unwrap_or_default())
                        .join("System32").join("taskkill.exe");
                    let _=Command::new(helper).args(["/F","/T","/PID",&child.id().to_string()])
                        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                        .creation_flags(0x08000000).status();
                }
                let _=child.kill();let _=child.wait();
                let _=out.join();let _=err.join();
                return json!({"pending":false,"executed":false,"error":"COMMAND_CANCELED_OR_EXPIRED"});
            }
            match child.try_wait(){
                Ok(Some(status))=>{
                    let (out, out_truncated)=out.join().unwrap_or_default();
                    let (err, err_truncated)=err.join().unwrap_or_default();
                    return json!({"pending":false,"executed":true,"data":{"exit_code":status.code().unwrap_or(-1),
                        "stdout":out,"stderr":err,"truncated":out_truncated || err_truncated}});
                }
                Ok(None)=>thread::sleep(Duration::from_millis(100)),
                Err(_)=>{let _=child.kill();let _=child.wait();return json!({"pending":false,"executed":false,"error":"SHELL_EXIT_FAILED"});}
            }
        }
    }
    #[cfg(not(windows))]
    {let _=(command,state,host,expires);json!({"pending":false,"executed":false,"error":"WINDOWS_ONLY"})}
}

fn capture(mut stream:impl Read)->(String, bool){
    let mut truncated = false;
    let mut output=Vec::new();
    let mut buf=[0u8;2048];
    while let Ok(n)=stream.read(&mut buf) {
        if n==0 {break;}
        let keep = n.min(6000 - output.len());
        truncated |= keep < n;
        output.extend_from_slice(&buf[..keep]);
    }
    (String::from_utf8_lossy(&output).into_owned(), truncated)
}
pub(crate) fn base64_encode(data:&[u8])->String {
    const TABLE:&[u8]=b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s=String::with_capacity(data.len().div_ceil(3)*4);
    for bytes in data.chunks(3){
        let a=bytes[0];let b=*bytes.get(1).unwrap_or(&0);let c=*bytes.get(2).unwrap_or(&0);
        s.push(TABLE[(a>>2) as usize] as char);
        s.push(TABLE[(((a&3)<<4)|(b>>4)) as usize] as char);
        s.push(if bytes.len()>1{TABLE[(((b&15)<<2)|(c>>6)) as usize] as char}else{'='});
        s.push(if bytes.len()>2{TABLE[(c&63) as usize] as char}else{'='});
    }
    s
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_result_retention_is_bounded_and_grant_scoped() {
        let state = tempfile::tempdir().unwrap();
        let grant = Uuid::new_v4();
        let outcome = json!({"executed":true,"data":{"exit_code":7,"stdout":"partial copy"}});
        let expired = json!(Uuid::new_v4().to_string());
        write_record(&state.path().join("command-results.json"), &json!([{
            "run_id":expired,"grant_id":grant.to_string(),
            "finished_at":epoch()-RESULT_RETENTION,"outcome":outcome
        }])).unwrap();
        let mut ids = Vec::new();
        for _ in 0..=RESULT_LIMIT {
            let id = json!(Uuid::new_v4().to_string());
            remember_result(state.path(), &json!({"request_id":id}), grant, &outcome).unwrap();
            ids.push(id);
        }
        let latest = ids.last().unwrap();
        let record = command_result(state.path(), grant, latest).unwrap();
        assert_eq!(record["outcome"], outcome);
        assert!(record.get("grant_id").is_none());
        assert!(command_result(state.path(), Uuid::new_v4(), latest).is_err());
        assert!(command_result(state.path(), grant, &ids[0]).is_err());
        assert!(command_result(state.path(), grant, &expired).is_err());
    }

    #[test]
    fn captured_output_reports_truncation() {
        assert_eq!(capture(&b"abc"[..]), ("abc".into(), false));
        let (out, truncated) = capture(&vec![b'a'; 6001][..]);
        assert_eq!(out.len(), 6000);
        assert!(truncated);
    }
    #[test]fn base64_is_correct(){
        assert_eq!(base64_encode(b""),"");
        assert_eq!(base64_encode(b"f"),"Zg==");
        assert_eq!(base64_encode(b"fo"),"Zm8=");
        assert_eq!(base64_encode(b"foo"),"Zm9v");
    }
    #[test]fn host_binding_expiry_and_revocation_are_fail_closed(){
        let template=json!({"version":1,"scope":"unattended_admin",
            "host_id":"hostA","revoked":false,"issued_at":1000,
            "grant_id":"b05ac90c-c882-4ca4-b7e8-2bff57713818","expires_at":2000});
        assert!(valid_grant(&template,"hostA",1500));
        assert!(!valid_grant(&template,"hostB",1500));
        assert!(!valid_grant(&template,"hostA",2000));
        assert!(!valid_grant(&template,"hostA",999));
        let mut revoked=template.clone();revoked["revoked"]=json!(true);
        assert!(!valid_grant(&revoked,"hostA",1500));
        let mut indefinite=template.clone();indefinite["expires_at"]=Value::Null;
        assert!(valid_grant(&indefinite,"hostA",999999));
    }
    #[test]fn ordinary_directory_cannot_create_unattended_grant(){
        let t=tempfile::tempdir().unwrap();
        assert!(!active(t.path(),"aabbcc","admin_command"));
    }
}
