//! Persistent, fail-closed local review inbox. Recording a review never grants
//! remote tool execution. Request IDs remain spent across process restarts.
use crate::route;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const TTL_SECONDS: u64 = 120;
const CAPACITY: usize = 32;
const MAX_SEEN: usize = 16_384;
const MAX_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
const JOURNAL_NAME: &str = "remote-approval-journal-v1.jsonl";

#[derive(Clone, Copy, PartialEq, Eq)]
enum Status {
    Pending,
    ApprovedForReview,
    Denied,
    Revoked,
    Consumed,
}

struct Entry {
    frame: Value,
    digest: String,
    created: u64,
    status: Status,
    scope: Option<String>,
    granted_at: Option<u64>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Stage {
        version: u32,
        created: u64,
        frame: Value,
        digest: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scope: Option<String>,
    },
    Review {
        version: u32,
        at: u64,
        request_id: String,
        digest: String,
        choice: String,
    },
    AdminCommand {
        version: u32,
        at: u64,
        scope: String,
        duration: Option<String>,
    },
    Revoke {
        version: u32,
        at: u64,
    },
}

fn epoch_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "INVALID_SYSTEM_CLOCK".into())
}

fn fingerprint(frame: &Value) -> Result<String, String> {
    let encoded = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(&encoded)))
}

fn is_active(entry: &Entry, now: u64) -> bool {
    entry.status == Status::Pending
        && entry.created <= now
        && now - entry.created < TTL_SECONDS
        && (entry.frame["version"]!=2 || entry.frame["expires_at"].as_u64().is_some_and(|expires|now<expires))
}

pub struct Inbox {
    journal: File,
    host_id: String,
    entries: HashMap<String, Entry>,
    manual_admin: Option<(String, u64, Option<u64>)>,
}

impl Inbox {
    pub fn open(dir: &Path, own_host_id: &str) -> Result<Self, String> {
        if own_host_id.len() != 32 || !own_host_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("APPROVAL_HOST_ID_INVALID".into());
        }
        let path = dir.join(JOURNAL_NAME);
        if let Ok(metadata) = fs::symlink_metadata(&path) {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err("APPROVAL_JOURNAL_UNSAFE_FILE".into());
            }
            if metadata.len() > MAX_JOURNAL_BYTES {
                return Err("APPROVAL_JOURNAL_FULL".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.permissions().mode() & 0o077 != 0
                {
                    return Err("APPROVAL_JOURNAL_PERMISSIONS".into());
                }
            }
        }
        let mut options = OpenOptions::new();
        options.read(true).append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let journal = options.open(&path)
            .map_err(|e| format!("APPROVAL_JOURNAL_OPEN: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            journal.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("APPROVAL_JOURNAL_PERMISSIONS: {e}"))?;
        }
        let contents = fs::read(&path).map_err(|e| format!("APPROVAL_JOURNAL_READ: {e}"))?;
        if contents.len() as u64 > MAX_JOURNAL_BYTES {
            return Err("APPROVAL_JOURNAL_FULL".into());
        }
        if !contents.is_empty() && contents.last() != Some(&b'\n') {
            return Err("APPROVAL_JOURNAL_INCOMPLETE".into());
        }
        let mut inbox = Self {
            journal,
            host_id: own_host_id.into(),
            entries: HashMap::new(),
            manual_admin: None,
        };
        for line in contents.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
            let event: Event = serde_json::from_slice(line)
                .map_err(|e| format!("APPROVAL_JOURNAL_INVALID: {e}"))?;
            inbox.replay_event(event)?;
        }
        // Executable grants and pending executable reviews never survive a restart.
        // Their spent IDs do, so an interrupted operation requires a fresh request.
        for entry in inbox.entries.values_mut() {
            if entry.frame["version"]==2 && !(entry.frame["tool"]=="request_permission" && entry.status==Status::Consumed) {
                entry.status=Status::Revoked;
            }
        }
        Ok(inbox)
    }

    fn replay_event(&mut self, event: Event) -> Result<(), String> {
        match event {
            Event::Stage { version: 1, created, frame, digest, scope } => {
                route::deny(&frame, &self.host_id)?;
                if (frame["tool"] == "request_permission") != scope.as_ref().is_some_and(|path| !path.is_empty()) {
                    return Err("APPROVAL_JOURNAL_SCOPE_MISMATCH".into());
                }
                if fingerprint(&frame)? != digest {
                    return Err("APPROVAL_JOURNAL_FINGERPRINT_MISMATCH".into());
                }
                let id = frame["request_id"].as_str().ok_or("APPROVAL_ID_MISSING")?;
                if self.entries.contains_key(id) || self.entries.len() >= MAX_SEEN {
                    return Err("APPROVAL_JOURNAL_DUPLICATE_OR_FULL".into());
                }
                self.entries.insert(id.into(), Entry {
                    frame,
                    digest,
                    created,
                    status: Status::Pending,
                    scope,
                    granted_at: None,
                });
            }
            Event::Review { version: 1, at, request_id, digest, choice } => {
                let entry = self.entries.get_mut(&request_id)
                    .ok_or("APPROVAL_JOURNAL_UNKNOWN_REVIEW")?;
                if (entry.status != Status::Pending && !(choice=="consume" && entry.status==Status::ApprovedForReview)) || entry.digest != digest {
                    return Err("APPROVAL_JOURNAL_REVIEW_MISMATCH".into());
                }
                entry.status = match choice.as_str() {
                    "approve" => Status::ApprovedForReview,
                    "deny" => Status::Denied,
                    "consume" => {
                        entry.granted_at = Some(at);
                        Status::Consumed
                    },
                    _ => return Err("APPROVAL_JOURNAL_INVALID_DECISION".into()),
                };
            }
            Event::AdminCommand { version: 1, at, scope, duration } => {
                let value = Self::manual_duration(&scope, duration.as_deref())?;
                self.apply_admin_setting(scope, at, value);
            }
            Event::Revoke { version: 1, at: _ } => {
                self.manual_admin = None;
                for entry in self.entries.values_mut() {
                    if matches!(entry.status,Status::Pending|Status::ApprovedForReview) || entry.frame["tool"]=="request_permission" {
                        entry.status = Status::Revoked;
                    }
                }
            }
            _ => return Err("APPROVAL_JOURNAL_UNSUPPORTED_VERSION".into()),
        }
        Ok(())
    }

    fn append(&mut self, event: &Event) -> Result<(), String> {
        let mut line = serde_json::to_vec(event).map_err(|e| e.to_string())?;
        line.push(b'\n');
        let old_len = self.journal.metadata()
            .map_err(|e| format!("APPROVAL_JOURNAL_METADATA: {e}"))?.len();
        if old_len.saturating_add(line.len() as u64) > MAX_JOURNAL_BYTES {
            return Err("APPROVAL_JOURNAL_FULL".into());
        }
        self.journal.write_all(&line)
            .map_err(|e| format!("APPROVAL_JOURNAL_WRITE: {e}"))?;
        self.journal.sync_all()
            .map_err(|e| format!("APPROVAL_JOURNAL_SYNC: {e}"))
    }

    pub fn stage(&mut self, frame: &Value, scope: Option<&str>) -> Result<Value, String> {
        route::deny(frame, &self.host_id)?;
        if (frame["tool"] == "request_permission") != scope.is_some_and(|path| !path.is_empty()) {
            return Err("APPROVAL_SCOPE_MISMATCH".into());
        }
        let scope = scope.map(str::to_owned);
        let id = frame["request_id"].as_str().ok_or("APPROVAL_ID_MISSING")?;
        if self.entries.contains_key(id) { return Err("APPROVAL_REPLAYED".into()); }
        if self.entries.len() >= MAX_SEEN { return Err("APPROVAL_HISTORY_FULL".into()); }
        let now = epoch_seconds()?;
        if frame["version"]==2 && !frame["expires_at"].as_u64().is_some_and(|expires|expires>now && expires<=now.saturating_add(TTL_SECONDS)) {return Err("APPROVAL_ROUTE_EXPIRED".into());}
        if self.entries.values().filter(|entry| is_active(entry, now)).count() >= CAPACITY {
            return Err("APPROVAL_QUEUE_FULL".into());
        }
        let digest = fingerprint(frame)?;
        let id = id.to_string();
        // Write and fsync before acknowledging. Failed writes never create
        // in-memory approvals, and a torn record prevents unsafe restarts.
        self.append(&Event::Stage {
            version: 1, created: now, frame: frame.clone(), digest: digest.clone(), scope: scope.clone(),
        })?;
        self.entries.insert(id, Entry {
            frame: frame.clone(), digest, created: now, status: Status::Pending, scope, granted_at: None,
        });
        Ok(json!({"queued":true,"remote_tools_enabled":false,"execution_enabled":false}))
    }

    pub fn list(&self) -> Value {
        let now = epoch_seconds().unwrap_or(0);
        let mut pending: Vec<Value> = self.entries.iter()
            .filter(|(_, item)| is_active(item, now))
            .map(|(id, item)| json!({
                "request_id":id,
                "nonce":item.frame["nonce"],
                "request_hash":item.digest,
                "target_host_id":item.frame["target_host_id"],
                "workspace_id":item.frame["workspace_id"],
                "tool":item.frame["tool"],
                "arguments":item.frame.get("arguments").cloned().unwrap_or(json!({})),
                "expires_in_seconds":TTL_SECONDS.saturating_sub(now - item.created).min(item.frame["expires_at"].as_u64().map(|e|e.saturating_sub(now)).unwrap_or(TTL_SECONDS)),
                "execution_enabled":item.frame["version"]==2
            }))
            .collect();
        pending.sort_by(|a,b|a["request_id"].as_str().cmp(&b["request_id"].as_str()));
        json!({"pending":pending,"execution_enabled":false})
    }

    pub fn decide(&mut self, id: &str, nonce: &str, request_hash: &str, choice: &str)
        -> Result<Value, String>
    {
        let now = epoch_seconds()?;
        if !matches!(choice, "approve" | "deny") {
            return Err("INVALID_APPROVAL_DECISION".into());
        }
        let entry = self.entries.get(id).ok_or("APPROVAL_NOT_FOUND_OR_EXPIRED")?;
        if !is_active(entry, now) { return Err("APPROVAL_NOT_FOUND_OR_EXPIRED".into()); }
        if entry.frame["nonce"] != nonce { return Err("APPROVAL_NONCE_MISMATCH".into()); }
        if entry.digest != request_hash { return Err("APPROVAL_REQUEST_MISMATCH".into()); }
        let executable=entry.frame["version"]==2;
        self.append(&Event::Review {
            version: 1, at: now, request_id: id.into(),
            digest: request_hash.into(), choice: choice.into(),
        })?;
        self.entries.get_mut(id).ok_or("APPROVAL_NOT_FOUND")?.status =
            if choice == "approve" { Status::ApprovedForReview } else { Status::Denied };
        Ok(json!({
            "decision":if choice=="approve" {if executable {"approved_once"} else {"approved_for_review"}} else {"denied"},
            "request_id":id,
            "request_hash":request_hash,
            "authorization_granted":executable && choice=="approve",
            "executed":false
        }))
    }

    /// Atomically spend an exact, unexpired local grant before invoking the tool.
    /// A failed execution is spent too; no restart or retry may execute it twice.
    // Trusted SYSTEM service has checked the owner's durable elevated grant,
    // so its exact incoming route can be reviewed and spent without a tray popup.
    // This is never callable over the local API.
    pub fn approve_automatic(&mut self,frame:&Value)->Result<Value,String>{
        let queued=self.stage(frame,None)?;
        if queued["queued"]!=true {return Err("AUTO_STAGE_FAILED".into());}
        let fingerprint=fingerprint(frame)?;
        let id=frame["request_id"].as_str().ok_or("APPROVAL_ID_REQUIRED")?;
        let nonce=frame["nonce"].as_str().ok_or("APPROVAL_NONCE_REQUIRED")?;
        self.decide(id,nonce,&fingerprint,"approve")?;
        Ok(queued)
    }

    pub fn consume(&mut self, frame:&Value)->Result<bool,String> {
        route::deny(frame,&self.host_id)?;
        if frame["version"]!=2 {return Err("EXECUTABLE_ROUTE_REQUIRED".into());}
        let id=frame["request_id"].as_str().ok_or("APPROVAL_ID_REQUIRED")?;
        let entry=self.entries.get(id).ok_or("APPROVAL_NOT_FOUND")?;
        if entry.frame!=*frame || entry.digest!=fingerprint(frame)? {return Err("APPROVAL_REQUEST_MISMATCH".into());}
        let now=epoch_seconds()?;
        if now<entry.created || now-entry.created>=TTL_SECONDS || frame["expires_at"].as_u64().is_none_or(|expires|now>=expires) {return Err("APPROVAL_EXPIRED".into());}
        match entry.status {
            Status::Pending=>return Ok(false),
            Status::ApprovedForReview=>{},
            _=>return Err("APPROVAL_DENIED_REVOKED_OR_SPENT".into()),
        }
        let digest=entry.digest.clone();
        self.append(&Event::Review{version:1,at:now,request_id:id.into(),digest,choice:"consume".into()})?;
        let entry = self.entries.get_mut(id).ok_or("APPROVAL_NOT_FOUND")?;
        entry.status = Status::Consumed;
        entry.granted_at = Some(now);
        Ok(true)
    }

    pub fn has_permission(&self, capability: &str, scope: &str) -> bool {
        epoch_seconds().is_ok_and(|now| self.has_permission_at(capability, scope, now))
    }

    fn has_permission_at(&self, capability: &str, scope: &str, now: u64) -> bool {
        if capability == crate::elevation::COMMAND && self.manual_admin.as_ref().is_some_and(|(path, at, duration)| {
            path == scope && now >= *at && duration.is_none_or(|seconds| now - at < seconds)
        }) {
            return true;
        }
        self.entries.values().any(|entry| {
            let active = entry.granted_at.is_some_and(|granted| {
                now >= granted && entry.frame["arguments"]["duration"].as_str()
                    .and_then(route::permission_duration).is_some_and(|duration| {
                        duration.is_none_or(|seconds| now - granted < seconds)
                    })
            });
            active && entry.status == Status::Consumed
                && entry.frame["tool"] == "request_permission"
                && entry.frame["arguments"]["capability"] == capability
                && entry.scope.as_deref() == Some(scope)
        })
    }

    fn manual_duration(scope: &str, duration: Option<&str>) -> Result<Option<Option<u64>>, String> {
        if scope.is_empty() { return Err("WORKSPACE_ENCODING".into()); }
        duration.map(|value| route::permission_duration(value).ok_or_else(|| "INVALID_PERMISSION_DURATION".into())).transpose()
    }

    fn apply_admin_setting(&mut self, scope: String, at: u64, duration: Option<Option<u64>>) {
        self.manual_admin = duration.map(|seconds| (scope, at, seconds));
        for entry in self.entries.values_mut() {
            if entry.frame["tool"] == crate::elevation::COMMAND ||
                (entry.frame["tool"] == "request_permission" && entry.frame["arguments"]["capability"] == crate::elevation::COMMAND)
            {
                entry.status = Status::Revoked;
            }
        }
    }

    pub fn set_admin_command(&mut self, scope: &str, duration: Option<&str>) -> Result<(), String> {
        let value = Self::manual_duration(scope, duration)?;
        let at = epoch_seconds()?;
        self.append(&Event::AdminCommand { version: 1, at, scope: scope.into(), duration: duration.map(str::to_owned) })?;
        self.apply_admin_setting(scope.into(), at, value);
        Ok(())
    }

    pub fn clear(&mut self) -> Result<(), String> {
        self.append(&Event::Revoke { version: 1, at: epoch_seconds()? })?;
        self.manual_admin = None;
        for entry in self.entries.values_mut() {
            if matches!(entry.status,Status::Pending|Status::ApprovedForReview) || entry.frame["tool"]=="request_permission" { entry.status = Status::Revoked; }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn host() -> &'static str { "aabbccddeeff00112233445566778899" }
    fn frame() -> Value {
        json!({"type":"route_intent","version":1,
            "request_id":"21b664fb-676b-48dd-9e46-f7406fc061d8",
            "target_host_id":host(),"workspace_id":"default",
            "tool":"fs_read","nonce":"ab".repeat(32)})
    }

    fn executable()->Value {let mut f=frame();f["version"]=json!(2);f["tool"]=json!("git_status");f["arguments"]=json!({});f["expires_at"]=json!(epoch_seconds().unwrap()+100);f}
    #[test]
    fn manual_admin_command_duration_and_revocation_survive_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut inbox = Inbox::open(dir.path(), host()).unwrap();
        let capability = crate::elevation::COMMAND;
        assert!(inbox.set_admin_command("/project", Some("18446744073709551615m")).is_err());
        inbox.set_admin_command("/project", Some("7m")).unwrap();
        let start = inbox.manual_admin.as_ref().unwrap().1;
        assert!(inbox.has_permission_at(capability, "/project", start + 419));
        assert!(!inbox.has_permission_at(capability, "/project", start + 420));
        assert!(!inbox.has_permission_at(capability, "/other", start));
        inbox.set_admin_command("/project", Some("permanent")).unwrap();
        drop(inbox);
        let mut inbox = Inbox::open(dir.path(), host()).unwrap();
        assert!(inbox.has_permission_at(capability, "/project", start + 86_400));
        inbox.set_admin_command("/project", None).unwrap();
        drop(inbox);
        let inbox = Inbox::open(dir.path(), host()).unwrap();
        assert!(!inbox.has_permission(capability, "/project"));
    }

    #[test]
    fn timed_permissions_expire_and_permanent_renewal_survives_restart() {
        let dir = tempfile::tempdir().unwrap();
        let mut inbox = Inbox::open(dir.path(), host()).unwrap();
        let mut request = executable();
        request["tool"] = json!("request_permission");
        request["arguments"] = json!({"capability":"git_status","duration":"30m"});
        assert!(inbox.stage(&request, None).is_err());
        inbox.stage(&request, Some("/project")).unwrap();
        let item = inbox.list()["pending"][0].clone();
        let id = request["request_id"].as_str().unwrap();
        let nonce = request["nonce"].as_str().unwrap().to_owned();
        inbox.decide(id, &nonce, item["request_hash"].as_str().unwrap(), "approve").unwrap();
        assert!(!inbox.has_permission("git_status", "/project"));
        assert!(inbox.consume(&request).unwrap());
        let started = inbox.entries[id].granted_at.unwrap();
        assert!(inbox.has_permission_at("git_status", "/project", started + 1799));
        assert!(!inbox.has_permission_at("git_status", "/project", started + 1800));
        assert!(!inbox.has_permission_at("git_status", "/other", started));
        assert!(!inbox.has_permission_at("fs_read", "/project", started));

        request["request_id"] = json!(uuid::Uuid::new_v4().to_string());
        request["arguments"]["duration"] = json!("permanent");
        inbox.stage(&request, Some("/project")).unwrap();
        let item = inbox.list()["pending"][0].clone();
        inbox.decide(request["request_id"].as_str().unwrap(), &nonce, item["request_hash"].as_str().unwrap(), "approve").unwrap();
        assert!(inbox.consume(&request).unwrap());
        drop(inbox);
        let mut inbox = Inbox::open(dir.path(), host()).unwrap();
        assert!(inbox.has_permission_at("git_status", "/project", started + 3600));
        inbox.clear().unwrap();
        drop(inbox);
        assert!(!Inbox::open(dir.path(), host()).unwrap().has_permission("git_status", "/project"));
    }

    #[test] fn executable_grant_is_exact_expiring_revocable_and_one_use() {
        let dir=tempfile::tempdir().unwrap();let mut inbox=Inbox::open(dir.path(),host()).unwrap();let f=executable();inbox.stage(&f, None).unwrap();
        assert!(!inbox.consume(&f).unwrap());let id=f["request_id"].as_str().unwrap();let digest=fingerprint(&f).unwrap();
        inbox.decide(id,f["nonce"].as_str().unwrap(),&digest,"approve").unwrap();
        let mut changed=f.clone();changed["arguments"]=json!({"path":"outside"});assert!(inbox.consume(&changed).is_err());
        let mut changed=f.clone();changed["expires_at"]=json!(epoch_seconds().unwrap()+99);assert!(inbox.consume(&changed).is_err());
        assert!(inbox.consume(&f).unwrap());assert!(inbox.consume(&f).is_err());
        drop(inbox);let mut inbox=Inbox::open(dir.path(),host()).unwrap();assert!(inbox.stage(&f, None).is_err());assert!(inbox.consume(&f).is_err());
    }
    #[test] fn executable_grants_never_survive_revocation_or_restart() {
        for restart in [false,true] {
            let dir=tempfile::tempdir().unwrap();let mut inbox=Inbox::open(dir.path(),host()).unwrap();let f=executable();inbox.stage(&f, None).unwrap();
            inbox.decide(f["request_id"].as_str().unwrap(),f["nonce"].as_str().unwrap(),&fingerprint(&f).unwrap(),"approve").unwrap();
            if restart {drop(inbox);inbox=Inbox::open(dir.path(),host()).unwrap();}else{inbox.clear().unwrap();}
            assert!(inbox.consume(&f).is_err());
        }
    }
    #[test] fn expired_executable_frame_is_not_staged() {
        let dir=tempfile::tempdir().unwrap();let mut inbox=Inbox::open(dir.path(),host()).unwrap();let mut f=executable();f["expires_at"]=json!(epoch_seconds().unwrap());assert!(inbox.stage(&f, None).is_err());
    }

    #[test]
    fn approval_survives_restart_and_is_bound_to_exact_frame() {
        let tmp=tempfile::tempdir().unwrap();
        let mut inbox=Inbox::open(tmp.path(),host()).unwrap();
        inbox.stage(&frame(), None).unwrap();
        let item=inbox.list()["pending"][0].clone();
        let id=item["request_id"].as_str().unwrap();
        let hash=item["request_hash"].as_str().unwrap();
        assert!(inbox.decide(id,&"cd".repeat(32),hash,"approve").is_err());
        assert!(inbox.decide(id,&"ab".repeat(32),"wrong-hash","approve").is_err());
        drop(inbox);
        let mut inbox=Inbox::open(tmp.path(),host()).unwrap();
        assert_eq!(inbox.list()["pending"].as_array().unwrap().len(),1);
        let result=inbox.decide(id,&"ab".repeat(32),hash,"approve").unwrap();
        assert_eq!(result["authorization_granted"],false);
        assert_eq!(result["executed"],false);
        drop(inbox);
        let mut inbox=Inbox::open(tmp.path(),host()).unwrap();
        assert!(inbox.stage(&frame(), None).is_err());
        assert!(inbox.decide(id,&"ab".repeat(32),hash,"deny").is_err());
        assert_eq!(inbox.list()["pending"].as_array().unwrap().len(),0);
    }

    #[test]
    fn revoked_requests_remain_spent_after_restart() {
        let tmp=tempfile::tempdir().unwrap();
        let mut inbox=Inbox::open(tmp.path(),host()).unwrap();
        inbox.stage(&frame(), None).unwrap();
        inbox.clear().unwrap();
        drop(inbox);
        let mut inbox=Inbox::open(tmp.path(),host()).unwrap();
        assert!(inbox.stage(&frame(), None).is_err());
        assert_eq!(inbox.list()["pending"].as_array().unwrap().len(),0);
    }

    #[test]
    fn expired_requests_cannot_be_revived_or_replayed() {
        let tmp=tempfile::tempdir().unwrap();
        let mut inbox=Inbox::open(tmp.path(),host()).unwrap();
        inbox.stage(&frame(), None).unwrap();
        let id=frame()["request_id"].as_str().unwrap().to_string();
        inbox.entries.get_mut(&id).unwrap().created=epoch_seconds().unwrap()-TTL_SECONDS;
        let hash=fingerprint(&frame()).unwrap();
        assert!(inbox.decide(&id,&"ab".repeat(32),&hash,"approve").is_err());
        drop(inbox);
        let mut inbox=Inbox::open(tmp.path(),host()).unwrap();
        assert!(inbox.stage(&frame(), None).is_err());
    }

    #[test]
    fn corrupted_journal_fails_closed_instead_of_resetting_replay_history() {
        let tmp=tempfile::tempdir().unwrap();
        let mut inbox=Inbox::open(tmp.path(),host()).unwrap();
        inbox.stage(&frame(), None).unwrap();
        drop(inbox);
        let path=tmp.path().join(JOURNAL_NAME);
        std::fs::OpenOptions::new().append(true).open(&path).unwrap()
            .write_all(b"{\"kind\":\"stage\"").unwrap();
        assert!(Inbox::open(tmp.path(),host()).is_err());
    }

    #[test]
    fn frame_changes_or_bad_host_cannot_bypass_replay() {
        let tmp=tempfile::tempdir().unwrap();
        let mut inbox=Inbox::open(tmp.path(),host()).unwrap();
        inbox.stage(&frame(), None).unwrap();
        let mut changed=frame();
        changed["nonce"]=json!("cd".repeat(32));
        assert!(inbox.stage(&changed, None).is_err());
        changed["request_id"]=json!("c92a6769-ff00-4610-bc6a-c6d444820401");
        changed["target_host_id"]=json!("00000000000000000000000000000000");
        assert!(inbox.stage(&changed, None).is_err());
    }
}
