//! Persistent, keyed audit journal for operator-submitted routed requests.
//! No execution grants are stored or produced by this module.
use crate::policy::Intent;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    sync::{Mutex, OnceLock},
    fs::{self, File, OpenOptions},
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const KEY_FILE: &str = "route-audit-v1.key";
const LOCK_FILE: &str = "route-audit-v1.lock";
const LOG_FILE: &str = "route-audit-v1.jsonl";
const MAX_BYTES: u64 = 16 * 1024 * 1024;
const MAX_REQUESTS: usize = 16_384;
const ZERO_MAC: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    version: u32,
    sequence: u64,
    at: u64,
    event: String,
    request_id: String,
    host_id: String,
    intent_sha256: String,
    previous_mac: String,
    #[serde(default,skip_serializing_if="Option::is_none")]
    operation_sha256:Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    #[serde(flatten)]
    payload: Payload,
    mac: String,
}

fn hmac_sha256(key: &[u8], input: &[u8]) -> String {
    assert!(key.len() <= 64);
    let mut inner_key = [0x36_u8; 64];
    let mut outer_key = [0x5c_u8; 64];
    for (i, value) in key.iter().enumerate() {
        inner_key[i] ^= value;
        outer_key[i] ^= value;
    }
    let mut inner = Sha256::new();
    inner.update(inner_key);
    inner.update(input);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_key);
    outer.update(inner);
    hex::encode(outer.finalize())
}

fn fingerprint(intent: &Intent) -> Result<String, String> {
    serde_json::to_vec(intent)
        .map(|bytes| hex::encode(Sha256::digest(bytes)))
        .map_err(|e| format!("AUDIT_ENCODE_INTENT: {e}"))
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now().duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "AUDIT_INVALID_SYSTEM_CLOCK".into())
}

fn validate_file(path: &Path) -> Result<Option<u64>, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if !meta.is_file() || meta.file_type().is_symlink() {
                return Err("AUDIT_UNSAFE_FILE".into());
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::{MetadataExt, PermissionsExt};
                if meta.uid() != unsafe { libc::geteuid() }
                    || meta.permissions().mode() & 0o077 != 0
                {
                    return Err("AUDIT_UNSAFE_PERMISSIONS".into());
                }
            }
            Ok(Some(meta.len()))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("AUDIT_METADATA: {e}")),
    }
}

fn create_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}

static ACTIVE_AUDIT_DIRS: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

struct DirGuard {
    path: PathBuf,
}

impl DirGuard {
    fn acquire(directory: &Path) -> Result<Self, String> {
        let path=fs::canonicalize(directory)
            .map_err(|e|format!("AUDIT_CANONICALIZE: {e}"))?;
        let registry=ACTIVE_AUDIT_DIRS.get_or_init(||Mutex::new(HashSet::new()));
        let mut active=registry.lock().map_err(|_|"AUDIT_REGISTRY_POISONED")?;
        if !active.insert(path.clone()) {
            return Err("AUDIT_ALREADY_OPEN_IN_PROCESS".into());
        }
        Ok(Self{path})
    }
}

impl Drop for DirGuard {
    fn drop(&mut self) {
        if let Some(registry)=ACTIVE_AUDIT_DIRS.get() {
            if let Ok(mut active)=registry.lock() {
                active.remove(&self.path);
            }
        }
    }
}

pub struct Audit {
    _guard: DirGuard,
    _lock: File,
    key: [u8; 32],
    file: File,
    sequence: u64,
    previous_mac: String,
    seen: HashMap<String, (String, String)>,
    results: HashSet<String>,
}

impl Audit {
    pub fn open(dir: &Path) -> Result<Self, String> {
        #[cfg(windows)] crate::windows_acl::verify_private(dir)?;
        let meta = fs::symlink_metadata(dir)
            .map_err(|e| format!("AUDIT_DIRECTORY: {e}"))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            return Err("AUDIT_UNSAFE_DIRECTORY".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if meta.uid() != unsafe { libc::geteuid() }
                || meta.permissions().mode() & 0o077 != 0
            {
                return Err("AUDIT_UNSAFE_DIRECTORY_PERMISSIONS".into());
            }
        }
        let lock_path = dir.join(LOCK_FILE);
        validate_file(&lock_path)?;
        let mut lock_options=OpenOptions::new();
        lock_options.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            lock_options.mode(0o600);
        }
        let lock=lock_options.open(&lock_path)
            .map_err(|e|format!("AUDIT_LOCK_OPEN: {e}"))?;
        lock.try_lock().map_err(|_| "AUDIT_LOCK_BUSY".to_string())?;
        let guard=DirGuard::acquire(dir)?;
        let key_path = dir.join(KEY_FILE);
        let log_path = dir.join(LOG_FILE);
        let key_size = validate_file(&key_path)?;
        let log_size = validate_file(&log_path)?;
        if key_size.is_none() != log_size.is_none() {
            return Err("AUDIT_MISSING_KEY_OR_LOG".into());
        }
        if key_size.is_none() {
            let mut key = [0u8; 32];
            OsRng.fill_bytes(&mut key);
            let mut key_file = create_options().open(&key_path)
                .map_err(|e| format!("AUDIT_KEY_CREATE: {e}"))?;
            key_file.write_all(&key)
                .and_then(|_| key_file.sync_all())
                .map_err(|e| format!("AUDIT_KEY_WRITE: {e}"))?;
            let mut log_file = create_options().open(&log_path)
                .map_err(|e| format!("AUDIT_LOG_CREATE: {e}"))?;
            log_file.write_all(b"").and_then(|_| log_file.sync_all())
                .map_err(|e| format!("AUDIT_LOG_WRITE: {e}"))?;
        }
        if validate_file(&key_path)? != Some(32) {
            return Err("AUDIT_INVALID_KEY".into());
        }
        let key: [u8; 32] = fs::read(&key_path)
            .map_err(|e| format!("AUDIT_KEY_READ: {e}"))?
            .try_into().map_err(|_| "AUDIT_INVALID_KEY")?;
        let length = validate_file(&log_path)?.ok_or("AUDIT_MISSING_LOG")?;
        if length > MAX_BYTES { return Err("AUDIT_LOG_FULL".into()); }
        let data = fs::read(&log_path).map_err(|e| format!("AUDIT_LOG_READ: {e}"))?;
        if !data.is_empty() && data.last() != Some(&b'\n') {
            return Err("AUDIT_INCOMPLETE_LOG".into());
        }
        let file = OpenOptions::new().append(true).open(&log_path)
            .map_err(|e| format!("AUDIT_LOG_OPEN: {e}"))?;
        let mut ledger = Self {
            _guard: guard, _lock: lock,
            key, file, sequence: 0, previous_mac: ZERO_MAC.into(),
            seen: HashMap::new(), results: HashSet::new(),
        };
        for line in data.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()) {
            let record: Record = serde_json::from_slice(line)
                .map_err(|e| format!("AUDIT_CORRUPT_RECORD: {e}"))?;
            ledger.validate_record(&record)?;
        }
        Ok(ledger)
    }

    fn validate_record(&mut self, record: &Record) -> Result<(), String> {
        let p = &record.payload;
        if p.version != 1 || p.sequence != self.sequence + 1
            || p.previous_mac != self.previous_mac
            || p.host_id.len() != 32
            || !p.host_id.bytes().all(|b| b.is_ascii_hexdigit())
            || p.intent_sha256.len() != 64
            || !p.intent_sha256.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return Err("AUDIT_INVALID_CHAIN".into());
        }
        let encoded = serde_json::to_vec(p).map_err(|e| e.to_string())?;
        let mac = hmac_sha256(&self.key, &encoded);
        // Constant-work tag comparison (the journal and key remain private).
        if mac.len() != record.mac.len()
            || mac.bytes().zip(record.mac.bytes()).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) != 0
        {
            return Err("AUDIT_BAD_MAC".into());
        }
        match p.event.as_str() {
            "reserved" => {
                if self.seen.len() >= MAX_REQUESTS || self.seen.contains_key(&p.request_id) {
                    return Err("AUDIT_DUPLICATE_OR_FULL".into());
                }
                self.seen.insert(p.request_id.clone(),
                    (p.host_id.clone(), p.intent_sha256.clone()));
            }
            "requires_local_approval" | "completed" => {
                if self.seen.get(&p.request_id) !=
                    Some(&(p.host_id.clone(), p.intent_sha256.clone()))
                    || !self.results.insert(p.request_id.clone())
                {
                    return Err("AUDIT_UNMATCHED_RESULT".into());
                }
            }
            _ => return Err("AUDIT_UNSUPPORTED_EVENT".into()),
        }
        self.sequence = p.sequence;
        self.previous_mac = record.mac.clone();
        Ok(())
    }

    fn append_bound(&mut self, intent: &Intent, host: &str, event: &str, binding:Option<String>) -> Result<(), String> {
        let p = Payload {
            version: 1, sequence: self.sequence + 1, at: unix_now()?,
            event: event.into(), request_id: intent.request_id.clone(),
            host_id: host.into(), intent_sha256: fingerprint(intent)?,
            previous_mac: self.previous_mac.clone(),
            operation_sha256:binding,
        };
        let encoded = serde_json::to_vec(&p).map_err(|e| e.to_string())?;
        let record = Record { mac: hmac_sha256(&self.key, &encoded), payload: p };
        let mut bytes = serde_json::to_vec(&record).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        if self.file.metadata().map_err(|e| e.to_string())?.len()
            .saturating_add(bytes.len() as u64) > MAX_BYTES {
            return Err("AUDIT_LOG_FULL".into());
        }
        self.file.write_all(&bytes).map_err(|e| format!("AUDIT_LOG_WRITE: {e}"))?;
        self.file.sync_all().map_err(|e| format!("AUDIT_LOG_SYNC: {e}"))?;
        self.validate_record(&record)
    }

    fn append(&mut self,intent:&Intent,host:&str,event:&str)->Result<(),String> {self.append_bound(intent,host,event,None)}
    pub fn reserve_bound(&mut self,intent:&Intent,host:&str,frame:&serde_json::Value)->Result<(),String> {
        if self.seen.contains_key(&intent.request_id) || self.seen.len()>=MAX_REQUESTS || intent.target_host_id!=host {return Err("AUDIT_REPLAYED_OR_INVALID_REQUEST".into());}
        self.append_bound(intent,host,"reserved",Some(crate::broker::digest(frame)))
    }

    pub fn reserve(&mut self, intent: &Intent, authenticated_host: &str)
        -> Result<(), String>
    {
        if self.seen.contains_key(&intent.request_id) { return Err("AUDIT_REPLAYED_REQUEST".into()); }
        if self.seen.len() >= MAX_REQUESTS { return Err("AUDIT_HISTORY_FULL".into()); }
        if intent.target_host_id != authenticated_host {
            return Err("AUDIT_HOST_MISMATCH".into());
        }
        self.append(intent, authenticated_host, "reserved")
    }

    pub fn record_completion(&mut self,intent:&Intent,host:&str)->Result<(),String> {
        if self.seen.get(&intent.request_id)!=Some(&(host.to_owned(),fingerprint(intent)?)) || self.results.contains(&intent.request_id) {return Err("AUDIT_INVALID_RESULT".into());}
        self.append(intent,host,"completed")
    }

    pub fn record_denial(&mut self, intent: &Intent, authenticated_host: &str)
        -> Result<(), String>
    {
        if self.seen.get(&intent.request_id) !=
            Some(&(authenticated_host.to_owned(), fingerprint(intent)?))
            || self.results.contains(&intent.request_id) {
            return Err("AUDIT_INVALID_RESULT".into());
        }
        self.append(intent, authenticated_host, "requires_local_approval")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_temp()->tempfile::TempDir {
        #[cfg(windows)] let dir=tempfile::tempdir_in(std::env::var_os("USERPROFILE").unwrap()).unwrap();
        #[cfg(not(windows))] let dir=tempfile::tempdir().unwrap();
        #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;fs::set_permissions(dir.path(),fs::Permissions::from_mode(0o700)).unwrap();}
        dir
    }

    fn intent() -> Intent {
        Intent {
            request_id: "21b664fb-676b-48dd-9e46-f7406fc061d8".into(),
            target_host_id: "aabbccddeeff00112233445566778899".into(),
            workspace_id: "default".into(),
            tool: "fs_read".into(),
        }
    }

    #[test]
    fn hmac_matches_rfc4231_vector() {
        let key = [0x0b_u8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(mac,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    }

    #[test]
    fn spent_id_survives_restart_and_result_is_audited() {
        let temp = private_temp();
        let mut audit = Audit::open(temp.path()).unwrap();
        audit.reserve(&intent(), &intent().target_host_id).unwrap();
        drop(audit);
        let mut audit = Audit::open(temp.path()).unwrap();
        assert!(audit.reserve(&intent(), &intent().target_host_id).is_err());
        audit.record_denial(&intent(), &intent().target_host_id).unwrap();
        drop(audit);
        let mut audit = Audit::open(temp.path()).unwrap();
        assert!(audit.reserve(&intent(), &intent().target_host_id).is_err());
        assert!(audit.record_denial(&intent(), &intent().target_host_id).is_err());
    }

    #[test]
    fn corrupt_log_and_mismatched_key_fail_closed() {
        let temp = private_temp();
        let mut audit = Audit::open(temp.path()).unwrap();
        audit.reserve(&intent(), &intent().target_host_id).unwrap();
        drop(audit);
        let log = temp.path().join(LOG_FILE);
        let mut data = fs::read(&log).unwrap();
        let pos = data.iter().position(|byte| *byte == b'a').unwrap();
        data[pos] = b'B';
        fs::write(&log, data).unwrap();
        assert!(Audit::open(temp.path()).is_err());
        let temp = private_temp();
        let mut audit = Audit::open(temp.path()).unwrap();
        audit.reserve(&intent(), &intent().target_host_id).unwrap();
        drop(audit);
        fs::write(temp.path().join(KEY_FILE), [0x33u8;32]).unwrap();
        assert!(Audit::open(temp.path()).is_err());
    }

    #[test]
    fn truncated_log_and_missing_key_fail_closed() {
        let temp = private_temp();
        let mut audit = Audit::open(temp.path()).unwrap();
        audit.reserve(&intent(), &intent().target_host_id).unwrap();
        drop(audit);
        OpenOptions::new().append(true).open(temp.path().join(LOG_FILE)).unwrap()
            .write_all(b"{\"broken\":").unwrap();
        assert!(Audit::open(temp.path()).is_err());
        let temp = private_temp();
        let mut audit = Audit::open(temp.path()).unwrap();
        audit.reserve(&intent(), &intent().target_host_id).unwrap();
        drop(audit);
        fs::remove_file(temp.path().join(KEY_FILE)).unwrap();
        assert!(Audit::open(temp.path()).is_err());
    }

    #[test]
    fn second_gateway_cannot_share_active_audit_directory() {
        let temp = private_temp();
        let first=Audit::open(temp.path()).unwrap();
        assert!(Audit::open(temp.path()).is_err());
        drop(first);
        assert!(Audit::open(temp.path()).is_ok());
    }

    #[test]
    fn mismatched_result_cannot_poison_existing_journal() {
        let temp = private_temp();
        let mut audit = Audit::open(temp.path()).unwrap();
        audit.reserve(&intent(), &intent().target_host_id).unwrap();
        let mut modified = intent();
        modified.tool = "git_status".into();
        assert!(audit.record_denial(&modified, &intent().target_host_id).is_err());
        assert!(audit.record_denial(&intent(), "00000000000000000000000000000000").is_err());
        drop(audit);
        let mut audit = Audit::open(temp.path()).unwrap();
        assert!(audit.record_denial(&intent(), &intent().target_host_id).is_ok());
    }

    #[test]
    fn wrong_host_never_reserves_request() {
        let temp = private_temp();
        let mut audit = Audit::open(temp.path()).unwrap();
        assert!(audit.reserve(&intent(), "00000000000000000000000000000000").is_err());
        assert!(audit.reserve(&intent(), &intent().target_host_id).is_ok());
    }
}
