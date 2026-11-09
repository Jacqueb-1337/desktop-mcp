//! Persistent terminals are served only by the authenticated Windows service.
#[cfg(windows)]
use serde_json::json;
use serde_json::Value;
use std::path::Path;
use uuid::Uuid;

pub fn is_tool(tool: &str) -> bool {
    matches!(
        tool,
        "terminal_open" | "terminal_list" | "terminal_run" | "terminal_read" | "terminal_close"
    )
}

pub fn start_cleanup(state: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        windows::start_cleanup(state)
    }
    #[cfg(not(windows))]
    {
        let _ = state;
        Ok(())
    }
}

pub fn valid_args(tool: &str, args: &Value) -> bool {
    let Some(fields) = args.as_object() else {
        return false;
    };
    let id = |name: &str| {
        args[name].as_str().is_some_and(|value| {
            Uuid::parse_str(value).is_ok_and(|uuid| {
                uuid.get_version() == Some(uuid::Version::Random) && uuid.to_string() == value
            })
        })
    };
    match tool {
        "terminal_open" | "terminal_list" => fields.is_empty(),
        "terminal_run" => {
            id("terminal_id")
                && fields.len() == 2 + usize::from(fields.contains_key("timeout_seconds"))
                && args["command"]
                    .as_str()
                    .is_some_and(crate::elevation::valid_command)
                && fields
                    .get("timeout_seconds")
                    .is_none_or(|value| value.as_u64().is_some_and(|n| (1..=28800).contains(&n)))
        }
        "terminal_read" => {
            id("terminal_id")
                && fields.len() == 1 + usize::from(fields.contains_key("offset"))
                && fields.get("offset").is_none_or(Value::is_u64)
        }
        "terminal_close" => id("terminal_id") && fields.len() == 1,
        _ => false,
    }
}

#[cfg(not(windows))]
#[derive(Debug, Default)]
pub struct Pool;

#[cfg(not(windows))]
impl Pool {
    pub fn call(
        &mut self,
        _: &Path,
        _: &str,
        _: Uuid,
        _: &str,
        _: &Value,
    ) -> Result<Value, String> {
        Err("WINDOWS_ONLY".into())
    }
    pub fn close_all(&mut self) {}
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::unattended;
    use serde::{Deserialize, Serialize};
    use std::{
        collections::{HashMap, VecDeque},
        fs,
        io::{BufRead, BufReader, Read, Write},
        os::windows::{
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
            process::CommandExt,
        },
        path::PathBuf,
        process::{Child, Command, Stdio},
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc, Mutex,
        },
        thread,
        time::{Duration, Instant},
    };
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    const ACTIVE_LIMIT: usize = 4;
    const OUTPUT_LIMIT: usize = 4 * 1024 * 1024;
    const STORAGE_LIMIT: u64 = 64 * 1024 * 1024;
    const RETENTION: u64 = 24 * 60 * 60;
    const IDLE_LIMIT: Duration = Duration::from_secs(30 * 60);
    const DEFAULT_TIMEOUT: u64 = 2 * 60 * 60;
    const CHECKPOINT: Duration = Duration::from_secs(5);
    const RECORD_LIMIT: u64 = 2 * OUTPUT_LIMIT as u64 + 65536;

    const BOOTSTRAP: &str = r#"
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$ProgressPreference = 'SilentlyContinue'
while ($null -ne ($__dmcp_line = [Console]::ReadLine())) {
    $__dmcp_input = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($__dmcp_line)) | ConvertFrom-Json
    $global:LASTEXITCODE = 0
    try {
        . ([ScriptBlock]::Create($__dmcp_input.command))
        $__dmcp_ok = $?
        $__dmcp_exit = $global:LASTEXITCODE
        if (!$__dmcp_ok -and $__dmcp_exit -eq 0) { $__dmcp_exit = 1 }
    } catch {
        [Console]::Error.WriteLine($_.ToString())
        $__dmcp_exit = 1
    }
    [Console]::Out.WriteLine()
    [Console]::Out.WriteLine('__DMCP_DONE__' + $__dmcp_input.id + ':' + $__dmcp_exit)
    [Console]::Out.Flush()
}
"#;

    #[derive(Debug, Serialize, Deserialize)]
    struct CommandRecord {
        id: Uuid,
        exit_code: Option<i32>,
        status: String,
    }

    #[derive(Debug)]
    struct Record {
        id: Uuid,
        grant: Uuid,
        closed_at: Option<u64>,
        reason: Option<String>,
        start: u64,
        output: VecDeque<u8>,
        commands: VecDeque<CommandRecord>,
    }

    #[derive(Serialize, Deserialize)]
    struct Stored {
        id: Uuid,
        grant: Uuid,
        saved_at: u64,
        closed_at: Option<u64>,
        reason: Option<String>,
        start: u64,
        output: String,
        commands: VecDeque<CommandRecord>,
    }

    impl Record {
        fn append(&mut self, bytes: &[u8]) {
            let discard = (self.output.len() + bytes.len()).saturating_sub(OUTPUT_LIMIT);
            self.output.drain(..discard);
            self.start += discard as u64;
            self.output.extend(bytes);
        }
        fn summary(&self) -> Value {
            json!({"terminal_id":self.id.to_string(),"state":if self.closed_at.is_some() {"closed"}
                else if self.commands.back().is_some_and(|command|command.status=="running") {"running"}
                else {"idle"},"reason":self.reason,"latest_command":self.commands.back()})
        }
        fn read(&self, offset: Option<u64>) -> Value {
            let end = self.start + self.output.len() as u64;
            let requested = offset.unwrap_or_else(|| end.saturating_sub(4096));
            let from = requested.clamp(self.start, end);
            let bytes: Vec<u8> = self
                .output
                .iter()
                .skip((from - self.start) as usize)
                .take(4096)
                .copied()
                .collect();
            json!({"terminal":self.summary(),"commands":self.commands,
                "output":String::from_utf8_lossy(&bytes),"offset":from,
                "next_offset":from+bytes.len() as u64,"end_offset":end,"truncated":requested<self.start})
        }
        fn save(&self, path: &Path) -> Result<(), String> {
            let output: String = self
                .output
                .iter()
                .flat_map(|byte| {
                    let alphabet = b"0123456789abcdef";
                    [
                        alphabet[(byte >> 4) as usize] as char,
                        alphabet[(byte & 15) as usize] as char,
                    ]
                })
                .collect();
            unattended::write_record(
                path,
                &json!({
                    "id":self.id.to_string(),"grant":self.grant.to_string(),"saved_at":unattended::epoch(),
                    "closed_at":self.closed_at,"reason":self.reason,"start":self.start,"output":output,"commands":self.commands
                }),
            )
        }
    }

    fn load(path: &Path) -> Option<Record> {
        let file = fs::File::open(path).ok()?;
        if file.metadata().ok()?.len() > RECORD_LIMIT {
            return None;
        }
        let stored: Stored = serde_json::from_reader(file.take(RECORD_LIMIT)).ok()?;
        if stored.output.len() > 2 * OUTPUT_LIMIT || stored.commands.len() > 64 {
            return None;
        }
        let mut commands = stored.commands;
        if let Some(command) = commands
            .back_mut()
            .filter(|command| command.status == "running")
        {
            command.status = "interrupted".into();
        }
        Some(Record {
            id: stored.id,
            grant: stored.grant,
            closed_at: Some(stored.closed_at.unwrap_or(stored.saved_at)),
            reason: stored.reason.or_else(|| Some("service_restarted".into())),
            start: stored.start,
            output: hex::decode(stored.output).ok()?.into(),
            commands,
        })
    }

    fn records(directory: &Path) -> Vec<(PathBuf, u64, u64)> {
        let Ok(entries) = fs::read_dir(directory) else {
            return Vec::new();
        };
        entries
            .flatten()
            .filter_map(|entry| {
                let path = entry.path();
                if path.extension()?.to_str()? != "json" {
                    return None;
                }
                Uuid::parse_str(path.file_stem()?.to_str()?).ok()?;
                let metadata = entry.metadata().ok()?;
                let time = metadata
                    .modified()
                    .ok()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()?
                    .as_secs();
                Some((path, metadata.len(), time))
            })
            .collect()
    }

    pub(super) fn start_cleanup(state: &Path) -> Result<(), String> {
        let directory = state.join("terminal-history");
        thread::Builder::new()
            .name("desktop-mcp-terminal-cleanup".into())
            .spawn(move || loop {
                let now = unattended::epoch();
                for (path, _, modified) in records(&directory) {
                    // Active shells close or checkpoint well within the retention period.
                    if now.saturating_sub(modified) >= RETENTION {
                        let _ = fs::remove_file(path);
                    }
                }
                if let Ok(entries) = fs::read_dir(&directory) {
                    for entry in entries
                        .flatten()
                        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "tmp"))
                    {
                        if entry
                            .metadata()
                            .ok()
                            .and_then(|m| m.modified().ok())
                            .and_then(|at| at.elapsed().ok())
                            .is_some_and(|age| age.as_secs() >= RETENTION)
                        {
                            let _ = fs::remove_file(entry.path());
                        }
                    }
                }
                thread::sleep(Duration::from_secs(60));
            })
            .map(|_| ())
            .map_err(|_| "TERMINAL_CLEANUP_UNAVAILABLE".into())
    }

    fn prune(directory: &Path, active: &HashMap<Uuid, Session>) {
        let mut entries = records(directory);
        // Reserve room for all active sessions to grow to their maximum size.
        let mut total: u64 = entries
            .iter()
            .filter(|(path, _, _)| {
                path.file_stem()
                    .and_then(|id| id.to_str())
                    .and_then(|id| Uuid::parse_str(id).ok())
                    .is_none_or(|id| !active.contains_key(&id))
            })
            .map(|entry| entry.1)
            .sum();
        let closed_budget = STORAGE_LIMIT - (ACTIVE_LIMIT as u64) * RECORD_LIMIT;
        entries.sort_by_key(|entry| entry.2);
        let now = unattended::epoch();
        let mut count = entries.len();
        for (path, size, time) in entries {
            let active_id = path
                .file_stem()
                .and_then(|id| id.to_str())
                .and_then(|id| Uuid::parse_str(id).ok());
            if active_id.is_some_and(|id| active.contains_key(&id)) {
                continue;
            }
            if (now.saturating_sub(time) >= RETENTION || total > closed_budget || count > 16)
                && fs::remove_file(&path).is_ok()
            {
                total = total.saturating_sub(size);
                count -= 1;
            }
        }
    }

    #[derive(Debug)]
    struct Work {
        id: Uuid,
        command: String,
        timeout: Duration,
    }
    #[derive(Debug)]
    struct Session {
        record: Arc<Mutex<Record>>,
        send: mpsc::SyncSender<Work>,
        stop: Arc<AtomicBool>,
    }
    impl Drop for Session {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
        }
    }

    #[derive(Debug, Default)]
    pub struct Pool {
        active: HashMap<Uuid, Session>,
    }

    impl Pool {
        pub fn close_all(&mut self) {
            for session in self.active.values() {
                session.stop.store(true, Ordering::Release);
            }
        }

        pub fn call(
            &mut self,
            state: &Path,
            host: &str,
            grant: Uuid,
            tool: &str,
            args: &Value,
        ) -> Result<Value, String> {
            self.active.retain(|_, session| {
                session
                    .record
                    .lock()
                    .is_ok_and(|record| record.closed_at.is_none())
            });
            let directory = state.join("terminal-history");
            fs::create_dir_all(&directory).map_err(|_| "TERMINAL_HISTORY_UNAVAILABLE")?;
            prune(&directory, &self.active);
            if tool == "terminal_list" {
                let mut items = Vec::new();
                for session in self.active.values() {
                    let record = session
                        .record
                        .lock()
                        .map_err(|_| "TERMINAL_STATE_UNAVAILABLE")?;
                    if record.grant == grant {
                        items.push(record.summary());
                    }
                }
                for (path, _, _) in records(&directory) {
                    if let Some(record) = load(&path).filter(|record| {
                        record.grant == grant && !self.active.contains_key(&record.id)
                    }) {
                        if record
                            .closed_at
                            .is_some_and(|at| unattended::epoch().saturating_sub(at) < RETENTION)
                        {
                            items.push(record.summary());
                        }
                    }
                }
                return Ok(
                    json!({"terminals":items,"persistent_limit":ACTIVE_LIMIT,"one_shot_available":true}),
                );
            }
            if tool == "terminal_open" {
                if self.active.len() >= ACTIVE_LIMIT {
                    return Err(
                        "PERSISTENT_TERMINAL_LIMIT_USE_ADMIN_COMMAND_FOR_SHORT_TASKS".into(),
                    );
                }
                let id = Uuid::new_v4();
                let path = directory.join(format!("{id}.json"));
                let record = Record {
                    id,
                    grant,
                    closed_at: None,
                    reason: None,
                    start: 0,
                    output: VecDeque::new(),
                    commands: VecDeque::new(),
                };
                record.save(&path)?;
                let record = Arc::new(Mutex::new(record));
                let (send, receive) = mpsc::sync_channel(1);
                let stop = Arc::new(AtomicBool::new(false));
                let worker = record.clone();
                let worker_stop = stop.clone();
                let state = state.to_path_buf();
                let host = host.to_owned();
                let (child, job) = start_shell()?;
                thread::Builder::new()
                    .name("desktop-mcp-terminal".into())
                    .spawn(move || {
                        run(
                            child,
                            job,
                            worker,
                            receive,
                            worker_stop,
                            state,
                            host,
                            grant,
                            path,
                        )
                    })
                    .map_err(|_| "TERMINAL_WORKER_UNAVAILABLE")?;
                self.active.insert(id, Session { record, send, stop });
                return Ok(json!({"terminal_id":id.to_string(),"visibility":"hidden"}));
            }
            let id = Uuid::parse_str(args["terminal_id"].as_str().ok_or("TERMINAL_ID_REQUIRED")?)
                .map_err(|_| "INVALID_TERMINAL_ID")?;
            if let Some(session) = self.active.get(&id) {
                let mut record = session
                    .record
                    .lock()
                    .map_err(|_| "TERMINAL_STATE_UNAVAILABLE")?;
                if record.grant != grant {
                    return Err("TERMINAL_NOT_FOUND_OR_EXPIRED".into());
                }
                return match tool {
                    "terminal_read" => Ok(record.read(args["offset"].as_u64())),
                    "terminal_close" => {
                        session.stop.store(true, Ordering::Release);
                        Ok(json!({"closing":true}))
                    }
                    "terminal_run" => {
                        if session.stop.load(Ordering::Acquire) || record.closed_at.is_some() {
                            return Err("TERMINAL_CLOSED".into());
                        }
                        if record
                            .commands
                            .back()
                            .is_some_and(|command| command.status == "running")
                        {
                            return Err("TERMINAL_BUSY".into());
                        }
                        let command = args["command"]
                            .as_str()
                            .ok_or("COMMAND_REQUIRED")?
                            .to_owned();
                        let timeout = Duration::from_secs(
                            args["timeout_seconds"].as_u64().unwrap_or(DEFAULT_TIMEOUT),
                        );
                        let command_id = Uuid::new_v4();
                        session
                            .send
                            .try_send(Work {
                                id: command_id,
                                command,
                                timeout,
                            })
                            .map_err(|_| "TERMINAL_UNAVAILABLE")?;
                        if record.commands.len() >= 64 {
                            record.commands.pop_front();
                        }
                        record.commands.push_back(CommandRecord {
                            id: command_id,
                            exit_code: None,
                            status: "running".into(),
                        });
                        Ok(
                            json!({"terminal_id":id.to_string(),"command_id":command_id.to_string(),"status":"running"}),
                        )
                    }
                    _ => Err("INVALID_TERMINAL_TOOL".into()),
                };
            }
            if tool == "terminal_read" {
                if let Some(record) = load(&directory.join(format!("{id}.json"))).filter(|record| {
                    record.grant == grant
                        && record
                            .closed_at
                            .is_some_and(|at| unattended::epoch().saturating_sub(at) < RETENTION)
                }) {
                    return Ok(record.read(args["offset"].as_u64()));
                }
            }
            Err("TERMINAL_NOT_FOUND_OR_EXPIRED".into())
        }
    }

    fn start_shell() -> Result<(Child, OwnedHandle), String> {
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err("TERMINAL_JOB_UNAVAILABLE".into());
        }
        // The handle is not inheritable. Its owner killing or exiting closes the whole job.
        let job = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe {
            SetInformationJobObject(
                raw,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err("TERMINAL_JOB_LIMIT_FAILED".into());
        }
        let root = std::env::var_os("SystemRoot").ok_or("SYSTEM_ROOT_UNAVAILABLE")?;
        let shell = PathBuf::from(root)
            .join("System32")
            .join("WindowsPowerShell")
            .join("v1.0")
            .join("powershell.exe");
        let encoded = unattended::base64_encode(
            &BOOTSTRAP
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
        );
        let mut child = Command::new(shell)
            .args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                &encoded,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(0x08000000)
            .spawn()
            .map_err(|_| "TERMINAL_SHELL_UNAVAILABLE")?;
        // The bootstrap blocks on stdin. No caller code is sent before assignment succeeds.
        if unsafe { AssignProcessToJobObject(raw, child.as_raw_handle()) } == 0 {
            let _ = child.kill();
            let _ = child.wait();
            return Err("TERMINAL_JOB_ASSIGN_FAILED".into());
        }
        Ok((child, job))
    }

    fn drain(stream: impl Read, output: mpsc::SyncSender<(bool, Vec<u8>)>, stdout: bool) {
        let mut reader = BufReader::new(stream);
        loop {
            let mut bytes = Vec::new();
            match reader.by_ref().take(8192).read_until(b'\n', &mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if output.send((stdout, bytes)).is_err() {
                        break;
                    }
                }
            }
        }
    }

    fn run(
        mut child: Child,
        job: OwnedHandle,
        record: Arc<Mutex<Record>>,
        receive: mpsc::Receiver<Work>,
        stop: Arc<AtomicBool>,
        state: PathBuf,
        host: String,
        grant: Uuid,
        path: PathBuf,
    ) {
        let mut input = child.stdin.take().expect("piped stdin");
        let (input_send, input_receive) = mpsc::sync_channel::<String>(1);
        let _ = thread::spawn(move || {
            for line in input_receive {
                if writeln!(input, "{line}")
                    .and_then(|_| input.flush())
                    .is_err()
                {
                    break;
                }
            }
        });
        let stdout = child.stdout.take().expect("piped stdout");
        let stderr = child.stderr.take().expect("piped stderr");
        let (send, output) = mpsc::sync_channel(32);
        let stdout_send = send.clone();
        let _ = thread::spawn(move || drain(stdout, stdout_send, true));
        let _ = thread::spawn(move || drain(stderr, send, false));
        let mut current: Option<(Uuid, Instant)> = None;
        let mut idle = Instant::now();
        let mut checkpoint = Instant::now();
        let mut dirty = false;
        let reason = loop {
            if stop.load(Ordering::Acquire) {
                break "closed";
            }
            if unattended::grant_id(&state, &host) != Some(grant)
                || !state.join("remote-readonly.enabled").is_file()
            {
                break "grant_inactive";
            }
            if current.is_some_and(|(_, until)| Instant::now() >= until) {
                break "command_timed_out";
            }
            if current.is_none() {
                match receive.try_recv() {
                    Ok(work) => {
                        let payload =
                            json!({"id":work.id.to_string(),"command":work.command}).to_string();
                        let encoded = unattended::base64_encode(payload.as_bytes());
                        if input_send.try_send(encoded).is_err() {
                            break "shell_input_failed";
                        }
                        current = Some((work.id, Instant::now() + work.timeout));
                        dirty = true;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => break "closed",
                    Err(mpsc::TryRecvError::Empty) if idle.elapsed() >= IDLE_LIMIT => {
                        break "idle_timeout"
                    }
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
            if !matches!(child.try_wait(), Ok(None)) {
                break "shell_exited";
            }
            for _ in 0..32 {
                let Ok((is_stdout, bytes)) = output.try_recv() else {
                    break;
                };
                let Ok(mut entry) = record.lock() else {
                    return;
                };
                let marker = if is_stdout {
                    current.and_then(|(id, _)| {
                        let prefix = format!("__DMCP_DONE__{id}:");
                        std::str::from_utf8(&bytes)
                            .ok()?
                            .trim_end_matches(['\r', '\n'])
                            .strip_prefix(&prefix)?
                            .parse::<i32>()
                            .ok()
                    })
                } else {
                    None
                };
                if let Some(code) = marker {
                    if let Some(command) = entry.commands.back_mut() {
                        command.exit_code = Some(code);
                        command.status = "finished".into();
                    }
                    current = None;
                    idle = Instant::now();
                    let _ = entry.save(&path);
                    dirty = false;
                    checkpoint = Instant::now();
                } else {
                    entry.append(&bytes);
                    dirty = true;
                }
            }
            if dirty && checkpoint.elapsed() >= CHECKPOINT {
                if let Ok(entry) = record.lock() {
                    let _ = entry.save(&path);
                }
                dirty = false;
                checkpoint = Instant::now();
            }
            thread::sleep(Duration::from_millis(100));
        };
        drop(input_send);
        drop(job);
        let _ = child.wait();
        if let Ok(mut entry) = record.lock() {
            while let Ok((_, bytes)) = output.recv_timeout(Duration::from_millis(25)) {
                entry.append(&bytes);
            }
            if let Some(command) = entry
                .commands
                .back_mut()
                .filter(|command| command.status == "running")
            {
                command.status = reason.into();
            }
            entry.reason = Some(reason.into());
            entry.closed_at = Some(unattended::epoch());
            let _ = entry.save(&path);
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn hidden_shell_reuses_environment_and_directory_and_reports_native_exit() {
            let (mut child, job) = start_shell().unwrap();
            let mut stdin = child.stdin.take().unwrap();
            let stdout = child.stdout.take().unwrap();
            let (sender, receiver) = mpsc::sync_channel(32);
            let worker = thread::spawn(move || drain(stdout, sender, true));
            let send = |stdin: &mut std::process::ChildStdin, cmd: &str| {
                let id = Uuid::new_v4();
                let command = json!({"id":id.to_string(),"command":cmd}).to_string();
                writeln!(stdin, "{}", unattended::base64_encode(command.as_bytes())).unwrap();
                stdin.flush().unwrap();
                let marker = format!("__DMCP_DONE__{id}:");
                let mut output = String::new();
                let deadline = Instant::now() + Duration::from_secs(12);
                loop {
                    let (_, bytes) = receiver
                        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                        .unwrap();
                    let text = String::from_utf8_lossy(&bytes);
                    if let Some(code) = text.trim_end().strip_prefix(&marker) {
                        return (output, code.parse::<i32>().unwrap());
                    }
                    output.push_str(&text);
                }
            };
            assert_eq!(
                send(
                    &mut stdin,
                    "$env:DMCP_TEST = 'retained'; Set-Location $env:SystemRoot"
                )
                .1,
                0
            );
            let (output,code)=send(&mut stdin,"Write-Output $env:DMCP_TEST; Write-Output ((Get-Location).Path); & cmd.exe /c exit 7");
            assert!(output.contains("retained"), "{output:?}");
            assert!(
                output
                    .to_lowercase()
                    .contains(&std::env::var("SystemRoot").unwrap().to_lowercase()),
                "{output:?}"
            );
            assert_eq!(code, 7);
            drop(job);
            let _ = child.wait().unwrap();
            worker.join().unwrap();
        }
    }
}

#[cfg(windows)]
pub use windows::Pool;
