//! A single elevated diagnostic. The helper receives a permit only from a fresh
//! poll of the exact approved request, after Windows has completed elevation.
use serde_json::{json, Value};

pub const TOOL: &str = "system_volume_status";
pub const COMMAND: &str = "admin_command";

pub fn is_privileged(tool: &str) -> bool { matches!(tool, TOOL | COMMAND) }

pub fn valid_command(command: &str) -> bool {
    !command.trim().is_empty() && command.len() <= 2000 && command.chars().all(|ch| {
        (matches!(ch, '\n' | '\t') || !ch.is_control())
            && !matches!(ch, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    })
}

#[cfg(windows)]
mod platform {
    use super::*;
    use rand::{rngs::OsRng, RngCore};
    use std::{
        io::{Read, Write},
        net::TcpListener,
        os::windows::{ffi::OsStringExt, fs::MetadataExt, process::CommandExt},
        path::PathBuf,
        process::{Command, Stdio},
        sync::mpsc::{self, Receiver, Sender, TryRecvError},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    const REPARSE_POINT: u32 = 0x400;

    #[repr(C)]
    struct Guid(u32, u16, u16, [u8; 8]);

    #[link(name = "shell32")]
    extern "system" {
        fn SHGetKnownFolderPath(id: *const Guid, flags: u32, token: isize, result: *mut *mut u16) -> i32;
    }
    #[link(name = "ole32")]
    extern "system" {
        fn CoTaskMemFree(pointer: *mut std::ffi::c_void);
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemDirectoryW(buffer: *mut u16, size: u32) -> u32;
    }

    fn helper(tool: &str) -> Option<PathBuf> {
        // FOLDERID_ProgramFiles. Do not resolve the elevated image through PATH
        // or environment variables inherited from the requesting user.
        let folder = Guid(0x905e63b6, 0xc1bf, 0x494e, [0xb2, 0x9c, 0x65, 0xb7, 0x32, 0xd3, 0xd2, 0x1a]);
        let mut pointer = std::ptr::null_mut();
        let status = unsafe { SHGetKnownFolderPath(&folder, 0, 0, &mut pointer) };
        if status < 0 || pointer.is_null() { return None; }
        let path = unsafe {
            let len = (0..).take_while(|offset| *pointer.add(*offset) != 0).count();
            let path = std::ffi::OsString::from_wide(std::slice::from_raw_parts(pointer, len));
            CoTaskMemFree(pointer.cast());
            PathBuf::from(path)
        };
        let directory = path.join("DesktopMCP");
        let exe = directory.join(match tool {
            TOOL => "VolumeCheck.exe",
            COMMAND => "CommandRunner.exe",
            _ => return None,
        });
        if [path.as_path(), directory.as_path(), exe.as_path()].iter().any(|part| {
            std::fs::symlink_metadata(part).map_or(true, |info| info.file_attributes() & REPARSE_POINT != 0)
        }) || !exe.is_file() { return None; }
        Some(exe)
    }

    pub fn available(tool: &str) -> bool { helper(tool).is_some() }

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map_or(u64::MAX, |time| time.as_secs())
    }

    #[derive(Debug)]
    enum Progress {
        Ready,
        Complete(Result<Value, &'static str>),
    }

    #[derive(Debug)]
    pub struct Run {
        frame: Value,
        permit: Sender<()>,
        progress: Receiver<Progress>,
    }

    impl Run {
        pub fn start(frame: &Value, workspace: &std::path::Path) -> Result<Self, &'static str> {
            let tool = frame["tool"].as_str().ok_or("ADMIN_TOOL_REQUIRED")?;
            let executable = helper(tool).ok_or("ADMIN_HELPER_UNAVAILABLE")?;
            let payload = if tool == COMMAND {
                let workspace = workspace.to_str().ok_or("WORKSPACE_ENCODING")?;
                Some(serde_json::to_vec(&json!({"command":frame["arguments"]["command"],"workspace":workspace}))
                    .map_err(|_| "ADMIN_COMMAND_ENCODING")?)
            } else { None };
            let expires = frame["expires_at"].as_u64().ok_or("INVALID_EXPIRY")?;
            let listener = TcpListener::bind("127.0.0.1:0").map_err(|_| "ADMIN_LOOPBACK_UNAVAILABLE")?;
            listener.set_nonblocking(true).map_err(|_| "ADMIN_LOOPBACK_UNAVAILABLE")?;
            let port = listener.local_addr().map_err(|_| "ADMIN_LOOPBACK_UNAVAILABLE")?.port();
            let (permit, approval) = mpsc::channel();
            let (report, progress) = mpsc::channel();
            thread::Builder::new().name("desktop-mcp-elevation".into()).spawn(move || {
                let result = run_helper(executable, listener, port, expires, payload, &approval, &report);
                let _ = report.send(Progress::Complete(result));
            }).map_err(|_| "ADMIN_WORKER_UNAVAILABLE")?;
            Ok(Self { frame: frame.clone(), permit, progress })
        }

        pub fn matches(&self, frame: &Value) -> bool { &self.frame == frame }

        pub fn poll(&self) -> Value {
            if self.frame["expires_at"].as_u64().is_none_or(|expires| now() >= expires) {
                return rejected("ADMIN_REQUEST_EXPIRED");
            }
            match self.progress.try_recv() {
                Ok(Progress::Ready) => match self.permit.send(()) {
                    Ok(()) => json!({"pending":true}),
                    Err(_) => rejected("ADMIN_WORKER_UNAVAILABLE"),
                },
                Ok(Progress::Complete(Ok(data))) =>
                    json!({"pending":false,"executed":true,"data":data}),
                Ok(Progress::Complete(Err(error))) => rejected(error),
                Err(TryRecvError::Empty) => json!({"pending":true}),
                Err(TryRecvError::Disconnected) => rejected("ADMIN_WORKER_UNAVAILABLE"),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn expired_elevation_cannot_send_a_permit() {
            let (permit, approval) = mpsc::channel();
            let (report, progress) = mpsc::channel();
            let frame = json!({"expires_at":now()});
            let run = Run { frame:frame.clone(), permit, progress };
            report.send(Progress::Ready).unwrap();
            assert!(run.matches(&frame));
            assert!(!run.matches(&json!({"expires_at":0})));
            assert_eq!(run.poll()["error"], "ADMIN_REQUEST_EXPIRED");
            assert_eq!(approval.try_recv(), Err(TryRecvError::Empty));
            drop(run);
            assert_eq!(approval.try_recv(), Err(TryRecvError::Disconnected));
        }
    }

    fn run_helper(
        executable: PathBuf,
        listener: TcpListener,
        port: u16,
        expires: u64,
        payload: Option<Vec<u8>>,
        approval: &Receiver<()>,
        report: &Sender<Progress>,
    ) -> Result<Value, &'static str> {
        let mut system = [0u16; 32768];
        let count = unsafe { GetSystemDirectoryW(system.as_mut_ptr(), system.len() as u32) } as usize;
        if count == 0 || count >= system.len() { return Err("ADMIN_LAUNCHER_UNAVAILABLE"); }
        let shell = PathBuf::from(std::ffi::OsString::from_wide(&system[..count]))
            .join("WindowsPowerShell/v1.0/powershell.exe");
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let proof = hex::encode(nonce);
        if now() >= expires { return Err("ADMIN_REQUEST_EXPIRED"); }
        let mut launcher = Command::new(shell)
            .args(["-NoProfile", "-NonInteractive", "-Command",
                r#"$ErrorActionPreference='Stop'
$path=$env:DMCP_VOLUME_CHECK_EXE
$folder=Split-Path -Parent $path
$trusted=@('S-1-5-18','S-1-5-32-544',
    ([Security.Principal.NTAccount]::new('NT SERVICE\TrustedInstaller')).Translate([Security.Principal.SecurityIdentifier]).Value)
foreach ($item in @($path,$folder,(Split-Path -Parent $folder))) {
    if ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 2 }
    $acl=Get-Acl -LiteralPath $item
    if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) { exit 2 }
    foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
        if ($ace.AccessControlType -eq 'Allow' -and
            !($ace.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
            $trusted -notcontains $ace.IdentityReference.Value -and
            ([int]$ace.FileSystemRights -band 0x000d0156)) { exit 2 }
    }
}
Start-Process -FilePath $path -WorkingDirectory $folder -ArgumentList $env:DMCP_VOLUME_CHECK_ARGS -Verb RunAs
"#])
            .env("DMCP_VOLUME_CHECK_EXE", executable)
            .env("DMCP_VOLUME_CHECK_ARGS", format!("{port} {proof} {expires}"))
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
            .creation_flags(0x08000000)
            .spawn().map_err(|_| "ADMIN_LAUNCHER_UNAVAILABLE")?;

        let result = loop {
            if now() >= expires { break Err("ADMIN_REQUEST_EXPIRED"); }
            if approval.try_recv() == Err(TryRecvError::Disconnected) { break Err("ADMIN_REQUEST_CANCELED"); }
            if launcher.try_wait().map_or(true, |status| status.is_some_and(|code| !code.success())) {
                break Err("WINDOWS_ELEVATION_DECLINED_OR_UNAVAILABLE");
            }
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let timeout = Some(Duration::from_secs(2));
                    // Winsock accept can inherit nonblocking mode from the listener.
                    // Use blocking I/O with timeouts while the helper runs the check.
                    if stream.set_nonblocking(false).is_err()
                        || stream.set_read_timeout(timeout).is_err()
                        || stream.set_write_timeout(timeout).is_err()
                    {
                        break Err("ADMIN_LOOPBACK_UNAVAILABLE");
                    }
                    let mut supplied = [0u8; 64];
                    if stream.read_exact(&mut supplied).is_err() || supplied.as_slice() != proof.as_bytes() {
                        continue;
                    }
                    if report.send(Progress::Ready).is_err() ||
                        approval.recv_timeout(Duration::from_secs(2)).is_err() || now() >= expires {
                        break Err("ADMIN_REQUEST_CANCELED");
                    }
                    if stream.write_all(&[1]).is_err() { break Err("ADMIN_HELPER_UNAVAILABLE"); }
                    if let Some(payload) = &payload {
                        break command_reply(stream, payload, expires, approval);
                    }
                    let mut reply = [0];
                    break match stream.read_exact(&mut reply) {
                        Ok(()) if reply[0] < 2 => Ok(json!({"needs_disk_check":reply[0] == 1})),
                        Ok(()) => Err("SYSTEM_VOLUME_STATUS_UNAVAILABLE"),
                        Err(_) => Err("ADMIN_HELPER_REPLY_UNAVAILABLE"),
                    };
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => thread::sleep(Duration::from_millis(50)),
                Err(_) => break Err("ADMIN_LOOPBACK_UNAVAILABLE"),
            }
        };
        // A pending UAC dialog can outlive the requesting connection. Without
        // this listener and a fresh permit, the helper exits before accessing
        // the volume even if the user accepts a late dialog.
        let _ = launcher.kill();
        let _ = launcher.wait();
        result
    }

    fn command_reply(mut stream: std::net::TcpStream, payload: &[u8], expires: u64, approval: &Receiver<()>) -> Result<Value, &'static str> {
        if payload.len() > 16384 { return Err("ADMIN_COMMAND_ENCODING"); }
        stream.write_all(&(payload.len() as u32).to_le_bytes()).map_err(|_| "ADMIN_HELPER_REPLY_UNAVAILABLE")?;
        stream.write_all(payload).map_err(|_| "ADMIN_HELPER_REPLY_UNAVAILABLE")?;
        stream.set_read_timeout(Some(Duration::from_millis(250))).map_err(|_| "ADMIN_LOOPBACK_UNAVAILABLE")?;
        let mut header = [0; 4];
        read_until_deadline(&mut stream, &mut header, expires, approval)?;
        let size = u32::from_le_bytes(header) as usize;
        if size == 0 || size > 100_000 { return Err("ADMIN_COMMAND_RESULT_INVALID"); }
        let mut bytes = vec![0; size];
        read_until_deadline(&mut stream, &mut bytes, expires, approval)?;
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "ADMIN_COMMAND_RESULT_INVALID")?;
        if value["error"].is_string() { return Err("ADMIN_COMMAND_DECLINED_OR_FAILED"); }
        if value.as_object().is_none_or(|fields| fields.len() != 4)
            || value["exit_code"].as_i64().is_none_or(|n| i32::try_from(n).is_err())
            || value["stdout"].as_str().is_none_or(|s| s.len() > 24_000)
            || value["stderr"].as_str().is_none_or(|s| s.len() > 24_000)
            || !value["truncated"].is_boolean()
        {
            return Err("ADMIN_COMMAND_RESULT_INVALID");
        }
        Ok(value)
    }

    fn read_until_deadline(
        stream: &mut std::net::TcpStream, mut bytes: &mut [u8], expires: u64, approval: &Receiver<()>,
    ) -> Result<(), &'static str> {
        while !bytes.is_empty() {
            if now() >= expires { return Err("ADMIN_REQUEST_EXPIRED"); }
            if approval.try_recv() == Err(TryRecvError::Disconnected) { return Err("ADMIN_REQUEST_CANCELED"); }
            match stream.read(bytes) {
                Ok(0) => return Err("ADMIN_HELPER_REPLY_UNAVAILABLE"),
                Ok(count) => bytes = &mut bytes[count..],
                Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut | std::io::ErrorKind::Interrupted) => {},
                Err(_) => return Err("ADMIN_HELPER_REPLY_UNAVAILABLE"),
            }
        }
        Ok(())
    }
}

pub fn rejected(error: &str) -> Value {
    json!({"pending":false,"executed":false,"error":error})
}

#[cfg(windows)]
pub use platform::{available, Run};

#[cfg(not(windows))]
pub fn available(_: &str) -> bool { false }

#[cfg(not(windows))]
#[derive(Debug)]
pub struct Run;

#[cfg(not(windows))]
impl Run {
    pub fn start(_: &Value, _: &std::path::Path) -> Result<Self, &'static str> { Err("ADMIN_HELPER_UNAVAILABLE") }
    pub fn matches(&self, _: &Value) -> bool { false }
    pub fn poll(&self) -> Value { rejected("ADMIN_HELPER_UNAVAILABLE") }
}
