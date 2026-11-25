//! Explicit owner-approved Windows-managed process launch. This intentionally
//! uses an on-demand, non-elevated Task Scheduler task, not a job breakaway.
use serde_json::{json, Value};
pub const TOOL:&str="process_spawn_detached";
pub fn valid_args(args:&Value)->bool{
    args.as_object().is_some_and(|o|o.len()==1+usize::from(o.contains_key("working_directory"))
        && args["command"].as_str().is_some_and(crate::elevation::valid_command)
        && o.get("working_directory").is_none_or(|v|v.as_str().is_some_and(|s|
            crate::route::valid_repository_path(s))))
}
#[cfg(windows)]
pub fn spawn(frame:&Value)->Result<Value,String>{
    use std::{io::Write,os::windows::process::CommandExt,path::PathBuf,process::{Command,Stdio}};
    use windows_sys::Win32::{Foundation::CloseHandle,Security::{GetTokenInformation,TokenElevation,TOKEN_ELEVATION,TOKEN_QUERY},System::Threading::{GetCurrentProcess,OpenProcessToken}};
    let mut token=std::ptr::null_mut();
    let mut elevation=TOKEN_ELEVATION::default();let mut size=0;
    if unsafe{OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&mut token)}==0{return Err("DETACHED_OWNER_TOKEN_UNAVAILABLE".into());}
    let ok=unsafe{GetTokenInformation(token,TokenElevation,(&mut elevation as *mut TOKEN_ELEVATION).cast(),
        std::mem::size_of::<TOKEN_ELEVATION>() as u32,&mut size)};
    unsafe{CloseHandle(token);}
    if ok==0 || elevation.TokenIsElevated!=0{return Err("DETACHED_NON_ELEVATED_OWNER_REQUIRED".into());}
    let args=&frame["arguments"];
    if !valid_args(args){return Err("INVALID_DETACHED_ARGUMENTS".into());}
    let id=frame["request_id"].as_str().and_then(|s|uuid::Uuid::parse_str(s).ok()).ok_or("INVALID_REQUEST_ID")?;
    let name=format!("DesktopMCP-Detached-{id}");
    let directory=match args["working_directory"].as_str(){
        Some(path)=>PathBuf::from(path).canonicalize().map_err(|_|"DETACHED_DIRECTORY_UNAVAILABLE")?,
        None=>PathBuf::from(std::env::var_os("USERPROFILE").ok_or("OWNER_PROFILE_UNAVAILABLE")?),
    };
    if !directory.is_dir(){return Err("DETACHED_DIRECTORY_UNAVAILABLE".into());}
    // Task Scheduler accepts normal Win32 paths, not the verbatim spelling
    // returned by canonicalize. Preserve mapped-drive/UNC spelling.
    let path=directory.to_str().ok_or("DETACHED_DIRECTORY_ENCODING")?;
    let path=if let Some(rest)=path.strip_prefix(r"\\?\UNC\"){format!(r"\\{rest}")}
        else{path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()};
    let powershell=PathBuf::from(std::env::var_os("SystemRoot").ok_or("SYSTEM_ROOT_UNAVAILABLE")?)
        .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let command=args["command"].as_str().unwrap();
    let encoded=crate::unattended::base64_encode(&command.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
    // Exact action data arrives via stdin, never interpolated into broker code.
    // One on-demand task, interactive token only, no trigger/restart/elevation,
    // visible in Task Scheduler and stoppable by the Windows owner.
    let script=r#"$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue'
try {
 $r=[Console]::In.ReadToEnd() | ConvertFrom-Json
 $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
 if($identity.IsSystem -or (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Invalid owner context'}
 $s=New-Object -ComObject Schedule.Service;$s.Connect()
 $folder=$s.GetFolder('\')
 $d=$s.NewTask(0)
 $d.RegistrationInfo.Description='Explicitly approved Desktop MCP detached launch. Independent of MCP; no automatic triggers. End or delete this task in Task Scheduler.'
 $d.Principal.UserId=$identity.User.Value
 $d.Principal.LogonType=3
 $d.Principal.RunLevel=0
 $d.Settings.Enabled=$true
 $d.Settings.Hidden=$false
 $d.Settings.AllowDemandStart=$true
 $d.Settings.ExecutionTimeLimit='PT0S'
 $d.Settings.DisallowStartIfOnBatteries=$false
 $d.Settings.StopIfGoingOnBatteries=$false
 $d.Settings.MultipleInstances=2
 $a=$d.Actions.Create(0)
 $a.Path=[string]$r.executable
 $a.Arguments='-NoLogo -NoProfile -NonInteractive -EncodedCommand '+[string]$r.encoded
 $a.WorkingDirectory=[string]$r.directory
 $t=$folder.RegisterTaskDefinition([string]$r.name,$d,2,$identity.User.Value,$null,3,$null)
 try {$run=$t.Run($null)} catch {throw 'Task registered, launch result unavailable; inspect Task Scheduler before retrying'}
 [Console]::Out.WriteLine((@{task_name=[string]$t.Path;instance_id=[string]$run.InstanceGuid;engine_pid=[int]$run.EnginePID;state=[int]$run.State;managed_by='Windows Task Scheduler';automatic_triggers=$false;survives_mcp_shutdown=$true;unmanaged_by_mcp=$true} | ConvertTo-Json -Compress))
} catch {[Console]::Error.WriteLine($_.Exception.Message);exit 1}"#;
    let mut child=Command::new(&powershell).args(["-NoLogo","-NoProfile","-NonInteractive","-Command",script])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).creation_flags(0x08000000)
        .spawn().map_err(|_|"DETACHED_SCHEDULER_UNAVAILABLE")?;
    let payload=serde_json::to_vec(&json!({"name":name,"executable":powershell,"encoded":encoded,"directory":path})).map_err(|_|"DETACHED_ARGUMENT_ENCODING")?;
    let sent=child.stdin.take().ok_or("DETACHED_SCHEDULER_IO")?.write_all(&payload);
    if sent.is_err(){let _=child.kill();let _=child.wait();return Err("DETACHED_SCHEDULER_IO".into());}
    let start=std::time::Instant::now();
    loop{
        match child.try_wait(){
            Ok(Some(_))=>break,
            Ok(None) if start.elapsed()<std::time::Duration::from_secs(4)=>std::thread::sleep(std::time::Duration::from_millis(20)),
            _=>{let _=child.kill();let _=child.wait();return Err(format!("DETACHED_LAUNCH_RESULT_UNKNOWN: inspect task {name} before retrying"));}
        }
    }
    let output=child.wait_with_output().map_err(|_|"DETACHED_SCHEDULER_IO")?;
    if !output.status.success(){return Err(format!("DETACHED_SCHEDULER_REJECTED: inspect task {name} before retrying"));}
    let value:Value=serde_json::from_slice(&output.stdout).map_err(|_|format!("DETACHED_LAUNCH_RESULT_UNKNOWN: inspect task {name} before retrying"))?;
    if value["task_name"]!=format!(r"\{name}") || value["unmanaged_by_mcp"]!=true{return Err("DETACHED_INVALID_RESPONSE".into());}
    Ok(value)
}
#[cfg(not(windows))]
pub fn spawn(_: &Value)->Result<Value,String>{Err("DETACHED_WINDOWS_ONLY".into())}

#[cfg(test)]
mod tests{
 use super::*;
 #[test]fn strictly_validates_arguments(){
   assert!(valid_args(&json!({"command":"Write-Output 'test'"})));
   assert!(!valid_args(&json!({"command":"Write-Output 'test'","elevated":true})));
   assert!(!valid_args(&json!({"command":"Write-Output 'test'","working_directory":"relative"})));
   assert!(!valid_args(&json!({"command":""})));
 }
}
