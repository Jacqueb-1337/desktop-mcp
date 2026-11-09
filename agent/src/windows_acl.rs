//! Verify private Windows credentials against explicit OS ACLs, fail closed.
//! This module never changes permissions or invokes elevation.
#[cfg(windows)]
pub fn verify_private(path: &std::path::Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    use std::{
        path::PathBuf,
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };
    let powershell =
        PathBuf::from(std::env::var_os("SystemRoot").ok_or("WINDOWS_SYSTEM_ROOT_REQUIRED")?)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let script = r#"$ErrorActionPreference='Stop';try {
$p=Get-Item -LiteralPath $env:DESKTOP_MCP_ACL_PATH -Force
$profile=[IO.Path]::GetFullPath($env:USERPROFILE).TrimEnd('\')
$full=$p.FullName.TrimEnd('\')
if (!$full.StartsWith($profile+'\',[StringComparison]::OrdinalIgnoreCase)) {exit 2}
$user=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowed=@($user,'S-1-5-18','S-1-5-32-544')
$targets=@($p);if($p.PSIsContainer){$targets+=@(Get-ChildItem -LiteralPath $p.FullName -Force)}
foreach($target in $targets){
 if(($target.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){exit 3}
 $item=$target;$strict=$true
 while($item -and $item.FullName.StartsWith($profile,[StringComparison]::OrdinalIgnoreCase)){
  $acl=Get-Acl -LiteralPath $item.FullName
  $owner=$acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
  if($allowed -notcontains $owner){exit 4}
  $mask=if($strict){0x1f01ff}else{0x000d0156}
  foreach($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])){
   if($ace.AccessControlType -eq 'Allow' -and $allowed -notcontains $ace.IdentityReference.Value -and ([int]$ace.FileSystemRights -band $mask)-ne 0){exit 5}
  }
  if($item.FullName.TrimEnd('\') -eq $profile){break}
  $item=if($item.PSIsContainer){$item.Parent}else{$item.Directory};$strict=$false
 }
}
exit 0
}catch{exit 6}"#;
    let mut child = Command::new(powershell)
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .env("DESKTOP_MCP_ACL_PATH", path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(0x08000000)
        .spawn()
        .map_err(|_| "WINDOWS_ACL_CHECK_UNAVAILABLE")?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err("WINDOWS_PRIVATE_ACL_REQUIRED".into())
                }
            }
            Ok(None) if started.elapsed() < Duration::from_secs(8) => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("WINDOWS_ACL_CHECK_TIMEOUT".into());
            }
        }
    }
}

// Verify the exact SYSTEM-only state path is protected by Windows ACLs.
// This is independent from the ordinary per-user Desktop MCP state verifier.
#[cfg(windows)]
pub fn verify_system_private(state:&std::path::Path)->Result<(),String>{
    use std::os::windows::process::CommandExt;
    use std::{process::{Command,Stdio},time::{Instant,Duration},thread};
    let system=std::env::var_os("SystemRoot").ok_or("SYSTEM_ROOT_MISSING")?;
    let shell=std::path::Path::new(&system).join("System32/WindowsPowerShell/v1.0/powershell.exe");
    let script=r#"$ErrorActionPreference='Stop';try{
if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18'){exit 10}
$p=[IO.Path]::GetFullPath($env:DESKTOP_MCP_SYSTEM_STATE).TrimEnd('\')
$root=[IO.Path]::GetFullPath((Join-Path $env:ProgramData 'DesktopMCP')).TrimEnd('\')
if($p -ine (Join-Path $root 'State')){exit 11}
$paths=@($root,$p,(Join-Path $root 'grant.json'))
$paths+=@(Get-ChildItem -LiteralPath $p -Force | ForEach-Object FullName)
$allowed=@('S-1-5-18','S-1-5-32-544')
foreach($file in $paths){
 if(!(Test-Path -LiteralPath $file)){if($file.EndsWith('grant.json')){continue};exit 12}
 $item=Get-Item -LiteralPath $file -Force
 if(($item.Attributes -band [IO.FileAttributes]::ReparsePoint)-ne 0){exit 13}
 $acl=Get-Acl -LiteralPath $file
 if($allowed -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value){exit 14}
 $write=[int][Security.AccessControl.FileSystemRights]::Write
 $delete=[int][Security.AccessControl.FileSystemRights]::Delete
 $aclRules=$acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])
 foreach($ace in $aclRules){
  if($ace.AccessControlType -eq 'Allow' -and $allowed -notcontains $ace.IdentityReference.Value){
   if(([int]$ace.FileSystemRights -band ($write -bor $delete -bor 0x80000 -bor 0x40000)) -ne 0){exit 15}
  }
 }
}
exit 0
}catch{exit 16}"#;
    let mut child=Command::new(shell).args(["-NoProfile","-NonInteractive","-Command",script])
        .env("DESKTOP_MCP_SYSTEM_STATE",state)
        .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
        .creation_flags(0x08000000)
        .spawn().map_err(|_|"SYSTEM_ACL_VERIFIER_UNAVAILABLE")?;
    let begin=Instant::now();
    loop{
        match child.try_wait(){
            Ok(Some(code))=>return if code.success(){Ok(())}else{Err("SYSTEM_STATE_OR_ACL_UNSAFE".into())},
            Ok(None) if begin.elapsed()<Duration::from_secs(8)=>thread::sleep(Duration::from_millis(30)),
            _=>{let _=child.kill();let _=child.wait();return Err("SYSTEM_ACL_VERIFIER_TIMEOUT".into())}
        }
    }
}
