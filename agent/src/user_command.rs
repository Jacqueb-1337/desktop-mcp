//! Owner-bound, non-elevated execution worker. The service never inherits a
//! user's passwords or accepts a caller-selected SID/session. The only allowed
//! token is the installation owner's non-elevated active console token.
use serde_json::{json, Value};
pub const TOOL:&str="user_command";
pub const RESULT:&str="user_command_result";
pub const ELEVATED:&str="elevated_user_command";
pub const ELEVATED_RESULT:&str="elevated_user_command_result";

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{ffi::c_void, io::{Read,Write,BufRead,BufReader}, net::{TcpListener,TcpStream,Ipv4Addr,SocketAddrV4},
        os::windows::{ffi::OsStrExt,process::CommandExt,io::{OwnedHandle,FromRawHandle}}, path::Path, process::{Command,Stdio},
        ptr::{null,null_mut}, thread, time::{Duration,Instant}};
    use windows_sys::Win32::{
        Foundation::{HANDLE,CloseHandle,LocalFree,WAIT_OBJECT_0},
        Security::{GetTokenInformation,TokenUser,TokenElevation,TokenLinkedToken,TOKEN_LINKED_TOKEN,TOKEN_USER,TOKEN_ELEVATION,EqualSid,PSID,
            Authorization::ConvertStringSidToSidW},
        System::{
            Environment::{CreateEnvironmentBlock,DestroyEnvironmentBlock},
            RemoteDesktop::{WTSGetActiveConsoleSessionId,WTSQueryUserToken},
            Threading::{CreateProcessAsUserW,ResumeThread,TerminateProcess,WaitForSingleObject,
                STARTUPINFOW,PROCESS_INFORMATION,CREATE_SUSPENDED,CREATE_UNICODE_ENVIRONMENT,CREATE_NO_WINDOW},
            JobObjects::{CreateJobObjectW,AssignProcessToJobObject,SetInformationJobObject,
                JobObjectExtendedLimitInformation,JOBOBJECT_EXTENDED_LIMIT_INFORMATION,JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE}
        },
        UI::Shell::GetUserProfileDirectoryW,
    };
    struct Handle(HANDLE);
    impl Drop for Handle {fn drop(&mut self){if !self.0.is_null(){unsafe{CloseHandle(self.0);}}}}
    struct Environment(*mut c_void);
    impl Drop for Environment {fn drop(&mut self){unsafe{DestroyEnvironmentBlock(self.0);}}}
    fn wide(s:&std::ffi::OsStr)->Vec<u16>{s.encode_wide().chain(Some(0)).collect()}
    fn owner_token(owner:&str,want_elevated:bool)->Result<Handle,String>{
        let mut raw=null_mut();
        let session=unsafe{WTSGetActiveConsoleSessionId()};
        if session==u32::MAX || unsafe{WTSQueryUserToken(session,&mut raw)}==0 {
            return Err("OWNER_SESSION_UNAVAILABLE".into());
        }
        let token=Handle(raw);
        let mut size=0u32;
        unsafe{GetTokenInformation(token.0,TokenUser,null_mut(),0,&mut size);}
        if size==0 || size>16384 {return Err("OWNER_TOKEN_INVALID".into());}
        let mut data=vec![0usize;(size as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe{GetTokenInformation(token.0,TokenUser,data.as_mut_ptr().cast(),size,&mut size)}==0 {
            return Err("OWNER_TOKEN_INVALID".into());
        }
        let user=unsafe{&*(data.as_ptr().cast::<TOKEN_USER>())};
        let mut sid:PSID=null_mut();
        let expected=wide(owner.as_ref());
        if unsafe{ConvertStringSidToSidW(expected.as_ptr(),&mut sid)}==0 {
            return Err("OWNER_SID_INVALID".into());
        }
        let matches=unsafe{EqualSid(user.User.Sid,sid)}!=0;
        unsafe{LocalFree(sid);}
        if !matches {return Err("OWNER_SESSION_MISMATCH".into());}
        let mut elevated=TOKEN_ELEVATION::default();
        if unsafe{GetTokenInformation(token.0,TokenElevation,(&mut elevated as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,&mut size)}==0 {
            return Err("OWNER_TOKEN_INVALID".into());
        }
        if (elevated.TokenIsElevated!=0)==want_elevated {return Ok(token);}
        if !want_elevated {return Err("NON_ELEVATED_OWNER_TOKEN_REQUIRED".into());}
        // Only the already elevated, protected SYSTEM broker reaches this path,
        // after a distinct, explicit owner-approved elevated-user grant.
        // Never manufacture a token for a standard user or select another SID.
        let mut linked=TOKEN_LINKED_TOKEN::default();
        if unsafe{GetTokenInformation(token.0,TokenLinkedToken,(&mut linked as *mut TOKEN_LINKED_TOKEN).cast(),
            std::mem::size_of::<TOKEN_LINKED_TOKEN>() as u32,&mut size)}==0 || linked.LinkedToken.is_null() {
            return Err("OWNER_ELEVATED_TOKEN_UNAVAILABLE".into());
        }
        let linked=Handle(linked.LinkedToken);
        if unsafe{GetTokenInformation(linked.0,TokenElevation,(&mut elevated as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,&mut size)}==0 || elevated.TokenIsElevated==0 {
            return Err("OWNER_ELEVATED_TOKEN_UNAVAILABLE".into());
        }
        let mut size=0u32;
        unsafe{GetTokenInformation(linked.0,TokenUser,null_mut(),0,&mut size);}
        if size==0 || size>16384 {return Err("OWNER_TOKEN_INVALID".into());}
        let mut linked_data=vec![0usize;(size as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe{GetTokenInformation(linked.0,TokenUser,linked_data.as_mut_ptr().cast(),size,&mut size)}==0 ||
            unsafe{EqualSid(user.User.Sid,(*(linked_data.as_ptr().cast::<TOKEN_USER>())).User.Sid)}==0 {
            return Err("OWNER_SESSION_MISMATCH".into());
        }
        Ok(linked)
    }
    fn launch(owner:&str,port:u16,nonce:&str,elevated:bool,terminal:bool)->Result<(Handle,Handle),String>{
        let token=owner_token(owner,elevated)?;
        let mut profile=vec![0u16;32768];let mut size=profile.len() as u32;
        if unsafe{GetUserProfileDirectoryW(token.0,profile.as_mut_ptr(),&mut size)}==0 {
            return Err("OWNER_PROFILE_UNAVAILABLE".into());
        }
        let mut env=null_mut();
        if unsafe{CreateEnvironmentBlock(&mut env,token.0,0)}==0{return Err("OWNER_ENVIRONMENT_UNAVAILABLE".into());}
        let env=Environment(env);
        let exe=std::env::current_exe().map_err(|_|"WORKER_BINARY_UNAVAILABLE")?;
        let exe_w=wide(exe.as_os_str());
        let mut line:Vec<u16>="\"".encode_utf16().chain(exe.as_os_str().encode_wide())
            .chain(format!("\" {} {port} {nonce}",if terminal {"--user-terminal-worker"}else{"--user-command-worker"}).encode_utf16()).chain(Some(0)).collect();
        let mut info=STARTUPINFOW::default();info.cb=std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi=PROCESS_INFORMATION::default();
        let job=Handle(unsafe{CreateJobObjectW(null(),null())});
        if job.0.is_null(){return Err("USER_JOB_UNAVAILABLE".into());}
        let mut limit=JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if unsafe{SetInformationJobObject(job.0,JobObjectExtendedLimitInformation,
            (&limit as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32)}==0 {
            return Err("USER_JOB_UNAVAILABLE".into());
        }
        if unsafe{CreateProcessAsUserW(token.0,exe_w.as_ptr(),line.as_mut_ptr(),null(),null(),0,
            CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT|CREATE_NO_WINDOW,env.0,
            profile.as_ptr(),&info,&mut pi)}==0{return Err("OWNER_WORKER_LAUNCH_FAILED".into());}
        let process=Handle(pi.hProcess);let initial=Handle(pi.hThread);
        if unsafe{AssignProcessToJobObject(job.0,process.0)}==0 ||
            unsafe{ResumeThread(initial.0)}==u32::MAX {
            unsafe{TerminateProcess(process.0,1);}
            return Err("OWNER_WORKER_JOB_FAILED".into());
        }
        Ok((process,job))
    }
    fn read_line(stream:&mut TcpStream,limit:usize,active:&impl Fn()->bool)->Result<Vec<u8>,String>{
        stream.set_read_timeout(Some(Duration::from_millis(200))).map_err(|_|"WORKER_IO")?;
        let mut result=Vec::new();let mut buf=[0u8;4096];
        while active() {
            match stream.read(&mut buf) {
                Ok(0)=>return Err("WORKER_DISCONNECTED".into()),
                Ok(n)=>{
                    if result.len()+n>limit {return Err("WORKER_OUTPUT_TOO_LARGE".into());}
                    result.extend_from_slice(&buf[..n]);
                    if result.last()==Some(&b'\n'){return Ok(result);}
                },
                Err(e) if matches!(e.kind(),std::io::ErrorKind::WouldBlock|std::io::ErrorKind::TimedOut)=>{},
                Err(_)=>return Err("WORKER_IO".into()),
            }
        }
        Err("COMMAND_CANCELED_OR_EXPIRED".into())
    }
    pub fn run(command:&str,state:&Path,elevated:bool,active:impl Fn()->bool)->Result<Value,String>{
        if !active(){return Err("GRANT_REVOKED".into());}
        let cfg:Value=serde_json::from_slice(&std::fs::read(state.parent().ok_or("MACHINE_STATE_MISSING")?.join("gateway.json"))
            .map_err(|_|"OWNER_CONFIGURATION_MISSING")?).map_err(|_|"OWNER_CONFIGURATION_INVALID")?;
        let owner=cfg["ownerSid"].as_str().ok_or("OWNER_CONFIGURATION_INVALID")?;
        let listener=TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST,0)).map_err(|_|"WORKER_BIND_FAILED")?;
        listener.set_nonblocking(true).map_err(|_|"WORKER_BIND_FAILED")?;
        let nonce=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());
        let port=listener.local_addr().map_err(|_|"WORKER_BIND_FAILED")?.port();
        let (process,_job)=launch(owner,port,&nonce,elevated,false)?;
        let deadline=Instant::now()+Duration::from_secs(8);
        let mut stream=loop {
            if !active(){return Err("COMMAND_CANCELED_OR_EXPIRED".into());}
            if Instant::now()>=deadline || unsafe{WaitForSingleObject(process.0,0)}==WAIT_OBJECT_0 {
                return Err("OWNER_WORKER_OFFLINE".into());
            }
            match listener.accept(){
                Ok((s,addr)) if addr.ip().is_loopback()=>break s,
                Ok(_)=>continue,
                Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>thread::sleep(Duration::from_millis(20)),
                Err(_)=>return Err("WORKER_ACCEPT_FAILED".into())
            }
        };
        let handshake=read_line(&mut stream,128,&||active() && Instant::now()<deadline)?;
        if handshake!=format!("{nonce}\n").as_bytes(){return Err("OWNER_WORKER_AUTH_FAILED".into());}
        if !active(){return Err("COMMAND_CANCELED_OR_EXPIRED".into());}
        stream.set_write_timeout(Some(Duration::from_secs(1))).map_err(|_|"WORKER_IO")?;
        let mut request=serde_json::to_vec(&json!({"command":command})).map_err(|_|"WORKER_REQUEST_INVALID")?;
        request.push(b'\n');stream.write_all(&request).map_err(|_|"WORKER_IO")?;
        let raw=read_line(&mut stream,96*1024,&active)?;
        let result:Value=serde_json::from_slice(&raw).map_err(|_|"WORKER_RESPONSE_INVALID")?;
        if !active(){return Err("COMMAND_CANCELED_OR_EXPIRED".into());}
        if result.as_object().is_some_and(|o|o.len()==4) && result["exit_code"].as_i64().is_some_and(|x|i32::try_from(x).is_ok())
            && result["stdout"].as_str().is_some_and(|s|s.len()<=24000)
            && result["stderr"].as_str().is_some_and(|s|s.len()<=24000) && result["truncated"].is_boolean() {
            Ok(result)
        }else{Err("WORKER_RESPONSE_INVALID".into())}
    }
    pub struct TerminalShell {
        pub process:OwnedHandle,
        pub job:OwnedHandle,
        pub input:TcpStream,
        pub output:TcpStream,
        pub error:TcpStream,
    }
    fn owned(handle:Handle)->OwnedHandle {
        let handle=std::mem::ManuallyDrop::new(handle);
        unsafe{OwnedHandle::from_raw_handle(handle.0)}
    }
    pub fn terminal_shell(state:&Path,elevated:bool)->Result<TerminalShell,String>{
        let cfg:Value=serde_json::from_slice(&std::fs::read(state.parent().ok_or("MACHINE_STATE_MISSING")?.join("gateway.json"))
            .map_err(|_|"OWNER_CONFIGURATION_MISSING")?).map_err(|_|"OWNER_CONFIGURATION_INVALID")?;
        let owner=cfg["ownerSid"].as_str().ok_or("OWNER_CONFIGURATION_INVALID")?;
        let listener=TcpListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST,0)).map_err(|_|"WORKER_BIND_FAILED")?;
        listener.set_nonblocking(true).map_err(|_|"WORKER_BIND_FAILED")?;
        let nonce=format!("{}{}",uuid::Uuid::new_v4().simple(),uuid::Uuid::new_v4().simple());
        let port=listener.local_addr().map_err(|_|"WORKER_BIND_FAILED")?.port();
        let (process,job)=launch(owner,port,&nonce,elevated,true)?;
        let deadline=Instant::now()+Duration::from_secs(6);
        let mut main=None;let mut error=None;
        while main.is_none() || error.is_none() {
            if Instant::now()>=deadline || unsafe{WaitForSingleObject(process.0,0)}==WAIT_OBJECT_0 {
                return Err("OWNER_TERMINAL_OFFLINE".into());
            }
            let (mut s,_)=match listener.accept(){
                Ok(v)=>v,
                Err(e) if e.kind()==std::io::ErrorKind::WouldBlock=>{thread::sleep(Duration::from_millis(20));continue;},
                Err(_)=>return Err("WORKER_ACCEPT_FAILED".into())
            };
            s.set_nonblocking(false).map_err(|_|"WORKER_IO")?;
            s.set_read_timeout(Some(Duration::from_millis(500))).map_err(|_|"WORKER_IO")?;
            let mut hello=[0u8;65];
            if s.read_exact(&mut hello).is_err() || &hello[..64]!=nonce.as_bytes(){continue;}
            s.set_read_timeout(None).map_err(|_|"WORKER_IO")?;
            s.set_write_timeout(Some(Duration::from_secs(3))).map_err(|_|"WORKER_IO")?;
            match hello[64] {
                b'O' if main.is_none()=>main=Some(s),
                b'E' if error.is_none()=>error=Some(s),
                _=>return Err("OWNER_TERMINAL_AUTH_FAILED".into())
            }
        }
        let output=main.unwrap();
        let input=output.try_clone().map_err(|_|"WORKER_IO")?;
        Ok(TerminalShell{process:owned(process),job:owned(job),input,output,error:error.unwrap()})
    }
    pub fn terminal_worker(port:u16,nonce:&str)->Result<(),String>{
        if nonce.len()!=64 || !nonce.bytes().all(|b|b.is_ascii_hexdigit()) {return Err("WORKER_AUTH_INVALID".into());}
        let connect=|role:u8|->Result<TcpStream,String>{
            let mut stream=TcpStream::connect_timeout(&SocketAddrV4::new(Ipv4Addr::LOCALHOST,port).into(),Duration::from_secs(3))
                .map_err(|_|"WORKER_CONNECT_FAILED")?;
            stream.set_write_timeout(Some(Duration::from_secs(8))).map_err(|_|"WORKER_IO")?;
            let mut hello=nonce.as_bytes().to_vec();hello.push(role);
            stream.write_all(&hello).map_err(|_|"WORKER_IO")?;
            Ok(stream)
        };
        let mut output=connect(b'O')?;let mut error=connect(b'E')?;
        let mut input=output.try_clone().map_err(|_|"WORKER_IO")?;
        let powershell=Path::new(&std::env::var_os("SystemRoot").ok_or("SYSTEM_ROOT_MISSING")?)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let encoded=crate::unattended::base64_encode(&crate::terminal::BOOTSTRAP.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
        let mut child=Command::new(powershell).args(["-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",&encoded])
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped()).creation_flags(CREATE_NO_WINDOW)
            .spawn().map_err(|_|"SHELL_UNAVAILABLE")?;
        let mut stdin=child.stdin.take().ok_or("WORKER_PIPE_FAILED")?;
        let mut stdout=child.stdout.take().ok_or("WORKER_PIPE_FAILED")?;
        let mut stderr=child.stderr.take().ok_or("WORKER_PIPE_FAILED")?;
        let _input=thread::spawn(move||std::io::copy(&mut input,&mut stdin));
        let out=thread::spawn(move||std::io::copy(&mut stdout,&mut output));
        let err=thread::spawn(move||std::io::copy(&mut stderr,&mut error));
        child.wait().map_err(|_|"SHELL_EXIT_FAILED")?;
        let _=out.join();let _=err.join();
        Ok(())
    }

    pub fn worker(port:u16,nonce:&str)->Result<(),String>{
        if nonce.len()!=64 || !nonce.bytes().all(|b|b.is_ascii_hexdigit()) {return Err("WORKER_AUTH_INVALID".into());}
        let mut stream=TcpStream::connect_timeout(&SocketAddrV4::new(Ipv4Addr::LOCALHOST,port).into(),Duration::from_secs(3))
            .map_err(|_|"WORKER_CONNECT_FAILED")?;
        stream.set_read_timeout(Some(Duration::from_secs(8))).map_err(|_|"WORKER_IO")?;
        stream.set_write_timeout(Some(Duration::from_secs(8))).map_err(|_|"WORKER_IO")?;
        stream.write_all(format!("{nonce}\n").as_bytes()).map_err(|_|"WORKER_IO")?;
        let mut input=Vec::new();
        BufReader::new(&stream).take(16*1024).read_until(b'\n',&mut input).map_err(|_|"WORKER_IO")?;
        let request:Value=serde_json::from_slice(&input).map_err(|_|"WORKER_REQUEST_INVALID")?;
        let command=request["command"].as_str().filter(|c|crate::elevation::valid_command(c)).ok_or("WORKER_REQUEST_INVALID")?;
        let powershell=Path::new(&std::env::var_os("SystemRoot").ok_or("SYSTEM_ROOT_MISSING")?)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe");
        let encoded=crate::unattended::base64_encode(&command.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<_>>());
        let mut child=Command::new(powershell).args(["-NoLogo","-NoProfile","-NonInteractive","-EncodedCommand",&encoded])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).creation_flags(CREATE_NO_WINDOW)
            .spawn().map_err(|_|"SHELL_UNAVAILABLE")?;
        let stdout=child.stdout.take().ok_or("WORKER_PIPE_FAILED")?;
        let stderr=child.stderr.take().ok_or("WORKER_PIPE_FAILED")?;
        let out=thread::spawn(move||crate::unattended::capture(stdout));
        let err=thread::spawn(move||crate::unattended::capture(stderr));
        let status=child.wait().map_err(|_|"SHELL_EXIT_FAILED")?;
        let (stdout,o)=out.join().map_err(|_|"WORKER_PIPE_FAILED")?;
        let (stderr,e)=err.join().map_err(|_|"WORKER_PIPE_FAILED")?;
        let mut response=serde_json::to_vec(&json!({"exit_code":status.code().unwrap_or(-1),"stdout":stdout,"stderr":stderr,"truncated":o||e}))
            .map_err(|_|"WORKER_RESPONSE_INVALID")?;
        response.push(b'\n');stream.write_all(&response).map_err(|_|"WORKER_IO".to_string())
    }
}
#[cfg(windows)]pub use platform::{run,worker,terminal_shell,terminal_worker};
