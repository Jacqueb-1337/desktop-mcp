//! Dedicated remote executor: fixed Git executable, fixed read-only arguments,
//! bounded output/time, no shell, hooks, fsmonitor, optional locks or submodules.
use serde_json::{json, Value};
use std::{
    fs,
    io::Read,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};
pub(crate) fn reparse(path: &Path) -> Result<bool, String> {
    let m = fs::symlink_metadata(path).map_err(|_| "WORKSPACE_UNAVAILABLE")?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        return Ok(m.file_attributes() & 0x400 != 0);
    }
    #[cfg(not(windows))]
    {
        Ok(m.file_type().is_symlink())
    }
}
pub(crate) fn validate_root(root: &Path) -> Result<(), String> {
    // Refuse linked worktrees and submodules whose Git directory lives elsewhere.
    if !root.is_absolute()
        || reparse(root)?
        || reparse(&root.join(".git"))?
        || !root.join(".git").is_dir()
    {
        return Err("REMOTE_REQUIRES_ORDINARY_REPOSITORY_ROOT".into());
    }
    for current in root.ancestors() {
        if reparse(current)? {
            return Err("WORKSPACE_REPARSE_POINT".into());
        }
    }
    Ok(())
}
pub fn status_worker(root: &Path) -> Result<Value, String> {
    validate_root(root)?;
    let repo = git2::Repository::open_ext(
        root,
        git2::RepositoryOpenFlags::NO_SEARCH,
        std::iter::empty::<&Path>(),
    )
    .map_err(|_| "GIT_REPOSITORY_INVALID")?;
    // Never let repository config redirect the worktree or Git directory.
    if repo.is_bare()
        || repo
            .workdir()
            .and_then(|p| p.canonicalize().ok())
            .as_deref()
            != Some(root)
        || repo
            .path()
            .canonicalize()
            .map_err(|_| "GIT_DIRECTORY_INVALID")?
            != root
                .join(".git")
                .canonicalize()
                .map_err(|_| "GIT_DIRECTORY_INVALID")?
    {
        return Err("GIT_WORKSPACE_MISMATCH".into());
    }
    let mut options = git2::StatusOptions::new();
    options
        .include_untracked(true)
        .recurse_untracked_dirs(false)
        .exclude_submodules(true)
        .renames_head_to_index(false)
        .renames_index_to_workdir(false)
        .no_refresh(true)
        .update_index(false);
    let statuses = repo
        .statuses(Some(&mut options))
        .map_err(|_| "GIT_STATUS_FAILED")?;
    if statuses.len() > 512 {
        return Err("GIT_OUTPUT_LIMIT".into());
    }
    let mut entries = Vec::new();
    for entry in statuses.iter() {
        let path = entry.path().map_err(|_| "GIT_PATH_ENCODING_UNSUPPORTED")?;
        if Path::new(path).is_absolute() || path.split('/').any(|p| p == "..") {
            return Err("GIT_PATH_OUTSIDE_WORKSPACE".into());
        }
        let status = entry.status();
        let index = if status.is_conflicted() {
            "U"
        } else if status.is_index_new() {
            "A"
        } else if status.is_index_modified() {
            "M"
        } else if status.is_index_deleted() {
            "D"
        } else if status.is_index_typechange() {
            "T"
        } else if status.is_wt_new() {
            "?"
        } else {
            " "
        };
        let worktree = if status.is_conflicted() {
            "U"
        } else if status.is_wt_new() {
            "?"
        } else if status.is_wt_modified() {
            "M"
        } else if status.is_wt_deleted() {
            "D"
        } else if status.is_wt_typechange() {
            "T"
        } else {
            " "
        };
        entries.push(json!({"index":index,"worktree":worktree,"path":path}));
    }
    let result = json!({"clean":entries.is_empty(),"entries":entries});
    if serde_json::to_vec(&result)
        .map_err(|_| "GIT_OUTPUT_INVALID")?
        .len()
        > 60000
    {
        return Err("GIT_OUTPUT_LIMIT".into());
    }
    Ok(result)
}
pub fn valid_read_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 500
        && !path.contains(['\\', ':', '\0'])
        && path.split('/').all(|p| {
            !p.is_empty()
                && p != "."
                && p != ".."
                && !p.eq_ignore_ascii_case(".git")
                && !p.ends_with([' ', '.'])
                && !p.contains(['<', '>', '|', '?', '*'])
        })
}
pub fn read_worker(root: &Path, path: &str) -> Result<Value, String> {
    use sha2::{Digest, Sha256};
    validate_root(root)?;
    if !valid_read_path(path) {
        return Err("READ_PATH_NOT_PERMITTED".into());
    }
    let dir = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
        .map_err(|_| "WORKSPACE_UNAVAILABLE")?;
    let file = dir
        .open(path)
        .map_err(|_| "READ_PATH_NOT_PERMITTED_OR_MISSING")?;
    if !file
        .metadata()
        .map_err(|_| "READ_METADATA_FAILED")?
        .is_file()
    {
        return Err("READ_REQUIRES_REGULAR_FILE".into());
    }
    let mut bytes = Vec::new();
    file.take(16385)
        .read_to_end(&mut bytes)
        .map_err(|_| "READ_FAILED")?;
    if bytes.len() > 16384 {
        return Err("READ_LIMIT_16_KIB".into());
    }
    let content = std::str::from_utf8(&bytes).map_err(|_| "READ_REQUIRES_UTF8_TEXT")?;
    if content.contains('\0') {
        return Err("READ_REQUIRES_UTF8_TEXT".into());
    }
    Ok(
        json!({"path":path,"content":content,"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes))}),
    )
}
pub fn valid_read_args(args: &Value) -> bool {
    args.as_object().is_some_and(|o| {
        o.keys().all(|k| matches!(k.as_str(),"path"|"start_line"|"end_line"))
        && args["path"].as_str().is_some_and(valid_read_path)
        && o.get("start_line").is_none_or(|v|v.as_u64().is_some_and(|n|(1..=8_388_608).contains(&n)))
        && o.get("end_line").is_none_or(|v|v.as_u64().is_some_and(|n|(1..=8_388_608).contains(&n)))
        && args["end_line"].as_u64().is_none_or(|end| end>=args["start_line"].as_u64().unwrap_or(1))
    })
}
pub fn ranged_read_worker(root:&Path,args:&Value)->Result<Value,String> {
    use sha2::{Digest,Sha256};
    validate_root(root)?;
    if !valid_read_args(args) {return Err("INVALID_READ_ARGUMENTS".into());}
    let path=args["path"].as_str().unwrap();
    let mut current=root.to_path_buf();
    for part in path.split('/') {
        current.push(part);
        if reparse(&current)? {return Err("READ_REPARSE_POINT".into());}
    }
    let dir=cap_std::fs::Dir::open_ambient_dir(root,cap_std::ambient_authority()).map_err(|_|"WORKSPACE_UNAVAILABLE")?;
    let file=dir.open(path).map_err(|_|"READ_PATH_NOT_PERMITTED_OR_MISSING")?;
    const MAX_BYTES:usize=8*1024*1024;
    if !file.metadata().is_ok_and(|m|m.is_file() && m.len()<=MAX_BYTES as u64) {
        return Err("READ_REQUIRES_REGULAR_FILE_UP_TO_8_MIB".into());
    }
    let mut bytes=Vec::new();
    file.take(MAX_BYTES as u64+1).read_to_end(&mut bytes).map_err(|_|"READ_FAILED")?;
    if bytes.len()>MAX_BYTES {return Err("READ_LIMIT_8_MIB".into());}
    let text=std::str::from_utf8(&bytes).map_err(|_|"READ_REQUIRES_UTF8_TEXT")?;
    if text.contains('\0') {return Err("READ_REQUIRES_UTF8_TEXT".into());}
    let start=args["start_line"].as_u64().unwrap_or(1) as usize;
    let end=args["end_line"].as_u64().unwrap_or(u64::MAX).min(8_388_608) as usize;
    let total=text.split_inclusive('\n').count();
    if start>total && !(total==0 && start==1) {return Err("READ_LINE_OUT_OF_RANGE".into());}
    let mut content=String::new();
    let mut last=start-1;
    let mut escaped=0usize;
    for (i,line) in text.split_inclusive('\n').enumerate().skip(start-1).take(end-start+1) {
        if content.len()+line.len()>16384 {
            if content.is_empty() {return Err("READ_LINE_EXCEEDS_PAGE_LIMIT".into());}
            break;
        }
        let encoded=serde_json::to_vec(line).map_err(|_|"READ_ENCODING_FAILED")?.len().saturating_sub(2);
        if escaped+encoded>48000 {
            if content.is_empty() {return Err("READ_LINE_EXCEEDS_PAGE_LIMIT".into());}
            break;
        }
        content.push_str(line);
        escaped+=encoded;
        last=i+1;
    }
    let repo=git2::Repository::open_ext(root,git2::RepositoryOpenFlags::NO_SEARCH,std::iter::empty::<&Path>())
        .map_err(|_|"GIT_REPOSITORY_INVALID")?;
    if repo.workdir().and_then(|p|p.canonicalize().ok()).as_deref()!=Some(root)
        || repo.path().canonicalize().ok()!=root.join(".git").canonicalize().ok() {
        return Err("GIT_WORKSPACE_MISMATCH".into());
    }
    let head=repo.head().ok().and_then(|h|h.peel_to_commit().ok()).map(|c|c.id().to_string());
    Ok(json!({"path":path,"content":content,"bytes":bytes.len(),"page_bytes":content.len(),
        "sha256":hex::encode(Sha256::digest(&bytes)),"head":head,"start_line":start,"end_line":last,
        "total_lines":total,"next_start_line":if last<total {Some(last+1)}else{None},
        "truncated":last<end.min(total)}))
}
pub fn valid_list_query(query:&Value)->bool {
    query.as_object().is_some_and(|o|
        o.keys().all(|k|matches!(k.as_str(),"path"|"depth"|"limit"|"offset"))
        && o.get("path").is_none_or(|v|v.as_str().is_some_and(|s|s=="."||valid_read_path(s)))
        && o.get("depth").is_none_or(|v|v.as_u64().is_some_and(|n|(1..=5).contains(&n)))
        && o.get("limit").is_none_or(|v|v.as_u64().is_some_and(|n|(1..=200).contains(&n)))
        && o.get("offset").is_none_or(|v|v.as_u64().is_some_and(|n|n<=20000)))
}
pub fn valid_diff_query(query:&Value)->bool {
    query.as_object().is_some_and(|o|
        o.keys().all(|k|matches!(k.as_str(),"path"|"base"|"context"))
        && query["path"].as_str().is_some_and(valid_read_path)
        && o.get("base").is_none_or(|v|matches!(v.as_str(),Some("head"|"staged"|"unstaged")))
        && o.get("context").is_none_or(|v|v.as_u64().is_some_and(|n|n<=10)))
}
fn check_components(root:&Path,path:&str,allow_missing:bool)->Result<bool,String>{
    let mut current=root.to_path_buf();
    for part in path.split('/') {
        current.push(part);
        match fs::symlink_metadata(&current) {
            Ok(_)=>if reparse(&current)?{return Err("READ_REPARSE_POINT".into());},
            Err(e) if allow_missing && e.kind()==std::io::ErrorKind::NotFound=>return Ok(false),
            Err(_)=>return Err("READ_PATH_NOT_PERMITTED_OR_MISSING".into()),
        }
    }
    Ok(true)
}
pub fn list_worker(root:&Path,query:&Value)->Result<Value,String>{
    validate_root(root)?;
    if !valid_list_query(query){return Err("INVALID_LIST_QUERY".into());}
    let path=query["path"].as_str().unwrap_or(".");
    let depth=query["depth"].as_u64().unwrap_or(1) as usize;
    let limit=query["limit"].as_u64().unwrap_or(100) as usize;
    let offset=query["offset"].as_u64().unwrap_or(0) as usize;
    if path!="."{check_components(root,path,false)?;}
    let dir=cap_std::fs::Dir::open_ambient_dir(root,cap_std::ambient_authority()).map_err(|_|"WORKSPACE_UNAVAILABLE")?;
    let mut pending=vec![(if path=="."{String::new()}else{path.to_owned()},0usize)];
    let mut entries=Vec::new();
    let mut skipped=0usize;
    let mut scanned=0usize;
    let mut exhausted=false;
    let deadline=Instant::now()+Duration::from_secs(4);
    'walk: while let Some((parent,level))=pending.pop(){
        let handle=if parent.is_empty(){dir.try_clone()}else{dir.open_dir(&parent)};
        let handle=match handle{Ok(h)=>h,Err(_) if level>0=>{skipped+=1;continue;},Err(_)=>return Err("LIST_REQUIRES_DIRECTORY".into())};
        let items=match handle.entries(){Ok(v)=>v,Err(_) if level>0=>{skipped+=1;continue;},Err(_)=>return Err("LIST_DIRECTORY_FAILED".into())};
        for item in items {
            if Instant::now()>=deadline || scanned>=20000 {exhausted=true;break 'walk;}
            scanned+=1;
            let Ok(item)=item else{skipped+=1;continue;};
            let name=item.file_name();
            let Some(name)=name.to_str()else{skipped+=1;continue;};
            let relative=if parent.is_empty(){name.to_owned()}else{format!("{parent}/{name}")};
            if !valid_read_path(&relative)||check_components(root,&relative,false).is_err(){skipped+=1;continue;}
            let Ok(meta)=item.metadata()else{skipped+=1;continue;};
            if !meta.is_dir()&&!meta.is_file(){skipped+=1;continue;}
            if meta.is_dir()&&level+1<depth{pending.push((relative.clone(),level+1));}
            entries.push((relative,meta.is_dir(),meta.len()));
        }
    }
    entries.sort_unstable_by(|a,b|a.0.cmp(&b.0));
    let count=entries.len();
    let mut result=Vec::new();
    let mut bytes=0;
    for (path,directory,size) in entries.into_iter().skip(offset).take(limit){
        let item=json!({"path":path,"kind":if directory{"directory"}else{"file"},"bytes":if directory{None}else{Some(size)}});
        let n=serde_json::to_vec(&item).map_err(|_|"LIST_ENCODING_FAILED")?.len();
        if bytes+n>48000{break;}
        bytes+=n;result.push(item);
    }
    let next=offset+result.len();
    Ok(json!({"path":path,"entries":result,"offset":offset,"scanned":scanned,"skipped":skipped,
        "scan_budget_exhausted":exhausted,"truncated":exhausted||next<count,
        "next_offset":if !exhausted&&next<count{Some(next)}else{None}}))
}
fn diff_blob(repo:&git2::Repository,id:git2::Oid,mode:i32)->Result<Vec<u8>,String>{
    if !matches!(mode,0o100644|0o100755){return Err("DIFF_REQUIRES_REGULAR_FILE".into());}
    let blob=repo.find_blob(id).map_err(|_|"DIFF_BLOB_UNAVAILABLE")?;
    if blob.size()>256*1024{return Err("DIFF_FILE_LIMIT_256_KIB".into());}
    Ok(blob.content().to_vec())
}
pub fn diff_worker(root:&Path,query:&Value)->Result<Value,String>{
    validate_root(root)?;
    if !valid_diff_query(query){return Err("INVALID_DIFF_QUERY".into());}
    let path=query["path"].as_str().unwrap();
    let base=query["base"].as_str().unwrap_or("head");
    let repo=git2::Repository::open_ext(root,git2::RepositoryOpenFlags::NO_SEARCH,std::iter::empty::<&Path>()).map_err(|_|"GIT_REPOSITORY_INVALID")?;
    if repo.workdir().and_then(|p|p.canonicalize().ok()).as_deref()!=Some(root)
        || repo.path().canonicalize().ok()!=root.join(".git").canonicalize().ok(){return Err("GIT_WORKSPACE_MISMATCH".into());}
    let rel=Path::new(path);
    let head=match repo.head(){
        Ok(h)=>Some(h.peel_to_commit().map_err(|_|"DIFF_HEAD_INVALID")?),
        Err(e) if matches!(e.code(),git2::ErrorCode::UnbornBranch|git2::ErrorCode::NotFound)=>None,
        Err(_)=>return Err("DIFF_HEAD_INVALID".into()),
    };
    let head_bytes=||->Result<Option<Vec<u8>>,String>{
        let Some(commit)=&head else{return Ok(None);};
        let tree=commit.tree().map_err(|_|"DIFF_TREE_INVALID")?;
        match tree.get_path(rel){
            Ok(entry)=>diff_blob(&repo,entry.id(),entry.filemode()).map(Some),
            Err(e) if e.code()==git2::ErrorCode::NotFound=>Ok(None),
            Err(_)=>Err("DIFF_TREE_PATH_INVALID".into()),
        }
    };
    let index_bytes=||->Result<Option<Vec<u8>>,String>{
        let index=repo.index().map_err(|_|"DIFF_INDEX_INVALID")?;
        if (1..=3).any(|stage|index.get_path(rel,stage).is_some()){return Err("DIFF_INDEX_CONFLICT".into());}
        index.get_path(rel,0).map(|e|diff_blob(&repo,e.id,e.mode as i32)).transpose()
    };
    let worktree_bytes=||->Result<Option<Vec<u8>>,String>{
        if !check_components(root,path,true)?{return Ok(None);}
        let dir=cap_std::fs::Dir::open_ambient_dir(root,cap_std::ambient_authority()).map_err(|_|"WORKSPACE_UNAVAILABLE")?;
        let file=dir.open(path).map_err(|_|"DIFF_FILE_UNAVAILABLE")?;
        let meta=file.metadata().map_err(|_|"DIFF_METADATA_FAILED")?;
        if !meta.is_file(){return Err("DIFF_REQUIRES_REGULAR_FILE".into());}
        if meta.len()>256*1024{return Err("DIFF_FILE_LIMIT_256_KIB".into());}
        let mut bytes=Vec::new();
        file.take(256*1024+1).read_to_end(&mut bytes).map_err(|_|"DIFF_READ_FAILED")?;
        if bytes.len()>256*1024{return Err("DIFF_FILE_LIMIT_256_KIB".into());}
        Ok(Some(bytes))
    };
    // Compare captured bytes rather than allowing Git to invoke filters,
    // external diff drivers, follow worktree links, or read arbitrary paths.
    let (old,new)=match base{
        "staged"=>(head_bytes()?,index_bytes()?),
        "unstaged"=>(index_bytes()?,worktree_bytes()?),
        _=>(head_bytes()?,worktree_bytes()?),
    };
    if old.is_none()&&new.is_none(){return Err("DIFF_PATH_NOT_FOUND".into());}
    let old_exists=old.is_some();let new_exists=new.is_some();
    let a=old.as_deref().unwrap_or(&[]);let b=new.as_deref().unwrap_or(&[]);
    let binary=[a,b].iter().any(|v|v.contains(&0)||std::str::from_utf8(v).is_err());
    let changed=old!=new;
    let mut diff=String::new();let mut truncated=false;
    if changed&&!binary {
        let mut opts=git2::DiffOptions::new();
        opts.context_lines(query["context"].as_u64().unwrap_or(3) as u32);
        let mut patch=git2::Patch::from_buffers(a,old_exists.then_some(rel),b,new_exists.then_some(rel),Some(&mut opts))
            .map_err(|_|"DIFF_GENERATION_FAILED")?;
        let buf=patch.to_buf().map_err(|_|"DIFF_GENERATION_FAILED")?;
        let text=std::str::from_utf8(buf.as_ref()).map_err(|_|"DIFF_ENCODING_FAILED")?;
        let mut escaped=0;
        for line in text.split_inclusive('\n'){
            let n=serde_json::to_vec(line).map_err(|_|"DIFF_ENCODING_FAILED")?.len().saturating_sub(2);
            if escaped+n>48000{truncated=true;break;}
            escaped+=n;diff.push_str(line);
        }
    }
    Ok(json!({"path":path,"base":base,"head":head.map(|c|c.id().to_string()),"changed":changed,
        "old_exists":old_exists,"new_exists":new_exists,"binary":binary,"diff":diff,"truncated":truncated,
        "old_bytes":a.len(),"new_bytes":b.len()}))
}
pub fn fs_list(root:&Path,args:&Value)->Result<Value,String>{
    if args.as_object().is_none_or(|o|o.len()!=1)||!valid_list_query(&args["query"]){return Err("INVALID_LIST_QUERY".into());}
    run_worker(root,"--readonly-list-worker",Some(&args["query"].to_string()))
}
pub fn git_diff(root:&Path,args:&Value)->Result<Value,String>{
    if args.as_object().is_none_or(|o|o.len()!=1)||!valid_diff_query(&args["query"]){return Err("INVALID_DIFF_QUERY".into());}
    run_worker(root,"--readonly-diff-worker",Some(&args["query"].to_string()))
}
pub fn fs_read(root: &Path, args: &Value) -> Result<Value, String> {
    if !valid_read_args(args) {return Err("INVALID_READ_ARGUMENTS".into());}
    let query=serde_json::to_string(args).map_err(|_|"INVALID_READ_ARGUMENTS")?;
    run_worker(root,"--readonly-range-worker",Some(&query))
}
pub fn git_status(root: &Path, args: &Value) -> Result<Value, String> {
    if args != &json!({}) {
        return Err("INVALID_GIT_STATUS_ARGUMENTS".into());
    }
    run_worker(root, "--readonly-status-worker", None)
}

/// A single workspace-pinned child. I/O is isolated from the service thread and
/// has the same hard deadline and bounded JSON response as one-shot workers.
#[derive(Debug,Default)]
pub struct SearchWorker {
    session:Option<SearchSession>,
}
#[derive(Debug)]
struct SearchSession {
    root:std::path::PathBuf,
    child:std::process::Child,
    requests:std::sync::mpsc::SyncSender<Vec<u8>>,
    responses:std::sync::mpsc::Receiver<Result<Value,String>>,
}
impl Drop for SearchSession {
    fn drop(&mut self) {
        let _=self.child.kill();
        let _=self.child.wait();
    }
}
impl SearchWorker {
    pub fn clear(&mut self){self.session=None;}
    pub fn query(&mut self,root:&Path,args:&Value)->Result<Value,String> {
        validate_root(root)?;
        if args.as_object().is_none_or(|o|o.len()!=1)||!crate::search::valid_query(&args["query"]) {
            return Err("INVALID_SEARCH_QUERY".into());
        }
        if self.session.as_ref().is_some_and(|s|s.root!=root){self.clear();}
        if self.session.is_none(){self.session=Some(SearchSession::start(root)?);}
        let mut request=serde_json::to_vec(&args["query"]).map_err(|_|"INVALID_SEARCH_QUERY")?;
        request.push(b'\n');
        if request.len()>32768{return Err("SEARCH_INPUT_LIMIT".into());}
        let session=self.session.as_ref().unwrap();
        if session.requests.try_send(request).is_err(){self.clear();return Err("SEARCH_WORKER_UNAVAILABLE".into());}
        let response=session.responses.recv_timeout(Duration::from_secs(6));
        match response {
            Ok(Ok(v))=> {
                if let Some(error)=v["error"].as_str(){return Err(error.into());}
                v.get("data").cloned().ok_or("SEARCH_OUTPUT_INVALID".into())
            }
            Ok(Err(error))=>{self.clear();Err(error)}
            Err(_)=>{self.clear();Err("SEARCH_WORKER_TIMEOUT".into())}
        }
    }
}
impl SearchSession {
    fn start(root:&Path)->Result<Self,String> {
        use std::io::{BufRead,BufReader,Write};
        let executable=std::env::current_exe().map_err(|_|"SEARCH_WORKER_UNAVAILABLE")?;
        let mut command=Command::new(executable);
        command.env_clear().args(["--readonly-search-session","--workspace"]).arg(root)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
        #[cfg(windows)] {
            use std::os::windows::process::CommandExt;
            command.env("SystemRoot",std::env::var_os("SystemRoot").ok_or("SYSTEM_ROOT_UNAVAILABLE")?);
            command.creation_flags(0x08000000);
        }
        let mut child=command.spawn().map_err(|_|"SEARCH_WORKER_UNAVAILABLE")?;
        let Some(mut input)=child.stdin.take()else{let _=child.kill();let _=child.wait();return Err("SEARCH_WORKER_PIPE".into());};
        let Some(output)=child.stdout.take()else{let _=child.kill();let _=child.wait();return Err("SEARCH_WORKER_PIPE".into());};
        let (requests,rx)=std::sync::mpsc::sync_channel::<Vec<u8>>(1);
        let (tx,responses)=std::sync::mpsc::sync_channel(1);
        thread::spawn(move||{
            let mut reader=BufReader::new(output);
            while let Ok(request)=rx.recv(){
                let result=(|| {
                    input.write_all(&request).and_then(|_|input.flush()).map_err(|_|"SEARCH_WORKER_WRITE_FAILED".to_string())?;
                    let mut bytes=Vec::new();
                    let n=reader.by_ref().take(65537).read_until(b'\n',&mut bytes).map_err(|_|"SEARCH_WORKER_READ_FAILED".to_string())?;
                    if n==0||n>65536||!bytes.ends_with(b"\n"){return Err("SEARCH_OUTPUT_LIMIT_OR_EOF".into());}
                    serde_json::from_slice::<Value>(&bytes).map_err(|_|"SEARCH_OUTPUT_INVALID".into())
                })();
                let failed=result.is_err();
                if tx.send(result).is_err()||failed{break;}
            }
        });
        Ok(Self{root:root.to_path_buf(),child,requests,responses})
    }
}
fn run_worker(root: &Path, mode: &str, path: Option<&str>) -> Result<Value, String> {
    validate_root(root)?;
    let executable = std::env::current_exe().map_err(|_| "STATUS_WORKER_UNAVAILABLE")?;
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args([
            mode,
            "--workspace",
        ])
        .arg(root);
    if let Some(path) = path {
        command.arg(path);
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    #[cfg(windows)]
    {
        let system = std::env::var_os("SystemRoot").ok_or("SYSTEM_ROOT_UNAVAILABLE")?;
        command.env("SystemRoot", &system);
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = command.spawn().map_err(|_| "STATUS_WORKER_UNAVAILABLE")?;
    let stdout = child.stdout.take().ok_or("GIT_OUTPUT_UNAVAILABLE")?;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stdout.take(65537).read_to_end(&mut bytes);
        (result, bytes)
    });
    let start = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if start.elapsed() < Duration::from_secs(6) => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reader.join();
                return Err("GIT_TIMEOUT_OR_OUTPUT_LIMIT".into());
            }
        }
    };
    let (read, bytes) = reader.join().map_err(|_| "GIT_READ_FAILED")?;
    if read.is_err() || bytes.len() > 65536 {
        return Err("GIT_OUTPUT_LIMIT".into());
    }
    if !status.success() {
        return Err("GIT_STATUS_FAILED".into());
    }
    let response: Value = serde_json::from_slice(&bytes).map_err(|_| "GIT_OUTPUT_INVALID")?;
    if let Some(error) = response["error"].as_str() {
        return Err(error.into());
    }
    response
        .get("data")
        .cloned()
        .ok_or("GIT_OUTPUT_INVALID".into())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn directory_queries_enforce_path_and_budget() {
        let tmp=tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        let root=tmp.path().canonicalize().unwrap();
        fs::create_dir(root.join("sub")).unwrap();
        fs::write(root.join("sub/one.txt"),"one").unwrap();
        fs::write(root.join("two.txt"),"two").unwrap();
        let first=list_worker(&root,&json!({"depth":2,"limit":1})).unwrap();
        let next=list_worker(&root,&json!({"depth":2,"offset":first["next_offset"]})).unwrap();
        assert_eq!(first["entries"][0]["path"],"sub");
        assert_eq!(next["entries"][0]["path"],"sub/one.txt");
        assert_eq!(next["entries"][1]["path"],"two.txt");
        for q in [json!({"path":"../"}),json!({"path":".git"}),json!({"depth":6}),
            json!({"limit":0}),json!({"offset":20001}),json!({"unknown":true})] {
            assert!(list_worker(&root,&q).is_err(),"{q}");
        }
        assert!(list_worker(&root,&json!({"path":"two.txt"})).is_err());
        assert!(diff_worker(&root,&json!({"path":"../outside"})).is_err());
        assert!(diff_worker(&root,&json!({"path":"two.txt","base":"arbitrary"})).is_err());
        assert!(diff_worker(&root,&json!({"path":"two.txt","context":11})).is_err());
        let diff=diff_worker(&root,&json!({"path":"two.txt"})).unwrap();
        assert_eq!(diff["old_exists"],false);
        assert_eq!(diff["new_exists"],true);
        assert!(diff["diff"].as_str().unwrap().contains("+two"));
        fs::write(root.join("big.txt"),vec![b'a';256*1024+1]).unwrap();
        assert!(diff_worker(&root,&json!({"path":"big.txt"})).is_err());
    }
    #[test]
    fn file_read_is_bounded_and_rejects_traversal_and_git_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        let root = tmp.path().canonicalize().unwrap();
        fs::write(root.join("example.txt"), "hello").unwrap();
        assert_eq!(
            read_worker(&root, "example.txt").unwrap()["content"],
            "hello"
        );
        for path in [
            "../secret",
            "/absolute",
            "C:/secret",
            "example.txt:stream",
            ".git/config",
            ".GIT/config",
            "./example.txt",
            "sub/../../secret",
            "sub\\secret",
            "file. ",
        ] {
            assert!(read_worker(&root, path).is_err(), "{path}");
        }
        fs::write(root.join("big.txt"), vec![b'a'; 16385]).unwrap();
        assert!(read_worker(&root, "big.txt").is_err());
        fs::write(root.join("binary"), [0, 255]).unwrap();
        assert!(read_worker(&root, "binary").is_err());
        #[cfg(unix)]
        {
            let outside = tempfile::tempdir().unwrap();
            fs::write(outside.path().join("secret"), "private").unwrap();
            std::os::unix::fs::symlink(outside.path(), root.join("escape")).unwrap();
            assert!(read_worker(&root, "escape/secret").is_err());
        }
    }
    #[test]
    fn ranged_read_preserves_full_hash_and_line_terminators() {
        use sha2::{Digest,Sha256};
        let tmp=tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        let root=tmp.path().canonicalize().unwrap();
        let text=format!("{}last", "abcdefghij\r\n".repeat(2000));
        fs::write(root.join("large.txt"),&text).unwrap();
        let first=ranged_read_worker(&root,&json!({"path":"large.txt"})).unwrap();
        assert_eq!(first["bytes"],text.len());
        assert_eq!(first["sha256"],hex::encode(Sha256::digest(text.as_bytes())));
        assert_eq!(first["truncated"],true);
        let next=first["next_start_line"].as_u64().unwrap();
        let second=ranged_read_worker(&root,&json!({"path":"large.txt","start_line":next})).unwrap();
        assert_eq!(second["sha256"],first["sha256"]);
        assert_eq!(second["next_start_line"],Value::Null);
        assert_eq!(format!("{}{}",first["content"].as_str().unwrap(),second["content"].as_str().unwrap()),text);
        let last=ranged_read_worker(&root,&json!({"path":"large.txt","start_line":2001,"end_line":2001})).unwrap();
        assert_eq!(last["content"],"last");
        assert!(ranged_read_worker(&root,&json!({"path":"large.txt","start_line":2002})).is_err());
        assert!(!valid_read_args(&json!({"path":"large.txt","start_line":10,"end_line":1})));
        fs::write(root.join("long.txt"),"x".repeat(20000)).unwrap();
        assert_eq!(ranged_read_worker(&root,&json!({"path":"long.txt"})).unwrap_err(),"READ_LINE_EXCEEDS_PAGE_LIMIT");
        fs::write(root.join("empty.txt"),"").unwrap();
        let empty=ranged_read_worker(&root,&json!({"path":"empty.txt"})).unwrap();
        assert_eq!(empty["total_lines"],0);
        assert_eq!(empty["content"],"");
    }
    #[test]
    fn refuses_arguments_and_linked_git_directory() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(git_status(tmp.path(), &json!({"command":"bad"})).is_err());
        fs::write(tmp.path().join(".git"), "gitdir: /elsewhere").unwrap();
        assert!(git_status(tmp.path(), &json!({})).is_err());
    }
    #[test]
    fn ignores_repository_command_filters_and_rejects_worktree_redirection() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = git2::Repository::init(tmp.path()).unwrap();
        fs::write(tmp.path().join(".gitattributes"), "*.txt filter=evil\n").unwrap();
        fs::write(tmp.path().join("example.txt"), "hello").unwrap();
        let mut index = repo.index().unwrap();
        index.add_path(Path::new("example.txt")).unwrap();
        index.write().unwrap();
        let mut cfg = repo.config().unwrap();
        cfg.set_str("filter.evil.clean", "touch SHOULD_NOT_EXIST")
            .unwrap();
        cfg.set_str("filter.evil.process", "touch SHOULD_NOT_EXIST")
            .unwrap();
        fs::write(tmp.path().join("example.txt"), "modified").unwrap();
        status_worker(&tmp.path().canonicalize().unwrap()).unwrap();
        assert!(!tmp.path().join("SHOULD_NOT_EXIST").exists());
        let other = tempfile::tempdir().unwrap();
        cfg.set_str("core.worktree", other.path().to_str().unwrap())
            .unwrap();
        assert!(status_worker(&tmp.path().canonicalize().unwrap()).is_err());
    }
    #[test]
    fn reports_actual_changes_without_hooks() {
        let tmp = tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        fs::write(tmp.path().join("example.txt"), "example").unwrap();
        let result = status_worker(&tmp.path().canonicalize().unwrap()).unwrap();
        assert_eq!(result["clean"], false);
        assert_eq!(result["entries"][0]["path"], "example.txt");
        assert_eq!(result["entries"][0]["index"], "?");
    }
}
