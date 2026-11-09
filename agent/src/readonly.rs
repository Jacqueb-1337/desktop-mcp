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
fn reparse(path: &Path) -> Result<bool, String> {
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
fn validate_root(root: &Path) -> Result<(), String> {
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
pub fn fs_read(root: &Path, args: &Value) -> Result<Value, String> {
    if args.as_object().is_none_or(|o| o.len() != 1) {
        return Err("INVALID_READ_ARGUMENTS".into());
    }
    let path = args["path"]
        .as_str()
        .filter(|s| valid_read_path(s))
        .ok_or("READ_PATH_NOT_PERMITTED")?;
    run_worker(root, Some(path))
}
pub fn git_status(root: &Path, args: &Value) -> Result<Value, String> {
    if args != &json!({}) {
        return Err("INVALID_GIT_STATUS_ARGUMENTS".into());
    }
    run_worker(root, None)
}
fn run_worker(root: &Path, path: Option<&str>) -> Result<Value, String> {
    validate_root(root)?;
    let executable = std::env::current_exe().map_err(|_| "STATUS_WORKER_UNAVAILABLE")?;
    let mut command = Command::new(executable);
    command
        .env_clear()
        .args([
            if path.is_some() {
                "--readonly-read-worker"
            } else {
                "--readonly-status-worker"
            },
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
