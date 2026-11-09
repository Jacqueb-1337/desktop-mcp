use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use similar::TextDiff;
use std::collections::{HashMap, HashSet};
use std::fs::{self};
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};
use tempfile::{NamedTempFile, TempDir};
use uuid::Uuid;

const MAX_FILE_BYTES: u64 = 256 * 1024;
const MAX_PATCHES: usize = 64;
const PROPOSAL_LIFETIME: Duration = Duration::from_secs(15 * 60);

type ApiResult = Result<Value, String>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchChange {
    path: String,
    operation: String,
    expected_sha256: Option<String>,
    new_content: Option<String>,
}

#[derive(Debug, Clone)]
struct Change {
    path: String,
    old_content: Option<String>,
    new_content: Option<String>,
    old_sha256: Option<String>,
    new_sha256: Option<String>,
    permissions: Option<fs::Permissions>,
}

struct Proposal {
    id: String,
    base_head: String,
    changes: Vec<Change>,
    diff: String,
    created: Instant,
    status: &'static str,
    commit: Option<String>,
}

pub struct Agent {
    workspace: PathBuf,
    approval_scope: PathBuf,
    desktop_mode: bool,
    allow_writes: bool,
    proposals: HashMap<String, Proposal>,
}

fn hash(input: &[u8]) -> String {
    format!("{:x}", Sha256::digest(input))
}

fn required<'a>(args: &'a Value, key: &str) -> Result<&'a str, String> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|v| !v.is_empty())
        .ok_or_else(|| format!("INVALID_ARGUMENT: missing or empty {key}"))
}

fn run_git(root: &Path, args: &[&str], index: Option<&Path>) -> Result<Output, String> {
    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(root).args(args);
    if let Some(index) = index {
        cmd.env("GIT_INDEX_FILE", index);
    }
    cmd.output().map_err(|e| format!("GIT_UNAVAILABLE: {e}"))
}

fn git(root: &Path, args: &[&str], index: Option<&Path>) -> Result<String, String> {
    let output = run_git(root, args, index)?;
    if !output.status.success() {
        return Err(format!(
            "GIT_ERROR: git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout)
        .map(|s| s.trim_end_matches('\n').trim_end_matches('\r').to_string())
        .map_err(|e| format!("GIT_ENCODING_ERROR: {e}"))
}

fn valid_rel_path(path: &str) -> Result<(), String> {
    if path.is_empty() || path.len() > 500 || path.contains('\\') || path.contains(':') || path.contains('\0') {
        return Err("INVALID_PATH: use a short, relative, forward-slash path".into());
    }
    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => {
                let part = part.to_string_lossy();
                if part.eq_ignore_ascii_case(".git") || part.ends_with(' ') || part.ends_with('.') {
                    return Err("INVALID_PATH: reserved Git or Windows path component".into());
                }
            }
            _ => return Err("INVALID_PATH: absolute or traversal path rejected".into()),
        }
    }
    Ok(())
}

impl Agent {
    pub fn new(root: &Path, allow_writes: bool) -> Result<Self, String> {
        let root = root.canonicalize().map_err(|e| format!("WORKSPACE_NOT_FOUND: {e}"))?;
        if !root.is_dir() {
            return Err("INVALID_WORKSPACE: path must be a directory".into());
        }
        let repo = git(&root, &["rev-parse", "--show-toplevel"], None)?;
        let repo_root = PathBuf::from(repo)
            .canonicalize()
            .map_err(|e| format!("INVALID_REPOSITORY: {e}"))?;
        if repo_root != root {
            return Err("INVALID_WORKSPACE: select the Git repository root".into());
        }
        Ok(Self {
            approval_scope: root.clone(),
            workspace: root,
            desktop_mode: false,
            allow_writes,
            proposals: HashMap::new(),
        })
    }

    /// Standalone desktop service. Installation and pairing need no Git repo.
    pub fn new_desktop(state: &Path) -> Result<Self, String> {
        let root = state.canonicalize().map_err(|e| format!("STATE_DIR_UNAVAILABLE: {e}"))?;
        if !root.is_dir() { return Err("INVALID_STATE_DIRECTORY".into()); }
        let mut agent = Self {
            approval_scope: root.clone(), workspace: root.clone(),
            // Remote patch tools are separately permission-gated by the local inbox.
            // This flag enables only the local patch engine; it grants no remote authority.
            desktop_mode: true, allow_writes: true, proposals: HashMap::new(),
        };
        if let Ok(saved) = fs::read_to_string(root.join("selected-repository.txt")) {
            // A missing/moved repo must not prevent the desktop agent from starting.
            let _ = agent.use_repository(saved.trim(), false);
        }
        Ok(agent)
    }

    pub fn authorization_scope(&self) -> &Path { &self.approval_scope }
    pub fn remote_patch_enabled(&self) -> bool { self.desktop_mode && self.allow_writes }
    pub fn root(&self) -> &Path { &self.workspace }

    /// Choose an existing repository or explicitly initialize an ordinary folder.
    /// Never create a repository at install time or silently track existing files.
    pub fn use_repository(&mut self, path: &str, initialize: bool) -> Result<Value, String> {
        if !self.desktop_mode { return Err("DESKTOP_MODE_REQUIRED".into()); }
        if path.is_empty() || path.len() > 500 || path.chars().any(char::is_control) {
            return Err("INVALID_REPOSITORY_PATH".into());
        }
        let supplied = Path::new(path);
        if !supplied.is_absolute() { return Err("ABSOLUTE_REPOSITORY_PATH_REQUIRED".into()); }
        let root = supplied.canonicalize().map_err(|_| "REPOSITORY_FOLDER_MISSING")?;
        if !root.is_dir() || root.parent().is_none() || root.components().count() < 2 {
            return Err("REPOSITORY_FOLDER_INVALID".into());
        }
        // Reject links/junctions anywhere in the proposed path, including ancestors.
        for ancestor in root.ancestors() {
            let metadata = fs::symlink_metadata(ancestor).map_err(|_| "REPOSITORY_PATH_UNSAFE")?;
            if metadata.file_type().is_symlink() { return Err("REPOSITORY_LINK_DENIED".into()); }
            #[cfg(windows)] {
                use std::os::windows::fs::MetadataExt;
                if metadata.file_attributes() & 0x400 != 0 {
                    return Err("REPOSITORY_REPARSE_POINT_DENIED".into());
                }
            }
        }
        #[cfg(windows)] {
            // Never initialize repositories inside Windows or Program Files.
            for key in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)"] {
                if let Some(system) = std::env::var_os(key) {
                    if root.starts_with(Path::new(&system)) {
                        return Err("PROTECTED_DIRECTORY_DENIED".into());
                    }
                }
            }
        }
        let git_dir = root.join(".git");
        if git_dir.exists() && !git_dir.is_dir() { return Err("UNSUPPORTED_GIT_WORKTREE".into()); }
        let fresh = !git_dir.exists();
        if fresh && !initialize { return Err("REPOSITORY_NOT_INITIALIZED".into()); }
        if fresh {
            git2::Repository::init(&root).map_err(|e| format!("REPOSITORY_INIT_FAILED: {e}"))?;
        }
        let repo = git2::Repository::open_ext(
            &root, git2::RepositoryOpenFlags::NO_SEARCH, std::iter::empty::<&Path>()
        ).map_err(|_| "REPOSITORY_INVALID")?;
        if repo.is_bare() || repo.workdir().and_then(|p| p.canonicalize().ok()).as_deref() != Some(root.as_path()) {
            return Err("REPOSITORY_ROOT_MISMATCH".into());
        }
        fs::write(self.approval_scope.join("selected-repository.txt"), root.to_string_lossy().as_bytes())
            .map_err(|_| "REPOSITORY_SELECTION_SAVE_FAILED")?;
        self.workspace = root.clone();
        self.proposals.clear();
        Ok(json!({"path":root.to_string_lossy(),"initialized":fresh,"selected":true}))
    }

    fn validate_target(&self, args: &Value) -> Result<(), String> {
        let host = required(args, "host_id")?;
        let workspace = required(args, "workspace_id")?;
        if host != "local" || workspace != "default" {
            return Err("UNKNOWN_TARGET: only host_id=local, workspace_id=default are available".into());
        }
        Ok(())
    }

    fn path(&self, relative: &str) -> Result<PathBuf, String> {
        valid_rel_path(relative)?;
        let mut candidate = self.workspace.clone();
        for comp in Path::new(relative).components() {
            candidate.push(comp.as_os_str());
            if let Ok(meta) = fs::symlink_metadata(&candidate) {
                if meta.file_type().is_symlink() {
                    return Err(format!("SYMLINK_DENIED: {relative}"));
                }
                #[cfg(windows)] {
                    use std::os::windows::fs::MetadataExt;
                    if meta.file_attributes() & 0x400 != 0 {
                        return Err(format!("REPARSE_POINT_DENIED: {relative}"));
                    }
                }
            }
        }
        if let Ok(canon) = candidate.canonicalize() {
            if !canon.starts_with(&self.workspace) {
                return Err("WORKSPACE_ESCAPE_DENIED".into());
            }
        } else {
            // New files must have an existing, canonical, non-symlinked parent.
            let parent = candidate.parent().ok_or("INVALID_PATH")?;
            let canon = parent.canonicalize()
                .map_err(|e| format!("INVALID_PARENT: {e}"))?;
            if !canon.starts_with(&self.workspace) {
                return Err("WORKSPACE_ESCAPE_DENIED".into());
            }
        }
        Ok(candidate)
    }

    fn read_text(&self, relative: &str) -> Result<Option<String>, String> {
        let path = self.path(relative)?;
        if !path.exists() {
            return Ok(None);
        }
        let metadata = fs::metadata(&path).map_err(|e| format!("FILE_ERROR: {e}"))?;
        if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
            return Err(format!("FILE_NOT_TEXT_OR_TOO_LARGE: max {MAX_FILE_BYTES} bytes"));
        }
        let bytes = fs::read(path).map_err(|e| format!("FILE_ERROR: {e}"))?;
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| "BINARY_FILE_UNSUPPORTED".into())
    }

    fn head(&self) -> Result<String, String> {
        if self.desktop_mode {
            let repo=git2::Repository::open_ext(&self.workspace,git2::RepositoryOpenFlags::NO_SEARCH,
                std::iter::empty::<&Path>()).map_err(|_|"REPOSITORY_INVALID")?;
            return Ok(repo.head().map_err(|_|"GIT_HEAD_UNBORN: create a baseline snapshot first")?
                .peel_to_commit().map_err(|_|"GIT_HEAD_INVALID")?.id().to_string());
        }
        git(&self.workspace, &["rev-parse", "--verify", "HEAD"], None)
    }

    fn target_clean(&self, path: &str) -> Result<(), String> {
        if self.desktop_mode {
            let repo=git2::Repository::open_ext(&self.workspace,git2::RepositoryOpenFlags::NO_SEARCH,
                std::iter::empty::<&Path>()).map_err(|_|"REPOSITORY_INVALID")?;
            return match repo.status_file(Path::new(path)) {
                Ok(git2::Status::CURRENT) => Ok(()),
                Err(e) if e.code()==git2::ErrorCode::NotFound && !self.workspace.join(path).exists()=>Ok(()),
                _ => Err(format!("DIRTY_TARGET: {path}; snapshot or commit existing edits first")),
            };
        }
        // Check both staged and unstaged changes relative to HEAD, for this file only.
        for args in [
            vec!["diff", "--quiet", "HEAD", "--", path],
            vec!["diff", "--cached", "--quiet", "HEAD", "--", path],
        ] {
            let out = run_git(&self.workspace, &args, None)?;
            if !out.status.success() {
                return Err(format!("DIRTY_TARGET: {path}; commit or discard existing edits to that file first"));
            }
        }
        Ok(())
    }

    pub fn dispatch(&mut self, name: &str, args: &Value) -> ApiResult {
        match name {
            "gateway_info" => Ok(json!({
                "mode":"local_stdio", "version":"0.1.0",
                "network_listener":false, "gateway_connected":false,
                "writes_enabled":self.allow_writes,
                "note":"This is a local MCP server, not yet connected to ChatGPT's remote gateway."
            })),
            "list_hosts" => Ok(json!({"hosts":[{"host_id":"local","name":"Local computer","connected":true,"workspace_ids":["default"]}]})),
            "get_capabilities" => Ok(json!({
                "host_id":"local", "workspace_id":"default",
                "implemented":["gateway_info","list_hosts","get_capabilities","fs_read","git_status","git_diff",
                    "patch_prepare","patch_review","patch_apply","patch_status","git_commit_patch"],
                "writes_enabled":self.allow_writes,
                "remote_pairing":false,"admin":false,"shell":false
            })),
            _ => {
                self.validate_target(args)?;
                match name {
                    "fs_read" => self.fs_read(args),
                    "git_status" => self.git_status(),
                    "git_diff" => self.git_diff(args),
                    "git_snapshot" => self.git_snapshot(args),
                    "patch_prepare" => self.patch_prepare(args),
                    "patch_review" => self.patch_review(args),
                    "patch_apply" => self.patch_apply(args),
                    "patch_status" => self.patch_status(args),
                    "git_commit_patch" => self.git_commit_patch(args),
                    _ => Ok(json!({
                        "status":"not_implemented","code":"NOT_IMPLEMENTED",
                        "tool":name,"host_id":"local","workspace_id":"default",
                        "message":"Reserved manifest shim. This operation has no implementation or side effects."
                    }))
                }
            }
        }
    }

    fn fs_read(&self, args: &Value) -> ApiResult {
        let path = required(args, "path")?;
        let content = self.read_text(path)?
            .ok_or_else(|| format!("FILE_NOT_FOUND: {path}"))?;
        Ok(json!({"path":path, "sha256":hash(content.as_bytes()), "bytes":content.len(),
            "content":content, "head":self.head()?}))
    }

    fn git_status(&self) -> ApiResult {
        Ok(json!({"head":self.head()?,
            "porcelain":git(&self.workspace,&["status","--porcelain=v1","--untracked-files=normal"],None)?}))
    }

    /// Stage precisely the named existing text files and commit them as a baseline.
    /// An empty path set creates an empty root commit for a newly initialized repo.
    fn git_snapshot(&mut self, args: &Value) -> ApiResult {
        if !self.remote_patch_enabled() {
            return Err("STANDALONE_DESKTOP_PATCHING_REQUIRED".into());
        }
        let paths = args.get("paths").and_then(Value::as_array).ok_or("PATHS_ARRAY_REQUIRED")?;
        if paths.len() > 16 { return Err("TOO_MANY_SNAPSHOT_PATHS".into()); }
        let message = required(args,"message")?;
        if message.len() > 200 || message.chars().any(char::is_control) {
            return Err("INVALID_COMMIT_MESSAGE".into());
        }
        let repo = git2::Repository::open_ext(&self.workspace,
            git2::RepositoryOpenFlags::NO_SEARCH,std::iter::empty::<&Path>()
        ).map_err(|_| "REPOSITORY_INVALID")?;
        if repo.is_bare() || repo.workdir().and_then(|p|p.canonicalize().ok())
            .as_deref() != Some(self.workspace.as_path()) {
            return Err("REPOSITORY_ROOT_MISMATCH".into());
        }
        let mut index=repo.index().map_err(|_|"GIT_INDEX_UNAVAILABLE")?;
        let previous=match repo.head() {
            Ok(h)=>Some(h.peel_to_commit().map_err(|_|"GIT_HEAD_INVALID")?),
            Err(e) if e.code()==git2::ErrorCode::UnbornBranch || e.code()==git2::ErrorCode::NotFound =>None,
            Err(_)=>return Err("GIT_HEAD_INVALID".into())
        };
        let prior_tree=previous.as_ref().map(|c|c.tree_id());
        let current_tree=index.write_tree_to(&repo).map_err(|_|"GIT_INDEX_INVALID")?;
        if prior_tree.is_some() && prior_tree!=Some(current_tree) {
            return Err("EXISTING_STAGED_CHANGES_DENIED".into());
        }
        let mut selected=Vec::new();
        let mut unique=HashSet::new();
        for value in paths {
            let path=value.as_str().ok_or("INVALID_SNAPSHOT_PATH")?;
            if !unique.insert(path.to_owned()) { return Err("DUPLICATE_SNAPSHOT_PATH".into()); }
            let item=self.path(path)?;
            if !item.is_file() || self.read_text(path)?.is_none() {
                return Err("SNAPSHOT_REQUIRES_EXISTING_TEXT_FILE".into());
            }
            index.add_path(Path::new(path)).map_err(|e|format!("SNAPSHOT_STAGE_FAILED: {e}"))?;
            selected.push(path.to_owned());
        }
        let new_tree=index.write_tree_to(&repo).map_err(|_|"SNAPSHOT_TREE_FAILED")?;
        if prior_tree==Some(new_tree) {
            return Err("SNAPSHOT_HAS_NO_CHANGES".into());
        }
        let tree=repo.find_tree(new_tree).map_err(|_|"SNAPSHOT_TREE_FAILED")?;
        let signature=repo.signature().or_else(|_|git2::Signature::now("Desktop MCP","desktop-mcp@local.invalid"))
            .map_err(|_|"GIT_SIGNATURE_UNAVAILABLE")?;
        let parents:Vec<&git2::Commit<'_>>=previous.as_ref().into_iter().collect();
        let commit=repo.commit(Some("HEAD"),&signature,&signature,message,&tree,&parents)
            .map_err(|e|format!("SNAPSHOT_COMMIT_FAILED: {e}"))?;
        index.write().map_err(|_|"SNAPSHOT_INDEX_SYNC_FAILED")?;
        Ok(json!({"commit":commit.to_string(),"parent":previous.as_ref().map(|c|c.id().to_string()),
            "paths":selected,"created_root_commit":parents.is_empty()}))
    }

    fn git_diff(&self, args: &Value) -> ApiResult {
        let mut arglist = vec!["diff", "--no-ext-diff", "HEAD", "--"];
        let path = args.get("path").and_then(Value::as_str);
        if let Some(path) = path {
            self.path(path)?;
            arglist.push(path);
        }
        let diff = git(&self.workspace, &arglist, None)?;
        if diff.len() > 128 * 1024 {
            return Err("DIFF_TOO_LARGE: narrow the path".into());
        }
        Ok(json!({"head":self.head()?, "diff":diff}))
    }

    fn patch_prepare(&mut self, args: &Value) -> ApiResult {
        let expected_head = required(args, "expected_head")?;
        let head = self.head()?;
        if expected_head != head {
            return Err(format!("STALE_HEAD: expected {expected_head}, actual {head}"));
        }
        let raw = args.get("changes").cloned().ok_or("INVALID_ARGUMENT: changes required")?;
        let changes: Vec<PatchChange> = serde_json::from_value(raw)
            .map_err(|e| format!("INVALID_CHANGES: {e}"))?;
        if changes.is_empty() || changes.len() > 16 {
            return Err("INVALID_CHANGES: provide between 1 and 16 files".into());
        }
        let mut seen = HashSet::new();
        let mut entries = Vec::new();
        let mut diff = String::new();
        for requested in changes {
            if !seen.insert(requested.path.clone()) {
                return Err(format!("DUPLICATE_PATH: {}",requested.path));
            }
            let path = self.path(&requested.path)?;
            let current = self.read_text(&requested.path)?;
            let current_sha = current.as_ref().map(|c| hash(c.as_bytes()));
            if current_sha != requested.expected_sha256 {
                return Err(format!("STALE_FILE: {} expected {:?}, actual {:?}",
                    requested.path,requested.expected_sha256,current_sha));
            }
            self.target_clean(&requested.path)?;
            match requested.operation.as_str() {
                "modify" if current.is_some() && requested.new_content.is_some() => {},
                "create" if current.is_none() && requested.new_content.is_some() => {},
                "delete" if current.is_some() && requested.new_content.is_none() => {},
                _ => return Err(format!("INVALID_OPERATION: {} for {}",requested.operation,requested.path))
            };
            if requested.new_content.as_ref().is_some_and(|c| c.len() as u64 > MAX_FILE_BYTES) {
                return Err("FILE_TOO_LARGE: proposed content exceeds 256KiB".into());
            }
            if requested.new_content == current {
                return Err(format!("NO_CHANGE: {}",requested.path));
            }
            let tracked = if self.desktop_mode {
                git2::Repository::open_ext(&self.workspace,git2::RepositoryOpenFlags::NO_SEARCH,
                    std::iter::empty::<&Path>()).map_err(|_|"REPOSITORY_INVALID")?
                    .index().map_err(|_|"GIT_INDEX_UNAVAILABLE")?
                    .get_path(Path::new(&requested.path),0).is_some()
            } else {
                run_git(&self.workspace,
                    &["ls-files", "--error-unmatch", "--", &requested.path],None)?
                    .status.success()
            };
            if requested.operation == "create" && tracked {
                return Err(format!("TRACKED_PATH_EXISTS: {}",requested.path));
            }
            if requested.operation != "create" && !tracked {
                return Err(format!("NOT_TRACKED: {} (commit existing file first)",requested.path));
            }
            let before = current.as_deref().unwrap_or("");
            let after = requested.new_content.as_deref().unwrap_or("");
            let old_name = if current.is_some() {format!("a/{}",requested.path)} else {"/dev/null".into()};
            let new_name = if requested.new_content.is_some() {format!("b/{}",requested.path)} else {"/dev/null".into()};
            let text_diff = TextDiff::from_lines(before, after)
                .unified_diff()
                .context_radius(3)
                .header(&old_name,&new_name)
                .to_string();
            diff.push_str(&text_diff);
            diff.push('\n');
            entries.push(Change{
                path: requested.path,
                old_content: current,
                new_sha256: requested.new_content.as_ref().map(|c|hash(c.as_bytes())),
                new_content: requested.new_content,
                old_sha256: current_sha,
                permissions: if path.exists() { Some(fs::metadata(path).map_err(|e|e.to_string())?.permissions()) } else { None }
            });
        }
        if self.proposals.len() >= MAX_PATCHES {
            self.proposals.retain(|_,p| p.created.elapsed() < PROPOSAL_LIFETIME);
            if self.proposals.len() >= MAX_PATCHES {
                return Err("TOO_MANY_PROPOSALS: finish or restart session".into());
            }
        }
        // Keep replies below MCP ingress and broker output limits.
        if diff.len() > 24000 { return Err("PATCH_DIFF_TOO_LARGE: split into smaller patches".into()); }
        let id = Uuid::new_v4().to_string();
        let count = entries.len();
        self.proposals.insert(id.clone(), Proposal {
            id: id.clone(), base_head: head.clone(), changes: entries,
            diff: diff.clone(), created: Instant::now(), status:"prepared",commit:None
        });
        Ok(json!({"status":"prepared","patch_id":id,"base_head":head,"files_changed":count,
            "diff":diff,"writes_enabled":self.allow_writes,
            "warning":"No files modified. Explicit patch_apply is required. Proposal expires after 15 minutes."}))
    }

    fn proposal(&self, id: &str) -> Result<&Proposal, String> {
        let proposal = self.proposals.get(id).ok_or("PATCH_NOT_FOUND: prepare a new patch")?;
        if proposal.created.elapsed() > PROPOSAL_LIFETIME && proposal.status == "prepared" {
            return Err("PATCH_EXPIRED: prepare a new patch".into());
        }
        Ok(proposal)
    }

    pub fn patch_contains_delete(&self, patch_id: &str) -> Result<bool, String> {
        Ok(self.proposal(patch_id)?.changes.iter().any(|change| change.new_content.is_none()))
    }

    fn patch_review(&self, args: &Value) -> ApiResult {
        let proposal = self.proposal(required(args,"patch_id")?)?;
        Ok(json!({"patch_id":proposal.id, "status":proposal.status, "base_head":proposal.base_head,
            "diff":proposal.diff,
            "files":proposal.changes.iter().map(|c|json!({
                "path":c.path,"original_sha256":c.old_sha256,"proposed_sha256":c.new_sha256
            })).collect::<Vec<_>>() }))
    }

    fn patch_status(&self, args: &Value) -> ApiResult {
        let proposal = self.proposal(required(args,"patch_id")?)?;
        Ok(json!({"patch_id":proposal.id,"status":proposal.status,"commit":proposal.commit,
            "base_head":proposal.base_head}))
    }

    fn patch_apply(&mut self, args: &Value) -> ApiResult {
        if !self.allow_writes {
            return Err("WRITE_DENIED: start the local agent explicitly with --allow-writes".into());
        }
        let id = required(args,"patch_id")?.to_string();
        let p = self.proposal(&id)?;
        if p.status != "prepared" {
            return Err(format!("PATCH_NOT_PREPARED: {}",p.status));
        }
        if self.head()? != p.base_head {
            return Err("STALE_HEAD: repository changed after review".into());
        }
        let changes = p.changes.clone();
        for change in &changes {
            let current = self.read_text(&change.path)?;
            if current.as_ref().map(|c|hash(c.as_bytes())) != change.old_sha256 {
                return Err(format!("CONFLICT: {} changed since patch_prepare",change.path));
            }
            self.target_clean(&change.path)?;
        }
        // Stage all new content in temporary same-filesystem files before changing any target.
        let mut staged: Vec<Option<NamedTempFile>> = Vec::new();
        for change in &changes {
            staged.push(if let Some(content)=&change.new_content {
                let path = self.path(&change.path)?;
                let mut temp=NamedTempFile::new_in(path.parent().ok_or("INVALID_PATH")?)
                    .map_err(|e|format!("STAGE_ERROR: {e}"))?;
                temp.write_all(content.as_bytes()).map_err(|e|format!("STAGE_ERROR: {e}"))?;
                if let Some(perm)=&change.permissions {
                    temp.as_file().set_permissions(perm.clone()).map_err(|e|format!("STAGE_ERROR: {e}"))?;
                }
                temp.as_file().sync_all().map_err(|e|format!("STAGE_ERROR: {e}"))?;
                Some(temp)
            } else {
                None
            });
        }
        let mut applied: Vec<usize> = Vec::new();
        let mut failure: Option<String> = None;
        for (idx, change) in changes.iter().enumerate() {
            let result=(|| -> Result<(),String> {
                if self.read_text(&change.path)?.as_ref().map(|c|hash(c.as_bytes()))!=change.old_sha256 {
                    return Err(format!("CONFLICT: {} changed during apply",change.path));
                }
                let path = self.path(&change.path)?;
                if change.new_content.is_none() {
                    fs::remove_file(&path).map_err(|e|format!("REMOVE_ERROR: {e}"))?;
                } else if let Some(temp) = staged[idx].take() {
                    if change.old_content.is_none() {
                        temp.persist_noclobber(&path).map_err(|e|format!("CREATE_ERROR: {}",e.error))?;
                    } else {
                        temp.persist(&path).map_err(|e|format!("REPLACE_ERROR: {}",e.error))?;
                    }
                }
                Ok(())
            })();
            if let Err(e)=result {
                failure=Some(e);
                break;
            }
            applied.push(idx);
        }
        if let Some(reason) = failure {
            let mut rollback_errors=Vec::new();
            for idx in applied.into_iter().rev() {
                let c = &changes[idx];
                let latest = self.read_text(&c.path);
                if latest.as_ref().ok().and_then(|v|v.as_ref()).map(|v|hash(v.as_bytes())) != c.new_sha256 {
                    rollback_errors.push(format!("{} modified externally; untouched",c.path));
                    continue;
                }
                if let Err(e) = self.restore(c) {
                    rollback_errors.push(e);
                }
            }
            return Err(format!("APPLY_FAILED: {reason}; rollback_errors={rollback_errors:?}"));
        }
        for c in &changes {
            if self.read_text(&c.path)?.as_ref().map(|v|hash(v.as_bytes())) != c.new_sha256 {
                return Err(format!("POST_APPLY_MISMATCH: {}. Inspect files immediately",c.path));
            }
        }
        self.proposals.get_mut(&id).unwrap().status="applied";
        Ok(json!({"patch_id":id,"status":"applied","files":changes.iter().map(|c|&c.path).collect::<Vec<_>>(),
            "verified_sha256":changes.iter().map(|c|json!({"path":c.path,"sha256":c.new_sha256})).collect::<Vec<_>>(),
            "commit_created":false}))
    }

    fn restore(&self, c:&Change) -> Result<(),String> {
        let path=self.path(&c.path)?;
        match &c.old_content {
            Some(original)=>{
                let mut f=NamedTempFile::new_in(path.parent().ok_or("INVALID_PATH")?)
                    .map_err(|e|e.to_string())?;
                f.write_all(original.as_bytes()).map_err(|e|e.to_string())?;
                if let Some(p)=&c.permissions {
                    f.as_file().set_permissions(p.clone()).map_err(|e|e.to_string())?;
                }
                f.persist(path).map_err(|e|e.error.to_string())?;
            },
            None => {
                if path.exists() { fs::remove_file(path).map_err(|e|e.to_string())?; }
            }
        }
        Ok(())
    }

    // Commit selected patch paths using libgit2 without requiring Git for Windows.
    // Preserve any unrelated staged files in the real index.
    fn git_commit_patch_git2(&mut self, args:&Value)->ApiResult {
        if !self.remote_patch_enabled() {return Err("PATCHING_DISABLED".into());}
        let id=required(args,"patch_id")?.to_owned();
        let message=required(args,"message")?;
        if message.is_empty() || message.len()>200 || message.chars().any(char::is_control) {
            return Err("INVALID_COMMIT_MESSAGE".into());
        }
        let proposal=self.proposal(&id)?;
        if proposal.status!="applied" {return Err("PATCH_NOT_APPLIED".into());}
        let expected=proposal.base_head.clone();
        let changes=proposal.changes.clone();
        if self.head()?!=expected {return Err("STALE_HEAD".into());}
        let repo=git2::Repository::open_ext(&self.workspace,git2::RepositoryOpenFlags::NO_SEARCH,
            std::iter::empty::<&Path>()).map_err(|_|"REPOSITORY_INVALID")?;
        let parent=repo.find_commit(git2::Oid::from_str(&expected).map_err(|_|"INVALID_EXPECTED_HEAD")?)
            .map_err(|_|"GIT_PARENT_MISSING")?;
        let tree=parent.tree().map_err(|_|"GIT_TREE_MISSING")?;
        let existing_index=repo.index().map_err(|_|"GIT_INDEX_UNAVAILABLE")?;
        let mut fresh=git2::Index::new().map_err(|_|"GIT_INDEX_UNAVAILABLE")?;
        fresh.read_tree(&tree).map_err(|_|"GIT_TREE_INVALID")?;
        for change in &changes {
            let path=Path::new(&change.path);
            let actual=self.read_text(&change.path)?;
            if actual.as_ref().map(|s|hash(s.as_bytes()))!=change.new_sha256 {
                return Err(format!("PATCH_CONTENT_CHANGED: {}",change.path));
            }
            let staged=existing_index.get_path(path,0).map(|e|e.id);
            let original=tree.get_path(path).ok().map(|e|e.id());
            if staged!=original {return Err(format!("INDEX_CONFLICT: {}",change.path));}
            if let Some(data)=actual {
                let blob=repo.blob(data.as_bytes()).map_err(|_|"GIT_BLOB_FAILED")?;
                let mut entry=fresh.get_path(path,0).unwrap_or_else(||git2::IndexEntry {
                    ctime:git2::IndexTime::new(0,0),
                    mtime:git2::IndexTime::new(0,0),
                    dev:0,ino:0,mode:0o100644,uid:0,gid:0,
                    file_size:0,id:blob,flags:0,flags_extended:0,path:change.path.as_bytes().to_vec()
                });
                entry.id=blob;
                entry.file_size=data.len() as u32;
                fresh.add(&entry).map_err(|e|format!("STAGE_FAILED: {e}"))?;
            } else {
                fresh.remove_path(path).map_err(|_|"DELETE_STAGE_FAILED")?;
            }
        }
        let new_oid=fresh.write_tree_to(&repo).map_err(|_|"GIT_TREE_WRITE_FAILED")?;
        let new_tree=repo.find_tree(new_oid).map_err(|_|"GIT_TREE_MISSING")?;
        // One last HEAD check before committing. Competing writers must not silently merge.
        if self.head()?!=expected {return Err("STALE_HEAD".into());}
        let signature=repo.signature().or_else(|_|git2::Signature::now("Desktop MCP","desktop-mcp@local.invalid"))
            .map_err(|_|"GIT_SIGNATURE_UNAVAILABLE")?;
        let commit=repo.commit(Some("HEAD"),&signature,&signature,message,&new_tree,&[&parent])
            .map_err(|e|format!("GIT_COMMIT_FAILED: {e}"))?;
        let mut index=repo.index().map_err(|_|format!("COMMITTED_INDEX_NEEDS_SYNC: {commit}"))?;
        for change in &changes {
            let path=Path::new(&change.path);
            if change.new_content.is_some() {
                index.add_path(path).map_err(|e|format!("COMMITTED_INDEX_NEEDS_SYNC: {commit} {e}"))?;
            } else {
                index.remove_path(path).map_err(|e|format!("COMMITTED_INDEX_NEEDS_SYNC: {commit} {e}"))?;
            }
        }
        index.write().map_err(|_|format!("COMMITTED_INDEX_NEEDS_SYNC: {commit}"))?;
        self.proposals.get_mut(&id).unwrap().status="committed";
        self.proposals.get_mut(&id).unwrap().commit=Some(commit.to_string());
        Ok(json!({"status":"committed","patch_id":id,
            "commit":commit.to_string(),"parent":expected,
            "files_committed":changes.iter().map(|c|&c.path).collect::<Vec<_>>(),
            "unrelated_changes_preserved":true}))
    }

    fn git_commit_patch(&mut self, args:&Value)->ApiResult {
        if self.desktop_mode {
            return self.git_commit_patch_git2(args);
        }
        if !self.allow_writes {
            return Err("WRITE_DENIED: start the local agent explicitly with --allow-writes".into());
        }
        let id=required(args,"patch_id")?.to_string();
        let message=required(args,"message")?.to_string();
        if message.len()>200 || message.contains('\n') {
            return Err("INVALID_MESSAGE: use a single line up to 200 characters".into());
        }
        let p=self.proposal(&id)?;
        if p.status!="applied" {
            return Err(format!("PATCH_NOT_APPLIED: {}",p.status));
        }
        let head=p.base_head.clone();
        let changes=p.changes.clone();
        if self.head()?!=head {
            return Err("STALE_HEAD: another commit occurred since patch_prepare".into());
        }
        for c in &changes {
            if self.read_text(&c.path)?.as_ref().map(|v|hash(v.as_bytes())) != c.new_sha256 {
                return Err(format!("POST_APPLY_CONFLICT: {} changed after patch_apply",c.path));
            }
            let out=run_git(&self.workspace,&["diff","--cached","--quiet",&head,"--",&c.path],None)?;
            if !out.status.success() {
                return Err(format!("INDEX_CONFLICT: {} staged by another tool",c.path));
            }
        }
        let indexdir=TempDir::new().map_err(|e|e.to_string())?;
        let indexfile=indexdir.path().join("index");
        git(&self.workspace,&["read-tree",&head],Some(&indexfile))?;
        let paths:Vec<&str>=changes.iter().map(|c|c.path.as_str()).collect();
        let mut stage_args=vec!["add","-A","--"];
        stage_args.extend(paths.iter().copied());
        git(&self.workspace,&stage_args,Some(&indexfile))?;
        let tree=git(&self.workspace,&["write-tree"],Some(&indexfile))?;
        let commit=git(&self.workspace,&["commit-tree",&tree,"-p",&head,"-m",&message],None)?;
        // Reject concurrent commits using expected HEAD CAS.
        git(&self.workspace,&["update-ref","HEAD",&commit,&head],None)?;
        self.proposals.get_mut(&id).unwrap().commit=Some(commit.clone());
        self.proposals.get_mut(&id).unwrap().status="committed";
        // Bring the real index into sync for our paths without touching unrelated staging.
        for c in &changes {
            if self.read_text(&c.path)?.as_ref().map(|v|hash(v.as_bytes()))!=c.new_sha256 {
                return Err(format!("COMMITTED_INDEX_NEEDS_SYNC: {} changed; commit={commit}",c.path));
            }
        }
        git(&self.workspace,&stage_args,None)
            .map_err(|e|format!("COMMITTED_INDEX_NEEDS_SYNC: commit={commit} {e}"))?;
        Ok(json!({"status":"committed","patch_id":id,"commit":commit,"parent":head,
            "files_committed":paths, "unrelated_changes_preserved":true}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn standalone_desktop_starts_without_git_and_initializes_only_on_request() {
        let state=TempDir::new().unwrap();
        let folder=TempDir::new().unwrap();
        let path=folder.path().to_str().unwrap();
        let mut agent=Agent::new_desktop(state.path()).unwrap();
        assert_eq!(agent.root(),state.path().canonicalize().unwrap());
        assert_eq!(agent.authorization_scope(),state.path().canonicalize().unwrap());
        assert!(agent.use_repository(path,false).unwrap_err().contains("NOT_INITIALIZED"));
        assert!(!folder.path().join(".git").exists());
        std::fs::write(folder.path().join("original.txt"),"leave unchanged").unwrap();
        let selected=agent.use_repository(path,true).unwrap();
        assert_eq!(selected["initialized"],true);
        assert!(folder.path().join(".git").is_dir());
        assert_eq!(std::fs::read_to_string(folder.path().join("original.txt")).unwrap(),"leave unchanged");
        assert_eq!(agent.root(),folder.path().canonicalize().unwrap());
        assert_eq!(agent.authorization_scope(),state.path().canonicalize().unwrap());
        let restarted=Agent::new_desktop(state.path()).unwrap();
        assert_eq!(restarted.root(),folder.path().canonicalize().unwrap());
    }
    #[test]
    fn standalone_desktop_snapshot_patch_and_commit_preserve_history() {
        let state=TempDir::new().unwrap();
        let folder=TempDir::new().unwrap();
        fs::write(folder.path().join("original.txt"), "original\n").unwrap();
        let mut agent=Agent::new_desktop(state.path()).unwrap();
        assert_eq!(agent.use_repository(folder.path().to_str().unwrap(),true).unwrap()["initialized"],true);
        let initial=json!({"host_id":"local","workspace_id":"default",
            "paths":["original.txt"],"message":"Capture original"});
        let base=agent.dispatch("git_snapshot",&initial).unwrap();
        assert!(base["created_root_commit"].as_bool().unwrap());
        let head=base["commit"].as_str().unwrap().to_owned();
        let patch=json!({"host_id":"local","workspace_id":"default",
            "expected_head":head,"changes":[{"path":"original.txt","operation":"modify",
                "expected_sha256":hash(b"original\n"),"new_content":"updated\n"}]});
        let prepared=agent.dispatch("patch_prepare",&patch).unwrap();
        assert_eq!(prepared["status"],"prepared");
        assert_eq!(fs::read_to_string(folder.path().join("original.txt")).unwrap(),"original\n");
        let id=prepared["patch_id"].as_str().unwrap();
        let applied=agent.dispatch("patch_apply",&json!({"host_id":"local",
            "workspace_id":"default","patch_id":id})).unwrap();
        assert_eq!(applied["status"],"applied");
        let committed=agent.dispatch("git_commit_patch",&json!({"host_id":"local",
            "workspace_id":"default","patch_id":id,"message":"Patch original"})).unwrap();
        assert_eq!(committed["status"],"committed");
        assert_ne!(committed["commit"].as_str().unwrap(),head);
        let repo=git2::Repository::open(folder.path()).unwrap(); let mut history=repo.revwalk().unwrap(); history.push_head().unwrap(); assert_eq!(history.count(),2);
        assert_eq!(fs::read_to_string(folder.path().join("original.txt")).unwrap(),"updated\n");
        assert_eq!(agent.authorization_scope(),state.path().canonicalize().unwrap());
    }
    #[test]
    fn standalone_desktop_refuses_nonexistent_repository_folder() {
        let state=TempDir::new().unwrap();
        let mut agent=Agent::new_desktop(state.path()).unwrap();
        let path=state.path().join("missing");
        assert!(agent.use_repository(path.to_str().unwrap(),true).is_err());
        assert!(!path.exists());
    }
    fn fixture() -> (TempDir, Agent, String) {
        let tmp=TempDir::new().unwrap();
        git(tmp.path(),&["init","-q"],None).unwrap();
        git(tmp.path(),&["config","user.name","Agent Test"],None).unwrap();
        git(tmp.path(),&["config","user.email","agent@example.invalid"],None).unwrap();
        fs::write(tmp.path().join("file.txt"),"before\n").unwrap();
        fs::write(tmp.path().join("unrelated.txt"),"same\n").unwrap();
        git(tmp.path(),&["add","."],None).unwrap();
        git(tmp.path(),&["commit","-q","-m","initial"],None).unwrap();
        let agent=Agent::new(tmp.path(),true).unwrap();
        let head=agent.head().unwrap();
        (tmp,agent,head)
    }
    fn scope()->Value {json!({"host_id":"local","workspace_id":"default"})}
    #[test]
    fn prepare_apply_commit_preserves_unrelated_unstaged_changes() {
        let (tmp,mut agent,head)=fixture();
        fs::write(tmp.path().join("unrelated.txt"),"user work\n").unwrap();
        let mut req=scope();
        req["expected_head"]=json!(head);
        req["changes"]=json!([{"path":"file.txt","operation":"modify",
            "expected_sha256":hash(b"before\n"),"new_content":"after\n"}]);
        let out=agent.dispatch("patch_prepare",&req).unwrap();
        assert!(out["diff"].as_str().unwrap().contains("+after"));
        assert_eq!(fs::read_to_string(tmp.path().join("file.txt")).unwrap(),"before\n");
        let id=out["patch_id"].as_str().unwrap().to_string();
        let p=json!({"host_id":"local","workspace_id":"default","patch_id":id});
        agent.dispatch("patch_apply",&p).unwrap();
        assert_eq!(fs::read_to_string(tmp.path().join("file.txt")).unwrap(),"after\n");
        let c=json!({"host_id":"local","workspace_id":"default","patch_id":id,"message":"Update target"});
        let commit=agent.dispatch("git_commit_patch",&c).unwrap();
        assert_eq!(commit["status"],"committed");
        let names=git(tmp.path(),&["show","--format=","--name-only","HEAD"],None).unwrap();
        assert_eq!(names.trim(),"file.txt");
        assert_eq!(fs::read_to_string(tmp.path().join("unrelated.txt")).unwrap(),"user work\n");
        assert!(git(tmp.path(),&["status","--porcelain"],None).unwrap().contains("unrelated.txt"));
    }
    #[test]
    fn stale_file_refuses_prepare() {
        let (_tmp,mut agent,head)=fixture();
        let r=json!({"host_id":"local","workspace_id":"default","expected_head":head,
            "changes":[{"path":"file.txt","operation":"modify",
            "expected_sha256":"deadbeef","new_content":"changed"}]});
        assert!(agent.dispatch("patch_prepare",&r).unwrap_err().contains("STALE_FILE"));
    }
    #[test]
    fn stale_after_prepare_refuses_write() {
        let (tmp,mut agent,head)=fixture();
        let r=json!({"host_id":"local","workspace_id":"default","expected_head":head,
            "changes":[{"path":"file.txt","operation":"modify",
            "expected_sha256":hash(b"before\n"),"new_content":"after\n"}]});
        let out=agent.dispatch("patch_prepare",&r).unwrap();
        fs::write(tmp.path().join("file.txt"),"concurrent edit\n").unwrap();
        let a=json!({"host_id":"local","workspace_id":"default","patch_id":out["patch_id"]});
        assert!(agent.dispatch("patch_apply",&a).unwrap_err().contains("CONFLICT"));
        assert_eq!(fs::read_to_string(tmp.path().join("file.txt")).unwrap(),"concurrent edit\n");
    }
    #[test]
    fn read_only_prevents_apply() {
        let (tmp,mut agent,head)=fixture();
        agent.allow_writes=false;
        let r=json!({"host_id":"local","workspace_id":"default","expected_head":head,
            "changes":[{"path":"file.txt","operation":"modify",
            "expected_sha256":hash(b"before\n"),"new_content":"after\n"}]});
        let out=agent.dispatch("patch_prepare",&r).unwrap();
        let a=json!({"host_id":"local","workspace_id":"default","patch_id":out["patch_id"]});
        assert!(agent.dispatch("patch_apply",&a).unwrap_err().contains("WRITE_DENIED"));
        assert_eq!(fs::read_to_string(tmp.path().join("file.txt")).unwrap(),"before\n");
    }
    #[test]
    fn path_traversal_and_git_metadata_are_forbidden() {
        let (_tmp,agent,_)=fixture();
        assert!(agent.path("../outside").is_err());
        assert!(agent.path("/etc/passwd").is_err());
        assert!(agent.path(".git/config").is_err());
    }
    #[cfg(unix)]
    #[test]
    fn symlinks_are_forbidden() {
        use std::os::unix::fs::symlink;
        let (tmp,agent,_)=fixture();
        symlink("/tmp",tmp.path().join("escape")).unwrap();
        assert!(agent.path("escape/secret").is_err());
    }
    #[test]
    fn create_and_delete_commit_only_selected_files() {
        let (tmp,mut agent,head)=fixture();
        let r=json!({"host_id":"local","workspace_id":"default","expected_head":head,
            "changes":[{"path":"new.txt","operation":"create","expected_sha256":null,"new_content":"hello\n"},
            {"path":"file.txt","operation":"delete","expected_sha256":hash(b"before\n"),"new_content":null}]});
        let out=agent.dispatch("patch_prepare",&r).unwrap();
        let id=out["patch_id"].as_str().unwrap();
        let a=json!({"host_id":"local","workspace_id":"default","patch_id":id});
        agent.dispatch("patch_apply",&a).unwrap();
        let c=json!({"host_id":"local","workspace_id":"default","patch_id":id,"message":"Add and delete"});
        agent.dispatch("git_commit_patch",&c).unwrap();
        assert!(!tmp.path().join("file.txt").exists());
        assert_eq!(fs::read_to_string(tmp.path().join("new.txt")).unwrap(),"hello\n");
    }
}
