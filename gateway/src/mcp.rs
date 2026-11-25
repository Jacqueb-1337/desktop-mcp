//! Bounded HTTPS MCP ingress. Authentication precedes protocol/tool discovery.
//! Private, pre-shared bearer authentication; OAuth is delegated to deployment.
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    path::Path,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
pub const VERSION: &str = "2026-07-28";
const LIMIT: usize = 64 * 1024;
pub type Dispatch =
    Arc<dyn Fn(&str, &Value, &dyn Fn() -> bool) -> Result<Value, String> + Send + Sync>;

pub struct Config {
    token: String,
    pub authority: String,
}
impl Config {
    pub fn load(path: &Path, authority: String) -> Result<Self, String> {
        #[cfg(windows)]
        crate::windows_acl::verify_private(path)?;
        let bytes = crate::secure_file(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let m = std::fs::metadata(path).map_err(|_| "TOKEN_METADATA")?;
            if m.permissions().mode() & 0o077 != 0 || m.uid() != unsafe { libc::geteuid() } {
                return Err("TOKEN_PERMISSIONS".into());
            }
        }
        let token = String::from_utf8(bytes)
            .map_err(|_| "TOKEN_ENCODING")?
            .trim()
            .to_string();
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("TOKEN_REQUIRES_256_BIT_HEX".into());
        }
        if authority.is_empty()
            || authority
                .bytes()
                .any(|b| b <= 32 || b >= 127 || b == b'/' || b == b'@')
        {
            return Err("INVALID_MCP_AUTHORITY".into());
        }
        Ok(Self { token, authority })
    }
}

struct Http {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}
fn read_http(stream: &mut impl Read) -> Result<Http, u16> {
    let mut head = Vec::new();
    let started = std::time::Instant::now();
    while !head.ends_with(b"\r\n\r\n") {
        if started.elapsed() > Duration::from_secs(10) {
            return Err(408);
        }
        if head.len() >= 8192 {
            return Err(431);
        }
        let mut b = [0];
        stream.read_exact(&mut b).map_err(|_| 400u16)?;
        head.push(b[0]);
    }
    let text = std::str::from_utf8(&head).map_err(|_| 400u16)?;
    let mut lines = text.split("\r\n");
    let parts: Vec<_> = lines.next().ok_or(400u16)?.split(' ').collect();
    if parts.len() != 3 || parts[2] != "HTTP/1.1" {
        return Err(400);
    }
    let mut headers = HashMap::new();
    for line in lines.filter(|s| !s.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            || value.bytes().any(|b| b < 32 && b != 9 || b == 127)
        {
            return Err(400);
        }
        if headers
            .insert(name.to_ascii_lowercase(), value.trim().to_string())
            .is_some()
        {
            return Err(400);
        }
    }
    if headers.contains_key("transfer-encoding") || headers.contains_key("expect") {
        return Err(400);
    }
    let length = headers
        .get("content-length")
        .map(|s| s.parse::<usize>())
        .transpose()
        .map_err(|_| 400u16)?
        .unwrap_or(0);
    if length > LIMIT {
        return Err(413);
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).map_err(|_| 400u16)?;
    Ok(Http {
        method: parts[0].into(),
        path: parts[1].into(),
        headers,
        body,
    })
}
fn error(id: &Value, code: i32, message: &str) -> Value {
    let mut v = json!({"jsonrpc":"2.0","error":{"code":code,"message":message}});
    if !id.is_null() {
        v["id"] = id.clone();
    }
    v
}
fn complete(id: &Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
fn schema() -> Value {
    json!({"type":"object","properties":{"host_id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"workspace_id":{"type":"string","const":"default"},"request_id":{"type":"string","format":"uuid","description":"Optional unique idempotency key. Repeated IDs fail closed."}},"required":["host_id","workspace_id"],"additionalProperties":false})
}

fn valid_read_path(path: &str) -> bool {
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
fn browse_schema(tool:&str)->Value {
    let mut value=schema();
    value["properties"]["query"]=if tool=="fs_batch" {
        json!({"type":"array","minItems":1,"maxItems":4,"items":{"type":"object","additionalProperties":false,
            "properties":{"tool":{"enum":["fs_read","fs_list","fs_search","git_diff","git_status"]},
                "arguments":{"type":"object","description":"Inner tool arguments: omit host/workspace; search/list/diff use their query fields directly."}},
            "required":["tool","arguments"]}})
    }else if tool=="fs_list"{
        json!({"type":"object","additionalProperties":false,"properties":{
            "path":{"type":"string","default":".","description":"Repository-relative directory, or . for root"},
            "depth":{"type":"integer","minimum":1,"maximum":5,"default":1},
            "limit":{"type":"integer","minimum":1,"maximum":200,"default":100},
            "offset":{"type":"integer","minimum":0,"maximum":20000}}})
    }else{
        json!({"type":"object","additionalProperties":false,"properties":{
            "path":{"type":"string","description":"Single repository-relative file"},
            "base":{"enum":["head","staged","unstaged"],"default":"head"},
            "context":{"type":"integer","minimum":0,"maximum":10,"default":3}},"required":["path"]})
    };
    value["required"].as_array_mut().unwrap().push(json!("query"));
    value
}
fn admin_command_schema() -> Value {
    let mut value = schema();
    value["properties"]["command"] = json!({"type":"string","minLength":1,"maxLength":2000,
        "description":"Exact PowerShell command, reviewed locally before elevation. Runs from the configured project directory."});
    value["required"].as_array_mut().expect("schema has required fields").push(json!("command"));
    value
}

fn detached_schema()->Value{
    let mut value=user_command_schema();
    value["properties"]["command"]["description"]=json!("Exact PowerShell command for an independently managed, non-elevated on-demand Windows task. Each launch requires explicit local approval.");
    value["properties"]["working_directory"]=json!({"type":"string","minLength":1,"maxLength":500,"description":"Optional absolute Windows directory; defaults to owner profile"});
    value
}
fn user_command_schema() -> Value {
    let mut value=admin_command_schema();
    value["properties"]["command"]["description"]=json!("Exact PowerShell command to run in the installation owner's non-elevated Windows session, after a separate user_command grant.");
    value
}
fn terminal_schema(tool:&str)->Value {
    let mut value=schema();
    value["properties"]["context"]=json!({"type":"string","enum":["system","user","elevated_user"],"default":"system",
        "description":"Execution context. Use the same context on all operations for a terminal. Each needs its own owner-approved grant."});
    if matches!(tool,"terminal_run"|"terminal_read"|"terminal_close") {
        value["properties"]["terminal_id"]=json!({"type":"string","format":"uuid"});
        value["required"].as_array_mut().unwrap().push(json!("terminal_id"));
    }
    if tool=="terminal_run" {
        value["properties"]["command"]=json!({"type":"string","minLength":1,"maxLength":2000});
        value["properties"]["timeout_seconds"]=json!({"type":"integer","minimum":1,"maximum":28800,"default":7200});
        value["required"].as_array_mut().unwrap().push(json!("command"));
    }
    if tool=="terminal_read" {
        value["properties"]["offset"]=json!({"type":"integer","minimum":0});
    }
    value
}

fn command_result_schema() -> Value {
    let mut value=schema();
    value["properties"]["run_id"]=json!({"type":"string","format":"uuid","description":"The request_id returned by admin_command."});
    value["required"].as_array_mut().expect("schema has required fields").push(json!("run_id"));
    value
}

fn search_schema()->Value {
    let mut v=schema();
    v["properties"]["query"]=json!({"type":"object","additionalProperties":false,"properties":{
        "mode":{"enum":["paths","text"]},"pattern":{"type":"string","minLength":1,"maxLength":512},
        "regex":{"type":"boolean"},"case_sensitive":{"type":"boolean"},"limit":{"type":"integer","minimum":1,"maximum":200},
                "scope":{"type":"string","description":"Repository-relative file or directory"},
                "exclude":{"type":"array","maxItems":32,"items":{"type":"string"},"description":"Repository-relative path prefixes to exclude"},
                "context":{"type":"integer","minimum":0,"maximum":3},"offset":{"type":"integer","minimum":0,"maximum":20000},
                "refresh":{"type":"boolean","description":"Force a fresh search index"},
                "engine":{"enum":["native","fff"],"default":"fff","description":"FFF fuzzy paths and indexed text by default; native exact/regex fallback or explicit override"}},
        "required":["mode","pattern"]});
    v["required"].as_array_mut().unwrap().push(json!("query"));
    v
}
fn permission_schema() -> Value {
    let mut value = schema();
    value["properties"]["capability"] = json!({"type":"string","enum":["pairing","git_status","fs_read","fs_search","fs_list","fs_batch","git_diff","use_repository","git_snapshot","patch_prepare","patch_review","patch_status","patch_apply","git_commit_patch","system_volume_status","admin_command","user_command","elevated_user_command","process_spawn_detached"]});
    value["properties"]["duration"] = json!({"type":"string","description":"1 to 1440 minutes, for example 45m, or permanent (until revoked).","pattern":"^(?:[1-9][0-9]{0,3}m|1h|4h|permanent)$"});
    let required = value["required"].as_array_mut().expect("schema has required fields");
    required.extend([json!("capability"), json!("duration")]);
    value
}

fn snapshot_schema()->Value {
    let mut v=schema();
    v["properties"]["paths"]=json!({"type":"array","maxItems":16,
        "items":{"type":"string","minLength":1,"maxLength":500},
        "description":"Exact existing files to snapshot. Empty array creates an initial empty commit only."});
    v["properties"]["message"]=json!({"type":"string","minLength":1,"maxLength":200});
    v["required"].as_array_mut().unwrap().extend([json!("paths"),json!("message")]);
    v
}
fn patch_prepare_schema()->Value {
    let mut v=schema();
    v["properties"]["expected_head"]=json!({"type":"string","pattern":"^[0-9a-fA-F]{40}$"});
    v["properties"]["changes"]=json!({"type":"array","minItems":1,"maxItems":16,"items":{
      "type":"object","additionalProperties":false,
      "properties":{"path":{"type":"string","maxLength":500},
        "operation":{"type":"string","enum":["create","modify","delete","copy","move","rename"]},
        "expected_sha256":{"type":["string","null"]},
                        "source_path":{"type":"string","description":"Copy/move/rename source; destination is path, expected_sha256 and new_content must be null."},
                        "source_sha256":{"type":"string","pattern":"^[0-9a-fA-F]{64}$"},
        "new_content":{"type":["string","null"]},
        "edits":{"type":"array","minItems":1,"maxItems":32,
          "description":"Optional sequential targeted edits for modify; set new_content to null. Exact text must occur once. Lines are 1-based inclusive; replacement includes any desired line terminator.",
          "items":{"oneOf":[
            {"type":"object","additionalProperties":false,"properties":{"kind":{"const":"exact"},"old":{"type":"string","minLength":1},"new":{"type":"string"}},"required":["kind","old","new"]},
            {"type":"object","additionalProperties":false,"properties":{"kind":{"const":"lines"},"start":{"type":"integer","minimum":1},"end":{"type":"integer","minimum":1},"new":{"type":"string"}},"required":["kind","start","end","new"]}
          ]}}},
      "required":["path","operation","expected_sha256","new_content"]}});
    v["required"].as_array_mut().unwrap().extend([json!("expected_head"),json!("changes")]);
    v
}
fn patch_id_schema()->Value {
    let mut v=schema();
    v["properties"]["patch_id"]=json!({"type":"string","format":"uuid"});
    v["required"].as_array_mut().unwrap().push(json!("patch_id"));
    v
}
fn patch_commit_schema()->Value {
    let mut v=patch_id_schema();
    v["properties"]["message"]=json!({"type":"string","minLength":1,"maxLength":200});
    v["required"].as_array_mut().unwrap().push(json!("message"));
    v
}
fn repository_schema() -> Value {
    let mut value=schema();
    value["properties"]["path"]=json!({"type":"string","minLength":1,"maxLength":500,
        "description":"Absolute path of an existing folder on the target PC. Exact path requires local approval."});
    value["properties"]["initialize"]=json!({"type":"boolean",
        "description":"Initialize a local Git repository in the folder if missing. No files are staged or committed."});
    value["required"].as_array_mut().unwrap().extend([json!("path"),json!("initialize")]);
    value
}
fn read_schema() -> Value {
    let mut value = schema();
    value["properties"]["path"] = json!({"type":"string","minLength":1,"maxLength":500,"description":"Relative UTF-8 file path inside the approved project."});
    value["properties"]["start_line"]=json!({"type":"integer","minimum":1,"maximum":8388608});
    value["properties"]["end_line"]=json!({"type":"integer","minimum":1,"maximum":8388608});
    value["required"]
        .as_array_mut()
        .unwrap()
        .push(json!("path"));
    value
}

fn rpc(
    request: Value,
    headers: &HashMap<String, String>,
    dispatch: &Dispatch,
    alive: &dyn Fn() -> bool,
) -> (u16, Option<Value>) {
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let method = request.get("method").and_then(Value::as_str).unwrap_or("");
    if !request.is_object()
        || request["jsonrpc"] != "2.0"
        || method.is_empty()
        || (!id.is_string() && !id.is_i64() && !id.is_u64())
        || request.get("result").is_some()
        || request.get("error").is_some()
    {
        return (400, Some(error(&Value::Null, -32600, "Invalid request")));
    }
    let params = request.get("params").cloned().unwrap_or(json!({}));
    if !params.is_object() {
        return (400, Some(error(&id, -32602, "Invalid params")));
    }
    let version = params["_meta"]["io.modelcontextprotocol/protocolVersion"].as_str();
    if version.is_none()
        || !params["_meta"]["io.modelcontextprotocol/clientCapabilities"].is_object()
    {
        return (
            400,
            Some(error(&id, -32602, "Required per-request metadata missing")),
        );
    }
    let version = version.unwrap();
    if headers.get("mcp-protocol-version").map(String::as_str) != Some(version)
        || headers.get("mcp-method").map(String::as_str) != Some(method)
        || (method == "tools/call"
            && headers.get("mcp-name").map(String::as_str) != params["name"].as_str())
    {
        return (400, Some(error(&id, -32020, "HeaderMismatch")));
    }
    if version != VERSION {
        let mut err = error(&id, -32022, "Unsupported protocol version");
        err["error"]["data"] = json!({"supported":[VERSION],"requested":version});
        return (400, Some(err));
    }
    let result = match method {
        "server/discover" => {
            json!({"resultType":"complete","supportedVersions":[VERSION],"capabilities":{"tools":{}},"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"desktop-mcp","version":"0.2.0"}},"instructions":"Standalone desktop hosts. Repositories are selected only when needed; every operation requires local approval."})
        }
        "ping" => json!({"resultType":"complete"}),
        "tools/list" => {
            if params.get("cursor").is_some() {
                return (400, Some(error(&id, -32602, "Invalid cursor")));
            }
            json!({"resultType":"complete","tools":[{"name":"pair_device","description":"Pair a Windows Desktop MCP installation using the complete DMW1 registration code shared by its owner (automatically enrolls WireGuard), or a legacy DM1 identity code. Include an optional nickname such as Dad's PC. Request administrator access separately for the owner to approve.","inputSchema":{"type":"object","properties":{"code":{"type":"string","pattern":"^(DM1-[a-f0-9]{64}|DMW1:DM1-[a-f0-9]{64}:[A-Za-z0-9+/]{43}=)$"},"nickname":{"type":"string","minLength":1,"maxLength":64}},"required":["code"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},{"name":"rename_device","description":"Set the nickname of an already paired PC using its host ID. This changes only its label.","inputSchema":{"type":"object","properties":{"host_id":{"type":"string","pattern":"^[a-f0-9]{32}$"},"nickname":{"type":"string","minLength":1,"maxLength":64}},"required":["host_id","nickname"],"additionalProperties":false},"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":true,"openWorldHint":false}},{"name":"list_projects","description":"List paired desktop hosts, nicknames and connection status. Resolve a requested nickname to its exact host ID before sending a command.","inputSchema":{"type":"object","additionalProperties":false},"annotations":{"readOnlyHint":true,"openWorldHint":false}},{"name":"fs_batch","description":"Run up to four independent read-only repository operations in one scoped approval, preserving order and individual errors.","inputSchema":browse_schema("fs_batch"),"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}},{"name":"fs_list","description":"List repository directory entries with depth and offset pagination; skips links and Git metadata, includes ignored entries.","inputSchema":browse_schema("fs_list"),"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}},{"name":"git_diff","description":"Read a bounded single-file unified text diff against HEAD, staged or unstaged; binary changes reported without contents.","inputSchema":browse_schema("git_diff"),"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}},{"name":"fs_search","description":"Search selected repository paths or UTF-8 text with Git ignore rules, literal or regex; bounded results, separate local approval.","inputSchema":search_schema(),"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}},{"name":"fs_read","description":"Read a bounded 16 KiB UTF-8 line page from a file up to 8 MiB, with full-file SHA-256 and Git HEAD, after exact local approval.","inputSchema":read_schema(),"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}},{"name":"request_permission","description":"Ask the PC owner to approve one named capability for a fixed duration or until revoked. For admin_command on a Windows service installation, the owner approves unattended access once for the requested duration.","inputSchema":permission_schema(),"annotations":{"readOnlyHint":false,"destructiveHint":false,"idempotentHint":false,"openWorldHint":false}},{"name":"admin_command","description":"Run an exact PowerShell command as administrator on the selected Windows PC. A service installation can run this within an active unattended owner grant. A legacy installation needs approval and UAC for each command. Can modify the PC. Returns bounded output and exit code.","inputSchema":admin_command_schema(),"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},{"name":"user_command","description":"Run PowerShell in the installation owner's non-elevated logged-in Windows account. Requires a separate owner-approved user_command permission; no fallback to SYSTEM. Returns bounded output.","inputSchema":user_command_schema(),"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},{"name":"process_spawn_detached","description":"Launch a PowerShell command in a visible, on-demand Windows Scheduled Task as the non-elevated signed-in owner. Requires dedicated capability AND exact local launch approval. Continues independently of MCP, including after MCP revocation. No automatic triggers or restart. Returns task path, instance ID and scheduler engine PID; stop via Task Scheduler. No MCP-managed output.","inputSchema":detached_schema(),"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},{"name":"user_command_result","description":"Read retained output of a user_command request, bound to the same owner grant.","inputSchema":command_result_schema(),"annotations":{"readOnlyHint":true,"openWorldHint":false}},{"name":"elevated_user_command","description":"Run PowerShell as the signed-in installation owner's elevated administrator account. Requires separate explicit elevated_user_command approval; no SYSTEM fallback. Network drive mappings may differ from standard user.","inputSchema":admin_command_schema(),"annotations":{"readOnlyHint":false,"destructiveHint":true,"idempotentHint":false,"openWorldHint":true}},{"name":"elevated_user_command_result","description":"Read a retained elevated_user_command result under the same grant.","inputSchema":command_result_schema(),"annotations":{"readOnlyHint":true,"openWorldHint":false}},{"name":"terminal_open","description":"Open a hidden persistent PowerShell terminal under an active unattended grant. Up to four per PC. If full, use admin_command for short one-shot tasks.","inputSchema":terminal_schema("terminal_open"),"annotations":{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":false}},{"name":"terminal_list","description":"List running, idle and recently closed persistent terminals for the current grant.","inputSchema":terminal_schema("terminal_list"),"annotations":{"readOnlyHint":true,"openWorldHint":false}},{"name":"terminal_run","description":"Start a command asynchronously in an idle terminal. Directory and variables persist. Returns a command ID immediately.","inputSchema":terminal_schema("terminal_run"),"annotations":{"readOnlyHint":false,"destructiveHint":true,"openWorldHint":true}},{"name":"terminal_read","description":"Read command status and a bounded console output page. Pass next_offset to continue reading new output later.","inputSchema":terminal_schema("terminal_read"),"annotations":{"readOnlyHint":true,"openWorldHint":false}},{"name":"terminal_close","description":"Close a terminal and terminate its process tree. Recent results remain readable.","inputSchema":terminal_schema("terminal_close"),"annotations":{"readOnlyHint":false,"destructiveHint":true,"openWorldHint":false}},{"name":"admin_command_result","description":"Read a retained one-shot command result by request ID, including exit code and captured output. Requires the same active unattended grant.","inputSchema":command_result_schema(),"annotations":{"readOnlyHint":true,"openWorldHint":false}},{"name":"system_volume_status","description":"Check whether Windows has flagged its system volume for a disk check. Requires a separate local approval and Windows elevation on every call.","inputSchema":schema(),"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}},{"name":"use_repository","description":"Select an existing local Git repository, or initialize an ordinary folder as one when initialize=true. Requires approval for the exact path. No files are added or committed.","inputSchema":repository_schema(),"annotations":{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":true}},{"name":"git_snapshot","description":"Create a locally approved Git snapshot commit of selected existing files; empty paths establish the first empty commit.","inputSchema":snapshot_schema(),"annotations":{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":false}},
{"name":"patch_prepare","description":"Propose bounded UTF-8 file changes against an expected Git HEAD and file SHA256. Returns a diff; does not write.","inputSchema":patch_prepare_schema(),"annotations":{"readOnlyHint":true,"openWorldHint":false}},
{"name":"patch_review","description":"Review a prepared patch and its exact diff after local approval.","inputSchema":patch_id_schema(),"annotations":{"readOnlyHint":true,"openWorldHint":false}},
{"name":"patch_status","description":"Read the current state of a prepared patch after local approval.","inputSchema":patch_id_schema(),"annotations":{"readOnlyHint":true,"openWorldHint":false}},
{"name":"patch_apply","description":"Apply a previously prepared patch only after a separate exact local approval. Does not commit.","inputSchema":patch_id_schema(),"annotations":{"readOnlyHint":false,"destructiveHint":true,"openWorldHint":false}},
{"name":"git_commit_patch","description":"Commit only the successfully applied patch files as a Git commit after a separate local approval.","inputSchema":patch_commit_schema(),"annotations":{"readOnlyHint":false,"destructiveHint":false,"openWorldHint":false}},{"name":"git_status","description":"Read Git status in the selected repository after exact local approval.","inputSchema":schema(),"annotations":{"readOnlyHint":true,"destructiveHint":false,"openWorldHint":false}}]})
        }
        "tools/call" => {
            if !matches!(
                params["name"].as_str(),
                Some("git_status" | "fs_read" | "fs_search" | "fs_list" | "fs_batch" | "git_diff" | "use_repository" | "git_snapshot" | "patch_prepare" | "patch_review" | "patch_status" | "patch_apply" | "git_commit_patch" | "list_projects" | "pair_device" | "rename_device" | "request_permission" | "system_volume_status" | "admin_command" | "admin_command_result" | "user_command" | "user_command_result" | "elevated_user_command" | "elevated_user_command_result" | "process_spawn_detached" | "terminal_open" | "terminal_list" | "terminal_run" | "terminal_read" | "terminal_close")
            ) {
                return (400, Some(error(&id, -32602, "Unknown tool")));
            }
            let args = &params["arguments"];
            let tool = params["name"].as_str().unwrap_or("");
            let valid = if tool == "list_projects" {
                args == &json!({})
            } else if tool=="pair_device" {
                args.as_object().is_some_and(|value|value.len()==1+usize::from(value.contains_key("nickname"))) &&
                    args["code"].as_str().and_then(crate::enrollment::split_code).is_some() &&
                    args.get("nickname").is_none_or(|value|value.as_str().is_some_and(crate::broker::valid_nickname))
            } else if tool=="rename_device" {
                args.as_object().is_some_and(|value|value.len()==2) &&
                    args["host_id"].as_str().is_some_and(|id|id.len()==32 && id.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) &&
                    args["nickname"].as_str().is_some_and(crate::broker::valid_nickname)
            } else {
                args.as_object().is_some_and(|a| {
                let id=args.get("request_id").is_none_or(|v|v.as_str().is_some_and(|s|matches!(uuid::Uuid::parse_str(s),Ok(id) if id.get_version()==Some(uuid::Version::Random) && id.to_string()==s)));
                let (extra, valid_tool_args) = match tool {
                    "fs_search" => (1,crate::policy::valid_search_query(&args["query"])),
                    "fs_list" => (1,crate::policy::valid_list_query(&args["query"])),
                    "fs_batch" => (1,crate::policy::valid_batch_query(&args["query"])),
                    "git_diff" => (1,crate::policy::valid_diff_query(&args["query"])),
                    "fs_read" => (1+usize::from(a.contains_key("start_line"))+usize::from(a.contains_key("end_line")),
                        args["path"].as_str().is_some_and(valid_read_path)
                        && a.get("start_line").is_none_or(|v|v.as_u64().is_some_and(|n|(1..=8_388_608).contains(&n)))
                        && a.get("end_line").is_none_or(|v|v.as_u64().is_some_and(|n|(1..=8_388_608).contains(&n)))
                        && args["end_line"].as_u64().is_none_or(|end|end>=args["start_line"].as_u64().unwrap_or(1))),
                    "terminal_open" | "terminal_list" => (0,true),
                    "terminal_run" | "terminal_read" | "terminal_close" => {
                        let terminal_id=args["terminal_id"].as_str().is_some_and(|id|matches!(
                            uuid::Uuid::parse_str(id),Ok(value) if value.get_version()==Some(uuid::Version::Random) && value.to_string()==id));
                        match tool {
                            "terminal_run" => (2+usize::from(a.contains_key("timeout_seconds")),terminal_id
                                && args["command"].as_str().is_some_and(crate::policy::valid_command)
                                && a.get("timeout_seconds").is_none_or(|v|v.as_u64().is_some_and(|n|(1..=28800).contains(&n)))),
                            "terminal_read" => (1+usize::from(a.contains_key("offset")),terminal_id
                                && a.get("offset").is_none_or(Value::is_u64)),
                            _ => (1,terminal_id),
                        }
                    },
                    "admin_command_result" | "user_command_result" | "elevated_user_command_result" => (1, args["run_id"].as_str().is_some_and(|id|matches!(uuid::Uuid::parse_str(id), Ok(value) if value.get_version()==Some(uuid::Version::Random) && value.to_string()==id))),
                    "process_spawn_detached" => {
                        let mut payload=json!({"command":args["command"]});
                        if let Some(value)=args.get("working_directory"){payload["working_directory"]=value.clone();}
                        (1+usize::from(a.contains_key("working_directory")),crate::policy::valid_detached_args(&payload))
                    },
                    "admin_command" | "user_command" | "elevated_user_command" => (1, args["command"].as_str().is_some_and(crate::policy::valid_command)),
                    "use_repository" => (2, args["path"].as_str().is_some_and(|s|!s.is_empty() && s.len()<=500 && !s.chars().any(char::is_control)) && args["initialize"].is_boolean()),
                    "git_snapshot" => (2,crate::policy::valid_snapshot_args(&json!({"paths":args["paths"],"message":args["message"]}))),
                    "patch_prepare" => (2,crate::policy::valid_prepare_args(&json!({"expected_head":args["expected_head"],"changes":args["changes"]}))),
                    "patch_review"|"patch_status"|"patch_apply" => (1,crate::policy::valid_patch_id_args(&json!({"patch_id":args["patch_id"]}))),
                    "git_commit_patch" => (2,crate::policy::valid_commit_args(&json!({"patch_id":args["patch_id"],"message":args["message"]}))),
                    "request_permission" => (2,
                        matches!(args["capability"].as_str(), Some("pairing" | "git_status" | "fs_read" | "fs_search" | "fs_list" | "fs_batch" | "git_diff" | "use_repository" | "git_snapshot" | "patch_prepare" | "patch_review" | "patch_status" | "patch_apply" | "git_commit_patch" | "system_volume_status" | "admin_command" | "user_command" | "elevated_user_command" | "process_spawn_detached"))
                        && args["duration"].as_str().is_some_and(crate::policy::valid_duration)),
                    _ => (0, true),
                };
                let terminal=crate::broker::terminal_tool(tool);
                let valid_context=!a.contains_key("context") || (terminal && matches!(args["context"].as_str(),Some("system"|"user"|"elevated_user")));
                let expected=2+usize::from(args.get("request_id").is_some())+extra+usize::from(terminal && a.contains_key("context"));
                a.len()==expected && valid_context && id && args["workspace_id"]=="default" && args["host_id"].as_str().is_some_and(|s|s.len()==32 && s.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b))) && valid_tool_args
            })
            };
            if !valid {
                return (400, Some(error(&id, -32602, "Invalid tool arguments")));
            }
            match dispatch(tool, args, alive) {
                Ok(data) => {
                    json!({"resultType":"complete","content":[{"type":"text","text":data.to_string()}],"structuredContent":data,"isError":data["outcome"].get("error").is_some()})
                }
                Err(reason) => {
                    json!({"resultType":"complete","content":[{"type":"text","text":reason}],"isError":true})
                }
            }
        }
        _ => {
            return (
                404,
                Some(error(
                    &id,
                    -32601,
                    "Method not found; supported protocol 2026-07-28",
                )),
            )
        }
    };
    (200, Some(complete(&id, result)))
}
/// Stateless 2025 compatibility. Session IDs are deliberately not allocated;
/// credentials and negotiated-version headers remain mandatory on every call.
fn legacy(
    mut request: Value,
    headers: &HashMap<String, String>,
    dispatch: &Dispatch,
    alive: &dyn Fn() -> bool,
) -> (u16, Option<Value>) {
    let method = request["method"].as_str().unwrap_or("").to_string();
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    if method == "initialize" {
        if request["jsonrpc"] != "2.0"
            || (!id.is_string() && !id.is_i64() && !id.is_u64())
            || !request["params"]["protocolVersion"].is_string()
            || !request["params"]["capabilities"].is_object()
            || !request["params"]["clientInfo"]["name"].is_string()
            || !request["params"]["clientInfo"]["version"].is_string()
        {
            return (400, Some(error(&id, -32602, "Invalid initialize params")));
        }
        let version = if request["params"]["protocolVersion"] == "2025-06-18" {
            "2025-06-18"
        } else {
            "2025-11-25"
        };
        return (
            200,
            Some(complete(
                &id,
                json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"desktop-mcp","version":"0.2.0"},"instructions":"Use pair_device with a code from the PC owner, then request_permission for admin_command. An unattended owner grant applies to subsequent commands on that device."}),
            )),
        );
    }
    if method == "notifications/initialized"
        && request["jsonrpc"] == "2.0"
        && request.get("id").is_none()
    {
        return (202, None);
    }
    let mut mapped = headers.clone();
    mapped.insert("mcp-protocol-version".into(), VERSION.into());
    mapped.insert("mcp-method".into(), method.clone());
    if method == "tools/call" {
        mapped.insert(
            "mcp-name".into(),
            request["params"]["name"].as_str().unwrap_or("").into(),
        );
    }
    if request.get("params").is_none() {
        request["params"] = json!({});
    }
    if !request["params"].is_object() {
        return (400, Some(error(&id, -32602, "Invalid params")));
    }
    request["params"]["_meta"] = json!({"io.modelcontextprotocol/protocolVersion":VERSION,"io.modelcontextprotocol/clientCapabilities":{}});
    let (status, mut body) = rpc(request, &mapped, dispatch, alive);
    if let Some(result) = body
        .as_mut()
        .and_then(|b| b.get_mut("result"))
        .and_then(Value::as_object_mut)
    {
        result.remove("resultType");
    }
    (status, body)
}
fn process(
    http: Http,
    cfg: &Config,
    dispatch: &Dispatch,
    alive: &dyn Fn() -> bool,
) -> (u16, Option<Value>) {
    if http.headers.get("host") != Some(&cfg.authority) {
        return (403, None);
    }
    if http
        .headers
        .get("origin")
        .is_some_and(|s| s != &format!("https://{}", cfg.authority))
    {
        return (403, None);
    }
    let supplied = http
        .headers
        .get("authorization")
        .map(String::as_str)
        .unwrap_or("");
    let expected = format!("Bearer {}", cfg.token);
    if supplied.len() != expected.len()
        || supplied
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |a, (x, y)| a | (x ^ y))
            != 0
    {
        return (401, None);
    }
    if http.path != "/mcp" {
        return (404, None);
    }
    if http.method != "POST" {
        return (405, None);
    }
    if http
        .headers
        .get("content-type")
        .map(|s| s.split(';').next().unwrap_or("").trim())
        != Some("application/json")
    {
        return (415, None);
    }
    let accepts = http.headers.get("accept").map(String::as_str).unwrap_or("");
    if !["application/json", "text/event-stream"]
        .iter()
        .all(|kind| {
            accepts
                .split(',')
                .any(|v| v.trim().split(';').next() == Some(kind))
        })
    {
        return (406, None);
    }
    match serde_json::from_slice::<Value>(&http.body) {
        Ok(v) => {
            let modern = v
                .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
                .is_some();
            let legacy_version = http
                .headers
                .get("mcp-protocol-version")
                .is_some_and(|v| matches!(v.as_str(), "2025-11-25" | "2025-06-18"));
            if !modern && (v["method"] == "initialize" || legacy_version) {
                legacy(v, &http.headers, dispatch, alive)
            } else {
                rpc(v, &http.headers, dispatch, alive)
            }
        }
        Err(_) => (400, Some(error(&Value::Null, -32700, "Parse error"))),
    }
}
fn respond(stream: &mut impl Write, status: u16, body: Option<Value>) -> Result<(), String> {
    let payload = body.map(|v| v.to_string()).unwrap_or_default();
    let auth = if status == 401 {
        "WWW-Authenticate: Bearer realm=\"desktop-mcp\"\r\n"
    } else {
        ""
    };
    write!(stream,"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\n{auth}\r\n{payload}",payload.len()).map_err(|_|"MCP_WRITE_FAILED".to_string())?;
    stream.flush().map_err(|_| "MCP_WRITE_FAILED".into())
}
pub fn start(
    address: SocketAddr,
    tls: ServerConfig,
    cfg: Config,
    dispatch: Dispatch,
) -> Result<(), String> {
    let listener = TcpListener::bind(address).map_err(|e| format!("MCP_BIND: {e}"))?;
    start_listener(listener, tls, cfg, dispatch)
}

fn start_listener(
    listener: TcpListener,
    mut tls: ServerConfig,
    cfg: Config,
    dispatch: Dispatch,
) -> Result<(), String> {
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let tls = Arc::new(tls);
    let cfg = Arc::new(cfg);
    eprintln!(
        "MCP_LISTENING {}",
        listener.local_addr().map_err(|e| e.to_string())?
    );
    let count = Arc::new(AtomicUsize::new(0));
    thread::spawn(move || {
        for incoming in listener.incoming() {
            let socket = match incoming {
                Ok(s) => s,
                Err(_) => continue,
            };
            if count.fetch_add(1, Ordering::SeqCst) >= 16 {
                count.fetch_sub(1, Ordering::SeqCst);
                continue;
            }
            let (tls, cfg, dispatch, count) =
                (tls.clone(), cfg.clone(), dispatch.clone(), count.clone());
            thread::spawn(move || {
                struct Guard(Arc<AtomicUsize>);
                impl Drop for Guard {
                    fn drop(&mut self) {
                        self.0.fetch_sub(1, Ordering::SeqCst);
                    }
                }
                let _guard = Guard(count);
                let _ = socket.set_nodelay(true);
                let _ = socket.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = socket.set_write_timeout(Some(Duration::from_secs(10)));
                if let Ok(conn) = ServerConnection::new(tls) {
                    let mut stream = StreamOwned::new(conn, socket);
                    let (status, body) = match read_http(&mut stream) {
                        Ok(req) => {
                            let _ = stream.sock.set_read_timeout(Some(Duration::from_millis(1)));
                            let alive = || {
                                let mut byte = [0];
                                match stream.sock.peek(&mut byte) {
                                    Err(e)
                                        if matches!(
                                            e.kind(),
                                            std::io::ErrorKind::WouldBlock
                                                | std::io::ErrorKind::TimedOut
                                        ) =>
                                    {
                                        true
                                    }
                                    _ => false,
                                }
                            };
                            process(req, &cfg, &dispatch, &alive)
                        }
                        Err(status) => (status, None),
                    };
                    let _ = respond(&mut stream, status, body);
                }
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn dispatch() -> Dispatch {
        Arc::new(|_, _, _| Err("HOST_DISCONNECTED".into()))
    }
    fn headers() -> HashMap<String, String> {
        HashMap::from([
            ("mcp-protocol-version".into(), VERSION.into()),
            ("mcp-method".into(), "tools/list".into()),
        ])
    }
    fn request() -> Value {
        json!({"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":VERSION,"io.modelcontextprotocol/clientCapabilities":{}}}})
    }
    #[test]
    fn repository_and_patch_tools_are_advertised_and_schema_checked() {
        let (status, reply)=rpc(request(),&headers(),&dispatch(),&||true);
        assert_eq!(status,200);
        let value=reply.unwrap();
        let tools=value["result"]["tools"].as_array().unwrap();
        for name in ["fs_search","fs_list","fs_batch","git_diff","use_repository","git_snapshot","patch_prepare","patch_review",
                     "patch_status","patch_apply","git_commit_patch"] {
            assert!(tools.iter().any(|t|t["name"]==name),"missing tool {name}");
        }
        let mut r=request();
        r["method"]=json!("tools/call");
        r["params"]["name"]=json!("patch_prepare");
        r["params"]["arguments"]=json!({"host_id":"ab".repeat(16),
            "workspace_id":"default","expected_head":"0".repeat(40),
            "changes":[{"path":"../escape","operation":"modify",
                "expected_sha256":"0".repeat(64),"new_content":"evil"}]});
        let mut h=headers();
        h.insert("mcp-method".into(),"tools/call".into());
        h.insert("mcp-name".into(),"patch_prepare".into());
        assert_eq!(rpc(r.clone(),&h,&dispatch(),&||true).0,400);
        r["params"]["arguments"]["changes"]=json!([{"path":"src/main.rs","operation":"modify",
            "expected_sha256":"0".repeat(64),"new_content":null,
            "edits":[{"kind":"exact","old":"before","new":"after"}]}]);
        assert_eq!(rpc(r.clone(),&h,&dispatch(),&||true).0,200);
        r["params"]["arguments"]["changes"][0]["edits"][0]["old"]=json!("");
        assert_eq!(rpc(r,&h,&dispatch(),&||true).0,400);
        assert!(!crate::policy::valid_snapshot_args(&json!({"paths":["../evil"],"message":"snapshot"})));
    }
    #[test]
    fn browse_schema_rejects_unsafe_queries() {
        for (name,valid,invalid) in [
            ("fs_list",json!({"path":".","depth":2,"limit":100}),json!({"path":"../escape"})),
            ("git_diff",json!({"path":"src/main.rs","base":"staged"}),json!({"path":".git/config"})),
        ] {
            let mut r=request();
            r["method"]=json!("tools/call");
            r["params"]["name"]=json!(name);
            r["params"]["arguments"]=json!({"host_id":"ab".repeat(16),"workspace_id":"default","query":valid});
            let mut h=headers();
            h.insert("mcp-method".into(),"tools/call".into());
            h.insert("mcp-name".into(),name.into());
            assert_eq!(rpc(r.clone(),&h,&dispatch(),&||true).0,200);
            r["params"]["arguments"]["query"]=invalid;
            assert_eq!(rpc(r,&h,&dispatch(),&||true).0,400);
        }
    }
    #[test]
    fn independent_rpc_dispatches_overlap() {
        // No desktop connection or real execution: each dispatch merely
        // announces arrival and waits for a bounded test-only release signal.
        use std::sync::{mpsc,Mutex};
        let (arrived_tx,arrived_rx)=mpsc::channel();
        let release=Arc::new((Mutex::new(false),std::sync::Condvar::new()));
        let gate=release.clone();
        let dispatch:Dispatch=Arc::new(move|_,args,_|{
            arrived_tx.send(args["host_id"].clone()).unwrap();
            let (lock,cv)=&*gate;
            let guard=lock.lock().unwrap();
            let _guard=cv.wait_timeout_while(guard,Duration::from_secs(3),|open|!*open).unwrap();
            Ok(json!({"simulated":true}))
        });
        let workers:Vec<_>=(1..=3).map(|id|{
            let dispatch=dispatch.clone();
            thread::spawn(move||{
                let mut r=request();
                r["id"]=json!(id);
                r["method"]=json!("tools/call");
                r["params"]["name"]=json!("git_status");
                r["params"]["arguments"]=json!({"host_id":"ab".repeat(16),"workspace_id":"default"});
                let mut h=headers();
                h.insert("mcp-method".into(),"tools/call".into());
                h.insert("mcp-name".into(),"git_status".into());
                rpc(r,&h,&dispatch,&||true)
            })
        }).collect();
        let deadline=std::time::Instant::now()+Duration::from_secs(2);
        let mut arrivals=0;
        while arrivals<3 && arrived_rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())).is_ok() {
            arrivals+=1;
        }
        *release.0.lock().unwrap()=true;
        release.1.notify_all();
        for worker in workers {
            let (status,body)=worker.join().unwrap();
            assert_eq!(status,200);
            assert_eq!(body.unwrap()["result"]["structuredContent"]["simulated"],true);
        }
        assert_eq!(arrivals,3,"RPC calls must enter dispatch before any finishes");
    }

    #[test]
    fn independent_https_connections_overlap() {
        use std::sync::{mpsc, Mutex, Condvar};
        use std::net::TcpStream;
        use rustls::{ClientConfig, ClientConnection, RootCertStore};
        use rustls::pki_types::ServerName;
        use std::process::Command;
        let dir = tempfile::tempdir().unwrap();
        let openssl = if cfg!(windows) {
            "C:/Program Files/Git/usr/bin/openssl.exe"
        } else { "openssl" };
        let run = |args: &[&str]| {
            let out = Command::new(openssl).args(args).current_dir(dir.path()).output().unwrap();
            assert!(out.status.success(), "fixture certificate generation failed");
        };
        run(&["req","-x509","-newkey","rsa:2048","-nodes","-keyout","ca.key",
            "-out","ca.pem","-days","1","-subj","/CN=Local Test CA",
            "-addext","basicConstraints=critical,CA:TRUE",
            "-addext","keyUsage=critical,keyCertSign,cRLSign"]);
        run(&["req","-new","-newkey","rsa:2048","-nodes","-keyout","server.key",
            "-out","server.csr","-subj","/CN=localhost"]);
        std::fs::write(dir.path().join("ext"),"subjectAltName=DNS:localhost\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\n").unwrap();
        run(&["x509","-req","-in","server.csr","-CA","ca.pem","-CAkey","ca.key",
            "-CAcreateserial","-out","server.pem","-days","1","-extfile","ext"]);
        let read = |name: &str| std::fs::read(dir.path().join(name)).unwrap();
        let cert = read("server.pem");
        let key = read("server.key");
        let tls = ServerConfig::builder().with_no_client_auth().with_single_cert(
            rustls_pemfile::certs(&mut cert.as_slice()).collect::<Result<Vec<_>,_>>().unwrap(),
            rustls_pemfile::private_key(&mut key.as_slice()).unwrap().unwrap()).unwrap();
        let ca = read("ca.pem");
        let mut roots = RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut ca.as_slice()) { roots.add(c.unwrap()).unwrap(); }
        let client = Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth());
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let authority = address.to_string();
        let token = "ab".repeat(32);
        let (arrived_tx, arrived_rx) = mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let gate = release.clone();
        let dispatch: Dispatch = Arc::new(move |_, _, _| {
            arrived_tx.send(()).unwrap();
            let lock = gate.0.lock().unwrap();
            let _guard = gate.1.wait_timeout_while(lock, Duration::from_secs(8), |v| !*v).unwrap();
            Ok(json!({"simulated":true}))
        });
        start_listener(listener, tls, Config { token: token.clone(), authority: authority.clone() }, dispatch).unwrap();
        let workers: Vec<_> = (1..=3).map(|id| {
            let (client, token, authority) = (client.clone(), token.clone(), authority.clone());
            thread::spawn(move || {
                let socket = TcpStream::connect_timeout(&address, Duration::from_secs(3)).unwrap();
                socket.set_read_timeout(Some(Duration::from_secs(12))).unwrap();
                socket.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
                let conn = ClientConnection::new(client, ServerName::try_from("localhost").unwrap()).unwrap();
                let mut stream = StreamOwned::new(conn, socket);
                let mut r = request();
                r["id"] = json!(id);
                r["method"] = json!("tools/call");
                r["params"]["name"] = json!("git_status");
                r["params"]["arguments"] = json!({"host_id":"ab".repeat(16),"workspace_id":"default"});
                let body = r.to_string();
                write!(stream, "POST /mcp HTTP/1.1\r\nHost: {authority}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nMCP-Protocol-Version: {VERSION}\r\nMcp-Method: tools/call\r\nMcp-Name: git_status\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                stream.flush().unwrap();
                let mut reader = std::io::BufReader::new(stream);
                use std::io::BufRead;
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.starts_with("HTTP/1.1 200 "));
                let mut len = None;
                loop {
                    line.clear();
                    assert!(reader.read_line(&mut line).unwrap() > 0);
                    if line == "\r\n" { break; }
                    if let Some(v) = line.strip_prefix("Content-Length: ") {
                        len = Some(v.trim().parse::<usize>().unwrap());
                    }
                }
                let mut payload = vec![0;len.unwrap()];
                reader.read_exact(&mut payload).unwrap();
                let v: Value = serde_json::from_slice(&payload).unwrap();
                assert_eq!(v["id"], id);
                assert_eq!(v["result"]["structuredContent"]["simulated"], true);
            })
        }).collect();
        let deadline = std::time::Instant::now() + Duration::from_secs(6);
        let mut arrivals = 0;
        while arrivals < 3 && arrived_rx.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now())).is_ok() {
            arrivals += 1;
        }
        *release.0.lock().unwrap() = true;
        release.1.notify_all();
        for worker in workers { worker.join().unwrap(); }
        assert_eq!(arrivals, 3, "all three authenticated TLS requests must reach dispatch before any finishes");
    }
    #[test]
    fn modern_discovery_and_validation() {
        assert_eq!(rpc(request(), &headers(), &dispatch(), &|| true).0, 200);
        let mut h = headers();
        h.insert("mcp-method".into(), "tools/call".into());
        assert_eq!(
            rpc(request(), &h, &dispatch(), &|| true).1.unwrap()["error"]["code"],
            -32020
        );
        let mut r = request();
        r["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"] = json!("unknown");
        let mut h = headers();
        h.insert("mcp-protocol-version".into(), "unknown".into());
        assert_eq!(
            rpc(r, &h, &dispatch(), &|| true).1.unwrap()["error"]["code"],
            -32022
        );
        let mut r = request();
        r["params"] = json!({});
        assert_eq!(rpc(r, &headers(), &dispatch(), &|| true).0, 400);
    }
    #[test]
    fn authentication_precedes_discovery_and_origin_is_checked() {
        let cfg = Config {
            token: "ab".repeat(32),
            authority: "localhost:1234".into(),
        };
        let mut h = headers();
        h.insert("host".into(), cfg.authority.clone());
        let req = |headers| Http {
            method: "POST".into(),
            path: "/mcp".into(),
            body: serde_json::to_vec(&request()).unwrap(),
            headers,
        };
        assert_eq!(process(req(h.clone()), &cfg, &dispatch(), &|| true).0, 401);
        h.insert("authorization".into(), format!("Bearer {}", cfg.token));
        h.insert("origin".into(), "https://attacker.invalid".into());
        assert_eq!(process(req(h.clone()), &cfg, &dispatch(), &|| true).0, 403);
        h.remove("origin");
        h.insert(
            "accept".into(),
            "application/json, text/event-stream".into(),
        );
        h.insert("content-type".into(), "application/json".into());
        assert_eq!(process(req(h), &cfg, &dispatch(), &|| true).0, 200);
    }
    #[test]
    fn legacy_handshake_keeps_authentication_and_shared_validation() {
        let r = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1"}}});
        assert_eq!(
            legacy(r, &HashMap::new(), &dispatch(), &|| true).1.unwrap()["result"]
                ["protocolVersion"],
            "2025-11-25"
        );
        let r = json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"shell","arguments":{}}});
        assert_eq!(
            legacy(r, &HashMap::new(), &dispatch(), &|| true).1.unwrap()["error"]["code"],
            -32602
        );
        assert_eq!(
            legacy(
                json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
                &HashMap::new(),
                &dispatch(),
                &|| true
            )
            .0,
            202
        );
    }
    #[test]
    fn rejects_smuggling_batches_and_oversize() {
        for raw in [
            "POST /mcp HTTP/1.1\r\nContent-Length: 0\r\ncontent-length: 0\r\n\r\n",
            "POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /mcp HTTP/1.1\r\nContent-Length: 999999\r\n\r\n",
        ] {
            assert!(read_http(&mut raw.as_bytes()).is_err());
        }
        assert_eq!(rpc(json!([]), &headers(), &dispatch(), &|| true).0, 400);
        let mut r = request();
        r["id"] = Value::Null;
        assert_eq!(rpc(r, &headers(), &dispatch(), &|| true).0, 400);
    }
}
