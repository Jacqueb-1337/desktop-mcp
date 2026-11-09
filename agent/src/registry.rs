use serde_json::{json, Value};

const RESERVED: &[&str] = &[
    // Discovery, pairing, authorization.
    "get_host", "get_tool_status", "pair_host", "unpair_host", "request_approval",
    "list_audit_events", "execute_extension", "create_support_invite",
    "accept_support_invite", "list_access_grants", "revoke_access_grant",
    "end_support_session", "get_approval_policy", "request_privilege_escalation",
    "get_privilege_status",
    // Command execution, persistent shells and jobs.
    "run_command", "start_terminal", "terminal_input", "terminal_output",
    "stop_terminal", "start_job", "job_status", "job_output", "cancel_job",
    // File operations and larger transfers.
    "list_directory", "stat_path", "read_file_chunk", "write_file", "write_file_chunk",
    "search_files", "search_text", "create_directory", "copy_path", "move_path",
    "delete_path", "hash_file",
    // OS, services, apps, updates.
    "system_info", "system_metrics", "list_processes", "process_info", "stop_process",
    "list_services", "service_info", "manage_service", "list_startup_items",
    "manage_startup_item", "read_system_logs", "reboot_host", "list_apps",
    "app_info", "install_package", "uninstall_package", "list_updates",
    "apply_updates", "launch_app", "app_permissions",
    // Networking.
    "network_info", "list_connections", "dns_lookup", "ping_host",
    "traceroute_host", "http_request", "check_port", "list_firewall_rules",
    "update_firewall_rule",
    // Desktop / UI.
    "screen_info", "screenshot", "record_screen", "list_windows",
    "focus_window", "get_ui_tree", "click", "drag", "scroll",
    "type_text", "press_key", "read_clipboard", "write_clipboard",
    "notify_user", "request_user_input",
    // Code, Git and patching.
    "project_info", "search_symbols", "code_diagnostics", "apply_patch",
    "run_tests", "build_project", "git_log", "git_show", "git_branch",
    "git_checkout", "patch_undo",
    // Storage and NAS.
    "list_disks", "disk_health", "list_volumes", "filesystem_info",
    "mount_volume", "unmount_volume", "filesystem_check", "list_shares",
    "manage_share", "start_backup", "restore_backup",
    // Security.
    "security_status", "list_security_events", "inspect_binary", "scan_file",
    "scan_host", "quarantine_file", "restore_quarantine",
    // Containers, virtualization, browsers.
    "list_containers", "container_info", "container_logs", "container_exec",
    "manage_container", "list_virtual_machines", "manage_virtual_machine",
    "create_snapshot", "browser_sessions", "browser_tabs", "browser_navigate",
    "browser_dom", "browser_click", "browser_fill", "browser_screenshot",
    "browser_download",
    // Automation, media, archives, data, skills.
    "list_scheduled_tasks", "create_scheduled_task", "update_scheduled_task",
    "delete_scheduled_task", "watch_event", "stop_watch", "media_probe",
    "media_convert", "archive_create", "archive_extract", "database_schema",
    "database_query", "database_backup", "database_restore",
    "list_skills", "read_skill", "list_resources", "read_resource"
];

const IMPLEMENTED: &[&str] = &[
    "gateway_info", "list_hosts", "get_capabilities", "fs_read",
    "git_status", "git_diff", "patch_prepare", "patch_review",
    "patch_apply", "patch_status", "git_commit_patch"
];

fn schema(props: Value, required: &[&str]) -> Value {
    json!({"type":"object","properties":props,"required":required,"additionalProperties":false})
}

fn target() -> Value {
    json!({"host_id":{"type":"string","const":"local"},
        "workspace_id":{"type":"string","const":"default"}})
}

fn tool(name: &str, description: &str, input: Value, readonly: bool) -> Value {
    json!({
        "name":name,
        "description":description,
        "inputSchema":input,
        "annotations":{
            "readOnlyHint":readonly,
            "destructiveHint":!readonly,
            "idempotentHint":readonly,
            "openWorldHint":false
        }
    })
}

fn implemented(name: &str) -> Value {
    let mut p=target();
    match name {
        "gateway_info" | "list_hosts" | "get_capabilities" => tool(name,
            "Implemented: inspect the local MCP process/capabilities. Local stdio only.",
            schema(json!({}),&[]),true),
        "fs_read" => {
            p["path"]=json!({"type":"string","description":"Relative path within the pinned Git workspace, e.g. src/main.rs"});
            tool(name,"Implemented: read a UTF-8 file and its SHA-256 precondition. Rejects traversal and symlinks.",
                 schema(p,&["host_id","workspace_id","path"]),true)
        },
        "git_status" => tool(name,"Implemented: show Git HEAD and porcelain worktree status.",
                 schema(p,&["host_id","workspace_id"]),true),
        "git_diff" => {
            p["path"]=json!({"type":"string","description":"Optional single relative path"});
            tool(name,"Implemented: show working tree changes against HEAD, optionally by path.",
                 schema(p,&["host_id","workspace_id"]),true)
        },
        "patch_prepare" => {
            p["expected_head"]=json!({"type":"string","description":"Exact Git HEAD from fs_read or git_status"});
            p["changes"]=json!({"type":"array","minItems":1,"maxItems":16,
                "description":"Proposed text changes. Requires content SHA-256; null only for creation.",
                "items":{"type":"object","additionalProperties":false,
                    "properties":{
                        "path":{"type":"string"},
                        "operation":{"type":"string","enum":["create","modify","delete"]},
                        "expected_sha256":{"type":["string","null"]},
                        "new_content":{"type":["string","null"]}
                    },"required":["path","operation","expected_sha256","new_content"]}});
            tool(name,"Implemented, read-only: verify Git HEAD, file hashes and clean targets; produce unified diff proposal without writing.",
                 schema(p,&["host_id","workspace_id","expected_head","changes"]),true)
        },
        "patch_review" | "patch_status" | "patch_apply" => {
            p["patch_id"]=json!({"type":"string","description":"Opaque proposal ID from patch_prepare"});
            tool(name,match name {
                "patch_review"=>"Implemented, read-only: retrieve diff and checksums for a prepared patch.",
                "patch_status"=>"Implemented, read-only: inspect patch application/commit state.",
                _=>"Implemented, writes only if process explicitly started with --allow-writes: hash-check and apply the reviewed patch."
            }, schema(p,&["host_id","workspace_id","patch_id"]),name!="patch_apply")
        },
        "git_commit_patch" => {
            p["patch_id"]=json!({"type":"string"});
            p["message"]=json!({"type":"string","maxLength":200});
            tool(name,"Implemented, writes only if --allow-writes: commit ONLY this applied patch with a private Git index and HEAD compare-and-swap.",
                 schema(p,&["host_id","workspace_id","patch_id","message"]),false)
        },
        _=>unreachable!()
    }
}

pub fn definitions() -> Vec<Value> {
    let mut result=IMPLEMENTED.iter().map(|name| implemented(name)).collect::<Vec<_>>();
    result.extend(RESERVED.iter().map(|name| {
        // Intentionally generic and permanent so adding a handler later
        // does not require changing the public MCP tool schema.
        tool(name, &format!(
            "RESERVED SHIM, NOT IMPLEMENTED. {} has no side effects. \
             Future arguments must be nested inside parameters.",
            name
        ),schema(json!({
            "host_id":{"type":"string"},
            "workspace_id":{"type":"string"},
            "parameters":{"type":"object","additionalProperties":true}
        }),&["host_id","workspace_id"]),false)
    }));
    result
}

pub fn is_known(name: &str) -> bool {
    IMPLEMENTED.contains(&name) || RESERVED.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_has_unique_names() {
        let defs=definitions();
        let mut names=std::collections::HashSet::new();
        for tool in defs { assert!(names.insert(tool["name"].as_str().unwrap().to_string())); }
        assert!(names.len()>100);
    }
}
