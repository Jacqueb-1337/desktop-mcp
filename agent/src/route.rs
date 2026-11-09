//! Route transport currently returns a strict approval-required denial.
//! It never invokes local MCP tools, tray services, or filesystem operations.
use serde_json::{json, Value};
use uuid::{Uuid, Version};

pub const FEATURE: &str = "route_denial_v1";

pub fn valid_repository_path(path: &str) -> bool {
    !path.is_empty() && path.len() <= 500 && !path.chars().any(char::is_control)
        && std::path::Path::new(path).is_absolute()
}

pub fn valid_patch_id_args(args:&Value) -> bool {
    args.as_object().is_some_and(|obj|obj.len()==1
        && args["patch_id"].as_str().is_some_and(|id|matches!(
            Uuid::parse_str(id),Ok(v) if v.get_version()==Some(Version::Random) && v.to_string()==id
        )))
}
pub fn valid_snapshot_args(args:&Value) -> bool {
    args.as_object().is_some_and(|o|o.len()==2)
    && args["paths"].as_array().is_some_and(|v|v.len()<=16
        && v.iter().all(|path|path.as_str().is_some_and(crate::readonly::valid_read_path)))
    && args["message"].as_str().is_some_and(|s|!s.is_empty() && s.len()<=200
        && !s.chars().any(char::is_control))
}
pub fn valid_prepare_args(args:&Value) -> bool {
    args.as_object().is_some_and(|o|o.len()==2)
    && args["expected_head"].as_str().is_some_and(|s|s.len()==40 && s.bytes().all(|b|b.is_ascii_hexdigit()))
    && args["changes"].as_array().is_some_and(|items|!items.is_empty() && items.len()<=16
        && items.iter().all(|item|{
            item.as_object().is_some_and(|o|o.len()==4)
            && item["path"].as_str().is_some_and(crate::readonly::valid_read_path)
            && matches!(item["operation"].as_str(),Some("create"|"modify"|"delete"))
            && (item["expected_sha256"].is_null()||item["expected_sha256"].as_str()
                .is_some_and(|s|s.len()==64 && s.bytes().all(|b|b.is_ascii_hexdigit())))
            && (item["new_content"].is_null()||item["new_content"].as_str()
                .is_some_and(|s|s.len()<=48000 && !s.contains('\0')))
        }))
    && serde_json::to_vec(args).is_ok_and(|v|v.len()<=52000)
}
pub fn valid_commit_args(args:&Value) -> bool {
    args.as_object().is_some_and(|o|o.len()==2)
    && args["patch_id"].as_str().is_some_and(|id|matches!(Uuid::parse_str(id),Ok(v)
        if v.get_version()==Some(Version::Random) && v.to_string()==id))
    && args["message"].as_str().is_some_and(|m|!m.is_empty() && m.len()<=200
        && !m.chars().any(char::is_control))
}
pub fn permission_duration(duration: &str) -> Option<Option<u64>> {
    match duration {
        "permanent" => Some(None),
        "1h" => Some(Some(3600)),
        "4h" => Some(Some(14400)),
        _ => {
            let minutes = duration.strip_suffix('m')?;
            let count: u64 = minutes.parse().ok()?;
            ((1..=1440).contains(&count) && count.to_string() == minutes).then(|| Some(count * 60))
        }
    }
}

pub fn deny(frame: &Value, own_host_id: &str) -> Result<Value, String> {
    let object=frame.as_object().ok_or("INVALID_ROUTE_FRAME")?;
    let executable=frame["version"]==2;
    let expected=if executable {vec!["type","version","request_id","target_host_id","workspace_id","tool","nonce","arguments","expires_at"]} else {vec!["type","version","request_id","target_host_id","workspace_id","tool","nonce"]};
    if object.len()!=expected.len() || !expected.iter().all(|k|object.contains_key(*k)) {
        return Err("INVALID_ROUTE_FIELDS".into());
    }
    let id=frame.get("request_id").and_then(Value::as_str).ok_or("INVALID_ROUTE_ID")?;
    if !matches!(Uuid::parse_str(id),Ok(v) if v.get_version()==Some(Version::Random) && v.to_string()==id) {
        return Err("INVALID_ROUTE_ID".into());
    }
    let nonce=frame.get("nonce").and_then(Value::as_str).ok_or("INVALID_ROUTE_NONCE")?;
    if nonce.len()!=64 || !nonce.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
        return Err("INVALID_ROUTE_NONCE".into());
    }
    if frame.get("type")!=Some(&json!("route_intent"))
        || (!executable && frame.get("version")!=Some(&json!(1)))
        || frame.get("target_host_id")!=Some(&json!(own_host_id))
        || frame.get("workspace_id")!=Some(&json!("default"))
        || !(matches!(frame["tool"].as_str(),Some("fs_read"|"git_status"|"use_repository"|"git_snapshot"|"patch_prepare"|"patch_review"|"patch_status"|"patch_apply"|"git_commit_patch"))
            || (executable && matches!(frame["tool"].as_str(), Some("request_permission" | "admin_command_result" | crate::elevation::TOOL | crate::elevation::COMMAND))) || (executable && frame["tool"].as_str().is_some_and(crate::terminal::is_tool))) {
        return Err("ROUTE_NOT_PERMITTED".into());
    }
    if executable {
        let args = &frame["arguments"];
        let valid = match frame["tool"].as_str() {
            Some("git_status" | crate::elevation::TOOL) => args == &json!({}),
            Some("admin_command_result") => args.as_object().is_some_and(|a| {
                a.len() == 1 && args["run_id"].as_str().is_some_and(|id|
                    matches!(Uuid::parse_str(id), Ok(uuid) if uuid.get_version()==Some(Version::Random) && uuid.to_string()==id))
            }),
            Some(crate::elevation::COMMAND) => args.as_object().is_some_and(|a| {
                a.len() == 1 && args["command"].as_str().is_some_and(crate::elevation::valid_command)
            }),
            Some("fs_read") => args.as_object().is_some_and(|a| a.len() == 1 && args["path"].as_str().is_some_and(crate::readonly::valid_read_path)),
            Some("use_repository") => args.as_object().is_some_and(|a| a.len() == 2 && args["path"].as_str().is_some_and(valid_repository_path) && args["initialize"].is_boolean()),
            Some("git_snapshot") => valid_snapshot_args(args),
            Some("patch_prepare") => valid_prepare_args(args),
            Some("patch_review"|"patch_status"|"patch_apply") => valid_patch_id_args(args),
            Some("git_commit_patch") => valid_commit_args(args),
            Some("request_permission") => args.as_object().is_some_and(|a| {
                a.len() == 2
                    && matches!(args["capability"].as_str(), Some("pairing" | "git_status" | "fs_read" | "use_repository" | "git_snapshot" | "patch_prepare" | "patch_review" | "patch_status" | "patch_apply" | "git_commit_patch" | crate::elevation::TOOL | crate::elevation::COMMAND))
                    && args["duration"].as_str().and_then(permission_duration).is_some()
            }),
            Some(tool) if crate::terminal::is_tool(tool) => crate::terminal::valid_args(tool,args),
            _ => false,
        };
        if !valid || frame["expires_at"].as_u64().is_none() {
            return Err("EXECUTION_ROUTE_NOT_PERMITTED".into());
        }
    }
    Ok(json!({"type":"route_result","version":1,"request_id":id,
        "target_host_id":own_host_id,"nonce":nonce,"decision":"requires_local_approval",
        "authorization_granted":false,"executed":false}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn frame()->Value {
        json!({"type":"route_intent","version":1,
            "request_id":"21b664fb-676b-48dd-9e46-f7406fc061d8",
            "target_host_id":"aabbccddeeff00112233445566778899",
            "workspace_id":"default","tool":"fs_read","nonce":"ab".repeat(32)})
    }
    #[test]
    fn deny_without_tool_execution() {
        let reply=deny(&frame(),"aabbccddeeff00112233445566778899").unwrap();
        assert_eq!(reply["decision"],"requires_local_approval");
        assert_eq!(reply["authorization_granted"],false);
        assert_eq!(reply["executed"],false);
    }
    #[test]
    fn reject_wrong_host_unsafe_tools_and_extra_fields() {
        let id="aabbccddeeff00112233445566778899";
        assert!(deny(&frame(),"otherhost").is_err());
        let mut f=frame();f["tool"]=json!("shell");assert!(deny(&f,id).is_err());
        let mut f=frame();f["args"]=json!({});assert!(deny(&f,id).is_err());
        let mut f=frame();f["nonce"]=json!("invalid");assert!(deny(&f,id).is_err());
        let mut f=frame();f["request_id"]=json!("not-uuid");assert!(deny(&f,id).is_err());
    }
}
