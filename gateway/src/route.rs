//! Gateway-originated intent delivery is deliberately denial-only.
//! The next milestone must implement OS-backed approval before execution exists.
use crate::policy::Intent;
use serde_json::{json, Value};

pub const FEATURE: &str = "route_denial_v1";

pub fn request(intent: &Intent, nonce: &str) -> Value {
    json!({"type":"route_intent","version":1,"request_id":intent.request_id,
        "target_host_id":intent.target_host_id,"workspace_id":intent.workspace_id,
        "tool":intent.tool,"nonce":nonce})
}

pub fn verify_denial(reply: &Value, intent: &Intent, nonce: &str) -> Result<(), String> {
    let expected=json!({"type":"route_result","version":1,
        "request_id":intent.request_id,"target_host_id":intent.target_host_id,
        "nonce":nonce,"decision":"requires_local_approval",
        "authorization_granted":false,"executed":false});
    if reply!=&expected {
        return Err("ROUTE_RESULT_MISMATCH_OR_UNSAFE".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn denial_is_strict_and_nonce_bound() {
        let intent=Intent{request_id:"21b664fb-676b-48dd-9e46-f7406fc061d8".into(),
            target_host_id:"aabbccddeeff00112233445566778899".into(),
            workspace_id:"default".into(),tool:"fs_read".into()};
        let nonce="ab".repeat(32);
        let mut reply=json!({"type":"route_result","version":1,"request_id":intent.request_id,
            "target_host_id":intent.target_host_id,"nonce":nonce,
            "decision":"requires_local_approval","authorization_granted":false,"executed":false});
        assert!(verify_denial(&reply,&intent,&nonce).is_ok());
        assert!(verify_denial(&reply,&intent,&"cd".repeat(32)).is_err());
        reply["executed"]=json!(true);
        assert!(verify_denial(&reply,&intent,&nonce).is_err());
    }
}