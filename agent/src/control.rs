//! Identity-only probe response. Never invokes the local MCP agent, filesystem,
//! tray approval service, shell, or any user-specific data source.
use serde_json::{json, Value};

pub const FEATURE: &str = "control_probe_v1";

pub fn advertised_features() -> Value {
    json!([FEATURE,crate::route::FEATURE,"scoped_readonly_v2"])
}

pub fn probe_response(frame: &Value, own_host_id: &str) -> Result<Value, String> {
    let nonce=frame.get("nonce").and_then(Value::as_str).ok_or("CONTROL_PROBE_NONCE_MISSING")?;
    if nonce.len() != 64 || !nonce.bytes().all(|b|b.is_ascii_digit()||(b'a'..=b'f').contains(&b)) {
        return Err("CONTROL_PROBE_NONCE_INVALID".into());
    }
    let expected=json!({"type":"control_probe","version":1,
        "target_host_id":own_host_id,"nonce":nonce,"operation":"capability_status"});
    if *frame!=expected {
        return Err("CONTROL_PROBE_UNAUTHORIZED_FRAME".into());
    }
    Ok(json!({"type":"control_probe_result","version":1,
        "target_host_id":own_host_id,"nonce":nonce,
        "capabilities":["presence"],"remote_tools_enabled":false,"executed":false}))
}

pub fn verify_ack(frame: &Value, nonce: &str) -> Result<(), String> {
    let expected=json!({"type":"control_probe_ack","version":1,"nonce":nonce,
        "remote_tools_enabled":false});
    if *frame!=expected {
        return Err("CONTROL_PROBE_ACK_REJECTED".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_probe_only_reports_non_sensitive_presence() {
        let host="aabbccddeeff00112233445566778899";
        let nonce="ab".repeat(32);
        let req=json!({"type":"control_probe","version":1,
            "target_host_id":host,"nonce":nonce,"operation":"capability_status"});
        let response=probe_response(&req,host).unwrap();
        assert_eq!(response["remote_tools_enabled"],false);
        assert_eq!(response["executed"],false);
        assert_eq!(response["capabilities"],json!(["presence"]));
        assert!(verify_ack(&json!({"type":"control_probe_ack","version":1,
            "nonce":nonce,"remote_tools_enabled":false}),&nonce).is_ok());
    }

    #[test]
    fn wrong_host_nonce_or_remote_operation_is_rejected() {
        let host="aabbccddeeff00112233445566778899";
        let mut req=json!({"type":"control_probe","version":1,
            "target_host_id":host,"nonce":"ab".repeat(32),"operation":"capability_status"});
        assert!(probe_response(&req,"not-the-host").is_err());
        req["operation"]=json!("fs_read");
        assert!(probe_response(&req,host).is_err());
        req["operation"]=json!("capability_status");
        req["nonce"]=json!("WRONG");
        assert!(probe_response(&req,host).is_err());
        assert!(verify_ack(&json!({"type":"control_probe_ack","version":1,
            "nonce":"ab".repeat(32),"remote_tools_enabled":true}),&"ab".repeat(32)).is_err());
    }
}
