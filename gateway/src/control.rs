//! Opt-in, non-sensitive control probe on an already authenticated TLS session.
//! No MCP commands, workspace metadata, or execution capabilities are exposed.
use serde_json::{json, Value};

pub const FEATURE: &str = "control_probe_v1";

pub fn route_opted_in(auth:&Value)->bool {
    auth["features"]==json!([FEATURE,crate::route::FEATURE]) || exec_opted_in(auth)
}
pub fn exec_opted_in(auth:&Value)->bool {auth["features"]==json!([FEATURE,crate::route::FEATURE,crate::broker::FEATURE])}
pub fn agent_opted_in(auth:&Value)->bool {auth["features"]==json!([FEATURE]) || route_opted_in(auth)}

pub fn challenge(host_id: &str, nonce: &str) -> Value {
    json!({"type":"control_probe","version":1,"target_host_id":host_id,
        "nonce":nonce,"operation":"capability_status"})
}

pub fn verify_result(reply: &Value, host_id: &str, nonce: &str) -> Result<(), String> {
    let expected = json!({
        "type":"control_probe_result",
        "version":1,
        "target_host_id":host_id,
        "nonce":nonce,
        "capabilities":["presence"],
        "remote_tools_enabled":false,
        "executed":false
    });
    if *reply != expected {
        return Err("INVALID_CONTROL_PROBE_RESULT".into());
    }
    Ok(())
}

pub fn ack(nonce: &str) -> Value {
    json!({"type":"control_probe_ack","version":1,"nonce":nonce,
        "remote_tools_enabled":false})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_in_requires_exact_feature() {
        assert!(!agent_opted_in(&json!({})));
        assert!(!agent_opted_in(&json!({"features":["control_probe_v1","remote_exec"]})));
        assert!(agent_opted_in(&json!({"features":["control_probe_v1"]})));
    }

    #[test]
    fn reject_mismatched_nonce_identity_or_execution() {
        let id="aabbccddeeff00112233445566778899";
        let nonce="01".repeat(32);
        let mut result=json!({"type":"control_probe_result","version":1,
            "target_host_id":id,"nonce":nonce,"capabilities":["presence"],
            "remote_tools_enabled":false,"executed":false});
        assert!(verify_result(&result,id,&nonce).is_ok());
        assert!(verify_result(&result,id,&"02".repeat(32)).is_err());
        assert!(verify_result(&result,"different-host",&nonce).is_err());
        result["executed"]=json!(true);
        assert!(verify_result(&result,id,&nonce).is_err());
        result["executed"]=json!(false);
        result["capabilities"]=json!(["presence","fs_read"]);
        assert!(verify_result(&result,id,&nonce).is_err());
    }
}
