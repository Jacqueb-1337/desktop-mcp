//! Host-specific authorization policy. All allowed operations still require a
//! separate, explicit approval on the target host. This module never executes tools.
use serde::{Deserialize,Serialize};
use serde_json::{json,Value};
use std::collections::{HashMap,HashSet};
use std::time::{Duration,Instant};

#[derive(Debug,Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyFile {
    pub version:u32,
    pub hosts:Vec<HostScope>,
}

#[derive(Debug,Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct HostScope {
    pub host_id:String,
    pub workspace_id:String,
    pub tools:Vec<String>,
}

#[derive(Debug,Clone,Deserialize,Serialize)]
#[serde(deny_unknown_fields)]
pub struct Intent {
    pub request_id:String,
    pub target_host_id:String,
    pub workspace_id:String,
    pub tool:String,
}

#[derive(Debug,Clone,Serialize,PartialEq,Eq)]
#[serde(rename_all="snake_case")]
pub enum Decision {
    Denied,
    RequiresLocalApproval,
}

pub fn valid_rel_patch_path(path:&str)->bool {
    !path.is_empty() && path.len()<=500 && !path.contains(['\\',':','\0'])
    && path.split('/').all(|p|!p.is_empty() && p!=".." && p!="."
        && !p.eq_ignore_ascii_case(".git") && !p.ends_with([' ','.'])
        && !p.contains(['<','>','|','?','*']))
}
pub fn valid_patch_id_args(args:&Value)->bool {
    args.as_object().is_some_and(|o|o.len()==1)
    && args["patch_id"].as_str().is_some_and(|s|matches!(uuid::Uuid::parse_str(s),
        Ok(v) if v.get_version()==Some(uuid::Version::Random) && v.to_string()==s))
}
pub fn valid_snapshot_args(args:&Value)->bool {
    args.as_object().is_some_and(|o|o.len()==2)
    && args["paths"].as_array().is_some_and(|ps|ps.len()<=16
        && ps.iter().all(|p|p.as_str().is_some_and(valid_rel_patch_path)))
    && args["message"].as_str().is_some_and(|s|!s.is_empty() && s.len()<=200
        && !s.chars().any(char::is_control))
}
pub fn valid_prepare_args(args:&Value)->bool {
    args.as_object().is_some_and(|o|o.len()==2)
    && args["expected_head"].as_str().is_some_and(|s|s.len()==40 && s.bytes().all(|b|b.is_ascii_hexdigit()))
    && args["changes"].as_array().is_some_and(|items|!items.is_empty() && items.len()<=16
        && items.iter().all(|item|{
            item.as_object().is_some_and(|o|o.len()==4)
            && item["path"].as_str().is_some_and(valid_rel_patch_path)
            && matches!(item["operation"].as_str(),Some("create"|"modify"|"delete"))
            && (item["expected_sha256"].is_null()||item["expected_sha256"].as_str()
                .is_some_and(|s|s.len()==64 && s.bytes().all(|b|b.is_ascii_hexdigit())))
            && (item["new_content"].is_null()||item["new_content"].as_str()
                .is_some_and(|s|s.len()<=48000 && !s.contains('\0')))
        }))
    && serde_json::to_vec(args).is_ok_and(|bytes|bytes.len()<=52000)
}
pub fn valid_commit_args(args:&Value)->bool {
    args.as_object().is_some_and(|o|o.len()==2)
    && args["patch_id"].as_str().is_some_and(|s|matches!(uuid::Uuid::parse_str(s),
        Ok(v) if v.get_version()==Some(uuid::Version::Random) && v.to_string()==s))
    && args["message"].as_str().is_some_and(|s|!s.is_empty() && s.len()<=200
        && !s.chars().any(char::is_control))
}
pub fn valid_duration(duration: &str) -> bool {
    matches!(duration, "permanent" | "1h" | "4h") || duration.strip_suffix('m').is_some_and(|minutes| {
        minutes.parse::<u64>().is_ok_and(|n| (1..=1440).contains(&n) && n.to_string() == minutes)
    })
}

pub fn valid_command(command: &str) -> bool {
    !command.trim().is_empty() && command.len() <= 2000 && command.chars().all(|ch| {
        (matches!(ch, '\n' | '\t') || !ch.is_control())
            && !matches!(ch, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    })
}

impl PolicyFile {
    pub fn validate(&self)->Result<(),String> {
        if self.version!=1||self.hosts.len()>64 {return Err("INVALID_POLICY_VERSION_OR_SIZE".into())}
        let mut unique=HashSet::new();
        for host in &self.hosts {
            if host.host_id.len()!=32||!host.host_id.bytes().all(|b|b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err("INVALID_POLICY_HOST_ID".into())
            }
            if host.workspace_id!="default"||host.tools.len()>12 {
                return Err("INVALID_POLICY_WORKSPACE_OR_TOOLS".into())
            }
            if !unique.insert((host.host_id.as_str(),host.workspace_id.as_str())) {
                return Err("DUPLICATE_POLICY_SCOPE".into())
            }
            if host.tools.iter().any(|tool|!matches!(tool.as_str(),"git_status"|"fs_read"|"use_repository"|"git_snapshot"|"patch_prepare"|"patch_review"|"patch_status"|"patch_apply"|"git_commit_patch"|"request_permission"|"system_volume_status"|"admin_command")) {
                return Err("UNSAFE_POLICY_TOOL".into())
            }
            if host.tools.iter().collect::<HashSet<_>>().len()!=host.tools.len() {
                return Err("DUPLICATE_POLICY_TOOL".into())
            }
        }
        Ok(())
    }
    pub fn decide(&self,request:&Intent,actual_target:&str)->Decision {
        if self.validate().is_err()
            || request.target_host_id!=actual_target
            || request.workspace_id!="default"
            || !matches!(uuid::Uuid::parse_str(&request.request_id), Ok(id) if id.get_version() == Some(uuid::Version::Random)) {
            return Decision::Denied
        }
        if self.hosts.iter().any(|h|
            h.host_id==actual_target&&h.workspace_id==request.workspace_id
            &&h.tools.iter().any(|tool|tool==&request.tool)) {
            Decision::RequiresLocalApproval
        } else {Decision::Denied}
    }
}

/// In-memory, bounded request deduplication for future authenticated routing.
/// This is not durable replay protection; a gateway restart clears this ledger.
/// A matching request still requires separate approval on its target host.
pub struct RequestLedger {
    entries:HashMap<String,Instant>,
    ttl:Duration,
    capacity:usize,
}

impl RequestLedger {
    pub fn new(ttl:Duration,capacity:usize)->Self {
        Self{entries:HashMap::new(),ttl,capacity}
    }

    pub fn preflight(&mut self,policy:&PolicyFile,request:&Intent,session_host:&str)->Decision {
        let decision=policy.decide(request,session_host);
        if decision!=Decision::RequiresLocalApproval {return Decision::Denied}
        let now=Instant::now();
        self.entries.retain(|_,at|now.duration_since(*at)<self.ttl);
        if self.entries.contains_key(&request.request_id)||self.entries.len()>=self.capacity {
            return Decision::Denied
        }
        self.entries.insert(request.request_id.clone(),now);
        Decision::RequiresLocalApproval
    }

    #[cfg(test)]
    pub fn pending_count(&self)->usize {self.entries.len()}
}
/// Offline batch preflight, not an execution grant or a durable anti-replay store.
/// The caller must supply a trusted host identity; live sessions must derive it
/// from the authenticated TLS connection rather than client-submitted fields.
pub fn policy_decisions_batch(
    policy: &PolicyFile,
    requests: &[Value],
    connected_host_id: &str,
) -> Result<Vec<Value>, String> {
    const MAX_BATCH: usize = 128;
    if requests.len() > MAX_BATCH {
        return Err("PREFLIGHT_BATCH_TOO_LARGE".into());
    }
    let mut ledger = RequestLedger::new(Duration::from_secs(600), MAX_BATCH);
    let mut decisions = Vec::with_capacity(requests.len());
    for raw in requests {
        match serde_json::from_value::<Intent>(raw.clone()) {
            Ok(intent) => {
                let decision = ledger.preflight(policy, &intent, connected_host_id);
                decisions.push(json!({
                    "decision": decision,
                    "target_host_id": connected_host_id,
                    "request_id": intent.request_id,
                    "operation": intent.tool,
                    "executed": false,
                    "authorization_granted": false
                }));
            }
            Err(_) => decisions.push(json!({
                "decision": "denied",
                "reason": "invalid_intent",
                "executed": false,
                "authorization_granted": false
            })),
        }
    }
    Ok(decisions)
}
pub fn policy_decision(file:&PolicyFile,request:&Value,connected_host_id:&str)->Value {
    let parsed:Result<Intent,_>=serde_json::from_value(request.clone());
    let Ok(intent)=parsed else {return json!({"decision":"denied","reason":"invalid_intent"})};
    let decision=file.decide(&intent,connected_host_id);
    json!({"decision":decision,"target_host_id":connected_host_id,
        "request_id":intent.request_id,"operation":intent.tool,
        "executed":false,"authorization_granted":false})
}

#[cfg(test)]
mod tests {
    use super::*;
    const A:&str="aabbccddeeff00112233445566778899";
    const B:&str="00112233445566778899aabbccddeeff";
    fn policy()->PolicyFile {
        PolicyFile{version:1,hosts:vec![HostScope{host_id:A.into(),workspace_id:"default".into(),
            tools:vec!["fs_read".into(),"git_status".into()]}]}
    }
    fn intent(target:&str,tool:&str)->Intent {
        Intent{request_id:uuid::Uuid::new_v4().to_string(),target_host_id:target.into(),
            workspace_id:"default".into(),tool:tool.into()}
    }
    #[test]
    fn exact_target_never_grants_execution(){
        assert_eq!(policy().decide(&intent(A,"fs_read"),A),Decision::RequiresLocalApproval);
        assert_eq!(policy().decide(&intent(B,"fs_read"),A),Decision::Denied);
        assert_eq!(policy().decide(&intent(B,"fs_read"),B),Decision::Denied);
        assert_eq!(policy().decide(&intent(A,"patch_apply"),A),Decision::Denied);
        assert_eq!(policy().decide(&intent(A,"run_command"),A),Decision::Denied);
        let result=policy_decision(&policy(),&serde_json::to_value(intent(A,"fs_read")).unwrap(),A);
        assert_eq!(result["executed"],false);
        assert_eq!(result["authorization_granted"],false);
    }
    #[test]
    fn rejects_invalid_and_ambiguous_configuration(){
        let mut p=policy();p.hosts.push(p.hosts[0].clone());
        assert!(p.validate().is_err());
        let mut p=policy();p.hosts[0].tools.push("run_command".into());
        assert!(p.validate().is_err());
        let mut p=policy();p.version=2;
        assert!(p.validate().is_err());
    }
    #[test]
    fn invalid_request_identity_and_uuid_version_are_denied() {
        let mut p=policy();
        p.hosts[0].host_id=A.to_uppercase();
        assert!(p.validate().is_err());
        let mut request=intent(A,"fs_read");
        request.request_id=uuid::Uuid::nil().to_string();
        assert_eq!(policy().decide(&request,A),Decision::Denied);
        request.request_id=uuid::Uuid::new_v4().to_string();
        assert_eq!(policy().decide(&request,A),Decision::RequiresLocalApproval);
    }
    #[test]
    fn ledger_rejects_replay_cross_host_and_capacity() {
        let mut ledger=RequestLedger::new(Duration::from_secs(60),1);
        let first=intent(A,"fs_read");
        assert_eq!(ledger.preflight(&policy(),&first,A),Decision::RequiresLocalApproval);
        assert_eq!(ledger.preflight(&policy(),&first,A),Decision::Denied);
        assert_eq!(ledger.pending_count(),1);
        assert_eq!(ledger.preflight(&policy(),&intent(B,"fs_read"),A),Decision::Denied);
        assert_eq!(ledger.preflight(&policy(),&intent(A,"fs_read"),A),Decision::Denied);
        let mut empty=RequestLedger::new(Duration::from_secs(60),0);
        assert_eq!(empty.preflight(&policy(),&first,A),Decision::Denied);
    }
    #[test]
    fn ledger_reclaims_expired_requests() {
        let first=intent(A,"fs_read");
        let mut ledger=RequestLedger::new(Duration::ZERO,1);
        assert_eq!(ledger.preflight(&policy(),&first,A),Decision::RequiresLocalApproval);
        assert_eq!(ledger.preflight(&policy(),&first,A),Decision::RequiresLocalApproval);
        assert_eq!(ledger.pending_count(),1);
    }
    #[test]
    fn batch_denies_replayed_ids_cross_host_requests_and_invalid_payloads() {
        let first=serde_json::to_value(intent(A,"fs_read")).unwrap();
        let wrong_host=serde_json::to_value(intent(B,"fs_read")).unwrap();
        let malformed=json!({"request_id":"bad","extra":true});
        let results=policy_decisions_batch(
            &policy(),&[first.clone(),first,wrong_host,malformed],A
        ).unwrap();
        assert_eq!(results.len(),4);
        assert_eq!(results[0]["decision"],"requires_local_approval");
        assert_eq!(results[1]["decision"],"denied");
        assert_eq!(results[2]["decision"],"denied");
        assert_eq!(results[3]["reason"],"invalid_intent");
        assert!(results.iter().all(|item|item["executed"]==false &&
            item["authorization_granted"]==false));
    }

    #[test]
    fn batch_rejects_excessive_length() {
        let requests=vec![Value::Null;129];
        assert!(policy_decisions_batch(&policy(),&requests,A).is_err());
    }

    #[test]    fn policy_defaults_to_no_permissions() {
        let p=PolicyFile{version:1,hosts:vec![]};
        assert_eq!(p.decide(&intent(A,"fs_read"),A),Decision::Denied);
    }
}
