use crate::mcp::Dispatch;
use serde_json::{json, Value};
use std::{collections::HashMap, sync::{Arc,Mutex}, thread, time::{Duration,Instant}};

#[derive(Clone)]
enum State { Running, Finished(Result<Option<Value>,String>) }
struct Entry { host:String, tool:String, at:Instant, state:State }

// Only command status and route errors are kept here. Successful output remains
// on the agent and is read through its existing grant-checked result endpoint.
pub fn wrap(inner:Dispatch) -> Dispatch {
    let jobs:Arc<Mutex<HashMap<String,Entry>>> = Arc::new(Mutex::new(HashMap::new()));
    Arc::new(move |tool,args,alive| {
        if matches!(tool,"admin_command"|"user_command"|"elevated_user_command") {
            let id=args.get("request_id").and_then(Value::as_str).map(str::to_owned)
                .unwrap_or_else(||uuid::Uuid::new_v4().to_string());
            let host=args["host_id"].as_str().ok_or("HOST_REQUIRED")?.to_owned();
            let mut args=args.clone(); args["request_id"]=json!(id);
            {
                let mut entries=jobs.lock().map_err(|_|"ASYNC_COMMAND_UNAVAILABLE")?;
                entries.retain(|_,v| matches!(v.state,State::Running) || v.at.elapsed()<Duration::from_secs(86400));
                if entries.contains_key(&id) {return Err("REQUEST_ID_ALREADY_USED".into());}
                if entries.len()>=256 {
                    if let Some(old)=entries.iter().filter(|(_,e)| !matches!(e.state,State::Running)).min_by_key(|(_,e)|e.at).map(|(k,_)|k.clone()) {entries.remove(&old);}
                }
                if entries.len()>=256 || entries.values().filter(|e| e.host==host && matches!(e.state,State::Running)).count()>=4 {return Err("ASYNC_COMMAND_BUSY".into());}
                entries.insert(id.clone(),Entry{host:host.clone(),tool:tool.to_owned(),at:Instant::now(),state:State::Running});
            }
            let entries=jobs.clone(); let inner=inner.clone(); let name=tool.to_owned(); let key=id.clone();
            if thread::Builder::new().name("async-command".into()).spawn(move || {
                let result=inner(&name,&args,&||true).map(|v| if v["outcome"]["executed"]==true {None} else {Some(v)});
                if let Ok(mut map)=entries.lock() {if let Some(e)=map.get_mut(&key) {e.state=State::Finished(result); e.at=Instant::now();}}
            }).is_err() {if let Ok(mut map)=jobs.lock(){map.remove(&id);} return Err("ASYNC_COMMAND_WORKER_UNAVAILABLE".into());}
            return Ok(json!({"host_id":host,"workspace_id":"default","request_id":id,"outcome":{"pending":true,"executed":false,"run_id":id}}));
        }
        if matches!(tool,"admin_command_result"|"user_command_result"|"elevated_user_command_result") {
            let host=args["host_id"].as_str().ok_or("HOST_REQUIRED")?;
            let id=args["run_id"].as_str().ok_or("RUN_ID_REQUIRED")?;
            let expected=tool.strip_suffix("_result").unwrap();
            let status={let map=jobs.lock().map_err(|_|"ASYNC_COMMAND_UNAVAILABLE")?;
                map.get(id).filter(|e|e.host==host && e.tool==expected).map(|e|e.state.clone())};
            match status {
                Some(State::Running)=>return Ok(json!({"host_id":host,"workspace_id":"default","outcome":{"pending":true,"executed":false,"run_id":id}})),
                Some(State::Finished(Err(error)))=>return Err(error),
                Some(State::Finished(Ok(Some(value))))=>return Ok(value),
                _=>{}
            }
        }
        inner(tool,args,alive)
    })
}

#[cfg(test)]
mod tests {
 use super::*;
 use std::sync::mpsc;
 #[test]
 fn pending_returns_promptly_and_result_stays_grant_checked() {
  let (release_tx, release_rx)=mpsc::channel::<()>(); let rx=Mutex::new(release_rx);
  let inner:Dispatch=Arc::new(move |tool,_,_| {
   if tool=="user_command" {rx.lock().unwrap().recv().unwrap(); Ok(json!({"outcome":{"executed":true,"data":{"secret":"not cached"}}}))}
   else {Err("GRANT_CHECKED".into())}
  });
  let call=wrap(inner); let id=uuid::Uuid::new_v4().to_string();
  let args=json!({"host_id":"host","request_id":id,"workspace_id":"default","command":"slow"});
  let start=Instant::now(); let started=call("user_command",&args,&||true).unwrap();
  assert!(start.elapsed()<Duration::from_secs(1)); assert_eq!(started["outcome"]["pending"],true);
  let result=json!({"host_id":"host","run_id":id,"workspace_id":"default"});
  assert_eq!(call("user_command_result",&result,&||true).unwrap()["outcome"]["pending"],true);
  assert_eq!(call("admin_command_result",&result,&||true).unwrap_err(),"GRANT_CHECKED");
  release_tx.send(()).unwrap();
  for _ in 0..100 {if call("user_command_result",&result,&||true).is_err(){return;} thread::sleep(Duration::from_millis(10));}
  panic!("completed result did not return to grant-checked agent");
 }
}
