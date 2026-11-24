
use serde::Deserialize;
use serde_json::{json, Value};
use std::{io::Read, path::Path, time::{Duration, Instant}};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    mode: String,
    pattern: String,
    #[serde(default)]
    regex: bool,
    #[serde(default)]
    case_sensitive: bool,
    #[serde(default = "default_limit")]
    limit: usize,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    exclude: Vec<String>,
    #[serde(default)]
    context: usize,
    #[serde(default)]
    offset: usize,
    #[serde(default)]
    refresh: bool,
}
fn default_limit() -> usize { 100 }
pub fn valid_query(value: &Value) -> bool {
    serde_json::from_value::<Query>(value.clone()).is_ok_and(|q|
        matches!(q.mode.as_str(), "paths" | "text") &&
        !q.pattern.is_empty() && q.pattern.len() <= 512 &&
        !q.pattern.contains('\0') && (1..=200).contains(&q.limit) &&
        q.scope.as_deref().is_none_or(crate::readonly::valid_read_path) &&
        q.exclude.len()<=32 && q.exclude.iter().all(|p|crate::readonly::valid_read_path(p)) &&
        q.context<=3 && q.offset<=20000)
}

use notify::{Watcher, RecursiveMode, RecommendedWatcher};
use rayon::prelude::*;
use std::{sync::{Arc,atomic::{AtomicBool,Ordering}}, io::{BufRead,Write}};

const INDEX_TTL: Duration=Duration::from_secs(10);
const MAX_INDEX_BYTES:usize=16*1024*1024;
const MAX_INDEX_ENTRIES:usize=100_000;

struct Snapshot {
    scope:Option<String>, exclude:Vec<String>, paths:Vec<String>, built:Instant, skipped:usize,
}
pub struct SearchCache {
    watcher:Option<RecommendedWatcher>,
    persistent:bool,
    dirty:Arc<AtomicBool>,
    snapshot:Option<Snapshot>,
    pool:Option<rayon::ThreadPool>,
}
impl SearchCache {
    pub fn new(_root:&Path,persistent:bool)->Self {
        let dirty=Arc::new(AtomicBool::new(false));
        let threads=std::thread::available_parallelism().map(|n|n.get()).unwrap_or(1).clamp(1,8);
        Self{watcher:None,persistent,dirty,snapshot:None,pool:rayon::ThreadPoolBuilder::new().num_threads(threads).build().ok()}
    }
    fn start_watch(&mut self,root:&Path) {
        self.watcher=None;
        self.dirty.store(false,Ordering::Release);
        if !self.persistent{return;}
        let flag=self.dirty.clone();
        self.watcher=RecommendedWatcher::new(move |event:notify::Result<notify::Event>| {
            if !matches!(event,Ok(e) if matches!(e.kind,notify::EventKind::Access(_))) {
                flag.store(true,Ordering::Release);
            }
        },notify::Config::default().with_follow_symlinks(false)).ok();
        #[cfg(windows)]
        if self.watcher.as_mut().is_some_and(|w|w.watch(root,RecursiveMode::Recursive).is_err()){
            self.watcher=None;
        }
        // Linux recursive watches would traverse ignored directories too. Register
        // only directories actually visited by the ignore-aware walk below.
        #[cfg(not(windows))]
        {
            let info=root.join(".git/info");
            if info.is_dir() && !crate::readonly::reparse(&info).unwrap_or(true) {
                if self.watcher.as_mut().is_some_and(|w|w.watch(&info,RecursiveMode::NonRecursive).is_err()){
                    self.watcher=None;
                }
            }
        }
    }
    pub fn query(&mut self,root:&Path,value:&Value)->Result<Value,String> {
        crate::readonly::validate_root(root)?;
        if !valid_query(value){return Err("INVALID_SEARCH_QUERY".into());}
        let q:Query=serde_json::from_value(value.clone()).map_err(|_|"INVALID_SEARCH_QUERY")?;
        let pattern=if q.regex{q.pattern.clone()}else{regex::escape(&q.pattern)};
        let matcher=regex::RegexBuilder::new(&pattern).case_insensitive(!q.case_sensitive)
            .size_limit(1024*1024).build().map_err(|_|"INVALID_SEARCH_REGEX")?;
        let started=Instant::now();
        let deadline=started+Duration::from_secs(4);
        if q.mode=="paths" {
            let invalidated=self.dirty.swap(false,Ordering::AcqRel);
            let reusable=!q.refresh && !invalidated && self.watcher.is_some() &&
                self.snapshot.as_ref().is_some_and(|s|s.scope==q.scope && s.exclude==q.exclude && s.built.elapsed()<INDEX_TTL);
            if !reusable {
                self.start_watch(root);
                #[cfg(not(windows))]
                let mut watched_dirs=0usize;
                let mut paths=Vec::new();
                let mut bytes=0usize;
                let mut skipped=0usize;
                let mut visited=0usize;
                let mut complete=true;
                for entry in walker(root,&q).build() {
                    if Instant::now()>=deadline || visited>=MAX_INDEX_ENTRIES || bytes>=MAX_INDEX_BYTES {
                        complete=false;break;
                    }
                    visited+=1;
                    #[cfg(not(windows))]
                    if let Ok(ref item)=entry {
                        if item.file_type().is_some_and(|t|t.is_dir()) && self.watcher.is_some() {
                            watched_dirs+=1;
                            if watched_dirs>2048 || self.watcher.as_mut().unwrap().watch(item.path(),RecursiveMode::NonRecursive).is_err(){
                                self.watcher=None;
                            }
                        }
                    }
                    match path_entry(root,entry) {
                        Ok(Some(path))=>{bytes+=path.len()+std::mem::size_of::<String>();paths.push(path);},
                        Err(())=>skipped+=1,
                        _=>{}
                    }
                }
                let snapshot=Snapshot{scope:q.scope.clone(),exclude:q.exclude.clone(),paths,built:Instant::now(),skipped};
                let mut answer=path_results(root,&q,&matcher,&snapshot,false,complete,deadline);
                answer["index_watch_active"]=json!(self.watcher.is_some());
                self.snapshot=if complete && self.watcher.is_some() && !self.dirty.load(Ordering::Acquire){Some(snapshot)}else{None};
                return Ok(answer);
            }
            let mut result=path_results(root,&q,&matcher,self.snapshot.as_ref().unwrap(),true,true,deadline);
            result["index_watch_active"]=json!(true);
            result["index_changed_during_query"]=json!(self.dirty.load(Ordering::Acquire));
            // An event observed during the query invalidates the snapshot for the next call.
            return Ok(result);
        }
        let dir=cap_std::fs::Dir::open_ambient_dir(root,cap_std::ambient_authority())
            .map_err(|_|"WORKSPACE_UNAVAILABLE")?;
        let mut state=Page::new(q.offset);
        let mut scanned=0usize;
        let mut skipped=0usize;
        let mut bytes=0usize;
        let mut exhausted=false;
        let mut entries=walker(root,&q).build();
        'scan: loop {
            let mut batch=Vec::new();
            while batch.len()<24 {
                if Instant::now()>=deadline || scanned>=20000 || bytes>=64*1024*1024 {
                    exhausted=true;break;
                }
                let Some(entry)=entries.next()else{break;};
                scanned+=1;
                match path_entry(root,entry){Ok(Some(p))=>batch.push(p),Err(())=>skipped+=1,_=>{}}
            }
            if batch.is_empty(){break;}
            let scan=|path:&String|scan_file(&dir,path,&matcher,!q.regex,q.offset+q.limit+1,deadline);
            let files:Vec<_>=if let Some(pool)=&self.pool{
                pool.install(||batch.par_iter().map(scan).collect())
            }else{batch.iter().map(scan).collect()};
            for (path,file) in batch.iter().zip(files) {
                let Some((content,hits))=file else{skipped+=1;continue;};
                bytes+=content.len();
                if bytes>64*1024*1024 || Instant::now()>=deadline {exhausted=true;break 'scan;}
                if hits.is_empty(){continue;}
                let lines:Vec<&str>=content.lines().collect();
                for i in hits {
                    if Instant::now()>=deadline {exhausted=true;break 'scan;}
                    let line=lines[i];
                    let Some(m)=matcher.find(line)else{continue;};
                    let mut start=m.start().saturating_sub(100);
                    while !line.is_char_boundary(start){start+=1;}
                    let mut end=(start+600).min(line.len());
                    while !line.is_char_boundary(end){end-=1;}
                    let mut hit=json!({"path":path,"line":i+1,"column":line[..m.start()].chars().count()+1,
                        "preview":&line[start..end],"preview_truncated":start>0||end<line.len()});
                    if q.context>0 {
                        let first=i.saturating_sub(q.context);
                        let last=(i+q.context+1).min(lines.len());
                        hit["context"]=json!((first..last).filter(|n|*n!=i).map(|n|{
                            let s=lines[n];let mut end=s.len().min(240);
                            while !s.is_char_boundary(end){end-=1;}
                            json!({"line":n+1,"text":&s[..end],"truncated":end<s.len()})
                        }).collect::<Vec<_>>());
                    }
                    if !state.add(hit,&q){break 'scan;}
                }
            }
            if Instant::now()>=deadline{exhausted=true;}
            if exhausted{break;}
        }
        Ok(state.finish(&q,scanned,bytes,skipped,exhausted))
    }
}
fn walker(root:&Path,q:&Query)->ignore::WalkBuilder {
    let scope=q.scope.clone();
    let exclude=q.exclude.clone();
    let walk_root=root.to_path_buf();
    let mut walker=ignore::WalkBuilder::new(root);
    walker.hidden(false).follow_links(false).parents(false).git_global(false)
        .git_ignore(true).git_exclude(true).max_depth(Some(64))
        .sort_by_file_path(|a,b|a.cmp(b))
        .filter_entry(move |e| {
            if e.file_name().eq_ignore_ascii_case(".git") || crate::readonly::reparse(e.path()).unwrap_or(true){return false;}
            let Ok(rel)=e.path().strip_prefix(&walk_root)else{return false;};
            if rel.as_os_str().is_empty(){return true;}
            let Some(path)=rel.to_str().map(|p|p.replace('\\',"/"))else{return false;};
            if exclude.iter().any(|p|path_prefix(&path,p)){return false;}
            scope.as_ref().is_none_or(|s|path_prefix(&path,s)||path_prefix(s,&path))
        });
    walker
}
fn path_prefix(path:&str,prefix:&str)->bool {
    #[cfg(windows)]
    {Path::new(&path.to_lowercase()).starts_with(prefix.to_lowercase())}
    #[cfg(not(windows))]
    {Path::new(path).starts_with(prefix)}
}
fn path_entry(root:&Path,entry:Result<ignore::DirEntry,ignore::Error>)->Result<Option<String>,()> {
    let entry=entry.map_err(|_|())?;
    if !entry.file_type().is_some_and(|t|t.is_file()){return Ok(None);}
    let relative=entry.path().strip_prefix(root).map_err(|_|())?;
    let path=relative.to_str().ok_or(())?.replace('\\',"/");
    Ok(crate::readonly::valid_read_path(&path).then_some(path))
}
fn still_regular(root:&Path,path:&str)->bool {
    let mut current=root.to_path_buf();
    for part in path.split('/') {
        current.push(part);
        if crate::readonly::reparse(&current).unwrap_or(true){return false;}
    }
    std::fs::metadata(current).is_ok_and(|m|m.is_file())
}
fn path_results(root:&Path,q:&Query,matcher:&regex::Regex,s:&Snapshot,cached:bool,complete:bool,deadline:Instant)->Value {
    let mut state=Page::new(q.offset);
    let mut scanned=0usize;
    let mut skipped=s.skipped;
    let mut exhausted=!complete;
    for path in &s.paths {
        if Instant::now()>=deadline {exhausted=true;break;}
        scanned+=1;
        if matcher.is_match(path) {
            if cached && !still_regular(root,path){skipped+=1;continue;}
            if !state.add(json!({"path":path}),q){break;}
        }
    }
    let mut result=state.finish(q,scanned,0,skipped,exhausted);
    result["index_hit"]=json!(cached);
    result["index_entries"]=json!(s.paths.len());
    result["index_age_ms"]=json!(s.built.elapsed().as_millis());
    result
}
fn scan_file(dir:&cap_std::fs::Dir,path:&str,matcher:&regex::Regex,literal:bool,limit:usize,deadline:Instant)->Option<(String,Vec<usize>)> {
    if Instant::now()>=deadline{return None;}
    let file=dir.open(path).ok()?;
    if !file.metadata().is_ok_and(|m|m.is_file() && m.len()<=1024*1024){return None;}
    let mut bytes=Vec::new();
    file.take(1024*1024+1).read_to_end(&mut bytes).ok()?;
    if bytes.len()>1024*1024 || bytes.contains(&0){return None;}
    let content=String::from_utf8(bytes).ok()?;
    let mut hits=Vec::new();
    if literal && !matcher.is_match(&content){return Some((content,hits));}
    for (i,line) in content.lines().enumerate() {
        if i%256==0 && Instant::now()>=deadline{break;}
        if matcher.is_match(line){hits.push(i);if hits.len()>=limit{break;}}
    }
    Some((content,hits))
}
struct Page {
    results:Vec<Value>, matched:usize, output_bytes:usize, full:bool,
}
impl Page {
    fn new(_offset:usize)->Self{Self{results:Vec::new(),matched:0,output_bytes:0,full:false}}
    fn add(&mut self,hit:Value,q:&Query)->bool {
        if self.matched<q.offset{self.matched+=1;return true;}
        let size=serde_json::to_vec(&hit).map(|v|v.len()).unwrap_or(60001);
        if self.results.len()>=q.limit || self.output_bytes+size>48000 {self.full=true;return false;}
        self.output_bytes+=size;
        self.matched+=1;
        self.results.push(hit);true
    }
    fn finish(self,q:&Query,scanned:usize,bytes:usize,skipped:usize,exhausted:bool)->Value {
        json!({"results":self.results,"truncated":self.full||exhausted,"entries_scanned":scanned,
            "bytes_scanned":bytes,"skipped":skipped,"offset":q.offset,
            "next_offset":if self.full && !exhausted && self.matched<=20000 {Some(self.matched)}else{None},
            "scan_budget_exhausted":exhausted})
    }
}
pub fn search(root:&Path,value:&Value)->Result<Value,String>{
    SearchCache::new(root,false).query(root,value)
}
pub fn session(root:&Path)->Result<(),String>{
    crate::readonly::validate_root(root)?;
    let mut cache=SearchCache::new(root,true);
    let stdin=std::io::stdin();
    let mut reader=stdin.lock();
    let stdout=std::io::stdout();
    let mut writer=stdout.lock();
    loop {
        let mut line=Vec::new();
        let n=reader.by_ref().take(32769).read_until(b'\n',&mut line).map_err(|_|"SEARCH_INPUT_FAILED")?;
        if n==0{return Ok(());}
        if n>32768 || !line.ends_with(b"\n"){return Err("SEARCH_INPUT_LIMIT".into());}
        let result=serde_json::from_slice::<Value>(&line).map_err(|_|"INVALID_SEARCH_QUERY".into())
            .and_then(|v|cache.query(root,&v));
        let response=match result{Ok(data)=>json!({"data":data}),Err(error)=>json!({"error":error})};
        let bytes=serde_json::to_vec(&response).map_err(|_|"SEARCH_OUTPUT_INVALID")?;
        if bytes.len()>65535{return Err("SEARCH_OUTPUT_LIMIT".into());}
        writer.write_all(&bytes).and_then(|_|writer.write_all(b"\n")).and_then(|_|writer.flush()).map_err(|_|"SEARCH_OUTPUT_FAILED")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn watched_index_refreshes_and_respects_scope() {
        let tmp=tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        let root=tmp.path().canonicalize().unwrap();
        std::fs::write(root.join("first.rs"),"abc").unwrap();
        let mut cache=SearchCache::new(&root,true);
        let q=json!({"mode":"paths","pattern":".rs"});
        let first=cache.query(&root,&q).unwrap();
        assert_eq!(first["index_hit"],false);
        if first["index_watch_active"]==true {
            let second=cache.query(&root,&q).unwrap();
            assert_eq!(second["index_hit"],true);
            std::fs::write(root.join("second.rs"),"abc").unwrap();
            for _ in 0..100 {
                if cache.dirty.load(Ordering::Acquire){break;}
                std::thread::sleep(Duration::from_millis(10));
            }
            assert!(cache.dirty.load(Ordering::Acquire),"watcher did not observe create");
            let third=cache.query(&root,&q).unwrap();
            assert_eq!(third["index_hit"],false);
            assert_eq!(third["results"].as_array().unwrap().len(),2);
        }
        let refreshed=cache.query(&root,&json!({"mode":"paths","pattern":".rs","refresh":true})).unwrap();
        assert_eq!(refreshed["index_hit"],false);
        let scoped=cache.query(&root,&json!({"mode":"paths","pattern":".rs","scope":"first.rs"})).unwrap();
        assert_eq!(scoped["results"],json!([{"path":"first.rs"}]));
    }
    #[test]
    fn scoped_search_pages_and_context_are_stable() {
        let tmp=tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        let root=tmp.path().canonicalize().unwrap();
        std::fs::create_dir_all(root.join("src/vendor")).unwrap();
        std::fs::create_dir_all(root.join("src2")).unwrap();
        for p in ["src/a.rs","src/b.rs","src/vendor/c.rs","src2/d.rs"] {
            std::fs::write(root.join(p),"before\nneedle\nafter\n").unwrap();
        }
        let mut query=json!({"mode":"text","pattern":"needle","scope":"src","exclude":["src/vendor"],"context":1,"limit":1});
        let first=search(&root,&query).unwrap();
        assert_eq!(first["results"][0]["path"],"src/a.rs");
        assert_eq!(first["results"][0]["context"],json!([{"line":1,"text":"before","truncated":false},{"line":3,"text":"after","truncated":false}]));
        query["offset"]=first["next_offset"].clone();
        let second=search(&root,&query).unwrap();
        assert_eq!(second["results"][0]["path"],"src/b.rs");
        assert_eq!(second["next_offset"],Value::Null);
        assert_eq!(second["truncated"],false);
        assert!(!valid_query(&json!({"mode":"paths","pattern":"x","scope":"../outside"})));
    }
    #[test]
    fn search_respects_ignore_binary_limits_and_regex() {
        let tmp=tempfile::tempdir().unwrap();
        git2::Repository::init(tmp.path()).unwrap();
        let root=tmp.path().canonicalize().unwrap();
        std::fs::write(root.join(".gitignore"),"ignored.txt\n").unwrap();
        std::fs::write(root.join("main.rs"),"zero\nHello 123\nHello 456\n").unwrap();
        std::fs::write(root.join("ignored.txt"),"Hello 999").unwrap();
        std::fs::write(root.join("binary"),b"Hello 111\0").unwrap();
        let result=search(&root,&json!({"mode":"text","pattern":"hello [0-9]+","regex":true,"limit":1})).unwrap();
        assert_eq!(result["results"][0]["path"],"main.rs");
        assert_eq!(result["results"][0]["line"],2);
        assert_eq!(result["truncated"],true);
        let result=search(&root,&json!({"mode":"paths","pattern":".rs"})).unwrap();
        assert_eq!(result["results"],json!([{"path":"main.rs"}]));
        assert!(search(&root,&json!({"mode":"text","pattern":"[","regex":true})).is_err());
        assert!(!valid_query(&json!({"mode":"text","pattern":"x","limit":201})));
    }
}
