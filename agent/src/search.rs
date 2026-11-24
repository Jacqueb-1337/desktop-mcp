
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
pub fn search(root: &Path, value: &Value) -> Result<Value, String> {
    crate::readonly::validate_root(root)?;
    if !valid_query(value) { return Err("INVALID_SEARCH_QUERY".into()); }
    let query: Query = serde_json::from_value(value.clone()).map_err(|_|"INVALID_SEARCH_QUERY")?;
    let pattern = if query.regex { query.pattern.clone() } else { regex::escape(&query.pattern) };
    let matcher = regex::RegexBuilder::new(&pattern)
        .case_insensitive(!query.case_sensitive).size_limit(1024*1024)
        .build().map_err(|_|"INVALID_SEARCH_REGEX")?;
    let dir = cap_std::fs::Dir::open_ambient_dir(root, cap_std::ambient_authority())
        .map_err(|_|"WORKSPACE_UNAVAILABLE")?;
    let started = Instant::now();
    let scope=query.scope.clone();
    let exclude=query.exclude.clone();
    let walk_root=root.to_path_buf();
    let mut walker = ignore::WalkBuilder::new(root);
    walker.hidden(false).follow_links(false).parents(false).git_global(false)
        .git_ignore(true).git_exclude(true).max_depth(Some(64))
        .sort_by_file_path(|a,b|a.cmp(b))
        .filter_entry(move |e| {
            if e.file_name().eq_ignore_ascii_case(".git") || crate::readonly::reparse(e.path()).unwrap_or(true) {return false;}
            let Ok(rel)=e.path().strip_prefix(&walk_root) else{return false;};
            if rel.as_os_str().is_empty(){return true;}
            let Some(path)=rel.to_str().map(|p|p.replace('\\',"/")) else{return false;};
            let path=Path::new(&path);
            if exclude.iter().any(|p|path.starts_with(p)){return false;}
            scope.as_ref().is_none_or(|s|path.starts_with(s)||Path::new(s).starts_with(path))
        });
    let mut results = Vec::new();
    let mut scanned = 0usize;
    let mut bytes_scanned = 0usize;
    let mut skipped = 0usize;
    let mut truncated = false;
    let mut output_bytes = 0usize;
    let mut matched=0usize;
    let mut page_full=false;
    'walk: for entry in walker.build() {
        if started.elapsed() >= Duration::from_secs(4) || scanned >= 20000 || bytes_scanned >= 64*1024*1024 {
            truncated = true; break;
        }
        scanned += 1;
        let Ok(entry) = entry else { skipped += 1; continue; };
        if !entry.file_type().is_some_and(|t|t.is_file()) { continue; }
        let Ok(relative) = entry.path().strip_prefix(root) else { continue; };
        let Some(path) = relative.to_str().map(|p|p.replace('\\',"/")) else { skipped += 1; continue; };
        if !crate::readonly::valid_read_path(&path) { continue; }
        let mut add = |hit: Value| {
            if matched<query.offset {matched+=1;return true;}
            let size = serde_json::to_vec(&hit).map(|v|v.len()).unwrap_or(60001);
            if results.len() >= query.limit || output_bytes + size > 48000 {page_full=true;return false;}
            output_bytes += size;
            matched+=1;
            results.push(hit);
            true
        };
        if query.mode == "paths" {
            if matcher.is_match(&path) && !add(json!({"path":path})) { truncated=true; break; }
        } else {
            // Open through the repository capability, never through the ambient path.
            let Ok(file) = dir.open(&path) else { skipped+=1; continue; };
            if !file.metadata().is_ok_and(|m|m.is_file() && m.len()<=1024*1024) { skipped+=1; continue; }
            let mut bytes = Vec::new();
            if file.take(1024*1024+1).read_to_end(&mut bytes).is_err() || bytes.len()>1024*1024 {
                skipped+=1; continue;
            }
            bytes_scanned += bytes.len();
            let Ok(content) = std::str::from_utf8(&bytes) else { skipped+=1; continue; };
            if content.contains('\0') { skipped+=1; continue; }
            let lines:Vec<&str>=content.lines().collect();
            for (i,line) in lines.iter().copied().enumerate() {
                if started.elapsed() >= Duration::from_secs(4) { truncated=true; break 'walk; }
                if let Some(m) = matcher.find(line) {
                    let mut start=m.start().saturating_sub(100);
                    while !line.is_char_boundary(start) { start+=1; }
                    let mut end=(start+600).min(line.len());
                    while !line.is_char_boundary(end) { end-=1; }
                    let mut hit=json!({"path":path,"line":i+1,"column":line[..m.start()].chars().count()+1,
                        "preview":&line[start..end],"preview_truncated":start>0||end<line.len()});
                    if query.context>0 {
                        let first=i.saturating_sub(query.context);
                        let last=(i+query.context+1).min(lines.len());
                        hit["context"]=json!((first..last).filter(|n|*n!=i).map(|n|{
                            let s=lines[n];let mut end=s.len().min(240);
                            while !s.is_char_boundary(end){end-=1;}
                            json!({"line":n+1,"text":&s[..end],"truncated":end<s.len()})
                        }).collect::<Vec<_>>());
                    }
                    if !add(hit) {
                        truncated=true; break 'walk;
                    }
                }
            }
        }
    }
    Ok(json!({"results":results,"truncated":truncated,"entries_scanned":scanned,
        "bytes_scanned":bytes_scanned,"skipped":skipped,"offset":query.offset,
        "next_offset":if page_full && matched<=20000 {Some(matched)}else{None},
        "scan_budget_exhausted":truncated&&!page_full}))
}

#[cfg(test)]
mod tests {
    use super::*;
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
