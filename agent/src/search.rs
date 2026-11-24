
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
}
fn default_limit() -> usize { 100 }
pub fn valid_query(value: &Value) -> bool {
    serde_json::from_value::<Query>(value.clone()).is_ok_and(|q|
        matches!(q.mode.as_str(), "paths" | "text") &&
        !q.pattern.is_empty() && q.pattern.len() <= 512 &&
        !q.pattern.contains('\0') && (1..=200).contains(&q.limit))
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
    let mut walker = ignore::WalkBuilder::new(root);
    walker.hidden(false).follow_links(false).parents(false).git_global(false)
        .git_ignore(true).git_exclude(true).max_depth(Some(64))
        .filter_entry(|e| !e.file_name().eq_ignore_ascii_case(".git") && !crate::readonly::reparse(e.path()).unwrap_or(true));
    let mut results = Vec::new();
    let mut scanned = 0usize;
    let mut bytes_scanned = 0usize;
    let mut skipped = 0usize;
    let mut truncated = false;
    let mut output_bytes = 0usize;
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
            let size = serde_json::to_vec(&hit).map(|v|v.len()).unwrap_or(60001);
            if results.len() >= query.limit || output_bytes + size > 48000 { return false; }
            output_bytes += size;
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
            for (i,line) in content.lines().enumerate() {
                if started.elapsed() >= Duration::from_secs(4) { truncated=true; break 'walk; }
                if let Some(m) = matcher.find(line) {
                    let mut start=m.start().saturating_sub(100);
                    while !line.is_char_boundary(start) { start+=1; }
                    let mut end=(start+600).min(line.len());
                    while !line.is_char_boundary(end) { end-=1; }
                    if !add(json!({"path":path,"line":i+1,"column":line[..m.start()].chars().count()+1,
                        "preview":&line[start..end],"preview_truncated":start>0||end<line.len()})) {
                        truncated=true; break 'walk;
                    }
                }
            }
        }
    }
    Ok(json!({"results":results,"truncated":truncated,"entries_scanned":scanned,
        "bytes_scanned":bytes_scanned,"skipped":skipped}))
}

#[cfg(test)]
mod tests {
    use super::*;
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
