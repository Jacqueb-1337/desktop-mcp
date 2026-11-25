# Desktop MCP agent (local protocol milestone)

This standalone MCP engine supports both stdio operation and a separately running local background agent. The background mode binds only to 127.0.0.1 and requires a per-user authentication token. It does not expose a public listener or connect to ChatGPT through a remote gateway. See docs/LOCAL_AGENT.md for the service workflow.

## Start

Linux:
```sh
desktop-mcp-agent --workspace /absolute/path/to/git/repository
```

Windows:
```powershell
desktop-mcp-agent.exe --workspace C:\\path\\to\\git\\repository
```

The selected directory must be a **Git repository root**, and Git must be installed on the target computer. Paths given to tools are relative to that root. Symlink paths, parent traversal, and edits to `.git` are rejected.

By default the server is read-only. To explicitly enable file changes for a trusted local session, launch with `--allow-writes`. This is **not** integrated with tray approval, UAC, sudo, or remote authorization. Never expose this stdio process through a network proxy until the gateway and permission checks are implemented.

## Working tools

- `gateway_info`, `list_hosts`, `get_capabilities`
- `fs_read`, `fs_search`, `fs_list`, `git_status`, `git_diff`
- `patch_prepare`, `patch_review`, `patch_status`, `patch_apply`, `git_commit_patch`

Other advertised tools are deliberately marked as **NOT_IMPLEMENTED** and return errors without side effects. Their generic argument wrapper allows implementing new functionality without changing tool names/schemas.

### Patch workflow

1. Read the target file with `fs_read` to get `sha256` and `head`.
2. Call `patch_prepare` with `expected_head` and a list of up to 16 file changes.
3. Review `patch_id` and its unified diff; files are **not modified** at this stage.
4. Call `patch_apply`; the server rechecks Git HEAD, each SHA-256, and clean tracked targets before writing.
5. Call `git_commit_patch` with a commit message. It commits only files in the patch via an isolated Git index, preserving unrelated staged and unstaged work.

`patch_prepare` changes use this structure:

```json
{
  "host_id": "local",
  "workspace_id": "default",
  "expected_head": "<40-character commit id>",
  "changes": [
    {
      "path": "src/main.rs",
      "operation": "modify",
      "expected_sha256": "<64-character SHA256>",
      "new_content": "replacement UTF-8 text"
    }
  ]
}
```

For a targeted modification, set `new_content` to `null` and provide `edits`, for example:
`[{"kind":"exact","old":"old text","new":"new text"},{"kind":"lines","start":5,"end":6,"new":"replacement\\n"}]`.
Edits execute sequentially against the evolving in-memory text. Exact text must occur exactly once (including overlapping occurrences); line ranges are 1-based and inclusive. Include any required line terminators. The resulting content goes through the existing hash, Git HEAD, diff preview and apply checks.

`fs_search` takes a `query` object, e.g. `{"mode":"text","pattern":"fn main","regex":false,"limit":100}`. Use `mode:"paths"` for filenames/paths. Search is case-insensitive unless `case_sensitive` is true, respects repository ignore rules, and skips symlinks/reparse points, binary and oversized text files. Results are bounded; inspect `truncated` and `skipped`. Remote search needs its own gateway policy scope and local permission. Optional scope and exclude entries are repository-relative path prefixes (not globs). Set context to 0?3 neighboring lines, and use next_offset to retrieve the next page with identical query settings; pages assume unchanged files. A scan-budget truncation may require narrowing scope instead. Remote path queries reuse a workspace-pinned, in-memory index for up to 10 seconds when filesystem notifications are available. Changes invalidate the snapshot; use refresh:true to force a new scan. The response reports index_hit, index_age_ms and index_watch_active. Without a usable watcher, the agent scans freshly. Text searches read current files rather than caching contents, use up to eight scanning threads, and retain deterministic result order. The index is bounded to 100,000 visited entries and 16 MiB of estimated path storage; incomplete indexes are not reused. The existing scan time and output budgets still apply. Default engine:"fff" uses FFF's SIMD fuzzy matching for case-insensitive, non-regex paths and FFF's bigram filter for literal ASCII content searches. The agent builds the content index only from capability-opened, repository-scoped files, never using FFF's ambient filesystem walker. Candidate contents are read again before returning results. The FFF filter is limited to 20,000 paths and 64 MiB of scanned source; non-ASCII and unindexed files remain candidates. Regex and case-sensitive filename search retain exact matching. Cache hits and prefiltered file counts are reported; use refresh:true or engine:"native" for exact fresh scans. Automatic native fallback handles unsupported queries, missing/slow indexes, and fuzzy matching failures; results identify the requested and actual engines. Cold content indexing is limited to 1.5 seconds to preserve scan time.

fs_read supports optional inclusive start_line/end_line and returns full-file SHA-256, Git HEAD (null if unborn), total_lines, and next_start_line. Files up to 8 MiB can be read in pages of at most 16 KiB; an individual line above the page limit is rejected. The separate patch engine still caps editable file size at 256 KiB.

For `create`, set `expected_sha256` to `null`. For `delete`, set `new_content` to `null`.

Only UTF-8 text files up to 256 KiB are supported in this milestone. Patch proposals expire after 15 minutes, remain in process memory, and do not survive restart. Multi-file rollback is best effort and external filesystem modifications are not locked against races. This is not yet a hardened multi-user remote editing service.

## Test

```sh
cargo test --manifest-path agent/Cargo.toml
python3 agent/smoke_protocol.py /path/to/desktop-mcp-agent
```

The smoke test creates a disposable Git repository, performs MCP JSON-RPC requests over stdio, verifies a patch and a selective commit, then deletes the repository.

## NAS builds

- `docs/build-agent-on-nas.sh`: Linux tests plus optimized Linux binary.
- `docs/build-agent-windows-on-nas.sh`: Windows x64 cross-build using cargo-xwin.

Both use the NAS ext4 HDD for source/cache and refuse to run if the HDD mount is unavailable.

Remote repository browsing: `fs_list` accepts `query` with path (default "."), depth 1?5, limit 1?200 and offset. Entries include ignored files, omit Git metadata and links; incomplete scan budgets are explicit. Remote `git_diff` accepts a single relative file in `query.path`, base head/staged/unstaged and context 0?10. It compares raw file bytes, not Git filters or rename/mode detection; text is limited to 256 KiB per side, output bounded, binary content omitted. Both require separately allowed capabilities and exact local approval. Local stdio git_diff retains its legacy schema.

Reviewed transfers: in patch_prepare, use operation copy/move/rename, path as new destination, expected_sha256 and new_content null, source_path and source_sha256. Clean tracked non-executable UTF-8 files up to 256 KiB only, existing destination parent, no overwrite or overlapping paths. Review displays exact source/destination and hash; move/rename remove the original only during explicitly approved apply, with rollback on failure. No directory or binary transfers.

Remote fs_batch: query is an array of 1?4 {tool,arguments} items (fs_read, fs_list, fs_search, git_diff, git_status). For list/search/diff the inner arguments are the query itself. All subtools must be permitted as well as fs_batch, and one exact batch approval is required. The isolated worker runs independent reads concurrently, reports results in input order with per-item errors, and caps aggregate output. Batch search uses a fresh index, not the resident search cache. No commands, writes or nested batches.

Windows SMB repositories: run the repository agent in the authorized signed-in user context (not LocalSystem). If Git reports dubious ownership, the owner must explicitly trust the exact repository in their user Git configuration; do not use a wildcard. Isolated workers retain profile location hints so libgit2 sees that trust configuration. Directory listing has a UNC-only SMB compatibility path, with canonical-path and capability checks retained. The integration fixture can be run on a mapped share using DMCP_SMOKE_REPO_PARENT; it uses disposable Git configuration and repository data.


## Windows owner-context repository relay

When the protected Windows service owns the machine's gateway connection, it
forwards only repository routes (and their capability permission requests) to
the existing signed-in owner's local agent. The protected service launches a
non-elevated worker using the installation owner's active console token and
a bounded authenticated loopback protocol. The worker discovers the local
agent in the owner's application-data directory; it does not read or forward
the protected service's private state or credentials. The user-local agent
must report the same host identity, normal-user mode, and pairing-consent
enforcement. The owner still approves pairing, each capability, and each exact
repository operation through the tray. The selected repository is bound to
the approval journal entry; changing it invalidates a pending operation for
the previous repository. Cancellation revokes unspent approvals.

The machine gateway connection remains the only gateway connection; do not
start a second gateway connection using the copied machine identity. Repository
operations need an explicitly allowed gateway host policy and the owner-local
agent running while the installation owner is signed in. The machine command
grants do not authorize repository tools. Revoke repository access using the
user tray's remote-access revoke action. A lost response during a write is
ambiguous: inspect the repository before retrying. The native SMB test can
be run with DMCP_SMOKE_REPO_PARENT pointing to the mapped project directory
and python gateway/smoke_owner_repository.py <agent.exe>. This exercises the
actual worker protocol, not the protected service's Windows token launcher.

Detached Windows tasks: process_spawn_detached accepts command (PowerShell, max 2000 bytes) and optional absolute working_directory (defaults to the owner's profile). A distinct host policy capability, user-local pairing permission, capability permission and exact per-launch owner approval are required. No administrator or command grant implies this permission. Windows Task Scheduler starts a visible on-demand task with the owner's interactive non-elevated token, unlimited execution time, no automatic trigger or restart. It consumes no MCP terminal slot and continues after terminal/agent/gateway shutdown or MCP permission revocation. Stop and delete it via Windows Task Scheduler; no output is retained by MCP and no sign-out/reboot survival is promised. Returned task path, instance ID and scheduler engine PID identify the Windows task. If a launch result is ambiguous, inspect Task Scheduler before retrying; each approved request ID is one-use. Test with gateway/smoke_detached.py on a disposable fixture.
