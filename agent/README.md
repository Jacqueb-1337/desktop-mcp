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
- `fs_read`, `git_status`, `git_diff`
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
