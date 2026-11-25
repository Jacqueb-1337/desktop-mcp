# MCP ingress

The gateway optionally exposes HTTPS `/mcp` using the 2026-07-28 stateless MCP
protocol, server/tool discovery, strict argument validation, structured errors,
and exact HTTP metadata/header matching.

Opt-in flags: `--mcp-listen 127.0.0.1:8444 --mcp-authority localhost:8444
--mcp-token-file <private-file>`. Token files contain 64 random hexadecimal
characters (256 bits), with Unix mode 0600. Keep credentials outside source control
and command lines. All calls, including discovery, require bearer authentication
over TLS. Untrusted Host and Origin headers are rejected. Each connection carries
one bounded HTTP/1.1 request. Transfer encoding, duplicate headers, oversized
requests and batches are rejected. The ingress has at most 16 workers.

This private authentication profile is for explicitly configured clients. It does
not implement OAuth discovery or registration. ChatGPT connection authentication
and network exposure must be verified before deployment. Never remove authentication
for compatibility.

References checked 2026-11-08:
- https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- https://modelcontextprotocol.io/specification/2026-07-28/basic/lifecycle
- https://modelcontextprotocol.io/specification/2026-07-28/server/tools

Ingress alone does not enable execution. Every operation must pass persistent
routing, gateway policy and exact local authorization described below.

## Scoped execution milestone

Persistent MCP mode now requires `--policy <file> --audit-dir <private-directory>`.
Policy files explicitly allow host IDs, the `default` workspace, and named tools.
The agent's local service must be launched with `--allow-remote-readonly`; it is
otherwise incapable of staging or executing v2 operations. Its `--workspace`
argument selects exactly one repository root. The tray remote switch can disable
remote reads and revoke pending/approved grants. Enabling requires launch capability
and an explicit local opt-in. A saved disable or revocation survives agent restart;
missing or malformed opt-in state is treated as disabled.

The negotiated `scoped_readonly_v2` transport queues at most four requests per host.
Each request includes a fresh UUID/nonce and 100-second expiry. The keyed gateway
journal binds the full envelope before delivery. The local UI reviews the project,
tool, arguments and request hash. A grant is spent and fsynced before execution;
all executable approvals and pending executable reviews are invalidated after
service restart. The spent IDs survive restarts. Legacy v1 reviews remain denial-only.

`git_status` uses a private libgit2 worker, with network features disabled, no
shell or command filters, no index refresh, and a six-second deadline. Linked
worktrees, redirected worktrees, non-root projects and reparse-point roots are
rejected. Results are capped at 512 entries and 60 KB. Returned results are bound
to the operation ID, authenticated host, nonce and full request hash. Denial and
revocation return structured errors. Optional `request_id` tool arguments provide
a durable idempotency key. Disconnected clients cancel pending gateway work.

Verified with real disposable Windows processes using `smoke_execution.py`;
not yet a ChatGPT-originated call or a production deployment.

## Scoped file reads and project discovery

`list_projects` returns configured host/workspace IDs, allowed tools and current
connection status after ingress authentication. It does not enumerate the PC's
filesystem. The initial MVP intentionally supports one explicit project per agent
service (`workspace_id=default`).

`fs_read` accepts a project-relative path and requires its own exact local approval.
The path is part of the signed/audited request fingerprint. Reads run in the same
six-second isolated-worker architecture and use cap-std directory capabilities
for containment, including protection against outside symlinks and Windows
junctions. Absolute paths, traversal, alternate streams and `.git` components are
rejected; output is at most 16 KiB of UTF-8 text. Missing, binary, oversized or
outside files fail with fixed error codes rather than OS paths or file contents.
The process regression checks an approved Windows junction escape and confirms
that outside data is not returned.

## Compatibility and OS security

The endpoint also supports 2025-11-25 and 2025-06-18 clients using initialization.
Legacy operation is stateless and allocates no session ID. Authentication is still
required on initialization, notifications, discovery and every tool call. Legacy
requests must send their negotiated MCP-Protocol-Version header. They share the
same tool validation, policy, approvals and executor as modern requests.

Windows executable services now verify credential/state ACLs rather than assuming
that inherited profile permissions are private. Only the current user, SYSTEM and
Administrators may access credentials. Untrusted writable ancestor directories
fail verification. The Windows installer protects only dedicated app directories
and files, and registers a Limited per-user task. Unix journal tests explicitly
create mode-0700 directories; production audit checks remain unchanged.

## Windows execution contexts (0.3.4)

- `admin_command`: existing unattended SYSTEM execution and authorization.
- `user_command`: non-elevated signed-in installation owner, with separate permission.
- `elevated_user_command`: elevated signed-in installation owner, with separate explicit permission. Requires an administrator token belonging to that owner; never falls back to SYSTEM.
- Persistent terminal tools accept `context` (`system`, `user`, `elevated_user`). Use the same context for open, list, run, read and close. The default remains `system`.
- Each permission can be temporary or permanent until revoked. The existing elevated Windows service remains responsible for enforcing them. Owner-session execution requires the owner to be signed in; a machine with no owner session fails closed.
- User-session shells use the owner's Windows profile and available network credentials. Windows may expose different SMB drive mappings to elevated and non-elevated tokens. If a drive is not present, use its UNC path when accessible, or establish a mapping with the owner's approval. No credentials are copied or automatically changed.
- The terminal limit remains four per PC. Up to four one-shot routes can be in flight independently, and terminal output pages contain up to 16 KiB.

## Detached launches (0.3.5)

The process_spawn_detached capability permits explicitly approved on-demand Windows tasks as the signed-in normal user. Tasks are intentionally unmanaged by Desktop MCP, have no automatic triggers and do not stop on MCP access revocation. The owner must approve the exact launch; an existing command grant is insufficient. The result includes the task path and instance ID. Stop and remove the task in Windows Task Scheduler. Commands may access connected user drives. No automatic sign-out/reboot persistence, elevated launch, captured output, or MCP job control is provided.
