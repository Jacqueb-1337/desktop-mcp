# Implementation tracking

## Completed in initial tray UI milestone
- [x] Create dedicated Rust/Tauri desktop project.
- [x] Native Windows system tray and Linux tray menu fallback.
- [x] Frameless, rounded, dark tray popup matching approved layout.
- [x] Open from tray, hide on loss of focus, Escape key, no taskbar window.
- [x] Persist local preferences (JSON) and recent local policy activity.
- [x] Read-only / Ask / Auto-approve policy preferences and session duration.
- [x] Remote access preference + local emergency revoke.
- [x] Privilege elevation fail-closed until a privileged helper exists.
- [x] Proper not-paired status and unavailable-feature explanations.

## Local MCP milestone (implemented)
- [x] Standalone stdio MCP server, separate from the tray UI, with no network listener.
- [x] Stable manifest with 154 defined tools, reserved shims and capability discovery.
- [x] Workspace-scoped UTF-8 file reads, Git status and working-tree diffs.
- [x] Reviewable patch preparation, SHA-256 conflict detection, verified apply.
- [x] Selective Git commit using a temporary index; unrelated edits preserved.
- [x] Linux and Windows x64 agent binaries cross-built on the NAS HDD.
- [x] 10 Rust unit tests plus end-to-end MCP stdio smoke test.

## Local background-agent milestone
- [x] Standalone background agent process with loopback-only, bearer-token-authenticated local IPC.
- [x] Per-user runtime credentials, read-only default, and 30/60/240-minute or persistent approval policy.
- [x] Tray Rust bridge for local agent status, policy updates, and emergency revocation.
- [x] Linux and Windows local-service smoke tests, including failed authentication and revoke.
- [x] Linux and Windows user-level autostart installer scripts created and syntax-checked (not installed).
- [x] Updated Linux and Windows tray and agent binaries compiled.

## Next: secure desktop integration
- [x] Windows desktop tray visually confirmed communicating with the separately running local agent (status read).
- [x] Windows user startup task and uninstaller tested with a disposable Git repository (read-only).
- [ ] Test interactive tray approval/revocation through the WebView, plus Linux desktop startup.
- [ ] Harden IPC with native OS peer credentials and explicit Windows DACL validation.
- [ ] Real per-operation Ask approvals, approvals per host/workspace, and auditable consent.
- [ ] Complete reserved tools for file search, shell, process diagnostics and long-running jobs.
- [ ] Production installation and packaging, Linux desktop runtime testing, restart resilience, and logged-in user startup validation.
- [ ] End-to-end atomicity and external concurrency hardening for patch engine.

## Signed device-identity enrollment milestone
- [x] Persistent per-host Ed25519 signing identities and stable device fingerprints.
- [x] Ten-minute, one-use 256-bit invitation and mutually signed join/receipt.
- [x] Local pairing APIs, tray device-pairing subview, and local CLI exchange.
- [x] Durable identity-only trust records, individual revocation, forged/replayed request rejection.
- [x] Two independent agent processes verified end to end on Linux and Windows.
- [ ] Windows identity-file DACL validation and OS peer-credential strengthening.
- [ ] Authenticated remote transport, gateway registration, and host-scoped authorizations.

## Next: multi-computer gateway and security
- [x] TLS-verified outbound agent presence, signed fresh gateway challenge, allowlisted host registration and heartbeat-only protocol, tested end to end on Linux.
- [x] NAS Linux gateway and Linux/Windows agent release builds.
- [ ] Connection quotas for unauthenticated clients, production certificate management and deployment.
- [ ] Authenticate gateway identities in the tray and show live presence status.
- [ ] Gateway MCP endpoint with validated ChatGPT user identity and host routing.
- [ ] Per-device policy and per-user access grants with expiry/revocation.
- [ ] Separate privileged helper; locally approved elevation, never IPC-only elevation.
- [ ] Support invitations with restricted, expiring permissions.
- [ ] Real-time activity log, audit trails and stop/cancel for active jobs.
- [ ] Optional OpenAI secure tunnel on the gateway only.

## Requirements
- One ChatGPT MCP installation; agents can be added without manifest changes.
- No separate settings application or dashboard, only tray popups and a headless CLI.
- No sharing OpenAI tunnel credentials between computers.
- Safe code-editing workflow: inspect -> prepare -> review diff -> revalidate hash -> apply -> verify -> selectively commit.
- Unrestricted shell is not a substitute for patch authorization; enforce policy at the server boundary.
- Never report connected/admin/functional until the capability exists.
