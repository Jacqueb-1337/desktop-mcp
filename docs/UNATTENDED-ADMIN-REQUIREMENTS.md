# Desktop MCP: required unattended elevated-access design

## Product contract (not implemented by existing per-command approval path)

The intended Desktop MCP workflow is **device pairing followed by an optional explicit owner-authorized unattended administrator delegation**. The user must not have to monitor a tray popup for every command.

1. A machine owner installs a single Desktop MCP installer. Installation does not ask for a Git repository or development directory.
2. The owner pairs the machine with a specific authorized controller, using a device-bound cryptographic identity.
3. In the PC's **local** Desktop MCP UI, the owner may grant that paired identity unattended access for a selected finite duration or permanently until revoked. Administrator access is a separate explicit choice. Default is disabled.
4. The owner approves Windows elevation **once during installation/activation** of a protected elevated service. No system-wide UAC weakening or auto-clicking UAC is permitted.
5. While the grant is active, the controller can submit authenticated permitted requests even when the PC's owner is away, without a new per-command tray prompt, UAC dialog, or command confirmation.
6. Every command must be bound to the paired identity, grant ID, expiry, command payload, request nonce, and replay protection; the privileged service verifies authorization independently, not by trusting a user-writable flag or arguments.
7. Every execution is written to a durable local audit trail including time, identity, requested operation, approval grant, result code, and revocation state. Output must be bounded. The owner can view and revoke the grant locally at any time, and an explicit kill switch halts execution.
8. The persistent grant survives a reboot, with finite grants expiring on wall-clock time. The pairing may persist after the grant is revoked, but the pairing **must not** imply elevated authority.
9. The installer and service must protect binaries, configuration, and credentials with Windows ACLs. An unprivileged process must not be able to replace the elevated executable, forge a grant, or use local IPC to escalate without authorization.
10. Git initialization, snapshots, patch review, patch application, and commits are separately available according to the scope of the chosen grant.

## Current known blockers

- `agent/src/approval.rs` stores finite and permanent admin command capability grants, but the grants are **not** an unattended privileged execution session.
- `agent/src/service.rs` requires exact per-command local approval before executing remote operations.
- `agent/src/elevation.rs` launches an elevated command helper for **each** request.
- `docs/WindowsCommandRunner.cs` explicitly requires the Windows UAC elevation and an elevated command confirmation dialog on each request.
- `src-tauri/src/lib.rs` rejects enabling administrator commands through its settings UI.
- No authenticated, protected long-lived elevated Windows service implements unattended execution.

These are architectural blockers. Merely changing `request_permission` to `permanent`, refreshing the plugin, or removing a confirmation popup does not implement the desired experience and must not be reported as completion.

## Release criteria

A clean Windows VM without Git or a project folder must support install, pairing, a one-time user-granted elevated delegation, background execution after sign-out/reboot, local auditing, immediate revocation, and expiry. Automated tests must prove that unpaired identities, expired/revoked grants, forged local IPC requests, replayed requests, and tampered binaries/configurations are denied.

**Do not deploy a shortcut that globally disables UAC, installs an unauthenticated SYSTEM command endpoint, or grants privilege solely from a writable local file.**
