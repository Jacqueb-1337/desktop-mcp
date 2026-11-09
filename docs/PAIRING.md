# Desktop MCP: signed device identity enrollment

This milestone provides **offline, mutual Ed25519 host enrollment**. It is NOT the remote gateway, encrypted transport, ChatGPT connector, or authorization to execute tools on another computer.

## What is implemented

- Each local agent creates a persistent Ed25519 signing key in its user-specific app configuration directory on first start.
- A device ID is derived from the SHA-256 fingerprint of the public key.
- One-time invitations contain a randomly generated 256-bit secret and expire after 10 minutes. Replacing or cancelling an invitation invalidates the previous one.
- The joining device signs its join request; the inviting device verifies that signature, target identity and invitation secret, and issues a signed receipt. The joining device verifies the receipt before trusting the inviter.
- Enrolled peer records persist across restarts and may be revoked individually. Peer authorization is fixed to `identity_only`, so **no remote MCP tool access is granted**.
- The process uses the existing authenticated local loopback IPC. Pairing operations can be performed through the tray's Device pairing screen or the local CLI; no remote listener is opened.

## How to enroll two devices through the CLI

Both devices must be running their local `desktop-mcp-agent` service with their own accessible Git workspace. The following examples use PowerShell on Windows; change `$state` to `$HOME/.config/com.jacqueb.desktopmcp` for Linux.

1. On the inviting computer:

   ```powershell
   $state = "$env:APPDATA\com.jacqueb.desktopmcp"
   .\desktop-mcp-agent.exe --state-dir $state --pair-action pair_create_invite > invitation.json
   ```

2. Transfer the invitation JSON **privately** to the joining computer. On the joining computer:

   ```powershell
   .\desktop-mcp-agent.exe --state-dir $state --pair-action pair_prepare_join --pair-payload-file invitation.json --pair-name "Laptop" > join.json
   ```

3. Transfer `join.json` back to the inviting computer and accept it there:

   ```powershell
   .\desktop-mcp-agent.exe --state-dir $state --pair-action pair_accept_join --pair-payload-file join.json > receipt.json
   ```

4. Transfer `receipt.json` to the joining computer:

   ```powershell
   .\desktop-mcp-agent.exe --state-dir $state --pair-action pair_finalize_join --pair-payload-file receipt.json --pair-name "Desktop"
   ```

5. Check enrollment, or revoke it locally:

   ```powershell
   .\desktop-mcp-agent.exe --state-dir $state --pair-action pair_list
   .\desktop-mcp-agent.exe --state-dir $state --pair-action pair_revoke --pair-name "<peer host_id>"
   ```

Remove transferred invitation, request and receipt files when finished. `invitation.json` and `join.json` contain a short-lived bearer secret. Never publish them or paste them into a public issue/chat.

The tray screen performs the same exchange with paste/copy controls. Device identities listed there are **not connected**: they are trusted public keys, not live gateway sessions.

## Security scope and limitations

- End-to-end security of future transport has not been implemented. Do not forward the local loopback port or bearer token to the internet.
- The identity seed is stored on disk. On Unix it is mode 0600 under a 0700 config directory. Windows currently relies on per-user profile ACLs; explicit Windows DACL enforcement and stronger peer credentials are pending.
- Local identity trust alone does not grant remote commands or elevated privileges. Per-host scope, authenticated remote transport, explicit approvals, encryption and gateway routing remain required.
- Revocation is local. A future gateway must enforce revocation on both sides and reject revoked device identities.
- An active invitation or pending join exists only in the running agent process. Restarting the agent invalidates unfinished exchanges; start over with a fresh invitation.
- The protocol is intentionally limited to a single 10-minute invitation, at most 32 trusted peers, and human-mediated exchange. The public-key identity is persistent and the invitation is not.

## Verification

The Rust pairing unit tests exercise successful mutual signatures, persistence, replay and forgery rejection, expiry, self-pairing rejection and revocation.

The end-to-end `agent/smoke_pairing.py` test runs **two independent local agent processes** with disposable Git repositories. It verifies signed enrollment, tampering, replay rejection, persistence after restart, revocation, and the absence of remote permissions. This test has passed on Linux and Windows.
