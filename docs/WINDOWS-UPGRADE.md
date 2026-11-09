# Desktop MCP Windows in-place upgrade (development branch)

**Status:** Implemented in `feat/transactional-windows-upgrade`, not yet in the published v0.3.2 release. Run the upgrade only from an installer built from this branch after reviewing the notes.

## Installer behavior

For an existing `%LOCALAPPDATA%\Programs\DesktopMCP` and matching
`%APPDATA%\com.jacqueb.desktopmcp` pair, running the new setup prompts to
upgrade rather than refusing to proceed. It uses the same Windows user and
original scheduled tasks.

- Existing `gateway-endpoint.json` is read and retained byte-for-byte. The
  public IP/hostname is **not prompted for again**.
- Existing `pairing-identity.json` is never modified by the updater. The
  signing key fingerprint is checked before and after.
- The user agent and tray binary are staged in the private install directory,
  checksummed and backed up. Existing scheduled tasks are stopped, installed
  files are atomically replaced, then previously running tasks are restarted.
  Task definitions and their registered owners are never rewritten.
- If the gateway TLS CA already exists, its fingerprint must match the bundle.
  A changed CA cannot be installed silently.
- If migrating an old local-only installation without a saved public gateway
  endpoint, the setup asks **once**, saves that value, and removes it on failure.
- When the protected SYSTEM service exists, the upgrade requires one fresh
  Windows UAC approval. It checks the existing owner, matching signing key,
  private TLS server address and CA, and pinned WireGuard server public key.
  It then stops the service and upgrades only the protected agent and service
  executable. It verifies the same machine identity and restarts the service.
- The existing WireGuard tunnel service, private and public peer keys,
  private tunnel address, `grant.json`, audit logs, controller pairing, and
  authorization grants are left untouched. Upgrading is never consent to a
  new administrator grant.
- An earlier local-only install can optionally receive the protected service
  after the local binary upgrade, subject to a separate UAC approval.

## Rollback

The local and SYSTEM components each use an independent file backup
transaction. If a process fails to stop, a checksum mismatches, a replacement
cannot be written, or protected service setup fails, the prior binaries are
restored where possible. If rollback itself fails, backups remain in a
`.upgrade-...` directory for administrator recovery. Existing state and
grants are never overwritten as part of rollback.

**Limit:** Rollback is tested for detected runtime errors, injected callback
errors, and file locks. Sudden power loss or forced installer termination in
the middle of a multi-file update does not yet have automatic journal-based
recovery. In that case the backup directory must be checked before retrying.

## Tests run

- C# unit tests: staged binaries, commit, restoration, new-file removal,
  concurrent edits, file-lock interruption and path escape
- A disposable real Windows scheduled-task installation followed by an in-place
  upgrade, verifying local agent identity, endpoint, tasks and service status
- An injected protected-upgrade failure after swapping a *different* tray
  executable, followed by byte-for-byte rollback and healthy agent restart
- Nested installer verification ensures the updater code is bundled in the
  public installer and in the protected SYSTEM service

The disposable tests do not change the user's existing Desktop MCP installation.

## Remaining acceptance work

A real protected Windows service upgrade, UAC, reboot, and off-network
WireGuard connection from a secondary Windows PC still require acceptance
testing. No existing administrator grant or peer should be reset as a test
shortcut. Do not imply that these production tests have passed.
