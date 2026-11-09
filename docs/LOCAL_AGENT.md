# Desktop MCP local background service

The Desktop MCP Rust agent now runs as a separate local process and can outlive the tray popup. It supports MCP stdio as before, plus a local IPC protocol for tray status, approval, and revocation.

## Security properties and limitations

- Listens only on IPv4 loopback (127.0.0.1) at an ephemeral port. No remote gateway connection or administrator execution.
- A random 256-bit bearer token is stored inside the current user's app-config directory. Linux applies mode 0700 to the directory and 0600 to the token file. Windows relies on the current user's profile ACLs; explicit Windows DACL enforcement and peer identity verification are future work.
- The tray Rust backend reads the token. The HTML/JavaScript frontend never receives it.
- Editing is denied by default even if the agent was started with write capability. An active, time-limited auto-approval policy is required for patch application and Git commits.
- Revoking access resets approval to Ask. Restarting the agent also resets approval.
- Delete patches are blocked by the local service, even during auto-approval, until a separate destructive-operation confirmation mechanism is implemented.
- The explicit --allow-writes startup argument permits local file edits to be approved. Without it, the agent remains read-only regardless of the tray setting.
- Not yet hardened for remote/multiuser use. Do not expose the local listener or its token through a tunnel.

## Manual startup

The --workspace argument must be the Git repository root and accessible to the OS user running the agent. The --state-dir argument must refer to the tray application's app config directory.

Linux example:

    desktop-mcp-agent --workspace "$HOME/projects/my-repo" --state-dir "$HOME/.config/com.jacqueb.desktopmcp" --serve-local

Windows PowerShell example:

    .\desktop-mcp-agent.exe --workspace 'C:\Projects\my-repo' --state-dir "$env:APPDATA\com.jacqueb.desktopmcp" --serve-local

Append --allow-writes to explicitly enable the capability to approve edits. Local approval still begins in Ask mode.

## Optional user-level startup installers

These have passed syntax checks but have NOT yet been installed or tested in a live desktop login session. They do not request administrator privileges.

On Linux, run as your desktop user:

    bash docs/install-local-agent-linux.sh /path/to/desktop-mcp-agent /path/to/git/repo --allow-writes

This copies the binary to ~/.local/bin, creates a systemd user service, and starts it. Omit --allow-writes for read-only mode.

On Windows, run PowerShell as your normal user:

    .\docs\install-local-agent-windows.ps1 -AgentExe .\desktop-mcp-agent-windows-x64.exe -Workspace C:\Projects\my-repo -AllowWrites

This copies the executable to your local AppData Programs directory, registers an unprivileged scheduled task at sign-in, and starts it. Omit -AllowWrites for read-only mode.

Hiding or exiting the tray never stops the background agent. Uninstall using docs/uninstall-local-agent-windows.ps1 -RemoveInstalledBinary or bash docs/uninstall-local-agent-linux.sh --remove-binaries. Repositories and preferences are retained. --show-popup is an optional diagnostic launch flag; normal launches remain tray-only.

## Verified and outstanding

- 13 Rust unit tests passed.
- Local IPC authentication, status, default denial, timed auto-approval, patch application, Git commit, and revoke passed end-to-end on Linux and Windows.
- The Windows popup was visually verified to show Local agent ready while the independent agent was running. Closing the tray left the agent alive. Interactive approval controls still need separate UI testing.
- JavaScript, Linux shell installer, and Windows PowerShell installer syntax checks passed.
- Windows startup installer and uninstaller passed a disposable Git workspace test. The read-only agent started and the task, process and test files were removed afterward. Linux startup is syntax-checked, not yet live-tested. Windows token DACL hardening, peer checks and remote pairing remain future work.
