# Desktop MCP

Desktop MCP provides a local desktop agent, a Windows/Linux tray interface, and a
self-hosted gateway that routes authenticated MCP requests to paired devices.
Windows unattended administrator access is optional and requires explicit
approval from the Windows owner.

## Windows release

- **DesktopMCP-Setup-v0.3.2.exe** is the complete *fresh-install* Windows package.
  It includes the tray, local agent, protected unattended SYSTEM service, pinned
  public gateway trust material, and the signed official WireGuard Windows MSI.
  The owner enters their gateway's public IP/hostname and approves local UAC
  elevation before enabling unattended access. The setup EXE itself is unsigned.
- This release's remote trust material identifies a specific private family
  gateway. Entering another server's IP will not bypass its pinned identity.
- **DesktopMCP-Tray-v0.3.2.exe** is a tray-only binary for a manual update.
  Exit Desktop MCP, back up and replace desktop-mcp.exe in
  %LOCALAPPDATA%\Programs\DesktopMCP, then start it again.
  This does **not** upgrade the local agent, protected service, or WireGuard.
- **Do not run the published v0.3.2 setup EXE over an existing installation.**
  That release only supports fresh installs. The newer development branch
  implements transactional in-place upgrades and UAC-approved protected-service
  updates, preserving the pairing identity and existing tunnel settings.
  See docs/WINDOWS-UPGRADE.md for tests and outstanding acceptance work.
  Fresh remote Windows installs and reboots still require end-to-end
  verification. See docs/GATEWAY-SETUP.md.
- SHA256SUMS.txt lists the hashes of the downloadable release executables.

The tray checks this repository's latest stable GitHub release at startup and every
six hours. Check for updates is also available in the tray. Installing an update
is a separate manual action. The release check uses the system curl command.

## Build

Use Rust 1.90 or later, Cargo, and the Tauri 2 system prerequisites. Windows needs
WebView2 and MSVC build tools. The setup scripts use Windows PowerShell and the
.NET Framework C# compiler.

    cargo build --release --locked --manifest-path agent/Cargo.toml
    cargo build --release --locked --manifest-path gateway/Cargo.toml
    cargo build --release --locked --manifest-path src-tauri/Cargo.toml --features tauri/custom-protocol

See [the gateway guide](gateway/README.md) to host your own deployment and
[local agent commands](docs/LOCAL_AGENT.md) for standalone use.
