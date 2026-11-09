# Desktop MCP

Desktop MCP provides a local desktop agent, a Windows/Linux tray interface, and a
self-hosted gateway that routes authenticated MCP requests to paired devices.
Windows unattended administrator access is optional and requires explicit
approval from the Windows owner.

## Windows release

- DesktopMCP-Setup-v0.2.0.exe installs the tray and local agent for a fresh PC.
  It ships with no gateway configuration or elevated service. The installer is unsigned.
- DesktopMCP-Tray-v0.2.0.exe is the tray-only update for existing installations.
  Exit Desktop MCP from the tray menu, back up and replace desktop-mcp.exe in
  %LOCALAPPDATA%\Programs\DesktopMCP with the downloaded tray executable (rename
  it to desktop-mcp.exe), then start it again. The agent and gateway run separately.
- SHA256SUMS.txt lists the hashes of both executables.

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
