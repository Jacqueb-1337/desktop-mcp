# Desktop MCP

Desktop MCP provides a local desktop agent, a Windows/Linux tray interface, and a
self-hosted gateway that routes authenticated MCP requests to paired devices.
Windows unattended administrator access is optional and requires explicit
approval from the Windows owner.

## Windows release

- **DesktopMCP-Setup-v0.3.5.exe** installs or upgrades the Windows tray, agent and optional protected service. Existing installations keep their pairing and gateway configuration. The setup is unsigned and bundles the signed WireGuard MSI.
- The bundled trust configuration identifies the private family gateway. For another gateway, build with its public trust configuration.
- **DesktopMCP-Tray-v0.3.5.exe** updates the tray component only.
- See docs/WINDOWS-UPGRADE.md for upgrade behavior and docs/GATEWAY-SETUP.md for fresh installations.
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
