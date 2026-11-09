# Generic gateway endpoint setup

Desktop MCP installers should be reusable across self-hosted gateways. This
branch adds the first-run public endpoint field and per-user persistence.

## Endpoint

- Installer accepts a public IPv4 address, an IPv6 address, or a DNS hostname.
- Optional UDP port (default 51820) is for WireGuard, **not** the Desktop MCP
  gateway's TLS/relay listener.
- Endpoint is saved as `gateway-endpoint.json` in the owner's private
  `%APPDATA%\com.jacqueb.desktopmcp` directory.
- Existing installations load the saved file and do not prompt again.
- `SaveNew` intentionally refuses to overwrite existing configuration.
- The existing tray-only update does not modify this state. The full installer
  still refuses in-place upgrades, so implementing safe service upgrades remains
  a separate release blocker.
- To change an endpoint deliberately, use a future owner-facing Settings UI with
  explicit confirmation and update of the WireGuard tunnel endpoint.

## Authentication (required before usable remote release)

The public IP alone **cannot** authenticate a gateway or enroll a machine.
The WireGuard server public key must be authenticated, the new PC must generate
its own private key locally, and the NAS must register only that PC's public key.
Each device must use its own peer key. Never bundle private peer keys, service
tokens, or NAS TLS private keys in a publicly available installer.

The Windows WireGuard tunnel service must be installed, started and configured
before the protected Desktop MCP service attempts to reach its private gateway
address. The protected service must be included and installed with the owner's
explicit Windows authorization. Pairing and unattended access grants remain
separate owner decisions.

The existing protected service installer still reads an embedded gateway TLS
configuration. The Windows tunnel-client provisioning and generic credential
exchange are **not yet implemented**. This is an endpoint-configuration feature,
not an end-to-end remote connection release.

## Verification

Build the installer with `docs/build-windows-setup.ps1` and run an isolated test:

```powershell
$compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
& $compiler /nologo /target:exe /warnaserror+ /reference:System.Web.Extensions.dll /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /out:$env:TEMP\GatewayEndpointTests.exe docs\GatewayEndpoint.cs docs\GatewayEndpointTests.cs
& $env:TEMP\GatewayEndpointTests.exe
```

The test checks parsing, invalid inputs, persistence, reload, and refusal to
replace an existing gateway. It does not touch a live Desktop MCP installation.
