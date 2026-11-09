# Self-host Desktop MCP

Run the gateway on a network you control. Use a private route for the agent
listener. Keep the MCP endpoint on loopback behind your authenticated MCP
connection. Do not expose the agent listener to the public internet without
additional protection against connection exhaustion.

## Gateway configuration

Supply a TLS certificate and its private key. The certificate must cover the
hostname used by your agents. Keep the signing key, server key, MCP bearer token,
audit state, and device registry private. Agents receive only the public CA.

Create an allowlist and a policy file, each starting with {"version":1,"hosts":[]},
a private audit directory, and a token file containing a random 64-character
hexadecimal token. On Linux keep the key and token files mode 0600 and the audit
directory mode 0700, owned by the service account. Start the gateway with:

    desktop-mcp-gateway --listen 127.0.0.1:19874 --cert server.pem --key server.key \
      --allowlist allowlist.json --policy policy.json --audit-dir audit \
      --mcp-listen 127.0.0.1:19875 --mcp-authority 127.0.0.1:19875 --mcp-token-file mcp-token

For remote agents, replace the first listen address with the private interface
address and add --allow-lan. Keep the MCP endpoint bound to loopback. The bundled
gateway/tunnel_stdio.py adapter can provide an authenticated stdio connection.
Run it with --ca and --token-file pointing to your deployment files.

## Build an installer for your gateway

From the repository root in Windows PowerShell, set $agent and $tray to the
compiled Windows executables. Set $address to your private gateway host and port,
$tlsName to the certificate hostname, and $ca to the path of the public CA PEM.

    .\docs\build-windows-unattended-service.ps1 -AgentExe $agent -GatewayCa $ca -GatewayAddress $address -GatewayTlsName $tlsName -Output DesktopMCP-Service.exe
    .\docs\build-windows-setup.ps1 -AgentExe $agent -TrayExe $tray -UnattendedServiceExe .\DesktopMCP-Service.exe -GatewayCa $ca -GatewayAddress $address -GatewayTlsName $tlsName -Output DesktopMCP-SelfHosted-Setup.exe

Omit the service and gateway arguments to build a local-only package. Never
bundle private keys or the MCP token into a Windows installer.

The Windows owner can install the optional service through UAC, then share their
setup code with the gateway operator. The operator calls pair_device with that
code, then requests admin_command access through request_permission. Pairing
alone grants no command execution. The Windows owner approves a timed or
until-revoked grant. During that grant, admin_command runs as Windows LocalSystem.
The owner can revoke access from the tray or the Desktop MCP revoke shortcut.

A controller with the MCP bearer token can use active unattended grants.
Restrict who can access that token and the MCP connection.
