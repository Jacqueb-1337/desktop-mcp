# Desktop MCP v0.3.2

This release packages the complete Windows installer for use with a private Desktop MCP gateway. **Remote WireGuard onboarding is experimental** because a fresh off-network Windows install and reboot have not yet been acceptance-tested.

## What's included

- Windows Desktop MCP agent and tray rebuilt from v0.3.2 source
- Protected unattended Windows service, installed only with the owner's local UAC consent
- Signed official WireGuard Windows installer inside the single setup executable
- Public gateway TLS CA and WireGuard server public key pinned in the service installer
- On first installation, prompts once for gateway public IP/hostname and optional UDP port (default 51820)
- Generates each PC's WireGuard identity locally, then displays a combined DMW1 registration code
- NAS administrator must enroll the device's public WireGuard key independently; ChatGPT pairing and elevated grants still require separate owner approval
- Gateway WireGuard listener and private relay were tested with isolated Linux peer and verified TLS; those tests do not establish router forwarding or remote Windows compatibility

## Important limitations

- **Fresh installations only.** Do not run the setup over an existing Desktop MCP installation. It deliberately refuses an in-place update. The current pairing identity and saved gateway are retained.
- **Tray-only update does not update the agent or protected service.** To update an existing machine's full installation, a safe transactional upgrade system is still required.
- The installation EXE itself is unsigned. The bundled third-party WireGuard MSI is signed and pinned to its approved SHA256 digest.
- Public IP or hostname is configurable, but this build is pinned to one trusted gateway identity. It is not a general-purpose client for arbitrary independently hosted gateways.
- Fresh off-network Windows install, WireGuard service startup and persistence after reboot, owner grant/revocation, and real WAN UDP 51820 forwarding have **not** been acceptance-tested. Do not claim the remote installation is fully verified.
- No NAS private keys, MCP API tokens, device secrets, or the owner's external IP are bundled in the public EXE.
- The NAS gateway and MCP registration/admin endpoints are *not* public services. Only WireGuard UDP 51820 should be forwarded.

## Release assets

- `DesktopMCP-Setup-v0.3.2.exe`: Windows fresh-install package, including agent, tray, protected service and WireGuard
- `DesktopMCP-Tray-v0.3.2.exe`: separate tray executable for manual tray-only replacement
- `SHA256SUMS.txt`: SHA256 checksums for both binaries
