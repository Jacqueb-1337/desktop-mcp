# Desktop MCP family enrollment and gateway setup

The Desktop MCP plugin, gateway routes and protected administrator interface remain
private on the NAS. The Windows **installer** can be publicly distributed.

## What is included

- Windows agent, tray and protected unattended SYSTEM service
- The signed official WireGuard Windows MSI, verified by publisher and pinned digest
- The NAS WireGuard **public** server key and public TLS CA certificate
- Only the internal tunnel gateway address (`10.93.42.1:19874`)
- A first-run public IPv4, IPv6 or DNS hostname field with UDP port 51820 default

No NAS public IP, WireGuard PRIVATE keys, passwords or MCP access tokens are in the
public installer. There is no internet-facing MCP TCP port.

## End user

1. Run the installer, enter the **public** IP or DNS name (UDP port defaults to
   51820). It is saved in `%APPDATA%\com.jacqueb.desktopmcp\gateway-endpoint.json`.
2. Approve the Windows UAC request to install the signed WireGuard tunnel and
   protected unattended service. Each PC generates a fresh private WireGuard key
   and saves it under administrator-protected ProgramData. It does NOT share its
   private key with the NAS administrator.
3. Share the single displayed `DMW1:DM1-...:<wg-public-key>` registration code
   with the NAS administrator. The code contains only public identities.
4. Wait for the NAS owner to approve both its Desktop MCP signing identity
   and its WireGuard public key. Once authorized the WireGuard tunnel can
   authenticate and the agent can reach the private TLS gateway.
5. The PC owner separately approves a temporary or until-revoked unattended
   administrator grant. Pairing alone confers NO administrator access.

## NAS owner registration

- The private NAS tool `/usr/local/sbin/desktop-mcp-register-peer` validates the
  owner's combined code and registers the WireGuard public key with an address
  derived from the 32-byte DM1 signing public key. It also persists a peer section
  in `/etc/wireguard/wgdmcp.conf`, and allows revocation without restarting
  the server.
- Starting with v0.3.6, send the complete DMW1 registration code to the authenticated
  `pair_device` tool. It validates the signing identity, saves the pairing, and calls
  the optional local enrollment socket to register the WireGuard public key.
  The tool reports success only after the live WireGuard peer is confirmed.
  If the helper is unavailable, the signing identity remains paired; retry the
  same combined code after fixing the helper. Legacy DM1 codes still work.
- On a NAS that uses the existing root-owned `desktop-mcp-register-peer` utility,
  install the three files under `docs/nas-enrollment/` explicitly as administrator.
  Copy the Python helper to `/usr/local/libexec/desktop-mcp-enrollment-helper.py`
  (root:root, mode 0755) and the socket and service units to `/etc/systemd/system/`
  (root:root, mode 0644), then run `systemctl daemon-reload` and
  `systemctl enable --now desktop-mcp-enrollment.socket`.
  The socket is accessible only to the designated gateway account; the root helper
  verifies the connecting UID and validates the exact request. It cannot run
  arbitrary commands or grant Windows permissions. The updated Debian packaging
  includes the helper and systemd units, with conditional activation on a
  configured gateway. Existing administrator-managed units are preserved.
  The manual source installation above remains available.
- Without the helper, the NAS administrator can still use the old separate
  DM1 pairing and `desktop-mcp-register-peer enroll '<DM1-code>' '<WireGuard-public-key>'` workflow.
- To revoke tunnel entry:

  ```
  desktop-mcp-register-peer revoke '<DM1-code>'
  ```

  Revoke Desktop MCP pairing and existing grants separately. These are
  independent authorization boundaries.

- NAS Wi-Fi LAN IP `192.168.1.159`, WireGuard server UDP port `51820`.
  Router must forward **only UDP 51820** to `192.168.1.159:51820`.
  No TCP port to the NAS or to Windows is required for family access.
- The WireGuard gateway is `10.93.42.1/16`, with host-specific peer /32s.
  nftables drops all client traffic except TCP 19874 to the private gateway.
  It does NOT permit forwarding to other NAS networks or services.
- `wg-quick@wgdmcp`, `desktop-mcp-wg-proxy.socket`, and
  `desktop-mcp-gateway.service` are enabled and running.
- Peer registration is local, root-only and **not publicly hosted**.

## Validation and release status

- Public endpoint parsing, saving, reloading and no-overwrite tests passed.
- Windows peer-identity derivation, key-validation, and narrow route tests passed.
- The full candidate builds, including nested service and official WireGuard MSI.
- An isolated Linux network namespace successfully authenticated via UDP
  WireGuard to the NAS, reached the restricted TCP proxy and verified gateway
  TLS against the correct pinned CA. Temporary test peer was removed afterward.

**Not yet approved for public release:** a fresh Windows install, WireGuard
tunnel service installation and startup after owner UAC, first external UDP
connection through the router, and subsequent Windows reboot must be tested.
The published v0.3.2 setup still refuses in-place upgrades. A newer
transactional updater is implemented on the development branch and is
documented in [WINDOWS-UPGRADE.md](WINDOWS-UPGRADE.md). Its detected-failure
rollback and disposable local Windows tests pass. A protected service update,
reboot, and genuine WAN Windows test are still required before production use.
Do not distribute a development installer as production-ready.

## Offline upgrade compatibility review

Before replacing a gateway binary, run the candidate build's offline review
against a disposable copy of the current policy. An optional independently
prepared proposed policy can be compared in the same command:

    desktop-mcp-gateway --review-upgrade current-copy.json
    desktop-mcp-gateway --review-upgrade current-copy.json proposed-copy.json

The versioned JSON report validates both inputs and identifies added or
removed host scopes and capabilities. Any authorization difference requires
administrator review. The command does not modify either file, start a
listener, grant access, or generate a replacement authorization policy.
Unsupported versions and malformed policies fail closed. A legacy policy
with fewer capabilities remains valid; its existing authorization choices
are preserved. Capability changes are separate from binary deployment and
must remain subject to the administrator's established approval process.

The binary-only maintenance helper, `gateway_binary_upgrade.py`, performs
checksum verification, offline compatibility review, a same-directory
atomic binary replacement, a verified backup, and a systemd restart check.
On detected failure after replacement it restores the previous binary and
restarts the service. It never writes policy, pairing, keys or grant files.
This is not a policy migration utility. The operator must independently
verify the candidate provenance and use the existing administrative process
for authorization changes. A service-active check is not proof of remote
connectivity; verify device reconnection after a successful upgrade.
Sudden power loss and live Linux service recovery are not covered by the
disposable test suite. Run the latter with
`python -B -m unittest discover -s docs -p test_gateway_binary_upgrade.py`.
