#!/usr/bin/env python3
# Socket-activated, single-purpose NAS administrator enrollment helper.
# No shell, client-supplied paths, arbitrary commands or grant issuance.
import base64
import hashlib
import ipaddress
import os
import re
import socket
import struct
import subprocess

REGISTER = "/usr/local/sbin/desktop-mcp-register-peer"
GATEWAY_USER = "desktopmcprun"
WG = "/usr/bin/wg"

def parse(request):
    match = re.fullmatch(rb"(DM1-([0-9a-f]{64})) ([A-Za-z0-9+/]{43}=)\n", request)
    if not match:
        raise ValueError("Invalid request")
    identity, signing, peer = (part.decode("ascii") for part in match.groups())
    public = base64.b64decode(peer, validate=True)
    if len(public) != 32 or not any(public) or base64.b64encode(public).decode() != peer:
        raise ValueError("Invalid public key")
    digest = hashlib.sha256(bytes.fromhex(signing)).digest()
    host = digest[:16].hex()
    address = str(ipaddress.IPv4Address(bytes([10, 93, digest[16], digest[17]])))
    if address in ("10.93.42.1", "10.93.42.2"):
        raise ValueError("Reserved address")
    return identity, peer, host, address

def main():
    import pwd
    with socket.socket(fileno=os.dup(0)) as conn:
        conn.settimeout(2)
        try:
            _, uid, _ = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
            if uid != pwd.getpwnam(GATEWAY_USER).pw_uid:
                raise PermissionError("Unexpected peer")
            # Exactly one bounded request, including EOF.
            request = b""
            while len(request) < 128:
                chunk = conn.recv(128-len(request))
                if not chunk:
                    break
                request += chunk
            identity, peer, host, address = parse(request)
            result = subprocess.run([REGISTER, "enroll", identity, peer],
                check=True, capture_output=True, text=True, timeout=6,
                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"})
            if result.stdout.strip() not in (
                f"ENROLL_OK host={host} address={address}",
                f"ALREADY_ENROLLED host={host} address={address}"):
                raise RuntimeError("Unexpected enrollment response")
            live = subprocess.run([WG, "show", "wgdmcp", "allowed-ips"],
                check=True, capture_output=True, text=True, timeout=1)
            matches = [line.split() for line in live.stdout.splitlines()]
            if [peer, address + "/32"] not in matches:
                raise RuntimeError("Persistent peer not active")
            conn.sendall(("OK " + host + "\n").encode("ascii"))
        except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
            # Never leak private network configuration or privileged command output.
            try:
                conn.sendall(b"ERROR\n")
            except OSError:
                pass

if __name__ == "__main__":
    main()
