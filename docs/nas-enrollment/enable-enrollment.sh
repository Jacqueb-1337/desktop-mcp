#!/bin/sh
# Only activate the packaged helper on an already configured gateway.
set -eu
mode=${1:-}
case "$mode" in ""|--if-configured) ;; *) echo "Usage: $0 [--if-configured]" >&2; exit 2;; esac
[ "$#" -le 1 ] || exit 2
skip() {
    echo "Desktop MCP enrollment: $*" >&2
    if [ "$mode" = --if-configured ]; then exit 0; fi
    exit 1
}
[ "$(id -u)" = 0 ] || skip "administrator privileges required"
[ -z "${DPKG_ROOT:-}" ] || skip "offline package root; activation skipped"
[ -d /run/systemd/system ] || skip "systemd is not running"
command -v systemctl >/dev/null || skip "systemctl unavailable"
getent passwd desktopmcprun >/dev/null || skip "gateway account is not configured"
getent group desktopmcprun >/dev/null || skip "gateway group is not configured"
[ -x /usr/bin/python3 ] && [ -x /usr/bin/wg ] || skip "Python or WireGuard tools missing"
register=/usr/local/sbin/desktop-mcp-register-peer
[ -f "$register" ] && [ ! -L "$register" ] && [ -x "$register" ] || skip "administrator registration utility missing"
[ "$(stat -c %u "$register")" = 0 ] || skip "registration utility is not root-owned"
# Do not activate an enrollment helper that would execute a writable utility.
permissions=$(stat -c %a "$register")
case "$permissions" in *[2367][0-7]|*[0-7][2367]) skip "registration utility is group/world writable";; esac
systemctl is-active --quiet wg-quick@wgdmcp.service || skip "WireGuard gateway not active"
systemctl is-active --quiet desktop-mcp-gateway.service || skip "Desktop MCP gateway not active"
# Respect locally installed or masked enrollment units rather than replacing them.
for unit in desktop-mcp-enrollment.socket desktop-mcp-enrollment@.service; do
    for dir in /etc/systemd/system /run/systemd/system; do
        if [ -e "$dir/$unit" ] || [ -L "$dir/$unit" ]; then
            if systemctl is-active --quiet desktop-mcp-enrollment.socket; then
                echo "Desktop MCP enrollment: existing local socket is active; preserved"
                exit 0
            fi
            skip "local enrollment unit override exists; administrator must manage it"
        fi
    done
done
systemctl daemon-reload || skip "systemd reload failed"
systemctl enable --now desktop-mcp-enrollment.socket || skip "socket activation failed; retry this command"
systemctl is-active --quiet desktop-mcp-enrollment.socket || skip "socket did not become active"
echo "Desktop MCP enrollment: packaged socket active"
