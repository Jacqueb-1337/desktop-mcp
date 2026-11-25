#!/bin/sh
set -eu
if [ "${1:-}" = remove ] && [ -z "${DPKG_ROOT:-}" ] && [ -d /run/systemd/system ]; then
    # Never stop a manually installed or masked administrator socket.
    for unit in desktop-mcp-enrollment.socket desktop-mcp-enrollment@.service; do
        for dir in /etc/systemd/system /run/systemd/system; do
            if [ -e "$dir/$unit" ] || [ -L "$dir/$unit" ]; then exit 0; fi
        done
    done
    systemctl disable --now desktop-mcp-enrollment.socket || true
fi
exit 0
