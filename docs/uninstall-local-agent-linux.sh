#!/usr/bin/env bash
# Remove the per-user Desktop MCP background service without deleting projects.
set -euo pipefail

if [ "$#" -gt 1 ] || { [ "$#" -eq 1 ] && [ "$1" != "--remove-binaries" ]; }; then
  echo "Usage: $0 [--remove-binaries]" >&2
  exit 2
fi

if [ "$(id -u)" -eq 0 ]; then
  echo "Run as the desktop user, not root." >&2
  exit 2
fi

UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
UNIT="$UNIT_DIR/desktop-mcp-agent.service"
INSTALL_DIR="$HOME/.local/bin"

if command -v systemctl >/dev/null 2>&1; then
  systemctl --user disable --now desktop-mcp-agent.service 2>/dev/null || true
fi

if [ -f "$UNIT" ]; then
  rm -- "$UNIT"
  if command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload
  fi
fi

if [ "${1:-}" = "--remove-binaries" ]; then
  rm -f -- "$INSTALL_DIR/desktop-mcp-agent-start" "$INSTALL_DIR/desktop-mcp-agent"
  echo "Removed the installed launcher and executable."
fi

echo "Desktop MCP user-level service disabled and removed."
echo "Workspace files and user preferences were not deleted."
