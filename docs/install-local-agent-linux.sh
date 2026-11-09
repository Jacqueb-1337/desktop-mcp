#!/usr/bin/env bash
# Install a per-user Linux background agent. No root or administrator access.
set -euo pipefail
if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 /path/to/desktop-mcp-agent /path/to/git/repo [--allow-writes]" >&2
  exit 2
fi
if [ "$(id -u)" = 0 ]; then
  echo "Run as the desktop user, not root." >&2
  exit 2
fi
ALLOW_WRITES=0
if [ "$#" = 3 ]; then
  test "$3" = "--allow-writes" || { echo "Unknown argument: $3" >&2; exit 2; }
  ALLOW_WRITES=1
fi
BINARY="$(realpath "$1")"
WORKSPACE="$(realpath "$2")"
test -x "$BINARY" || { echo "Agent executable missing." >&2; exit 1; }
test -d "$WORKSPACE" || { echo "Workspace missing." >&2; exit 1; }
TOP="$(git -C "$WORKSPACE" rev-parse --show-toplevel)"
test "$(realpath "$TOP")" = "$WORKSPACE" || {
  echo "Workspace must be a Git repository root." >&2
  exit 1
}
command -v systemctl >/dev/null || { echo "systemd unavailable." >&2; exit 1; }

CONFIG_HOME="$(printenv XDG_CONFIG_HOME || printf '%s/.config' "$HOME")"
INSTALL_DIR="$HOME/.local/bin"
CONFIG_DIR="$CONFIG_HOME/com.jacqueb.desktopmcp"
UNIT_DIR="$CONFIG_HOME/systemd/user"
AGENT="$INSTALL_DIR/desktop-mcp-agent"
LAUNCHER="$INSTALL_DIR/desktop-mcp-agent-start"
UNIT="$UNIT_DIR/desktop-mcp-agent.service"

install -d -m 700 "$CONFIG_DIR"
install -d -m 755 "$INSTALL_DIR" "$UNIT_DIR"
install -m 755 "$BINARY" "$AGENT"
{
  printf '#!/usr/bin/env bash\nset -euo pipefail\n'
  printf 'exec %q --serve-local --workspace %q --state-dir %q' "$AGENT" "$WORKSPACE" "$CONFIG_DIR"
  if [ "$ALLOW_WRITES" = 1 ]; then printf ' --allow-writes'; fi
  printf '\n'
} > "$LAUNCHER"
chmod 700 "$LAUNCHER"
cat > "$UNIT" <<'UNIT'
[Unit]
Description=Desktop MCP local agent (unprivileged)

[Service]
Type=simple
ExecStart=%h/.local/bin/desktop-mcp-agent-start
Restart=on-failure
RestartSec=3
NoNewPrivileges=true

[Install]
WantedBy=default.target
UNIT
systemctl --user daemon-reload
systemctl --user enable desktop-mcp-agent.service
systemctl --user restart desktop-mcp-agent.service
systemctl --user --no-pager status desktop-mcp-agent.service
echo "Local agent installed; closing or restarting the tray does not stop it."
echo "Writes remain denied until an active local approval policy permits them."
