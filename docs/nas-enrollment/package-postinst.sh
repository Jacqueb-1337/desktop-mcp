#!/bin/sh
set -eu
if [ "${1:-}" = configure ] && [ -z "${DPKG_ROOT:-}" ]; then
    /usr/lib/desktop-mcp/enable-enrollment --if-configured
fi
exit 0
