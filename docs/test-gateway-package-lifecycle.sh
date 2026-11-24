#!/usr/bin/env bash
# Isolated dpkg lifecycle regression test. Never uses the host package database,
# service manager, gateway configuration, network, or real gateway executable.
set -euo pipefail
[[ $(id -u) == 0 ]] || { echo 'Run in a disposable Linux test environment as root.' >&2; exit 2; }
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
root=$work/root
admin=$root/var/lib/dpkg
mkdir -p "$admin" "$root/etc/fixture" "$root/var/lib/fixture" "$root/opt/legacy-fixture" "$root/etc/systemd/system"
touch "$admin/status"
arch=$(dpkg --print-architecture)
case "$arch" in amd64|arm64) ;; *) exit 2 ;; esac
for version in 1 2; do
    printf '#include <stdio.h>\nint main(void) { puts("fixture-%s"); return 0; }\n' "$version" > "$work/fixture.c"
    cc -static -o "$work/fixture-$version" "$work/fixture.c"
    bash "$repo/docs/build-gateway-deb.sh" "$work/fixture-$version" "0.0.$version" "$arch" "$work/out"
done
printf 'test settings\n' > "$root/etc/fixture/settings"
printf 'test pairing data\n' > "$root/var/lib/fixture/pairings"
printf 'test certificate\n' > "$root/var/lib/fixture/certificate"
chmod 0600 "$root/var/lib/fixture/"*
cp "$work/fixture-1" "$root/opt/legacy-fixture/executable"
printf '[Service]\nExecStart=/opt/legacy-fixture/executable\n' > "$root/etc/systemd/system/fixture.service"
snapshot() {
    (cd "$root"; find etc var/lib/fixture opt/legacy-fixture -type f -print0 | sort -z | xargs -0 sha256sum; find etc var/lib/fixture opt/legacy-fixture -type f -printf '%m %U %G %p\n' | sort)
}
snapshot > "$work/before"
check_state() {
    snapshot > "$work/after"
    cmp "$work/before" "$work/after"
}
install_version() {
    local version=$1
    dpkg --root="$root" --install "$work/out/desktop-mcp-gateway_0.0.${version}_${arch}.deb"
    [[ $(dpkg-query --admindir="$admin" -W -f='${Version}' desktop-mcp-gateway) == "0.0.$version" ]]
    [[ $("$root/usr/lib/desktop-mcp/desktop-mcp-gateway") == "fixture-$version" ]]
    cmp "$work/fixture-$version" "$root/usr/lib/desktop-mcp/desktop-mcp-gateway"
    check_state
}
install_version 1
install_version 2
install_version 2
install_version 1
# Test package removal and purge against only the isolated root.
dpkg --root="$root" --remove desktop-mcp-gateway
[[ ! -e "$root/usr/lib/desktop-mcp/desktop-mcp-gateway" ]]
check_state
install_version 2
dpkg --root="$root" --purge desktop-mcp-gateway
[[ ! -e "$root/usr/lib/desktop-mcp/desktop-mcp-gateway" ]]
check_state
echo 'Isolated package lifecycle tests passed: fresh install, upgrade, reinstall, downgrade, remove, purge, preserved fixture state.'
