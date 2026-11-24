#!/usr/bin/env bash
# Package an already-built, statically linked Linux gateway. No live installation.
set -euo pipefail
if [[ $# != 4 ]]; then
    echo "Usage: $0 BINARY VERSION ARCH OUTPUT_DIR" >&2
    exit 2
fi
binary=$1 version=$2 arch=$3 output=$4
[[ -f "$binary" && ! -L "$binary" ]] || { echo 'Invalid binary' >&2; exit 2; }
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.+~-][0-9A-Za-z.+~-]+)?$ ]] || { echo 'Invalid version' >&2; exit 2; }
case "$arch" in
    amd64) machine='Advanced Micro Devices X86-64' ;;
    arm64) machine='AArch64' ;;
    *) echo 'Unsupported architecture' >&2; exit 2 ;;
esac
export LC_ALL=C
header=$(readelf -h "$binary")
[[ "$header" == *"$machine"* && "$header" == *ELF64* ]] || { echo 'ELF architecture mismatch' >&2; exit 2; }
program=$(readelf -l "$binary")
dynamic=$(readelf -d "$binary")
[[ "$program" != *INTERP* && "$dynamic" != *NEEDED* ]] || { echo 'Static Linux binary required' >&2; exit 2; }
mkdir -p "$output"
output=$(realpath "$output")
root=$(mktemp -d)
trap 'rm -rf -- "$root"' EXIT
chmod 0755 "$root"
install -d -m 0755 "$root/DEBIAN" "$root/usr/lib/desktop-mcp" "$root/usr/share/doc/desktop-mcp-gateway"
install -m 0755 "$binary" "$root/usr/lib/desktop-mcp/desktop-mcp-gateway"
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
install -m 0644 "$repo/LICENSE" "$root/usr/share/doc/desktop-mcp-gateway/copyright"
size=$(du -sk "$root/usr" | cut -f1)
cat > "$root/DEBIAN/control" <<EOF
Package: desktop-mcp-gateway
Version: $version
Architecture: $arch
Maintainer: Desktop MCP maintainers
Section: net
Priority: optional
Installed-Size: $size
Description: Desktop MCP Linux gateway executable
 Static gateway binary for an independently configured Desktop MCP service.
 This package does not create, activate, or modify authorization or service state.
EOF
chmod 0644 "$root/DEBIAN/control"
(cd "$root" && find usr -type f -print0 | sort -z | xargs -0 md5sum > DEBIAN/md5sums)
chmod 0644 "$root/DEBIAN/md5sums"
package="$output/desktop-mcp-gateway_${version}_${arch}.deb"
[[ ! -e "$package" ]] || { echo 'Package already exists' >&2; exit 2; }
dpkg-deb --root-owner-group --build "$root" "$package"
(cd "$output" && sha256sum "$(basename -- "$package")" > "$(basename -- "$package").sha256")
