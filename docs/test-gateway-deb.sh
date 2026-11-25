#!/usr/bin/env bash
# Smoke-test the package format with a harmless static fixture.
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
case "$(uname -m)" in
    x86_64) arch=amd64; wrong=arm64 ;;
    aarch64) arch=arm64; wrong=amd64 ;;
    *) echo 'Unsupported test host architecture' >&2; exit 2 ;;
esac
printf 'int main(void) { return 0; }\n' > "$work/fixture.c"
cc -static -o "$work/fixture" "$work/fixture.c"
cc -o "$work/dynamic" "$work/fixture.c"
build="$repo/docs/build-gateway-deb.sh"
bash "$build" "$work/fixture" 0.0.0 "$arch" "$work/out"
package="$work/out/desktop-mcp-gateway_0.0.0_${arch}.deb"
[[ "$(dpkg-deb -f "$package" Architecture)" == "$arch" ]]
[[ "$(dpkg-deb -f "$package" Version)" == 0.0.0 ]]
dpkg-deb -e "$package" "$work/control"
dpkg-deb -x "$package" "$work/extracted"
[[ "$(find "$work/control" -maxdepth 1 -type f | wc -l)" == 4 ]]
[[ -f "$work/control/control" && -f "$work/control/md5sums" ]]
for hook in postinst prerm; do
    [[ -x "$work/control/$hook" ]]
    cmp "$repo/docs/nas-enrollment/package-$hook.sh" "$work/control/$hook"
done
[[ "$(stat -c %a "$work/extracted")" == 755 ]]
cmp "$work/fixture" "$work/extracted/usr/lib/desktop-mcp/desktop-mcp-gateway"
(cd "$work/extracted" && md5sum -c "$work/control/md5sums")
(cd "$work/out" && sha256sum -c "$(basename "$package").sha256")
"$work/extracted/usr/lib/desktop-mcp/desktop-mcp-gateway"
if bash "$build" "$work/fixture" 0.0.0 "$wrong" "$work/wrong"; then exit 1; fi
if bash "$build" "$work/dynamic" 0.0.0 "$arch" "$work/dynamic-out"; then exit 1; fi
if bash "$build" "$work/fixture" 0.0.0 "$arch" "$work/out"; then exit 1; fi
echo 'Package smoke tests passed (static fixture only).'
