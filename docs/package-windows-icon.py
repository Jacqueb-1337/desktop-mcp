#!/usr/bin/env python3
"""Wrap the existing PNG app icon as a Windows ICO resource, without redrawing it."""
from pathlib import Path
import struct

icons = Path(__file__).resolve().parents[1] / "src-tauri" / "icons"
png = (icons / "icon.png").read_bytes()
if png[:8] != b"\x89PNG\r\n\x1a\n":
    raise SystemExit("icon.png is not a PNG file")
width, height = struct.unpack_from(">II", png, 16)
if not (1 <= width <= 256 and 1 <= height <= 256):
    raise SystemExit("PNG dimensions must fit in ICO resource")
header = struct.pack("<HHH", 0, 1, 1)
entry = struct.pack("<BBBBHHII", width % 256, height % 256, 0, 0, 1, 32, len(png), 22)
output = icons / "icon.ico"
output.write_bytes(header + entry + png)
print(f"Packaged {width}x{height} PNG into {output}")
