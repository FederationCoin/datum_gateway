#!/usr/bin/env python3
"""Zip one file at archive root for mill daemon extras."""
import sys
import zipfile
from pathlib import Path

if len(sys.argv) != 3:
    sys.stderr.write("usage: zip-one.py SRC DEST.zip\n")
    sys.exit(1)
src = Path(sys.argv[1])
dest = Path(sys.argv[2])
if not src.is_file():
    sys.stderr.write(f"missing {src}\n")
    sys.exit(1)
dest.parent.mkdir(parents=True, exist_ok=True)
with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as z:
    z.write(src, src.name)
