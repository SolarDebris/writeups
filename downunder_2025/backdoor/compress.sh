#!/usr/bin/env bash
set -euo pipefail

# pick the directory
if [[ -d initramfs ]]; then
  SRC=initramfs
  OUT=initramfs.cpio.gz
elif [[ -d rootfs ]]; then
  SRC=rootfs
  OUT=rootfs.cpio.gz
else
  echo "Error: no 'initramfs/' or 'rootfs/' directory found." >&2
  exit 1
fi

# build the cpio.gz in one go
( cd "$SRC" && find . | cpio -H newc -o ) | gzip -n > "$OUT"
echo "✔ Created $OUT from $SRC/"

