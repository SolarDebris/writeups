#!/usr/bin/env bash
set -euo pipefail

# pick the archive
if [[ -f initramfs.cpio.gz ]]; then
  IN=initramfs.cpio.gz
  DST=initramfs
elif [[ -f rootfs.cpio.gz ]]; then
  IN=rootfs.cpio.gz
  DST=rootfs
else
  echo "Error: no 'initramfs.cpio.gz' or 'rootfs.cpio.gz' found." >&2
  exit 1
fi

# clear old dir, recreate, and unpack
rm -rf "$DST"
mkdir -p "$DST"
gzip -dc "$IN" | ( cd "$DST" && cpio -idmv )
echo "✔ Extracted $IN into $DST/"

