#!/bin/sh
TEMP_DIR=$(mktemp -d)
cp ./babybs.bin "$TEMP_DIR/babybs.bin"
cd "$TEMP_DIR"
qemu-system-i386 -nographic -drive file="$TEMP_DIR",format=raw
cd -
rm -rf "$TEMP_DIR"
