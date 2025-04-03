#!/bin/sh
mkdir -p rootfs && cd rootfs
cp ../initramfs.cpio.gz . ||
    cp ../rootfs.cpio.gz . ||
    cp ../initramfs.cpio . ||
    cp ../rootfs.cpio .

if [ -f ./initramfs.cpio.gz ]; then
    gunzip ./initramfs.cpio.gz
    cpio_file="./initramfs.cpio"
elif [ -f ./rootfs.cpio.gz ]; then
    gunzip ./rootfs.cpio.gz
    cpio_file="./rootfs.cpio"
elif [ -f ./initramfs.cpio ]; then
    cpio_file="./initramfs.cpio"
elif [ -f ./rootfs.cpio ]; then
    cpio_file="./rootfs.cpio"
else
    echo "No cpio file found."
    exit 1
fi

cpio -idm < $cpio_file
rm $cpio_file

