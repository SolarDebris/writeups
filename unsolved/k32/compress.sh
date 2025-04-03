#!/bin/sh
gcc -o exploit -static $1
mv ./exploit ./rootfs
cd rootfs
chmod +x exploit
sudo find . | sudo cpio -o -H newc > ../rootfs.cpio
