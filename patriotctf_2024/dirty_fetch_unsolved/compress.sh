gcc $1 -o exp -static -no-pie 
mv ./exp ./rootfs
cd rootfs
#find . -print0 \
#   cpio --null -ov --format=newc \
#   gzip -9 > initramfs.cpio.gz
find . -print0 | cpio --null -ov --format=newc | gzip -9 > ../initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
