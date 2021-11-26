


sudo qemu-system-x86_64 \
	-kernel ../arch/x86_64/boot/bzImage \
	-nographic \
	-drive format=raw,file=fs/rootfs.ext4 \
	-append "root=/dev/sda console=ttyS0 nokaslr" \
	-m 4G \
	-smp $(nproc) \
	-net nic \
	-net user,hostfwd=tcp::10022-:22 \

