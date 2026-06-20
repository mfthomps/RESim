#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# --- Configuration ---
WORK_DIR=/eems_images/fvp_foundation_workspace
mkdir -p $WORK_DIR
export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-
export JOBS=$(nproc)

echo "===================================================="
echo " Starting ARM64 FVP u-boot Build Process"
echo " Workspace: $WORK_DIR"
echo "===================================================="

cd "$WORK_DIR"
if [ ! -d "u-boot" ]; then
    git clone --depth 1 https://source.denx.de/u-boot/u-boot.git
fi
cd u-boot
# Use the Versatile Express AEMv8 FVP configuration
make mrproper
make vexpress_aemv8a_semi_defconfig
echo "--> Stripping out fatal VirtIO/Block auto-probing for Foundation Model..."
scripts/config --disable CONFIG_VIRTIO
scripts/config --disable CONFIG_VIRTIO_MMIO
scripts/config --disable CONFIG_VIRTIO_BLK
scripts/config --disable CONFIG_VIRTIO_NET
scripts/config --disable CONFIG_CMD_VIRTIO
scripts/config --enable CONFIG_FIT
scripts/config --enable CONFIG_FIT_PRINT
scripts/config --disable CONFIG_BOOTMETH_VBE
make olddefconfig
make -j"$JOBS"

cd "$WORK_DIR"
if [ ! -d "arm-trusted-firmware" ]; then
    git clone --depth 1 https://github.com/ARM-software/arm-trusted-firmware.git
fi
cd arm-trusted-firmware
make PLAT=fvp clean
# We point BL33 to the U-Boot binary we compiled above
make PLAT=fvp \
     BL33="$WORK_DIR/u-boot/u-boot.bin" \
     DEBUG=0 \
     all fip
cd ../
OUTPUT_DIR=$WORK_DIR/output
cp arm-trusted-firmware/build/fvp/release/bl1.bin "$OUTPUT_DIR/"
cp arm-trusted-firmware/build/fvp/release/fip.bin "$OUTPUT_DIR/"

KERNEL_DTS_DIR="$WORK_DIR/linux/arch/arm64/boot/dts/arm"
TFA_DIR="$WORK_DIR/arm-trusted-firmware"
#FIPTOOL="/usr/bin/fiptool"
FIPTOOL="$WORK_DIR/arm-trusted-firmware/tools/fiptool/fiptool"
TFA_FDT_DIR="$TFA_DIR/build/fvp/release/fdts"
#$FIPTOOL update --hw-config "$KERNEL_DTS_DIR/foundation-v8-gicv3-psci.dtb" "$OUTPUT_DIR/fip.bin"
if [ -d "$TFA_DIR/build/fvp/release/fdts" ]; then
    $FIPTOOL update --hw-config "$TFA_FDT_DIR/fvp-base-gicv3-psci.dtb" "$OUTPUT_DIR/fip.bin"
    $FIPTOOL update --tb-fw-config "$TFA_DIR/build/fvp/release/fdts/fvp_tb_fw_config.dtb" "$OUTPUT_DIR/fip.bin"
    $FIPTOOL update --soc-fw-config "$TFA_DIR/build/fvp/release/fdts/fvp_soc_fw_config.dtb" "$OUTPUT_DIR/fip.bin"
    $FIPTOOL update --nt-fw-config "$TFA_DIR/build/fvp/release/fdts/fvp_nt_fw_config.dtb" "$OUTPUT_DIR/fip.bin"
    echo "done with fiptool"
else
    echo "NO fdts directory"
    exit 1
fi
echo "done"
