#!/bin/bash
#
# Build Linux kernel for the FVP Foundation board.
# Also creates a patched dtb file.
#
set -e

# --- Configuration ---
WORK_DIR=$(realpath ./fvp_foundation_workspace)
mkdir -p $WORK_DIR

KERNEL_DIR="$WORK_DIR/linux"  # Adjust if your kernel source folder is named differently
OUTPUT_DIR="$WORK_DIR/output"

cd $WORK_DIR
if [ ! -d "linux" ]; then
    git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
fi
cd linux

export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-

mkdir -p "$OUTPUT_DIR"

echo "--> Cleaning kernel source tree..."
make mrproper

echo "--> Loading ARM64 defconfig..."
# Image-based ARM64 kernels use the unified defconfig which includes FVP support
make defconfig

# Force old-school ramdisk support to match your massive initrd layout
./scripts/config --enable CONFIG_BLK_DEV_RAM
./scripts/config --set-val CONFIG_BLK_DEV_RAM_COUNT 16
./scripts/config --set-val CONFIG_BLK_DEV_RAM_SIZE 524288 # 512MB max limit to clear your 292MB image

# Strip out RTC drivers
./scripts/config --disable CONFIG_RTC_DRV_EFI
./scripts/config --disable CONFIG_RTC_DRV_DS3232
./scripts/config --disable CONFIG_RTC_DRV_DS3232_HWMON

echo "--> Applying and validating configuration..."
make olddefconfig

echo "--> fix dts file..."
dtsfile=./arch/arm64/boot/dts/arm/foundation-v8-gicv3-psci.dts
did_patch=$( grep watchdog $dtsfile || true )
if [[ -z "$did_patch" ]]; then
    echo "--> patching $dtsfile."
    cat <<EOF >> $dtsfile
&{/watchdog@2a440000} {
    status = "disabled";
};
EOF
else
    echo "dts already patched"
fi

echo "--> Compiling Kernel and Device Tree Blobs..."
# We build the Image (uncompressed) and the explicit Foundation Model Device Tree
make -j$(nproc) Image dtbs 

echo "--> Copying build artifacts to $OUTPUT_DIR..."
cp arch/arm64/boot/Image "$OUTPUT_DIR/Image"

# Locate and copy the exact foundation model device tree blob
if [ -f arch/arm64/boot/dts/arm/foundation-v8-gicv3-psci.dtb ]; then
    cp arch/arm64/boot/dts/arm/foundation-v8-gicv3-psci.dtb "$OUTPUT_DIR/foundation.dtb"
else
    echo "--> ERROR: Could not find foundation DTB in standard paths!"
    exit
fi

echo "=========================================================="
echo " Kernel build complete! Files available in $OUTPUT_DIR"
echo "=========================================================="
