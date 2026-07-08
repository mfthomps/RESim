#!/bin/bash
#
# Also creates a patched dtb file.
#
set -e

# --- Configuration ---
WORK_DIR=$(realpath ./fvp_foundation_workspace)

KERNEL_DIR="$WORK_DIR/linux"  # Adjust if your kernel source folder is named differently
OUTPUT_DIR="$WORK_DIR/output"

cd $WORK_DIR
cd linux

export ARCH=arm64
export CROSS_COMPILE=aarch64-linux-gnu-

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

echo "--> Compiling Device Tree Blobs..."
# We build the Image (uncompressed) and the explicit Foundation Model Device Tree
make -j$(nproc) dtbs 

# Locate and copy the exact foundation model device tree blob
if [ -f arch/arm64/boot/dts/arm/foundation-v8-gicv3-psci.dtb ]; then
    cp arch/arm64/boot/dts/arm/foundation-v8-gicv3-psci.dtb "$OUTPUT_DIR/"
else
    echo "--> ERROR: Could not find foundation DTB in standard paths!"
    exit
fi

echo "=========================================================="
echo " dtb build complete copy arch/arm64/boot/dts/arm/foundation-v8-gicv3-psci.dtb"
echo "=========================================================="
