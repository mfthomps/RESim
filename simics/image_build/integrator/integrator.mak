CROSS_COMPILE	?= arm-none-linux-gnueabihf-
#CROSS_COMPILE	?= arm-linux-gnueabi-
#CROSS_COMPILE	?= arm-none-eabi-
#CROSS_COMPILE	?= armv4tl-
build_dir       := $(CURDIR)/build-integrator
output_dir	:= $(HOME)
rootfs		:= $(HOME)/rootfs-integrator.cpio
install_dir     := $(build_dir)/install
config_file     := $(build_dir)/.config
strip		:= $(CROSS_COMPILE)strip
objcopy		:= $(CROSS_COMPILE)objcopy
rootfsbase	:= $(shell basename $(rootfs))
ap_dtb		:= $(build_dir)/arch/arm/boot/dts/integratorap.dtb
impd1_dtb	:= $(build_dir)/arch/arm/boot/dts/integratorap-im-pd1.dtb
cp_dtb		:= $(build_dir)/arch/arm/boot/dts/integratorcp.dtb
tftproot	:= /var/lib/tftpboot
makejobs	:= $(shell grep '^processor' /proc/cpuinfo | sort -u | wc -l)
makethreads	:= $(shell dc -e "$(makejobs) 1 + p")

ARCH ?= arm

make_options := -f Makefile \
		-j$(makethreads) -l$(makejobs) \
                ARCH=$(ARCH) \
                CROSS_COMPILE=$(CROSS_COMPILE) \
                KBUILD_OUTPUT=$(build_dir)
make_flags	:= CONFIG_DEBUG_SECTION_MISMATCH=y

.PHONY: help
help:
	@echo "****  Common Makefile  ****"
	@echo "make config - configure for Integrator"
	@echo "make build - build the kernel and produce a RAMdisk image"
	@echo
	@echo "example:"
	@echo "make -f integrator.mak config"
	@echo "make -f integrator.mak build"

.PHONY: have-rootfs
have-rootfs:
	@if [ ! -f $(rootfs) ] ; then \
	     echo "ERROR: no rootfs at $(rootfs)" ; \
	     echo "This is needed to boot the system." ; \
	     echo "ABORTING." ; \
	     exit 1 ; \
	else \
	     echo "Rootfs available at $(rootfs)" ; \
	fi

.PHONY: have-crosscompiler
have-crosscompiler:
	@echo -n "Check that $(CROSS_COMPILE)gcc is available..."
	@which $(CROSS_COMPILE)gcc > /dev/null ; \
	if [ ! $$? -eq 0 ] ; then \
	   echo "ERROR: cross-compiler $(CROSS_COMPILE)gcc not in PATH=$$PATH!" ; \
	   echo "ABORTING." ; \
	   exit 1 ; \
	else \
	   echo "OK" ;\
	fi

config-base: FORCE
	@mkdir -p $(build_dir)
	@cp $(rootfs) $(build_dir)/$(rootfsbase)
	$(MAKE) $(make_options) integrator_defconfig

config-initramfs: config-base
	# Configure in the initramfs
	$(CURDIR)/scripts/config --file $(config_file) \
	--enable BLK_DEV_INITRD \
	--set-str INITRAMFS_SOURCE $(rootfsbase) \
	--enable RD_GZIP \
	--enable INITRAMFS_COMPRESSION_GZIP

# For early printk
config-earlydebug: config-base
	$(CURDIR)/scripts/config --file $(config_file) \
	--enable DEBUG_LL \
	--enable EARLY_PRINTK \
	--set-str CMDLINE "root=/dev/mmcblk0p1 rootwait console=ttyAM0,38400n8 earlyprintk"

config-devicetree: config-base
	# Configure in the device tree
	$(CURDIR)/scripts/config --file $(config_file) \
	--enable USE_OF \
	--disable ARM_APPENDED_DTB \
	--disable ARM_ATAG_DTB_COMPAT \
	--disable ATAGS \
	--enable PROC_DEVICETREE

config-kasan: config-base
	$(CURDIR)/scripts/config --file $(config_file) \
	--enable SLUB \
	--enable SLUB_DEBUG \
	--enable SLUB_DEBUG_ON \
	--enable KASAN \
	--enable KASAN_OUTLINE \
	--enable STACKTRACE \
	--enable TEST_KASAN

config-bfq: config-base
	@echo "Enabling BFQ"
	$(CURDIR)/scripts/config --file $(config_file) \
	--enable IOSCHED_BFQ \
	--enable DEFAULT_BFQ \
	--disable IOSCHED_DEADLINE \
	--disable IOSCHED_CFQ

config-v3-vga: config-base
	@echo "Enabling V3 VGA"
	$(CURDIR)/scripts/config --file $(config_file) \
	--enable FB \
	--enable VGA_ARB \
	--enable VGA_CONSOLE \
	--enable LOGO \
	--enable FB_S3

config-drm: config-base
	$(CURDIR)/scripts/config --file $(config_file) \
	--disable FB_ARMCLCD \
	--enable CMA \
	--enable DRM \
	--enable DRM_PL111 \
	--enable FRAMEBUFFER_CONSOLE \
	--enable DRM_PANEL \
	--enable DRM_BRIDGE \
	--enable DRM_PANEL_BRIDGE \
	--enable DRM_SIMPLE_BRIDGE \
	--enable DRM_DISPLAY_CONNECTOR \
	--enable LOGO

config: have-rootfs config-base config-earlydebug config-initramfs config-drm FORCE
	# Reconfigure a bit
	$(CURDIR)/scripts/config --file $(build_dir)/.config \
	--enable DEBUG_FS \
	--enable COMMON_CLK_DEBUG \
	--disable VGA_CONSOLE \
	--enable SERIAL_AMBA_PL011 \
	--enable SERIAL_AMBA_PL011_CONSOLE \
	--enable MMC \
	--enable MMC_ARMMMCI \
	--enable FAT_FS \
	--enable VFAT_FS \
	--enable NLS \
	--enable NLS_CODEPAGE_437 \
	--enable NLS_ISO8859_1 \
	--enable NET_VENDOR_SMSC \
	--enable SMC91X \
	--enable GPIO_PL061 \
	--enable MTD_PHYSMAP_OF \
	--enable NEW_LEDS \
	--enable LEDS_CLASS \
	--enable LEDS_SYSCON \
	--enable CPUFREQ_DT \
	--enable CPUFREQ_DT_PLATDEV \
	--enable REGULATOR \
	--enable REGULATOR_FIXED_VOLTAGE \
	--enable INPUT \
	--enable INPUT_EVDEV \
	--enable KEYBOARD_GPIO \
	--enable DMA_CMA
	yes "" | make $(make_options) oldconfig

menuconfig: FORCE
	$(MAKE) $(make_options) menuconfig
	$(MAKE) $(make_options) savedefconfig

saveconfig: FORCE
	$(MAKE) $(make_options) savedefconfig
	cp $(build_dir)/defconfig arch/arm/configs/integrator_defconfig

build-dtbs: FORCE
	$(MAKE) $(make_options) dtbs $(make_flags)

check-bindings: FORCE
	$(MAKE) $(make_options) W=1 dt_binding_check -k $(make_flags)
	$(MAKE) $(make_options) W=1 dtbs_check -k $(make_flags)

build: have-rootfs have-crosscompiler build-dtbs FORCE
	@cp $(rootfs) $(build_dir)/$(rootfsbase)
	$(MAKE) $(make_options) zImage $(make_flags)
	# $(MAKE) $(make_options) modules
	# Copy to output dir
	cp -f $(build_dir)/arch/arm/boot/zImage $(output_dir)/zImage
	@which mkimage > /dev/null ; \
	if [ ! $$? -eq 0 ] ; then \
	   echo "mkimage not in PATH=$$PATH" ; \
	   echo "This tool creates the uImage and comes from the uboot tools" ; \
	   echo "On Ubuntu/Debian sudo apt-get install uboot-mkimage" ; \
	   echo "SKIPPING uImage GENERATION" ; \
	else \
	   mkimage \
		-A arm \
		-O linux \
		-T kernel \
		-C none \
		-a 0x00007fc0 \
		-e 0x00007fc0 \
		-n "Integrator Device Tree kernel" \
		-d $(output_dir)/zImage \
		$(output_dir)/uImage ; \
	fi
	cp -f $(build_dir)/vmlinux $(output_dir)/vmlinux.debug
	if [ -r $(ap_dtb) ] ; then \
	   cp $(ap_dtb) $(output_dir) ; \
	fi ; \
	if [ -r $(impd1_dtb) ] ; then \
	   cp $(impd1_dtb) $(output_dir) ; \
	fi ; \
	if [ -r $(cp_dtb) ] ; then \
	   cp $(cp_dtb) $(output_dir) ; \
	fi ; \
	# If we have a TFTP boot directory
	if [ -w $(tftproot) ] ; then \
	   cp $(output_dir)/uImage $(tftproot) ; \
	   if [ -r $(ap_dtb) ] ; then \
	      cp $(ap_dtb) $(tftproot) ; \
	   fi ; \
	   if [ -r $(impd1_dtb) ] ; then \
	      cp $(impd1_dtb) $(tftproot) ; \
	   fi ; \
	   if [ -r $(cp_dtb) ] ; then \
	      cp $(cp_dtb) $(tftproot) ; \
	   fi ; \
	fi
	@echo "setenv serverip 192.168.1.121;setenv ipaddr 192.168.1.134;setenv bootfile uImage;tftpboot 0x00007fc0 uImage;tftpboot 0x00800000 integratorcp.dtb;bootm 0x00007fc0 - 0x00800000"

clean:
	$(MAKE) -f Makefile clean
	rm -f $(module_files)
	rm -rf $(build_dir)

# Rules without commands or prerequisites that do not match a file name
# are considered to always change when make runs. This means that any rule
# that depends on FORCE will always be remade also.
FORCE:
