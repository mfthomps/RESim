LINUX_VERSION=3.4
BUILDROOT_VERSION=2014.08
TARGET_ARCH=ppc


# checkout buildroot branch and apply patch
if [ ! -d buildroot ]; then
    #git clone git://git.buildroot.net/buildroot
    git clone git://git.busybox.net/buildroot
fi

cd buildroot
git branch -f qsp-$TARGET_ARCH $BUILDROOT_VERSION
git checkout qsp-$TARGET_ARCH

PATCH=../pkgconf.patch
cd package
git apply -p1 ../$PATCH
cd ..

PATCH=../Config.patch
cd package
git apply -p1 ../$PATCH
cd ..

PATCH=../qsp-$TARGET_ARCH-buildroot-*.patch
if [ ! -e configs/qsp_${TARGET_ARCH}_linux_defconfig ]; then
    # patching buildroot
    if [ ! -e $PATCH ]; then
        echo Patch $PATCH missing
        exit 1
    fi
    #cd package
    git apply -p1 $PATCH
    chmod 755 board/windriver/qsp_fs_post.sh
    echo Patched with $PATCH
    #cd ..
fi
 
make qsp_${TARGET_ARCH}_linux_defconfig
../dopatches.sh
make 

