# hammerhead kernel for Weir, android-5.0.1

# make config. Only once.
#make ARCH=arm CROSS_COMPILE=arm-eabi- hammerhead_weir_defconfig

# make
# iMac
#make -j8 ARCH=arm CROSS_COMPILE=/Volumes/android/Weir/prebuilts/gcc/darwin-x86/arm/arm-eabi-4.8/bin/arm-eabi-
#eno
make -j8 ARCH=arm CROSS_COMPILE=arm-eabi-

# copy it to the Android source
cp arch/arm/boot/zImage-dtb ../Weir/device/lge/hammerhead-kernel/zImage-dtb
