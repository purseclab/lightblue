adb push $1 /sdcard/
adb shell su -c "mount -o remount,rw /"
adb shell su -c "cp /sdcard/$1 /system/lib64/libbluetooth.so"
adb reboot
